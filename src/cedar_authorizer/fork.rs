use cedar_policy_core::{expr_builder::ExprBuilder, parser::Loc};
use smol_str::SmolStr;
use nonempty::NonEmpty;

use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter},
    process::{Child, ChildStdin, ChildStdout, Command},
};
use std::{path::Path, process::Stdio};
use cedar_policy_symcc::{
    err::SolverError,
    solver::{Decision, Solver},
    SmtLibScript,
};

// NOTE: This is a copy of the original function in cedar-policy-core.
// Filename: cedar/cedar-policy-core/src/parser/cst_to_ast.rs
// The code is Apache-2.0 licensed by the Cedar contributors.
// Hopefully, one would be able to make this function public in the future,
// to avoid the copy here.
pub(super) fn construct_exprs_extended_has<Build: ExprBuilder>(
    t: Build::Expr,
    attrs: &NonEmpty<SmolStr>,
    loc: Option<&Loc>,
) -> Build::Expr {
    let (first, rest) = attrs.split_first();
    let has_expr = Build::new()
        .with_maybe_source_loc(loc)
        .has_attr(t.clone(), first.to_owned());
    let get_expr = Build::new()
        .with_maybe_source_loc(loc)
        .get_attr(t, first.to_owned());
    // Foldl on the attribute list
    // It produces the following for `principal has contactInfo.address.zip`
    //     Expr.and
    //   (Expr.and
    //     (Expr.hasAttr (Expr.var .principal) "contactInfo")
    //     (Expr.hasAttr
    //       (Expr.getAttr (Expr.var .principal) "contactInfo")
    //       "address"))
    //   (Expr.hasAttr
    //     (Expr.getAttr
    //       (Expr.getAttr (Expr.var .principal) "contactInfo")
    //       "address")
    //     "zip")
    // This is sound. However, the evaluator has to recur multiple times to the
    // left-most node to evaluate the existence of the first attribute. The
    // desugared expression should be the following to avoid the issue above,
    // Expr.and
    //   Expr.hasAttr (Expr.var .principal) "contactInfo"
    //   (Expr.and
    //      (Expr.hasAttr (Expr.getAttr (Expr.var .principal) "contactInfo")"address")
    //      (Expr.hasAttr ..., "zip"))
    rest.iter()
        .fold((has_expr, get_expr), |(has_expr, get_expr), attr| {
            (
                Build::new().with_maybe_source_loc(loc).and(
                    has_expr,
                    Build::new()
                        .with_maybe_source_loc(loc)
                        .has_attr(get_expr.clone(), attr.to_owned()),
                ),
                Build::new()
                    .with_maybe_source_loc(loc)
                    .get_attr(get_expr, attr.to_owned()),
            )
        })
        .0
}


/// Implements `Solver` by launching an SMT solver in a new process and
/// communicating with it
/// 
/// Note: This is a modified copy of the original struct in cedar-policy-symcc.
/// Filename: cedar/cedar-policy-symcc/src/symcc/solver.rs
/// The code is Apache-2.0 licensed by the Cedar contributors.
/// 
/// This LocalSolver is slightly modified to drop the solver process when the
/// LocalSolver is dropped. I'm not sure if that happens with the original
/// LocalSolver. In any case, once it is made sure that the Cedar upstream
/// LocalSolver kills the solver process when it is dropped, we can remove this.
#[derive(Debug)]
pub struct LocalSolver {
    solver_stdin: BufWriter<ChildStdin>,
    solver_stdout: BufReader<ChildStdout>,
    child: Child,
}

impl LocalSolver {
    fn new<'a>(
        path: impl AsRef<Path>,
        args: impl IntoIterator<Item = &'a str>,
    ) -> Result<Self, SolverError> {
        let mut child = Command::new(path.as_ref())
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()?;
        tracing::debug!("Spawned solver instance with PID: {:?}", child.id());
        let (stdin, stdout) = match (child.stdin.take(), child.stdout.take()) {
            (Some(stdin), Some(stdout)) => (stdin, stdout),
            _ => {
                return Err(SolverError::Solver(
                    "Failed to fetch IO pipes for solver process".into(),
                ))
            }
        };
        Ok(Self {
            solver_stdin: BufWriter::new(stdin),
            solver_stdout: BufReader::new(stdout),
            child,
        })
    }

    pub fn cvc5() -> Result<Self, SolverError> {
        Self::new(
            std::env::var("CVC5").unwrap_or_else(|_| "cvc5".into()),
            ["--lang", "smt", "--tlimit=60000"], // limit of 60000ms = 1 min of wall time for local solves, for now
        )
    }
}

impl Solver for LocalSolver {
    fn smtlib_input(&mut self) -> &mut (dyn tokio::io::AsyncWrite + Unpin + Send) {
        &mut self.solver_stdin
    }

    async fn check_sat(&mut self) -> Result<Decision, SolverError> {
        self.smtlib_input().check_sat().await?;
        self.solver_stdin.flush().await?;
        let mut output = String::new();
        self.solver_stdout.read_line(&mut output).await?;
        match output.as_str() {
            "sat\n" => Ok(Decision::Sat),
            "unsat\n" => Ok(Decision::Unsat),
            "unknown\n" => Ok(Decision::Unknown),
            s => match s
                .strip_prefix("(error \"")
                .and_then(|s| s.strip_suffix("\")\n"))
            {
                Some(e) => Err(SolverError::Solver(e.to_string())),
                _ => Err(SolverError::UnrecognizedSolverOutput(output)),
            },
        }
    }

    async fn get_model(&mut self) -> Result<Option<String>, SolverError> {
        self.smtlib_input().get_model().await?;
        self.solver_stdin.flush().await?;
        let mut output = String::new();

        // We assume that the output is one of the following forms:
        // 1. "(\n<the actual model>\n)\n"
        // 2. "(error ...)\n"

        // Read the first line
        self.solver_stdout.read_line(&mut output).await?;
        match output.as_str() {
            "(\n" => {
                // Read until a line ")\n"
                loop {
                    let len: usize = self.solver_stdout.read_line(&mut output).await?;
                    if &output[output.len() - len..] == ")\n" {
                        break;
                    }
                }
                Ok(Some(output))
            }

            s => match s
                .strip_prefix("(error \"")
                .and_then(|s| s.strip_suffix("\")\n"))
            {
                Some(e) => Err(SolverError::Solver(e.to_string())),
                _ => Err(SolverError::UnrecognizedSolverOutput(output)),
            },
        }
    }
}

impl Drop for LocalSolver {
    fn drop(&mut self) {
        if let Some(id) = self.child.id() {
            tracing::debug!("Dropping solver instance with PID: {}", id);
        } else {
            tracing::debug!("Dropping solver instance (process already terminated)");
        }
    }
}