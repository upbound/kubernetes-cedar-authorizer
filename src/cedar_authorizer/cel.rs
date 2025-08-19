use std::collections::HashMap;

use cedar_policy_core::ast as cedar_ast;
use cel::parser::ast as cel_ast;
use cel::IdedExpr as CelIdedExpr;
use itertools::Itertools;

// TODO: Maybe we could just take a Residual instead, that might be a bit more straightforward than PolicySet Expr.

fn without_id_res(expr: cel_ast::Expr) -> Result<CelIdedExpr, CedarToCelError> {
    Ok(without_id(expr))
}

fn without_id(expr: cel_ast::Expr) -> CelIdedExpr {
    CelIdedExpr { id: 0, expr }
}

#[derive(thiserror::Error, Debug)]
pub enum CedarToCelError {
    #[error("Unsupported Cedar operator: {0}")]
    UnsupportedOperator(cedar_ast::BinaryOp),
    #[error("Unsupported Cedar extension function: {0}")]
    UnsupportedExtensionFunction(String),
    #[error("CEL parser error: {0}")]
    CELParseError(#[from] cel::parser::ParseError),
}

pub trait EntityToCelVariableMapper {
    fn cel_identifier_for_entity(&mut self, entity_uid: &cedar_ast::EntityUID) -> String;
}

pub struct DefaultEntityToCelVariableMapper {
    entity_uid_to_cel_identifier: HashMap<cedar_ast::EntityUID, String>,
    counter: u64,
}

impl DefaultEntityToCelVariableMapper {
    pub fn new(i: impl IntoIterator<Item = (cedar_ast::EntityUID, String)>) -> Self {
        Self {
            entity_uid_to_cel_identifier: i.into_iter().collect(),
            counter: 0,
        }
    }
}

impl EntityToCelVariableMapper for DefaultEntityToCelVariableMapper {
    fn cel_identifier_for_entity(&mut self, entity_uid: &cedar_ast::EntityUID) -> String {
        self.entity_uid_to_cel_identifier
            .get(entity_uid)
            .cloned()
            .unwrap_or_else(|| {
                let identifier = format!("entity{}", self.counter);
                self.entity_uid_to_cel_identifier
                    .insert(entity_uid.clone(), identifier.clone());
                self.counter += 1;
                identifier
            })
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct CELExpression(String);

impl CELExpression {
    pub fn as_str(&self) -> &str {
        &self.0
    }
    fn new_unchecked(s: String) -> Self {
        Self(s)
    }
    // TODO: This does not work in the general case, it's a hack. Need to actually parse the AST and rewrite that way.
    // For example, replacing "resource.name" does not match "resource["name"]"; and "resource.name" might be part of a string literal, etc.
    pub fn rename_variables(&self, mappings: &HashMap<String, String>) -> Self {
        let mut expr = self.0.clone();
        for (old_name, new_name) in mappings {
            expr = expr.replace(old_name, new_name);
        }
        Self(expr)
    }
}
impl std::fmt::Display for CELExpression {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// TODO: Improve the Rust CEL library to support marshalling an AST to a String.
// It is required to store the original "call expression" of macros, either in a SourceInfo
// struct like the Go library (https://github.com/google/cel-go/blob/8e7beb65e9a70f501fd743c3b70b2a0a2fadac52/parser/unparser.go#L450)
// (just like the protobuf spec defines: https://github.com/google/cel-spec/blob/a8f582aae6a65b5c417c0ab7d22aab68f41ec4b2/proto/cel/expr/syntax.proto#L335),
// or by making a "to_string" method on the Rust AST node, that is generic over how to encode macros (one fallible and one not).
// Also, possibly make an AST walker (just like Cedar has) that can be used to rewrite the AST in a more general way.
pub fn cedar_to_cel<M: EntityToCelVariableMapper>(
    cedar_expr: &cedar_ast::Expr,
    entity_uid_mapper: &mut M,
) -> Result<CELExpression, CedarToCelError> {
    match cedar_expr.expr_kind() {
        cedar_ast::ExprKind::And { left, right } => {
            // NOTE: CEL, as per its specification, treats || and && operators as commutative, that is NOT short-circuiting like Cedar.
            // Thus, we need to rewrite the expression to be short-circuiting, as (Cedar) "e1 && e2" => (CEL) "e1 ? e2 : false"
            // TODO: Figure out operator precedence, and if we need to wrap the whole thing in parentheses.
            // This would be easiest to implement by being consistent with unparser.go in the Go library.
            Ok(CELExpression::new_unchecked(format!(
                "({} ? {} : false)",
                cedar_to_cel(left, entity_uid_mapper)?,
                cedar_to_cel(right, entity_uid_mapper)?
            )))
        }
        cedar_ast::ExprKind::BinaryApp { op, arg1, arg2 } => match op {
            cedar_ast::BinaryOp::Add => Ok(CELExpression::new_unchecked(format!(
                "({} + {})",
                cedar_to_cel(arg1, entity_uid_mapper)?,
                cedar_to_cel(arg2, entity_uid_mapper)?
            ))),
            cedar_ast::BinaryOp::Mul => Ok(CELExpression::new_unchecked(format!(
                "({} * {})",
                cedar_to_cel(arg1, entity_uid_mapper)?,
                cedar_to_cel(arg2, entity_uid_mapper)?
            ))),
            cedar_ast::BinaryOp::Sub => Ok(CELExpression::new_unchecked(format!(
                "({} - {})",
                cedar_to_cel(arg1, entity_uid_mapper)?,
                cedar_to_cel(arg2, entity_uid_mapper)?
            ))),

            cedar_ast::BinaryOp::Contains => {
                // Could maybe also use the extension function "contains" instead of "in"
                let set = cedar_to_cel(arg1, entity_uid_mapper)?;
                let val = cedar_to_cel(arg2, entity_uid_mapper)?;
                Ok(CELExpression::new_unchecked(format!("({val} in {set})")))
            }
            cedar_ast::BinaryOp::ContainsAll => {
                // The Cedar containsAll function "evaluates to true if every member of the operand set is a member of the receiver set.""
                // (Cedar) "superset.containsAll(subset)" => (CEL) "subset.all(i, i in superset)"
                let superset = cedar_to_cel(arg1, entity_uid_mapper)?;
                let subset = cedar_to_cel(arg2, entity_uid_mapper)?;
                // TODO: What happens if the i variable is already used somewhere else in the scope?
                Ok(CELExpression::new_unchecked(format!(
                    "{subset}.all(i, i in {superset})"
                )))
            }
            cedar_ast::BinaryOp::ContainsAny => {
                // The Cedar containsAny function "evaluates to true if any one or more members of the operand set is a member of the receiver set"
                // (Cedar) "superset.containsAny(subset)" => (CEL) "subset.exists(i, i in superset)"
                let superset = cedar_to_cel(arg1, entity_uid_mapper)?;
                let subset = cedar_to_cel(arg2, entity_uid_mapper)?;

                Ok(CELExpression::new_unchecked(format!(
                    "{subset}.exists(i, i in {superset})"
                )))
            }
            cedar_ast::BinaryOp::Eq => Ok(CELExpression::new_unchecked(format!(
                "({} == {})",
                cedar_to_cel(arg1, entity_uid_mapper)?,
                cedar_to_cel(arg2, entity_uid_mapper)?
            ))),
            cedar_ast::BinaryOp::GetTag => todo!(),
            cedar_ast::BinaryOp::HasTag => todo!(),
            cedar_ast::BinaryOp::In => Err(CedarToCelError::UnsupportedOperator(*op)),
            cedar_ast::BinaryOp::Less => Ok(CELExpression::new_unchecked(format!(
                "({} < {})",
                cedar_to_cel(arg1, entity_uid_mapper)?,
                cedar_to_cel(arg2, entity_uid_mapper)?
            ))),
            cedar_ast::BinaryOp::LessEq => Ok(CELExpression::new_unchecked(format!(
                "({} <= {})",
                cedar_to_cel(arg1, entity_uid_mapper)?,
                cedar_to_cel(arg2, entity_uid_mapper)?
            ))),
        },
        cedar_ast::ExprKind::ExtensionFunctionApp { fn_name, .. } => Err(
            CedarToCelError::UnsupportedExtensionFunction(fn_name.to_string()),
        ),
        cedar_ast::ExprKind::GetAttr { expr, attr } => Ok(CELExpression::new_unchecked(format!(
            "{}.{}",
            cedar_to_cel(expr, entity_uid_mapper)?,
            attr
        ))),
        cedar_ast::ExprKind::HasAttr { expr, attr } => Ok(CELExpression::new_unchecked(format!(
            "has({}.{})",
            cedar_to_cel(expr, entity_uid_mapper)?,
            attr
        ))),

        cedar_ast::ExprKind::If {
            test_expr,
            then_expr,
            else_expr,
        } => Ok(CELExpression::new_unchecked(format!(
            "({} ? {} : {})",
            cedar_to_cel(test_expr, entity_uid_mapper)?,
            cedar_to_cel(then_expr, entity_uid_mapper)?,
            cedar_to_cel(else_expr, entity_uid_mapper)?
        ))),
        cedar_ast::ExprKind::Is { expr, entity_type } => todo!(),
        cedar_ast::ExprKind::Like { expr, pattern } => {
            let expr = cedar_to_cel(expr, entity_uid_mapper)?;
            let literal_string = || {
                pattern
                    .iter()
                    .flat_map(|c| match c {
                        cedar_ast::PatternElem::Char(c) => Some(c), // Note: Now that there are no wildcards, we should collect '*' characters into literal such ones
                        cedar_ast::PatternElem::Wildcard => None,
                    })
                    .collect::<String>()
            };
            let literal_string_with_wildcards = || {
                pattern
                    .iter()
                    .flat_map(|c| match c {
                        cedar_ast::PatternElem::Char('*') => Some("\\*".to_string()),
                        cedar_ast::PatternElem::Char(c) => Some(c.to_string()), // TODO: Need to escape quite a lot of characters here
                        cedar_ast::PatternElem::Wildcard => Some(".*".to_string()),
                    })
                    .collect::<String>()
            };
            match pattern
                .iter()
                .filter(|c| matches!(c, cedar_ast::PatternElem::Wildcard))
                .count()
            {
                0 => Ok(CELExpression::new_unchecked(format!(
                    "{expr} == '{}'",
                    literal_string()
                ))),
                1 => match (pattern.get_elems().first(), pattern.get_elems().last()) {
                    (Some(cedar_ast::PatternElem::Wildcard), Some(_)) => {
                        Ok(CELExpression::new_unchecked(format!(
                            "{expr}.endsWith('{}')",
                            literal_string()
                        )))
                    }
                    (Some(_), Some(cedar_ast::PatternElem::Wildcard)) => {
                        Ok(CELExpression::new_unchecked(format!(
                            "{expr}.startsWith('{}')",
                            literal_string()
                        )))
                    }
                    _ => Ok(CELExpression::new_unchecked(format!(
                        "{expr}.matches('^{}$')",
                        literal_string_with_wildcards()
                    ))),
                },
                _ => Ok(CELExpression::new_unchecked(format!(
                    "{expr}.matches('^{}$')",
                    literal_string_with_wildcards()
                ))),
            }
        }
        cedar_ast::ExprKind::Or { left, right } => {
            // NOTE: CEL, as per its specification, treats || and && operators as commutative, that is NOT short-circuiting like Cedar.
            // Thus, we need to rewrite the expression to be short-circuiting, as (Cedar) "e1 || e2" => (CEL) "e1 ? true : e2"
            Ok(CELExpression::new_unchecked(format!(
                "({} ? true : {})",
                cedar_to_cel(left, entity_uid_mapper)?,
                cedar_to_cel(right, entity_uid_mapper)?
            )))
        }
        cedar_ast::ExprKind::Record(attrs) => Ok(CELExpression::new_unchecked(format!(
            "{{ {} }}",
            attrs
                .iter()
                .map(|(k, v)| Ok(format!("'{}': {}", k, cedar_to_cel(v, entity_uid_mapper)?)))
                .collect::<Result<Vec<String>, CedarToCelError>>()?
                .join(", ")
        ))),
        cedar_ast::ExprKind::Set(items) => Ok(CELExpression::new_unchecked(format!(
            "[{}]",
            items
                .iter()
                .map(|v| cedar_to_cel(v, entity_uid_mapper))
                .collect::<Result<Vec<CELExpression>, CedarToCelError>>()?
                .iter()
                .map(|e| e.to_string())
                .join(", ")
        ))),
        cedar_ast::ExprKind::UnaryApp { op, arg } => match op {
            cedar_ast::UnaryOp::Not => Ok(CELExpression::new_unchecked(format!(
                "!({})",
                cedar_to_cel(arg, entity_uid_mapper)?
            ))),
            cedar_ast::UnaryOp::Neg => Ok(CELExpression::new_unchecked(format!(
                "-({})",
                cedar_to_cel(arg, entity_uid_mapper)?
            ))),
            cedar_ast::UnaryOp::IsEmpty => Ok(CELExpression::new_unchecked(format!(
                "size({}) == 0",
                cedar_to_cel(arg, entity_uid_mapper)?
            ))),
        },
        cedar_ast::ExprKind::Var(var) => Ok(CELExpression::new_unchecked(var.to_string())),
        cedar_ast::ExprKind::Lit(lit) => Ok(match lit {
            cedar_ast::Literal::Bool(b) => CELExpression::new_unchecked(b.to_string()),
            cedar_ast::Literal::String(s) => CELExpression::new_unchecked(format!("'{s}'")),
            cedar_ast::Literal::Long(l) => CELExpression::new_unchecked(l.to_string()),
            cedar_ast::Literal::EntityUID(uid) => {
                CELExpression::new_unchecked(entity_uid_mapper.cel_identifier_for_entity(uid))
            }
        }),
        cedar_ast::ExprKind::Slot(_) => todo!(),
        cedar_ast::ExprKind::Unknown(_) => todo!(),
    }
}

mod test {
    #[test]
    fn test_cel_expression() {
        use serde_json::json;

        /*let program = cel_interpreter::Program::compile(
        r#"has(resource.stored.v1) && has(resource.stored.v1.spec) && resource.stored.v1.spec.nodeName == "node-1""#)
        .unwrap();*/
        let parser = cel::parser::Parser::default();
        let program = parser
            .parse(r#"has(resource.stored.v1) && has(resource.stored.v1.spec) && resource.stored.v1.spec.nodeName == "node-1""#)
            .unwrap();
        dbg!(&program);
        let mut context = cel::Context::default();
        context.add_variable_from_value(
            "resource",
            cel::to_value(json!({
                "stored": {
                }
            }))
            .unwrap(),
        );
        let result = cel::Value::resolve(&program, &context).unwrap();
        assert_eq!(result, cel::Value::Bool(true));
    }

    #[test]
    fn test_cel_expression_with_function() {
        fn starts_with(This(this): This<Arc<String>>, prefix: Arc<String>) -> bool {
            this.starts_with(prefix.as_str())
        }
        use cel::extractors::This;
        use cel::{Context, Program};
        use std::sync::Arc;
        let mut context = Context::default();
        context.add_function("startsWith", starts_with);
        let program1 = "'fobar'.startsWith('foo') == true";
        let program2 = "startsWith('foobar', 'foo') == true";
        let program1 = Program::compile(program1).unwrap();
        let program2 = Program::compile(program2).unwrap();
        let value = program1.execute(&context).unwrap();
        assert_eq!(value, true.into());
        let value = program2.execute(&context).unwrap();
        assert_eq!(value, true.into());
    }

    #[test]
    fn test_in_operator() {
        use std::str::FromStr;
        let parser = cel::parser::Parser::default();
        let program = parser.parse("[1, 101, 34].all(i, i in [1, 34])").unwrap();
        dbg!(&program);

        let policy_set = cedar_policy::PolicySet::from_str(
            r#"permit(principal, action, resource) when {[1, 34].containsAll([1, 101, 34])};"#,
        )
        .unwrap();
        let cedar_expr = policy_set.policies().next().unwrap().as_ref().condition();
        dbg!(&cedar_expr);
    }

    #[test]
    fn test_has_macro_and_select() {
        let parser = cel::parser::Parser::default();
        let program = parser.parse("has(a.b) && a.b == 'foo'").unwrap();
        dbg!(&program);
    }

    #[test]
    fn test_cedar_to_cel() {
        use cedar_policy_core::ast as cedar_ast;
        let tests = vec![
            (
                r#"[1, 34].containsAll([1, 101, 34])"#,
                "[1, 101, 34].all(i, i in [1, 34])",
            ),
            (
                r#"(((core::VersionedPod::"3c0edf18-ae66-48ca-8309-4f2f94c5d4ae" has "v1") && ((core::VersionedPod::"3c0edf18-ae66-48ca-8309-4f2f94c5d4ae"["v1"]) has "spec")) && ((((core::VersionedPod::"3c0edf18-ae66-48ca-8309-4f2f94c5d4ae"["v1"])["spec"])["nodeName"]) == "node-1"))"#,
                "((has(entity0.v1) ? has(entity0.v1.spec) : false) ? (entity0.v1.spec.nodeName == 'node-1') : false)",
            ),
            (
                r#"resource.apiGroup like "pods/*""#,
                r#"resource.apiGroup.startsWith('pods/')"#,
            ),
            (
                r#"resource.apiGroup like "*/scale""#,
                r#"resource.apiGroup.endsWith('/scale')"#,
            ),
            (
                r#"resource.apiGroup like "*/scale/*""#,
                r#"resource.apiGroup.matches('.*\\/scale\\/.*')"#,
            ),
        ];
        for (cedar_expr, wanted_cel_expr) in tests {
            let cedar_expr: cedar_ast::Expr = cedar_expr.parse().unwrap();
            let mut entity_uid_mapper = super::DefaultEntityToCelVariableMapper::new([]);
            let cel_expr = super::cedar_to_cel(&cedar_expr, &mut entity_uid_mapper).unwrap();
            assert_eq!(cel_expr.as_str(), wanted_cel_expr);
        }
    }

    /*#[test]
    fn test_other_cel_library() {
        let env = cel_cxx::Env::builder()
            .declare_variable::<String>("name").unwrap()
            .build()
            .unwrap();

        let program = env.compile("name.startsWith('foo')").unwrap();


        let activation = cel_cxx::Activation::new()
            .bind_variable("name", "foobar".to_string())
            .unwrap();

        let result = program.evaluate(&activation).unwrap();
        assert_eq!(result, true.into());
    }*/
}
