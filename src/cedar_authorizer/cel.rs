use std::collections::HashMap;

use cel::{Context, Program, Value as CelValue};

use cedar_policy_core::{ast as cedar_ast};
use cel::parser::{reference::Val as CelVal, ast as cel_ast};
use cel::IdedExpr as CelIdedExpr;

// TODO: Maybe we could just take a Residual instead, that might be a bit more straightforward than PolicySet Expr.

fn without_id_res(expr: cel_ast::Expr) -> Result<CelIdedExpr, CedarToCelError> {
    Ok(without_id(expr))
}

fn without_id(expr: cel_ast::Expr) -> CelIdedExpr {
    CelIdedExpr{
        id: 0,
        expr
    }
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

trait EntityToCelVariableMapper {
    fn cel_identifier_for_entity(&mut self, entity_uid: &cedar_ast::EntityUID) -> String;
}

struct DefaultEntityToCelVariableMapper {
    entity_uid_to_cel_identifier: HashMap<cedar_ast::EntityUID, String>,
    counter: u64,
}

impl DefaultEntityToCelVariableMapper {
    fn new(i: impl IntoIterator<Item = (cedar_ast::EntityUID, String)>) -> Self {
        Self {
            entity_uid_to_cel_identifier: i.into_iter().collect(),
            counter: 0,
        }
    }
}

impl EntityToCelVariableMapper for DefaultEntityToCelVariableMapper {
    fn cel_identifier_for_entity(&mut self, entity_uid: &cedar_ast::EntityUID) -> String {
        self.entity_uid_to_cel_identifier.get(entity_uid).cloned().unwrap_or_else(|| {
            let identifier = format!("entity{}", self.counter);
            self.entity_uid_to_cel_identifier.insert(entity_uid.clone(), identifier.clone());
            self.counter += 1;
            identifier
        })
    }
}

fn cedar_to_cel<M: EntityToCelVariableMapper>(cedar_expr: &cedar_ast::Expr, entity_uid_mapper: &mut M) -> Result<CelIdedExpr, CedarToCelError> {
    match cedar_expr.expr_kind() {
        cedar_ast::ExprKind::And { left, right } => {
            // NOTE: CEL, as per its specification, treats || and && operators as commutative, that is NOT short-circuiting like Cedar.
            // Thus, we need to rewrite the expression to be short-circuiting, as (Cedar) "e1 && e2" => (CEL) "e1 ? e2 : false"
            without_id_res(cel_ast::Expr::Call(cel_ast::CallExpr{
                func_name: cel_ast::operators::CONDITIONAL.to_string(),
                target: None, // target is the optional receiver of the function, e.g. 'somestr' in "somestr.startsWith("foo")"
                args: vec![cedar_to_cel(left, entity_uid_mapper)?, cedar_to_cel(right, entity_uid_mapper)?, without_id(cel_ast::Expr::Literal(CelVal::Boolean(false)))],
            }))
        }
        cedar_ast::ExprKind::BinaryApp { op, arg1, arg2 } => match op {
            cedar_ast::BinaryOp::Add => without_id_res(cel_ast::Expr::Call(cel_ast::CallExpr{
                func_name: cel_ast::operators::ADD.to_string(),
                target: None,
                args: vec![cedar_to_cel(arg1, entity_uid_mapper)?, cedar_to_cel(arg2, entity_uid_mapper)?],
            })),
            cedar_ast::BinaryOp::Mul => without_id_res(cel_ast::Expr::Call(cel_ast::CallExpr{
                func_name: cel_ast::operators::MULTIPLY.to_string(),
                target: None,
                args: vec![cedar_to_cel(arg1, entity_uid_mapper)?, cedar_to_cel(arg2, entity_uid_mapper)?],
            })),
            cedar_ast::BinaryOp::Sub => without_id_res(cel_ast::Expr::Call(cel_ast::CallExpr{
                func_name: cel_ast::operators::SUBSTRACT.to_string(),
                target: None,
                args: vec![cedar_to_cel(arg1, entity_uid_mapper)?, cedar_to_cel(arg2, entity_uid_mapper)?],
            })),

            cedar_ast::BinaryOp::Contains => {
                // Could maybe also use the extension function "contains" instead of "in"
                let set = cedar_to_cel(arg1, entity_uid_mapper)?;
                let val = cedar_to_cel(arg2, entity_uid_mapper)?;
                without_id_res(cel_ast::Expr::Call(cel_ast::CallExpr{
                    func_name: cel_ast::operators::IN.to_string(),
                    target: None,
                    // NOTE: (Cedar) "set.contains(val)" => (CEL) "val in set"
                    args: vec![val, set],
                }))
            }
            cedar_ast::BinaryOp::ContainsAll => {
                // The Cedar containsAll function "evaluates to true if every member of the operand set is a member of the receiver set.""
                // (Cedar) "superset.containsAll(subset)" => (CEL) "subset.all(i, i in superset)"
                let superset = cedar_to_cel(arg1, entity_uid_mapper)?;
                let subset = cedar_to_cel(arg2, entity_uid_mapper)?;
                
                let mut parser_helper = cel::parser::ParserHelper::default();
                let mut helper = cel::parser::MacroExprHelper::new(&mut parser_helper, 0);
                let i = without_id(cel_ast::Expr::Ident("i".to_string()));
                Ok(cel::parser::macros::all_macro_expander(&mut helper, Some(subset), vec![
                    i.clone(),
                    without_id(cel_ast::Expr::Call(cel_ast::CallExpr{
                        func_name: cel_ast::operators::IN.to_string(),
                        target: None,
                        args: vec![i, superset],
                    })),
                ])?)
            }
            cedar_ast::BinaryOp::ContainsAny => {
                // The Cedar containsAny function "evaluates to true if any one or more members of the operand set is a member of the receiver set"
                // (Cedar) "superset.containsAny(subset)" => (CEL) "subset.exists(i, i in superset)"
                let superset = cedar_to_cel(arg1, entity_uid_mapper)?;
                let subset = cedar_to_cel(arg2, entity_uid_mapper)?;
                
                let mut parser_helper = cel::parser::ParserHelper::default();
                let mut helper = cel::parser::MacroExprHelper::new(&mut parser_helper, 0);
                let i = without_id(cel_ast::Expr::Ident("i".to_string()));
                Ok(cel::parser::macros::exists_macro_expander(&mut helper, Some(subset), vec![
                    i.clone(),
                    without_id(cel_ast::Expr::Call(cel_ast::CallExpr{
                        func_name: cel_ast::operators::IN.to_string(),
                        target: None,
                        args: vec![i, superset],
                    })),
                ])?)
            }
            cedar_ast::BinaryOp::Eq => without_id_res(cel_ast::Expr::Call(cel_ast::CallExpr{
                func_name: cel_ast::operators::EQUALS.to_string(),
                target: None,
                args: vec![cedar_to_cel(arg1, entity_uid_mapper)?, cedar_to_cel(arg2, entity_uid_mapper)?],
            })),
            cedar_ast::BinaryOp::GetTag => todo!(),
            cedar_ast::BinaryOp::HasTag => todo!(),
            cedar_ast::BinaryOp::In => Err(CedarToCelError::UnsupportedOperator(op.clone())),
            cedar_ast::BinaryOp::Less => without_id_res(cel_ast::Expr::Call(cel_ast::CallExpr{
                func_name: cel_ast::operators::LESS.to_string(),
                target: None,
                args: vec![cedar_to_cel(arg1, entity_uid_mapper)?, cedar_to_cel(arg2, entity_uid_mapper)?],
            })),
            cedar_ast::BinaryOp::LessEq => without_id_res(cel_ast::Expr::Call(cel_ast::CallExpr{
                func_name: cel_ast::operators::LESS_EQUALS.to_string(),
                target: None,
                args: vec![cedar_to_cel(arg1, entity_uid_mapper)?, cedar_to_cel(arg2, entity_uid_mapper)?],
            }))
        }
        cedar_ast::ExprKind::ExtensionFunctionApp {fn_name, .. } => Err(CedarToCelError::UnsupportedExtensionFunction(fn_name.to_string())),
        cedar_ast::ExprKind::GetAttr { expr, attr } => without_id_res(cel_ast::Expr::Select(cel_ast::SelectExpr{
            operand: Box::new(cedar_to_cel(expr, entity_uid_mapper)?),
            field: attr.to_string(),
            test: false,
        })),
        cedar_ast::ExprKind::HasAttr { expr, attr } => without_id_res(cel_ast::Expr::Select(cel_ast::SelectExpr{
            operand: Box::new(cedar_to_cel(expr, entity_uid_mapper)?),
            field: attr.to_string(),
            test: true,
        })),

        cedar_ast::ExprKind::If {
            test_expr,
            then_expr,
            else_expr,
        } => without_id_res(cel_ast::Expr::Call(cel_ast::CallExpr{
            func_name: cel_ast::operators::CONDITIONAL.to_string(),
            target: None,
            args: vec![cedar_to_cel(test_expr, entity_uid_mapper)?, cedar_to_cel(then_expr, entity_uid_mapper)?, cedar_to_cel(else_expr, entity_uid_mapper)?],
        })),
        cedar_ast::ExprKind::Is { expr, entity_type } => todo!(),
        cedar_ast::ExprKind::Like { expr, pattern } => todo!(),
        cedar_ast::ExprKind::Or { left, right } => {
            // NOTE: CEL, as per its specification, treats || and && operators as commutative, that is NOT short-circuiting like Cedar.
            // Thus, we need to rewrite the expression to be short-circuiting, as (Cedar) "e1 || e2" => (CEL) "e1 ? true : e2"
            without_id_res(cel_ast::Expr::Call(cel_ast::CallExpr{
                func_name: cel_ast::operators::CONDITIONAL.to_string(),
                target: None, // target is the optional receiver of the function, e.g. 'somestr' in "somestr.startsWith("foo")"
                args: vec![cedar_to_cel(left, entity_uid_mapper)?, without_id(cel_ast::Expr::Literal(CelVal::Boolean(true))), cedar_to_cel(right, entity_uid_mapper)?],
            }))
        }
        cedar_ast::ExprKind::Record(attrs) => without_id_res(cel_ast::Expr::Map(cel_ast::MapExpr{
            entries: attrs.iter().map(|(k, v)| Ok::<_, CedarToCelError>(cel_ast::IdedEntryExpr{
                id: 0, 
                expr: cel_ast::EntryExpr::MapEntry(cel_ast::MapEntryExpr{
                    key: without_id(cel_ast::Expr::Literal(CelVal::String(k.to_string()))),
                    value: cedar_to_cel(v, entity_uid_mapper)?,
                    optional: false,
                })
            })).collect::<Result<Vec<cel_ast::IdedEntryExpr>, CedarToCelError>>()?,
        })),
        cedar_ast::ExprKind::Set(items) => without_id_res(cel_ast::Expr::List(cel_ast::ListExpr{
            elements: items.iter().map(|v| cedar_to_cel(v, entity_uid_mapper)).collect::<Result<Vec<cel_ast::IdedExpr>, CedarToCelError>>()?,
        })),
        cedar_ast::ExprKind::UnaryApp { op, arg } => match op {
            cedar_ast::UnaryOp::Not => without_id_res(cel_ast::Expr::Call(cel_ast::CallExpr{
                func_name: cel_ast::operators::LOGICAL_NOT.to_string(),
                target: None,
                args: vec![cedar_to_cel(arg, entity_uid_mapper)?],
            })),
            cedar_ast::UnaryOp::Neg => without_id_res(cel_ast::Expr::Call(cel_ast::CallExpr{
                func_name: cel_ast::operators::NEGATE.to_string(),
                target: None,
                args: vec![cedar_to_cel(arg, entity_uid_mapper)?],
            })),
            cedar_ast::UnaryOp::IsEmpty => without_id_res(cel_ast::Expr::Call(cel_ast::CallExpr{
                // (Cedar) "set.isEmpty()" => (CEL) "size(set) == 0"
                func_name: cel_ast::operators::EQUALS.to_string(),
                target: None,
                args: vec![
                    without_id(cel_ast::Expr::Call(cel_ast::CallExpr{
                        func_name: "size".to_string(),
                        target: None,
                        args: vec![cedar_to_cel(arg, entity_uid_mapper)?],
                    })),
                    without_id(cel_ast::Expr::Literal(CelVal::Int(0))),
                ],
            })), 
        },
        cedar_ast::ExprKind::Var(var) => without_id_res(cel_ast::Expr::Ident(var.to_string())),
        cedar_ast::ExprKind::Lit(lit) => without_id_res(match lit {
            cedar_ast::Literal::Bool(b) => cel_ast::Expr::Literal(CelVal::Boolean(*b)),
            cedar_ast::Literal::String(s) => cel_ast::Expr::Literal(CelVal::String(s.to_string())),
            cedar_ast::Literal::Long(l) => cel_ast::Expr::Literal(CelVal::Int(*l)),
            cedar_ast::Literal::EntityUID(uid) => cel_ast::Expr::Ident(entity_uid_mapper.cel_identifier_for_entity(uid)),
        }),
        cedar_ast::ExprKind::Slot(_) => todo!(),
        cedar_ast::ExprKind::Unknown(_) => todo!(),
    }
}

mod test {
    use std::str::FromStr;

    use serde_json::json;

    #[test]
    fn test_cel_expression() {
        /*let program = cel_interpreter::Program::compile(
            r#"has(resource.stored.v1) && has(resource.stored.v1.spec) && resource.stored.v1.spec.nodeName == "node-1""#)
            .unwrap();*/
        let parser = cel::parser::Parser::default();
        let program = parser
            .parse(r#"has(resource.stored.v1) && has(resource.stored.v1.spec) && resource.stored.v1.spec.nodeName == "node-1""#)
            .unwrap();
        dbg!(&program);
        let mut context = cel::Context::default();
        context.add_variable_from_value("resource", cel::to_value(json!({
            "stored": {
            }
        })).unwrap());
        let result = cel::Value::resolve(&program, &context).unwrap();
        assert_eq!(result, cel::Value::Bool(true));
    }

    #[test]
    fn test_cel_expression_with_function() {
        fn starts_with(This(this): This<Arc<String>>, prefix: Arc<String>) -> bool {
            this.starts_with(prefix.as_str())
        }
        use std::sync::Arc;
        use cel::{Program, Context};
        use cel::extractors::This;
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

        let policy_set = cedar_policy::PolicySet::from_str(r#"permit(principal, action, resource) when {[1, 34].containsAll([1, 101, 34])};"#).unwrap();
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
                r#"[1, 101, 34].all(i, i in [1, 34])"#,
            ),
            (
                r#"(((core::VersionedPod::"3c0edf18-ae66-48ca-8309-4f2f94c5d4ae" has "v1") && ((core::VersionedPod::"3c0edf18-ae66-48ca-8309-4f2f94c5d4ae"["v1"]) has "spec")) && ((((core::VersionedPod::"3c0edf18-ae66-48ca-8309-4f2f94c5d4ae"["v1"])["spec"])["nodeName"]) == "node-1"))"#,
                r#"has(entity1.v1) && has(entity1.v1.spec) && entity1.v1.spec.nodeName == "node-1""#,
            ),
        ];
        for (cedar_expr, wanted_cel_expr) in tests {
            let cedar_expr = cedar_ast::Expr::from_str(cedar_expr).unwrap();
            let mut entity_uid_mapper = super::DefaultEntityToCelVariableMapper::new([]);
            let cel_expr = super::cedar_to_cel(&cedar_expr, &mut entity_uid_mapper).unwrap();
            assert_eq!(cel_expr.to_string().as_str(), wanted_cel_expr);
        }
    }
}