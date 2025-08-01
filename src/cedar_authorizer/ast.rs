/*
    Rewrites of the AST to support partially-unknown attributes of simple values, when Cedar TPE only supports that through entity references.

    The attributes that can be partially unknown of resources are:
    Of k8s::Resource:
    - (simple) resource.apiGroup                (during SubjectAccessReviews for *)
    - (simple) resource.resourceCombined        (during SubjectAccessReviews for *)
    - (simple) resource.name                    (during SubjectAccessReviews for *, or list/watch/deletecollection without fieldSelector .metadata.name)
    - (entityref) resource.namespace            (during SubjectAccessReviews for *, or cluster-wide list/watch/deletecollection for a namespaced resource)

    Of typed resources, e.g. core::secrets:
    - (simple) resource.name                    (during list/watch/deletecollection (without fieldSelector .metadata.name), and creates)
    - (entityref) resource.namespace            (during cluster-wide list/watch/deletecollection (without fieldSelector .metadata.namespace) for a namespaced resource)
      Note: Kubernetes disallows POST /api/v1/pods, i.e. a cluster-wide create request for a namespaced resource, so we always have the
      namespace available for creates if applicable.
    - (entityref) resource.request              (during create/update/patch requests)
    - (entityref) resource.stored               (during update/patch/delete/deletecollection requests)

    We will thus:
    - For each entity that is a resource accessible from some action in the Cedar k8s namespace, which also has the
      attribute resource.apiGroup, resource.resourceCombined, and resource.name, we will create a new entityref




    For the general case, if we have a policy which:
    - is relevant both in a request environment which this code cares about (i.e. has a resource type which is rewritten)
        and in a request environment which is not rewritten, and
    - actually references the rewritten value, e.g. resource.apiGroup
    - then we need to guard the change with an "if" statement as follows:
        resource.apiGroup => if (resource is k8s::Resource || resource is core::secrets) { resource.apiGroup.value } else { resource.apiGroup }
        (or the other way, depending on which set of resource types is bigger)
    - This means that the policy will typecheck afterwards in our rewritten policies, as well as all other ones.

    If a policy does not match any request environments that are NOT rewritten, then we can remove the if statement and just substitute
      resource.apiGroup => resource.apiGroup.value

    In our case, we will rewrite the same fields for all resource types, and we can enforce the invariant that policies cannot apply to
      any non-rewritten resource types for now.
*/

use std::collections::{HashMap, HashSet};

use cedar_policy_core::ast::ExprKind;
use cedar_policy_core::ast::{Expr, InternalName, Name, UnreservedId, Var};
use cedar_policy_core::expr_builder::ExprBuilder;
use cedar_policy_core::validator::json_schema::{self, EntityTypeKind, Fragment};
use cedar_policy_core::validator::RawName;

use crate::cedar_authorizer::SchemaError;
use crate::schema::core::K8S_NS;

pub(super) fn rewrite_schema(
    schema: &mut Fragment<RawName>,
    rewrite_resource_attr_to_entity: &HashMap<String, RawName>,
) -> Result<(), SchemaError> {
    let k8s_ns = schema
        .0
        .get(&K8S_NS)
        .ok_or(SchemaError::SchemaRewriteError(
            "Namespace k8s not found in schema".to_string(),
        ))?;

    let resource_types: HashSet<InternalName> = k8s_ns
        .actions
        .values()
        .flat_map(|action| action.applies_to.iter())
        .flat_map(|applies_to| applies_to.resource_types.iter())
        .map(|resource_type| resource_type.clone().qualify_with_name(K8S_NS.as_ref()))
        .collect();

    for resource_type in resource_types {
        let resource_type_ns = match schema.0.get_mut(&ns_of_internal_name(&resource_type)) {
            Some(ns) => ns,
            None => {
                return Err(SchemaError::SchemaRewriteError(format!(
                    "Namespace {} not found in schema",
                    resource_type.namespace()
                )))
            }
        };
        let id = UnreservedId::try_from(resource_type.basename().clone()).unwrap();
        let resource_type_name = match resource_type_ns.entity_types.get_mut(&id) {
            Some(resource_type) => resource_type,
            None => return Err(SchemaError::MissingResourceType(resource_type.to_string())),
        };
        match &mut resource_type_name.kind {
            EntityTypeKind::Standard(json_schema::StandardEntityType {
                shape:
                    json_schema::AttributesOrContext(json_schema::Type::Type {
                        ty:
                            json_schema::TypeVariant::Record(json_schema::RecordType {
                                attributes, ..
                            }),
                        ..
                    }),
                ..
            }) => {
                for (resource_attr_name, new_entity_type_name) in rewrite_resource_attr_to_entity {
                    if let Some(attr) = attributes.get_mut(resource_attr_name.as_str()) {
                        *attr = json_schema::TypeOfAttribute {
                            ty: json_schema::Type::Type {
                                ty: json_schema::TypeVariant::Entity {
                                    name: new_entity_type_name.clone(),
                                },
                                loc: None,
                            },
                            annotations: attr.annotations.clone(),
                            required: attr.required,
                        }
                    }
                }
            }
            _ => {
                return Err(SchemaError::SchemaRewriteError(format!(
                    "Resource type {resource_type} is not a standard entity record type as expected"
                )))
            }
        }
    }
    Ok(())
}

fn ns_of_internal_name(internal_name: &InternalName) -> Option<Name> {
    match internal_name.namespace().as_str() {
        "" => None,
        ns => Some(ns.parse().unwrap()),
    }
}

pub(super) fn rewrite_expr(expr: &Expr, substitutions: &HashSet<String>) -> Expr {
    // let (expr_kind, maybeloc, data) = expr.as_ref().clone().into_parts();
    match expr.expr_kind() {
        ExprKind::And { left, right } => Expr::and(
            rewrite_expr(left, substitutions),
            rewrite_expr(right, substitutions),
        ),
        ExprKind::BinaryApp { op, arg1, arg2 } => Expr::binary_app(
            *op,
            rewrite_expr(arg1, substitutions),
            rewrite_expr(arg2, substitutions),
        ),
        ExprKind::ExtensionFunctionApp { fn_name, args } => Expr::call_extension_fn(
            fn_name.clone(),
            args.iter()
                .map(|a| rewrite_expr(a, substitutions))
                .collect(),
        ),

        ExprKind::GetAttr {
            expr: get_expr,
            attr,
        } => {
            let is_resource = matches!(get_expr.expr_kind(), ExprKind::Var(Var::Resource));
            if is_resource && substitutions.contains(attr.as_str()) {
                return Expr::get_attr(expr.clone(), "value".into());
            } else {
                Expr::get_attr(rewrite_expr(get_expr, substitutions), attr.clone())
            }
        }
        ExprKind::HasAttr { expr, attr } => {
            Expr::has_attr(rewrite_expr(expr, substitutions), attr.clone())
        }

        ExprKind::If {
            test_expr,
            then_expr,
            else_expr,
        } => Expr::ite(
            rewrite_expr(test_expr, substitutions),
            rewrite_expr(then_expr, substitutions),
            rewrite_expr(else_expr, substitutions),
        ),
        ExprKind::Is { expr, entity_type } => {
            Expr::is_entity_type(rewrite_expr(expr, substitutions), entity_type.clone())
        }
        ExprKind::Like { expr, pattern } => {
            Expr::like(rewrite_expr(expr, substitutions), pattern.clone())
        }
        ExprKind::Or { left, right } => Expr::or(
            rewrite_expr(left, substitutions),
            rewrite_expr(right, substitutions),
        ),
        ExprKind::Record(attrs) => Expr::record(
            attrs
                .iter()
                .map(|(k, v)| (k.clone(), rewrite_expr(v, substitutions))),
        )
        .unwrap(),
        ExprKind::Set(items) => Expr::set(items.iter().map(|e| rewrite_expr(e, substitutions))),
        ExprKind::UnaryApp { op, arg } => Expr::unary_app(*op, rewrite_expr(arg, substitutions)),
        ExprKind::Var(var) => Expr::var(*var),
        ExprKind::Lit(lit) => Expr::val(lit.clone()),
        ExprKind::Slot(slot_id) => Expr::slot(*slot_id),
        ExprKind::Unknown(unknown) => Expr::unknown(unknown.clone()),
    }
    .with_maybe_source_loc(expr.source_loc().cloned())
}

mod test {
    #[test]
    fn test_parse_policy() {
        // Empirically test how the parser handles absence of parentheses.
        use cedar_policy::PolicySet;
        let policy1: PolicySet = "permit(principal, action, resource) when { (principal.a == resource.b && resource.c == principal.d) && resource.d == principal.e };".parse().unwrap();
        println!("{}", policy1);
        let json_policy1 = policy1.to_json().unwrap();
        let json_str = serde_json::to_string_pretty(&json_policy1).unwrap();
        println!("{json_str}");

        let policy2: PolicySet = "permit(principal, action, resource) when { principal.a == resource.b && resource.c == principal.d && resource.d == principal.e };".parse().unwrap();
        let json_policy2 = policy2.to_json().unwrap();

        assert!(json_policy1 == json_policy2);
    }

    #[test]
    fn test_typechecker() {
        use cedar_policy::PolicySet;
        use cedar_policy_core::extensions::Extensions;
        use cedar_policy_core::validator::json_schema::Fragment;
        use cedar_policy_core::validator::typecheck::PolicyCheck;
        use cedar_policy_core::validator::typecheck::Typechecker;
        use cedar_policy_core::validator::ValidatorSchema;
        let (schema, _) = Fragment::from_cedarschema_str(
            include_str!("testfiles/simple.cedarschema"),
            Extensions::all_available(),
        )
        .unwrap();
        let validator_schema: ValidatorSchema = schema.try_into().unwrap();

        let policyset: PolicySet = r#"permit(principal, action == k8s::Action::"get", resource) when { resource has apiGroup };"#.parse().unwrap();
        let policy = policyset.policies().next().unwrap();
        let type_checker = Typechecker::new(
            &validator_schema,
            cedar_policy_core::validator::ValidationMode::Strict,
        );
        let result = type_checker.typecheck_by_request_env(policy.as_ref().template());
        for (env, check) in result {
            match check {
                PolicyCheck::Success(_) => {
                    println!(
                        "Success: {} {} {} {}",
                        env.principal_type(),
                        env.action_entity_uid().unwrap(),
                        env.resource_type(),
                        env.context_type()
                    );
                }
                PolicyCheck::Irrelevant(_, _) => {
                    println!(
                        "Irrelevant: {} {} {} {}",
                        env.principal_type(),
                        env.action_entity_uid().unwrap(),
                        env.resource_type(),
                        env.context_type()
                    );
                }
                PolicyCheck::Fail(_) => {
                    println!(
                        "Fail: {} {} {} {}",
                        env.principal_type(),
                        env.action_entity_uid().unwrap(),
                        env.resource_type(),
                        env.context_type()
                    );
                }
            }
        }
    }

    #[test]
    fn test_has_resource_attribute() {
        use super::rewrite_expr;
        use cedar_policy_core::ast::Expr;
        use std::collections::HashSet;

        let expr: Expr<()> = r#"resource.apiGroup == "foo""#.parse().unwrap();
        assert_eq!(
            rewrite_expr(&expr, &HashSet::from([])).to_string(),
            r#"(resource["apiGroup"]) == "foo""#
        );

        let expr: Expr<()> = r#"resource.apiGroup == "foo""#.parse().unwrap();
        assert_eq!(
            rewrite_expr(&expr, &HashSet::from(["apiGroup".to_string()])).to_string(),
            r#"((resource["apiGroup"])["value"]) == "foo""#
        );

        let expr: Expr<()> = r#"resource.apiGroup == "foo" && [resource.name].contains("bar")"#
            .parse()
            .unwrap();
        assert_eq!(
            rewrite_expr(
                &expr,
                &HashSet::from(["apiGroup".to_string(), "name".to_string()])
            )
            .to_string(),
            r#"(((resource["apiGroup"])["value"]) == "foo") && ([(resource["name"])["value"]].contains("bar"))"#
        );

        /*let expr: Expr<()> = r#"resource.apiGroup == "foo""#.parse().unwrap();
        assert!(!has_resource_attribute(&expr, &HashSet::from([])));

        let expr: Expr<()> = r#"principal.apiGroup == "foo""#.parse().unwrap();
        assert!(!has_resource_attribute(&expr, &HashSet::from(["apiGroup".to_string()])));

        let expr: Expr<()> = r#"resource.apiGroup == "foo""#.parse().unwrap();
        assert!(has_resource_attribute(&expr, &HashSet::from(["apiGroup".to_string()])));

        let expr: Expr<()> = r#"resource has apiGroup"#.parse().unwrap();
        assert!(has_resource_attribute(&expr, &HashSet::from(["apiGroup".to_string()])));

        let expr: Expr<()> = r#"resource.apiGroup.foobar"#.parse().unwrap();
        assert!(has_resource_attribute(&expr, &HashSet::from(["apiGroup".to_string()])));

        let expr: Expr<()> = r#"principal.name == "foo" && resource.apiGroup == "foo""#.parse().unwrap();
        assert!(has_resource_attribute(&expr, &HashSet::from(["apiGroup".to_string()])));*/
    }

    #[test]
    fn test_rewrite_schema() {
        use super::rewrite_schema;
        use cedar_policy_core::extensions::Extensions;
        use cedar_policy_core::validator::json_schema::Fragment;
        use std::collections::HashMap;
        use std::io::Write;
        let (mut schema, _) = Fragment::from_cedarschema_str(
            include_str!("testfiles/rewrite-schema/before.cedarschema"),
            Extensions::all_available(),
        )
        .unwrap();
        let rewrite_resource_attr_to_entity = HashMap::from([
            ("foo".to_string(), "meta::UnknownString".parse().unwrap()),
            ("bar".to_string(), "meta::UnknownString".parse().unwrap()),
        ]);
        rewrite_schema(&mut schema, &rewrite_resource_attr_to_entity).unwrap();
        let got_schema_str = schema.to_cedarschema().unwrap();
        println!("{got_schema_str}");
        // assert test schema file is already formatted
        if got_schema_str != include_str!("testfiles/rewrite-schema/after.cedarschema") {
            let mut f = std::fs::File::create("src/cedar_authorizer/testfiles/rewrite-schema/after.cedarschema")
                .expect("open file works");
            f.write_all(got_schema_str.as_bytes())
                .expect("write to work");
            assert_eq!("actual", "expected")
        }
    }
}
