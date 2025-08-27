use std::{collections::HashMap, marker::PhantomData, sync::Arc};

use crate::{
    cedar_authorizer::kube_invariants,
    k8s_authorizer::{self, Attributes, RequestType, StarWildcardStringSelector, SymbolicEvaluationError},
};
use cedar_policy_core::{ast, expr_builder::ExprBuilder};
use cedar_policy_symcc::{err::SolverError, solver::Solver, CedarSymCompiler};
use itertools::Itertools;
use nonempty::NonEmpty;
use smol_str::{SmolStr, ToSmolStr};

use super::fork::LocalSolver;

#[derive(Debug, thiserror::Error)]
pub enum SolverFactoryError {
    #[error(transparent)]
    SolverError(#[from] SolverError),
    #[error(transparent)]
    ParserError(#[from] cedar_policy_symcc::err::Error),
}

pub trait SolverFactory<S: Solver> {
    fn new_solver(&self) -> Result<S, SolverFactoryError>;

    fn new_sym_compiler(&self) -> Result<CedarSymCompiler<S>, SolverFactoryError> {
        Ok(CedarSymCompiler::new(self.new_solver()?)?)
    }
}

pub struct LocalSolverFactory;

impl SolverFactory<LocalSolver> for LocalSolverFactory {
    fn new_solver(&self) -> Result<LocalSolver, SolverFactoryError> {
        Ok(LocalSolver::cvc5()?)
    }
}

pub struct SymbolicEvaluator<F: SolverFactory<S>, S: Solver> {
    symcc_factory: F,
    schema: Arc<kube_invariants::Schema>,
    _marker: PhantomData<S>,
}

impl<F: SolverFactory<S>, S: Solver> SymbolicEvaluator<F, S> {
    pub fn new(
        schema: Arc<kube_invariants::Schema>,
        symcc_factory: F,
    ) -> Result<Self, SolverFactoryError> {
        Ok(Self {
            schema,
            symcc_factory,
            _marker: PhantomData,
        })
    }

    pub async fn selector_conditions_are_authorized(
        &self,
        attrs: &Attributes,
        reqenv: &cedar_policy::RequestEnv,
        is_authorized: kube_invariants::PolicySet,
        unknown_jsonpaths_to_uid: HashMap<String, ast::EntityUID>,
        api_version: &StarWildcardStringSelector,
        namespace_scoped: bool,
    ) -> Result<bool, SymbolicEvaluationError> {
        let cedar_public_api_schema_ref = self.schema.as_ref().as_ref();
        let symenv = cedar_policy_symcc::SymEnv::new(cedar_public_api_schema_ref, reqenv)?;

        // TODO: Can we make registering unknowns type-safe by using an enum?

        // TODO: Figure out how errors are handled when a well-typed Cedar PolicySet is
        // mapped into an SMT Term. Do the semantics of "one allow policy erroring does not affect other allow policies"
        // hold also in the translation?

        // IMPORTANT: If there are no other requirements in object_selected, it must default to "true", just in case.
        // Cedar by default turns PolicySets into SMT Terms through the "is_authorized" function, and naturally,
        // whether an PolicySet authorizes a principal is a static false. However, if object_selected == false, it means
        // object_selected => is_authorized is a tautology, regardless of is_authorized. In our case, it is kind of the
        // opposite: absence of restrictions on the request object means that every object selected, and thus should
        // object_selected == true. However, if object_selected == true, then the invariant "object_selected => is_authorized"
        // is equivalent to "is_authorized". However, if we got here, we kind of already know that is_authorized is not
        // true, in that case a condition wouldn't most likely have been returned in the first place. However, there can still
        // be some weird corner cases where this happens, e.g. in "resource.name == resource.name" for create requests where it is
        // kept unknown; and thus in order to keep precision, we invoke the SMT solver anyways to check.
        let mut object_selected_expr: ast::Expr<()> = ast::ExprBuilder::new().val(true);

        // The following values can be unknown today:
        // For resource requests:
        // - resource.apiGroup: "any" if unknown => no restrictions in object_selected
        // - resource.resourceCombined: "any" if unknown => no restrictions in object_selected
        // - resource.namespace: either "any" or In/NotIn semantics from the field selector.
        // - resource.namespaceMetadata: The SAR request does not support enforcing any conditions on this, so needs to be kept as "any".
        // - resource.name: "any" or In/NotIn semantics from the field selector.
        // - resource.request.metadata: not supported, selectors operate only on data in storage
        // - resource.request.vX: not supported, selectors operate only on data in storage
        // - resource.stored.vX.metadata: field and label selectors can apply, but only to namespace and name.
        // - resource.stored.vX: field and label selectors can apply to any selectable field.
        // For non-resource requests:
        // - resource.path: "any" if unknown => no restrictions in object_selected

        match &attrs.request_type {
            RequestType::Resource(resource_attrs) => {
                object_selected_expr = apply_field_selectors_to_expr(
                    object_selected_expr,
                    resource_attrs.field_selector.as_ref(),
                    &unknown_jsonpaths_to_uid,
                    api_version,
                    namespace_scoped,
                );

                object_selected_expr = apply_label_selectors_to_expr(
                    object_selected_expr,
                    resource_attrs.label_selector.as_ref(),
                    &unknown_jsonpaths_to_uid,
                );
            }
            RequestType::NonResource(_) => (),
        }

        //println!("jsonpaths_to_uid: {unknown_jsonpaths_to_uid:?}, api_version: {api_version}, namespace_scoped: {namespace_scoped}");
        //println!("object_selected_expr: {object_selected_expr}");
        //println!("is_authorized: {is_authorized}");

        // TODO: Cedar to implement FromStr for PolicyID, and then use that.
        let object_selected =
            cedar_policy::PolicySet::from_policies([ast::Policy::from_when_clause(
                ast::Effect::Permit,
                object_selected_expr,
                ast::PolicyID::from_string("object_selected"),
                None,
            )
            .into()])?;

        let well_typed_object_selected = cedar_policy_symcc::WellTypedPolicies::from_policies(
            &object_selected,
            reqenv,
            cedar_public_api_schema_ref,
        )?;
        // Convert the kube_invariants::PolicySet to a cedar_policy::PolicySet.
        let is_authorized: cedar_policy::PolicySet = is_authorized.try_into()?;
        let well_typed_is_authorized = cedar_policy_symcc::WellTypedPolicies::from_policies(
            &is_authorized,
            reqenv,
            cedar_public_api_schema_ref,
        )?;
        // Enforce invariant that object_selected => is_authorized.
        // TODO: If some debug logging (or request-level, even, up to some DoS budget) is enabled,
        // then give a concrete counterexample too.
        let mut symcc = self.symcc_factory.new_sym_compiler()?;

        let selectors_authorized = symcc
            .check_implies_with_counterexample(
                &well_typed_object_selected,
                &well_typed_is_authorized,
                &symenv,
            )
            .await?;
        Ok(match selectors_authorized {
            Some(_counterexample) => {
                //let mut buf = Vec::new();
                //counterexample.entities.write_to_json(&mut buf).unwrap();
                //println!("counterexample: {}", String::from_utf8_lossy(&buf));
                false
            }
            None => true,
        })
    }
}

fn apply_field_selectors_to_expr(
    mut object_selected_expr: ast::Expr<()>,
    field_selectors: Option<&Vec<k8s_authorizer::Selector>>,
    unknown_jsonpaths_to_uid: &HashMap<String, ast::EntityUID>,
    api_version: &StarWildcardStringSelector,
    namespace_scoped: bool,
) -> ast::Expr<()> {
    if let Some(field_selectors) = field_selectors {
        for field_selector in field_selectors {
            if let Some(expr) = field_selector_to_expr(
                field_selector,
                unknown_jsonpaths_to_uid,
                api_version,
                namespace_scoped,
            ) {
                object_selected_expr = object_selected_expr.and(expr);
            }
        }
    }
    object_selected_expr
}

fn field_selector_to_expr(
    field_selector: &k8s_authorizer::Selector,
    unknown_jsonpaths_to_uid: &HashMap<String, ast::EntityUID>,
    api_version: &StarWildcardStringSelector,
    namespace_scoped: bool,
) -> Option<ast::Expr<()>> {
    // Trim "." prefix, if any. TODO: This invariant should probably be in the parsing layer.
    let key = field_selector
        .key
        .strip_prefix(".")
        .unwrap_or(field_selector.key.as_str());

    let (field_exists, field) = match key.strip_prefix("metadata.") {
        Some("name") => {
            // Note: If resource.name does not exist in unknown_jsonpaths_to_uid, it means that the variable is not used in is_authorized.
            // If that is the case, then there is no need to restrict the variable's scope in object_selected, as whatever the variable
            // value is, it won't affect the is_authorized value. Thus return None if not referenced.
            (
                ast::Expr::val(true),
                ast::Expr::val(unknown_jsonpaths_to_uid.get("resource.name")?.clone())
                    .get_attr("value"),
            )
        }
        // TODO: Is the handling of namespace/cluster-scoped resources here correct?
        Some("namespace") => (
            ast::Expr::val(namespace_scoped),
            ast::Expr::val(unknown_jsonpaths_to_uid.get("resource.namespace")?.clone())
                .get_attr("value"),
        ),
        // TODO: Do we need to support other metadata fields?
        // For now, ignoring the requirement here is sound, because objectSelected becomes wider than if this was implemented.
        // TODO: Check if there are any metadata fieldselectors.
        Some(_) => return None,
        _ => {
            let api_version = match api_version {
                StarWildcardStringSelector::Exact(api_version) => api_version,
                // If the api_version is unknown, then we can't apply the field selector.
                // This is still sound, because it means that objectSelected(o) returns true for a wider
                // range of objects, compared to if this field selector was applied.
                StarWildcardStringSelector::Any => return None,
            };
            let object = ast::Expr::val(
                unknown_jsonpaths_to_uid
                    .get(format!("resource.stored.{api_version}").as_str())?
                    .clone(),
            );

            let field_exists = super::fork::construct_exprs_extended_has::<ast::ExprBuilder<()>>(
                object.clone(),
                &NonEmpty::collect(key.split(".").map(|s| s.to_smolstr()))
                    .expect("str.split yields at least one item"),
                None,
            );

            let mut field = object;
            for field_part in key.split(".") {
                field = field.get_attr(field_part);
            }

            (field_exists, field)
        }
    };

    match &field_selector.op {
        k8s_authorizer::SelectorPredicate::Exists => {
            // object has spec.nodeName
            Some(field_exists)
        }
        k8s_authorizer::SelectorPredicate::NotExists => {
            // !(object has spec.nodeName)
            Some(field_exists.not())
        }
        k8s_authorizer::SelectorPredicate::In(values) => {
            // TODO: Implement more than just string support; needs to check the type of the variable from the schema.
            // TODO: We might want to optimize this when values.len() == 1 to use == or !=
            let specified_set =
                ast::Expr::set(values.iter().sorted().map(|v| ast::Expr::val(v.as_str())));
            // object has spec.nodeName && ["node1", "node2"].contains(object.spec.nodeName)
            Some(field_exists.and(specified_set.contains(field)))
        }
        k8s_authorizer::SelectorPredicate::NotIn(values) => {
            let specified_set =
                ast::Expr::set(values.iter().sorted().map(|v| ast::Expr::val(v.as_str())));
            // object has spec.nodeName && !["node1", "node2"].contains(object.spec.nodeName)
            Some(field_exists.and(specified_set.contains(field).not()))
        }
    }
}

fn apply_label_selectors_to_expr(
    mut object_selected_expr: ast::Expr<()>,
    label_selectors: Option<&Vec<k8s_authorizer::Selector>>,
    unknown_jsonpaths_to_uid: &HashMap<String, ast::EntityUID>,
) -> ast::Expr<()> {
    if let Some(label_selectors) = label_selectors {
        if !label_selectors.is_empty() {
            if let Some(metadata) =
                unknown_jsonpaths_to_uid.get("resource.stored.metadata".to_string().as_str())
            {
                let metadata_entity = ast::Expr::val(metadata.clone());

                let labels_guard = metadata_entity.clone().has_attr("labels");
                object_selected_expr = object_selected_expr.and(labels_guard);

                let labels_entity = metadata_entity.get_attr("labels");
                for label_selector in label_selectors {
                    let label_expr = label_selector_to_expr(label_selector, labels_entity.clone());
                    object_selected_expr = object_selected_expr.and(label_expr);
                }
            }
        }
    }
    object_selected_expr
}

fn label_selector_to_expr(
    label_selector: &k8s_authorizer::Selector,
    labels_entity: ast::Expr<()>,
) -> ast::Expr<()> {
    let label_exists = labels_entity
        .clone()
        .has_tag(ast::Expr::val(label_selector.key.to_smolstr()));
    match &label_selector.op {
        k8s_authorizer::SelectorPredicate::Exists => {
            // labels_entity.hasTag(key)
            label_exists
        }
        k8s_authorizer::SelectorPredicate::NotExists => {
            // !(labels_entity.hasTag(key))
            label_exists.not()
        }
        k8s_authorizer::SelectorPredicate::In(values) => {
            // TODO: We might want to optimize this when values.len() == 1 to use == or !=
            let specified_set =
                ast::Expr::set(values.iter().sorted().map(|v| ast::Expr::val(v.as_str())));
            // labels_entity.hasTag(key) && ["node1", "node2"].contains(labels_entity.getTag(key))
            label_exists.and(
                specified_set.contains(
                    labels_entity.get_tag(ast::Expr::val(label_selector.key.to_smolstr())),
                ),
            )
        }
        k8s_authorizer::SelectorPredicate::NotIn(values) => {
            let specified_set =
                ast::Expr::set(values.iter().sorted().map(|v| ast::Expr::val(v.as_str())));
            // labels_entity.hasTag(key) && !["node1", "node2"].contains(labels_entity.getTag(key))
            label_exists.and(
                specified_set
                    .contains(
                        labels_entity.get_tag(ast::Expr::val(label_selector.key.to_smolstr())),
                    )
                    .not(),
            )
        }
    }
}

trait WithExprBuilder: Sized {
    fn and<T: Into<ast::Expr<()>>>(self, other: T) -> Self;
    fn get_attr<T: Into<SmolStr>>(self, attr: T) -> Self;
    fn has_attr<T: Into<SmolStr>>(self, attr: T) -> Self;
    fn not(self) -> Self;
    fn contains<T: Into<ast::Expr<()>>>(self, value: T) -> Self;
    fn has_tag<T: Into<ast::Expr<()>>>(self, tag: T) -> Self;
    fn get_tag<T: Into<ast::Expr<()>>>(self, tag: T) -> Self;
}

impl WithExprBuilder for ast::Expr<()> {
    fn and<T: Into<ast::Expr<()>>>(self, other: T) -> Self {
        ast::Expr::and(self, other.into())
    }
    fn get_attr<T: Into<SmolStr>>(self, attr: T) -> Self {
        ast::Expr::get_attr(self, attr.into())
    }
    fn has_attr<T: Into<SmolStr>>(self, attr: T) -> Self {
        ast::Expr::has_attr(self, attr.into())
    }
    fn not(self) -> Self {
        ast::Expr::not(self)
    }
    fn contains<T: Into<ast::Expr<()>>>(self, value: T) -> Self {
        ast::Expr::contains(self, value.into())
    }
    fn has_tag<T: Into<ast::Expr<()>>>(self, tag: T) -> Self {
        ast::Expr::has_tag(self, tag.into())
    }
    fn get_tag<T: Into<ast::Expr<()>>>(self, tag: T) -> Self {
        ast::Expr::get_tag(self, tag.into())
    }
}

mod test {
    

    #[test]
    fn test_field_selector_to_expr() {
        use crate::k8s_authorizer;
        use std::collections::{HashMap, HashSet};
        use crate::k8s_authorizer::StarWildcardStringSelector;
        let tests = vec![
            (
                "None if metadata.name is not referenced in is_authorized",
                k8s_authorizer::Selector{
                    key: "metadata.name".to_string(),
                    op: k8s_authorizer::SelectorPredicate::In(HashSet::from(["node1".to_string(), "node2".to_string()])),
                },
                HashMap::new(),
                StarWildcardStringSelector::Any,
                true,
                None,
            ),
            (
                "None if metadata.namespace is not referenced in is_authorized",
                k8s_authorizer::Selector{
                    key: "metadata.namespace".to_string(),
                    op: k8s_authorizer::SelectorPredicate::In(HashSet::from(["ns1".to_string(), "ns2".to_string()])),
                },
                HashMap::new(),
                StarWildcardStringSelector::Any,
                true,
                None,
            ),
            (
                "None if spec.nodeName is not referenced in is_authorized",
                k8s_authorizer::Selector{
                    key: "spec.nodeName".to_string(),
                    op: k8s_authorizer::SelectorPredicate::In(HashSet::from(["node1".to_string(), "node2".to_string()])),
                },
                HashMap::new(),
                StarWildcardStringSelector::Any,
                true,
                None,
            ),
            (
                "Simple metadata.name case, with In predicate and leading dot",
                k8s_authorizer::Selector{
                    key: ".metadata.name".to_string(),
                    op: k8s_authorizer::SelectorPredicate::In(HashSet::from(["node1".to_string(), "node2".to_string()])),
                },
                HashMap::from([("resource.name".to_string(), r#"meta::UnknownString::"foo""#.parse().unwrap())]),
                StarWildcardStringSelector::Any,
                true,
                Some(r#"true && (["node1", "node2"].contains(meta::UnknownString::"foo"["value"]))"#.to_string()),
            ),
            (
                "Simple metadata.namespace case, with In predicate and leading dot, for namespace-scoped resource",
                k8s_authorizer::Selector{
                    key: ".metadata.namespace".to_string(),
                    op: k8s_authorizer::SelectorPredicate::In(HashSet::from(["ns1".to_string(), "ns2".to_string()])),
                },
                HashMap::from([("resource.namespace".to_string(), r#"meta::UnknownString::"foo""#.parse().unwrap())]),
                StarWildcardStringSelector::Any,
                true,
                Some(r#"true && (["ns1", "ns2"].contains(meta::UnknownString::"foo"["value"]))"#.to_string()),
            ),
            (
                "Simple metadata.namespace case, with In predicate and leading dot, for cluster-scoped resource",
                k8s_authorizer::Selector{
                    key: ".metadata.namespace".to_string(),
                    op: k8s_authorizer::SelectorPredicate::In(HashSet::from(["ns1".to_string(), "ns2".to_string()])),
                },
                HashMap::from([("resource.namespace".to_string(), r#"meta::UnknownString::"foo""#.parse().unwrap())]),
                StarWildcardStringSelector::Any,
                false,
                Some(r#"false && (["ns1", "ns2"].contains(meta::UnknownString::"foo"["value"]))"#.to_string()),
            ),
            (
                "Simple spec.nodeName case, with In predicate",
                k8s_authorizer::Selector{
                    key: ".spec.nodeName".to_string(),
                    op: k8s_authorizer::SelectorPredicate::In(HashSet::from(["node1".to_string(), "node2".to_string()])),
                },
                HashMap::from([("resource.stored.v1".to_string(), r#"core::V1Node::"foo""#.parse().unwrap())]),
                StarWildcardStringSelector::Exact("v1".to_string()),
                true,
                Some(r#"((core::V1Node::"foo" has "spec") && ((core::V1Node::"foo"["spec"]) has "nodeName")) && (["node1", "node2"].contains((core::V1Node::"foo"["spec"])["nodeName"]))"#.to_string()),
            ),
            (
                "Simple spec.nodeName case, with In predicate, but unknown apiVersion",
                k8s_authorizer::Selector{
                    key: ".spec.nodeName".to_string(),
                    op: k8s_authorizer::SelectorPredicate::In(HashSet::from(["node1".to_string(), "node2".to_string()])),
                },
                HashMap::from([("resource.stored.v1".to_string(), r#"core::V1Node::"foo""#.parse().unwrap())]),
                StarWildcardStringSelector::Any,
                true,
                None,
            ),
        ];
        for (
            test_name,
            field_selector,
            unknown_jsonpaths_to_uid,
            api_version,
            namespace_scoped,
            expected_expr,
        ) in tests
        {
            println!("test_name: {test_name}");
            let got = super::field_selector_to_expr(
                &field_selector,
                &unknown_jsonpaths_to_uid,
                &api_version,
                namespace_scoped,
            );
            if let Some(expr) = got.clone() {
                println!("got: {expr}");
            }
            assert_eq!(got.map(|e| e.to_string()), expected_expr);
        }
    }

    #[test]
    fn test_apply_label_selectors_to_expr() {
        use crate::k8s_authorizer;
        use cedar_policy_core::ast;
        use std::collections::{HashMap, HashSet};
        let tests = vec![
            (
                "None if resource.stored.metadata.labels.foo is not referenced in is_authorized",
                vec![k8s_authorizer::Selector {
                    key: "foo".to_string(),
                    op: k8s_authorizer::SelectorPredicate::In(HashSet::from([
                        "bar".to_string(),
                        "baz".to_string(),
                    ])),
                }],
                HashMap::new(),
                "true",
            ),
            (
                "Simple case, with In predicate",
                vec![k8s_authorizer::Selector {
                    key: "foo".to_string(),
                    op: k8s_authorizer::SelectorPredicate::In(HashSet::from([
                        "bar".to_string(),
                        "baz".to_string(),
                    ])),
                }],
                HashMap::from([(
                    "resource.stored.metadata".to_string(),
                    r#"meta::V1ObjectMeta::"foo""#.parse().unwrap(),
                )]),
                r#"(true && (meta::V1ObjectMeta::"foo" has "labels")) && (((meta::V1ObjectMeta::"foo"["labels"]).hasTag("foo")) && (["bar", "baz"].contains((meta::V1ObjectMeta::"foo"["labels"]).getTag("foo"))))"#,
            ),
            (
                "One In and one NotIn predicate; metadata has labels not duplicated",
                vec![
                    k8s_authorizer::Selector {
                        key: "foo".to_string(),
                        op: k8s_authorizer::SelectorPredicate::In(HashSet::from([
                            "bar".to_string(),
                            "baz".to_string(),
                        ])),
                    },
                    k8s_authorizer::Selector {
                        key: "bar".to_string(),
                        op: k8s_authorizer::SelectorPredicate::NotIn(HashSet::from([
                            "qux".to_string(),
                            "quux".to_string(),
                        ])),
                    },
                ],
                HashMap::from([(
                    "resource.stored.metadata".to_string(),
                    r#"meta::V1ObjectMeta::"foo""#.parse().unwrap(),
                )]),
                r#"(
                    (
                     true && 
                     (meta::V1ObjectMeta::"foo" has "labels")
                    ) && 
                    (
                     ((meta::V1ObjectMeta::"foo"["labels"]).hasTag("foo")) && 
                     (["bar", "baz"].contains((meta::V1ObjectMeta::"foo"["labels"]).getTag("foo"))
                    )
                   )
                  ) && 
                  (!(
                     ((meta::V1ObjectMeta::"foo"["labels"]).hasTag("bar")) && 
                     (["quux", "qux"].contains((meta::V1ObjectMeta::"foo"["labels"]).getTag("bar"))
                    )
                  )
                 )"#,
            ),
        ];
        for (test_name, label_selectors, unknown_jsonpaths_to_uid, expected_expr) in tests {
            println!("test_name: {test_name}");
            let mut object_selected_expr = ast::Expr::val(true);
            object_selected_expr = super::apply_label_selectors_to_expr(
                object_selected_expr,
                Some(&label_selectors),
                &unknown_jsonpaths_to_uid,
            );
            assert_eq!(
                object_selected_expr.to_string(),
                remove_whitespace(expected_expr.to_string())
            );
        }
    }

    #[cfg(test)]
    fn remove_whitespace(mut current: String) -> String {
        loop {
            let replaced = current.replace("  ", " ").replace("\n", "");
            if replaced == current {
                return current;
            }
            current = replaced;
        }
    }

    #[tokio::test]
    async fn test_symcc() {
        let cvc5 = cedar_policy_symcc::solver::LocalSolver::cvc5().unwrap();
        /*let cvc5_wrapped = cvc5.wrap(
            |w| cedar_policy_symcc::capture::CaptureWriter::new(w),
            |r| cedar_policy_symcc::capture::CaptureReader::new(r),
        );*/
        let mut symcc = cedar_policy_symcc::CedarSymCompiler::new(cvc5).unwrap();

        let reqenv = cedar_policy::RequestEnv::new(
            "k8s::User".parse().unwrap(),
            r#"k8s::Action::"get""#.parse().unwrap(),
            "core::pods".parse().unwrap(),
        );

        let object_selected_pset = include_str!("testfiles/object_selected.cedar")
            .parse()
            .unwrap();
        let is_authorized_pset = include_str!("testfiles/is_authorized.cedar")
            .parse()
            .unwrap();

        let (schema, _) = cedar_policy::Schema::from_cedarschema_str(include_str!(
            "testfiles/simple.cedarschema"
        ))
        .unwrap();
        let symenv = cedar_policy_symcc::SymEnv::new(&schema, &reqenv).unwrap();
        let object_selected_wtpset = cedar_policy_symcc::WellTypedPolicies::from_policies(
            &object_selected_pset,
            &reqenv,
            &schema,
        )
        .unwrap();
        let is_authorized_wtpset = cedar_policy_symcc::WellTypedPolicies::from_policies(
            &is_authorized_pset,
            &reqenv,
            &schema,
        )
        .unwrap();
        let result = symcc
            .check_implies_with_counterexample(
                &object_selected_wtpset,
                &is_authorized_wtpset,
                &symenv,
            )
            .await
            .unwrap()
            .unwrap();

        println!(
            "{}",
            result
                .request
                .principal()
                .map(|r| r.to_string())
                .unwrap_or("<none>".to_string())
        );
        println!(
            "{}",
            result
                .request
                .action()
                .map(|r| r.to_string())
                .unwrap_or("<none>".to_string())
        );
        println!(
            "{}",
            result
                .request
                .resource()
                .map(|r| r.to_string())
                .unwrap_or("<none>".to_string())
        );
        println!("{}", result.entities.to_dot_str());
        // println!("{}", String::from_utf8(capture_solver.writer.captured_data().to_vec()).unwrap());
        result
            .entities
            .write_to_json(
                std::fs::File::create_new("src/cedar_authorizer/testfiles/symcc_result.json")
                    .unwrap(),
            )
            .unwrap();
        assert!(false);
    }
}
