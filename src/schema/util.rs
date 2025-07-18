use std::collections::BTreeMap;
use std::ops::Deref;
use std::str::FromStr;

use cedar_policy_core::ast::Name;
use cedar_policy_core::validator::json_schema::AttributesOrContext;
use cedar_policy_core::validator::json_schema::RecordType;
use cedar_policy_core::validator::json_schema::Type;
use cedar_policy_core::validator::json_schema::TypeVariant;
use cedar_policy_core::validator::json_schema::{
    ApplySpec, EntityType, EntityTypeKind, Fragment, NamespaceDefinition, StandardEntityType,
};
use cedar_policy_core::validator::RawName;

use super::types::{ActionUID, CedarTypeName, TypeWrapper};

use super::err::{Result, SchemaProcessingError};

use super::core::META_NS;

pub(crate) fn namespace_of_fragment(
    fragment: &mut Fragment<RawName>,
    ns: Option<Name>,
) -> &mut NamespaceDefinition<RawName> {
    fragment.0.entry(ns).or_insert_with(|| NamespaceDefinition {
        annotations: Default::default(),
        actions: Default::default(),
        common_types: Default::default(),
        entity_types: Default::default(),
    })
}

pub(crate) fn applyspec_for_action<'a>(
    action_ns: &'a mut NamespaceDefinition<RawName>,
    actionuid: &ActionUID,
) -> Result<&'a mut ApplySpec<RawName>> {
    let action = action_ns
        .actions
        .get_mut(actionuid.1.as_str())
        .ok_or_else(|| SchemaProcessingError::ActionNotDefined(actionuid.clone()))?;

    Ok(action.applies_to.get_or_insert_with(|| ApplySpec {
        resource_types: Default::default(),
        principal_types: Default::default(), // TODO: Where is the action authoratively defined?
        context: Default::default(),
    }))
}

pub fn make_stringmap_type(val_ty: Type<RawName>) -> Option<(CedarTypeName, EntityType<RawName>)> {
    match get_type_name(&val_ty, false) {
        Some((ns, val_ty_name)) => Some((
            CedarTypeName::new(ns, &format!("StringTo{val_ty_name}Map")).unwrap(),
            EntityType {
                kind: EntityTypeKind::Standard(StandardEntityType {
                    member_of_types: Vec::new(),
                    shape: AttributesOrContext(Type::Type {
                        ty: TypeVariant::Record(RecordType {
                            attributes: BTreeMap::from([(
                                "keys".into(),
                                TypeWrapper::Set(Box::new(TypeWrapper::String)).required(),
                            )]),
                            additional_attributes: false,
                        }),
                        loc: None,
                    }),
                    tags: Some(val_ty),
                }),
                annotations: Default::default(),
                loc: Default::default(),
            },
        )),
        None => None,
    }
}

// builds the name of the map entity type, for a given value type. If the value type
// is a simple type, the entity lives in the meta namespace, otherwise, it lives in
// the same namespace as the type being referred to.
fn get_type_name(val_ty: &Type<RawName>, is_set_elem: bool) -> Option<(Option<Name>, String)> {
    match val_ty {
        Type::Type { ty, .. } => match ty {
            TypeVariant::String => Some((META_NS.clone(), "String".to_string())),
            TypeVariant::Long => Some((META_NS.clone(), "Long".to_string())),
            TypeVariant::Boolean => Some((META_NS.clone(), "Boolean".to_string())),
            TypeVariant::Set {
                element: inner_set_elem,
            } => match is_set_elem {
                true => None, // Don't support nested sets for now
                false => get_type_name(inner_set_elem.deref(), true)
                    .map(|(ns, name)| (ns, format!("{name}Set"))),
            },
            TypeVariant::Entity { name } => Some(split_rawname(name)),
            TypeVariant::EntityOrCommon { type_name } => Some(split_rawname(type_name)),
            _ => None,
        },
        Type::CommonTypeRef { type_name, .. } => Some(split_rawname(type_name)),
    }
}

// TODO: This would make a good candidate for being in upstream Cedar?
fn split_rawname(name: &RawName) -> (Option<Name>, String) {
    let name_str = name.to_string();
    let name_parts: Vec<&str> = name_str.split("::").collect();
    match name_parts.len() {
        0 => (None, String::new()),
        1 => (None, name_parts[0].to_string()),
        _ => (
            Some(Name::from_str(&name_parts[..name_parts.len() - 1].join("::")).unwrap()),
            name_parts[name_parts.len() - 1].to_string(),
        ),
    }
}
