// cedar imports
use cedar_policy_core::ast::{Name, UnreservedId};
use cedar_policy_core::validator::json_schema::*;
use cedar_policy_core::validator::RawName;

use super::err::{Result, SchemaProcessingError};

// core traits
use std::fmt::Display;
use std::ops::Deref;
use std::str::FromStr;

// other imports
use smol_str::SmolStr;
use std::collections::BTreeMap;

use super::util::{applyspec_for_action, namespace_of_fragment};

#[derive(Clone)]
pub struct CedarTypeName {
    pub cedar_namespace: Option<Name>,
    pub type_name: UnreservedId,
}

impl CedarTypeName {
    pub fn new(ns: Option<Name>, type_name: &str) -> Result<Self> {
        Ok(CedarTypeName {
            cedar_namespace: ns,
            type_name: UnreservedId::from_str(type_name)?,
        })
    }

    pub fn full_name(&self) -> RawName {
        let internal = RawName::new_from_unreserved(self.type_name.clone(), None)
            .qualify_with_name(self.cedar_namespace.as_ref());
        RawName::from_name(internal)
    }

    pub fn name(&self) -> Name {
        Name::unqualified_name(self.type_name.clone())
            .qualify_with_name(self.cedar_namespace.as_ref())
    }

    pub fn common_type_id(&self) -> Result<CommonTypeId> {
        CommonTypeId::new(self.type_name.clone()).map_err(|e| e.into())
    }
}

impl TryInto<CommonTypeId> for CedarTypeName {
    type Error = SchemaProcessingError;

    fn try_into(self) -> std::result::Result<CommonTypeId, Self::Error> {
        self.common_type_id()
    }
}

pub(crate) enum TypeWrapper {
    String,
    Set(Box<TypeWrapper>),
    EntityRef(RawName),
    CommonRef(RawName),
}

impl From<&TypeWrapper> for Type<RawName> {
    fn from(value: &TypeWrapper) -> Self {
        let typevariant = |ty: TypeVariant<RawName>| Type::Type { ty, loc: None };
        match value {
            TypeWrapper::String => typevariant(TypeVariant::String),
            TypeWrapper::Set(ty) => typevariant(TypeVariant::Set {
                element: Box::new(ty.deref().into()),
            }),
            TypeWrapper::EntityRef(name) => typevariant(TypeVariant::Entity { name: name.clone() }),
            TypeWrapper::CommonRef(name) => Type::CommonTypeRef {
                type_name: name.clone(),
                loc: None,
            },
        }
    }
}

impl TypeWrapper {
    pub(crate) fn optional(&self) -> TypeOfAttribute<RawName> {
        TypeOfAttribute {
            ty: self.into(),
            annotations: Default::default(),
            required: false,
        }
    }
    pub(crate) fn required(&self) -> TypeOfAttribute<RawName> {
        TypeOfAttribute {
            ty: self.into(),
            annotations: Default::default(),
            required: true,
        }
    }
}

pub(crate) enum TypeKind<'a> {
    EntityType {
        members_of_types: Vec<&'a CedarTypeName>,
        apply_to_actions_as_principal: Vec<ActionUID>,
        apply_to_actions_as_resource: Vec<ActionUID>,
        tags: Option<TypeWrapper>,
    },
    CommonType,
}

#[derive(Debug, Clone)]
pub(crate) struct ActionUID(pub(crate) Option<Name>, pub(crate) String);

impl ActionUID {
    pub(crate) fn apply(
        &self,
        fragment: &mut Fragment<RawName>,
        applies_to: Option<ApplySpec<RawName>>,
        member_of: Option<Vec<ActionEntityUID<RawName>>>,
    ) {
        let ns = namespace_of_fragment(fragment, self.0.clone());
        ns.actions
            .entry(self.1.as_str().into())
            .or_insert_with(|| ActionType {
                attributes: None,
                applies_to,
                member_of, // TODO: Apply as part of "any" action
                annotations: Default::default(),
                loc: None,
            });
    }
}

impl Display for ActionUID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            Some(ns) => write!(f, "{}::{}", ns, self.1),
            None => write!(f, "{}", self.1),
        }
    }
}

impl From<&ActionUID> for ActionEntityUID<RawName> {
    fn from(value: &ActionUID) -> Self {
        let action_ns = value.0.as_ref().map(|ns| {
            RawName::from_name(
                RawName::from_str("Action")
                    .unwrap()
                    .qualify_with_name(Some(ns)),
            )
        });

        ActionEntityUID::new(action_ns, value.1.clone().into())
    }
}

pub(crate) struct EntityWrapper<'a> {
    pub(crate) name: CedarTypeName,
    pub(crate) attrs: BTreeMap<SmolStr, TypeOfAttribute<RawName>>,
    pub(crate) kind: TypeKind<'a>,
}

impl EntityWrapper<'_> {
    pub(crate) fn apply(&self, fragment: &mut Fragment<RawName>) -> Result<()> {
        let ns = namespace_of_fragment(fragment, self.name.cedar_namespace.clone());
        match &self.kind {
            TypeKind::EntityType {
                members_of_types,
                apply_to_actions_as_principal,
                apply_to_actions_as_resource,
                tags,
            } => {
                // TODO: Check output value to avoid adding twice
                ns.entity_types.insert(
                    self.name.type_name.clone(),
                    EntityType {
                        kind: EntityTypeKind::Standard(StandardEntityType {
                            member_of_types: members_of_types
                                .iter()
                                .map(|m| m.full_name())
                                .collect(),
                            shape: AttributesOrContext(Type::Type {
                                ty: TypeVariant::Record(RecordType {
                                    attributes: self.attrs.clone(),
                                    additional_attributes: false,
                                }),
                                loc: None,
                            }),
                            tags: tags.as_ref().map(|w| w.into()),
                        }),
                        annotations: Default::default(),
                        loc: Default::default(),
                    },
                );

                for principal_action in apply_to_actions_as_principal {
                    let action_ns = namespace_of_fragment(fragment, principal_action.0.clone());

                    applyspec_for_action(action_ns, principal_action)?
                        .principal_types
                        .push(self.name.full_name());
                }

                for resource_action in apply_to_actions_as_resource {
                    let action_ns = namespace_of_fragment(fragment, resource_action.0.clone());

                    applyspec_for_action(action_ns, resource_action)?
                        .resource_types
                        .push(self.name.full_name());
                }

                Ok::<(), SchemaProcessingError>(())
            }
            TypeKind::CommonType => {
                // TODO: Check output value to avoid adding twice
                ns.common_types.insert(
                    self.name.clone().try_into()?,
                    CommonType {
                        ty: Type::Type {
                            ty: TypeVariant::Record(RecordType {
                                attributes: self.attrs.clone(),
                                additional_attributes: false,
                            }),
                            loc: None,
                        },
                        annotations: Default::default(),
                        loc: None,
                    },
                );
                Ok(())
            }
        }?;

        Ok(())
    }
}
