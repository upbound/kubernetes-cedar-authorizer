use std::collections::HashSet;

use cedar_policy_core::tpe::entities::PartialEntity;

pub fn title_case(name: &str) -> String {
    name.chars()
        .enumerate()
        .map(|(i, c)| match i {
            0 => c.to_ascii_uppercase(),
            _ => c,
        })
        .collect()
}

pub(crate) fn debug_entity(entity: &PartialEntity) {
    match cedar_policy_core::ast::Entity::new(
        entity.uid.clone(),
        entity
            .attrs
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k, v.into())),
        HashSet::new(),
        entity
            .ancestors
            .clone()
            .unwrap_or_default()
            .into_iter()
            .collect(),
        entity
            .tags
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|(k, v)| (k, v.into())),
        cedar_policy_core::extensions::Extensions::all_available(),
    ) {
        Ok(entity) => match entity.to_json_value() {
            Ok(s) => println!("{}", serde_json::to_string_pretty(&s).unwrap()),
            Err(e) => println!("Error: {e:?}"),
        },
        Err(e) => println!("Error: {e:?}"),
    }
}
