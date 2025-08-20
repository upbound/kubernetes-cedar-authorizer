pub fn title_case(name: &str) -> String {
    name.chars()
        .enumerate()
        .map(|(i, c)| match i {
            0 => c.to_ascii_uppercase(),
            _ => c,
        })
        .collect()
}
