// src/gum/selector.rs

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SelectorType {
    Indices(Vec<usize>),
    All,
}

pub fn parse_selection_type(s: &str) -> Result<SelectorType, String> {
    if s == "all" {
        return Ok(SelectorType::All);
    }
    let mut indices = vec![];
    for s in s.split(',').map(|s| s.trim()) {
        if let Ok(index) = s.parse::<usize>() {
            indices.push(index);
        } else {
            let ranges: Vec<_> = s.split('-').map(|s| s.trim()).collect();
            if ranges.len() > 2 {
                return Err(format!("Invalid range: {}", s));
            } else {
                let start = ranges.get(0).unwrap_or(&"0").parse::<usize>().unwrap_or(0);
                let end = ranges.get(1).unwrap_or(&"0").parse::<usize>().unwrap_or(0);
                if start > end {
                    return Err(format!("Invalid range: {}", s));
                }
                for i in start..=end {
                    indices.push(i);
                }
            }
        }
    }
    Ok(SelectorType::Indices(indices))
}