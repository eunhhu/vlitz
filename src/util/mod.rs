pub mod format;
pub mod logger;
use crossterm::style::Stylize;

pub fn fill(length: usize) -> String {
    String::from("█").repeat(length)
}

pub fn highlight(s: &str, filter: &str) -> String {
    let mut highlighted = String::new();
    let mut start = 0;

    while let Some(pos) = s.to_lowercase()[start..].find(&filter.to_lowercase()) {
        let mut end = 0;
        end = start + pos;
        highlighted.push_str(&s[start..end]);
        highlighted.push_str(&format!("{}", &s[end..end + filter.len()].red()));
        start = end + filter.len();
    }
    highlighted.push_str(&s[start..]);

    highlighted
}
