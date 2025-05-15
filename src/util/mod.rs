use crossterm::style::Stylize;
use unicode_segmentation::UnicodeSegmentation;

pub fn truncate(s: &str, max_chars: usize) -> String {
    if s.graphemes(true).count() <= max_chars {
        s.to_string()
    } else {
        let truncated_graphemes = s.graphemes(true).take(max_chars - 1).collect::<String>();
        let ellipsis = "…";

        format!("{}{}", truncated_graphemes, ellipsis)
    }
}

pub fn lengthed(s: &str, size: usize) -> String {
    let len = s.graphemes(true).count();
    if len == size {
        s.to_string()
    } else if len > size {
        let truncated_graphemes = s.graphemes(true).take(size - 1).collect::<String>();
        let ellipsis = "…";
        format!("{}{}", truncated_graphemes, ellipsis)
    } else {
        format!("{:<size$}", s, size = size)
    }
}

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
