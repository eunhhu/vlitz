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

pub fn fill(length: usize) -> String {
    String::from("█").repeat(length)
}