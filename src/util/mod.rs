use crossterm::style::Stylize;
use unicode_segmentation::UnicodeSegmentation;

pub fn lengthed(s: &str, size: usize) -> String {
    // Strip ANSI color codes for length calculation
    let stripped = strip_ansi_escapes::strip(s);
    let stripped_str = String::from_utf8_lossy(&stripped);
    
    let len = stripped_str.graphemes(true).count();
    if len == size {
        s.to_string()
    } else if len > size {
        let mut result = String::new();
        let mut current_len = 0;
        let ellipsis = "…";
        
        // Rebuild the string with color codes but proper length
        for c in s.chars() {
            if current_len >= size - 1 {
                result.push_str(ellipsis);
                break;
            }
            result.push(c);
            if c == '\x1B' {
                // Skip ANSI escape sequence
                while let Some(next) = s.chars().nth(result.len()) {
                    result.push(next);
                    if next == 'm' { break; }
                }
            } else {
                current_len += 1;
            }
        }
        result
    } else {
        format!("{:<size$}", s, size = size + (s.len() - stripped_str.len()))
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
