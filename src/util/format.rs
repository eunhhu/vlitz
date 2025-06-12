use unicode_segmentation::UnicodeSegmentation;

pub fn parse_hex_or_decimal(s: &str) -> Result<u64, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|_| format!("Invalid hex number: {}", s))
    } else {
        s.parse::<u64>()
            .map_err(|_| format!("Invalid number: {}", s))
    }
}

pub fn parse_hex_or_decimal_usize(s: &str) -> Result<usize, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        usize::from_str_radix(&s[2..], 16).map_err(|_| format!("Invalid hex number: {}", s))
    } else {
        s.parse::<usize>()
            .map_err(|_| format!("Invalid number: {}", s))
    }
}

pub fn get_address_width(addr: u64) -> usize {
    if addr <= 0xFFFF {
        6
    } else if addr <= 0xFFFFFFFF {
        10
    } else {
        18
    }
}

pub fn format_address(addr: u64) -> String {
    let width = get_address_width(addr);
    match width {
        6 => format!("{:#06x}", addr),
        10 => format!("{:#010x}", addr),
        18 => format!("{:#018x}", addr),
        _ => format!("{:#x}", addr),
    }
}

pub fn get_header_padding(addr: u64) -> String {
    let width = get_address_width(addr);
    " ".repeat(width + 2)
}

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
                    if next == 'm' {
                        break;
                    }
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
