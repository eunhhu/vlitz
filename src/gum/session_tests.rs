// Tests for session.rs command parsing

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty_command() {
        let result = parse_command("");
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_simple_command() {
        let result = parse_command("help");
        assert_eq!(result, vec!["help"]);
    }

    #[test]
    fn test_parse_command_with_args() {
        let result = parse_command("read 0x1000 byte 16");
        assert_eq!(result, vec!["read", "0x1000", "byte", "16"]);
    }

    #[test]
    fn test_parse_double_quoted_string() {
        let result = parse_command(r#"echo "hello world""#);
        assert_eq!(result, vec!["echo", "hello world"]);
    }

    #[test]
    fn test_parse_single_quoted_string() {
        let result = parse_command(r#"echo 'test'"#);
        assert_eq!(result, vec!["echo", "test"]);
    }

    #[test]
    fn test_parse_mixed_quotes() {
        let result = parse_command(r#"command "arg1" 'arg2' "arg3""#);
        assert_eq!(result, vec!["command", "arg1", "arg2", "arg3"]);
    }

    #[test]
    fn test_parse_with_special_chars() {
        let result = parse_command("test-arg_special@value");
        assert_eq!(result, vec!["test-arg_special@value"]);
    }
}
