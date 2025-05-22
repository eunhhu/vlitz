use serde_json::{json, Value};
use regex::Regex;

#[derive(Debug, PartialEq, Clone)]
pub enum FilterValue {
    String(String),
    Number(f64),
    Bool(bool),
}

#[derive(Debug, PartialEq, Clone)]
pub enum FilterOperator {
    Equal,        // =
    NotEqual,     // !=
    LessThan,     // <
    LessEqual,    // <=
    GreaterThan,  // >
    GreaterEqual, // >=
    Contains,     // :
    NotContains,  // !:
}

#[derive(Debug, PartialEq, Clone)]
pub struct FilterCondition {
    pub key: String,
    pub operator: FilterOperator,
    pub value: FilterValue,
}

#[derive(Debug, PartialEq, Clone)]
pub enum LogicalOperator {
    And,
    Or,
}

#[derive(Debug, PartialEq, Clone)]
pub enum FilterSegment {
    Condition(FilterCondition),
    Logical(LogicalOperator),
}

// Helper to convert string operator to enum
fn string_to_filter_operator(op_str: &str) -> Result<FilterOperator, String> {
    match op_str {
        "=" => Ok(FilterOperator::Equal),
        "!=" => Ok(FilterOperator::NotEqual),
        "<" => Ok(FilterOperator::LessThan),
        "<=" => Ok(FilterOperator::LessEqual),
        ">" => Ok(FilterOperator::GreaterThan),
        ">=" => Ok(FilterOperator::GreaterEqual),
        ":" => Ok(FilterOperator::Contains),
        "!:" => Ok(FilterOperator::NotContains),
        _ => Err(format!("Unknown operator: {}", op_str)),
    }
}

fn parse_value(s: &str) -> Result<FilterValue, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        if let Ok(num) = u64::from_str_radix(&s[2..], 16) {
            return Ok(FilterValue::Number(num as f64));
        }
    }
    if let Ok(num) = s.parse::<f64>() {
        return Ok(FilterValue::Number(num));
    }
    if let Ok(b) = s.parse::<bool>() {
        return Ok(FilterValue::Bool(b));
    }
    Ok(FilterValue::String(s.to_string()))
}

pub fn parse_filter_string(input: &str) -> Result<Vec<FilterSegment>, String> {
    let re_logical_ops = Regex::new(r"(&|\|)").unwrap();
    let mut segments_str: Vec<String> = Vec::new();
    let mut last_match_end = 0;

    for m in re_logical_ops.find_iter(input) {
        let segment = input[last_match_end..m.start()].trim();
        if !segment.is_empty() {
            segments_str.push(segment.to_string());
        }
        segments_str.push(m.as_str().to_string());
        last_match_end = m.end();
    }
    let last_segment = input[last_match_end..].trim();
    if !last_segment.is_empty() {
        segments_str.push(last_segment.to_string());
    }

    let mut result_filter_segments = Vec::new();

    let re_condition = Regex::new(
        r#"^\s*([^'"\s]+?)\s*(!=|<=|>=|=|>|<|:|!:)\s*(?:'([^']*)'|"([^"]*)"|([^\s&|]+))\s*$"#
    ).unwrap();

    for segment_str_val in segments_str {
        if segment_str_val == "&" {
            result_filter_segments.push(FilterSegment::Logical(LogicalOperator::And));
        } else if segment_str_val == "|" {
            result_filter_segments.push(FilterSegment::Logical(LogicalOperator::Or));
        } else {
            if let Some(caps) = re_condition.captures(&segment_str_val) {
                let key = caps.get(1).unwrap().as_str().to_string();
                let op_str = caps.get(2).unwrap().as_str();
                let operator = string_to_filter_operator(op_str)?;

                let value_str_inner = if caps.get(3).is_some() {
                    caps.get(3).unwrap().as_str()
                } else if caps.get(4).is_some() {
                    caps.get(4).unwrap().as_str()
                } else {
                    caps.get(5).unwrap().as_str()
                };

                let parsed_value = parse_value(value_str_inner)?;

                result_filter_segments.push(FilterSegment::Condition(FilterCondition {
                    key,
                    operator,
                    value: parsed_value,
                }));
            } else {
                return Err(format!("Failed to parse condition segment: '{}'. Please check syntax.", segment_str_val));
            }
        }
    }

    Ok(result_filter_segments)
}

// Helper to convert FilterValue to serde_json::Value
fn filter_value_to_json(fv: &FilterValue) -> Value {
    match fv {
        FilterValue::String(s) => json!(s),
        FilterValue::Number(n) => json!(n),
        FilterValue::Bool(b) => json!(b),
    }
}

// Helper to convert FilterOperator back to string
fn filter_operator_to_string(op: &FilterOperator) -> String {
    match op {
        FilterOperator::Equal => "=".to_string(),
        FilterOperator::NotEqual => "!=".to_string(),
        FilterOperator::LessThan => "<".to_string(),
        FilterOperator::LessEqual => "<=".to_string(),
        FilterOperator::GreaterThan => ">".to_string(),
        FilterOperator::GreaterEqual => ">=".to_string(),
        FilterOperator::Contains => ":".to_string(),
        FilterOperator::NotContains => "!:".to_string(),
    }
}

pub fn parse_filter_string_to_json(input: &str) -> Result<Value, String> {
    let native_segments = parse_filter_string(input)?;
    let mut json_array = Vec::new();

    for segment in native_segments {
        match segment {
            FilterSegment::Condition(cond) => {
                json_array.push(json!([
                    cond.key,
                    filter_operator_to_string(&cond.operator),
                    filter_value_to_json(&cond.value)
                ]));
            }
            FilterSegment::Logical(LogicalOperator::And) => {
                json_array.push(json!("and"));
            }
            FilterSegment::Logical(LogicalOperator::Or) => {
                json_array.push(json!("or"));
            }
        }
    }
    Ok(Value::Array(json_array))
}