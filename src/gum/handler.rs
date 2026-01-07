// src/gum/handler.rs
use crate::util::logger;
use crossterm::style::Stylize;
use frida::{Message, MessageLogLevel};
use serde_json::Value;

pub struct Handler;

impl Handler {
    /// Parse and format hook event messages
    fn format_hook_event(payload: &Value) -> Option<String> {
        let event_type = payload.get("type")?.as_str()?;
        
        match event_type {
            "hook:enter" => {
                let id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let address = payload.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                let thread = payload.get("threadId").and_then(|v| v.as_u64()).unwrap_or(0);
                let depth = payload.get("depth").and_then(|v| v.as_u64()).unwrap_or(0);
                
                let mut output = format!(
                    "{} {} @ {} (tid: {}, depth: {})",
                    "[ENTER]".green(),
                    id.to_string().cyan(),
                    address.to_string().yellow(),
                    thread,
                    depth
                );
                
                // Format arguments if present
                if let Some(args) = payload.get("args").and_then(|v| v.as_array()) {
                    if !args.is_empty() {
                        output.push_str("\n  Args:");
                        for (i, arg) in args.iter().enumerate() {
                            let value = arg.get("value").and_then(|v| v.as_str()).unwrap_or("?");
                            let ptr_info = arg.get("pointsTo")
                                .and_then(|v| v.as_str())
                                .map(|s| format!(" -> {}", s))
                                .unwrap_or_default();
                            output.push_str(&format!("\n    [{}] {}{}", i, value.yellow(), ptr_info.dark_grey()));
                        }
                    }
                }
                
                // Format backtrace if present
                if let Some(bt) = payload.get("backtrace").and_then(|v| v.as_array()) {
                    if !bt.is_empty() {
                        output.push_str("\n  Backtrace:");
                        for (i, frame) in bt.iter().take(8).enumerate() {
                            let addr = frame.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                            let module = frame.get("module").and_then(|v| v.as_str());
                            let symbol = frame.get("symbol").and_then(|v| v.as_str());
                            let offset = frame.get("offset").and_then(|v| v.as_i64());
                            
                            let location = match (module, symbol, offset) {
                                (Some(m), Some(s), Some(o)) => format!("{}!{} +{:#x}", m, s, o),
                                (Some(m), Some(s), None) => format!("{}!{}", m, s),
                                (Some(m), None, _) => m.to_string(),
                                _ => String::new()
                            };
                            
                            output.push_str(&format!("\n    #{} {} {}", i, addr.yellow(), location.dark_grey()));
                        }
                    }
                }
                
                Some(output)
            }
            "hook:leave" => {
                let id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let address = payload.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                let thread = payload.get("threadId").and_then(|v| v.as_u64()).unwrap_or(0);
                let depth = payload.get("depth").and_then(|v| v.as_u64()).unwrap_or(0);
                
                let mut output = format!(
                    "{} {} @ {} (tid: {}, depth: {})",
                    "[LEAVE]".magenta(),
                    id.to_string().cyan(),
                    address.to_string().yellow(),
                    thread,
                    depth
                );
                
                // Format return value if present
                if let Some(retval) = payload.get("retval") {
                    let value = retval.get("value").and_then(|v| v.as_str()).unwrap_or("?");
                    let ptr_info = retval.get("pointsTo")
                        .and_then(|v| v.as_str())
                        .map(|s| format!(" -> {}", s))
                        .unwrap_or_default();
                    output.push_str(&format!("\n  Return: {}{}", value.yellow(), ptr_info.dark_grey()));
                }
                
                Some(output)
            }
            "hook:attached" => {
                let id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let address = payload.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                Some(format!(
                    "{} Hook attached: {} @ {}",
                    "[HOOK]".green(),
                    id.to_string().cyan(),
                    address.to_string().yellow()
                ))
            }
            "hook:detached" => {
                let id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                Some(format!(
                    "{} Hook detached: {}",
                    "[HOOK]".yellow(),
                    id.to_string().cyan()
                ))
            }
            "hook:error" => {
                let id = payload.get("id").and_then(|v| v.as_str()).unwrap_or("?");
                let error = payload.get("error").and_then(|v| v.as_str()).unwrap_or("unknown error");
                Some(format!(
                    "{} Hook error ({}): {}",
                    "[ERROR]".red(),
                    id.to_string().cyan(),
                    error
                ))
            }
            "scan:progress" => {
                let scanned = payload.get("scanned").and_then(|v| v.as_u64()).unwrap_or(0);
                let total = payload.get("total").and_then(|v| v.as_u64()).unwrap_or(0);
                let found = payload.get("found").and_then(|v| v.as_u64()).unwrap_or(0);
                let percent = if total > 0 { (scanned * 100) / total } else { 0 };
                Some(format!(
                    "{} Scanning... {}% ({}/{} ranges, {} found)",
                    "[SCAN]".cyan(),
                    percent,
                    scanned,
                    total,
                    found.to_string().yellow()
                ))
            }
            _ => None
        }
    }
}

impl frida::ScriptHandler for Handler {
    fn on_message(&mut self, message: &Message, _data: Option<Vec<u8>>) {
        match message {
            Message::Send(s) => {
                // Try to parse as a structured hook event
                if let Some(payload) = s.payload.as_object() {
                    if payload.contains_key("type") {
                        if let Some(formatted) = Self::format_hook_event(&s.payload) {
                            println!("{}", formatted);
                            return;
                        }
                    }
                }
                // Default send message handling
                println!("{} {:?}", "[Send]".green(), s.payload);
            }
            Message::Log(log) => match log.level {
                MessageLogLevel::Info => println!("{} {}", "[Info]".cyan(), log.payload),
                MessageLogLevel::Debug => println!("{} {}", "[Debug]".magenta(), log.payload),
                MessageLogLevel::Warning => println!("{} {}", "[Warn]".yellow(), log.payload),
                MessageLogLevel::Error => logger::error(&log.payload),
            },
            Message::Error(err) => logger::error(&format!("{}\n{}", err.description, err.stack)),
            Message::Other(v) => println!("{} {:?}", "[Other]".grey(), v),
        }
    }
}
