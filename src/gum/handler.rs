// src/gum/handler.rs
use crate::util::logger;
use crossterm::style::Stylize;
use frida::{Message, MessageLogLevel};

pub struct Handler;

impl frida::ScriptHandler for Handler {
    fn on_message(&mut self, message: &Message, _data: Option<Vec<u8>>) {
        match message {
            Message::Send(s) => println!("{} {:?}", "[Send]".green(), s.payload),
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
