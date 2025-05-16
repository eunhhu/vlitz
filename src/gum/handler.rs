use crossterm::style::Stylize;
use frida::Message;

pub struct Handler;

impl frida::ScriptHandler for Handler {
    fn on_message(&mut self, message: &Message, _data: Option<Vec<u8>>) {
        println!("{} {:?}", "[Script]".yellow(), message);
    }
}
