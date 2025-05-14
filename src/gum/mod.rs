use frida::{ScriptOption, Device, Session};
use std::{fs::File, io::Read};
use std::path::PathBuf;

pub fn start_gum_session(device: &Device, session: &Session, pid: u32) {
    let mut so = ScriptOption::new();
    let file_path = PathBuf::from("src/gum.js");
    let mut file = File::open(&file_path).expect("Failed to open script file");
    let mut script_content = String::new();
    file.read_to_string(&mut script_content).expect("Failed to read script file");
    let mut script = session.create_script(&script_content, &mut so).unwrap();
    script.load().unwrap();
    println!("Script loaded successfully");
    device.resume(pid).unwrap();
    let exps = script.list_exports().expect("Failed to list exports");
    println!("Exports: {} {}", exps.len(), exps.first().unwrap());
    for exp in exps {
        println!("Exported function: {}", exp);
    }
}