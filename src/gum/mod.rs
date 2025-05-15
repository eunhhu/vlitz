mod handler;

use handler::Handler;
use frida::{ScriptOption, Device, ScriptHandler};
use std::{fs::File, io::Read};
use std::path::PathBuf;
use crate::core::cli::TargetArgs;

pub fn attach(device: &mut Device, args: &TargetArgs) {
    let (session, pid) = if let Some(_pid) = args.attach_pid {
        let pid = device.enumerate_processes()
            .iter()
            .find(|p| p.get_pid() == _pid)
            .map(|p| p.get_pid())
            .expect("Process not found");
        (device.attach(pid).unwrap(), pid)
    } else if let Some(ref file) = args.file {
        let pid = device.spawn(file, &frida::SpawnOptions::new()).expect("Failed to spawn process");
        (device.attach(pid).unwrap(), pid)
    } else if let Some(ref name) = args.attach_name {
        let pid = device.enumerate_processes()
            .iter()
            .find(|p| p.get_name().to_lowercase() == name.to_lowercase())
            .map(|p| p.get_pid())
            .expect("Process not found");
        (device.attach(pid).unwrap(), pid)
    } else if let Some(ref name) = args.attach_identifier {
        let pid = device.enumerate_processes()
            .iter()
            .find(|p| p.get_name().to_lowercase() == name.to_lowercase())
            .map(|p| p.get_pid())
            .expect("Process not found");
        (device.attach(pid).unwrap(), pid)
    } else if let Some(ref name) = args.target {
        let pid = device.enumerate_processes()
            .iter()
            .find(|p| p.get_name().to_lowercase() == name.to_lowercase())
            .map(|p| p.get_pid())
            .expect("Process not found");
        (device.attach(pid).unwrap(), pid)
    } else {
        panic!("No target specified");
    };
    if session.is_detached() {
        println!("Session detached");
        return;
    }
    let script_path = PathBuf::from("src/gum.js");
    let mut script_file = File::open(script_path).expect("Failed to open script file");
    let mut script_content = String::new();
    script_file.read_to_string(&mut script_content).expect("Failed to read script file");
    let mut script = session.create_script(&script_content, &mut ScriptOption::default()).unwrap();

    let handler = script.handle_message(Handler);
    if let Err(e) = handler {
        panic!("Failed to set message handler: {}", e);
    }

    script.load().unwrap();
    println!("Script loaded");
}