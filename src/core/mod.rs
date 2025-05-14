mod cli;
mod manager;
mod ps;
mod actions;

use std::process::exit;
use clap::Parser;
use manager::Manager;
use actions::{get_device, get_session};
use cli::{Cli, Commands};

pub fn execute_cli() {
    let cliparser = Cli::parse();
    let _manager = Manager::new();
    match &cliparser.command {
        Commands::Attach(args) => {
            let mut device = match get_device(&_manager, &args.connection) {
                Some(device) => device,
                None => {
                    println!("No device found");
                    return;
                }
            };
            let session_result = get_session(&mut device, &args.target);
            match session_result {
                Some(session) => {
                    println!("Attached");
                }
                None => {
                    println!("Failed to attach to process");
                }
            }
        }
        Commands::Ps(args) => {
            let device = get_device(&_manager, &args.connection);
            if let Some(device) = device {
                println!("Device: {:?}", device.get_name());
                for process in ps::ps(&device, args) {
                    println!("[{}] {}", process.get_pid(), process.get_name());
                }
            } else {
                println!("No device found");
            }
        }
        Commands::Kill(args) => {
            let device = get_device(&_manager, &args.connection);
            if let Some(mut device) = device {
                if let Some(pid) = args.process.attach_pid {
                    device.kill(pid).unwrap();
                    println!("Killed process with PID: {}", pid);
                } else {
                    println!("No PID provided");
                }
            } else {
                println!("No device found");
            }
        }
        Commands::Devices => {
            let devices = _manager.device_manager.enumerate_all_devices();
            for device in devices {
                println!("[{}] {} | {}", device.get_type(), device.get_id(), device.get_name());
            }
        }
    }
    exit(0);
}