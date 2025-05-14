mod cli;
mod manager;
mod ps;
mod kill;
mod actions;

use std::process::exit;
use clap::Parser;
use manager::Manager;
use actions::{get_device, get_session};
use cli::{Cli, Commands};
use crate::gum::start_gum_session;

pub fn execute_cli() {
    let cliparser = Cli::parse();
    let _manager = Manager::new();
    match &cliparser.command {
        Commands::Attach(args) => {
            let device_opt = get_device(&_manager, &args.connection);
            if let Some(mut device) = device_opt {
                let session_opt = get_session(&mut device, &args.target);
                if let Some((session, pid)) = session_opt {
                    // Pass a reference to device if cloning is not implemented
                    start_gum_session(&device, &session, pid);
                } else {
                    println!("Failed to attach to process");
                }
            } else {
                println!("No device found");
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
                let killed_pids = kill::kill(&mut device, &args.process);
                if killed_pids.is_empty() {
                    println!("No processes killed");
                } else {
                    for pid in killed_pids {
                        println!("Killed process with PID: {}", pid);
                    }
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