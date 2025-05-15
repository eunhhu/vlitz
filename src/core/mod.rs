pub mod cli;
mod manager;
mod ps;
mod kill;
mod actions;

use std::process::exit;
use clap::Parser;
use manager::Manager;
use actions::{get_device};
use cli::{Cli, Commands};
use crate::gum::attach;

pub fn execute_cli() {
    let cliparser = Cli::parse();
    let _manager = Manager::new();
    match &cliparser.command {
        Commands::Attach(args) => {
            let device_opt = get_device(&_manager, &args.connection);
            if let Some(mut device) = device_opt {
                attach(&mut device, &args.target);
                exit(0);
            } else {
                println!("No device found");
                exit(0);
            }
        }
        Commands::Ps(args) => {
            let device = get_device(&_manager, &args.connection);
            if let Some(device) = device {
                println!("Device: {:?}", device.get_name());
                for process in ps::ps(&device, args) {
                    println!("[{}] {}", process.get_pid(), process.get_name());
                }
                exit(0);
            } else {
                println!("No device found");
                exit(0);
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
                    exit(0);
                }
            } else {
                println!("No device found");
                exit(0);
            }
        }
        Commands::Devices => {
            let devices = _manager.device_manager.enumerate_all_devices();
            for device in devices {
                println!("[{}] {} | {}", device.get_type(), device.get_id(), device.get_name());
            }
            exit(0);
        }
    }
    exit(0);
}