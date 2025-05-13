mod cli;
mod manager;
mod ps;

use std::process::exit;
use clap::Parser;
use manager::Manager;

pub fn executeCli() {
    let cliparser = cli::Cli::parse();
    let _manager = Manager::new();
    match &cliparser.command {
        Some(cli::Commands::Ps(args)) => {
            ps::ps(&_manager, args);
        }
        Some(cli::Commands::Kill(args)) => {
            println!("Kill command executed with args: {:?}", args);
        }
        Some(cli::Commands::Devices) => {
            println!("Devices command executed");
        }
        Some(cli::Commands::External(args)) => {
            println!("Attach command provided with args: {:?}", args);
            println!("{:?}", cliparser)
        }
        None => {
            println!("Attach command provided {:?}", cliparser);
        }
    }
    exit(0);
}