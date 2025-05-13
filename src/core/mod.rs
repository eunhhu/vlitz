mod cli;

use clap::Parser;

pub fn execute() {
    let CLI = cli::Cli::parse();
    match &CLI.command {
        Some(cli::Commands::Ps(args)) => {
            println!("Ps command executed with args: {:?}", args);
        }
        Some(cli::Commands::Kill(args)) => {
            println!("Kill command executed with args: {:?}", args);
        }
        Some(cli::Commands::Devices) => {
            println!("Devices command executed");
        }
        None => {
            println!("No command provided");
        }
    }
}