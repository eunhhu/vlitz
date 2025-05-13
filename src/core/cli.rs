use clap::{Parser, Subcommand, Args};

#[derive(Parser, Debug)]
#[clap(name = "vlitz", about = "A strong dynamic debugger CLI tool based on frida", long_about = None)]
pub struct Cli {
    #[clap(Subcommand)]
    pub command: Option<Commands>,
    #[clap(short = 'D', long = "device", value_name = "ID", help = "connect to device with the given ID")]
    pub device: Option<String>,
    #[clap(short = 'U', long = "usb", help = "connect to USB device")]
    pub usb: Option<bool>,
    #[clap(short = 'R', long = "remote", help = "connect to remote frida-server")]
    pub remote: Option<bool>,
    #[clap(short = 'H', long = "host", value_name = "HOST", help = "connect to remote frida-server on HOST")]
    pub host: Option<String>,
}

#[derive(Args, Debug)]
pub struct PsArgs {
    #[clap(short = 'a', long = "applications", help = "list only applications")]
    pub applications: Option<bool>,

    #[clap(short = 'i', long = "installed", help = "include all installed applications")]
    pub installed: Option<bool>,
}

#[derive(Args, Debug)]
pub struct KillArgs {
    pub target: String,
}

#[derive(Subcommand, Debug)]
pub enum Commands{
    Ps (PsArgs),
    Kill (KillArgs),
    Devices,
}