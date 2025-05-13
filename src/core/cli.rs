use clap::{Parser, Subcommand, Args};

#[derive(Parser, Debug)]
#[clap(name = "vlitz", about = "A strong dynamic debugger CLI tool based on frida", long_about = None)]
pub struct Cli {
    #[clap(flatten)]
    pub connection: ConnectionArgs,

    #[clap(flatten)]
    pub attach: AttachArgs,

    #[clap(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Args, Debug)]
#[clap(group(
    clap::ArgGroup::new("connection")
        .args(&["device", "usb", "remote", "host"])
        .multiple(false)
))]
pub struct ConnectionArgs {
    #[clap(short = 'D', long, value_name = "ID", help = "connect to device with the given ID")]
    pub device: Option<String>,

    #[clap(short = 'U', long, help = "connect to USB device")]
    pub usb: bool,
    
    #[clap(short = 'R', long, help = "connect to remote frida-server")]
    pub remote: bool,

    #[clap(short = 'H', long, value_name = "HOST", help = "connect to remote frida-server on HOST")]
    pub host: Option<String>,
}

#[derive(Args, Debug)]
#[clap(group(
    clap::ArgGroup::new("process")
        .args(&["attach_identifier", "attach_pid"])
        .multiple(false)
))]
pub struct ProcessArgs {
    #[clap(short = 'N', long, value_name = "NAME", help = "attach to IDENTIFIER")]
    pub attach_identifier: Option<String>,
    
    #[clap(short = 'p', long, value_name = "PID", help = "attach to PID")]
    pub attach_pid: Option<u32>,
}

#[derive(Args, Debug)]
#[clap(group(
    clap::ArgGroup::new("attach")
    .args(&["file", "attach_name", "attach_identifier", "attach_pid"])
    .multiple(false)
))]
pub struct AttachArgs {
    #[clap(short, long, value_name = "TARGET", help = "spawn FILE")]
    pub file: Option<String>,
    
    #[clap(short = 'n', long, value_name = "NAME", help = "attach to NAME")]
    pub attach_name: Option<String>,
    
    #[clap(short = 'N', long, value_name = "NAME", help = "attach to IDENTIFIER")]
    pub attach_identifier: Option<String>,
    
    #[clap(short = 'p', long, value_name = "PID", help = "attach to PID")]
    pub attach_pid: Option<u32>,
}

#[derive(Args, Debug)]
pub struct PsArgs {
    #[clap(flatten)]
    pub connection: ConnectionArgs,

    #[clap(short = 'a', long = "applications", help = "list only applications")]
    pub applications: bool,

    #[clap(short = 'i', long = "installed", help = "include all installed applications")]
    pub installed: bool,
}

#[derive(Args, Debug)]
pub struct KillArgs {
    #[clap(flatten)]
    pub process: ProcessArgs,

    pub target: String,
}

#[derive(Subcommand, Debug)]
pub enum Commands{
    Ps (PsArgs),
    Kill (KillArgs),
    Devices,
    #[clap(external_subcommand)]
    External(Vec<String>),
}