use clap::{Parser, Subcommand, Args, ValueEnum, CommandFactory};
use clap_complete::{generate, Shell};
use std::io;

#[derive(Parser)]
#[clap(name = "vlitz", version, about = "A strong dynamic debugger CLI tool based on frida", long_about = None)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,

    #[clap(long, value_enum, hide = true)]
    pub generate_completion: Option<Shell>,
}

impl Cli {
    pub fn generate_completion(&self) -> std::io::Result<()> {
        if let Some(shell) = self.generate_completion {
            let mut cmd = Cli::command();
            let bin_name = "vlitz".to_string();
            generate(shell, &mut cmd, &bin_name, &mut io::stdout());
            Ok(())
        } else {
            Ok(())
        }
    }
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
    clap::ArgGroup::new("process_method")
        .args(&["attach_name", "attach_pid", "target"])
        .multiple(false)
        .required(true)
))]
pub struct ProcessArgs {
    #[clap(short = 'n', long, value_name = "NAME", help = "attach to NAME")]
    pub attach_name: Option<String>,
    
    #[clap(short = 'p', long, value_name = "PID", help = "attach to PID")]
    pub attach_pid: Option<u32>,

    #[clap(index = 1, help = "target NAME")]
    pub target: Option<String>,
}

#[derive(Args, Debug)]
#[clap(group(
    clap::ArgGroup::new("target_method")
    .args(&["file", "attach_identifier", "attach_name", "attach_pid", "target"])
    .multiple(false)
    .required(true)
))]
pub struct TargetArgs {
    #[clap(short, long, value_name = "TARGET", help = "spawn FILE")]
    pub file: Option<String>,
    
    #[clap(short = 'N', long, value_name = "IDENTIFIER", help = "attach to IDENTIFIER")]
    pub attach_identifier: Option<String>,

    #[clap(short = 'n', long, value_name = "NAME", help = "attach to NAME")]
    pub attach_name: Option<String>,
    
    #[clap(short = 'p', long, value_name = "PID", help = "attach to PID")]
    pub attach_pid: Option<u32>,

    #[clap(index = 1, help = "target NAME")]
    pub target: Option<String>,
}

#[derive(Args, Debug)]
pub struct AttachArgs {
    #[clap(flatten)]
    pub connection: ConnectionArgs,

    #[clap(flatten)]
    pub target: TargetArgs,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum Sort {
    Name,
    Pid,
}

#[derive(Args, Debug)]
pub struct PsArgs {
    #[clap(flatten)]
    pub connection: ConnectionArgs,

    // #[clap(short, long, help = "list only applications")]
    // pub applications: bool,

    // #[clap(short, long, help = "include all installed applications")]
    // pub installed: bool,

    #[clap(short, long, help = "sort by NAME or PID")]
    pub sort: Option<Sort>,

    #[clap(index = 1, help = "target NAME")]
    pub filter: Option<String>,
}

#[derive(Args, Debug)]
pub struct KillArgs {
    #[clap(flatten)]
    pub connection: ConnectionArgs,

    #[clap(flatten)]
    pub process: ProcessArgs,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate shell completion script
    #[command(name = "completions")]
    Completions {
        /// The shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
    Attach(AttachArgs),
    Ps(PsArgs),
    Kill(KillArgs),
    Devices,
}