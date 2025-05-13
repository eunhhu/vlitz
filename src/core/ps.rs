use frida::{Device};
use super::cli::PsArgs;

pub fn ps(device: &Device, args: &PsArgs) {
    let processes = device.enumerate_processes();
    for process in processes {
        println!("{} (PID: {})", process.get_name(), process.get_pid());
    }
}