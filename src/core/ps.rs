use frida::{Device, Process};
use super::cli::PsArgs;

pub fn ps<'a>(device: &'a Device<'a>, args: &'a PsArgs) -> Vec<Process<'a>> {
    let processes = device.enumerate_processes();
    return processes;
}