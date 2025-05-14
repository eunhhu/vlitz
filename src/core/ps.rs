use frida::{Device, Process};
use super::cli::PsArgs;

pub fn ps<'a>(device: &'a Device<'a>, args: &'a PsArgs) -> Vec<Process<'a>> {
    let processes = device.enumerate_processes();
    let filtered = processes
        .into_iter()
        .filter(|process| {
            if let Some(name) = &args.filter {
                process.get_name().to_lowercase().contains(&name.to_lowercase())
            } else {
                true
            }
        })
        .collect::<Vec<Process>>();
    return filtered;
}