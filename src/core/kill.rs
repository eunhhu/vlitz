use super::cli::ProcessArgs;
use frida::Device;

pub fn kill(device: &mut Device, args: &ProcessArgs) -> Vec<(String, u32)> {
    let processes = device.enumerate_processes().into_iter().collect::<Vec<_>>();
    let mut killed_processes = Vec::new();

    let filtered_processes: Vec<(String, u32)> = processes
        .into_iter()
        .filter_map(|process| {
            if let Some(pid) = args.attach_pid {
                if process.get_pid() == pid {
                    Some((process.get_name().to_string(), process.get_pid()))
                } else {
                    None
                }
            } else if let Some(attach_name) = &args.attach_name {
                if process.get_name().to_lowercase() == attach_name.to_lowercase() {
                    Some((process.get_name().to_string(), process.get_pid()))
                } else {
                    None
                }
            } else if let Some(target) = &args.target {
                if process.get_name().to_lowercase() == target.to_lowercase() {
                    Some((process.get_name().to_string(), process.get_pid()))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    for (name, pid) in filtered_processes {
        match device.kill(pid) {
            Ok(_) => killed_processes.push((name, pid)),
            Err(e) => {
                crate::util::logger::error(&format!("Failed to kill {} (pid {}): {}", name, pid, e))
            }
        }
    }

    killed_processes
}
