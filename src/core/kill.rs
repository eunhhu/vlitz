use frida::Device;
use super::cli::ProcessArgs;

pub fn kill(device: &mut Device, args: &ProcessArgs) -> Vec<u32> {
    let processes = device.enumerate_processes().into_iter().collect::<Vec<_>>();
    let mut killed_pids = Vec::new();

    // Collect matching PIDs first to avoid borrowing device across kill calls
    let filtered_pids: Vec<u32> = processes.into_iter().filter_map(|process| {
        if let Some(pid) = args.attach_pid {
            if process.get_pid() == pid {
                Some(process.get_pid())
            } else {
                None
            }
        } else if let Some(attach_name) = &args.attach_name {
            if process.get_name() == attach_name {
                Some(process.get_pid())
            } else {
                None
            }
        } else if let Some(target) = &args.target {
            if process.get_name() == target {
                Some(process.get_pid())
            } else {
                None
            }
        } else {
            None
        }
    }).collect();

    for pid in filtered_pids {
        device.kill(pid).unwrap();
        killed_pids.push(pid);
    }

    killed_pids
}