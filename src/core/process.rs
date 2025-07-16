use super::cli::TargetArgs;
use super::error::{VlitzError, VlitzResult};
use frida::{Device, Session};

pub fn find_process_by_target(device: &Device, args: &TargetArgs) -> VlitzResult<u32> {
    if let Some(pid) = args.attach_pid {
        find_process_by_pid(device, pid)
    } else if let Some(ref name) = args.attach_name {
        find_process_by_name(device, name)
    } else if let Some(ref name) = args.attach_identifier {
        find_process_by_name(device, name)
    } else if let Some(ref name) = args.target {
        find_process_by_name(device, name)
    } else {
        Err(VlitzError::ProcessNotFound(
            "No target specified".to_string(),
        ))
    }
}

pub fn find_process_by_pid(device: &Device, pid: u32) -> VlitzResult<u32> {
    device
        .enumerate_processes()
        .iter()
        .find(|p| p.get_pid() == pid)
        .map(|p| p.get_pid())
        .ok_or_else(|| VlitzError::ProcessNotFound(pid.to_string()))
}

pub fn find_process_by_name(device: &Device, name: &str) -> VlitzResult<u32> {
    device
        .enumerate_processes()
        .iter()
        .find(|p| p.get_name().to_lowercase() == name.to_lowercase())
        .map(|p| p.get_pid())
        .ok_or_else(|| VlitzError::ProcessNotFound(name.to_string()))
}

pub fn attach_to_process<'a>(device: &'a Device<'a>, pid: u32) -> VlitzResult<Session<'a>> {
    device
        .attach(pid)
        .map_err(|e| VlitzError::AttachFailed(format!("{} ({})", pid, e)))
}

pub fn spawn_process(device: &mut Device, file: &str) -> VlitzResult<u32> {
    device
        .spawn(file, &frida::SpawnOptions::new())
        .map_err(|e| VlitzError::SpawnFailed(format!("{} ({})", file, e)))
}

pub fn resume_process(device: &mut Device, pid: u32) -> VlitzResult<()> {
    device
        .resume(pid)
        .map_err(|e| VlitzError::ResumeFailed(format!("{}", e)))
}
