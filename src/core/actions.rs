use super::cli::{ConnectionArgs, TargetArgs};
use super::manager::Manager;
use frida::{Device, DeviceType, Session, SpawnOptions};

pub fn get_device<'a>(manager: &'a Manager, args: &ConnectionArgs) -> Option<Device<'a>> {
    let mut _device = None;
    if let Some(host) = &args.host {
        _device = manager.device_manager.get_remote_device(host).ok();
    } else if args.usb {
        _device = manager.device_manager.get_device_by_type(DeviceType::USB).ok();
    } else if args.remote {
        _device = manager.device_manager.get_device_by_type(DeviceType::Remote).ok();
    } else if let Some(device) = &args.device {
        _device = manager.device_manager.get_device_by_id(device).ok();
    } else {
        _device = manager.device_manager.get_local_device().ok();
    }
    if let Some(device) = _device {
        return Some(device);
    }
    None
}

pub fn get_session<'a>(device: &'a mut Device, args: &TargetArgs) -> Option<(Session<'a>, u32)> {
    if let Some(file) = &args.file {
        let so = SpawnOptions::new();
        if let Ok(pid) = device.spawn(file, &so) {
            if let Ok(session) = device.attach(pid) {
                return Some((session, pid));
            }
        }
    } else if let Some(attach_identifier) = &args.attach_identifier {
        if let Some(pid) = device.enumerate_processes().iter().find(|p| {
            p.get_name() == attach_identifier
        }).map(|p| p.get_pid()) {
            if let Ok(session) = device.attach(pid) {
                return Some((session, pid));
            }
        }
    } else if let Some(attach_name) = &args.attach_name {
        if let Some(pid) = device.enumerate_processes().iter().find(|p| {
            p.get_name() == attach_name
        }).map(|p| p.get_pid()) {
            if let Ok(session) = device.attach(pid) {
                return Some((session, pid));
            }
        }
    } else if let Some(attach_pid) = args.attach_pid {
        if let Some(pid) = device.enumerate_processes().iter().find(|p| {
            p.get_pid() == attach_pid
        }).map(|p| p.get_pid()) {
            if let Ok(session) = device.attach(pid) {
                return Some((session, pid));
            }
        }
    } else if let Some(target) = &args.target {
        if let Some(pid) = device.enumerate_processes().iter().find(|p| {
            p.get_name() == target
        }).map(|p| p.get_pid()) {
            if let Ok(session) = device.attach(pid) {
                return Some((session, pid));
            }
        }
    }
    None
}