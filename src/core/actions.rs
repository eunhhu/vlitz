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

pub fn get_session<'a>(device: &'a mut Device<'a>, args: &TargetArgs) -> Option<Session<'a>> {
    if let Some(file) = &args.file {
        let so = SpawnOptions::new();
        let pid = device.spawn(file, &so).ok();
        if let Some(pid) = pid {
            let session = device.attach(pid).ok();
            if let Some(session) = session {
                return Some(session);
            }
        }
    } else if let Some(attach_identifier) = &args.attach_identifier {
        return device.enumerate_processes().iter().find(|p| {
            p.get_name() == attach_identifier
        }).and_then(|p| device.attach(p.get_pid()).ok());
    } else if let Some(attach_name) = &args.attach_name {
        return device.enumerate_processes().iter().find(|p| {
            p.get_name() == attach_name
        }).and_then(|p| device.attach(p.get_pid()).ok());
    } else if let Some(attach_pid) = args.attach_pid {
        return device.attach(attach_pid).ok();
    } else if let Some(target) = &args.target {
        return device.enumerate_processes().iter().find(|p| {
            p.get_name() == target
        }).and_then(|p| device.attach(p.get_pid()).ok());
    }
    None
}