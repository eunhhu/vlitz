use super::cli::{ConnectionArgs};
use super::manager::Manager;
use frida::{Device, DeviceType};

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
