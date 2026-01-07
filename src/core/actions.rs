use super::cli::ConnectionArgs;
use super::manager::Manager;
use frida::{Device, DeviceType};

/// Obtains a device based on connection arguments
///
/// Returns None if the specified device is not found or connection fails
pub fn get_device<'a>(manager: &'a Manager, args: &ConnectionArgs) -> Option<Device<'a>> {
    let device_manager = &manager.device_manager;
    let device = if args.host.is_some() {
        device_manager.get_device_by_type(DeviceType::Remote)
    } else if args.usb {
        device_manager.get_device_by_type(DeviceType::USB)
    } else if args.remote {
        device_manager.get_device_by_type(DeviceType::Remote)
    } else if args.device.is_some() {
        device_manager.get_device_by_id(args.device.as_deref()?)
    } else {
        device_manager.get_local_device()
    };

    device.ok()
}
