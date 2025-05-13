use super::manager::Manager;
use super::cli;
use frida::DeviceType;

pub fn ps(manager: &Manager, args: &cli::PsArgs) {
    let mut _device = None;
    if let Some(host) = &args.connection.host {
        _device = Some(manager.device_manager.get_remote_device(host));
    } else if args.connection.usb {
        _device = Some(manager.device_manager.get_device_by_type(DeviceType::USB));
    } else if args.connection.remote {
        _device = Some(manager.device_manager.get_device_by_type(DeviceType::Remote));
    } else if let Some(device) = &args.connection.device {
        _device = Some(manager.device_manager.get_device_by_id(device));
    } else {
        _device = Some(manager.device_manager.get_local_device());
    }
    if let Some(device) = _device {
        let device = device.expect("Failed to get device");
        let processes = device.enumerate_processes();
        for process in processes {
            println!("{} (PID: {})", process.get_name(), process.get_pid());
        }
    } else {
        println!("No device found");
    }
}