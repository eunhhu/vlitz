use frida::{DeviceManager, Frida};

pub struct Manager {
    pub frida: Box<Frida>,
    pub device_manager: DeviceManager<'static>,
}

impl Manager {
    pub fn new() -> Self {
        let frida = Box::new(unsafe { Frida::obtain() });
        let device_manager = unsafe { std::mem::transmute::<DeviceManager<'_>, DeviceManager<'static>>(DeviceManager::obtain(&*frida)) };
        Manager { frida, device_manager }
    }
}