use frida::{DeviceManager, Frida};

/// Manages Frida context for device and process operations
///
/// The Manager holds Frida context and DeviceManager with a 'static lifetime.
/// This uses an unsafe transmute to extend DeviceManager lifetime, which is a known pattern
/// when working with self-referential structs. The Frida context is boxed to ensure
/// it lives for the duration of the program.
pub struct Manager {
    pub frida: Box<Frida>,
    pub device_manager: DeviceManager<'static>,
}

impl Manager {
    /// Creates a new Manager with a Frida context
    ///
    /// SAFETY: This performs an unsafe lifetime transmute to extend the DeviceManager lifetime.
    /// The Frida context is boxed to ensure it outlives the Manager.
    /// This is a known pattern when dealing with self-referential structs in the Frida crate.
    pub fn new() -> Self {
        let frida = Box::new(unsafe { Frida::obtain() });
        let device_manager = unsafe {
            let dm = DeviceManager::obtain(&*frida);
            std::mem::transmute::<DeviceManager<'_>, DeviceManager<'static>>(dm)
        };
        Manager {
            frida,
            device_manager,
        }
    }
}
