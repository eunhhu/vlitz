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

impl Manager {
    /// Creates a new Manager with a Frida context
    pub fn new() -> Self {
        // Frida::obtain() is inherently unsafe as it manages global state
        let frida = Box::new(unsafe { Frida::obtain() });
        Manager { frida }
    }

    /// Obtains a local device manager from Frida context
    pub fn get_local_device_manager(&self) -> Option<DeviceManager<'_>> {
        DeviceManager::get_local_device(&*self.frida)
            .ok()
            .map(|_| unsafe { DeviceManager::obtain(&*self.frida) })
    }

    /// Obtains a USB device manager from Frida context
    pub fn get_usb_device_manager(&self) -> Option<DeviceManager<'_>> {
        DeviceManager::get_device_by_type(&*self.frida, frida::DeviceType::USB)
            .ok()
            .map(|_| unsafe { DeviceManager::obtain(&*self.frida) })
    }

    /// Obtains a remote device manager from Frida context
    pub fn get_remote_device_manager(&self, host: &str) -> Option<DeviceManager<'_>> {
        DeviceManager::get_remote_device(&*self.frida, host)
            .ok()
            .map(|_| unsafe { DeviceManager::obtain(&*self.frida) })
    }

    /// Obtains a device manager by ID from Frida context
    pub fn get_device_manager_by_id(&self, id: &str) -> Option<DeviceManager<'_>> {
        DeviceManager::get_device_by_id(&*self.frida, id)
            .ok()
            .map(|_| unsafe { DeviceManager::obtain(&*self.frida) })
    }

    /// Obtains a device manager from Frida context
    ///
    /// This provides a convenient method to obtain a device manager
    /// for device enumeration operations.
    pub fn device_manager(&self) -> DeviceManager {
        unsafe { DeviceManager::obtain(&*self.frida) }
    }
}

impl Manager {
    /// Creates a new Manager with a Frida context
    pub fn new() -> Self {
        // Frida::obtain() is inherently unsafe as it manages global state
        let frida = Box::new(unsafe { Frida::obtain() });
        Manager { frida }
    }

    /// Obtains a local device manager from the Frida context
    pub fn get_local_device_manager(&self) -> Option<DeviceManager<'_>> {
        DeviceManager::get_local_device(&*self.frida)
            .ok()
            .map(|_| unsafe { DeviceManager::obtain(&*self.frida) })
    }

    /// Obtains a USB device manager from the Frida context
    pub fn get_usb_device_manager(&self) -> Option<DeviceManager<'_>> {
        DeviceManager::get_device_by_type(&*self.frida, frida::DeviceType::USB)
            .ok()
            .map(|_| unsafe { DeviceManager::obtain(&*self.frida) })
    }

    /// Obtains a remote device manager from the Frida context
    pub fn get_remote_device_manager(&self, host: &str) -> Option<DeviceManager<'_>> {
        DeviceManager::get_remote_device(&*self.frida, host)
            .ok()
            .map(|_| unsafe { DeviceManager::obtain(&*self.frida) })
    }

    /// Obtains a device manager by ID from the Frida context
    pub fn get_device_manager_by_id(&self, id: &str) -> Option<DeviceManager<'_>> {
        DeviceManager::get_device_by_id(&*self.frida, id)
            .ok()
            .map(|_| unsafe { DeviceManager::obtain(&*self.frida) })
    }

    /// Obtains a device manager from the Frida context
    ///
    /// This provides a convenient method to obtain a device manager
    /// for device enumeration operations.
    pub fn device_manager(&self) -> DeviceManager {
        unsafe { DeviceManager::obtain(&*self.frida) }
    }
}

impl Manager {
    /// Creates a new Manager with a Frida context
    pub fn new() -> Self {
        // Frida::obtain() is inherently unsafe as it manages global state
        let frida = Box::new(unsafe { Frida::obtain() });
        Manager { frida }
    }

    /// Obtains a local device manager from the Frida context
    pub fn get_local_device_manager(&self) -> Option<DeviceManager<'_>> {
        DeviceManager::get_local_device(&*self.frida)
            .ok()
            .map(|_| unsafe { DeviceManager::obtain(&*self.frida) })
    }

    /// Obtains a USB device manager from the Frida context
    pub fn get_usb_device_manager(&self) -> Option<DeviceManager<'_>> {
        DeviceManager::get_device_by_type(&*self.frida, frida::DeviceType::USB)
            .ok()
            .map(|_| unsafe { DeviceManager::obtain(&*self.frida) })
    }

    /// Obtains a remote device manager from the Frida context
    pub fn get_remote_device_manager(&self, host: &str) -> Option<DeviceManager<'_>> {
        DeviceManager::get_remote_device(&*self.frida, host)
            .ok()
            .map(|_| unsafe { DeviceManager::obtain(&*self.frida) })
    }

    /// Obtains a device manager by ID from the Frida context
    pub fn get_device_manager_by_id(&self, id: &str) -> Option<DeviceManager<'_>> {
        DeviceManager::get_device_by_id(&*self.frida, id)
            .ok()
            .map(|_| unsafe { DeviceManager::obtain(&*self.frida) })
    }

    /// Obtains a device manager from the Frida context
    ///
    /// This provides a convenient method to obtain a device manager
    /// for device enumeration operations.
    pub fn device_manager(&self) -> DeviceManager {
        unsafe { DeviceManager::obtain(&*self.frida) }
    }
}

impl Manager {
    /// Creates a new Manager with a Frida context
    pub fn new() -> Self {
        // Frida::obtain() is inherently unsafe as it manages global state
        let frida = Box::new(unsafe { Frida::obtain() });
        Manager { frida }
    }

    /// Obtains the device manager from the Frida context
    ///
    /// This method obtains a new DeviceManager each time it's called.
    /// While this has a small performance overhead, it's safer than storing
    /// a self-referential DeviceManager with an unsafe lifetime transmute.
    pub fn device_manager(&self) -> DeviceManager {
        unsafe { DeviceManager::obtain(&*self.frida) }
    }
}
