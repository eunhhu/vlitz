// src/gum/navigator.rs
use super::vzdata::{VzBase, VzData, VzDataType, VzPointer, VzValueType};
use crossterm::style::Stylize;
use std::fmt;

#[derive(Debug, Clone)]
pub struct Navigator {
    pub data: Option<VzData>,
}

impl fmt::Display for Navigator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.data {
            Some(data) => match data {
                VzData::Pointer(p) => write!(
                    f,
                    "{}{}",
                    format!("{}:", p.base.data_type.to_string()).blue(),
                    format!("{:#x}", p.address).yellow(),
                ),
                VzData::Module(m) => write!(
                    f,
                    "{}{}{}",
                    format!("{}:", m.base.data_type.to_string()).blue(),
                    format!("{}", m.name),
                    format!("@{:#x}", m.address).yellow(),
                ),
                VzData::Range(r) => write!(
                    f,
                    "{}{}",
                    format!("{}:", r.base.data_type.to_string()).blue(),
                    format!("{:#x}", r.address).yellow(),
                ),
                VzData::Function(func) => write!(
                    f,
                    "{}{}{}",
                    format!("{}:", func.base.data_type.to_string()).blue(),
                    format!("{}", func.name),
                    format!("@{:#x}", func.address).yellow(),
                ),
                VzData::Variable(v) => write!(
                    f,
                    "{}{}{}",
                    format!("{}:", v.base.data_type.to_string()).blue(),
                    format!("{}", v.name),
                    format!("@{:#x}", v.address).yellow(),
                ),
                VzData::JavaClass(jc) => write!(
                    f,
                    "{}{}",
                    format!("{}:", jc.base.data_type.to_string()).blue(),
                    jc.name,
                ),
                VzData::JavaMethod(jm) => write!(
                    f,
                    "{}{}",
                    format!("{}:", jm.base.data_type.to_string()).blue(),
                    jm.name,
                ),
                VzData::ObjCClass(oc) => write!(
                    f,
                    "{}{}",
                    format!("{}:", oc.base.data_type.to_string()).blue(),
                    oc.name,
                ),
                VzData::ObjCMethod(om) => write!(
                    f,
                    "{}{}",
                    format!("{}:", om.base.data_type.to_string()).blue(),
                    om.name,
                ),
                VzData::Thread(t) => write!(
                    f,
                    "{}{}",
                    format!("{}:", t.base.data_type.to_string()).blue(),
                    format!("{}", t.id).yellow(),
                ),
                VzData::Hook(h) => write!(
                    f,
                    "{}{}{}",
                    format!("{}:", h.base.data_type.to_string()).blue(),
                    format!("{}", h.id).yellow(),
                    format!("@{:#x}", h.address).yellow(),
                ),
                VzData::Instruction(i) => write!(f, "{}", format!("{:#x}", i.address).yellow(),),
                VzData::ScanResult(s) => write!(
                    f,
                    "{:#x} = {}",
                    s.address,
                    s.value.as_deref().unwrap_or(&"?".to_string()).cyan(),
                ),
                VzData::Import(imp) => write!(
                    f,
                    "{}{}",
                    format!("{}:", imp.base.data_type.to_string()).blue(),
                    imp.name,
                ),
                VzData::Symbol(sym) => write!(
                    f,
                    "{}{}",
                    format!("{}:", sym.base.data_type.to_string()).blue(),
                    sym.name,
                ),
            },
            None => write!(f, "{}", "vlitz".blue()),
        }
    }
}

impl Navigator {
    pub fn new() -> Self {
        Navigator { data: None }
    }
    pub fn select(&mut self, data: &VzData) {
        self.data = Some(data.clone());
    }
    pub fn deselect(&mut self) {
        self.data = None;
    }
    pub fn get_data(&self) -> Option<&VzData> {
        self.data.as_ref()
    }
    pub fn add(&mut self, offset: u64) {
        if let Some(data) = self.data.as_mut() {
            match data {
                VzData::Pointer(p) => p.address += offset,
                VzData::Module(m) => {
                    m.address += offset;
                    *data = VzData::Pointer(m.to_pointer());
                }
                VzData::Range(r) => {
                    r.address += offset;
                    *data = VzData::Pointer(r.to_pointer());
                }
                VzData::Function(func) => {
                    func.address += offset;
                    *data = VzData::Pointer(func.to_pointer());
                }
                VzData::Variable(v) => {
                    v.address += offset;
                    *data = VzData::Pointer(v.to_pointer());
                }
                _ => {}
            }
        }
    }
    pub fn sub(&mut self, offset: u64) {
        if let Some(data) = self.data.as_mut() {
            match data {
                VzData::Pointer(p) => p.address -= offset,
                VzData::Module(m) => {
                    m.address -= offset;
                    *data = VzData::Pointer(m.to_pointer());
                }
                VzData::Range(r) => {
                    r.address -= offset;
                    *data = VzData::Pointer(r.to_pointer());
                }
                VzData::Function(func) => {
                    func.address -= offset;
                    *data = VzData::Pointer(func.to_pointer());
                }
                VzData::Variable(v) => {
                    v.address -= offset;
                    *data = VzData::Pointer(v.to_pointer());
                }
                _ => {}
            }
        }
    }
    pub fn goto(&mut self, address: u64) {
        if let Some(data) = self.data.as_mut() {
            match data {
                VzData::Pointer(p) => p.address = address,
                VzData::Module(m) => {
                    m.address = address;
                    *data = VzData::Pointer(m.to_pointer());
                }
                VzData::Range(r) => {
                    r.address = address;
                    *data = VzData::Pointer(r.to_pointer());
                }
                VzData::Function(func) => {
                    func.address = address;
                    *data = VzData::Pointer(func.to_pointer());
                }
                VzData::Variable(v) => {
                    v.address = address;
                    *data = VzData::Pointer(v.to_pointer());
                }
                _ => {}
            }
        } else {
            self.data = Some(VzData::Pointer(VzPointer {
                base: VzBase {
                    data_type: VzDataType::Pointer,
                    is_saved: false,
                },
                address,
                size: 8,
                value_type: VzValueType::Pointer,
            }));
        }
    }
}
