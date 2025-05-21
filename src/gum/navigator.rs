// src/gum/navigator.rs
use std::fmt;
use crossterm::style::Stylize;
use super::vzdata::{VzData};

#[derive(Debug, Clone)]
pub struct Navigator {
    pub data: Option<VzData>
}

impl fmt::Display for Navigator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.data {
            Some(data) => match data {
                VzData::Pointer(p) => write!(f, "{}{}",
                    format!("{}:", p.base.data_type.to_string().blue()),
                    format!("{:#x}", p.address).yellow(),
                ),
                VzData::Module(m) => write!(f, "{}{}{}",
                    format!("{}:", m.base.data_type.to_string().blue()),
                    format!("{} ", m.name).yellow(),
                    format!("@{:#x}", m.address).yellow(),
                ),
                VzData::Range(r) => write!(f, "{}{}",
                    format!("{}:", r.base.data_type.to_string().blue()),
                    format!("{:#x}", r.address).yellow(),
                ),
                VzData::Function(func) => write!(f, "{}{}{}",
                    format!("{}:", func.base.data_type.to_string().blue()),
                    format!("{} ", func.name).yellow(),
                    format!("@{:#x}", func.address).yellow(),
                ),
                VzData::Variable(v) => write!(f, "{}{}{}",
                    format!("{}:", v.base.data_type.to_string().blue()),
                    format!("{} ", v.name).yellow(),
                    format!("@{:#x}", v.address).yellow(),
                ),
                VzData::JavaClass(jc) => write!(f, "{}{}",
                    format!("{}:", jc.base.data_type.to_string().blue()),
                    jc.name,
                ),
                VzData::JavaMethod(jm) => write!(f, "{}{}",
                    format!("{}:", jm.base.data_type.to_string().blue()),
                    jm.name,
                ),
                VzData::ObjCClass(oc) => write!(f, "{}{}",
                    format!("{}:", oc.base.data_type.to_string().blue()),
                    oc.name,
                ),
                VzData::ObjCMethod(om) => write!(f, "{}{}",
                    format!("{}:", om.base.data_type.to_string().blue()),
                    om.name,
                ),
                VzData::Thread(t) => write!(f, "{}{}",
                    format!("{}:", t.base.data_type.to_string().blue()),
                    format!("{}", t.id).yellow(),
                ),
            },
            None => write!(f, "{}", "vlitz".blue()),
        }
    }
}

impl Navigator {
    pub fn new() -> Self {
        Navigator {
            data: None,
        }
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
        // 만약 address가 있는 VzData라면, 선택된 데이터를 Pointer로 바꾸고 offset만큼 더한다.
        // 그렇지 않다면, 아무것도 하지 않는다.
        if let Some(data) = self.data.as_mut() {
            if let VzData::Pointer(p) = data {
                p.address += offset;
            }
        }
    }
}