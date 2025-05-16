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
}