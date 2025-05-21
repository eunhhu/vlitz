use frida::Script;

use super::vzdata::{string_to_u64, VzBase, VzDataType, VzModule};

pub fn list_modules(script: &mut Script, filter: Option<&str>) -> Vec<VzModule> {
    let modules = script.exports.call("list_modules", Some(filter.into()));
    modules.unwrap().unwrap().as_array().unwrap().iter().map(|m| {
        let name = m.get("name").unwrap().as_str().unwrap().to_string();
        let base = m.get("base").unwrap().as_str().unwrap();
        let size = m.get("size").unwrap().as_u64().unwrap() as usize;
        VzModule {
            base: VzBase {
                data_type: VzDataType::Module,
                is_saved: false,
            },
            name, address: string_to_u64(base), size
        }
    }).collect()
}