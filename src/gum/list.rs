use frida::Script;

use super::vzdata::{string_to_u64, VzBase, VzDataType, VzModule};
use serde_json::json;

pub fn list_modules(script: &mut Script, filter: Option<&str>) -> Result<Vec<VzModule>, String> {
    let modules = script.exports
        .call("list_modules", Some(json!([filter.unwrap_or("")])))
        .map_err(|e| e.to_string())?;
    let binding = modules.unwrap();
    let mod_arr = binding.as_array()
        .ok_or_else(|| "Expected array of modules".to_string())?;
    mod_arr.iter().map(|m| {
            let name = m[0].as_str().unwrap();
            let base = m[1].as_str().unwrap();
            let size = m[2].as_u64().unwrap();

            Ok(VzModule {
                base: VzBase {
                    data_type: VzDataType::Module,
                    is_saved: false,
                },
                name: name.to_string(),
                address: string_to_u64(base),
                size: size as usize,
            })
        })
        .collect()
}