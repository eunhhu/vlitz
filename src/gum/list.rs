// src/gum/list.rs
use super::vzdata::{string_to_u64, VzBase, VzDataType, VzFunction, VzModule, VzRange, VzVariable};
use crate::gum::filter::parse_filter_string_to_json;
use frida::Script;
use serde_json::{json, Value};

pub fn list_modules(script: &mut Script, filter: Option<&str>) -> Result<Vec<VzModule>, String> {
    let filter = parse_filter_string_to_json(filter.unwrap_or("")).unwrap_or(json!([]));
    let modules = script
        .exports
        .call("list_modules", Some(json!([filter])))
        .map_err(|e| e.to_string())?;
    let binding = modules.ok_or_else(|| "No modules returned".to_string())?;
    let mod_arr = binding
        .as_array()
        .ok_or_else(|| "Expected object of modules".to_string())?;
    mod_arr
        .iter()
        .map(|m: &Value| {
            let obj = m
                .as_object()
                .ok_or_else(|| "Expected object of module".to_string())?;

            let name = obj
                .get("name")
                .ok_or_else(|| "Expected name of module".to_string())?
                .as_str()
                .ok_or_else(|| "Expected string name of module".to_string())?
                .to_string();
            let address = obj
                .get("address")
                .ok_or_else(|| "Expected address of module".to_string())?
                .as_str()
                .ok_or_else(|| "Expected string address of module".to_string())?
                .to_string();
            let size = obj
                .get("size")
                .ok_or_else(|| "Expected size of module".to_string())?
                .as_u64()
                .ok_or_else(|| "Expected u64 size of module".to_string())?;

            Ok(VzModule {
                base: VzBase {
                    data_type: VzDataType::Module,
                    is_saved: false,
                },
                name,
                address: string_to_u64(&address),
                size: size as usize,
            })
        })
        .collect::<Result<Vec<_>, _>>()
}

pub fn list_ranges(
    script: &mut Script,
    protect: Option<&str>,
    filter: Option<&str>,
) -> Result<Vec<VzRange>, String> {
    let protect = protect.unwrap_or("---");
    let filter = parse_filter_string_to_json(filter.unwrap_or("")).unwrap_or(json!([]));
    let ranges = script
        .exports
        .call("list_ranges", Some(json!([protect, filter])))
        .map_err(|e| e.to_string())?;
    let binding = ranges.ok_or_else(|| "No ranges returned".to_string())?;
    let range_arr = binding
        .as_array()
        .ok_or_else(|| "Expected object of ranges".to_string())?;
    range_arr
        .iter()
        .map(|r: &Value| {
            let obj = r
                .as_object()
                .ok_or_else(|| "Expected object of range".to_string())?;
            let address = obj
                .get("address")
                .ok_or_else(|| "Expected address of range".to_string())?
                .as_str()
                .ok_or_else(|| "Expected string address of range".to_string())?
                .to_string();
            let size = obj
                .get("size")
                .ok_or_else(|| "Expected size of range".to_string())?
                .as_u64()
                .ok_or_else(|| "Expected u64 size of range".to_string())?;
            let protection = obj
                .get("protection")
                .ok_or_else(|| "Expected protection of range".to_string())?
                .as_str()
                .ok_or_else(|| "Expected string protection of range".to_string())?
                .to_string();
            Ok(VzRange {
                base: VzBase {
                    data_type: VzDataType::Range,
                    is_saved: false,
                },
                address: string_to_u64(&address),
                size: size as usize,
                protection,
            })
        })
        .collect::<Result<Vec<_>, _>>()
}

pub fn list_functions(
    script: &mut Script,
    md: VzModule,
    filter: Option<&str>,
) -> Result<Vec<VzFunction>, String> {
    let filter = parse_filter_string_to_json(filter.unwrap_or("")).unwrap_or(json!([]));
    let functions = script
        .exports
        .call("list_functions", Some(json!([md.address, filter])))
        .map_err(|e| e.to_string())?;
    let binding = functions.ok_or_else(|| "No functions returned".to_string())?;
    let func_arr = binding
        .as_array()
        .ok_or_else(|| "Expected object of functions".to_string())?;
    func_arr
        .iter()
        .map(|f: &Value| {
            let obj = f
                .as_object()
                .ok_or_else(|| "Expected object of function".to_string())?;
            let name = obj
                .get("name")
                .ok_or_else(|| "Expected name of function".to_string())?
                .as_str()
                .ok_or_else(|| "Expected string name of function".to_string())?
                .to_string();
            let address = obj
                .get("address")
                .ok_or_else(|| "Expected address of function".to_string())?
                .as_str()
                .ok_or_else(|| "Expected string address of function".to_string())?
                .to_string();
            let module = obj
                .get("module")
                .ok_or_else(|| "Expected module of function".to_string())?
                .as_str()
                .ok_or_else(|| "Expected string module of function".to_string())?
                .to_string();
            Ok(VzFunction {
                base: VzBase {
                    data_type: VzDataType::Function,
                    is_saved: false,
                },
                name,
                address: string_to_u64(&address),
                module,
            })
        })
        .collect::<Result<Vec<_>, _>>()
}

pub fn list_variables(
    script: &mut Script,
    md: VzModule,
    filter: Option<&str>,
) -> Result<Vec<VzVariable>, String> {
    let filter = parse_filter_string_to_json(filter.unwrap_or("")).unwrap_or(json!([]));
    let variables = script
        .exports
        .call("list_variables", Some(json!([md.address, filter])))
        .map_err(|e| e.to_string())?;
    let binding = variables.ok_or_else(|| "No variables returned".to_string())?;
    let var_arr = binding
        .as_array()
        .ok_or_else(|| "Expected object of variables".to_string())?;
    var_arr
        .iter()
        .map(|v: &Value| {
            let obj = v
                .as_object()
                .ok_or_else(|| "Expected object of variable".to_string())?;
            let name = obj
                .get("name")
                .ok_or_else(|| "Expected name of variable".to_string())?
                .as_str()
                .ok_or_else(|| "Expected string name of variable".to_string())?
                .to_string();
            let address = obj
                .get("address")
                .ok_or_else(|| "Expected address of variable".to_string())?
                .as_str()
                .ok_or_else(|| "Expected string address of variable".to_string())?
                .to_string();
            let module = obj
                .get("module")
                .ok_or_else(|| "Expected module of variable".to_string())?
                .as_str()
                .ok_or_else(|| "Expected string module of variable".to_string())?
                .to_string();
            Ok(VzVariable {
                base: VzBase {
                    data_type: VzDataType::Variable,
                    is_saved: false,
                },
                name,
                address: string_to_u64(&address),
                module,
            })
        })
        .collect::<Result<Vec<_>, _>>()
}
