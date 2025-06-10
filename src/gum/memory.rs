use frida::Script;
use serde_json::json;
use super::vzdata::{VzData, VzValueType};
use crossterm::style::Stylize;

pub fn readbyte(script: &mut Script, addr: u64) -> Result<u8, String> {
    let data = script
        .exports
        .call("reader_byte", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.ok_or_else(|| "No data returned".to_string())?;
    let value = binding.as_u64().ok_or_else(|| "Invalid byte".to_string())?;
    Ok(value as u8)
}

pub fn readshort(script: &mut Script, addr: u64) -> Result<i16, String> {
    let data = script
        .exports
        .call("reader_short", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.ok_or_else(|| "No data returned".to_string())?;
    let value = binding
        .as_i64()
        .ok_or_else(|| "Invalid short".to_string())?;
    Ok(value as i16)
}

pub fn readushort(script: &mut Script, addr: u64) -> Result<u16, String> {
    let data = script
        .exports
        .call("reader_ushort", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.ok_or_else(|| "No data returned".to_string())?;
    let value = binding
        .as_u64()
        .ok_or_else(|| "Invalid ushort".to_string())?;
    Ok(value as u16)
}

pub fn readint(script: &mut Script, addr: u64) -> Result<i32, String> {
    let data = script
        .exports
        .call("reader_int", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.ok_or_else(|| "No data returned".to_string())?;
    let value = binding.as_i64().ok_or_else(|| "Invalid int".to_string())?;
    Ok(value as i32)
}

pub fn readuint(script: &mut Script, addr: u64) -> Result<u32, String> {
    let data = script
        .exports
        .call("reader_uint", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.ok_or_else(|| "No data returned".to_string())?;
    let value = binding.as_u64().ok_or_else(|| "Invalid uint".to_string())?;
    Ok(value as u32)
}

pub fn readlong(script: &mut Script, addr: u64) -> Result<i64, String> {
    let data = script
        .exports
        .call("reader_long", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.ok_or_else(|| "No data returned".to_string())?;
    let value = binding.as_i64().ok_or_else(|| "Invalid long".to_string())?;
    Ok(value)
}

pub fn readulong(script: &mut Script, addr: u64) -> Result<u64, String> {
    let data = script
        .exports
        .call("reader_ulong", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.ok_or_else(|| "No data returned".to_string())?;
    let value = binding
        .as_u64()
        .ok_or_else(|| "Invalid ulong".to_string())?;
    Ok(value)
}

pub fn readfloat(script: &mut Script, addr: u64) -> Result<f32, String> {
    let data = script
        .exports
        .call("reader_float", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.ok_or_else(|| "No data returned".to_string())?;
    let value = binding
        .as_f64()
        .ok_or_else(|| "Invalid float".to_string())?;
    Ok(value as f32)
}

pub fn readdouble(script: &mut Script, addr: u64) -> Result<f64, String> {
    let data = script
        .exports
        .call("reader_double", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.ok_or_else(|| "No data returned".to_string())?;
    let value = binding
        .as_f64()
        .ok_or_else(|| "Invalid double".to_string())?;
    Ok(value)
}

pub fn readstring(script: &mut Script, addr: u64) -> Result<String, String> {
    let data = script
        .exports
        .call("reader_string", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.ok_or_else(|| "No data returned".to_string())?;
    let value = binding
        .as_str()
        .ok_or_else(|| "Invalid string".to_string())?;
    Ok(value.to_string())
}

pub fn readbytes(script: &mut Script, addr: u64, len: usize) -> Result<Vec<u8>, String> {
    let data = script
        .exports
        .call("reader_bytes", Some(json!([addr, len])))
        .map_err(|e| e.to_string())?;
    let binding = data.ok_or_else(|| "No data returned".to_string())?;
    let arr = binding
        .as_array()
        .ok_or_else(|| "Invalid byte array".to_string())?;
    Ok(arr.iter().map(|v| v.as_u64().unwrap_or(0) as u8).collect())
}

pub fn writebyte(script: &mut Script, addr: u64, value: u8) -> Result<(), String> {
    script
        .exports
        .call("writer_byte", Some(json!([addr, value])))
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn writeshort(script: &mut Script, addr: u64, value: i16) -> Result<(), String> {
    script
        .exports
        .call("writer_short", Some(json!([addr, value])))
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn writeushort(script: &mut Script, addr: u64, value: u16) -> Result<(), String> {
    script
        .exports
        .call("writer_ushort", Some(json!([addr, value])))
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn writeint(script: &mut Script, addr: u64, value: i32) -> Result<(), String> {
    script
        .exports
        .call("writer_int", Some(json!([addr, value])))
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn writeuint(script: &mut Script, addr: u64, value: u32) -> Result<(), String> {
    script
        .exports
        .call("writer_uint", Some(json!([addr, value])))
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn writelong(script: &mut Script, addr: u64, value: i64) -> Result<(), String> {
    script
        .exports
        .call("writer_long", Some(json!([addr, value])))
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn writeulong(script: &mut Script, addr: u64, value: u64) -> Result<(), String> {
    script
        .exports
        .call("writer_ulong", Some(json!([addr, value])))
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn writefloat(script: &mut Script, addr: u64, value: f32) -> Result<(), String> {
    script
        .exports
        .call("writer_float", Some(json!([addr, value])))
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn writedouble(script: &mut Script, addr: u64, value: f64) -> Result<(), String> {
    script
        .exports
        .call("writer_double", Some(json!([addr, value])))
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn writestring(script: &mut Script, addr: u64, value: &str) -> Result<(), String> {
    script
        .exports
        .call("writer_string", Some(json!([addr, value])))
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn writebytes(script: &mut Script, addr: u64, value: &[u8]) -> Result<(), String> {
    script
        .exports
        .call("writer_bytes", Some(json!([addr, value])))
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn parse_hex_or_decimal(s: &str) -> Result<u64, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|_| format!("Invalid hex number: {}", s))
    } else {
        s.parse::<u64>().map_err(|_| format!("Invalid number: {}", s))
    }
}

fn get_address_from_data(data: &VzData) -> Option<u64> {
    match data {
        VzData::Pointer(p) => Some(p.address),
        VzData::Module(m) => Some(m.address),
        VzData::Range(r) => Some(r.address),
        VzData::Function(f) => Some(f.address),
        VzData::Variable(v) => Some(v.address),
        _ => None,
    }
}

fn parse_value_type(s: &str) -> VzValueType {
    match s.to_lowercase().as_str() {
        "byte" | "int8" => VzValueType::Byte,
        "ubyte" | "uint8" => VzValueType::UByte,
        "short" | "int16" => VzValueType::Short,
        "ushort" | "uint16" => VzValueType::UShort,
        "int" | "int32" => VzValueType::Int,
        "uint" | "uint32" => VzValueType::UInt,
        "long" | "int64" => VzValueType::Long,
        "ulong" | "uint64" => VzValueType::ULong,
        "float" | "float32" => VzValueType::Float,
        "double" | "float64" => VzValueType::Double,
        "bool" | "boolean" => VzValueType::Bool,
        "string" | "utf8" => VzValueType::String,
        "bytes" | "array" => VzValueType::Bytes,
        "pointer" => VzValueType::Pointer,
        _ => VzValueType::Byte, // Default to byte
    }
}

pub fn read_memory_by_type(
    script: &mut Script,
    addr: u64,
    value_type: &VzValueType,
    length: Option<usize>,
) -> Result<String, String> {
    match value_type {
        VzValueType::Byte | VzValueType::Int8 => {
            let val = readbyte(script, addr)?;
            Ok(format!("{} ({})", val, format!("{:#04x}", val).dark_grey()))
        }
        VzValueType::UByte | VzValueType::UInt8 => {
            let val = readbyte(script, addr)?;
            Ok(format!("{} ({})", val, format!("{:#04x}", val).dark_grey()))
        }
        VzValueType::Short | VzValueType::Int16 => {
            let val = readshort(script, addr)?;
            Ok(format!("{} ({})", val, format!("{:#06x}", val).dark_grey()))
        }
        VzValueType::UShort | VzValueType::UInt16 => {
            let val = readushort(script, addr)?;
            Ok(format!("{} ({})", val, format!("{:#06x}", val).dark_grey()))
        }
        VzValueType::Int | VzValueType::Int32 => {
            let val = readint(script, addr)?;
            Ok(format!("{} ({})", val, format!("{:#010x}", val).dark_grey()))
        }
        VzValueType::UInt | VzValueType::UInt32 => {
            let val = readuint(script, addr)?;
            Ok(format!("{} ({})", val, format!("{:#010x}", val).dark_grey()))
        }
        VzValueType::Long | VzValueType::Int64 => {
            let val = readlong(script, addr)?;
            Ok(format!("{} ({})", val, format!("{:#018x}", val).dark_grey()))
        }
        VzValueType::ULong | VzValueType::UInt64 => {
            let val = readulong(script, addr)?;
            Ok(format!("{} ({})", val, format!("{:#018x}", val).dark_grey()))
        }
        VzValueType::Float | VzValueType::Float32 => {
            let val = readfloat(script, addr)?;
            Ok(format!("{}", val))
        }
        VzValueType::Double | VzValueType::Float64 => {
            let val = readdouble(script, addr)?;
            Ok(format!("{}", val))
        }
        VzValueType::Bool | VzValueType::Boolean => {
            let val = readbyte(script, addr)?;
            Ok(format!("{}", val != 0))
        }
        VzValueType::String | VzValueType::Utf8 => {
            let val = readstring(script, addr)?;
            Ok(format!("\"{}\"", val))
        }
        VzValueType::Array | VzValueType::Bytes => {
            let len = length.unwrap_or(16);
            let val = readbytes(script, addr, len)?;
            let hex_str = val.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
            Ok(format!("[{}] ({})", hex_str, len))
        }
        VzValueType::Pointer => {
            let val = readulong(script, addr)?;
            Ok(format!("{:#018x}", val))
        }
        VzValueType::Void => Err("Cannot read void type".to_string()),
    }
}

pub fn write_memory_by_type(
    script: &mut Script,
    addr: u64,
    value_str: &str,
    value_type: &VzValueType,
) -> Result<(), String> {
    match value_type {
        VzValueType::Byte | VzValueType::Int8 => {
            let val = value_str.parse::<i8>().map_err(|_| "Invalid byte value")?;
            writebyte(script, addr, val as u8)
        }
        VzValueType::UByte | VzValueType::UInt8 => {
            let val = value_str.parse::<u8>().map_err(|_| "Invalid ubyte value")?;
            writebyte(script, addr, val)
        }
        VzValueType::Short | VzValueType::Int16 => {
            let val = value_str.parse::<i16>().map_err(|_| "Invalid short value")?;
            writeshort(script, addr, val)
        }
        VzValueType::UShort | VzValueType::UInt16 => {
            let val = value_str.parse::<u16>().map_err(|_| "Invalid ushort value")?;
            writeushort(script, addr, val)
        }
        VzValueType::Int | VzValueType::Int32 => {
            let val = value_str.parse::<i32>().map_err(|_| "Invalid int value")?;
            writeint(script, addr, val)
        }
        VzValueType::UInt | VzValueType::UInt32 => {
            let val = value_str.parse::<u32>().map_err(|_| "Invalid uint value")?;
            writeuint(script, addr, val)
        }
        VzValueType::Long | VzValueType::Int64 => {
            let val = value_str.parse::<i64>().map_err(|_| "Invalid long value")?;
            writelong(script, addr, val)
        }
        VzValueType::ULong | VzValueType::UInt64 => {
            let val = parse_hex_or_decimal(value_str).map_err(|_| "Invalid ulong value")?;
            writeulong(script, addr, val)
        }
        VzValueType::Float | VzValueType::Float32 => {
            let val = value_str.parse::<f32>().map_err(|_| "Invalid float value")?;
            writefloat(script, addr, val)
        }
        VzValueType::Double | VzValueType::Float64 => {
            let val = value_str.parse::<f64>().map_err(|_| "Invalid double value")?;
            writedouble(script, addr, val)
        }
        VzValueType::Bool | VzValueType::Boolean => {
            let val = match value_str.to_lowercase().as_str() {
                "true" | "1" => 1u8,
                "false" | "0" => 0u8,
                _ => return Err("Invalid boolean value, use true/false or 1/0".to_string()),
            };
            writebyte(script, addr, val)
        }
        VzValueType::String | VzValueType::Utf8 => {
            let clean_value = if value_str.starts_with('"') && value_str.ends_with('"') {
                &value_str[1..value_str.len()-1]
            } else {
                value_str
            };
            writestring(script, addr, clean_value)
        }
        VzValueType::Array | VzValueType::Bytes => {
            let bytes = if value_str.starts_with('[') && value_str.ends_with(']') {
                let inner = &value_str[1..value_str.len()-1];
                inner.split_whitespace()
                    .map(|s| u8::from_str_radix(s, 16).map_err(|_| "Invalid hex byte"))
                    .collect::<Result<Vec<u8>, _>>()?
            } else {
                value_str.split_whitespace()
                    .map(|s| u8::from_str_radix(s, 16).map_err(|_| "Invalid hex byte"))
                    .collect::<Result<Vec<u8>, _>>()?
            };
            writebytes(script, addr, &bytes)
        }
        VzValueType::Pointer => {
            let val = parse_hex_or_decimal(value_str).map_err(|_| "Invalid pointer value")?;
            writeulong(script, addr, val)
        }
        VzValueType::Void => Err("Cannot write void type".to_string()),
    }
}

pub fn resolve_address_argument(
    addr_arg: &str,
    field_data: &[VzData],
    lib_data: &[VzData],
    navigator_data: Option<&VzData>,
) -> Result<u64, String> {
    // Try to parse as direct address first
    if let Ok(addr) = parse_hex_or_decimal(addr_arg) {
        return Ok(addr);
    }

    // Try to parse as store selector (field:5 or lib:3)
    if let Some(colon_pos) = addr_arg.find(':') {
        let store_name = &addr_arg[..colon_pos];
        let selector = &addr_arg[colon_pos + 1..];
        
        let data = match store_name.to_lowercase().as_str() {
            "field" | "fld" | "f" => field_data,
            "lib" | "l" => lib_data,
            _ => return Err(format!("Unknown store: {}", store_name)),
        };
        
        if let Ok(index) = selector.parse::<usize>() {
            if index < data.len() {
                if let Some(addr) = get_address_from_data(&data[index]) {
                    return Ok(addr);
                } else {
                    return Err(format!("Data at {}:{} does not have an address", store_name, index));
                }
            } else {
                return Err(format!("Index {} out of bounds for store {}", index, store_name));
            }
        } else {
            return Err(format!("Invalid index: {}", selector));
        }
    }

    // Check if navigator has address data
    if let Some(nav_data) = navigator_data {
        if let Some(addr) = get_address_from_data(nav_data) {
            return Ok(addr);
        }
    }

    Err(format!("Cannot resolve address from: {}", addr_arg))
}
