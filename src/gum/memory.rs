use frida::Script;
use serde_json::{json, Value};

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
