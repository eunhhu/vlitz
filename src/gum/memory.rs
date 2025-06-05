use serde_json::{json, Value};
use frida::Script;

pub fn readbyte(script: &mut Script, addr: u64) -> Result<u8, String> {
    let data = script.exports
        .call("reader_byte", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.unwrap();
    Ok(binding.as_u64().unwrap() as u8)
}

pub fn readshort(script: &mut Script, addr: u64) -> Result<i16, String> {
    let data = script.exports
        .call("reader_short", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.unwrap();
    Ok(binding.as_i64().unwrap() as i16)
}

pub fn readushort(script: &mut Script, addr: u64) -> Result<u16, String> {
    let data = script.exports
        .call("reader_ushort", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.unwrap();
    Ok(binding.as_u64().unwrap() as u16)
}

pub fn readint(script: &mut Script, addr: u64) -> Result<i32, String> {
    let data = script.exports
        .call("reader_int", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.unwrap();
    Ok(binding.as_i64().unwrap() as i32)
}

pub fn readuint(script: &mut Script, addr: u64) -> Result<u32, String> {
    let data = script.exports
        .call("reader_uint", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.unwrap();
    Ok(binding.as_u64().unwrap() as u32)
}

pub fn readlong(script: &mut Script, addr: u64) -> Result<i64, String> {
    let data = script.exports
        .call("reader_long", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.unwrap();
    Ok(binding.as_i64().unwrap())
}

pub fn readulong(script: &mut Script, addr: u64) -> Result<u64, String> {
    let data = script.exports
        .call("reader_ulong", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.unwrap();
    Ok(binding.as_u64().unwrap())
}

pub fn readfloat(script: &mut Script, addr: u64) -> Result<f32, String> {
    let data = script.exports
        .call("reader_float", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.unwrap();
    Ok(binding.as_f64().unwrap() as f32)
}

pub fn readdouble(script: &mut Script, addr: u64) -> Result<f64, String> {
    let data = script.exports
        .call("reader_double", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.unwrap();
    Ok(binding.as_f64().unwrap())
}

pub fn readstring(script: &mut Script, addr: u64) -> Result<String, String> {
    let data = script.exports
        .call("reader_string", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.unwrap();
    Ok(binding.as_str().unwrap().to_string())
}

pub fn readbytes(script: &mut Script, addr: u64, len: usize) -> Result<Vec<u8>, String> {
    let data = script.exports
        .call("reader_bytes", Some(json!([addr, len])))
        .map_err(|e| e.to_string())?;
    let binding = data.unwrap();
    Ok(binding.as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u8).collect())
}

pub fn readinstruction(script: &mut Script, addr: u64) -> Result<String, String> {
    let data = script.exports
        .call("instruction", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let binding = data.unwrap();
    Ok(binding.as_str().unwrap().to_string())
}

pub fn writebyte(script: &mut Script, addr: u64, value: u8) -> Result<(), String> {
    script.exports
        .call("writer_byte", Some(json!([addr, value])))
        .map_err(|e| e.to_string())?;
    Ok(())
}