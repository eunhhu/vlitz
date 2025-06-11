use super::vzdata::{VzData, VzValueType};
use crossterm::style::Stylize;
use frida::Script;
use serde_json::json;

macro_rules! impl_reader {
    ($name:ident, $ret:ty, $export:expr, $conv:ident) => {
        pub fn $name(script: &mut Script, addr: u64) -> Result<$ret, String> {
            let data = script
                .exports
                .call($export, Some(json!([addr])))
                .map_err(|e| e.to_string())?;
            let value = data
                .ok_or_else(|| "No data returned".to_string())?
                .$conv()
                .ok_or_else(|| format!("Invalid value for {}", stringify!($name)))?;
            Ok(value as $ret)
        }
    };
}

macro_rules! impl_writer {
    ($name:ident, $export:expr, $typ:ty) => {
        pub fn $name(script: &mut Script, addr: u64, value: $typ) -> Result<(), String> {
            script
                .exports
                .call($export, Some(json!([addr, value])))
                .map_err(|e| e.to_string())?;
            Ok(())
        }
    };
}

impl_reader!(readbyte, i8, "reader_byte", as_i64);
impl_reader!(readubyte, u8, "reader_ubyte", as_u64);
impl_reader!(readshort, i16, "reader_short", as_i64);
impl_reader!(readushort, u16, "reader_ushort", as_u64);
impl_reader!(readint, i32, "reader_int", as_i64);
impl_reader!(readuint, u32, "reader_uint", as_u64);
impl_reader!(readlong, i64, "reader_long", as_i64);
impl_reader!(readulong, u64, "reader_ulong", as_u64);
impl_reader!(readfloat, f32, "reader_float", as_f64);
impl_reader!(readdouble, f64, "reader_double", as_f64);

pub fn readstring(script: &mut Script, addr: u64, len: Option<usize>) -> Result<String, String> {
    let data = script
        .exports
        .call("reader_string", Some(json!([addr, len])))
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

impl_writer!(writebyte, "writer_byte", i8);
impl_writer!(writeubyte, "writer_ubyte", u8);
impl_writer!(writeshort, "writer_short", i16);
impl_writer!(writeushort, "writer_ushort", u16);
impl_writer!(writeint, "writer_int", i32);
impl_writer!(writeuint, "writer_uint", u32);
impl_writer!(writelong, "writer_long", i64);
impl_writer!(writeulong, "writer_ulong", u64);
impl_writer!(writefloat, "writer_float", f32);
impl_writer!(writedouble, "writer_double", f64);

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

pub fn parse_hex_or_decimal(s: &str) -> Result<u64, String> {
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).map_err(|_| format!("Invalid hex number: {}", s))
    } else {
        s.parse::<u64>().map_err(|_| format!("Invalid number: {}", s))
    }
}

pub fn get_address_from_data(data: &VzData) -> Option<u64> {
    match data {
        VzData::Pointer(p) => Some(p.address),
        VzData::Module(m) => Some(m.address),
        VzData::Range(r) => Some(r.address),
        VzData::Function(f) => Some(f.address),
        VzData::Variable(v) => Some(v.address),
        _ => None,
    }
}

pub fn parse_value_type(s: &str) -> VzValueType {
    match s.to_lowercase().as_str() {
        "b" | "byte" | "int8" => VzValueType::Byte,
        "ub" | "ubyte" | "uint8" => VzValueType::UByte,
        "s" | "short" | "int16" => VzValueType::Short,
        "us" | "ushort" | "uint16" => VzValueType::UShort,
        "i" | "int" | "int32" => VzValueType::Int,
        "ui" | "uint" | "uint32" => VzValueType::UInt,
        "l" | "long" | "int64" => VzValueType::Long,
        "ul" | "ulong" | "uint64" => VzValueType::ULong,
        "f" | "float" | "float32" => VzValueType::Float,
        "d" | "double" | "float64" => VzValueType::Double,
        "bl" | "bool" | "boolean" => VzValueType::Bool,
        "str" | "string" | "utf8" => VzValueType::String,
        "bs" | "arr" | "bytes" | "array" => VzValueType::Bytes,
        "p" | "pointer" => VzValueType::Pointer,
        "" => VzValueType::Byte, // Default to Byte if empty
        _ => {
            VzValueType::Void // Return Void for unknown types
        }
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
            let val = readubyte(script, addr)?;
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
            let val = readstring(script, addr, length)?;
            Ok(format!("\"{}\"", val))
        }
        VzValueType::Array | VzValueType::Bytes => {
            let len = length.unwrap_or(16);
            let val = readbytes(script, addr, len)?;
            let hex_str = val.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
            Ok(format!("{} ({})", hex_str, len))
        }
        VzValueType::Pointer => {
            let val = readulong(script, addr)?;
            Ok(format!("{:#018x}", val))
        }
        VzValueType::Void => Err("Cannot read type".to_string()),
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
            writebyte(script, addr, val)
        }
        VzValueType::UByte | VzValueType::UInt8 => {
            let val = value_str.parse::<u8>().map_err(|_| "Invalid ubyte value")?;
            writeubyte(script, addr, val)
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
                "true" | "1" => 1i8,
                "false" | "0" => 0i8,
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

pub fn view_memory(
    script: &mut Script,
    addr: u64,
    _value_type: &VzValueType,
    length: usize,
) -> Result<String, String> {
    let bytes = readbytes(script, addr, length)?;
    if bytes.is_empty() {
        return Err("No data read from memory".to_string());
    }
    
    let mut output = String::new();
    
    // Header with column numbers
    output.push_str(&format!("{}    {}\n", 
        "           ".dark_grey(),
        "0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F    0123456789ABCDEF".cyan()
    ));
    
    // Process bytes in 16-byte chunks
    for (chunk_idx, chunk) in bytes.chunks(16).enumerate() {
        let current_addr = addr + (chunk_idx * 16) as u64;
        
        // Address column
        output.push_str(&format!("{:#010x}  ", current_addr).yellow().to_string());
        
        // Hex bytes
        for &byte in chunk.iter() {
            let hex_str = format!("{:02x}", byte);
            let colored_hex = match byte {
                0x00 => hex_str.dark_grey(),
                0x20..=0x7E => hex_str.green(),  // Printable ASCII
                0xFF => hex_str.red(),
                _ => hex_str.white(),
            };
            output.push_str(&format!("{} ", colored_hex));
        }
        
        // Pad remaining hex columns if chunk is less than 16 bytes
        for _ in chunk.len()..16 {
            output.push_str("   ");
        }
        
        // ASCII representation separator
        output.push_str("   ");
        
        // ASCII representation
        for &byte in chunk {
            let ascii_char = if byte >= 0x20 && byte <= 0x7E {
                (byte as char).to_string().green()
            } else {
                ".".to_string().dark_grey()
            };
            output.push_str(&ascii_char.to_string());
        }
        
        // Pad remaining ASCII columns if chunk is less than 16 bytes
        for _ in chunk.len()..16 {
            output.push(' ');
        }
        
        output.push('\n');
    }
    
    Ok(output)
}