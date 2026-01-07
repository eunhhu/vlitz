use super::vzdata::{VzData, VzValueType};
use crate::util::format::{get_header_padding, lengthed};
use crossterm::style::Stylize;
use frida::Script;
use serde_json::json;

macro_rules! impl_reader {
    ($name:ident, $ret:ty, $export:expr, $conv:ident) => {
        pub fn $name(script: &mut Script, addr: u64) -> Result<$ret, String> {
            if !check_read_protection(script, addr)? {
                let protection = get_memory_protection(script, addr)?;
                return Err(format!(
                    "Cannot read from address {:#x}: insufficient read permissions (protection: {})",
                    addr,
                    protection.unwrap_or("unknown".to_string())
                ));
            }

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
            if !check_write_protection(script, addr)? {
                let protection = get_memory_protection(script, addr)?;
                return Err(format!(
                    "Cannot write to address {:#x}: insufficient write permissions (protection: {})",
                    addr,
                    protection.unwrap_or("unknown".to_string())
                ));
            }

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
    if !check_read_protection(script, addr)? {
        let protection = get_memory_protection(script, addr)?;
        return Err(format!(
            "Cannot read from address {:#x}: insufficient read permissions (protection: {})",
            addr,
            protection.unwrap_or("unknown".to_string())
        ));
    }

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
    if !check_read_protection(script, addr)? {
        let protection = get_memory_protection(script, addr)?;
        return Err(format!(
            "Cannot read from address {:#x}: insufficient read permissions (protection: {})",
            addr,
            protection.unwrap_or("unknown".to_string())
        ));
    }

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
    if !check_write_protection(script, addr)? {
        let protection = get_memory_protection(script, addr)?;
        return Err(format!(
            "Cannot write to address {:#x}: insufficient write permissions (protection: {})",
            addr,
            protection.unwrap_or("unknown".to_string())
        ));
    }

    script
        .exports
        .call("writer_string", Some(json!([addr, value])))
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn writebytes(script: &mut Script, addr: u64, value: &[u8]) -> Result<(), String> {
    if !check_write_protection(script, addr)? {
        let protection = get_memory_protection(script, addr)?;
        return Err(format!(
            "Cannot write to address {:#x}: insufficient write permissions (protection: {})",
            addr,
            protection.unwrap_or("unknown".to_string())
        ));
    }

    script
        .exports
        .call("writer_bytes", Some(json!([addr, value])))
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn check_read_protection(script: &mut Script, addr: u64) -> Result<bool, String> {
    let data = script
        .exports
        .call("check_read_protection", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let result = data
        .ok_or_else(|| "No data returned".to_string())?
        .as_bool()
        .ok_or_else(|| "Invalid boolean value".to_string())?;
    Ok(result)
}

pub fn check_write_protection(script: &mut Script, addr: u64) -> Result<bool, String> {
    let data = script
        .exports
        .call("check_write_protection", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let result = data
        .ok_or_else(|| "No data returned".to_string())?
        .as_bool()
        .ok_or_else(|| "Invalid boolean value".to_string())?;
    Ok(result)
}

pub fn get_memory_protection(script: &mut Script, addr: u64) -> Result<Option<String>, String> {
    let data = script
        .exports
        .call("get_memory_protection", Some(json!([addr])))
        .map_err(|e| e.to_string())?;
    let result = data.ok_or_else(|| "No data returned".to_string())?;

    if result.is_null() {
        Ok(None)
    } else {
        let protection = result
            .as_str()
            .ok_or_else(|| "Invalid protection string".to_string())?;
        Ok(Some(protection.to_string()))
    }
}

pub fn get_address_from_data(data: &VzData) -> Option<u64> {
    match data {
        VzData::Pointer(p) => Some(p.address),
        VzData::Module(m) => Some(m.address),
        VzData::Range(r) => Some(r.address),
        VzData::Function(f) => Some(f.address),
        VzData::Variable(v) => Some(v.address),
        VzData::Hook(h) => Some(h.address),
        VzData::Instruction(i) => Some(i.address),
        VzData::ScanResult(s) => Some(s.address),
        VzData::Import(i) => i.address,
        VzData::Symbol(s) => Some(s.address),
        _ => None,
    }
}

pub fn parse_value_type(s: &str) -> Result<VzValueType, String> {
    match s.to_lowercase().as_str() {
        "b" | "byte" | "int8" => Ok(VzValueType::Byte),
        "ub" | "ubyte" | "uint8" => Ok(VzValueType::UByte),
        "s" | "short" | "int16" => Ok(VzValueType::Short),
        "us" | "ushort" | "uint16" => Ok(VzValueType::UShort),
        "i" | "int" | "int32" => Ok(VzValueType::Int),
        "ui" | "uint" | "uint32" => Ok(VzValueType::UInt),
        "l" | "long" | "int64" => Ok(VzValueType::Long),
        "ul" | "ulong" | "uint64" => Ok(VzValueType::ULong),
        "f" | "float" | "float32" => Ok(VzValueType::Float),
        "d" | "double" | "float64" => Ok(VzValueType::Double),
        "bl" | "bool" | "boolean" => Ok(VzValueType::Bool),
        "str" | "string" | "utf8" => Ok(VzValueType::String),
        "bs" | "arr" | "bytes" | "array" => Ok(VzValueType::Bytes),
        "p" | "pointer" => Ok(VzValueType::Pointer),
        "" => Ok(VzValueType::Byte), // Default to Byte if empty
        _ => Err(format!("Invalid memory type: '{}'", s)),
    }
}

pub fn read_memory_by_type(
    script: &mut Script,
    addr: u64,
    value_type: &VzValueType,
    length: Option<usize>,
    detailed: bool,
) -> Result<String, String> {
    match value_type {
        VzValueType::Byte | VzValueType::Int8 => {
            let val = readbyte(script, addr)?;
            let is_inactive = val == 0;
            if detailed {
                let result = format!("{} ({:#04x})", val, val as u8);
                Ok(format_value_with_color(&result, is_inactive))
            } else {
                Ok(format_value_with_color(&val.to_string(), is_inactive))
            }
        }
        VzValueType::UByte | VzValueType::UInt8 => {
            let val = readubyte(script, addr)?;
            let is_inactive = val == 0 || val == 0xFF;
            if detailed {
                let result = format!("{} ({:#04x})", val, val);
                Ok(format_value_with_color(&result, is_inactive))
            } else {
                Ok(format_value_with_color(&val.to_string(), is_inactive))
            }
        }
        VzValueType::Short | VzValueType::Int16 => {
            let val = readshort(script, addr)?;
            let is_inactive = val == 0;
            if detailed {
                let result = format!("{} ({})", val, format!("{:#06x}", val).dark_grey());
                Ok(format_value_with_color(&result, is_inactive))
            } else {
                Ok(format_value_with_color(&val.to_string(), is_inactive))
            }
        }
        VzValueType::UShort | VzValueType::UInt16 => {
            let val = readushort(script, addr)?;
            let is_inactive = val == 0 || val == 0xFFFF;
            if detailed {
                let result = format!("{} ({})", val, format!("{:#06x}", val).dark_grey());
                Ok(format_value_with_color(&result, is_inactive))
            } else {
                Ok(format_value_with_color(&val.to_string(), is_inactive))
            }
        }
        VzValueType::Int | VzValueType::Int32 => {
            let val = readint(script, addr)?;
            let is_inactive = val == 0;
            if detailed {
                let result = format!("{} ({})", val, format!("{:#010x}", val).dark_grey());
                Ok(format_value_with_color(&result, is_inactive))
            } else {
                Ok(format_value_with_color(&val.to_string(), is_inactive))
            }
        }
        VzValueType::UInt | VzValueType::UInt32 => {
            let val = readuint(script, addr)?;
            let is_inactive = val == 0 || val == 0xFFFFFFFF;
            if detailed {
                let result = format!("{} ({})", val, format!("{:#010x}", val).dark_grey());
                Ok(format_value_with_color(&result, is_inactive))
            } else {
                Ok(format_value_with_color(&val.to_string(), is_inactive))
            }
        }
        VzValueType::Long | VzValueType::Int64 => {
            let val = readlong(script, addr)?;
            let is_inactive = val == 0;
            if detailed {
                let result = format!("{} ({})", val, format!("{:#018x}", val).dark_grey());
                Ok(format_value_with_color(&result, is_inactive))
            } else {
                Ok(format_value_with_color(&val.to_string(), is_inactive))
            }
        }
        VzValueType::ULong | VzValueType::UInt64 => {
            let val = readulong(script, addr)?;
            let is_inactive = val == 0 || val == 0xFFFFFFFFFFFFFFFF;
            if detailed {
                let result = format!("{} ({})", val, format!("{:#018x}", val).dark_grey());
                Ok(format_value_with_color(&result, is_inactive))
            } else {
                Ok(format_value_with_color(&val.to_string(), is_inactive))
            }
        }
        VzValueType::Float | VzValueType::Float32 => {
            let val = readfloat(script, addr)?;
            let is_inactive = val == 0.0 || val.is_nan();
            if detailed {
                let bytes = val.to_bits();
                let result = format!("{} ({:#010x})", val, bytes);
                Ok(format_value_with_color(&result, is_inactive))
            } else {
                Ok(format_value_with_color(&val.to_string(), is_inactive))
            }
        }
        VzValueType::Double | VzValueType::Float64 => {
            let val = readdouble(script, addr)?;
            let is_inactive = val == 0.0 || val.is_nan();
            if detailed {
                let bytes = val.to_bits();
                let result = format!("{} ({:#018x})", val, bytes);
                Ok(format_value_with_color(&result, is_inactive))
            } else {
                Ok(format_value_with_color(&val.to_string(), is_inactive))
            }
        }
        VzValueType::Bool | VzValueType::Boolean => {
            let val = readbyte(script, addr)?;
            let bool_val = val != 0;
            let is_inactive = !bool_val; // false is considered inactive
            if detailed {
                let result = format!("{} ({:#04x})", bool_val, val as u8);
                Ok(format_value_with_color(&result, is_inactive))
            } else {
                Ok(format_value_with_color(
                    &format!("{}", bool_val),
                    is_inactive,
                ))
            }
        }
        VzValueType::String | VzValueType::Utf8 => {
            let val = readstring(script, addr, length)?;
            Ok(format!("\"{}\"", val))
        }
        VzValueType::Array | VzValueType::Bytes => {
            let len = length.unwrap_or(16);
            let val = readbytes(script, addr, len)?;
            let is_inactive = val.iter().all(|&b| b == 0 || b == 0xFF);
            let hex_str = val
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            if detailed {
                let result = format!("{} ({})", hex_str, len);
                Ok(format_value_with_color(&result, is_inactive))
            } else {
                Ok(format_value_with_color(&hex_str, is_inactive))
            }
        }
        VzValueType::Pointer => {
            let val = readulong(script, addr)?;
            let is_inactive = val == 0;
            let result = format!("{:#018x}", val);
            Ok(format_value_with_color(&result, is_inactive))
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
            let val = value_str
                .parse::<i16>()
                .map_err(|_| "Invalid short value")?;
            writeshort(script, addr, val)
        }
        VzValueType::UShort | VzValueType::UInt16 => {
            let val = value_str
                .parse::<u16>()
                .map_err(|_| "Invalid ushort value")?;
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
            let val = crate::util::format::parse_hex_or_decimal(value_str)
                .map_err(|_| "Invalid ulong value")?;
            writeulong(script, addr, val)
        }
        VzValueType::Float | VzValueType::Float32 => {
            let val = value_str
                .parse::<f32>()
                .map_err(|_| "Invalid float value")?;
            writefloat(script, addr, val)
        }
        VzValueType::Double | VzValueType::Float64 => {
            let val = value_str
                .parse::<f64>()
                .map_err(|_| "Invalid double value")?;
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
                &value_str[1..value_str.len() - 1]
            } else {
                value_str
            };
            writestring(script, addr, clean_value)
        }
        VzValueType::Array | VzValueType::Bytes => {
            let bytes = if value_str.starts_with('[') && value_str.ends_with(']') {
                let inner = &value_str[1..value_str.len() - 1];
                inner
                    .split_whitespace()
                    .map(|s| u8::from_str_radix(s, 16).map_err(|_| "Invalid hex byte"))
                    .collect::<Result<Vec<u8>, _>>()?
            } else {
                value_str
                    .split_whitespace()
                    .map(|s| u8::from_str_radix(s, 16).map_err(|_| "Invalid hex byte"))
                    .collect::<Result<Vec<u8>, _>>()?
            };
            writebytes(script, addr, &bytes)
        }
        VzValueType::Pointer => {
            let val = crate::util::format::parse_hex_or_decimal(value_str)
                .map_err(|_| "Invalid pointer value")?;
            writeulong(script, addr, val)
        }
        VzValueType::Void => Err("Cannot write void type".to_string()),
    }
}

pub fn view_memory(
    script: &mut Script,
    addr: u64,
    value_type: &VzValueType,
    length: usize,
) -> Result<String, String> {
    let bytes = readbytes(script, addr, length)?;
    if bytes.is_empty() {
        return Err("No data read from memory".to_string());
    }

    let mut output = String::new();

    // Header with column numbers - adaptive padding based on address width
    let header_padding = get_header_padding(addr);
    output.push_str(&format!(
        "{}{}     {}\n",
        header_padding.dark_grey(),
        "0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F".cyan(),
        "0123456789ABCDEF".cyan()
    ));

    let type_size = get_type_size(value_type);
    let use_hex_view = matches!(
        value_type,
        VzValueType::Byte
            | VzValueType::Int8
            | VzValueType::UByte
            | VzValueType::UInt8
            | VzValueType::String
            | VzValueType::Utf8
            | VzValueType::Array
            | VzValueType::Bytes
    );

    // Determine endianness once for this view when needed (single calibration read)
    let mut little_endian = true;
    if !use_hex_view && type_size > 1 {
        if let Ok(det) = determine_endianness(script, addr, value_type, &bytes[..type_size]) {
            little_endian = det;
        }
    }

    // Process bytes in 16-byte chunks
    for (chunk_idx, chunk) in bytes.chunks(16).enumerate() {
        let current_addr = addr + (chunk_idx * 16) as u64;

        // Address column - adaptive width
        let addr_width = crate::util::format::get_address_width(current_addr);
        let addr_format = match addr_width {
            6 => format!("{:#06x}", current_addr),
            10 => format!("{:#010x}", current_addr),
            18 => format!("{:#018x}", current_addr),
            _ => format!("{:#x}", current_addr),
        };
        output.push_str(&addr_format.yellow().to_string());
        output.push(' ');

        // Value representation based on type
        let mut type_column = String::new();
        let mut offset = 0;

        if use_hex_view {
            for (i, &byte) in chunk.iter().enumerate() {
                if i < 16 {
                    let formatted_byte = format_hex_byte_with_color(byte);
                    type_column.push_str(&format!("{} ", formatted_byte));
                }
            }
            for _ in chunk.len()..16 {
                type_column.push_str("   ");
            }
        } else {
            // Process values according to type size for other types, decoding locally from the buffer
            while offset < chunk.len() && offset < 16 {
                if offset + type_size <= chunk.len() {
                    let slice = &chunk[offset..offset + type_size];
                    let value = decode_value_to_string_from_bytes(value_type, slice, little_endian);

                    let is_zero_value = is_zero_or_inactive_value(&value);
                    let formatted_value = match value_type {
                        VzValueType::Float | VzValueType::Float32 => lengthed(&value, 3 * 4 - 1),
                        VzValueType::Double | VzValueType::Float64 => lengthed(&value, 3 * 8 - 1),
                        VzValueType::Short
                        | VzValueType::UShort
                        | VzValueType::Int16
                        | VzValueType::UInt16 => lengthed(&value, 3 * 2 - 1),
                        VzValueType::Int
                        | VzValueType::UInt
                        | VzValueType::Int32
                        | VzValueType::UInt32 => lengthed(&value, 3 * 4 - 1),
                        VzValueType::Long
                        | VzValueType::ULong
                        | VzValueType::Int64
                        | VzValueType::UInt64 => lengthed(&value, 3 * 8 - 1),
                        VzValueType::Pointer => lengthed(&value, 3 * 8 - 1),
                        VzValueType::Bool | VzValueType::Boolean => lengthed(&value, 3 - 1),
                        _ => lengthed(&value, 3 * 4 - 1),
                    };

                    let colored_value = if is_zero_value {
                        formatted_value.dark_grey().to_string()
                    } else {
                        formatted_value.cyan().to_string()
                    };
                    type_column.push_str(&colored_value);
                    type_column.push(' ');
                    offset += type_size;
                } else {
                    break;
                }
            }
        }

        while type_column.len() < 48 {
            type_column.push(' ');
        }
        output.push_str(&type_column);
        output.push_str("     ");

        // ASCII representation
        for &byte in chunk {
            let ascii_char = if byte >= 0x20 && byte <= 0x7E {
                let char_str = (byte as char).to_string();
                if is_inactive_value(byte) {
                    char_str.dark_grey()
                } else {
                    char_str.green()
                }
            } else if is_inactive_value(byte) {
                ".".to_string().dark_grey()
            } else {
                ".".to_string().dark_grey()
            };
            output.push_str(&ascii_char.to_string());
        }

        for _ in chunk.len()..16 {
            output.push(' ');
        }

        output.push('\n');
    }

    Ok(output)
}

fn get_type_size(value_type: &VzValueType) -> usize {
    match value_type {
        VzValueType::Byte | VzValueType::Int8 => 1,
        VzValueType::UByte | VzValueType::UInt8 => 1,
        VzValueType::Short | VzValueType::Int16 => 2,
        VzValueType::UShort | VzValueType::UInt16 => 2,
        VzValueType::Int | VzValueType::Int32 => 4,
        VzValueType::UInt | VzValueType::UInt32 => 4,
        VzValueType::Long | VzValueType::Int64 => 8,
        VzValueType::ULong | VzValueType::UInt64 => 8,
        VzValueType::Float | VzValueType::Float32 => 4,
        VzValueType::Double | VzValueType::Float64 => 8,
        VzValueType::Bool | VzValueType::Boolean => 1,
        VzValueType::Pointer => 8,
        VzValueType::String | VzValueType::Utf8 => 1,
        VzValueType::Array | VzValueType::Bytes => 1,
        VzValueType::Void => 1,
    }
}

fn is_inactive_value(byte: u8) -> bool {
    byte == 0x00 || byte == 0xFF
}

fn format_hex_byte_with_color(byte: u8) -> String {
    let hex_str = format!("{:02x}", byte);
    if is_inactive_value(byte) {
        hex_str.dark_grey().to_string()
    } else {
        hex_str.cyan().to_string()
    }
}

fn format_value_with_color(value: &str, is_inactive: bool) -> String {
    if is_inactive {
        value.dark_grey().to_string()
    } else {
        value.to_string()
    }
}

fn is_zero_or_inactive_value(value: &str) -> bool {
    value == "0" || value == "0.0" || value == "false" || value == "0x0000000000000000"
}

// Determine target endianness by comparing a single typed read with decoding the first value from the buffer.
fn determine_endianness(
    script: &mut Script,
    addr: u64,
    value_type: &VzValueType,
    first: &[u8],
) -> Result<bool, String> {
    let type_size = get_type_size(value_type);
    if first.len() < type_size || type_size <= 1 {
        return Ok(true);
    }

    // Helper to safely copy the first N bytes into a fixed-size array
    fn bytes_to_array<const N: usize>(slice: &[u8]) -> [u8; N] {
        let mut arr = [0u8; N];
        arr.copy_from_slice(&slice[..N]);
        arr
    }

    let le = match value_type {
        VzValueType::Short | VzValueType::Int16 => {
            let typed = readshort(script, addr)?;
            let arr = bytes_to_array::<2>(first);
            let le = i16::from_le_bytes(arr);
            let be = i16::from_be_bytes(arr);
            if le == typed {
                true
            } else if be == typed {
                false
            } else {
                true
            }
        }
        VzValueType::UShort | VzValueType::UInt16 => {
            let typed = readushort(script, addr)?;
            let arr = bytes_to_array::<2>(first);
            let le = u16::from_le_bytes(arr);
            let be = u16::from_be_bytes(arr);
            if le == typed {
                true
            } else if be == typed {
                false
            } else {
                true
            }
        }
        VzValueType::Int | VzValueType::Int32 => {
            let typed = readint(script, addr)?;
            let arr = bytes_to_array::<4>(first);
            let le = i32::from_le_bytes(arr);
            let be = i32::from_be_bytes(arr);
            if le == typed {
                true
            } else if be == typed {
                false
            } else {
                true
            }
        }
        VzValueType::UInt | VzValueType::UInt32 => {
            let typed = readuint(script, addr)?;
            let arr = bytes_to_array::<4>(first);
            let le = u32::from_le_bytes(arr);
            let be = u32::from_be_bytes(arr);
            if le == typed {
                true
            } else if be == typed {
                false
            } else {
                true
            }
        }
        VzValueType::Long | VzValueType::Int64 => {
            let typed = readlong(script, addr)?;
            let arr = bytes_to_array::<8>(first);
            let le = i64::from_le_bytes(arr);
            let be = i64::from_be_bytes(arr);
            if le == typed {
                true
            } else if be == typed {
                false
            } else {
                true
            }
        }
        VzValueType::ULong | VzValueType::UInt64 | VzValueType::Pointer => {
            let typed = readulong(script, addr)?;
            let arr = bytes_to_array::<8>(first);
            let le = u64::from_le_bytes(arr);
            let be = u64::from_be_bytes(arr);
            if le == typed {
                true
            } else if be == typed {
                false
            } else {
                true
            }
        }
        VzValueType::Float | VzValueType::Float32 => {
            let typed = readfloat(script, addr)?;
            let arr = bytes_to_array::<4>(first);
            let le = f32::from_le_bytes(arr).to_bits();
            let be = f32::from_be_bytes(arr).to_bits();
            let tb = typed.to_bits();
            if le == tb {
                true
            } else if be == tb {
                false
            } else {
                true
            }
        }
        VzValueType::Double | VzValueType::Float64 => {
            let typed = readdouble(script, addr)?;
            let arr = bytes_to_array::<8>(first);
            let le = f64::from_le_bytes(arr).to_bits();
            let be = f64::from_be_bytes(arr).to_bits();
            let tb = typed.to_bits();
            if le == tb {
                true
            } else if be == tb {
                false
            } else {
                true
            }
        }
        _ => true,
    };

    Ok(le)
}

// Decode a value of the given type from a byte slice into a plain string (without colors)
fn decode_value_to_string_from_bytes(value_type: &VzValueType, slice: &[u8], little_endian: bool) -> String {
    // Helper to safely copy bytes into arrays
    fn bytes_to_array<const N: usize>(slice: &[u8]) -> [u8; N] {
        let mut arr = [0u8; N];
        arr.copy_from_slice(&slice[..N]);
        arr
    }

    match value_type {
        VzValueType::Byte | VzValueType::Int8 => {
            let v = slice[0] as i8;
            v.to_string()
        }
        VzValueType::UByte | VzValueType::UInt8 => {
            let v = slice[0] as u8;
            v.to_string()
        }
        VzValueType::Short | VzValueType::Int16 => {
            let arr = bytes_to_array::<2>(slice);
            let v = if little_endian { i16::from_le_bytes(arr) } else { i16::from_be_bytes(arr) };
            v.to_string()
        }
        VzValueType::UShort | VzValueType::UInt16 => {
            let arr = bytes_to_array::<2>(slice);
            let v = if little_endian { u16::from_le_bytes(arr) } else { u16::from_be_bytes(arr) };
            v.to_string()
        }
        VzValueType::Int | VzValueType::Int32 => {
            let arr = bytes_to_array::<4>(slice);
            let v = if little_endian { i32::from_le_bytes(arr) } else { i32::from_be_bytes(arr) };
            v.to_string()
        }
        VzValueType::UInt | VzValueType::UInt32 => {
            let arr = bytes_to_array::<4>(slice);
            let v = if little_endian { u32::from_le_bytes(arr) } else { u32::from_be_bytes(arr) };
            v.to_string()
        }
        VzValueType::Long | VzValueType::Int64 => {
            let arr = bytes_to_array::<8>(slice);
            let v = if little_endian { i64::from_le_bytes(arr) } else { i64::from_be_bytes(arr) };
            v.to_string()
        }
        VzValueType::ULong | VzValueType::UInt64 => {
            let arr = bytes_to_array::<8>(slice);
            let v = if little_endian { u64::from_le_bytes(arr) } else { u64::from_be_bytes(arr) };
            v.to_string()
        }
        VzValueType::Float | VzValueType::Float32 => {
            let arr = bytes_to_array::<4>(slice);
            let v = if little_endian { f32::from_le_bytes(arr) } else { f32::from_be_bytes(arr) };
            v.to_string()
        }
        VzValueType::Double | VzValueType::Float64 => {
            let arr = bytes_to_array::<8>(slice);
            let v = if little_endian { f64::from_le_bytes(arr) } else { f64::from_be_bytes(arr) };
            v.to_string()
        }
        VzValueType::Bool | VzValueType::Boolean => {
            let v = slice[0] != 0;
            format!("{}", v)
        }
        VzValueType::Pointer => {
            let arr = bytes_to_array::<8>(slice);
            let v = if little_endian { u64::from_le_bytes(arr) } else { u64::from_be_bytes(arr) };
            format!("{:#018x}", v)
        }
        // For these types, view uses hex-bytes mode; fallback to single byte display string
        VzValueType::String | VzValueType::Utf8 | VzValueType::Array | VzValueType::Bytes => {
            format!("{:02x}", slice[0])
        }
        VzValueType::Void => "".to_string(),
    }
}
