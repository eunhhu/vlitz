// Tests for vzdata.rs type conversion

#[cfg(test)]
mod tests {
    use super::*;

    // Test the string_to_u64 utility function
    #[test]
    fn test_string_to_u64_hex() {
        assert_eq!(super::string_to_u64("0x1000"), 0x1000);
    }

    #[test]
    fn test_string_to_u64_decimal() {
        assert_eq!(super::string_to_u64("1000"), 1000);
    }

    #[test]
    fn test_string_to_u64_negative() {
        assert_eq!(super::string_to_u64("-10"), u64::MAX);
    }

    #[test]
    fn test_string_to_u64_invalid() {
        assert_eq!(super::string_to_u64("invalid"), u64::MAX);
    }

    // Test VzValueType Display implementations for all variants
    #[test]
    fn test_vzvalue_byte() {
        let v = super::VzValueType::Byte;
        assert_eq!(format!("{}", v), "Byte");
    }

    #[test]
    fn test_vzvalue_int8() {
        let v = super::VzValueType::Int8;
        assert_eq!(format!("{}", v), "Int8");
    }

    #[test]
    fn test_vzvalue_uint8() {
        let v = super::VzValueType::UInt8;
        assert_eq!(format!("{}", v), "uByte");
    }

    #[test]
    fn test_vzvalue_short() {
        let v = super::VzValueType::Short;
        assert_eq!(format!("{}", v), "Short");
    }

    #[test]
    fn test_vzvalue_int16() {
        let v = super::VzValueType::Int16;
        assert_eq!(format!("{}", v), "UShort");
    }

    #[test]
    fn test_vzvalue_uint16() {
        let v = super::VzValueType::UInt16;
        assert_eq!(format!("{}", v), "UInt");
    }

    #[test]
    fn test_vzvalue_int() {
        let v = super::VzValueType::Int;
        assert_eq!(format!("{}", v), "Int");
    }

    #[test]
    fn test_vzvalue_uint() {
        let v = super::VzValueType::UInt;
        assert_eq!(format!("{}", v), "uInt");
    }

    #[test]
    fn test_vzvalue_int32() {
        let v = super::VzValueType::Int32;
        assert_eq!(format!("{}", v), "Int32");
    }

    #[test]
    fn test_vzvalue_uint32() {
        let v = super::VzValueType::UInt32;
        assert_eq!(format!("{}", v), "UInt32");
    }

    #[test]
    fn test_vzvalue_int64() {
        let v = super::VzValueType::Int64;
        assert_eq!(format!("{}", v), "Long");
    }

    #[test]
    fn test_vzvalue_uint64() {
        let v = super::VzValueType::UInt64;
        assert_eq!(format!("{}", v), "uLong");
    }

    #[test]
    fn test_vzvalue_long() {
        let v = super::VzValueType::Long;
        assert_eq!(format!("{}", v), "Long");
    }

    #[test]
    fn test_vzvalue_float32() {
        let v = super::VzValueType::Float32;
        assert_eq!(format!("{}", v), "Float");
    }

    #[test]
    fn test_vzvalue_float64() {
        let v = super::VzValueType::Float64;
        assert_eq!(format!("{}", v), "Double");
    }

    #[test]
    fn test_vzvalue_bool() {
        let v = super::VzValueType::Bool;
        assert_eq!(format!("{}", v), "Bool");
    }

    #[test]
    fn test_vzvalue_boolean() {
        let v = super::VzValueType::Boolean;
        assert_eq!(format!("{}", v), "Boolean");
    }

    #[test]
    fn test_vzvalue_string() {
        let v = super::VzValueType::String;
        assert_eq!(format!("{}", v), "String");
    }

    #[test]
    fn test_vzvalue_utf8() {
        let v = super::VzValueType::Utf8;
        assert_eq!(format!("{}", v), "Utf8");
    }

    #[test]
    fn test_vzvalue_array() {
        let v = super::VzValueType::Array;
        assert_eq!(format!("{}", v), "Array");
    }

    #[test]
    fn test_vzvalue_bytes() {
        let v = super::VzValueType::Bytes;
        assert_eq!(format!("{}", v), "Bytes");
    }

    #[test]
    fn test_vzvalue_pointer() {
        let v = super::VzValueType::Pointer;
        assert_eq!(format!("{}", v), "Pointer");
    }

    #[test]
    fn test_vzvalue_void() {
        let v = super::VzValueType::Void;
        assert_eq!(format!("{}", v), "Void");
    }

    // Test new_base utility
    #[test]
    fn test_new_base() {
        let base = super::new_base(super::VzDataType::Module);
        assert_eq!(base.data_type, super::VzDataType::Module);
        assert!(!base.is_saved);
    }

    // Test VzData Display implementations for all variants
    #[test]
    fn test_vzdata_pointer_display() {
        let p = super::VzPointer {
            base: super::new_base(super::VzDataType::Pointer),
            address: 0x1000,
            size: 8,
            value_type: super::VzValueType::Pointer,
        };
        let result = format!("{}", p);
        assert!(result.contains("Pointer"));
    }

    #[test]
    fn test_vzdata_module_display() {
        let m = super::VzModule {
            base: super::new_base(super::VzDataType::Module),
            name: "test_module".into(),
            address: 0x2000,
            size: 0x1000,
        };
        let result = format!("{}", m);
        assert!(result.contains("Module"));
    }

    #[test]
    fn test_vzdata_range_display() {
        let r = super::VzRange {
            base: super::new_base(super::VzDataType::Range),
            address: 0x3000,
            size: 0x1000,
            protection: "rw-".into(),
        };
        let result = format!("{}", r);
        assert!(result.contains("Range"));
    }

    #[test]
    fn test_vzdata_function_display() {
        let f = super::VzFunction {
            base: super::new_base(super::VzDataType::Function),
            name: "test_func".into(),
            address: 0x4000,
            module: "test_module".into(),
        };
        let result = format!("{}", f);
        assert!(result.contains("Function"));
    }

    #[test]
    fn test_vzdata_variable_display() {
        let v = super::VzVariable {
            base: super::new_base(super::VzDataType::Variable),
            name: "test_var".into(),
            address: 0x5000,
            module: "test_module".into(),
        };
        let result = format!("{}", v);
        assert!(result.contains("Variable"));
    }

    // Test to_pointer methods for data types that support it
    #[test]
    fn test_module_to_pointer() {
        let m = super::VzModule {
            base: super::new_base(super::VzDataType::Module),
            name: "test".into(),
            address: 0x1000,
            size: 0x1000,
        };
        let result = m.to_pointer();
        assert_eq!(result.base.data_type, super::VzDataType::Pointer);
        assert_eq!(result.address, 0x1000);
        assert_eq!(result.size, 8);
        assert_eq!(result.value_type, super::VzValueType::Pointer);
    }

    #[test]
    fn test_range_to_pointer() {
        let r = super::VzRange {
            base: super::new_base(super::VzDataType::Range),
            address: 0x3000,
            size: 0x1000,
            protection: "rw-".into(),
        };
        let result = r.to_pointer();
        assert_eq!(result.base.data_type, super::VzDataType::Pointer);
        assert_eq!(result.address, 0x3000);
        assert_eq!(result.size, 8);
        assert_eq!(result.value_type, super::VzValueType::Pointer);
    }

    #[test]
    fn test_function_to_pointer() {
        let f = super::VzFunction {
            base: super::new_base(super::VzDataType::Function),
            name: "test".into(),
            address: 0x4000,
            module: "test".into(),
        };
        let result = f.to_pointer();
        assert_eq!(result.base.data_type, super::VzDataType::Pointer);
        assert_eq!(result.address, 0x4000);
        assert_eq!(result.size, 8);
        assert_eq!(result.value_type, super::VzValueType::Pointer);
    }

    #[test]
    fn test_variable_to_pointer() {
        let v = super::VzVariable {
            base: super::new_base(super::VzDataType::Variable),
            name: "test".into(),
            address: 0x5000,
            module: "test".into(),
        };
        let result = v.to_pointer();
        assert_eq!(result.base.data_type, super::VzDataType::Pointer);
        assert_eq!(result.address, 0x5000);
        assert_eq!(result.size, 8);
        assert_eq!(result.value_type, super::VzValueType::Pointer);
    }
}
