pub enum VzDataType {
    Pointer = "Pointer",
    Module = "Module",
    Function = "Function",
    Variable = "Variable",
    JavaClass = "JavaClass",
    JavaMethod = "JavaMethod",
    ObjCClass = "ObjCClass",
    ObjCMethod = "ObjCMethod",
    Thread = "Thread",
}

pub struct VzBase {
    pub data_type: VzDataType,
}

enum VzValueType {
    Byte = "Byte", Int8 = "Byte",
    UByte = "UByte", UInt8 = "UByte",
    Short = "Short", Int16 = "Short",
    UShort = "UShort", UInt16 = "UShort",
    Int = "Int", Int32 = "Int",
    UInt = "UInt", UInt32 = "UInt",
    Long = "Long", Int64 = "Long",
    ULong = "ULong", UInt64 = "ULong",
    Float = "Float", Float32 = "Float",
    Double = "Double", Float64 = "Double",
    Bool = "Bool", Boolean = "Bool",
    String = "String", Utf8 = "String",
    Array = "Array", Bytes = "Array",
    Pointer = "Pointer", Void = "Pointer",
}

pub struct VzPointer {
    pub base: VzBase,
    pub address: u64,
    pub size: usize,
    pub value_type: VzValueType,
}