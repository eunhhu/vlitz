#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VzDataType {
    Pointer,
    Module,
    Function,
    Variable,
    JavaClass,
    JavaMethod,
    ObjCClass,
    ObjCMethod,
    Thread,
}

pub struct VzBase {
    pub data_type: VzDataType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VzValueType {
    Byte, Int8,
    UByte, UInt8,
    Short, Int16,
    UShort, UInt16,
    Int, Int32,
    UInt, UInt32,
    Long, Int64,
    ULong, UInt64,
    Float, Float32,
    Double, Float64,
    Bool, Boolean,
    String, Utf8,
    Array, Bytes,
    Pointer,
    Void,
}

pub struct VzPointer {
    pub base: VzBase,
    pub address: u64,
    pub size: usize,
    pub value_type: VzValueType,
}

pub struct VzModule {
    pub base: VzBase,
    pub name: String,
    pub address: u64,
    pub size: usize,
}

pub struct VzFunction {
    pub base: VzBase,
    pub name: String,
    pub address: u64,
    pub module: String,
}

pub struct VzVariable {
    pub base: VzBase,
    pub name: String,
    pub address: u64,
    pub module: String,
}

pub struct VzJavaClass {
    pub base: VzBase,
    pub name: String,
}

pub struct VzJavaMethod {
    pub base: VzBase,
    pub class: String,
    pub name: String,
    pub args: Vec<VzValueType>,
}

pub struct VzObjCClass {
    pub base: VzBase,
    pub name: String,
}

pub struct VzObjCMethod {
    pub base: VzBase,
    pub class: String,
    pub name: String,
}

pub struct VzThread {
    pub base: VzBase,
    pub id: u64,
    pub stack: Vec<VzPointer>,
}