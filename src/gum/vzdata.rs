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

#[derive(Debug, Clone, PartialEq)]
pub struct VzBase {
    pub data_type: VzDataType,
    pub is_saved: bool,
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

#[derive(Debug, Clone, PartialEq)]
pub enum VzData {
    Pointer(VzPointer),
    Module(VzModule),
    Function(VzFunction),
    Variable(VzVariable),
    JavaClass(VzJavaClass),
    JavaMethod(VzJavaMethod),
    ObjCClass(VzObjCClass),
    ObjCMethod(VzObjCMethod),
    Thread(VzThread),
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzPointer {
    pub base: VzBase,
    pub address: u64,
    pub size: usize,
    pub value_type: VzValueType,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzModule {
    pub base: VzBase,
    pub name: String,
    pub address: u64,
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzFunction {
    pub base: VzBase,
    pub name: String,
    pub address: u64,
    pub module: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzVariable {
    pub base: VzBase,
    pub name: String,
    pub address: u64,
    pub module: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzJavaClass {
    pub base: VzBase,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzJavaMethod {
    pub base: VzBase,
    pub class: String,
    pub name: String,
    pub args: Vec<VzValueType>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzObjCClass {
    pub base: VzBase,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzObjCMethod {
    pub base: VzBase,
    pub class: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzThread {
    pub base: VzBase,
    pub id: u64,
    pub stack: Vec<VzPointer>,
}