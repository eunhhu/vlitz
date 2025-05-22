// src/gum/vzdata.rs
use crossterm::style::Stylize;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VzDataType {
    Pointer,
    Module,
    Range,
    Function,
    Variable,
    JavaClass,
    JavaMethod,
    ObjCClass,
    ObjCMethod,
    Thread,
}

impl fmt::Display for VzDataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VzDataType::Pointer => write!(f, "Pointer"),
            VzDataType::Module => write!(f, "Module"),
            VzDataType::Range => write!(f, "Range"),
            VzDataType::Function => write!(f, "Function"),
            VzDataType::Variable => write!(f, "Variable"),
            VzDataType::JavaClass => write!(f, "JavaClass"),
            VzDataType::JavaMethod => write!(f, "JavaMethod"),
            VzDataType::ObjCClass => write!(f, "ObjCClass"),
            VzDataType::ObjCMethod => write!(f, "ObjCMethod"),
            VzDataType::Thread => write!(f, "Thread"),
        }
    }
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

impl fmt::Display for VzValueType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            VzValueType::Byte | VzValueType::Int8 => write!(f, "Byte"),
            VzValueType::UByte | VzValueType::UInt8 => write!(f, "uByte"),
            VzValueType::Short | VzValueType::Int16 => write!(f, "Short"),
            VzValueType::UShort | VzValueType::UInt16 => write!(f, "uShort"),
            VzValueType::Int | VzValueType::Int32 => write!(f, "Int"),
            VzValueType::UInt | VzValueType::UInt32 => write!(f, "uInt"),
            VzValueType::Long | VzValueType::Int64 => write!(f, "Long"),
            VzValueType::ULong | VzValueType::UInt64 => write!(f, "uLong"),
            VzValueType::Float | VzValueType::Float32 => write!(f, "Float"),
            VzValueType::Double | VzValueType::Float64 => write!(f, "Double"),
            VzValueType::Bool | VzValueType::Boolean => write!(f, "Bool"),
            VzValueType::String | VzValueType::Utf8 => write!(f, "String"),
            VzValueType::Array | VzValueType::Bytes => write!(f, "Bytes"),
            VzValueType::Pointer => write!(f, "Pointer"),
            VzValueType::Void => write!(f, "Void"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum VzData {
    Pointer(VzPointer),
    Module(VzModule),
    Range(VzRange),
    Function(VzFunction),
    Variable(VzVariable),
    JavaClass(VzJavaClass),
    JavaMethod(VzJavaMethod),
    ObjCClass(VzObjCClass),
    ObjCMethod(VzObjCMethod),
    Thread(VzThread),
}

impl fmt::Display for VzData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VzData::Pointer(p) => write!(f, "{}", p),
            VzData::Module(m) => write!(f, "{}", m),
            VzData::Range(r) => write!(f, "{}", r),
            VzData::Function(func) => write!(f, "{}", func),
            VzData::Variable(v) => write!(f, "{}", v),
            VzData::JavaClass(jc) => write!(f, "{}", jc),
            VzData::JavaMethod(jm) => write!(f, "{}", jm),
            VzData::ObjCClass(oc) => write!(f, "{}", oc),
            VzData::ObjCMethod(om) => write!(f, "{}", om),
            VzData::Thread(t) => write!(f, "{}", t),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzPointer {
    pub base: VzBase,
    pub address: u64,
    pub size: usize,
    pub value_type: VzValueType,
}

impl fmt::Display for VzPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} {}",
            format!("[{}]", self.base.data_type).blue(),
            format!("{:#x}", self.address).yellow(),
            format!("({:#x})", self.size).dark_grey(),
            format!("[{}]", self.value_type).yellow(),
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzModule {
    pub base: VzBase,
    pub name: String,
    pub address: u64,
    pub size: usize,
}

impl fmt::Display for VzModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}",
            format!("[{}]", self.base.data_type).blue(),
            format!("{} @ {}", self.name, format!("{:#x}", self.address).yellow()),
            format!("({:#x})", self.size).dark_grey()
        )
    }
}

impl VzModule {
    pub fn to_pointer(&self) -> VzPointer {
        let mut bs = self.base.clone();
        bs.data_type = VzDataType::Pointer;
        VzPointer {
            base: bs,
            address: self.address,
            size: 8,
            value_type: VzValueType::Pointer,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzRange {
    pub base: VzBase,
    pub address: u64,
    pub size: usize,
    pub protection: String,
}

impl fmt::Display for VzRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {} {}",
            format!("[{}]", self.base.data_type).blue(),
            format!("{:#x} - {:#x}", self.address, self.address + self.size as u64),
            format!("({:#x})", self.size).dark_grey(),
            format!("[{}]", self.protection).yellow()
        )
    }
}

impl VzRange {
    pub fn to_pointer(&self) -> VzPointer {
        let mut bs = self.base.clone();
        bs.data_type = VzDataType::Pointer;
        VzPointer {
            base: bs,
            address: self.address,
            size: 8,
            value_type: VzValueType::Pointer,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzFunction {
    pub base: VzBase,
    pub name: String,
    pub address: u64,
    pub module: String,
}

impl fmt::Display for VzFunction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}",
            format!("[{}]", self.base.data_type).blue(),
            format!("{} @ {}", self.name, format!("{:#x}", self.address).yellow()),
            format!("({})", self.module).yellow()
        )
    }
}

impl VzFunction {
    pub fn to_pointer(&self) -> VzPointer {
        let mut bs = self.base.clone();
        bs.data_type = VzDataType::Pointer;
        VzPointer {
            base: bs,
            address: self.address,
            size: 8,
            value_type: VzValueType::Pointer,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzVariable {
    pub base: VzBase,
    pub name: String,
    pub address: u64,
    pub module: String,
}

impl fmt::Display for VzVariable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}",
            format!("[{}]", self.base.data_type).blue(),
            format!("{} @ {}", self.name, format!("{:#x}", self.address).yellow()),
            format!("({})", self.module).yellow()
        )
    }
}

impl VzVariable {
    pub fn to_pointer(&self) -> VzPointer {
        let mut bs = self.base.clone();
        bs.data_type = VzDataType::Pointer;
        VzPointer {
            base: bs,
            address: self.address,
            size: 8,
            value_type: VzValueType::Pointer,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzJavaClass {
    pub base: VzBase,
    pub name: String,
}

impl fmt::Display for VzJavaClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}",
            format!("[{}]", self.base.data_type).blue(),
            self.name
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzJavaMethod {
    pub base: VzBase,
    pub class: String,
    pub name: String,
    pub args: Vec<String>,
    pub return_type: String,
}

impl fmt::Display for VzJavaMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}{} -> {} @ {}",
            format!("[{}]", self.base.data_type).blue(),
            self.name,
            format!("({})", self.args.join(", ")).yellow(),
            self.return_type.clone().yellow(),
            format!("({})", self.class).yellow(),
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzObjCClass {
    pub base: VzBase,
    pub name: String,
}

impl fmt::Display for VzObjCClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}",
            format!("[{}]", self.base.data_type).blue(),
            self.name
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzObjCMethod {
    pub base: VzBase,
    pub class: String,
    pub name: String,
}

impl fmt::Display for VzObjCMethod {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} @ {}",
            format!("[{}]", self.base.data_type).blue(),
            self.name,
            format!("({})", self.class).yellow()
        )
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzThread {
    pub base: VzBase,
    pub id: u64,
}

impl fmt::Display for VzThread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}",
            format!("[{}]", self.base.data_type).blue(),
            self.id,
        )
    }
}

pub fn string_to_u64(s: &str) -> u64 {
    let s = s.trim_start_matches("0x");
    u64::from_str_radix(s, 16).unwrap()
}