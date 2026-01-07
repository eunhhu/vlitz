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
    Hook,
    Instruction,
    ScanResult,
    Import,
    Symbol,
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
            VzDataType::Hook => write!(f, "Hook"),
            VzDataType::Instruction => write!(f, "Instruction"),
            VzDataType::ScanResult => write!(f, "ScanResult"),
            VzDataType::Import => write!(f, "Import"),
            VzDataType::Symbol => write!(f, "Symbol"),
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
    Byte,
    Int8,
    UByte,
    UInt8,
    Short,
    Int16,
    UShort,
    UInt16,
    Int,
    Int32,
    UInt,
    UInt32,
    Long,
    Int64,
    ULong,
    UInt64,
    Float,
    Float32,
    Double,
    Float64,
    Bool,
    Boolean,
    String,
    Utf8,
    Array,
    Bytes,
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
    Hook(VzHook),
    Instruction(VzInstruction),
    ScanResult(VzScanResult),
    Import(VzImport),
    Symbol(VzSymbol),
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
            VzData::Hook(h) => write!(f, "{}", h),
            VzData::Instruction(i) => write!(f, "{}", i),
            VzData::ScanResult(s) => write!(f, "{}", s),
            VzData::Import(i) => write!(f, "{}", i),
            VzData::Symbol(s) => write!(f, "{}", s),
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
        write!(
            f,
            "{} {} {} {}",
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
        write!(
            f,
            "{} {} {}",
            format!("[{}]", self.base.data_type).blue(),
            format!(
                "{} @ {}",
                self.name,
                format!("{:#x}", self.address).yellow()
            ),
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
        write!(
            f,
            "{} {} {} {}",
            format!("[{}]", self.base.data_type).blue(),
            format!(
                "{:#x} - {:#x}",
                self.address,
                self.address + self.size as u64
            ),
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
        write!(
            f,
            "{} {} {}",
            format!("[{}]", self.base.data_type).blue(),
            format!(
                "{} @ {}",
                self.name,
                format!("{:#x}", self.address).yellow()
            ),
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
        write!(
            f,
            "{} {} {}",
            format!("[{}]", self.base.data_type).blue(),
            format!(
                "{} @ {}",
                self.name,
                format!("{:#x}", self.address).yellow()
            ),
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
        write!(
            f,
            "{} {}",
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
        write!(
            f,
            "{} {}{} -> {} @ {}",
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
        write!(
            f,
            "{} {}",
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
        write!(
            f,
            "{} {} @ {}",
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
        write!(
            f,
            "{} {}",
            format!("[{}]", self.base.data_type).blue(),
            self.id,
        )
    }
}

// ============================================================================
// New Types for Hooking, Disassembly, and Scanning
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub struct VzHook {
    pub base: VzBase,
    pub id: String,
    pub address: u64,
    pub target_name: Option<String>,
    pub module: Option<String>,
    pub enabled: bool,
    pub on_enter: bool,
    pub on_leave: bool,
    pub log_args: bool,
    pub log_retval: bool,
}

impl fmt::Display for VzHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.enabled {
            "enabled".green()
        } else {
            "disabled".dark_grey()
        };
        let name = self.target_name.as_deref().unwrap_or("unknown");
        let flags = format!(
            "{}{}{}{}",
            if self.on_enter { "E" } else { "-" },
            if self.on_leave { "L" } else { "-" },
            if self.log_args { "A" } else { "-" },
            if self.log_retval { "R" } else { "-" }
        );
        write!(
            f,
            "{} {} {} @ {} [{}] ({})",
            format!("[{}]", self.base.data_type).blue(),
            self.id.clone().cyan(),
            name,
            format!("{:#x}", self.address).yellow(),
            flags.dark_grey(),
            status
        )
    }
}

impl VzHook {
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
pub struct VzInstruction {
    pub base: VzBase,
    pub address: u64,
    pub size: usize,
    pub mnemonic: String,
    pub op_str: String,
    pub bytes: Vec<u8>,
}

impl fmt::Display for VzInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let bytes_hex = self.bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        write!(
            f,
            "{} {} {} {}",
            format!("{:#x}", self.address).yellow(),
            format!("{:<24}", bytes_hex).dark_grey(),
            self.mnemonic.clone().cyan(),
            self.op_str
        )
    }
}

impl VzInstruction {
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
pub struct VzScanResult {
    pub base: VzBase,
    pub address: u64,
    pub size: usize,
    pub value: Option<String>,
    pub pattern: Option<String>,
}

impl fmt::Display for VzScanResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value_str = self.value.as_deref().unwrap_or("?");
        write!(
            f,
            "{} {} = {}",
            format!("[{}]", self.base.data_type).blue(),
            format!("{:#x}", self.address).yellow(),
            value_str.cyan()
        )
    }
}

impl VzScanResult {
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
pub struct VzImport {
    pub base: VzBase,
    pub name: String,
    pub address: Option<u64>,
    pub import_type: String,
    pub module: String,
    pub slot: Option<u64>,
}

impl fmt::Display for VzImport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let addr_str = self.address
            .map(|a| format!("{:#x}", a))
            .unwrap_or_else(|| "?".to_string());
        write!(
            f,
            "{} {} @ {} ({}) [{}]",
            format!("[{}]", self.base.data_type).blue(),
            self.name,
            addr_str.yellow(),
            self.module.clone().dark_grey(),
            self.import_type.clone().dark_grey()
        )
    }
}

impl VzImport {
    pub fn to_pointer(&self) -> Option<VzPointer> {
        self.address.map(|address| {
            let mut bs = self.base.clone();
            bs.data_type = VzDataType::Pointer;
            VzPointer {
                base: bs,
                address,
                size: 8,
                value_type: VzValueType::Pointer,
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzSymbol {
    pub base: VzBase,
    pub name: String,
    pub address: u64,
    pub symbol_type: String,
    pub size: Option<usize>,
    pub is_global: bool,
    pub section: Option<String>,
}

impl fmt::Display for VzSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let size_str = self.size
            .map(|s| format!("({:#x})", s))
            .unwrap_or_default();
        let global_str = if self.is_global { "G" } else { "L" };
        write!(
            f,
            "{} {} @ {} {} [{}{}]",
            format!("[{}]", self.base.data_type).blue(),
            self.name,
            format!("{:#x}", self.address).yellow(),
            size_str.dark_grey(),
            self.symbol_type.clone().dark_grey(),
            global_str.dark_grey()
        )
    }
}

impl VzSymbol {
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

// ============================================================================
// Utility Functions
// ============================================================================

pub fn string_to_u64(s: &str) -> u64 {
    let s = s.trim_start_matches("0x");
    u64::from_str_radix(s, 16).unwrap_or(0)
}

/// Create a new VzBase with the specified data type
pub fn new_base(data_type: VzDataType) -> VzBase {
    VzBase {
        data_type,
        is_saved: false,
    }
}
