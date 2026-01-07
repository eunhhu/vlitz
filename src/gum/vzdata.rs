// src/gum/vzdata.rs
use crossterm::style::Stylize;
use std::fmt;

/// Represents the type of data stored in Vlitz stores and navigators
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

/// Common base fields shared across all Vlitz data types
#[derive(Debug, Clone, PartialEq)]
pub struct VzBase {
    /// The type of data this object represents
    pub data_type: VzDataType,
    /// Whether this data has been saved to persistent storage
    pub is_saved: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzPointer {
    pub base: VzBase,
    /// Memory address of the pointer
    pub address: u64,
    /// Size in bytes
    pub size: usize,
    /// Type of value pointed to
    pub value_type: VzValueType,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzModule {
    pub base: VzBase,
    /// Module name
    pub name: String,
    /// Base address in memory
    pub address: u64,
    /// Size in bytes
    pub size: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzRange {
    pub base: VzBase,
    /// Start address of the memory range
    pub address: u64,
    /// Size in bytes
    pub size: usize,
    /// Memory protection flags (e.g., "r-x", "rw-", "rwx")
    pub protection: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzFunction {
    pub base: VzBase,
    /// Function name
    pub name: String,
    /// Entry point address in memory
    pub address: u64,
    /// Module containing this function
    pub module: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzVariable {
    pub base: VzBase,
    /// Variable name
    pub name: String,
    /// Address in memory
    pub address: u64,
    /// Module containing this variable
    pub module: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzJavaClass {
    pub base: VzBase,
    /// Java class name
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzJavaMethod {
    pub base: VzBase,
    /// Method name
    pub name: String,
    /// Class name
    pub class: String,
    /// Method arguments
    pub args: Vec<String>,
    /// Return type
    pub return_type: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzObjCClass {
    pub base: VzBase,
    /// Objective-C class name
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzObjCMethod {
    pub base: VzBase,
    /// Method selector
    pub name: String,
    /// Class name
    pub class: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzThread {
    pub base: VzBase,
    /// Thread ID
    pub id: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzHook {
    pub base: VzBase,
    /// Hook ID string
    pub id: String,
    /// Hook address
    pub address: u64,
    /// Target name if available
    pub target_name: Option<String>,
    /// Module name if available
    pub module: Option<String>,
    /// Whether hook is enabled
    pub enabled: bool,
    /// Hook triggers on enter
    pub on_enter: bool,
    /// Hook triggers on leave
    pub on_leave: bool,
    /// Whether to log arguments
    pub log_args: bool,
    /// Whether to log return value
    pub log_retval: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzInstruction {
    pub base: VzBase,
    /// Instruction address
    pub address: u64,
    /// Instruction size in bytes
    pub size: usize,
    /// Instruction mnemonic
    pub mnemonic: String,
    /// Instruction operands
    pub op_str: String,
    /// Instruction bytes
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzScanResult {
    pub base: VzBase,
    /// Address where value was found
    pub address: u64,
    /// Size in bytes
    pub size: usize,
    /// Value found at address
    pub value: Option<String>,
    /// Pattern that matched
    pub pattern: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzImport {
    pub base: VzBase,
    /// Import name
    pub name: String,
    /// Address in memory if available
    pub address: Option<u64>,
    /// Import type (function, variable, etc.)
    pub import_type: String,
    /// Slot number
    pub slot: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct VzSymbol {
    pub base: VzBase,
    /// Symbol name
    pub name: String,
    /// Address in memory
    pub address: u64,
    /// Symbol type (function, variable, etc.)
    pub symbol_type: String,
    /// Size if available
    pub size: Option<usize>,
    /// Whether symbol is global
    pub is_global: bool,
    /// Section name if available
    pub section: Option<String>,
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
        let bytes_hex = self
            .bytes
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
        let addr_str = self
            .address
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
        let size_str = self.size.map(|s| format!("({:#x})", s)).unwrap_or_default();
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
