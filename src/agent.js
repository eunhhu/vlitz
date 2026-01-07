// vlitz Frida Agent
// Provides RPC exports for memory, hooks, disassembly, scanning, and more

// ============================================================================
// Utility Functions
// ============================================================================

function filtered(arr, filter) {
    if (!filter || !Array.isArray(filter) || filter.length === 0) {
        return arr;
    }

    const operators = {
        '=': (a, b) => a == b,
        '!=': (a, b) => a != b,
        '<': (a, b) => {
            if (typeof a === 'number' && typeof b === 'number') return a < b;
            const numA = Number(a), numB = Number(b);
            return !isNaN(numA) && !isNaN(numB) ? numA < numB : String(a) < String(b);
        },
        '>': (a, b) => {
            if (typeof a === 'number' && typeof b === 'number') return a > b;
            const numA = Number(a), numB = Number(b);
            return !isNaN(numA) && !isNaN(numB) ? numA > numB : String(a) > String(b);
        },
        '<=': (a, b) => {
            if (typeof a === 'number' && typeof b === 'number') return a <= b;
            const numA = Number(a), numB = Number(b);
            return !isNaN(numA) && !isNaN(numB) ? numA <= numB : String(a) <= String(b);
        },
        '>=': (a, b) => {
            if (typeof a === 'number' && typeof b === 'number') return a >= b;
            const numA = Number(a), numB = Number(b);
            return !isNaN(numA) && !isNaN(numB) ? numA >= numB : String(a) >= String(b);
        },
        ':': (a, b) => String(a).toLowerCase().includes(String(b).toLowerCase()),
        '!:': (a, b) => !String(a).toLowerCase().includes(String(b).toLowerCase())
    };

    const evaluate = (item, condition) => {
        if (!Array.isArray(condition) || condition.length < 3) return true;
        const [key, op, value] = condition;
        const operator = operators[op];
        return operator ? operator(item[key], value) : true;
    };

    const finalResults = new Set();
    let currentAndBlock = arr;
    
    for (const item of filter) {
        if (item === 'and') continue;
        if (item === 'or') {
            currentAndBlock.forEach(r => finalResults.add(r));
            currentAndBlock = arr;
        } else if (Array.isArray(item) && item.length >= 3) {
            currentAndBlock = currentAndBlock.filter(v => evaluate(v, item));
        }
    }
    
    currentAndBlock.forEach(r => finalResults.add(r));
    return Array.from(finalResults);
}

// ============================================================================
// Hook Management State
// ============================================================================

const activeHooks = new Map();  // id -> { listener, config, address, enabled }
let hookIdCounter = 0;

// ============================================================================
// Scan State
// ============================================================================

let scanResults = [];
let scanSnapshots = new Map();  // address -> { original, current }

// ============================================================================
// RPC Exports
// ============================================================================

rpc.exports = {
    // ========================================================================
    // Environment & Debug
    // ========================================================================
    
    get_env: () => [
        Java.available ? "Android" : ObjC.available ? "iOS" : "Native",
        Process.arch,
        Process.platform,
        Process.pointerSize
    ],
    
    get_process_info: () => ({
        pid: Process.id,
        arch: Process.arch,
        platform: Process.platform,
        pointerSize: Process.pointerSize,
        pageSize: Process.pageSize,
        codeSigningPolicy: Process.codeSigningPolicy,
        isDebuggerAttached: Process.isDebuggerAttached()
    }),

    // ========================================================================
    // Memory Readers
    // ========================================================================
    
    reader_byte: a => ptr(a).readS8(),
    reader_ubyte: a => ptr(a).readU8(),
    reader_short: a => ptr(a).readS16(),
    reader_ushort: a => ptr(a).readU16(),
    reader_int: a => ptr(a).readS32(),
    reader_uint: a => ptr(a).readU32(),
    reader_long: a => ptr(a).readS64(),
    reader_ulong: a => ptr(a).readU64(),
    reader_float: a => ptr(a).readFloat(),
    reader_double: a => ptr(a).readDouble(),
    reader_string: (a, l = 256) => ptr(a).readCString(l),
    reader_bytes: (a, l = 8) => Array.from(new Uint8Array(ptr(a).readByteArray(l))),
    reader_pointer: a => ptr(a).readPointer().toString(),
    
    // ========================================================================
    // Memory Writers
    // ========================================================================
    
    writer_byte: (a, v) => ptr(a).writeS8(v),
    writer_ubyte: (a, v) => ptr(a).writeU8(v),
    writer_short: (a, v) => ptr(a).writeS16(v),
    writer_ushort: (a, v) => ptr(a).writeU16(v),
    writer_long: (a, v) => ptr(a).writeS64(v),
    writer_ulong: (a, v) => ptr(a).writeU64(v),
    writer_int: (a, v) => ptr(a).writeS32(v),
    writer_uint: (a, v) => ptr(a).writeU32(v),
    writer_float: (a, v) => ptr(a).writeFloat(v),
    writer_double: (a, v) => ptr(a).writeDouble(v),
    writer_string: (a, v) => ptr(a).writeUtf8String(v),
    writer_bytes: (a, v) => ptr(a).writeByteArray(v),
    writer_pointer: (a, v) => ptr(a).writePointer(ptr(v)),

    // ========================================================================
    // Memory Protection
    // ========================================================================
    
    check_read_protection: (a) => {
        try {
            const range = Process.findRangeByAddress(ptr(a));
            return range ? range.protection.includes('r') : false;
        } catch (e) {
            return false;
        }
    },
    
    check_write_protection: (a) => {
        try {
            const range = Process.findRangeByAddress(ptr(a));
            return range ? range.protection.includes('w') : false;
        } catch (e) {
            return false;
        }
    },
    
    get_memory_protection: (a) => {
        try {
            const range = Process.findRangeByAddress(ptr(a));
            return range ? range.protection : null;
        } catch (e) {
            return null;
        }
    },
    
    set_memory_protection: (a, size, protection) => {
        try {
            Memory.protect(ptr(a), size, protection);
            return { success: true };
        } catch (e) {
            return { success: false, error: e.message };
        }
    },

    // ========================================================================
    // Disassembly
    // ========================================================================
    
    instruction: (a) => {
        try {
            const insn = Instruction.parse(ptr(a));
            if (!insn) return null;
            return {
                address: insn.address.toString(),
                next: insn.next.toString(),
                size: insn.size,
                mnemonic: insn.mnemonic,
                opStr: insn.opStr,
                groups: insn.groups || [],
                regsRead: insn.regsRead || [],
                regsWritten: insn.regsWritten || []
            };
        } catch (e) {
            return null;
        }
    },
    
    disassemble: (address, count = 20) => {
        const instructions = [];
        let current = ptr(address);
        
        for (let i = 0; i < count; i++) {
            try {
                const insn = Instruction.parse(current);
                if (!insn) break;
                
                let bytes = [];
                try {
                    bytes = Array.from(new Uint8Array(current.readByteArray(insn.size)));
                } catch (e) {
                    // Cannot read bytes
                }
                
                instructions.push({
                    address: current.toString(),
                    size: insn.size,
                    mnemonic: insn.mnemonic,
                    opStr: insn.opStr,
                    bytes: bytes,
                    groups: insn.groups || [],
                    regsRead: insn.regsRead || [],
                    regsWritten: insn.regsWritten || []
                });
                
                current = insn.next;
            } catch (e) {
                break;
            }
        }
        
        return instructions;
    },
    
    disassemble_function: (address, maxInstructions = 500) => {
        const instructions = [];
        let current = ptr(address);
        const visited = new Set();
        
        for (let i = 0; i < maxInstructions; i++) {
            const addrStr = current.toString();
            if (visited.has(addrStr)) break;
            visited.add(addrStr);
            
            try {
                const insn = Instruction.parse(current);
                if (!insn) break;
                
                let bytes = [];
                try {
                    bytes = Array.from(new Uint8Array(current.readByteArray(insn.size)));
                } catch (e) {
                    // Cannot read bytes
                }
                
                instructions.push({
                    address: current.toString(),
                    size: insn.size,
                    mnemonic: insn.mnemonic,
                    opStr: insn.opStr,
                    bytes: bytes
                });
                
                // Check for return instructions (architecture-dependent)
                const mn = insn.mnemonic.toLowerCase();
                if (mn === 'ret' || mn === 'retq' || mn === 'retn' || 
                    mn === 'bx' && insn.opStr.toLowerCase() === 'lr') {
                    break;
                }
                
                current = insn.next;
            } catch (e) {
                break;
            }
        }
        
        return instructions;
    },

    // ========================================================================
    // Module & Symbol Listing
    // ========================================================================
    
    list_modules: (filter) => filtered(
        Process.enumerateModules().map(m => ({
            name: m.name,
            address: m.base.toString(),
            size: m.size,
            path: m.path
        })), filter
    ),
    
    list_ranges: (protect = '---', filter) => filtered(
        Process.enumerateRanges(protect).map(m => ({
            address: m.base.toString(),
            size: m.size,
            protection: m.protection,
            file: m.file ? m.file.path : null
        })), filter
    ),
    
    list_ranges_by_module: (a, protect = '---', filter) => {
        const md = Process.findModuleByAddress(ptr(a));
        if (!md) return [];
        return filtered(Process.enumerateRanges(protect)
            .filter(m => m.base >= md.base && m.base.add(m.size) < md.base.add(md.size))
            .map(m => ({
                address: m.base.toString(),
                size: m.size,
                protection: m.protection
            })), filter);
    },
    
    list_exports: (a, type, filter) => {
        const md = Process.findModuleByAddress(ptr(a));
        if (!md) return [];
        const exps = md.enumerateExports().map(e => ({
            name: e.name,
            address: e.address.toString(),
            type: e.type,
            module: md.name
        }));
        if (type) {
            return filtered(exps.filter(e => e.type === type), filter);
        }
        return filtered(exps, filter);
    },
    
    list_imports: (a, filter) => {
        const md = Process.findModuleByAddress(ptr(a));
        if (!md) return [];
        return filtered(md.enumerateImports().map(i => ({
            name: i.name,
            address: i.address ? i.address.toString() : null,
            type: i.type,
            module: i.module,
            slot: i.slot ? i.slot.toString() : null
        })), filter);
    },
    
    list_symbols: (a, filter) => {
        const md = Process.findModuleByAddress(ptr(a));
        if (!md) return [];
        return filtered(md.enumerateSymbols().map(s => ({
            name: s.name,
            address: s.address.toString(),
            type: s.type,
            section: s.section,
            size: s.size,
            isGlobal: s.isGlobal
        })), filter);
    },
    
    list_functions: (a, filter) => {
        const md = Process.findModuleByAddress(ptr(a));
        if (!md) return [];
        const exps = md.enumerateExports()
            .filter(e => e.type === 'function')
            .map(e => ({
                name: e.name,
                address: e.address.toString(),
                module: md.name
            }));
        return filtered(exps, filter);
    },
    
    list_variables: (a, filter) => {
        const md = Process.findModuleByAddress(ptr(a));
        if (!md) return [];
        const exps = md.enumerateExports()
            .filter(e => e.type === 'variable')
            .map(e => ({
                name: e.name,
                address: e.address.toString(),
                module: md.name
            }));
        return filtered(exps, filter);
    },
    
    find_symbol: (name) => {
        const symbol = DebugSymbol.fromName(name);
        if (symbol && !symbol.address.isNull()) {
            return {
                name: symbol.name,
                address: symbol.address.toString(),
                moduleName: symbol.moduleName,
                fileName: symbol.fileName,
                lineNumber: symbol.lineNumber
            };
        }
        return null;
    },
    
    find_symbol_by_address: (a) => {
        const symbol = DebugSymbol.fromAddress(ptr(a));
        if (symbol) {
            return {
                name: symbol.name,
                address: symbol.address.toString(),
                moduleName: symbol.moduleName,
                fileName: symbol.fileName,
                lineNumber: symbol.lineNumber
            };
        }
        return null;
    },
    
    resolve_export: (moduleName, exportName) => {
        const addr = Module.findExportByName(moduleName, exportName);
        return addr ? addr.toString() : null;
    },

    // ========================================================================
    // Thread Operations
    // ========================================================================
    
    list_threads: () => {
        return Process.enumerateThreads().map(t => ({
            id: t.id,
            state: t.state,
            context: t.context ? {
                pc: t.context.pc.toString(),
                sp: t.context.sp.toString()
            } : null
        }));
    },
    
    get_thread_context: (threadId) => {
        const threads = Process.enumerateThreads();
        const thread = threads.find(t => t.id === threadId);
        
        if (!thread || !thread.context) {
            return null;
        }
        
        const ctx = thread.context;
        const regs = {};
        
        // Architecture-specific register extraction
        if (Process.arch === 'x64') {
            regs.rax = ctx.rax.toString();
            regs.rbx = ctx.rbx.toString();
            regs.rcx = ctx.rcx.toString();
            regs.rdx = ctx.rdx.toString();
            regs.rsi = ctx.rsi.toString();
            regs.rdi = ctx.rdi.toString();
            regs.rbp = ctx.rbp.toString();
            regs.rsp = ctx.rsp.toString();
            regs.r8 = ctx.r8.toString();
            regs.r9 = ctx.r9.toString();
            regs.r10 = ctx.r10.toString();
            regs.r11 = ctx.r11.toString();
            regs.r12 = ctx.r12.toString();
            regs.r13 = ctx.r13.toString();
            regs.r14 = ctx.r14.toString();
            regs.r15 = ctx.r15.toString();
            regs.rip = ctx.pc.toString();
            regs.rflags = ctx.rflags ? ctx.rflags.toString() : null;
        } else if (Process.arch === 'ia32') {
            regs.eax = ctx.eax.toString();
            regs.ebx = ctx.ebx.toString();
            regs.ecx = ctx.ecx.toString();
            regs.edx = ctx.edx.toString();
            regs.esi = ctx.esi.toString();
            regs.edi = ctx.edi.toString();
            regs.ebp = ctx.ebp.toString();
            regs.esp = ctx.esp.toString();
            regs.eip = ctx.pc.toString();
        } else if (Process.arch === 'arm64') {
            for (let i = 0; i <= 28; i++) {
                regs['x' + i] = ctx['x' + i].toString();
            }
            regs.fp = ctx.fp.toString();
            regs.lr = ctx.lr.toString();
            regs.sp = ctx.sp.toString();
            regs.pc = ctx.pc.toString();
        } else if (Process.arch === 'arm') {
            for (let i = 0; i <= 12; i++) {
                regs['r' + i] = ctx['r' + i].toString();
            }
            regs.sp = ctx.sp.toString();
            regs.lr = ctx.lr.toString();
            regs.pc = ctx.pc.toString();
            regs.cpsr = ctx.cpsr ? ctx.cpsr.toString() : null;
        }
        
        return regs;
    },
    
    read_stack: (address, depth = 32) => {
        const stack = [];
        let current = ptr(address);
        const ptrSize = Process.pointerSize;
        
        for (let i = 0; i < depth; i++) {
            try {
                const value = current.readPointer();
                const module = Process.findModuleByAddress(value);
                const symbol = DebugSymbol.fromAddress(value);
                
                stack.push({
                    offset: i * ptrSize,
                    address: current.toString(),
                    value: value.toString(),
                    module: module ? module.name : null,
                    symbol: symbol && symbol.name ? symbol.name : null
                });
                
                current = current.add(ptrSize);
            } catch (e) {
                break;
            }
        }
        
        return stack;
    },
    
    backtrace: (contextPtr = null) => {
        let context = null;
        if (contextPtr) {
            // This would need to be a CpuContext, typically from a hook
            context = contextPtr;
        }
        
        const bt = Thread.backtrace(context, Backtracer.ACCURATE);
        return bt.map(addr => {
            const module = Process.findModuleByAddress(addr);
            const symbol = DebugSymbol.fromAddress(addr);
            
            return {
                address: addr.toString(),
                module: module ? module.name : null,
                symbol: symbol ? symbol.name : null,
                offset: module ? addr.sub(module.base).toInt32() : null
            };
        });
    },

    // ========================================================================
    // Function Hooking (Interceptor)
    // ========================================================================
    
    hook_attach: (address, config = {}) => {
        try {
            const id = 'hook_' + (hookIdCounter++);
            const target = ptr(address);
            
            // Validate address
            const range = Process.findRangeByAddress(target);
            if (!range || !range.protection.includes('x')) {
                return { success: false, error: 'Invalid or non-executable address' };
            }
            
            const hookConfig = {
                onEnter: config.onEnter !== false,
                onLeave: config.onLeave === true,
                logArgs: config.logArgs === true,
                logRetval: config.logRetval === true,
                argCount: config.argCount || 4,
                modifyArgs: config.modifyArgs || null,
                modifyRetval: config.modifyRetval || null,
                backtrace: config.backtrace === true
            };
            
            const listener = Interceptor.attach(target, {
                onEnter: function(args) {
                    if (hookConfig.onEnter) {
                        const data = {
                            type: 'hook_enter',
                            id: id,
                            address: address,
                            threadId: this.threadId,
                            depth: this.depth
                        };
                        
                        if (hookConfig.logArgs) {
                            data.args = [];
                            for (let i = 0; i < hookConfig.argCount; i++) {
                                try {
                                    data.args.push(args[i].toString());
                                } catch (e) {
                                    data.args.push('(error)');
                                }
                            }
                        }
                        
                        if (hookConfig.backtrace) {
                            data.backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
                                .map(addr => {
                                    const sym = DebugSymbol.fromAddress(addr);
                                    return {
                                        address: addr.toString(),
                                        symbol: sym ? sym.name : null
                                    };
                                });
                        }
                        
                        send(data);
                    }
                    
                    // Argument modification
                    if (hookConfig.modifyArgs && Array.isArray(hookConfig.modifyArgs)) {
                        hookConfig.modifyArgs.forEach((mod, idx) => {
                            if (mod !== null && mod !== undefined) {
                                try {
                                    args[idx] = ptr(mod);
                                } catch (e) {
                                    // Ignore modification errors
                                }
                            }
                        });
                    }
                    
                    // Store context for onLeave
                    this.hookContext = { args: [], config: hookConfig };
                    if (hookConfig.logArgs) {
                        for (let i = 0; i < hookConfig.argCount; i++) {
                            try {
                                this.hookContext.args.push(args[i].toString());
                            } catch (e) {
                                this.hookContext.args.push('(error)');
                            }
                        }
                    }
                },
                onLeave: function(retval) {
                    if (hookConfig.onLeave) {
                        const data = {
                            type: 'hook_leave',
                            id: id,
                            address: address,
                            threadId: this.threadId
                        };
                        
                        if (hookConfig.logRetval) {
                            data.retval = retval.toString();
                        }
                        
                        if (hookConfig.logArgs && this.hookContext) {
                            data.args = this.hookContext.args;
                        }
                        
                        send(data);
                    }
                    
                    // Return value modification
                    if (hookConfig.modifyRetval !== null && hookConfig.modifyRetval !== undefined) {
                        try {
                            retval.replace(ptr(hookConfig.modifyRetval));
                        } catch (e) {
                            // Ignore modification errors
                        }
                    }
                }
            });
            
            activeHooks.set(id, { 
                listener, 
                config: hookConfig, 
                address: address,
                enabled: true,
                target: target.toString()
            });
            
            return { success: true, id: id, address: address };
        } catch (e) {
            return { success: false, error: e.message };
        }
    },
    
    hook_detach: (id) => {
        const hook = activeHooks.get(id);
        if (hook) {
            try {
                hook.listener.detach();
                activeHooks.delete(id);
                return { success: true };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
        return { success: false, error: 'Hook not found' };
    },
    
    hook_list: () => {
        return Array.from(activeHooks.entries()).map(([id, h]) => ({
            id: id,
            address: h.address,
            target: h.target,
            enabled: h.enabled,
            config: {
                onEnter: h.config.onEnter,
                onLeave: h.config.onLeave,
                logArgs: h.config.logArgs,
                logRetval: h.config.logRetval
            }
        }));
    },
    
    hook_enable: (id) => {
        const hook = activeHooks.get(id);
        if (!hook) {
            return { success: false, error: 'Hook not found' };
        }
        if (hook.enabled) {
            return { success: true, message: 'Already enabled' };
        }
        
        // Re-attach the hook
        try {
            const result = rpc.exports.hook_attach(hook.address, hook.config);
            if (result.success) {
                activeHooks.delete(id);
                return { success: true, newId: result.id };
            }
            return result;
        } catch (e) {
            return { success: false, error: e.message };
        }
    },
    
    hook_disable: (id) => {
        const hook = activeHooks.get(id);
        if (!hook) {
            return { success: false, error: 'Hook not found' };
        }
        if (!hook.enabled) {
            return { success: true, message: 'Already disabled' };
        }
        
        try {
            hook.listener.detach();
            hook.enabled = false;
            hook.listener = null;
            return { success: true };
        } catch (e) {
            return { success: false, error: e.message };
        }
    },
    
    hook_clear_all: () => {
        let count = 0;
        for (const [id, hook] of activeHooks) {
            try {
                if (hook.listener) {
                    hook.listener.detach();
                }
                count++;
            } catch (e) {
                // Ignore errors during cleanup
            }
        }
        activeHooks.clear();
        hookIdCounter = 0;
        return { success: true, count: count };
    },

    // ========================================================================
    // Memory Scanning
    // ========================================================================
    
    scan_pattern: (pattern, rangeSpec = null) => {
        scanResults = [];
        let targetRanges;
        
        if (rangeSpec) {
            if (typeof rangeSpec === 'string') {
                // Protection string like 'r--', 'rw-', 'r-x'
                targetRanges = Process.enumerateRanges(rangeSpec);
            } else if (rangeSpec.base && rangeSpec.size) {
                // Specific range
                targetRanges = [{ base: ptr(rangeSpec.base), size: rangeSpec.size }];
            } else {
                targetRanges = Process.enumerateRanges('r--');
            }
        } else {
            targetRanges = Process.enumerateRanges('r--');
        }
        
        for (const range of targetRanges) {
            try {
                const matches = Memory.scanSync(range.base, range.size, pattern);
                for (const match of matches) {
                    scanResults.push({
                        address: match.address.toString(),
                        size: match.size,
                        pattern: pattern
                    });
                }
            } catch (e) {
                // Skip inaccessible ranges
            }
        }
        
        return {
            count: scanResults.length,
            results: scanResults.slice(0, 1000)  // Limit returned results
        };
    },
    
    scan_value: (type, value, rangeSpec = null) => {
        let pattern;
        
        try {
            switch (type) {
                case 'int8':
                case 'byte': {
                    const v = parseInt(value) & 0xFF;
                    pattern = v.toString(16).padStart(2, '0');
                    break;
                }
                case 'int16':
                case 'short': {
                    const buf = Memory.alloc(2);
                    buf.writeS16(parseInt(value));
                    pattern = Array.from(new Uint8Array(buf.readByteArray(2)))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(' ');
                    break;
                }
                case 'int32':
                case 'int': {
                    const buf = Memory.alloc(4);
                    buf.writeS32(parseInt(value));
                    pattern = Array.from(new Uint8Array(buf.readByteArray(4)))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(' ');
                    break;
                }
                case 'int64':
                case 'long': {
                    const buf = Memory.alloc(8);
                    buf.writeS64(parseInt(value));
                    pattern = Array.from(new Uint8Array(buf.readByteArray(8)))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(' ');
                    break;
                }
                case 'float': {
                    const buf = Memory.alloc(4);
                    buf.writeFloat(parseFloat(value));
                    pattern = Array.from(new Uint8Array(buf.readByteArray(4)))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(' ');
                    break;
                }
                case 'double': {
                    const buf = Memory.alloc(8);
                    buf.writeDouble(parseFloat(value));
                    pattern = Array.from(new Uint8Array(buf.readByteArray(8)))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(' ');
                    break;
                }
                case 'string': {
                    // UTF-8 string
                    pattern = Array.from(new TextEncoder().encode(value))
                        .map(b => b.toString(16).padStart(2, '0'))
                        .join(' ');
                    break;
                }
                case 'wstring': {
                    // UTF-16 string (wide string)
                    const encoder = new TextEncoder();
                    const utf8 = encoder.encode(value);
                    const bytes = [];
                    for (let i = 0; i < utf8.length; i++) {
                        bytes.push(utf8[i].toString(16).padStart(2, '0'));
                        bytes.push('00');  // Wide char padding
                    }
                    pattern = bytes.join(' ');
                    break;
                }
                default:
                    return { success: false, error: 'Unknown type: ' + type };
            }
        } catch (e) {
            return { success: false, error: 'Failed to create pattern: ' + e.message };
        }
        
        return rpc.exports.scan_pattern(pattern, rangeSpec);
    },
    
    scan_string: (text, rangeSpec = null) => {
        return rpc.exports.scan_value('string', text, rangeSpec);
    },
    
    scan_next: (type, value, comparison = 'eq') => {
        // Refine previous results
        const newResults = [];
        
        for (const result of scanResults) {
            try {
                const addr = ptr(result.address);
                let currentValue;
                let targetValue;
                
                switch (type) {
                    case 'int8':
                    case 'byte':
                        currentValue = addr.readS8();
                        targetValue = parseInt(value);
                        break;
                    case 'int16':
                    case 'short':
                        currentValue = addr.readS16();
                        targetValue = parseInt(value);
                        break;
                    case 'int32':
                    case 'int':
                        currentValue = addr.readS32();
                        targetValue = parseInt(value);
                        break;
                    case 'int64':
                    case 'long':
                        currentValue = addr.readS64();
                        targetValue = parseInt(value);
                        break;
                    case 'float':
                        currentValue = addr.readFloat();
                        targetValue = parseFloat(value);
                        break;
                    case 'double':
                        currentValue = addr.readDouble();
                        targetValue = parseFloat(value);
                        break;
                    default:
                        continue;
                }
                
                let match = false;
                switch (comparison) {
                    case 'eq':
                        match = type.includes('float') || type === 'double'
                            ? Math.abs(currentValue - targetValue) < 0.0001
                            : currentValue === targetValue;
                        break;
                    case 'ne':
                        match = currentValue !== targetValue;
                        break;
                    case 'gt':
                        match = currentValue > targetValue;
                        break;
                    case 'lt':
                        match = currentValue < targetValue;
                        break;
                    case 'ge':
                        match = currentValue >= targetValue;
                        break;
                    case 'le':
                        match = currentValue <= targetValue;
                        break;
                }
                
                if (match) {
                    newResults.push({
                        ...result,
                        currentValue: currentValue
                    });
                }
            } catch (e) {
                // Address no longer readable, skip
            }
        }
        
        scanResults = newResults;
        return {
            count: scanResults.length,
            results: scanResults.slice(0, 1000)
        };
    },
    
    scan_changed: (type) => {
        // Find addresses where value has changed from snapshot
        const newResults = [];
        
        for (const result of scanResults) {
            try {
                const addr = ptr(result.address);
                const snapshot = scanSnapshots.get(result.address);
                if (!snapshot) continue;
                
                let currentValue;
                switch (type) {
                    case 'int32':
                    case 'int':
                        currentValue = addr.readS32();
                        break;
                    case 'float':
                        currentValue = addr.readFloat();
                        break;
                    default:
                        currentValue = addr.readS32();
                }
                
                if (currentValue !== snapshot.original) {
                    newResults.push({
                        ...result,
                        originalValue: snapshot.original,
                        currentValue: currentValue
                    });
                }
            } catch (e) {
                // Skip unreadable
            }
        }
        
        scanResults = newResults;
        return {
            count: scanResults.length,
            results: scanResults.slice(0, 1000)
        };
    },
    
    scan_unchanged: (type) => {
        // Find addresses where value is the same as snapshot
        const newResults = [];
        
        for (const result of scanResults) {
            try {
                const addr = ptr(result.address);
                const snapshot = scanSnapshots.get(result.address);
                if (!snapshot) continue;
                
                let currentValue;
                switch (type) {
                    case 'int32':
                    case 'int':
                        currentValue = addr.readS32();
                        break;
                    case 'float':
                        currentValue = addr.readFloat();
                        break;
                    default:
                        currentValue = addr.readS32();
                }
                
                if (currentValue === snapshot.original) {
                    newResults.push({
                        ...result,
                        currentValue: currentValue
                    });
                }
            } catch (e) {
                // Skip unreadable
            }
        }
        
        scanResults = newResults;
        return {
            count: scanResults.length,
            results: scanResults.slice(0, 1000)
        };
    },
    
    scan_snapshot: (type) => {
        // Take a snapshot of current values for comparison
        scanSnapshots.clear();
        
        for (const result of scanResults) {
            try {
                const addr = ptr(result.address);
                let value;
                
                switch (type) {
                    case 'int32':
                    case 'int':
                        value = addr.readS32();
                        break;
                    case 'float':
                        value = addr.readFloat();
                        break;
                    default:
                        value = addr.readS32();
                }
                
                scanSnapshots.set(result.address, { original: value, current: value });
            } catch (e) {
                // Skip unreadable
            }
        }
        
        return { success: true, count: scanSnapshots.size };
    },
    
    get_scan_results: (offset = 0, limit = 100) => {
        return {
            total: scanResults.length,
            results: scanResults.slice(offset, offset + limit)
        };
    },
    
    get_scan_result_values: (type, offset = 0, limit = 100) => {
        const results = scanResults.slice(offset, offset + limit);
        return results.map(r => {
            try {
                const addr = ptr(r.address);
                let value;
                
                switch (type) {
                    case 'int8':
                    case 'byte':
                        value = addr.readS8();
                        break;
                    case 'int16':
                    case 'short':
                        value = addr.readS16();
                        break;
                    case 'int32':
                    case 'int':
                        value = addr.readS32();
                        break;
                    case 'int64':
                    case 'long':
                        value = addr.readS64().toString();
                        break;
                    case 'float':
                        value = addr.readFloat();
                        break;
                    case 'double':
                        value = addr.readDouble();
                        break;
                    case 'string':
                        value = addr.readCString(64);
                        break;
                    default:
                        value = addr.readS32();
                }
                
                return { ...r, value: value };
            } catch (e) {
                return { ...r, value: '(error)', error: e.message };
            }
        });
    },
    
    clear_scan: () => {
        scanResults = [];
        scanSnapshots.clear();
        return { success: true };
    },

    // ========================================================================
    // Code Patching
    // ========================================================================
    
    patch_bytes: (address, bytes) => {
        try {
            const target = ptr(address);
            const range = Process.findRangeByAddress(target);
            
            if (!range) {
                return { success: false, error: 'Address not in valid range' };
            }
            
            // Save original bytes
            const original = Array.from(new Uint8Array(target.readByteArray(bytes.length)));
            
            // Save original protection
            const originalProtection = range.protection;
            
            // Make writable if needed - only add 'w' permission
            // Avoid using 'rwx' which is a security risk
            const needsProtectionChange = !originalProtection.includes('w');
            
            if (needsProtectionChange) {
                // Add write permission to existing protection
                const hasRead = originalProtection.includes('r');
                const hasExec = originalProtection.includes('x');
                const newProtection = (hasRead ? 'r' : '') + 'w' + (hasExec ? 'x' : '');
                Memory.protect(target, bytes.length, newProtection);
            }
            
            // Write new bytes
            target.writeByteArray(bytes);
            
            // Restore protection (remove write permission)
            if (needsProtectionChange) {
                Memory.protect(target, bytes.length, originalProtection);
            }
            
            return { 
                success: true, 
                address: address,
                original: original,
                patched: Array.from(bytes)
            };
        } catch (e) {
            return { success: false, error: e.message };
        }
    },
    
    nop_instructions: (address, count = 1) => {
        try {
            const target = ptr(address);
            const arch = Process.arch;
            
            // Get NOP opcode for architecture
            let nopBytes;
            let nopSize;
            
            switch (arch) {
                case 'x64':
                case 'ia32':
                    nopBytes = [0x90];  // Single-byte NOP
                    nopSize = 1;
                    break;
                case 'arm':
                    nopBytes = [0x00, 0xf0, 0x20, 0xe3];  // NOP (ARM mode)
                    nopSize = 4;
                    break;
                case 'arm64':
                    nopBytes = [0x1f, 0x20, 0x03, 0xd5];  // NOP
                    nopSize = 4;
                    break;
                default:
                    return { success: false, error: 'Unsupported architecture: ' + arch };
            }
            
            // Calculate total bytes to NOP by parsing instructions
            let totalSize = 0;
            let current = target;
            const instructionsSizes = [];
            
            for (let i = 0; i < count; i++) {
                try {
                    const insn = Instruction.parse(current);
                    if (!insn) break;
                    totalSize += insn.size;
                    instructionsSizes.push(insn.size);
                    current = insn.next;
                } catch (e) {
                    break;
                }
            }
            
            if (totalSize === 0) {
                return { success: false, error: 'Could not parse any instructions' };
            }
            
            // Generate NOP sled
            const nops = [];
            while (nops.length < totalSize) {
                for (const b of nopBytes) {
                    if (nops.length < totalSize) {
                        nops.push(b);
                    }
                }
            }
            
            return rpc.exports.patch_bytes(address, nops);
        } catch (e) {
            return { success: false, error: e.message };
        }
    },
    
    restore_bytes: (address, original) => {
        return rpc.exports.patch_bytes(address, original);
    },

    // ========================================================================
    // Java Support (Android)
    // ========================================================================
    
    list_java_classes: (filter) => {
        if (!Java.available) return [];
        return Java.perform(() => {
            return filtered(Java.enumerateLoadedClassesSync().map(c => ({
                name: c
            })), filter);
        });
    },
    
    list_java_methods: (className, filter) => {
        if (!Java.available) return [];
        return Java.perform(() => {
            try {
                const clazz = Java.use(className);
                return filtered(clazz.class.getMethods().map(m => ({
                    class: className,
                    name: m.getName(),
                    args: m.getParameterTypes().map(a => a.toString()),
                    return_type: m.getReturnType().toString()
                })), filter);
            } catch (e) {
                return [];
            }
        });
    },

    // ========================================================================
    // ObjC Support (iOS/macOS)
    // ========================================================================
    
    list_objc_classes: (filter) => {
        if (!ObjC.available) return [];
        return filtered(Object.keys(ObjC.classes).map(c => ({
            name: c
        })), filter);
    },
    
    list_objc_methods: (className, filter) => {
        if (!ObjC.available) return [];
        try {
            const clazz = ObjC.classes[className];
            if (!clazz) return [];
            
            const methods = [];
            
            // Instance methods
            clazz.$ownMethods.forEach(m => {
                methods.push({
                    class: className,
                    name: m,
                    type: m.startsWith('+') ? 'class' : 'instance'
                });
            });
            
            return filtered(methods, filter);
        } catch (e) {
            return [];
        }
    }
};
