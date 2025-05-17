function filtered(arr, filter) {
    return arr.filter(v => {
        
    })
}

rpc.exports = {
    // debug
    get_env: () => [
        Java.available ? "Android" : ObjC.available ? "iOS" : "Native",
        Process.arch
    ],
    // reader
    reader_byte: a => ptr(a).readU8(),
    reader_short: a => ptr(a).readS16(),
    reader_ushort: a => ptr(a).readU16(),
    reader_int: a => ptr(a).readS32(),
    reader_uint: a => ptr(a).readU32(),
    reader_long: a => ptr(a).readS64(),
    reader_ulong: a => ptr(a).readU64(),
    reader_float: a => ptr(a).readFloat(),
    reader_double: a => ptr(a).readDouble(),
    reader_string: a => ptr(a).readUtf8String(),
    reader_bytes: (a, l = 8) => ptr(a).readByteArray(l),
    // writer
    writer_byte: (a, v) => ptr(a).writeU8(v),
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
    // list
    list_modules: (filter) => Process.enumerateModules().map(m => [m.name, m.base.toUInt32(), m.size]),
    list_ranges: (protect = 'r--') => Process.enumerateRanges(protect).map(m => m.base),
    list_ranges_by_module: (a, protect = 'r--') => {
        const md = Process.findModuleByAddress(ptr(a));
        if (!md) return [];
        return Process.enumerateRanges(protect)
        .filter(m => m.base >= md.base && m.base.add(m.size) < md.base.add(md.size))
        .map(m => [m.base, m.size, m.protection]);
    },
    list_exports: (a, type, filter) => {
        const md = Process.findModuleByAddress(ptr(a));
        if (!md) return [];
        const exps = md.enumerateExports().map(e => [e.name, e.address.toString(), e.type, md.name]);
        if (type) {
            return exps.filter(e => e[2] === type);
        } else return exps;
    },
    list_java_classes: (filter) => {
        return Java.enumerateLoadedClassesSync();
    },
    list_java_methods: (c, filter) => {
        return Java.enumerateMethodsSync(`${c}!*`);
    }
}
