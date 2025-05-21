function filtered(arr, filter) {
    if (!filter || !Array.isArray(filter) || filter.length === 0) {
        return [...arr];
    }

    const operators = {
        '=': (a, b) => a == b,
        '!=': (a, b) => a != b,
        '<': (a, b) => a < b,
        '>': (a, b) => a > b,
        '<=': (a, b) => a <= b,
        '>=': (a, b) => a >= b,
        '::': (a, b) => String(a).includes(b),
        '!::': (a, b) => !String(a).includes(b),
    };

    const evaluate = (item, condition) => {
        if (!Array.isArray(condition) || condition.length < 3) {
            return true;
        }

        const [key, op, value] = condition;
        const itemValue = item[key];
        const operator = operators[op];

        if (!operator) {
            console.warn(`Unknown operator: ${op}`);
            return true;
        }

        return operator(itemValue, value);
    };

    let result = [...arr];
    let currentOp = 'and';

    for (let i = 0; i < filter.length; i++) {
        const item = filter[i];
        
        if (item === 'and' || item === 'or') {
            currentOp = item;
            continue;
        }

        if (Array.isArray(item) && item.length >= 3) {
            result = result.filter(v => {
                const matches = evaluate(v, item);
                return currentOp === 'and' ? matches : true;
            });
        }
    }

    return result;
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
    list_modules: (filter) => filtered(Process.enumerateModules().map(m => [m.name, m.base.toString(), m.size]), filter),
    list_ranges: (protect = '---') => Process.enumerateRanges(protect).map(m => [m.base.toString(), m.size, m.protection]),
    list_ranges_by_module: (a, protect = '---') => {
        const md = Process.findModuleByAddress(ptr(a));
        if (!md) return [];
        return filtered(Process.enumerateRanges(protect)
        .filter(m => m.base >= md.base && m.base.add(m.size) < md.base.add(md.size))
        .map(m => [m.base.toString(), m.size, m.protection]), filter);
    },
    list_exports: (a, type, filter) => {
        const md = Process.findModuleByAddress(ptr(a));
        if (!md) return [];
        const exps = md.enumerateExports().map(e => [e.name, e.address.toString(), e.type, md.name]);
        if (type) {
            return filtered(exps.filter(e => e[2] === type), filter);
        } else return filtered(exps, filter);
    },
    list_java_classes: (filter) => {
        return filtered(Java.enumerateLoadedClassesSync(), filter);
    },
    list_java_methods: (c, filter) => {
        return filtered(Java.enumerateMethodsSync(`${c}!*`), filter);
    }
}
