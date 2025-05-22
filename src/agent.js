function filtered(arr, filter) {
    if (!filter || !Array.isArray(filter) || filter.length === 0) {
        return [...arr];
    }

    const operators = {
        '=': (a, b) => a == b, // Using loose equality as per original
        '!=': (a, b) => a != b,
        '<': (a, b) => {
            const numA = Number(a);
            const numB = Number(b);
            if (typeof a === 'number' && typeof b === 'number') {
                return a < b;
            } else if (!isNaN(numA) && !isNaN(numB)) {
                return numA < numB;
            }
            return String(a) < String(b);
        },
        '>': (a, b) => {
            const numA = Number(a);
            const numB = Number(b);
            if (typeof a === 'number' && typeof b === 'number') {
                return a > b;
            } else if (!isNaN(numA) && !isNaN(numB)) {
                return numA > numB;
            }
            return String(a) > String(b);
        },
        '<=': (a, b) => {
            const numA = Number(a);
            const numB = Number(b);
            if (typeof a === 'number' && typeof b === 'number') {
                return a <= b;
            } else if (!isNaN(numA) && !isNaN(numB)) {
                return numA <= numB;
            }
            return String(a) <= String(b);
        },
        '>=': (a, b) => {
            const numA = Number(a);
            const numB = Number(b);
            if (typeof a === 'number' && typeof b === 'number') {
                return a >= b;
            } else if (!isNaN(numA) && !isNaN(numB)) {
                return numA >= numB;
            }
            return String(a) >= String(b);
        },
        ':': (a, b) => String(a).includes(String(b)),
        '!:': (a, b) => !String(a).includes(String(b)),
    };

    const evaluate = (item, condition) => {
        if (!Array.isArray(condition) || condition.length < 3) {
            console.warn(`Invalid condition format: ${JSON.stringify(condition)}. Treating as true.`);
            return true;
        }

        const [key, op, value] = condition;
        const itemValue = item[key];
        const operator = operators[op];

        if (!operator) {
            console.warn(`Unknown operator: ${op}. Treating as true.`);
            return true;
        }

        return operator(itemValue, value);
    };

    let finalResults = new Set();
    let currentAndBlock = [...arr];
    for (let i = 0; i < filter.length; i++) {
        const item = filter[i];

        if (item === 'and') {
        } else if (item === 'or') {
            currentAndBlock.forEach(resultItem => finalResults.add(resultItem));
            currentAndBlock = [...arr]; 
        } else if (Array.isArray(item) && item.length >= 3) {
            currentAndBlock = currentAndBlock.filter(v => evaluate(v, item));
        } else {
            console.warn(`Malformed filter element encountered: ${JSON.stringify(item)}`);
        }
    }
    currentAndBlock.forEach(resultItem => finalResults.add(resultItem));
    return Array.from(finalResults);
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
    list_modules: (filter) => filtered(Process.enumerateModules().map(m => {
        return {
            name: m.name,
            address: m.base.toString(),
            size: m.size
        }
    }), filter),
    list_ranges: (protect = '---', filter) => filtered(Process.enumerateRanges(protect).map(m => {
        return {
            address: m.base.toString(),
            size: m.size,
            protection: m.protection
        }
    }), filter),
    list_ranges_by_module: (a, protect = '---', filter) => {
        const md = Process.findModuleByAddress(ptr(a));
        if (!md) return [];
        return filtered(Process.enumerateRanges(protect)
            .filter(m => m.base >= md.base && m.base.add(m.size) < md.base.add(md.size))
            .map(m => {
                return {
                    address: m.base.toString(),
                    size: m.size,
                    protection: m.protection
                }
            }), filter);
    },
    list_exports: (a, type, filter) => {
        const md = Process.findModuleByAddress(ptr(a));
        if (!md) return [];
        const exps = md.enumerateExports().map(e => {
            return {
                name: e.name,
                address: e.address.toString(),
                type: e.type,
                module: md.name
            }
        });
        if (type) {
            return filtered(exps.filter(e => e.type === type), filter);
        } else return filtered(exps, filter);
    },
    list_functions: (a, filter) => {
        const md = Process.findModuleByAddress(ptr(a));
        if (!md) return [];
        const exps = md.enumerateExports()
            .filter(e => e.type === 'function')
            .map(e => {
            return {
                name: e.name,
                address: e.address.toString(),
                module: md.name
            }
        });
        return filtered(exps, filter);
    },
    list_variables: (a, filter) => {
        const md = Process.findModuleByAddress(ptr(a));
        if (!md) return [];
        const exps = md.enumerateExports()
            .filter(e => e.type === 'variable')
            .map(e => {
            return {
                name: e.name,
                address: e.address.toString(),
                module: md.name
            }
        });
        return filtered(exps, filter);
    },
    list_java_classes: (filter) => {
        return Java.available ? filtered(Java.enumerateLoadedClassesSync().map(c => {
            return {
                name: c
            }
        }), filter) : [];
    },
    list_java_methods: (c, filter) => {
        return Java.available ? filtered(Java.use(c).class.getMethods().map(m => {
            return {
                class: c,
                name: m.getName(),
                args: m.getParameterTypes().map(a => a.toString()),
                return_type: m.getReturnType().toString()
            }
        }), filter) : [];
    },
    list_objc_classes: (filter) => {
        return ObjC.available ? filtered(ObjC.classes.map(c => {
            return {
                name: c
            }
        }), filter) : [];
    }
}
