rpc.exports = {
    memory: {
        reader: {
            byte: a => a.readU8(),
            short: a => a.readS16(),
            ushort: a => a.readU16(),
            int: a => a.readS32(),
            uint: a => a.readU32(),
            long: a => a.readS64(),
            ulong: a => a.readU64(),
            float: a => a.readFloat(),
            double: a => a.readDouble(),
            string: a => a.readUtf8String(),
            bytes: (a, l = 8) => a.readByteArray(l)
        },

        writer: {
            byte: (a, v) => a.writeU8(v),
            short: (a, v) => a.writeS16(v),
            ushort: (a, v) => a.writeU16(v),
            long: (a, v) => a.writeS64(v),
            ulong: (a, v) => a.writeU64(v),
            int: (a, v) => a.writeS32(v),
            uint: (a, v) => a.writeU32(v),
            float: (a, v) => a.writeFloat(v),
            double: (a, v) => a.writeDouble(v),
            string: (a, v) => a.writeUtf8String(v),
            bytes: (a, v) => a.writeByteArray(v)
        }
    }
}