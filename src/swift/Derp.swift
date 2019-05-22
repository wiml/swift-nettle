// A few convenient DER packing primitives

/// Returns the length (in octets) of the DER length-field for
/// a value of the given length. Does not include the tag, nor the
/// value octets themselves.
internal func derLengthLength(forContentLength sz: Int) -> Int {
    if sz < 0x80 {
        return 1
    } else if sz < 0x100 {
        return 2
    } else if sz < 0x10000 {
        return 3
    } else if sz < 0x1000000 {
        return 4
    } else {
        fatalError("oversized DER")
    }
}

/// Pack the DER length field into the buffer at the specified location.
/// Returns the position after the length field.
internal func derPutLength(_ buf: inout ContiguousArray<UInt8>, _ pos: Int, _ sz: Int) -> Int {
    if sz < 0x80 {
        buf[pos] = UInt8(sz)
        return pos + 1
    } else if sz < 0x100 {
        buf[pos] = 0x81
        buf[pos + 1] = UInt8(sz)
        return pos + 2
    } else if sz < 0x10000 {
        buf[pos] = 0x82
        buf[pos + 1] = UInt8(sz >> 8)
        buf[pos + 2] = UInt8(sz & 0xFF)
        return pos + 3
    } else if sz < 0x1000000 {
        buf[pos] = 0x83
        buf[pos + 1] = UInt8(sz >> 16)
        buf[pos + 2] = UInt8((sz >> 8) & 0xFF)
        buf[pos + 3] = UInt8(sz & 0xFF)
        return pos + 4
    } else {
        fatalError("oversized DER")
    }
}
