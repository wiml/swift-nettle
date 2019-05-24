// A few convenient DER packing primitives

import CNettle.Hogweed

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

internal func derIntegerLength(_ n: mpz_srcptr) -> Int {
    let content_size = nettle_mpz_sizeinbase_256_s(n)
    return 1 + derLengthLength(forContentLength: content_size) + content_size
}


internal func derPutInteger(_ buf: inout ContiguousArray<UInt8>, _ pos: Int, _ n: mpz_srcptr) -> Int {
    buf[pos] = 0x02 /* INTEGER */

    let content_size = nettle_mpz_sizeinbase_256_s(n)
    let content_pos = derPutLength(&buf, pos+1, content_size)
    buf.withUnsafeMutableBufferPointer {
        (outbuf) -> Void in
        nettle_mpz_get_str_256(content_size, outbuf.baseAddress! + content_pos, n)
    }

    return content_pos + content_size
}
