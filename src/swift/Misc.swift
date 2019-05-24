import CNettle
import Foundation

/// The type of Swift functions/closures which can be supplied to provide
/// entropy to key generation, signing, etc. operations which need it.
///
/// This can't throw, because Nettle/Hogweed has no provision for RNG
/// failure --- if you can't provide the requested amount of entropy,
/// either abort the program, or set a flag to discard the result once
/// you get back out of library code.
public typealias getentropy_func = (UnsafeMutableBufferPointer<UInt8>) -> ()

/// Bridge from C-style context-and-function callback to Swift "fat pointer" callback
fileprivate func call_getentropy(_ ctxt: UnsafeMutableRawPointer?, _ count: Int, _ buf: UnsafeMutablePointer<UInt8>?) -> () {
    guard count > 0 else {
        return
    }
    ctxt!.assumingMemoryBound(to: getentropy_func.self).pointee(UnsafeMutableBufferPointer(start: buf, count: count))
}

/// In the particular case of using the default, builtin entropy source,
/// just use this with no context pointer
fileprivate func default_getentropy(_: UnsafeMutableRawPointer?, _ count: Int, _ buf: UnsafeMutablePointer<UInt8>?) -> () {
    system_entropy_source(UnsafeMutableBufferPointer(start: buf, count: count))
}

internal typealias getentropy_cb = @convention(c) (UnsafeMutableRawPointer?, Int, UnsafeMutablePointer<UInt8>?) -> Void

/// The type of Swift functions/callbacks to report the state of lengthy
/// operations (well, just RSA key generation really)
public typealias progress_func = (CInt) -> Void

/// Convert an integer to an octet string.
///
/// This implements the PKCS#1 I2OS primitive; the integer
/// is returned as unsigned, big-endian, base-256, with no leading zero
/// octets.
internal func i2os(_ v: UnsafePointer<mpz_t>) -> ContiguousArray<UInt8>
{
    let size = nettle_mpz_sizeinbase_256_u(v)
    var result = ContiguousArray<UInt8>(repeating: 0, count: size)
    result.withUnsafeMutableBufferPointer {
        nettle_mpz_get_str_256($0.count, $0.baseAddress, v)
    }
    return result
}

/// Convert an integer to an octet string.
///
/// The SECG SEC.1 "field element to octet string" primitive ([2.3.5] and [2.3.8]),
/// for prime curves (the only kind Nettle implements right now),
/// amounts to calling I2OS on the integer we retrieve from
/// libnettle. (Libnettle may use a different field element represetation
/// internally but its API gives us an integer.)
///
/// This returns an integer of a fixed width (typically required by elliptic
/// curve protocols); if the value does not fit, nil is returned.
internal func i2os(_ v: UnsafePointer<mpz_t>, width: Int) -> ContiguousArray<UInt8>?
{
    guard nettle_mpz_sizeinbase_256_u(v) <= width else {
        return nil
    }
    var result = ContiguousArray<UInt8>(repeating: 0, count: width)
    result.withUnsafeMutableBufferPointer {
        nettle_mpz_get_str_256($0.count, $0.baseAddress, v)
    }
    return result
}

/// The version of libnettle against which this library was compiled
public let libnettle_build_version = ( CNettle.NETTLE_VERSION_MAJOR, CNettle.NETTLE_VERSION_MINOR )

/// The version of libnettle we're using; may differ from libnettle_build_version
/// if nettle is dynamically linked
public let libnettle_run_version = ( nettle_version_major(), nettle_version_minor() )

internal func withNettleBuffer(_ writer: (UnsafeMutablePointer<nettle_buffer>) -> Bool) -> ContiguousArray<UInt8>? {
    var accumulator = nettle_buffer()
    nettle_buffer_init(&accumulator)
    if withUnsafeMutablePointer(to: &accumulator, writer) {
        let buffish = UnsafeBufferPointer<UInt8>(start: accumulator.contents, count: accumulator.size)
        let swifty = ContiguousArray<UInt8>(buffish)
        nettle_buffer_clear(&accumulator)
        return swifty
    } else {
        nettle_buffer_clear(&accumulator)
        return nil
    }
}

// This is used to call Nettle functions, whose bridged-from-C interface
// doesn't declare the non-escaping nature of the RNG, nor the fact that
// since our RNG callback takes a const pointer, the context pointer is
// also const. So we do a bunch of unsafe conversions here.
internal func withEntropyCallback<T>(_ entropy_source: getentropy_func?,
                                     _ cb: (UnsafeMutableRawPointer?, @escaping getentropy_cb) -> T) -> T
{
    if let csrng = entropy_source {
        return withExtendedLifetime(csrng) {
            return withUnsafePointer(to: csrng) {
                return cb(UnsafeMutableRawPointer(OpaquePointer($0)), call_getentropy)
            }
        }
    } else {
        return cb(nil, default_getentropy)
    }
}

#if canImport(Glibc)

import Glibc
import ErrNo

fileprivate func system_entropy_source(_ buf: UnsafeMutableBufferPointer<UInt8>) -> () {

    // The getentropy() call is limited to 256 bytes at a time (since it's
    // calling into the kernel RNG). Break up larger requests into multiple
    // small requests.
    let linux_getentropy_max = 256

    var pos = 0
    while pos < buf.count {
        let request_size = min(buf.count - pos, linux_getentropy_max)

        guard Glibc.getentropy(buf.baseAddress! + pos, request_size) == 0 else {
            fatalError("Random number generator failure (\(ErrNo.lastError) while requesting \(buf.count) bytes from \"getentropy\")")
        }

        pos += request_size
    }
}

#endif
