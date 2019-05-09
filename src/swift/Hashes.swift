import CNettle
import Foundation

public protocol HashProtocol {
    /// The digest size of the hash, in bytes.
    var digest_size: Int { get }

    /// The block size of the hash function, in bytes.
    /// This is usually of no interest, unless you are (for
    /// example) implementing HMAC.
    var block_size: Int { get }

    /// A name of this hash function, e.g. "sha-256"
    var name: String { get }

    /// Add the contents of a buffer to the hash.
    mutating func update(bytes buf: UnsafeBufferPointer<UInt8>)

    /// Finish computing the hash, writing its digest into
    /// the supplied buffer.
    ///
    /// The context is reset to its initial state and can
    /// be reused for a new hash computation.
    ///
    /// The buffer may be shorter than `digest_size`, in which case
    /// a prefix of the result will be written to it; but an assertion
    /// will be raised if the buffer is longer than `digest_size`.
    mutating func digest(into: UnsafeMutableBufferPointer<UInt8>)

    /// Finish computing the hash, returning its digest.
    ///
    /// The context is reset to its initial state and can
    /// be reused for a new hash computation.
    mutating func digest() -> ContiguousArray<UInt8>
}

public extension HashProtocol {

    /// Add the contents of a buffer to the hash.
    @inlinable
    mutating func update<D: DataProtocol>(_ bufs: D) {
        for region in bufs.regions {
            region.withUnsafeBytes {
                (span) -> Void in
                self.update(bytes: span.bindMemory(to: UInt8.self))
            }
        }
    }

    /// Finish computing the hash, returning its digest.
    ///
    /// The context is reset to its initial state and can
    /// be reused for a new hash computation.
    mutating func digest() -> ContiguousArray<UInt8> {
        var buf = ContiguousArray<UInt8>(repeating: 0x00, count: digest_size)
        buf.withUnsafeMutableBytes {
            digest(into: $0.bindMemory(to: UInt8.self))
        }
        return buf
    }

}

/// The SHA-1 hash function.
///
/// Note that for most purposes this hash function is obsolete.
/// It should only be used if compatibility with existing systems
/// is a requirement.
public struct SHA1 : HashProtocol {
    internal var ctxt: sha1_ctx

    public let digest_size = Int(SHA1_DIGEST_SIZE)
    public let block_size = Int(SHA1_BLOCK_SIZE)
    public let name = "sha1" // Matches libnettle

    public init() {
        ctxt = sha1_ctx() // dummy assignment to appease Swift compiler
        nettle_sha1_init(&ctxt)
    }

    public mutating func update(bytes buf: UnsafeBufferPointer<UInt8>) {
        nettle_sha1_update(&ctxt, buf.count, buf.baseAddress)
    }

    public mutating func digest(into buf: UnsafeMutableBufferPointer<UInt8>) {
        nettle_sha1_digest(&ctxt, buf.count, buf.baseAddress)
    }
}

public struct SHA256 : HashProtocol {
    internal var ctxt: sha256_ctx

    public let digest_size = Int(SHA256_DIGEST_SIZE)
    public let block_size = Int(SHA256_BLOCK_SIZE)
    public let name = "sha256" // Matches libnettle

    public init() {
        ctxt = sha256_ctx() // dummy assignment to appease Swift compiler
        nettle_sha256_init(&ctxt)
    }

    public mutating func update(bytes buf: UnsafeBufferPointer<UInt8>) {
        nettle_sha256_update(&ctxt, buf.count, buf.baseAddress)
    }

    public mutating func digest(into buf: UnsafeMutableBufferPointer<UInt8>) {
        nettle_sha256_digest(&ctxt, buf.count, buf.baseAddress)
    }
}

public struct SHA384 : HashProtocol {
    internal var ctxt: sha512_ctx // same context struct as sha512

    public let digest_size = Int(SHA384_DIGEST_SIZE)
    public let block_size = Int(SHA384_BLOCK_SIZE)
    public let name = "sha384" // Matches libnettle

    public init() {
        ctxt = sha512_ctx() // dummy assignment to appease Swift compiler
        nettle_sha384_init(&ctxt)
    }

    public mutating func update(bytes buf: UnsafeBufferPointer<UInt8>) {
        // SHA384 uses SHA512's update function
        nettle_sha512_update(&ctxt, buf.count, buf.baseAddress)
    }

    public mutating func digest(into buf: UnsafeMutableBufferPointer<UInt8>) {
        nettle_sha384_digest(&ctxt, buf.count, buf.baseAddress)
    }
}

public struct SHA512 : HashProtocol {
    internal var ctxt: sha512_ctx

    public let digest_size = Int(SHA512_DIGEST_SIZE)
    public let block_size = Int(SHA512_BLOCK_SIZE)
    public let name = "sha512" // Matches libnettle

    public init() {
        ctxt = sha512_ctx() // dummy assignment to appease Swift compiler
        nettle_sha512_init(&ctxt)
    }

    public mutating func update(bytes buf: UnsafeBufferPointer<UInt8>) {
        nettle_sha512_update(&ctxt, buf.count, buf.baseAddress)
    }

    public mutating func digest(into buf: UnsafeMutableBufferPointer<UInt8>) {
        nettle_sha512_digest(&ctxt, buf.count, buf.baseAddress)
    }
}

/// A cryptographic hash function from the Nettle library.
///
/// This can provide any of the hashes supported by the library,
/// but is marginally less efficient than the versions which
/// directly wrap a specific Nettle hash function.
public class Hash : ManagedBuffer<UnsafePointer<nettle_hash>, UInt8> & HashProtocol {
    internal var vtable: nettle_hash {
        get {
            return header.pointee
        }
    }

    public var digest_size : Int {
        get {
            return Int(vtable.digest_size)
        }
    }

    public var block_size : Int {
        get {
            return Int(vtable.block_size)
        }
    }

    public var name : String {
        get {
            return String(cString: vtable.name, encoding: .ascii)!
        }
    }

    public func update(bytes buf: UnsafeBufferPointer<UInt8>) {
        self.withUnsafeMutablePointerToElements {
            (ctxt) -> Void in
            vtable.update(ctxt, buf.count, buf.baseAddress)
        }
    }

    public func digest(into outbuf: UnsafeMutableBufferPointer<UInt8>) {
        self.withUnsafeMutablePointerToElements {
            (ctxt) -> Void in
            vtable.digest(ctxt, outbuf.count, outbuf.baseAddress)
        }
    }

    internal static func create(_ vtable: UnsafePointer<nettle_hash>) -> Hash {
        let instance = self.create(
          minimumCapacity: Int(vtable.pointee.context_size),
          makingHeaderWith: { (_) -> (UnsafePointer<nettle_hash>) in return vtable })
        instance.withUnsafeMutablePointerToElements {
            vtable.pointee.`init`($0)
        }
        return unsafeDowncast(instance, to: Hash.self)
    }

    /// Creates a copy of the current state of the hash function and returns it.
    public func clone() -> Self {
        let ctxt_size = Int(vtable.context_size)
        let clone = type(of: self).create(
          minimumCapacity: ctxt_size,
          makingHeaderWith: { (_) -> (UnsafePointer<nettle_hash>) in return header })
        clone.withUnsafeMutablePointerToElements {
            (newstate) -> Void in
            self.withUnsafeMutablePointerToElements {
                (oldstate) -> Void in
                newstate.assign(from: oldstate, count: ctxt_size)
            }
        }
        return unsafeDowncast(clone, to: type(of: self))
    }

    /// Look up a hash by name and return a hash context.
    ///
    /// - Parameters:
    ///   - hashName: The name of the hash, e.g. `sha256` or `sha512-224`
    public class func named(_ hashName: String) -> Hash? {
        guard let vtbl: UnsafePointer<nettle_hash> = (hashName.withCString(encodedAs: Unicode.ASCII.self) {
            (buf: UnsafePointer<Unicode.ASCII.CodeUnit>) -> UnsafePointer<nettle_hash>? in
            CNettle.nettle_lookup_hash(UnsafePointer<CChar>(OpaquePointer(buf)))
        }) else {
            return nil
        }

        return Hash.create(vtbl)
    }

    private static func getHashNames() -> Array<String> {
        guard var tbl = nettle_get_hashes() else {
            return []
        }
        var result = Array<String>()
        while let instance = tbl.pointee {
            print("reading instance \(instance) at \(tbl)")
            result.append(String(cString: instance.pointee.name, encoding: .ascii)!)
            tbl += 1
        }
        return result
    }

    /// A list of the hash function names available via `named()`
    public static var names: Array<String> = getHashNames()
}
