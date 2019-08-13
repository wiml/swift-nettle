import CNettle
import Foundation

public protocol HashContext {
    /// The digest size of the hash, in bytes.
    var digest_size: Int { get }

    /// The block size of the hash function, in bytes.
    /// This is usually of no interest, unless you are (for
    /// example) implementing HMAC.
    var block_size: Int { get }

    /// A name of this hash function, e.g. `sha256`
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

public extension HashContext {

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

public protocol HashContextRef : AnyObject {
    /// The digest size of the hash, in bytes.
    var digest_size: Int { get }

    /// The block size of the hash function, in bytes.
    /// This is usually of no interest, unless you are (for
    /// example) implementing HMAC.
    var block_size: Int { get }

    /// A name of this hash function, e.g. `sha256`
    var name: String { get }

    /// Add the contents of a buffer to the hash.
    func update(bytes buf: UnsafeBufferPointer<UInt8>)

    /// Finish computing the hash, writing its digest into
    /// the supplied buffer.
    ///
    /// The context is reset to its initial state and can
    /// be reused for a new hash computation.
    ///
    /// The buffer may be shorter than `digest_size`, in which case
    /// a prefix of the result will be written to it; but an assertion
    /// will be raised if the buffer is longer than `digest_size`.
    func digest(into: UnsafeMutableBufferPointer<UInt8>)

    /// Finish computing the hash, returning its digest.
    ///
    /// The context is reset to its initial state and can
    /// be reused for a new hash computation.
    func digest() -> ContiguousArray<UInt8>
}

public extension HashContextRef {

    /// Add the contents of a buffer to the hash.
    @inlinable
    func update<D: DataProtocol>(_ bufs: D) {
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
    func digest() -> ContiguousArray<UInt8> {
        var buf = ContiguousArray<UInt8>(repeating: 0x00, count: digest_size)
        buf.withUnsafeMutableBytes {
            digest(into: $0.bindMemory(to: UInt8.self))
        }
        return buf
    }
}

public protocol HashAlgorithm {
    associatedtype Context: HashContextRef

    /// Create a new context for computing
    /// a digest
    func new() -> Context

    /// The size in bytes of the digest computed by
    /// contexts returned from `new()`
    var digest_size : Int { get }

    /// The name of this algorithm
    var name : String { get }
}

public extension HashAlgorithm {

    /// Convenience method for computing a hash digest
    /// in one shot
    @inlinable
    func digest<D: DataProtocol>(of buf: D) -> ContiguousArray<UInt8> {
        let ctxt = self.new()
        ctxt.update(buf)
        return ctxt.digest()
    }

}

fileprivate typealias BufferElement = UInt64 // for alignment
fileprivate func requiredCapacity(_ vtable: UnsafePointer<nettle_hash>) -> Int {
    let bytesNeeded = vtable.pointee.context_size
    let eltStride = type(of:bytesNeeded).init(MemoryLayout<BufferElement>.stride)
    return Int((bytesNeeded + eltStride - 1) / eltStride)
}

fileprivate extension ManagedBuffer
  where Header == UnsafePointer<nettle_hash>, Element == BufferElement
{
    static func create(vtable: Header, count: Int) -> ManagedBuffer<Header, Element> {
        let instance = self.create(
          minimumCapacity: requiredCapacity(vtable) * count,
          makingHeaderWith: { (_) -> (Header) in return vtable })
        return instance
    }
}

/// A cryptographic hash function from the Nettle library.
///
/// This can provide any of the hashes supported by the library,
/// but is marginally less efficient than the versions which
/// directly wrap a specific Nettle hash function.
public class Hash : ManagedBuffer<UnsafePointer<nettle_hash>, UInt64> & HashContextRef {

    public struct Algorithm : HashAlgorithm, Equatable {
        public typealias Context = Hash

        fileprivate let vtable: UnsafePointer<nettle_hash>

        public func new() -> Hash {
            let instance = Hash.create(vtable: vtable, count: 1)
            instance.withUnsafeMutablePointerToElements {
                vtable.pointee.`init`($0)
            }
            return unsafeDowncast(instance, to: Hash.self)
        }

        public var digest_size : Int {
            get {
                return Int(vtable.pointee.digest_size)
            }
        }

        public var block_size : Int {
            get {
                return Int(vtable.pointee.block_size)
            }
        }

        public var name : String {
            get {
                return String(cString: vtable.pointee.name, encoding: .ascii)!
            }
        }

        /// Look up a hash by name and return a hash algorithm.
        ///
        /// - Parameters:
        ///   - hashName: The name of the hash, e.g. `sha256` or `sha512-224`
        public static func named(_ hashName: String) -> Algorithm? {
            let vtbl = hashName.withCString(encodedAs: Unicode.ASCII.self) {
                (buf: UnsafePointer<Unicode.ASCII.CodeUnit>) -> UnsafePointer<nettle_hash>? in
                CNettle.nettle_lookup_hash(UnsafePointer<CChar>(OpaquePointer(buf)))
            }

            return vtbl.map { Algorithm(vtable: $0) }
        }

        /// A list of the hash functions available
        public static var all: [Algorithm] {
            get {
                var results = [Algorithm]()
                var cursor = nettle_get_hashes()
                while let c = cursor, let elt = c.pointee {
                    results.append(Algorithm(vtable: elt))
                    cursor = c + 1
                }
                return results
            }
        }
    }

    public var algorithm: Algorithm {
        get {
            return Algorithm(vtable: header)
        }
    }

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

    @inlinable
    public static func named(_ name: String) -> Hash? {
        return Algorithm.named(name)?.new()
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

    /// Create a copy of the current state of the hash function.
    public func clone() -> Self {
        let clone = type(of: self).create(vtable: header, count: 1)
        clone.withUnsafeMutablePointerToElements {
            (newstate) -> Void in
            self.withUnsafeMutablePointerToElements {
                (oldstate) -> Void in
                newstate.assign(from: oldstate, count: requiredCapacity(header))
            }
        }
        return unsafeDowncast(clone, to: type(of: self))
    }

}

/// The HMAC construction.
///
/// HMACs can be computed using any underlying hash function
/// for which a Hash.Algorithm exists.
public class HMAC : HashContextRef {

    /// The key of this HMAC.
    ///
    /// Can be used to compute (or verify) additional MACs using the
    /// same key, somewhat more efficiently than starting from scratch
    /// each time.
    public let key: `Key`
    private let ctxt: UnsafeMutableBufferPointer<BufferElement>

    public var digest_size: Int { self.key.digest_size }
    public var block_size: Int { self.key.block_size }
    public var name: String { self.key.name }

    private static func makeContext(algorithm: Hash.Algorithm, key: UnsafeBufferPointer<UInt8>) -> (`Key`, UnsafeMutableBufferPointer<BufferElement>) {
        let vtable = algorithm.vtable
        let offset = requiredCapacity(vtable)
        var hashedKey = ContiguousArray<BufferElement>(repeating: 0, count: 2*offset)
        let initialState = UnsafeMutableBufferPointer<BufferElement>.allocate(capacity: offset)
        hashedKey.withUnsafeMutableBufferPointer {
            (keybuf) -> Void in
            nettle_hmac_set_key(keybuf.baseAddress,
                                keybuf.baseAddress! + offset,
                                initialState.baseAddress,
                                vtable,
                                key.count, key.baseAddress)
        }

        return (`Key`(impl: vtable,
                      hashedKey: hashedKey),
                initialState)
    }

    public init(algorithm: Hash.Algorithm, key: UnsafeBufferPointer<UInt8>) {
        let (keyinfo, state) = HMAC.makeContext(algorithm: algorithm, key: key)
        self.key = keyinfo
        self.ctxt = state
    }

    public init(_ alg: `Key`) {
        let offset = requiredCapacity(alg.impl)
        assert(alg.hashedKey.count == 2 * offset)
        key = alg
        ctxt = UnsafeMutableBufferPointer.allocate(capacity: offset)
        let _ = ctxt.initialize(from: key.hashedKey[ offset ..< 2*offset ])
    }

    deinit {
        ctxt.deallocate()
    }

    /// HMAC.Key represents the combination of
    /// an underlying hash algorithm and the key
    /// used for the HMAC.
    public struct `Key` : HashAlgorithm {
        public typealias Context = HMAC

        fileprivate let impl: UnsafePointer<nettle_hash>
        fileprivate let hashedKey: ContiguousArray<BufferElement>
        fileprivate init(impl: UnsafePointer<nettle_hash>, hashedKey: ContiguousArray<BufferElement>) {
            self.impl = impl
            self.hashedKey = hashedKey
        }

        public func new() -> HMAC {
            return HMAC(self)
        }

        public var digest_size : Int {
            get {
                return Int(impl.pointee.digest_size)
            }
        }

        public var block_size : Int {
            get {
                return Int(impl.pointee.block_size)
            }
        }

        public var name : String {
            get {
                return "hmac-" + String(cString: impl.pointee.name, encoding: .ascii)!
            }
        }
    }

    public func update(bytes buf: UnsafeBufferPointer<UInt8>) {
        nettle_hmac_update(ctxt.baseAddress, key.impl, buf.count, buf.baseAddress)
    }

    public func digest(into outbuf: UnsafeMutableBufferPointer<UInt8>) {
        key.hashedKey.withUnsafeBufferPointer {
            (keybuf) -> Void in
            nettle_hmac_digest(keybuf.baseAddress,
                               keybuf.baseAddress! + requiredCapacity(key.impl),
                               ctxt.baseAddress,
                               key.impl,
                               outbuf.count, outbuf.baseAddress)
        }
    }
}
