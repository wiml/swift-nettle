import CNettle

/// The Yarrow cryptographic random number generator
///
/// Nettle provides an implementation of Yarrow using SHA-256 and AES,
/// with a 256-bit internal state.
public final class Yarrow : ManagedBuffer<yarrow256_ctx, yarrow_source> {

    /// Create a new context with te specified number of input sources.
    /// Note that the algorithm requires at least two sources in
    /// order to incorporate environmental entropy.
    public class func new(sourceCount: CUnsignedInt) -> Self {
        let instance = self.create(
          minimumCapacity: Int(sourceCount),
          makingHeaderWith: { $0.header }
        )
        instance.withUnsafeMutablePointers {
            nettle_yarrow256_init($0, sourceCount, $1)
        }
        return unsafeDowncast(instance, to: self)
    }
    
    /// Restore entropy saved from a previous invocation.
    /// Typically this should be at least `SEED_FILE_SIZE` bytes
    /// (e.g. from a previous instatiation of Yarrow).
    public func seed(file: UnsafeRawBufferPointer) {
        let f = file.bindMemory(to: UInt8.self)
        nettle_yarrow256_seed(&self.header, f.count, f.baseAddress)
    }

    /// The recommended size of the seed file to be saved across invocations
    public final let SEED_FILE_SIZE = YARROW256_SEED_FILE_SIZE

    /// Feed environmental entropy into the context
    ///
    /// Yarrow accumulates samples in an internal buffer and uses it
    /// to reseed (or re-mix) its internal state when enough has been
    /// accumulated.
    ///
    /// - Parameters:
    ///   - source: The index of the entropy source (range 0 ..< `sourceCount`)
    ///   - entropy: Estimated entropy of the sample, in bits
    ///   - data: The environmental data
    /// - Return: Whether a reseed happened
    public func update(source: CUnsignedInt, entropy: CUnsignedInt,
                       withBytes buf: UnsafeBufferPointer<UInt8>) -> Bool {
        let res = nettle_yarrow256_update(&self.header,
                                          source, entropy,
                                          buf.count, buf.baseAddress)
        return res > 0
    }

    @inlinable
    public func update<T>(source: CUnsignedInt, entropy: CUnsignedInt, value: UnsafePointer<T>) -> Bool {
        let p = UnsafeBufferPointer<UInt8>(start: UnsafeRawPointer(value).assumingMemoryBound(to: UInt8.self), count: MemoryLayout<T>.size)
        return self.update(source: source, entropy: entropy, withBytes: p)
    }

    public func newEstimator(forSource src: CUnsignedInt) -> KeyEventEstimator {
        return KeyEventEstimator(destination: self, source: src)
    }
    
    /// Generate random data
    ///
    /// This function will always produce output, but the output
    /// will not be strongly random unless the generator has been
    /// properly seeded.
    public func random(_ into: UnsafeMutableBufferPointer<UInt8>) {
        nettle_yarrow256_random(&self.header, into.count, into.baseAddress)
    }

    /// Whether the generator is ready to produce output
    public var isSeeded: Bool {
        get {
            return nettle_yarrow256_is_seeded(&self.header) > 0
        }
    }

    public var sourceCount: CUnsignedInt {
        get {
            return self.header.nsources
        }
    }

    /// How many sources need more `updates()` before the next (re)seed
    public func neededSources() -> CUnsignedInt {
        return nettle_yarrow256_needed_sources(&self.header)
    }

    /// Re-seed the fast pool, even if it is not time
    ///
    /// Yarrow will do this automatically when there is sufficient
    /// entropy. Most users will not need to call this.
    public func reseedFastPool() {
        return nettle_yarrow256_fast_reseed(&self.header)
    }

    /// Re-seed the slow pool, even if it is not time
    ///
    /// Yarrow will do this automatically when there is sufficient
    /// entropy. Most users will not need to call this.
    public func reseedSlowPool() {
        return nettle_yarrow256_slow_reseed(&self.header)
    }

    /// A utility to provide a simple estimate of the amount
    /// of entropy in a stream of keypresses (or similar
    /// external events)
    public struct KeyEventEstimator {
        private var ctx: yarrow_key_event_ctx
        public let destination: Yarrow
        public let source: CUnsignedInt

        fileprivate init(destination y: Yarrow, source s: CUnsignedInt) {
            self.ctx = yarrow_key_event_ctx() // sigh
            nettle_yarrow_key_event_init(&self.ctx)
            self.destination = y
            self.source = s
        }

        /// Compute a conservative estimate of the amount of entropy
        /// in a keypress (or similar external event) and feed the
        /// information to `Yarrow.update()`.
        ///
        /// See the libnettle documentation for advice on using this
        /// algorithm.
        public mutating func update(key: CUnsignedInt, time: CUnsignedInt) -> Bool {
            let bits = nettle_yarrow_key_event_estimate(&self.ctx, key, time)
            var buf = (key, time)
            return self.destination.update(source: self.source,
                                           entropy: bits,
                                           value: &buf)
        }
    }
}

