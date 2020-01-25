import CNettle.Hogweed
import Foundation

/// Trampoline to call a Swift closure from a C callback
fileprivate func call_progress(_ ctxt: UnsafeMutableRawPointer?, _ st: CInt) -> () {
    ctxt!.assumingMemoryBound(to: progress_func.self).pointee(st)
}

fileprivate typealias progress_cb = @convention(c) (UnsafeMutableRawPointer?, CInt) -> Void

// TODO: Submit doc patch to nettle to explain limit / max_bits behavior

/// Contains a Nettle key structure for a public RSA key.
public class RSAPublicKey {
    fileprivate let state: rsa_public_key

    /// The conventional "size" in bits of the key (that is,
    /// the bit size of the modulus)
    public final var bit_size : CUnsignedInt {
        get {
            return withUnsafePointer(to: state.n) {
                CUnsignedInt(nettle_swift_mpz_sizeinbase_2($0))
            }
        }
    }

    /// Create an RSAPublicKey, adopting ownership of the Nettle structure
    fileprivate init(adopting st: rsa_public_key) {
        self.state = st
    }

    deinit {
        var buf = state // sigh
        nettle_rsa_public_key_clear(&buf)
    }

    /// Create a public key from its PKCS1 representation
    ///
    /// - Parameters:
    ///   - PKCS1: The RSAPublicKey structure, in DER encoding
    ///   - max_bits: Fail if the key is larger than this many bits
    public convenience init?(PKCS1 data: ContiguousBytes, max_bits: CUnsignedInt? = nil) {
        var keybuf = rsa_public_key() // initializer is bogus, but Swift needs it
        nettle_rsa_public_key_init(&keybuf) // the real initalizer
        let res = data.withUnsafeBytesAsCharBuffer {
            nettle_rsa_keypair_from_der(&keybuf, nil, max_bits ?? 0, $0.count, $0.baseAddress)
        }
        guard res > 0 else {
            nettle_rsa_public_key_clear(&keybuf)
            return nil
        }
        self.init(adopting: keybuf)
    }

    /// Create a public key from its SPKI S-expr representation
    ///
    /// - Parameters:
    ///   - Sexp: The public key parameters
    ///   - max_bits: Fail if the key is larger than this many bits
    public convenience init?(Sexp data: ContiguousBytes,  max_bits: CUnsignedInt? = nil) {
        var keybuf = rsa_public_key() // initializer is bogus, but Swift needs it
        nettle_rsa_public_key_init(&keybuf) // the real initalizer
        guard (data.withUnsafeBytes {
            nettle_rsa_keypair_from_sexp(&keybuf, nil, max_bits ?? 0, $0.count, $0.baseAddress!.assumingMemoryBound(to: UInt8.self))
        } > 0) else {
            nettle_rsa_public_key_clear(&keybuf)
            return nil
        }
        self.init(adopting: keybuf)
    }

    /// Produce the DER representation of this key
    ///
    /// The result of this call is the RSAPublicKey structure defined
    /// in PKCS#1, encoded according to DER.
    public func toPKCS1() -> ContiguousArray<UInt8> {
        let content_len = withUnsafePointer(to: state.n) { derIntegerLength($0) } + withUnsafePointer(to: state.e) { derIntegerLength($0) }
        let total_len = 1 + derLengthLength(forContentLength: content_len) + content_len

        var result = ContiguousArray<UInt8>(repeating: 0x00, count: total_len)

        result[0] = 0x30 /* SEQUENCE */
        let n_pos = derPutLength(&result, 1, content_len)
        let e_pos = withUnsafePointer(to: state.n) {  derPutInteger(&result, n_pos, $0) }
        let end_pos = withUnsafePointer(to: state.e) { derPutInteger(&result, e_pos, $0) }
        assert(end_pos == total_len)

        return result
    }

    /// Produce the SPKI S-expr representation of this key
    public func toSexp() -> ContiguousArray<UInt8>? {
        return withNettleBuffer {
            (nettlebuf: UnsafeMutablePointer<nettle_buffer>) -> Bool in
            withUnsafePointer(to: self.state) {
                (pubkey) -> Bool in
                nettle_rsa_keypair_to_sexp(nettlebuf, "rsa", pubkey, nil) > 0
            }
        }
    }

    public enum SignatureAlgorithm {
        public enum SSAHash {
            case sha1
            case sha256
            case sha512

            public var digestSize: Int {
                switch self {
                case .sha1:   return Int(SHA1_DIGEST_SIZE)
                case .sha256: return Int(SHA256_DIGEST_SIZE)
                case .sha512: return Int(SHA512_DIGEST_SIZE)
                }
            }

            public var digestAlgorithm: Hash.Algorithm {
                get {
                    switch self {
                    case .sha1: return Hash.Algorithm.sha1
                    case .sha256: return Hash.Algorithm.sha256
                    case .sha512: return Hash.Algorithm.sha512
                    }
                }
            }

        }
        public enum PSSHash {
            case sha256
            case sha384
            case sha512

            public var digestSize: Int {
                switch self {
                case .sha256: return Int(SHA256_DIGEST_SIZE)
                case .sha384: return Int(SHA384_DIGEST_SIZE)
                case .sha512: return Int(SHA512_DIGEST_SIZE)
                }
            }

            public var digestAlgorithm: Hash.Algorithm {
                get {
                    switch self {
                    case .sha256: return Hash.Algorithm.sha256
                    case .sha384: return Hash.Algorithm.sha384
                    case .sha512: return Hash.Algorithm.sha512
                    }
                }
            }
        }

        /// The PKCS#1 v1.5 padding scheme
        case pkcs1v15(_ : SSAHash)

        /// The PSS padding scheme
        case pss(_ : PSSHash, saltLength: Int)

        public var digestSize: Int {
            get {
                switch self {
                case .pkcs1v15(let h): return h.digestSize
                case .pss(let h, _): return h.digestSize
                }
            }
        }

        public var digestAlgorithm: some HashAlgorithm {
            get {
                switch self {
                case .pkcs1v15(let h): return h.digestAlgorithm
                case .pss(let h, _): return h.digestAlgorithm
                }
            }
        }
    }

    public func verify_pkcs1(_ buf: ContiguousArray<UInt8>, digest ctxt: inout SHA1) -> Bool {
        return withMpz(buf) {
            (sig) -> Bool in
            withUnsafePointer(to: state) {
                return nettle_rsa_sha1_verify($0, &ctxt.ctxt, sig) > 0
            }
        }
    }
    public func verify_pkcs1(_ buf: ContiguousArray<UInt8>, digest ctxt: inout SHA256) -> Bool {
        return withMpz(buf) {
            (sig) -> Bool in
            return withUnsafePointer(to: state) {
                return nettle_rsa_sha256_verify($0, &ctxt.ctxt, sig) > 0
            }
        }
    }
    public func verify_pkcs1(_ buf: ContiguousArray<UInt8>, digest ctxt: inout SHA512) -> Bool {
        return withMpz(buf) {
            (sig) -> Bool in
            return withUnsafePointer(to: state) {
                return nettle_rsa_sha512_verify($0, &ctxt.ctxt, sig) > 0
            }
        }
    }

    /// Verify an RSA signature
    ///
    /// - Parameters:
    ///   - algorithm: The padding scheme used with this signature
    ///   - signature: The signature to verify
    ///   - digest: The digest of the message
    /// - Return: True if the signature matches, False otherwise
    public func verify(_ algorithm: RSAPublicKey.SignatureAlgorithm,
                       _ signature: ContiguousArray<UInt8>,
                       digest: ContiguousArray<UInt8>) -> Bool {
        return withMpz(signature) {
            (sig) -> Bool in
            digest.withUnsafeBufferPointer {
                (msg) -> Bool in

                guard msg.count == algorithm.digestSize else {
                    return false
                }

                return withUnsafePointer(to: state) {
                    (keydata) -> Bool in

                    let msgPtr = msg.baseAddress

                    switch algorithm {
                    case .pkcs1v15(let hashFunc):

                        switch hashFunc {
                        case .sha1:
                            return nettle_rsa_sha1_verify_digest(keydata, msgPtr, sig) > 0
                        case .sha256:
                            return nettle_rsa_sha256_verify_digest(keydata, msgPtr, sig) > 0
                        case .sha512:
                            return nettle_rsa_sha512_verify_digest(keydata, msgPtr, sig) > 0
                        }

                    case .pss(let hashFunc, let saltLength):

                        switch hashFunc {
                        case .sha256:
                            return nettle_rsa_pss_sha256_verify_digest(keydata, saltLength, msgPtr, sig) > 0
                        case .sha384:
                            return nettle_rsa_pss_sha384_verify_digest(keydata, saltLength, msgPtr, sig) > 0
                        case .sha512:
                            return nettle_rsa_pss_sha512_verify_digest(keydata, saltLength, msgPtr, sig) > 0
                        }
                    }
                }
            }
        }
    }
}

/// Contains a Nettle key structure for a private RSA key.
public class RSAPrivateKey {

    /// The public key corresponding to this private key
    public let public_key: RSAPublicKey

    private let state: rsa_private_key

    /// The entropy source used for secret operations.
    ///
    /// If this is nil, the Nettle library will use the system's
    /// builtin strong randomness source.
    public var entropy_source: getentropy_func? = nil

    fileprivate init?(_ importer: (UnsafeMutablePointer<rsa_public_key>, UnsafeMutablePointer<rsa_private_key>) -> Bool) {
        var public_buf = rsa_public_key()
        nettle_rsa_public_key_init(&public_buf)
        var private_buf = rsa_private_key()
        nettle_rsa_private_key_init(&private_buf)
        guard importer(&public_buf, &private_buf) else {
            nettle_rsa_private_key_clear(&private_buf)
            nettle_rsa_public_key_clear(&public_buf)
            return nil
        }
        self.public_key = RSAPublicKey(adopting: public_buf)
        self.state = private_buf
    }

    deinit {
        var buf = state // sigh
        nettle_rsa_private_key_clear(&buf)
    }

    public enum exponentChoice {
        case fixed(UInt)
        case random(CUnsignedInt)
    }

    /// Generate a new RSA keypair
    ///
    /// A new secret key is generated by selecting random primes,
    /// and the corresponding key objects are returned.
    ///
    /// The only parameter that the caller must provide is the key size.
    /// Other parameters have sensible defaults, but can be overridden
    /// if necessary.
    ///
    /// - Parameters:
    ///   - sizeInBits: The desired size of the new key's modulus (e.g., 2048)
    ///   - exponent: How to select the public exponent.
    ///   - entropy: Allows overriding the default cryptographic random number generator.
    ///   - progress: A callback which is invoked to indicate progress.
    public static func generate(sizeInBits: CUnsignedInt,
                                exponent: exponentChoice = .fixed(0x10001),
                                entropy: getentropy_func? = nil,
                                progress: progress_func? = nil) -> RSAPrivateKey? {
        let result = RSAPrivateKey(
          {
              (pubkeybuf, privkeybuf) -> Bool in

              let e_size: CUnsignedInt
              switch exponent {
              case .fixed(let v):
                  nettle_swift_mpz_set_ui(&(pubkeybuf.pointee.e), v)
                  e_size = 0
              case .random(let sz):
                  e_size = sz
              }

              func call_2(_ progress: UnsafeMutableRawPointer?) -> Bool {
                  return withEntropyCallback(entropy) {
                      (rng_ctxt, rng_cb) -> Bool in
                      nettle_rsa_generate_keypair(
                        pubkeybuf, privkeybuf,
                        rng_ctxt, rng_cb,
                        progress, (progress == nil) ? nil : call_progress as progress_cb,
                        sizeInBits, e_size) > 0
                  }
              }

              if let progress_ = progress {
                  return withExtendedLifetime(progress_) {
                      return withUnsafePointer(to: progress_) {
                          return call_2(UnsafeMutablePointer(OpaquePointer($0)))
                      }
                  }
              } else {
                  return call_2(nil)
              }
          }
        )
        if let r = result {
            r.entropy_source = entropy
        }
        return result
    }

    /// Create a private key from its PKCS1 representation
    ///
    /// - Parameters:
    ///   - PKCS1: The RSAPrivateKey structure, in DER encoding
    ///   - max_bits: Fail if the key is larger than this many bits
    public convenience init?(PKCS1 data: ContiguousBytes, max_bits: CUnsignedInt? = nil) {
        self.init(
          {
              (pubkeybuf, privkeybuf) -> Bool in
              data.withUnsafeBytes {
                  nettle_rsa_keypair_from_der(pubkeybuf, privkeybuf, max_bits ?? 0, $0.count, $0.baseAddress!.assumingMemoryBound(to: UInt8.self))
              } > 0
          }
        )
    }

    /// Create a private key from its SPKI S-expr representation
    ///
    /// - Parameters:
    ///   - Sexp: The private key parameters
    ///   - max_bits: Fail if the key is larger than this many bits
    public convenience init?(Sexp data: ContiguousBytes, max_bits: CUnsignedInt? = nil) {
        self.init(
          {
              (pubkeybuf, privkeybuf) -> Bool in
              data.withUnsafeBytes {
                  nettle_rsa_keypair_from_sexp(pubkeybuf, privkeybuf, max_bits ?? 0, $0.count, $0.baseAddress!.assumingMemoryBound(to: UInt8.self))
              } > 0
          }
        )
    }

    public func toSexp() -> ContiguousArray<UInt8>? {
        return withNettleBuffer {
            (nettlebuf: UnsafeMutablePointer<nettle_buffer>) -> Bool in
            withUnsafePointer(to: self.public_key.state) {
                (pubkey) -> Bool in
                withUnsafePointer(to: self.state) {
                    (privkey) -> Bool in
                    nettle_rsa_keypair_to_sexp(nettlebuf, "rsa", pubkey, privkey) > 0
                }
            }
        }
    }

    public func toPKCS1() -> ContiguousArray<UInt8> {
        let seq_contents_len = (
            3 + /* the version number */
            /* See, this is why it's useful for a language to have real macros */
            withUnsafePointer(to: public_key.state.n) { derIntegerLength($0) } +
            withUnsafePointer(to: public_key.state.e) { derIntegerLength($0) } +
            withUnsafePointer(to: state.d) { derIntegerLength($0) } +
            withUnsafePointer(to: state.p) { derIntegerLength($0) } +
            withUnsafePointer(to: state.q) { derIntegerLength($0) } +
            withUnsafePointer(to: state.a) { derIntegerLength($0) } +
            withUnsafePointer(to: state.b) { derIntegerLength($0) } +
            withUnsafePointer(to: state.c) { derIntegerLength($0) })

        let total_der_size = 1 + derLengthLength(forContentLength: seq_contents_len) + seq_contents_len

        var result = ContiguousArray<UInt8>(repeating: 0x00, count: total_der_size)
        var pos: Int
        result[0] = 0x30 /* SEQUENCE */
        pos = derPutLength(&result, 1, seq_contents_len)
        result[pos] = 0x02 /* INTEGER */
        result[pos+1] = 1  /* length=1 */
        result[pos+2] = 0  /* structure version = two-prime(0) */
        pos = withUnsafePointer(to: public_key.state.n) { derPutInteger(&result, pos+3, $0) }
        pos = withUnsafePointer(to: public_key.state.e) { derPutInteger(&result, pos, $0) }
        pos = withUnsafePointer(to: state.d) { derPutInteger(&result, pos, $0) }
        pos = withUnsafePointer(to: state.p) { derPutInteger(&result, pos, $0) }
        pos = withUnsafePointer(to: state.q) { derPutInteger(&result, pos, $0) }
        pos = withUnsafePointer(to: state.a) { derPutInteger(&result, pos, $0) }
        pos = withUnsafePointer(to: state.b) { derPutInteger(&result, pos, $0) }
        pos = withUnsafePointer(to: state.c) { derPutInteger(&result, pos, $0) }
        assert(pos == total_der_size)

        return result
    }

    private func sign(_ impl: (UnsafePointer<rsa_public_key>, UnsafePointer<rsa_private_key>, mpz_ptr) -> Bool) -> ContiguousArray<UInt8>? {
        return withMpzBuffer {
            (m) -> Bool in
            withUnsafePointer(to: public_key.state) {
                (pubkey) -> Bool in
                withUnsafePointer(to: state) {
                    (privkey) -> Bool in
                    impl(pubkey, privkey, m)
                }
            }
        }
    }

    public func sign_pkcs1(digest: inout SHA1) -> ContiguousArray<UInt8>? {
        return self.sign {
            (pubkey, privkey, sig) -> Bool in
            withEntropyCallback(self.entropy_source) {
                (rng_ctxt, rng_cb) -> Bool in
                nettle_rsa_sha1_sign_tr(pubkey, privkey, rng_ctxt, rng_cb, &digest.ctxt, sig) > 0
            }
        }
    }

    public func sign_pkcs1(digest: inout SHA256) -> ContiguousArray<UInt8>? {
        return self.sign {
            (pubkey, privkey, sig) -> Bool in
            withEntropyCallback(self.entropy_source) {
                (rng_ctxt, rng_cb) -> Bool in
                nettle_rsa_sha256_sign_tr(pubkey, privkey, rng_ctxt, rng_cb, &digest.ctxt, sig) > 0
            }
        }
    }

    public func sign_pkcs1(digest: inout SHA512) -> ContiguousArray<UInt8>? {
        return self.sign {
            (pubkey, privkey, sig) -> Bool in
            withEntropyCallback(self.entropy_source) {
                (rng_ctxt, rng_cb) -> Bool in
                nettle_rsa_sha512_sign_tr(pubkey, privkey, rng_ctxt, rng_cb, &digest.ctxt, sig) > 0
            }
        }
    }

    /// Compute the RSA signature of a message digest.
    ///
    /// The key's entropy_source is used for random numbers in
    /// order to blind the signing key, and for random padding
    /// if the PSS padding scheme is used.
    ///
    /// - Parameters:
    ///   - algorithm: The padding scheme to use
    ///   - digest: The digest of the message
    /// - Return: The signature
    public func sign(_ algorithm: RSAPublicKey.SignatureAlgorithm,
                     digest: ContiguousArray<UInt8>) -> ContiguousArray<UInt8>? {
        guard digest.count == algorithm.digestSize else {
            return nil
        }

        return self.sign {
            (pubkey, privkey, sig) -> Bool in
            digest.withUnsafeBufferPointer {
                (msg) -> Bool in

                switch algorithm {
                case .pkcs1v15(let h):
                    return withEntropyCallback(self.entropy_source) {
                        (rng_ctxt, rng_cb) -> Bool in
                        switch h {
                        case .sha1:
                            return nettle_rsa_sha1_sign_digest_tr(pubkey, privkey, rng_ctxt, rng_cb, msg.baseAddress, sig) > 0
                        case .sha256:
                            return nettle_rsa_sha256_sign_digest_tr(pubkey, privkey, rng_ctxt, rng_cb, msg.baseAddress, sig) > 0
                        case .sha512:
                            return nettle_rsa_sha512_sign_digest_tr(pubkey, privkey, rng_ctxt, rng_cb, msg.baseAddress, sig) > 0
                        }
                    }

                case .pss(let h, let saltLength):
                    var saltbuf = ContiguousArray<UInt8>(repeating: 0, count: saltLength)
                    saltbuf.withUnsafeMutableBufferPointer { getRandomData($0, from: self.entropy_source) }
                    return withEntropyCallback(self.entropy_source) {
                        (rng_ctxt, rng_cb) -> Bool in
                        saltbuf.withUnsafeMutableBufferPointer {
                            (salt) -> Bool in
                            switch h {
                            case .sha256:
                                return nettle_rsa_pss_sha256_sign_digest_tr(pubkey, privkey, rng_ctxt, rng_cb, salt.count, salt.baseAddress, msg.baseAddress, sig) > 0
                            case .sha384:
                                return nettle_rsa_pss_sha384_sign_digest_tr(pubkey, privkey, rng_ctxt, rng_cb, salt.count, salt.baseAddress, msg.baseAddress, sig) > 0
                            case .sha512:
                                return nettle_rsa_pss_sha512_sign_digest_tr(pubkey, privkey, rng_ctxt, rng_cb, salt.count, salt.baseAddress, msg.baseAddress, sig) > 0
                            }
                        }
                    }
                }
            }
        }
    }
}
