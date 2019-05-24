import CNettle.Hogweed
import Foundation

fileprivate func call_progress(_ ctxt: UnsafeMutableRawPointer?, _ st: CInt) -> () {
    ctxt!.assumingMemoryBound(to: progress_func.self).pointee(st)
}

fileprivate typealias progress_cb = @convention(c) (UnsafeMutableRawPointer?, CInt) -> Void

// TODO: Submit doc patch to nettle to explain limit / max_bits behavior

public class RSAPublicKey {
    fileprivate let state: rsa_public_key

    public final var bit_size : CUnsignedInt {
        get {
            return withUnsafePointer(to: state.n) {
                CUnsignedInt(nettle_swift_mpz_sizeinbase_2($0))
            }
        }
    }

    fileprivate init(adopting st: rsa_public_key) {
        self.state = st
    }

    deinit {
        var buf = state // sigh
        nettle_rsa_public_key_clear(&buf)
    }

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
        }
        case pkcs1v15(_ : SSAHash)
        case pss(_ : PSSHash, saltLength: Int)

        public var digestSize: Int {
            get {
                switch self {
                case .pkcs1v15(let h): return h.digestSize
                case .pss(let h, _): return h.digestSize
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

public class RSAPrivateKey {
    public let public_key: RSAPublicKey
    private let state: rsa_private_key
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
