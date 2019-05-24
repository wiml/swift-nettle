import CNettle.Hogweed
import Foundation

fileprivate func call_progress(_ ctxt: UnsafeMutableRawPointer?, _ st: CInt) -> () {
    ctxt!.assumingMemoryBound(to: progress_func.self).pointee(st)
}

fileprivate typealias progress_cb = @convention(c) (UnsafeMutableRawPointer?, CInt) -> Void

// TODO: Submit doc patch to nettle to explain limit / max_bits behavior

public class RSAPublicKey {
    fileprivate var state: rsa_public_key

    public var output_size : Int {
        get {
            return Int(state.size)
        }
    }

    fileprivate init?(_ importer: (UnsafeMutablePointer<rsa_public_key>) -> Bool) {
        state = rsa_public_key()
        nettle_rsa_public_key_init(&state)
        guard importer(&state) else {
            nettle_rsa_public_key_clear(&state)
            return nil
        }
        guard nettle_rsa_public_key_prepare(&state) > 0 else {
            nettle_rsa_public_key_clear(&state)
            return nil
        }
    }

    deinit {
        nettle_rsa_public_key_clear(&state)
    }

    public convenience init?(PKCS1 data: ContiguousBytes, max_bits: CUnsignedInt? = nil) {
        self.init(
          {
              (keybuf) -> Bool in
              data.withUnsafeBytes {
                  nettle_rsa_keypair_from_der(keybuf, nil, max_bits ?? 0, $0.count, $0.baseAddress!.assumingMemoryBound(to: UInt8.self))
              } > 0
          }
        )
    }

    public convenience init?(Sexp data: ContiguousBytes,  max_bits: CUnsignedInt? = nil) {
        self.init(
          {
              (keybuf) -> Bool in
              data.withUnsafeBytes {
                  nettle_rsa_keypair_from_sexp(keybuf, nil, max_bits ?? 0, $0.count, $0.baseAddress!.assumingMemoryBound(to: UInt8.self))
              } > 0
          }
        )
    }

    private func verify_signature(_ buf: ContiguousArray<UInt8>, _ digest: ContiguousArray<UInt8>, _ impl: @convention(c) (UnsafePointer<rsa_public_key>?, UnsafePointer<UInt8>?, UnsafePointer<mpz_t>?) -> Int32) -> Bool {
        var m = mpz_t()
        buf.withUnsafeBytes {
            nettle_mpz_init_set_str_256_u(&m,  $0.count, $0.baseAddress!.assumingMemoryBound(to: UInt8.self))
        }
        let result = digest.withUnsafeBytes { impl(&state, $0.baseAddress!.assumingMemoryBound(to: UInt8.self), &m) }
        nettle_swift_mpz_clear(&m)
        return result > 0
    }

    private func verify_signature(_ buf: ContiguousArray<UInt8>, _ digest: ContiguousArray<UInt8>, _ saltLength: Int, _ impl: @convention(c) (UnsafePointer<rsa_public_key>?, Int, UnsafePointer<UInt8>?, UnsafePointer<mpz_t>?) -> Int32) -> Bool {
        var m = mpz_t()
        buf.withUnsafeBytes {
            nettle_mpz_init_set_str_256_u(&m,  $0.count, $0.baseAddress!.assumingMemoryBound(to: UInt8.self))
        }
        let result = digest.withUnsafeBytes { impl(&state, saltLength, $0.baseAddress!.assumingMemoryBound(to: UInt8.self), &m) }
        nettle_swift_mpz_clear(&m)
        return result > 0
    }

    private func verify_signature(_ buf: ContiguousArray<UInt8>, _ digest: UnsafeMutableRawPointer, _ saltLength: Int, _ impl: @convention(c) (UnsafePointer<rsa_public_key>?, Int, UnsafeMutableRawPointer, UnsafePointer<mpz_t>?) -> Int32) -> Bool {
        var m = mpz_t()
        buf.withUnsafeBytes {
            nettle_mpz_init_set_str_256_u(&m,  $0.count, $0.baseAddress!.assumingMemoryBound(to: UInt8.self))
        }
        let result = impl(&state, saltLength, digest, &m)
        nettle_swift_mpz_clear(&m)
        return result > 0
    }
    
    public func verify_pkcs1(digest: inout SHA1, _ buf: ContiguousArray<UInt8>) -> Bool {
        return self.verify_signature(buf, digest.digest(), nettle_rsa_sha1_verify_digest)
    }
    public func verify_pkcs1(digest: inout SHA256, _ buf: ContiguousArray<UInt8>) -> Bool {
        return self.verify_signature(buf, digest.digest(), nettle_rsa_sha256_verify_digest)
    }
    public func verify_pkcs1(digest: inout SHA512, _ buf: ContiguousArray<UInt8>) -> Bool {
        return self.verify_signature(buf, digest.digest(), nettle_rsa_sha512_verify_digest)
    }

    public func verify_pss(digest: inout SHA256, saltLength: Int, _ buf: ContiguousArray<UInt8>) -> Bool {
        return self.verify_signature(buf, digest.digest(), saltLength, nettle_rsa_pss_sha256_verify_digest)
    }
    public func verify_pss(digest: inout SHA384, saltLength: Int, _ buf: ContiguousArray<UInt8>) -> Bool {
        return self.verify_signature(buf, digest.digest(), saltLength, nettle_rsa_pss_sha384_verify_digest)
    }
    public func verify_pss(digest: inout SHA512, saltLength: Int, _ buf: ContiguousArray<UInt8>) -> Bool {
        return self.verify_signature(buf, digest.digest(), saltLength, nettle_rsa_pss_sha512_verify_digest)
    }
}

public class RSAPrivateKey {
    public let public_key: RSAPublicKey
    private var state: rsa_private_key
    public var entropy_source: getentropy_func? = nil

    fileprivate init?(_ importer: (UnsafeMutablePointer<rsa_public_key>, UnsafeMutablePointer<rsa_private_key>) -> Bool) {
        var state_buf = rsa_private_key()
        nettle_rsa_private_key_init(&state_buf)
        guard let public_key = (RSAPublicKey( { importer($0, &state_buf) })) else {
            nettle_rsa_private_key_clear(&state_buf)
            return nil
        }
        self.state = state_buf
        guard nettle_rsa_private_key_prepare(&state) > 0 else {
            nettle_rsa_private_key_clear(&state)
            return nil
        }
        self.public_key = public_key
    }

    deinit {
        nettle_rsa_private_key_clear(&state)
    }

    public enum exponentChoice {
        case fixed(UInt)
        case random(CUnsignedInt)
    }

    public static func generate(sizeInBits: CUnsignedInt,
                                exponent: exponentChoice = .fixed(0x10001),
                                entropy: getentropy_func? = nil,
                                progress: progress_func? = nil) -> RSAPrivateKey? {
        let result = self.init(
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
                    nettle_rsa_keypair_to_sexp(nettlebuf, nil, pubkey, privkey) > 0
                }
            }
        }
    }

    private typealias pkcs1_signer_fn = @convention(c)
      (UnsafePointer<rsa_public_key>?,
       UnsafePointer<rsa_private_key>?,
       UnsafeMutableRawPointer?, getentropy_cb?,
       UnsafePointer<UInt8>?,
       UnsafeMutablePointer<mpz_t>?) -> CInt

    private typealias pss_signer_fn = @convention(c)
      (UnsafePointer<rsa_public_key>?,
       UnsafePointer<rsa_private_key>?,
       UnsafeMutableRawPointer?, getentropy_cb?,
       Int, UnsafePointer<UInt8>?,
       UnsafePointer<UInt8>?,
       UnsafeMutablePointer<mpz_t>?) -> CInt

    private func compute_pkcs1v15_signature(_ digest: ContiguousArray<UInt8>, _ impl: pkcs1_signer_fn) -> ContiguousArray<UInt8>? {
        var m = mpz_t()
        nettle_swift_mpz_init_prealloc(&m, CUnsignedInt(8 * self.state.size))
        let result = digest.withUnsafeBytes {
            (buf: UnsafeRawBufferPointer) -> CInt in
            withEntropyCallback(self.entropy_source) {
                (rng_ctxt, rng_cb) -> CInt in
                impl(&public_key.state, &state,
                     rng_ctxt, rng_cb,
                     buf.baseAddress!.assumingMemoryBound(to: UInt8.self), &m)
            }
        }
        let digest: ContiguousArray<UInt8>?
        if result > 0 {
            digest = i2os(&m)
        } else {
            digest = nil
        }
        nettle_swift_mpz_clear(&m)
        return digest
    }

    private func compute_pss_signature(_ digest: ContiguousArray<UInt8>, saltLength: Int, _ impl: pss_signer_fn) -> ContiguousArray<UInt8>? {
        guard saltLength >= 0 && saltLength <= self.state.size else {
            return nil
        }
        var m = mpz_t()
        nettle_swift_mpz_init_prealloc(&m, CUnsignedInt(8 * self.state.size))
        let result = digest.withUnsafeBytes {
            (buf: UnsafeRawBufferPointer) -> CInt in
            let saltBuf = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: Int(saltLength))
            if let ent = self.entropy_source {
                ent(saltBuf)
            } else {
                default_entropy_source(saltBuf)
            }
            let result_ = withEntropyCallback(self.entropy_source) {
                (rng_ctxt, rng_cb) -> CInt in
                impl(&public_key.state, &state,
                     rng_ctxt, rng_cb,
                     saltLength, saltBuf.baseAddress,
                     buf.baseAddress!.assumingMemoryBound(to: UInt8.self), &m)
            }
            saltBuf.deallocate()
            return result_
        }
        let digest: ContiguousArray<UInt8>?
        if result > 0 {
            digest = i2os(&m)
        } else {
            digest = nil
        }
        nettle_swift_mpz_clear(&m)
        return digest
    }

    public func sign_pkcs1(digest: inout SHA1) -> ContiguousArray<UInt8>? {
        return self.compute_pkcs1v15_signature(digest.digest(), nettle_rsa_sha1_sign_digest_tr)
    }
    public func sign_pkcs1(digest: inout SHA256) -> ContiguousArray<UInt8>? {
        return self.compute_pkcs1v15_signature(digest.digest(), nettle_rsa_sha256_sign_digest_tr)
    }
    public func sign_pkcs1(digest: inout SHA512) -> ContiguousArray<UInt8>? {
        return self.compute_pkcs1v15_signature(digest.digest(), nettle_rsa_sha512_sign_digest_tr)
    }

    public func sign_pss(digest: inout SHA256, saltLength: Int) -> ContiguousArray<UInt8>? {
        return self.compute_pss_signature(digest.digest(), saltLength: saltLength, nettle_rsa_pss_sha256_sign_digest_tr)
    }
    public func sign_pss(digest: inout SHA384, saltLength: Int) -> ContiguousArray<UInt8>? {
        return self.compute_pss_signature(digest.digest(), saltLength: saltLength, nettle_rsa_pss_sha384_sign_digest_tr)
    }
    public func sign_pss(digest: inout SHA512, saltLength: Int) -> ContiguousArray<UInt8>? {
        return self.compute_pss_signature(digest.digest(), saltLength: saltLength, nettle_rsa_pss_sha512_sign_digest_tr)
    }
}
