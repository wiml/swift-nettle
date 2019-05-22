import CNettle.Hogweed
import Foundation
import Glibc

public enum ECCPrimeCurve {
    case secp192r1
    case secp224r1
    case secp256r1
    case secp384r1
    case secp521r1

    public var bit_size: Int {
        get {
            switch self {
            case .secp192r1: return 192
            case .secp224r1: return 224
            case .secp256r1: return 256
            case .secp384r1: return 384
            case .secp521r1: return 521
            }
        }
    }

    fileprivate var nettle_vtable: OpaquePointer {
        get {
            switch self {
            case .secp192r1: return nettle_get_secp_192r1()
            case .secp224r1: return nettle_get_secp_224r1()
            case .secp256r1: return nettle_get_secp_256r1()
            case .secp384r1: return nettle_get_secp_384r1()
            case .secp521r1: return nettle_get_secp_521r1()
            }
        }
    }

    fileprivate static func from(nettle_vtable p: OpaquePointer) -> ECCPrimeCurve? {
        switch p {
        case nettle_get_secp_192r1(): return .secp192r1
        case nettle_get_secp_224r1(): return .secp224r1
        case nettle_get_secp_256r1(): return .secp256r1
        case nettle_get_secp_384r1(): return .secp384r1
        case nettle_get_secp_521r1(): return .secp521r1
        default: return nil
        }
    }
}

/// Computes the Diffie-Hellman key agreement function between two keys.
/// The result is the X-value of the resulting shared point, converted to
/// an octet string in the conventional way described by SEC.1.
public func rawDiffieHellmanAgreement(_ pub: ECCPrimePublicKey, _ priv: ECCPrimePrivateKey) -> ContiguousArray<UInt8>? {
    if priv.scalar.ecc != pub.point.ecc {
        return nil
    }
    let bit_size = nettle_ecc_bit_size(priv.scalar.ecc)

    var result_point = ecc_point()
    nettle_ecc_point_init(&result_point, priv.scalar.ecc)
    withUnsafePointer(to: priv.scalar) {
        (ppriv) -> Void in
        withUnsafePointer(to: pub.point) {
            (ppub) -> Void in
            nettle_ecc_point_mul(&result_point, ppriv, ppub)
        }
    }

    var result_x = mpz_t()
    nettle_swift_mpz_init_prealloc(&result_x, bit_size)
    nettle_ecc_point_get(&result_point, &result_x, nil)

    let result_bytes = i2os(&result_x, width: Int((bit_size + 7) / 8))
    nettle_swift_mpz_clear(&result_x)
    nettle_ecc_point_clear(&result_point)

    return result_bytes
}

/// An elliptic curve public key.
/// This consists of a curve identifier and a point on the curve.
public final class ECCPrimePublicKey {
    fileprivate let point: ecc_point

    public var curve_size : CUnsignedInt {
        get {
            return nettle_ecc_bit_size(point.ecc)
        }
    }

    public var curve : ECCPrimeCurve {
        get {
            return ECCPrimeCurve.from(nettle_vtable: point.ecc)!
        }
    }

    fileprivate init(_ point: ecc_point) {
        self.point = point
    }

    public convenience init?(curve: ECCPrimeCurve, sec1: UnsafeBufferPointer<UInt8>) {
        self.init(curve: curve.nettle_vtable, sec1: sec1)
    }

    internal convenience init?(curve: OpaquePointer, sec1: UnsafeBufferPointer<UInt8>) {
        let bit_size = nettle_ecc_bit_size(curve)
        let octet_size = Int((bit_size + 7) / 8)

        var x_buf = mpz_t()
        var y_buf = mpz_t()

        if sec1.count == 1 + 2*octet_size {
            // Uncompressed point (the normal situation): 04 || X || Y
            if sec1[0] != 0x04 {
                return nil
            }

            nettle_mpz_init_set_str_256_u(&x_buf, octet_size, sec1.baseAddress!+1)
            nettle_mpz_init_set_str_256_u(&y_buf, octet_size, sec1.baseAddress!+1+octet_size)
        } else if sec1.count == 1 + octet_size {
            // Compressed point: {02 | 03} || X
            // where Y is computed from X and the prefix
            let negative: Bool
            switch sec1[0] {
            case 0x02:
                negative = false
            case 0x03:
                negative = true
            default:
                return nil
            }

            // TODO: Implement curve point decompression.
            // It probably makes more sense to implement this in libnettle and just call
            // that from here.
            return nil
        }

        var point = ecc_point()
        nettle_ecc_point_init(&point, curve)

        let res = nettle_ecc_point_set(&point, &x_buf, &y_buf)
        nettle_swift_mpz_clear(&x_buf)
        nettle_swift_mpz_clear(&y_buf)

        // ecc_point_set does sanity checks (is the point on the curve, nonzero, etc.);
        // if those failed, fail the initializer as well
        guard res > 0 else {
            nettle_ecc_point_clear(&point)
            return nil
        }

        self.init(point) // takes ownership of point contents
    }

    deinit {
        var buf = self.point
        nettle_ecc_point_clear(&buf)
    }

    /// Verify an ECDSA signature.
    /// Returns `true` if the signature matches the digest, `false` otherwise.
    public func verify(digest: ContiguousArray<UInt8>, _ signature: DSASignature) -> Bool {
        return withUnsafePointer(to: self.point) {
            (ppublic) -> Bool in
            return digest.withUnsafeBufferPointer {
                return nettle_ecdsa_verify(ppublic,
                                           $0.count, $0.baseAddress,
                                           &(signature.sig)) > 0
            }
        }
    }

    /// Converts the public key to the packed point representation
    /// described in SEC.1 [2.3.3].
    public func toSec1(compressed: Bool = false) -> ContiguousArray<UInt8> {
        // NOTE: We don't explicitly check for the special point at zero (or infinity).
        // My understanding is that because Nettle checks for that point in other cases,
        // we can't get that value here --- an ecc_point should never contain that value.

        var x_buf = mpz_t()
        var y_buf = mpz_t()
        let bit_size = self.curve_size
        nettle_swift_mpz_init_prealloc(&x_buf, bit_size)
        nettle_swift_mpz_init_prealloc(&y_buf, bit_size)
        withUnsafePointer(to: self.point) {
            nettle_ecc_point_get($0, &x_buf, &y_buf)
        }
        let octet_size = Int( (bit_size + 7) / 8 )

        var result: ContiguousArray<UInt8>

        if !compressed {
            result = ContiguousArray<UInt8>(repeating: 0x04, count: 1 + 2*octet_size)
            result.withUnsafeMutableBufferPointer {
                (outbuf) -> Void in
                nettle_mpz_get_str_256(octet_size, outbuf.baseAddress! + 1, &x_buf)
                nettle_mpz_get_str_256(octet_size, outbuf.baseAddress! + 1 + octet_size, &y_buf)
            }
        } else {
            result = ContiguousArray<UInt8>(repeating: 0x00, count: 1 + octet_size)
            result.withUnsafeMutableBufferPointer {
                (outbuf) -> Void in
                // This conversion only holds for prime-field curves
                if nettle_swift_mpz_odd_p(&y_buf) != 0 {
                    outbuf[0] = 0x03
                } else {
                    outbuf[0] = 0x02
                }
                nettle_mpz_get_str_256(octet_size, outbuf.baseAddress! + 1, &x_buf)
            }
        }

        nettle_swift_mpz_clear(&x_buf)
        nettle_swift_mpz_clear(&y_buf)

        return result
    }

    /// Generates a keypair using the same curve as the receiver.
    /// For example, this can be used to generate an ephemeral keypair
    /// for encryption operations via key agreement.
    public func generateSimilar(entropy: getentropy_func? = nil) -> (ECCPrimePublicKey, ECCPrimePrivateKey) {
        return ECCPrimePrivateKey.generate(curve: self.point.ecc, entropy: entropy)
    }
}

/// An elliptic curve private key.
/// This consists of a curve identifier and a secret scalar (integer) value.
public final class ECCPrimePrivateKey {
    fileprivate let scalar: ecc_scalar
    public var entropy_source: getentropy_func? = nil

    public var curve_size : CUnsignedInt {
        get {
            return nettle_ecc_bit_size(scalar.ecc)
        }
    }

    public var curve : ECCPrimeCurve {
        get {
            return ECCPrimeCurve.from(nettle_vtable: scalar.ecc)!
        }
    }

    fileprivate init(_ x: ecc_scalar) {
        self.scalar = x
    }

    deinit {
        var buf = scalar
        nettle_ecc_scalar_clear(&buf)
    }

    /// Create a private key from the representation of its secret scalar.
    ///
    /// The scalar should be in unsigned, big-endian, base-256 format, without any
    /// header.
    public convenience init?(curve: ECCPrimeCurve, scalar: UnsafeBufferPointer<UInt8>) {
        var z = mpz_t()
        nettle_mpz_init_set_str_256_u(&z, scalar.count, scalar.baseAddress)
        var buf = ecc_scalar()
        nettle_ecc_scalar_init(&buf, curve.nettle_vtable)
        let res = nettle_ecc_scalar_set(&buf, &z)
        nettle_swift_mpz_clear(&z)
        guard res > 0 else {
            nettle_ecc_scalar_clear(&buf)
            return nil
        }
        self.init(buf)
    }

    /// Generate a key pair with a specified elliptic curve.
    public static func generate(_ curve: ECCPrimeCurve, entropy: getentropy_func? = nil) -> (ECCPrimePublicKey, ECCPrimePrivateKey) {
        return self.generate(curve: curve.nettle_vtable, entropy: entropy)
    }

    internal static func generate(curve: OpaquePointer, entropy: getentropy_func? = nil) -> (ECCPrimePublicKey, ECCPrimePrivateKey) {
        var point = ecc_point()
        nettle_ecc_point_init(&point, curve)
        var scalar = ecc_scalar()
        nettle_ecc_scalar_init(&scalar, curve)
        withEntropyCallback(entropy) {
            (rng_ctxt, rng_cb) -> Void in
            nettle_ecdsa_generate_keypair(&point, &scalar,
                                          rng_ctxt, rng_cb)
        }
        return (ECCPrimePublicKey(point), ECCPrimePrivateKey(scalar))
    }

    /// Compute the public key corresponding to this secret key.
    /// This involves an EC multiplication; if the public key is
    /// needed often, it's a good idea to compute it once and cache it.
    public func compute_public_key() -> ECCPrimePublicKey {
        var buf = ecc_point()
        nettle_ecc_point_init(&buf, scalar.ecc)
        withUnsafePointer(to: scalar) {
            nettle_ecc_point_mul_g(&buf, $0)
        }
        return ECCPrimePublicKey(buf)
    }

    /// Returns this private key as an octet-string.
    /// The result corresponds to the field element converted to an octet
    /// string as described in SEC.1 section 2.3.5.
    /// The result is always a fixed length for a given curve.
    public func toSec1() -> ContiguousArray<UInt8> {
        let bits = curve_size
        let octets = Int((bits + 7) / 8)
        var integer = mpz_t()
        nettle_swift_mpz_init_prealloc(&integer, bits)
        withUnsafePointer(to: scalar) {
            nettle_ecc_scalar_get($0, &integer)
        }
        var result = ContiguousArray<UInt8>(repeating: 0x00, count: octets)
        result.withUnsafeMutableBufferPointer {
            (outbuf) -> Void in
            nettle_mpz_get_str_256(outbuf.count, outbuf.baseAddress, &integer)
        }
        nettle_swift_mpz_clear(&integer)
        return result
    }

    /// Produce an ECDSA signature of a value.
    /// Typically, the `digest` value will be the result of a hash function, whose size
    /// is approximately the same as this key's curve's group order.
    public func sign(digest: ContiguousArray<UInt8>, entropy: getentropy_func? = nil) -> DSASignature {
        return digest.withUnsafeBufferPointer {
            (buf) -> DSASignature in
            withUnsafePointer(to: self.scalar) {
                (pprivate) -> DSASignature in
                var signature = dsa_signature()
                withEntropyCallback(entropy ?? entropy_source) {
                    (rng_ctxt, rng_cb) -> Void in
                    nettle_ecdsa_sign(pprivate,
                                      rng_ctxt, rng_cb,
                                      buf.count, buf.baseAddress,
                                      &signature)
                }
                return DSASignature(takingOwnership: signature)
            }
        }
    }
}
