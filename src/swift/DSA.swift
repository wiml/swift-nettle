import CNettle.Hogweed

/// A convenience holder for DSA-style signatures.
///
/// A DSA signature (whether traditional or elliptic) consits of two
/// large numbers, `r` and `s`.  There are multiple external
/// representaions in use. This holds Nettle's internal representation
/// and allows converting to and from the common external
/// representations.
///
/// The "packed" representation is simply the concatenation of the `r`
/// and `s` values, represented as unsigned, fixed-width integers.
/// Packed signatures for a given key are always the same size.
///
/// The "der" representation is the `Dss-Sig-Value` defined in
/// RFC3279; it is a SEQUENCE containing `r` and `s` as INTEGERs.
/// Because of padding, the size of a DER-encoded DSA signature
/// varies unpredictably by a few bytes.
public final class DSASignature: Equatable {
    internal var sig: dsa_signature;

    internal init(takingOwnership buf: dsa_signature) {
        self.sig = buf
    }

    deinit {
        nettle_dsa_signature_clear(&sig)
    }

    /// Compare signatures for equality
    ///
    /// This is not a constant-time operation, and is generally not
    /// useful: DSA signatures include a random number, so two signatures
    /// of the same message will not be equal.
    public static func == (lhs: DSASignature, rhs: DSASignature) -> Bool {
        return ( nettle_swift_mpz_cmp(&lhs.sig.r, &rhs.sig.r) == 0 &&
                 nettle_swift_mpz_cmp(&lhs.sig.s, &rhs.sig.s) == 0 )
    }

    /// Create from "packed" representation
    public init?(packed: ContiguousArray<UInt8>) {
        guard packed.count > 2, packed.count.isMultiple(of: 2) else {
            return nil
        }
        let size = packed.count / 2

        sig = dsa_signature()
        packed.withUnsafeBufferPointer {
            (rs) -> Void in
            nettle_mpz_init_set_str_256_u(&sig.r, size, rs.baseAddress!)
            nettle_mpz_init_set_str_256_u(&sig.s, size, rs.baseAddress! + size)
        }
    }

    /// Create from "der" representation
    public init?(der: UnsafeBufferPointer<UInt8>, max_bits: CUnsignedInt? = nil) {
        let limit = max_bits ?? 0
        var cursor = asn1_der_iterator()
        guard nettle_asn1_der_iterator_first(&cursor, der.count, der.baseAddress) == ASN1_ITERATOR_CONSTRUCTED else {
            return nil
        }
        guard nettle_asn1_der_decode_constructed_last(&cursor) == ASN1_ITERATOR_PRIMITIVE else {
            return nil
        }
        var parsed = dsa_signature()
        nettle_dsa_signature_init(&parsed)
        guard nettle_asn1_der_get_bignum(&cursor, &parsed.r, limit) > 0 else {
            nettle_dsa_signature_clear(&parsed)
            return nil
        }
        guard nettle_asn1_der_iterator_next(&cursor) == ASN1_ITERATOR_PRIMITIVE else {
            nettle_dsa_signature_clear(&parsed)
            return nil
        }
        guard nettle_asn1_der_get_bignum(&cursor, &parsed.s, limit) > 0 else {
            nettle_dsa_signature_clear(&parsed)
            return nil
        }
        guard nettle_asn1_der_iterator_next(&cursor) == ASN1_ITERATOR_END else {
            nettle_dsa_signature_clear(&parsed)
            return nil
        }
        self.sig = parsed // takes ownership of pointers within buf
    }

    /// Produce a "packed" representation
    ///
    /// - Parameters:
    ///   - bit_size: The size in bits of the key which produced this
    ///               signature.
    public func toPacked(bit_size: CUnsignedInt) -> ContiguousArray<UInt8> {
        let octet_size = Int((bit_size + 7) / 8)
        var result = ContiguousArray<UInt8>(repeating: 0x00, count: 2 * octet_size)
        result.withUnsafeMutableBufferPointer {
            (outbuf) -> Void in
            withUnsafePointer(to: sig.r) {
                nettle_mpz_get_str_256(octet_size, outbuf.baseAddress, $0)
            }
            withUnsafePointer(to: sig.s) {
                nettle_mpz_get_str_256(octet_size, outbuf.baseAddress! + octet_size, $0)
            }
        }
        return result
    }

    /// Produce a "der" representation
    public func toDER() -> ContiguousArray<UInt8> {
        let r_size_octets = withUnsafePointer(to: sig.r) {
            nettle_mpz_sizeinbase_256_s($0)
        }
        let s_size_octets = withUnsafePointer(to: sig.s) {
            nettle_mpz_sizeinbase_256_s($0)
        }

        let r_der_hdr_size = 1 + derLengthLength(forContentLength: r_size_octets)
        let s_der_hdr_size = 1 + derLengthLength(forContentLength: s_size_octets)
        let sequence_contents_size = r_der_hdr_size + r_size_octets + s_der_hdr_size + s_size_octets
        let total_der_size = 1 + derLengthLength(forContentLength: sequence_contents_size) + sequence_contents_size

        var result = ContiguousArray<UInt8>(repeating: 0x00, count: total_der_size)

        result[0] = 0x30 /* SEQUENCE */
        let r_pos = derPutLength(&result, 1, sequence_contents_size)
        result[r_pos] = 0x02 /* INTEGER */
        let r_content_pos = derPutLength(&result, r_pos + 1, r_size_octets)
        let s_pos = r_content_pos + r_size_octets
        result[s_pos] = 0x02 /* INTEGER */
        let s_content_pos = derPutLength(&result, s_pos + 1, s_size_octets)
        assert(s_content_pos + s_size_octets == total_der_size)

        result.withUnsafeMutableBufferPointer {
            (outbuf) -> Void in
            withUnsafePointer(to: sig.r) {
                nettle_mpz_get_str_256(r_size_octets, outbuf.baseAddress! + r_content_pos, $0)
            }
            withUnsafePointer(to: sig.s) {
                nettle_mpz_get_str_256(s_size_octets, outbuf.baseAddress! + s_content_pos, $0)
            }
        }

        return result
    }

}
