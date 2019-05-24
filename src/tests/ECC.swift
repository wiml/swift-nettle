import XCTest
import Nettle

public class ECDHTests : XCTestCase {

    func testLoadSavePubKey() {
        let Qa = ec1_pub_sec1.withUnsafeBufferPointer {
            ECCPrimePublicKey(curve: ec1_curve, sec1: $0)
        }!
        XCTAssertEqual(Qa.curve_size, 256)
        XCTAssertEqual(Qa.curve, ec1_curve)
        XCTAssertEqual(Qa.toSec1(), ec1_pub_sec1)
        XCTAssertEqual(Qa.toSec1(compressed: true), ec1_pub_sec1_c)

        let Qb = ec2_pub_sec1.withUnsafeBufferPointer {
            ECCPrimePublicKey(curve: ec2_curve, sec1: $0)
        }!
        XCTAssertEqual(Qb.curve_size, 256)
        XCTAssertEqual(Qb.toSec1(), ec2_pub_sec1)
        XCTAssertEqual(Qb.toSec1(compressed: true), ec2_pub_sec1_c)
    }

    func testLoadSavePrivKey() {
        let da = ec1_priv_bare.withUnsafeBufferPointer {
            ECCPrimePrivateKey(curve: ec1_curve, scalar: $0)
        }!
        XCTAssertEqual(da.curve, ec1_curve)
        XCTAssertEqual(da.toSec1(), ec1_priv_bare)

        let Qa = da.compute_public_key()
        XCTAssertEqual(Qa.curve_size, 256)
        XCTAssertEqual(Qa.curve, ec1_curve)
        XCTAssertEqual(Qa.toSec1(), ec1_pub_sec1)
    }

    func testLoadSaveSig() {
        let s1 = DSASignature(packed: testmsg_signature_p)
        let s2 = testmsg_signature_der.withUnsafeBufferPointer {
            DSASignature(der: $0)
        }
        XCTAssertEqual(s1, s2)

        XCTAssertEqual(s1?.toDER(), testmsg_signature_der)
        XCTAssertEqual(s1?.toPacked(bit_size: CUnsignedInt(ec1_curve.bit_size)),
                       testmsg_signature_p)

        // TODO:
        // Test secp521 signatures (which will be large enough to extercise the
        // 2-byte length field code for the DER format)
        // Test signatures with various numbers of leading 0 bits in one or the
        // other value, to ensure that padding is/isn't inserted as appropriate
    }

    func testKnownSignature() {
        let Qa = ec1_pub_sec1.withUnsafeBufferPointer {
            ECCPrimePublicKey(curve: ec1_curve, sec1: $0)
        }!

        let sig = DSASignature(packed: testmsg_signature_p)!
        let result = Qa.verify(digest: testmsg_digest, sig)
        XCTAssertTrue(result)

        var broken_msg = testmsg_digest
        broken_msg[3] ^= 0x08
        XCTAssertFalse(Qa.verify(digest: broken_msg, sig))

        var broken_sig = testmsg_signature_p
        broken_sig[10] ^= 0x80
        XCTAssertFalse(Qa.verify(digest: testmsg_digest,
                                 DSASignature(packed: broken_sig)!))

        broken_sig = testmsg_signature_p
        broken_sig[broken_sig.count - 7] ^= 0x80
        XCTAssertFalse(Qa.verify(digest: testmsg_digest,
                                 DSASignature(packed: broken_sig)!))
    }

    func testSignVerify() {
        let Qa = ec1_pub_sec1.withUnsafeBufferPointer {
            ECCPrimePublicKey(curve: ec1_curve, sec1: $0)
        }!
        let da = ec1_priv_bare.withUnsafeBufferPointer {
            ECCPrimePrivateKey(curve: ec1_curve, scalar: $0)
        }!

        let sig1 = da.sign(digest: testmsg_digest)
        XCTAssertTrue(Qa.verify(digest: testmsg_digest, sig1))

        // Signatures include a random nonce; verify that multiple sigs differ
        let sig2 = da.sign(digest: testmsg_digest)
        XCTAssertEqual(sig1, sig1)
        XCTAssertNotEqual(sig1, sig2)
        XCTAssertTrue(Qa.verify(digest: testmsg_digest, sig2))
    }

    static public let allTests = [
        ("testLoadSavePubKey", testLoadSavePubKey),
        ("testLoadSavePrivKey", testLoadSavePrivKey),
        ("testLoadSaveSig", testLoadSaveSig),
        ("testKnownSignature", testKnownSignature),
        ("testSignVerify", testSignVerify),
    ]
}
