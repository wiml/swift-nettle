import XCTest
import Nettle

public class RSATests : XCTestCase {

    func testLoadSaveKey() {
        let privk = RSAPrivateKey(Sexp: rsa1_priv_sexp)!
        XCTAssertEqual(privk.public_key.bit_size, 500)

        XCTAssertEqual(privk.toSexp(), rsa1_priv_sexp)
        XCTAssertEqual(privk.toPKCS1(), rsa1_priv_pkcs1)
        XCTAssertEqual(privk.public_key.toPKCS1(), rsa1_pub_pkcs1)
        XCTAssertEqual(privk.public_key.toSexp(), rsa1_pub_sexp)

        let pubk = RSAPublicKey(PKCS1: rsa1_pub_pkcs1)!
        XCTAssertEqual(pubk.bit_size, 500)

        XCTAssertEqual(pubk.toPKCS1(), rsa1_pub_pkcs1)
        XCTAssertEqual(pubk.toSexp(), rsa1_pub_sexp)

        let privk2 = RSAPrivateKey(PKCS1: rsa1_priv_pkcs1)!
        XCTAssertEqual(privk2.toSexp(), rsa1_priv_sexp)
        XCTAssertEqual(privk2.public_key.toSexp(), rsa1_pub_sexp)

        let pubk2 = RSAPublicKey(Sexp: rsa1_pub_sexp)!
        XCTAssertEqual(pubk2.toSexp(), rsa1_pub_sexp)
        XCTAssertEqual(pubk2.toPKCS1(), rsa1_pub_pkcs1)

        let privk3 = RSAPrivateKey(PKCS1: rsa2_priv_pkcs1)!
        XCTAssertEqual(privk3.public_key.bit_size, 2048)
        XCTAssertEqual(privk3.toPKCS1(), rsa2_priv_pkcs1)
        XCTAssertEqual(privk3.public_key.toPKCS1(), rsa2_pub_pkcs1)
        let pubk3 = RSAPublicKey(PKCS1: rsa2_pub_pkcs1)!
        XCTAssertEqual(pubk3.bit_size, 2048)
        XCTAssertEqual(pubk3.toPKCS1(), rsa2_pub_pkcs1)

        // We don't have a known-good sexpr representation for rsa2,
        // but at least verify that we can roundtrip it
        XCTAssertEqual(
            RSAPrivateKey(Sexp: RSAPrivateKey(PKCS1: rsa2_priv_pkcs1)!.toSexp()!)!.toPKCS1(),
            rsa2_priv_pkcs1)
        XCTAssertEqual(
            RSAPublicKey(Sexp: RSAPublicKey(PKCS1: rsa2_pub_pkcs1)!.toSexp()!)!.toPKCS1(),
            rsa2_pub_pkcs1)
    }

    func testLoadFailures() {
        // Test the failure paths in key loading.
        // This is most useful in conjunction with a leak detector + address sanitizer build

        XCTAssertNil(RSAPrivateKey(Sexp: []))
        XCTAssertNil(RSAPrivateKey(Sexp: rsa1_priv_sexp[0 ..< 64]))

        XCTAssertNil(RSAPrivateKey(PKCS1: []))
        XCTAssertNil(RSAPrivateKey(PKCS1: rsa1_priv_pkcs1[0 ..< 100]))
        XCTAssertNil(RSAPrivateKey(PKCS1: rsa1_priv_pkcs1 + [0, 0, 0]))

        XCTAssertNil(RSAPublicKey(Sexp: []))
        XCTAssertNil(RSAPublicKey(Sexp: rsa1_pub_sexp[0 ..< 60]))

        XCTAssertNil(RSAPublicKey(PKCS1: []))
        XCTAssertNil(RSAPublicKey(PKCS1: rsa1_pub_pkcs1[0 ..< 1]))
        XCTAssertNil(RSAPublicKey(PKCS1: rsa1_pub_pkcs1[0 ..< 2]))
        XCTAssertNil(RSAPublicKey(PKCS1: rsa1_pub_pkcs1[0 ..< 3]))
        XCTAssertNil(RSAPublicKey(PKCS1: rsa1_pub_pkcs1[0 ..< 4]))
        XCTAssertNil(RSAPublicKey(PKCS1: rsa1_pub_pkcs1[0 ..< 20]))
        XCTAssertNil(RSAPublicKey(PKCS1: rsa1_pub_pkcs1 + [0xFF]))
    }

    func testGenerateSignVerify() {
        let key1 = RSAPrivateKey.generate(sizeInBits: 1536)!
        var msg = ContiguousArray<UInt8>(repeating: 0xFF, count: 128)
        msg.withUnsafeMutableBufferPointer { getRandomData($0, from: nil) }

        let sigtypes : [(RSAPublicKey.SignatureAlgorithm, () -> HashProtocol)] = [
            ( .pkcs1v15(.sha1), SHA1.init ),
            ( .pkcs1v15(.sha256), SHA256.init ),
            ( .pkcs1v15(.sha512), SHA512.init ),
            ( .pss(.sha256, saltLength: 32), SHA256.init ),
            ( .pss(.sha384, saltLength: 48), SHA384.init ),
            ( .pss(.sha384, saltLength: 64), SHA384.init ),
            ( .pss(.sha512, saltLength: 64), SHA512.init )
        ]

        for (alg, hc) in sigtypes {
            var d = hc()
            d.update(msg)
            let dgst = d.digest()

            let signature = key1.sign(alg, digest: dgst)!
            XCTAssertTrue(key1.public_key.verify(alg, signature, digest: dgst))

            var sig_broken = signature
            sig_broken[sig_broken.count / 2] ^= 0x30
            XCTAssertFalse(key1.public_key.verify(alg, sig_broken, digest: dgst))

            var dgst_broken = dgst
            dgst_broken[dgst_broken.count / 3] ^= 0x07
            XCTAssertFalse(key1.public_key.verify(alg, signature, digest: dgst_broken))

            XCTAssertFalse(key1.public_key.verify(alg, signature, digest: ContiguousArray(dgst[ 0 ..< dgst.count/2 ])))

            XCTAssertNil(key1.sign(alg, digest: ContiguousArray(dgst[ 0 ..< (dgst.count-1) ])))
            XCTAssertNil(key1.sign(alg, digest: dgst + [0]))
        }
    }

    func testVerifyPKCS1v15() {
        let test_msg = rsa2_test_msg.data(using: .ascii)!
        let key2 = RSAPublicKey(PKCS1: rsa2_pub_pkcs1)!

        var hc_sha256 = SHA256()
        hc_sha256.update(test_msg)
        XCTAssertTrue(key2.verify_pkcs1(rsa2_signature_pkcs1_sha256, digest: &hc_sha256))

        var hc_sha256_ = Hash.named("sha256")!
        hc_sha256_.update(test_msg)
        let sha256_digest = hc_sha256_.digest()
        XCTAssertTrue(key2.verify(.pkcs1v15(.sha256),
                                  rsa2_signature_pkcs1_sha256,
                                  digest: sha256_digest))

        // PKCS1 padding, unlike PSS, is deterministic --- signing the same data twice
        // will give the same signature.
        let privkey2 = RSAPrivateKey(PKCS1: rsa2_priv_pkcs1)!
        hc_sha256 = SHA256()
        hc_sha256.update(test_msg)
        let mysig = privkey2.sign_pkcs1(digest: &hc_sha256)
        XCTAssertEqual(mysig, rsa2_signature_pkcs1_sha256)
    }

    func testVerifyPSS() {
        let test_msg = rsa2_test_msg.data(using: .ascii)!
        let key = RSAPublicKey(PKCS1: rsa2_pub_pkcs1)!

        var hc = Hash.named("sha512")!
        hc.update(test_msg)
        let digest_sha512 = hc.digest()

        XCTAssertTrue(key.verify(.pss(.sha512, saltLength: 20),
                                 rsa2_signature_pss_sha512_20,
                                 digest: digest_sha512))
        XCTAssertFalse(key.verify(.pss(.sha512, saltLength: 20),
                                  rsa2_signature_pss_sha512_64,
                                  digest: digest_sha512))
        XCTAssertFalse(key.verify(.pss(.sha256, saltLength: 20),
                                  rsa2_signature_pss_sha512_20,
                                  digest: digest_sha512))
        XCTAssertTrue(key.verify(.pss(.sha512, saltLength: 64),
                                 rsa2_signature_pss_sha512_64,
                                 digest: digest_sha512))
        XCTAssertFalse(key.verify(.pss(.sha512, saltLength: 64),
                                  rsa2_signature_pss_sha512_20,
                                  digest: digest_sha512))

    }

    static public let allTests = [
        ("testLoadSaveKey", testLoadSaveKey),
        ("testLoadFailures", testLoadFailures),
        ("testGenerateSignVerify", testGenerateSignVerify),
        ("testVerifyPKCS1v15", testVerifyPKCS1v15),
        ("testVerifyPSS", testVerifyPSS),
    ]
}
