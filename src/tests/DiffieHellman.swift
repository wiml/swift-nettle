import XCTest
import Foundation
import Nettle

public class DiffieHellmanTests : XCTestCase {

    func randomKeyAgreement() {
        let (Qa, da) = ECCPrimePrivateKey.generate(.secp384r1)
        let (Qb, db) = ECCPrimePrivateKey.generate(.secp384r1)

        XCTAssertEqual(Qa.curve_size, 384)
        XCTAssertEqual(Qa.curve, .secp384r1)

        let secret1 = rawDiffieHellmanAgreement(Qa, db)!
        XCTAssertEqual(secret1.count, 384 / 8)
        let secret2 = rawDiffieHellmanAgreement(Qb, da)!
        XCTAssertEqual(secret1, secret2)
    }

    func randomKeyDisagreement() {
        let (Qa, da) = ECCPrimePrivateKey.generate(.secp384r1)
        let (Qb, db) = ECCPrimePrivateKey.generate(.secp256r1)

        XCTAssertEqual(Qb.curve_size, 256)
        XCTAssertEqual(Qa.curve, .secp384r1)
        XCTAssertEqual(Qb.curve, .secp256r1)

        let secret1 = rawDiffieHellmanAgreement(Qa, db)
        XCTAssertNil(secret1)
        let secret2 = rawDiffieHellmanAgreement(Qb, da)
        XCTAssertNil(secret2)
    }

    func generateSimilar() {
        let (Qa, da) = ECCPrimePrivateKey.generate(.secp521r1)
        let (Qb, db) = Qa.generateSimilar()

        XCTAssertEqual(Qb.curve_size, 521)
        XCTAssertEqual(Qb.curve, .secp521r1)

        let secret1 = rawDiffieHellmanAgreement(Qa, db)!
        XCTAssertEqual(secret1.count, (521 + 7) / 8)
        let secret2 = rawDiffieHellmanAgreement(Qb, da)!
        XCTAssertEqual(secret1, secret2)
    }

    func knownKeyAgreement() {
        let da = ec1_priv_bare.withUnsafeBufferPointer {
            ECCPrimePrivateKey(curve: ec1_curve, scalar: $0)
        }!
        let Qa = da.compute_public_key()

        let db = ec2_priv_bare.withUnsafeBufferPointer {
            ECCPrimePrivateKey(curve: ec2_curve, scalar: $0)
        }!
        let Qb = db.compute_public_key()

        let secret_a_b = rawDiffieHellmanAgreement(Qa, db)
        XCTAssertEqual(secret_a_b, ec1_ec2_raw_shared)

        let secret_b_a = rawDiffieHellmanAgreement(Qb, da)
        XCTAssertEqual(secret_b_a, ec1_ec2_raw_shared)
    }

    static public let allTests = [
        ("randomKeyAgreement", randomKeyAgreement),
        ("randomKeyDisagreement", randomKeyDisagreement),
        ("generateSimilar", generateSimilar),
        ("knownKeyAgreement", knownKeyAgreement),
    ]
}
