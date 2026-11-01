// Added for AeroOps. Licensed under Apache License 2.0, like the rest of this package.

import Crypto
import Foundation
import NIOCore
import Security
import XCTest

@testable import NIOSSH

final class RSAHostKeyTests: XCTestCase {
    private let message = SHA256.hash(data: Data("exchange hash".utf8))

    private func makeKey(bits: Int = 2048) throws -> (privateKey: SecKey, exponent: Data, modulus: Data) {
        let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: bits]
        var error: Unmanaged<CFError>?
        let privateKey = try XCTUnwrap(SecKeyCreateRandomKey(attributes as CFDictionary, &error))
        let publicKey = try XCTUnwrap(SecKeyCopyPublicKey(privateKey))
        let der = try XCTUnwrap(SecKeyCopyExternalRepresentation(publicKey, &error)) as Data
        var reader = DERReader(bytes: der)
        reader.enterSequence()
        let modulus = reader.readInteger()
        let exponent = reader.readInteger()
        return (privateKey, exponent, modulus)
    }

    private func wireKey(exponent: Data, modulus: Data, prefix: String = "ssh-rsa") -> ByteBuffer {
        var buffer = ByteBufferAllocator().buffer(capacity: 512)
        buffer.writeSSHString(prefix.utf8)
        buffer.writeSSHString(exponent)
        buffer.writeSSHString(modulus)
        return buffer
    }

    private func publicKey(_ key: (privateKey: SecKey, exponent: Data, modulus: Data)) throws -> NIOSSHPublicKey {
        var buffer = wireKey(exponent: key.exponent, modulus: key.modulus)
        return try XCTUnwrap(buffer.readSSHHostKey())
    }

    private func signature(
        by privateKey: SecKey, algorithm: SecKeyAlgorithm, name: String, over bytes: Data
    ) throws -> NIOSSHSignature {
        var error: Unmanaged<CFError>?
        let raw = try XCTUnwrap(SecKeyCreateSignature(privateKey, algorithm, bytes as CFData, &error)) as Data
        var buffer = ByteBufferAllocator().buffer(capacity: 512)
        buffer.writeSSHString(name.utf8)
        buffer.writeSSHString(raw)
        return try XCTUnwrap(buffer.readSSHSignature())
    }

    private var messageBytes: Data { message.withUnsafeBytes { Data($0) } }

    func testVerifiesBothSHA2Signatures() throws {
        let key = try makeKey()
        let host = try publicKey(key)
        for (algorithm, name) in [
            (SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA512, "rsa-sha2-512"),
            (SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256, "rsa-sha2-256"),
        ] {
            let signed = try signature(by: key.privateKey, algorithm: algorithm, name: name, over: messageBytes)
            XCTAssertTrue(host.isValidSignature(signed, for: message), name)
        }
    }

    func testRejectsAnotherMessageAndAnotherKey() throws {
        let key = try makeKey()
        let signed = try signature(
            by: key.privateKey, algorithm: .rsaSignatureMessagePKCS1v15SHA512, name: "rsa-sha2-512", over: messageBytes
        )
        XCTAssertFalse(try publicKey(key).isValidSignature(signed, for: SHA256.hash(data: Data("other".utf8))))
        XCTAssertFalse(try publicKey(try makeKey()).isValidSignature(signed, for: message))
    }

    func testRejectsAFlippedSignatureByte() throws {
        let key = try makeKey()
        let signed = try signature(
            by: key.privateKey, algorithm: .rsaSignatureMessagePKCS1v15SHA512, name: "rsa-sha2-512", over: messageBytes
        )
        guard case .rsa(let rsa) = signed.backingSignature else { return XCTFail("not RSA") }
        var bytes = rsa.bytes
        bytes[bytes.startIndex + 40] ^= 1
        let tampered = NIOSSHSignature(
            backingSignature: .rsa(RSAHostSignature(algorithm: rsa.algorithm, bytes: bytes))
        )
        XCTAssertFalse(try publicKey(key).isValidSignature(tampered, for: message))
    }

    func testRejectsASignatureClaimingTheOtherHash() throws {
        let key = try makeKey()
        let signed = try signature(
            by: key.privateKey, algorithm: .rsaSignatureMessagePKCS1v15SHA256, name: "rsa-sha2-512", over: messageBytes
        )
        XCTAssertFalse(try publicKey(key).isValidSignature(signed, for: message))
    }

    func testSHA1SignaturesStayUnknown() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 64)
        buffer.writeSSHString("ssh-rsa".utf8)
        buffer.writeSSHString(Data(repeating: 1, count: 256))
        XCTAssertThrowsError(try buffer.readSSHSignature())
    }

    func testRefusesSmallModulus() throws {
        let key = try makeKey(bits: 1024)
        var buffer = wireKey(exponent: key.exponent, modulus: key.modulus)
        XCTAssertThrowsError(try buffer.readSSHHostKey())
    }

    func testRefusesNonCanonicalEncodings() throws {
        let key = try makeKey()
        for (exponent, modulus) in [
            (Data([0, 1, 0, 1]), key.modulus),
            (Data([0x81, 0, 1]), key.modulus),
            (Data(), key.modulus),
            (Data([2]), key.modulus),
            (Data([1]), key.modulus),
            (Data(repeating: 1, count: 9), key.modulus),
            (key.exponent, Data([0]) + key.modulus),
            (key.exponent, key.modulus.dropFirst()),
        ] {
            var buffer = wireKey(exponent: exponent, modulus: Data(modulus))
            XCTAssertThrowsError(try buffer.readSSHHostKey())
        }
    }

    func testOpenSSHFormRoundTripsTheWireBytes() throws {
        let host = try publicKey(try makeKey())
        let text = String(openSSHPublicKey: host)
        XCTAssertTrue(text.hasPrefix("ssh-rsa AAAAB3NzaC1yc2E"))
        XCTAssertEqual(try NIOSSHPublicKey(openSSHPublicKey: text), host)
    }

    func testKeyAndSignatureMustFitTheNegotiatedAlgorithm() throws {
        let key = try makeKey()
        let host = try publicKey(key)
        let signed = try signature(
            by: key.privateKey, algorithm: .rsaSignatureMessagePKCS1v15SHA512, name: "rsa-sha2-512", over: messageBytes
        )
        XCTAssertTrue(host.fits(hostKeyAlgorithm: "rsa-sha2-512", signature: signed))
        XCTAssertFalse(host.fits(hostKeyAlgorithm: "rsa-sha2-256", signature: signed))
        XCTAssertFalse(host.fits(hostKeyAlgorithm: "ssh-rsa", signature: signed))
        XCTAssertFalse(host.fits(hostKeyAlgorithm: "ssh-ed25519", signature: signed))
    }

    func testOnlyHostKeyNegotiationLearnsRSA() {
        let offered = SSHKeyExchangeStateMachine.supportedServerHostKeyAlgorithms
        XCTAssertEqual(Array(offered.suffix(2)), ["rsa-sha2-512", "rsa-sha2-256"])
        XCTAssertFalse(offered.contains("ssh-rsa"))
        XCTAssertFalse(NIOSSHPublicKey.knownAlgorithms.contains { $0.elementsEqual("ssh-rsa".utf8) })
    }
}

private struct DERReader {
    var bytes: Data

    mutating func enterSequence() {
        _ = readHeader()
    }

    mutating func readInteger() -> Data {
        let length = readHeader()
        defer { bytes = Data(bytes.dropFirst(length)) }
        return Data(bytes.prefix(length))
    }

    private mutating func readHeader() -> Int {
        let first = bytes[bytes.startIndex + 1]
        guard first & 0x80 != 0 else {
            bytes = Data(bytes.dropFirst(2))
            return Int(first)
        }
        let count = Int(first & 0x7F)
        let length = bytes.dropFirst(2).prefix(count).reduce(0) { $0 << 8 | Int($1) }
        bytes = Data(bytes.dropFirst(2 + count))
        return length
    }
}
