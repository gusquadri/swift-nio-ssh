// Added for AeroOps. Licensed under Apache License 2.0, like the rest of this package.

import Foundation
import NIOCore
import Security

/// An RSA host key, which can only verify a server's signature over the key exchange.
///
/// Nothing here signs, and SHA-1 `ssh-rsa` signatures are never accepted. The key stays out of
/// ``NIOSSHPublicKey/knownAlgorithms``, so user authentication does not accept it, and verifying
/// anything but a key exchange fails, so it cannot be a certificate authority either.
struct RSAHostKey: Hashable, Sendable {
    static let keyPrefix = "ssh-rsa".utf8
    private static let modulusBits = 2048...16384
    private static let largestExponentBytes = 8

    /// The bodies of the two SSH mpints, unchanged, so fingerprints and pins match what ssh sees.
    let exponent: Data
    let modulus: Data

    /// Fails for anything but canonical positive mpints, an odd exponent above 1 that fits 64 bits,
    /// and a modulus of 2048 to 16384 bits.
    init(exponent: Data, modulus: Data) throws {
        guard let exponentBytes = Self.magnitude(ofMPInt: exponent), let modulusBytes = Self.magnitude(ofMPInt: modulus)
        else {
            throw NIOSSHError.invalidOpenSSHPublicKey(reason: "RSA key is not canonically encoded")
        }
        guard Self.modulusBits.contains(Self.bitCount(modulusBytes)) else {
            throw NIOSSHError.invalidOpenSSHPublicKey(reason: "RSA modulus must be 2048 to 16384 bits")
        }
        guard Self.isUsableExponent(exponentBytes) else {
            throw NIOSSHError.invalidOpenSSHPublicKey(reason: "RSA public exponent is not usable")
        }
        self.exponent = exponent
        self.modulus = modulus
    }

    /// The Security framework checks the padding, the hash and the signature's length.
    func isValidSignature(_ signature: RSAHostSignature, for message: Data) -> Bool {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPublic,
        ]
        guard let key = SecKeyCreateWithData(pkcs1DER as CFData, attributes as CFDictionary, nil) else {
            return false
        }
        return SecKeyVerifySignature(key, signature.algorithm.securityAlgorithm, message as CFData, signature.bytes as CFData, nil)
    }

    /// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`. A canonical SSH
    /// mpint body is already a valid DER INTEGER body.
    private var pkcs1DER: Data {
        Self.der(tag: 0x30, body: Self.der(tag: 0x02, body: modulus) + Self.der(tag: 0x02, body: exponent))
    }

    private static func der(tag: UInt8, body: Data) -> Data {
        var length = withUnsafeBytes(of: UInt32(body.count).bigEndian) { Data($0) }
        length = length.drop { $0 == 0 }
        let header = body.count < 0x80 ? Data([UInt8(body.count)]) : Data([0x80 | UInt8(length.count)]) + length
        return Data([tag]) + header + body
    }

    /// The value's bytes without the sign byte, or nil for an empty, negative or padded mpint.
    private static func magnitude(ofMPInt bytes: Data) -> Data? {
        guard let first = bytes.first, first & 0x80 == 0 else { return nil }
        guard first == 0 else { return bytes }
        guard let second = bytes.dropFirst().first, second & 0x80 != 0 else { return nil }
        return bytes.dropFirst()
    }

    private static func bitCount(_ magnitude: Data) -> Int {
        guard let first = magnitude.first else { return 0 }
        return (magnitude.count - 1) * 8 + (UInt8.bitWidth - first.leadingZeroBitCount)
    }

    private static func isUsableExponent(_ magnitude: Data) -> Bool {
        guard magnitude.count <= largestExponentBytes, let last = magnitude.last, last & 1 == 1 else { return false }
        return bitCount(magnitude) > 1
    }
}

/// An `rsa-sha2-256` or `rsa-sha2-512` signature.
struct RSAHostSignature: Hashable, Sendable {
    enum Algorithm: CaseIterable, Sendable {
        case sha512, sha256

        var name: String.UTF8View {
            switch self {
            case .sha512: return "rsa-sha2-512".utf8
            case .sha256: return "rsa-sha2-256".utf8
            }
        }

        var securityAlgorithm: SecKeyAlgorithm {
            switch self {
            case .sha512: return .rsaSignatureMessagePKCS1v15SHA512
            case .sha256: return .rsaSignatureMessagePKCS1v15SHA256
            }
        }

        init?<Bytes: Collection>(name: Bytes) where Bytes.Element == UInt8 {
            guard let match = Self.allCases.first(where: { $0.name.elementsEqual(name) }) else { return nil }
            self = match
        }
    }

    let algorithm: Algorithm
    let bytes: Data
}

extension NIOSSHPublicKey {
    /// Whether this key, with `signature`, is what negotiating `algorithm` promised. An RSA key is
    /// always named `ssh-rsa`, so for it the signature carries the negotiated name; a server cannot
    /// agree to one hash and sign with another.
    func fits(hostKeyAlgorithm algorithm: Substring, signature: NIOSSHSignature) -> Bool {
        guard case .rsa = backingKey else { return keyPrefix.elementsEqual(algorithm.utf8) }
        guard case .rsa(let rsaSignature) = signature.backingSignature else { return false }
        return rsaSignature.algorithm.name.elementsEqual(algorithm.utf8)
    }
}

extension ByteBuffer {
    /// `mpint e`, then `mpint n`. Not safe outside a rewinding caller, like the other key readers.
    mutating func readRSAPublicKey() throws -> NIOSSHPublicKey? {
        guard let exponent = readSSHString(), let modulus = readSSHString() else { return nil }
        let key = try RSAHostKey(exponent: Data(exponent.readableBytesView), modulus: Data(modulus.readableBytesView))
        return NIOSSHPublicKey(backingKey: .rsa(key))
    }

    mutating func writeRSAPublicKey(_ key: RSAHostKey) -> Int {
        writeSSHString(key.exponent) + writeSSHString(key.modulus)
    }

    /// `string signature`. Not safe outside a rewinding caller, like the other signature readers.
    mutating func readRSASignature(_ algorithm: RSAHostSignature.Algorithm) -> NIOSSHSignature? {
        guard let bytes = readSSHString() else { return nil }
        let signature = RSAHostSignature(algorithm: algorithm, bytes: Data(bytes.readableBytesView))
        return NIOSSHSignature(backingSignature: .rsa(signature))
    }

    mutating func writeRSASignature(_ signature: RSAHostSignature) -> Int {
        writeSSHString(signature.algorithm.name) + writeSSHString(signature.bytes)
    }
}
