import Foundation
import Security

enum ASN1 {
    static func encodeLength(_ length: Int) -> Data {
        if length < 0x80 {
            return Data([UInt8(length)])
        }
        var value = length
        var bytes: [UInt8] = []
        while value > 0 {
            bytes.insert(UInt8(value & 0xFF), at: 0)
            value >>= 8
        }
        return Data([UInt8(0x80 | bytes.count)] + bytes)
    }

    static func element(tag: UInt8, content: Data) -> Data {
        var result = Data([tag])
        result.append(encodeLength(content.count))
        result.append(content)
        return result
    }

    static func sequence(_ elements: [Data]) -> Data {
        element(tag: 0x30, content: elements.reduce(Data(), +))
    }

    static func set(_ elements: [Data]) -> Data {
        element(tag: 0x31, content: elements.reduce(Data(), +))
    }

    static func integer(_ value: Data) -> Data {
        element(tag: 0x02, content: value)
    }

    static func objectIdentifier(_ bytes: [UInt8]) -> Data {
        element(tag: 0x06, content: Data(bytes))
    }

    static func utf8String(_ string: String) -> Data {
        element(tag: 0x0C, content: Data(string.utf8))
    }

    static func printableString(_ string: String) -> Data {
        element(tag: 0x13, content: Data(string.utf8))
    }

    static func bitString(_ content: Data) -> Data {
        element(tag: 0x03, content: Data([0x00]) + content)
    }

    static func null() -> Data {
        Data([0x05, 0x00])
    }

    static func contextSpecific(_ tag: UInt8, _ content: Data) -> Data {
        element(tag: 0xA0 | tag, content: content)
    }
}

enum CertificateSigningRequest {
    private static let rsaEncryptionOID: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
    private static let sha256WithRSAOID: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]
    private static let commonNameOID: [UInt8] = [0x55, 0x04, 0x03]
    private static let countryNameOID: [UInt8] = [0x55, 0x04, 0x06]
    private static let emailAddressOID: [UInt8] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x01]

    static func generate(commonName: String, emailAddress: String) -> (pem: String, privateKeyPEM: String)? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            return nil
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            return nil
        }
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            return nil
        }
        guard let privateKeyData = SecKeyCopyExternalRepresentation(privateKey, &error) as Data? else {
            return nil
        }

        let subjectPublicKeyInfo = ASN1.sequence([
            ASN1.sequence([
                ASN1.objectIdentifier(rsaEncryptionOID),
                ASN1.null()
            ]),
            ASN1.bitString(publicKeyData)
        ])

        let subject = ASN1.sequence([
            ASN1.set([
                ASN1.sequence([
                    ASN1.objectIdentifier(countryNameOID),
                    ASN1.printableString("US")
                ])
            ]),
            ASN1.set([
                ASN1.sequence([
                    ASN1.objectIdentifier(commonNameOID),
                    ASN1.utf8String(commonName)
                ])
            ]),
            ASN1.set([
                ASN1.sequence([
                    ASN1.objectIdentifier(emailAddressOID),
                    ASN1.utf8String(emailAddress)
                ])
            ])
        ])

        let certificationRequestInfo = ASN1.sequence([
            ASN1.integer(Data([0x00])),
            subject,
            subjectPublicKeyInfo,
            ASN1.contextSpecific(0, Data())
        ])

        guard let signature = SecKeyCreateSignature(
            privateKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            certificationRequestInfo as CFData,
            &error
        ) as Data? else {
            return nil
        }

        let certificationRequest = ASN1.sequence([
            certificationRequestInfo,
            ASN1.sequence([
                ASN1.objectIdentifier(sha256WithRSAOID),
                ASN1.null()
            ]),
            ASN1.bitString(signature)
        ])

        let csrPEM = pemEncode(certificationRequest, label: "CERTIFICATE REQUEST")
        let keyPEM = pemEncode(privateKeyData, label: "RSA PRIVATE KEY")
        return (csrPEM, keyPEM)
    }

    private static func pemEncode(_ data: Data, label: String) -> String {
        let base64 = data.base64EncodedString()
        var lines: [String] = []
        var index = base64.startIndex
        while index < base64.endIndex {
            let end = base64.index(index, offsetBy: 64, limitedBy: base64.endIndex) ?? base64.endIndex
            lines.append(String(base64[index..<end]))
            index = end
        }
        return "-----BEGIN \(label)-----\n" + lines.joined(separator: "\n") + "\n-----END \(label)-----\n"
    }
}
