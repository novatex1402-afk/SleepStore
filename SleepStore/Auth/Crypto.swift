import Foundation
import CryptoKit
import CommonCrypto

enum CryptoUtilities {
    static func sha256(_ data: Data) -> Data {
        Data(SHA256.hash(data: data))
    }

    static func hmacSHA256(key: Data, message: Data) -> Data {
        let symmetricKey = SymmetricKey(data: key)
        let authentication = HMAC<SHA256>.authenticationCode(for: message, using: symmetricKey)
        return Data(authentication)
    }

    static func pbkdf2SHA256(password: Data, salt: Data, iterations: Int, keyLength: Int) -> Data {
        var derived = Data(repeating: 0, count: keyLength)
        let status = derived.withUnsafeMutableBytes { derivedBytes -> Int32 in
            salt.withUnsafeBytes { saltBytes -> Int32 in
                password.withUnsafeBytes { passwordBytes -> Int32 in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.baseAddress?.assumingMemoryBound(to: Int8.self),
                        password.count,
                        saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        derivedBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        keyLength
                    )
                }
            }
        }
        guard status == kCCSuccess else {
            return Data()
        }
        return derived
    }

    static func aesCBCDecrypt(key: Data, initializationVector: Data, cipherText: Data) -> Data? {
        let bufferSize = cipherText.count + kCCBlockSizeAES128
        var output = Data(repeating: 0, count: bufferSize)
        var decryptedCount = 0

        let status = output.withUnsafeMutableBytes { outputBytes -> Int32 in
            cipherText.withUnsafeBytes { cipherBytes -> Int32 in
                initializationVector.withUnsafeBytes { ivBytes -> Int32 in
                    key.withUnsafeBytes { keyBytes -> Int32 in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(0),
                            keyBytes.baseAddress,
                            key.count,
                            ivBytes.baseAddress,
                            cipherBytes.baseAddress,
                            cipherText.count,
                            outputBytes.baseAddress,
                            bufferSize,
                            &decryptedCount
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            return nil
        }
        output.removeSubrange(decryptedCount..<output.count)
        return output
    }
}
