import Foundation
import Security
import BigInt

final class SRPClient {
    private let primeModulus: BigUInt
    private let generator: BigUInt
    private let privateExponent: BigUInt
    let clientPublicKey: BigUInt

    private var sessionKeyStorage: Data = Data()

    init() {
        let primeHex =
            "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
            "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
            "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
            "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
            "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
            "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
            "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
            "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"

        self.primeModulus = BigUInt(primeHex, radix: 16)!
        self.generator = BigUInt(2)

        var randomBytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
        self.privateExponent = BigUInt(Data(randomBytes))

        self.clientPublicKey = generator.power(privateExponent, modulus: primeModulus)
    }

    var clientPublicKeyData: Data {
        padded(clientPublicKey)
    }

    var sessionKey: Data {
        sessionKeyStorage
    }

    func computeProof(
        username: String,
        password: String,
        salt: Data,
        serverPublicKey: Data,
        iterations: Int,
        isDoubleHashed: Bool
    ) -> Data? {
        let serverPublic = BigUInt(serverPublicKey)
        if serverPublic % primeModulus == 0 {
            return nil
        }

        let paddedClient = padded(clientPublicKey)
        let paddedServer = leftPad(serverPublicKey, toLength: byteWidth)
        let scramblingParameter = BigUInt(CryptoUtilities.sha256(paddedClient + paddedServer))

        let multiplier = BigUInt(CryptoUtilities.sha256(padded(primeModulus) + padded(generator)))

        let passwordData = Data(password.utf8)
        var innerHash = CryptoUtilities.sha256(passwordData)
        if isDoubleHashed {
            innerHash = Data(innerHash.hexEncodedString().utf8)
        }

        let derivedPassword = CryptoUtilities.pbkdf2SHA256(
            password: innerHash,
            salt: salt,
            iterations: iterations,
            keyLength: 32
        )
        if derivedPassword.isEmpty {
            return nil
        }

        let innerPasswordHash = CryptoUtilities.sha256(Data([0x3A]) + derivedPassword)
        let privateKeyData = CryptoUtilities.sha256(salt + innerPasswordHash)
        let privateKeyX = BigUInt(privateKeyData)

        let generatorToX = generator.power(privateKeyX, modulus: primeModulus)
        let base = (serverPublic + primeModulus - (multiplier * generatorToX) % primeModulus) % primeModulus
        let exponent = privateExponent + scramblingParameter * privateKeyX
        let premaster = base.power(exponent, modulus: primeModulus)

        let sharedSecret = premaster.serialize()
        self.sessionKeyStorage = CryptoUtilities.sha256(sharedSecret)

        let hashN = CryptoUtilities.sha256(padded(primeModulus))
        let hashG = CryptoUtilities.sha256(padded(generator))
        var groupHash = Data(count: hashN.count)
        for index in 0..<hashN.count {
            groupHash[index] = hashN[index] ^ hashG[index]
        }

        let usernameHash = CryptoUtilities.sha256(Data(username.utf8))

        var proofInput = Data()
        proofInput.append(groupHash)
        proofInput.append(usernameHash)
        proofInput.append(salt)
        proofInput.append(clientPublicKey.serialize())
        proofInput.append(serverPublic.serialize())
        proofInput.append(sessionKeyStorage)

        return CryptoUtilities.sha256(proofInput)
    }

    private var byteWidth: Int {
        (primeModulus.bitWidth + 7) / 8
    }

    private func padded(_ value: BigUInt) -> Data {
        leftPad(value.serialize(), toLength: byteWidth)
    }

    private func leftPad(_ data: Data, toLength length: Int) -> Data {
        if data.count >= length {
            return data
        }
        return Data(repeating: 0, count: length - data.count) + data
    }
}

extension Data {
    func hexEncodedString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}
