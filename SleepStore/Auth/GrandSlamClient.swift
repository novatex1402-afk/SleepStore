import Foundation

final class GrandSlamClient {
    private let anisetteProvider: AnisetteProvider
    private let session: URLSession

    private let serviceURL = URL(string: "https://gsa.apple.com/grandslam/GsService2")!
    private let validateURL = URL(string: "https://gsa.apple.com/grandslam/GsService2/validate")!
    private let trustedDeviceURL = URL(string: "https://gsa.apple.com/auth/verify/trusteddevice")!

    private var cachedAnisette: AnisetteData?
    private var accountDirectoryServicesIdentifier: String = ""
    private var identityManagementToken: String = ""

    init(anisetteProvider: AnisetteProvider, session: URLSession = .shared) {
        self.anisetteProvider = anisetteProvider
        self.session = session
    }

    func authenticate(appleIdentifier: String, password: String) async throws -> AuthenticationResult {
        let anisette = try await resolveAnisette()
        let srp = SRPClient()

        let initResponse = try await sendInitialRequest(
            appleIdentifier: appleIdentifier,
            clientPublicKey: srp.clientPublicKeyData,
            anisette: anisette
        )

        try throwIfRejected(initResponse)

        guard
            let salt = dataValue(initResponse["s"]),
            let serverPublicKey = dataValue(initResponse["B"]),
            let cookie = initResponse["c"] as? String,
            let iterations = integerValue(initResponse["i"]),
            let selectedProtocol = initResponse["sp"] as? String
        else {
            let keys = initResponse.keys.sorted().joined(separator: ", ")
            throw GrandSlamError.malformedServerResponse("init keys [\(keys)]")
        }

        let isDoubleHashed = selectedProtocol == "s2k_fo"

        guard let proof = srp.computeProof(
            username: appleIdentifier,
            password: password,
            salt: salt,
            serverPublicKey: serverPublicKey,
            iterations: iterations,
            isDoubleHashed: isDoubleHashed
        ) else {
            throw GrandSlamError.sessionKeyDerivationFailed
        }

        let completeResponse = try await sendCompletionRequest(
            appleIdentifier: appleIdentifier,
            proof: proof,
            cookie: cookie,
            anisette: anisette
        )

        try throwIfRejected(completeResponse)

        guard let encryptedSessionData = dataValue(completeResponse["spd"]) else {
            throw GrandSlamError.missingSessionData
        }

        guard let decrypted = decryptSessionData(encryptedSessionData, sessionKey: srp.sessionKey) else {
            throw GrandSlamError.sessionKeyDerivationFailed
        }

        self.accountDirectoryServicesIdentifier = decrypted["adsid"] as? String ?? ""
        self.identityManagementToken = decrypted["GsIdMS"] as? String ?? (decrypted["idmsToken"] as? String ?? "")

        if let status = completeResponse["Status"] as? [String: Any],
           let secondaryAuthentication = status["au"] as? String,
           secondaryAuthentication == "trustedDeviceSecondaryAuth" || secondaryAuthentication == "secondaryAuth" {
            try await requestTwoFactorCode(anisette: anisette)
            return .needsTwoFactor
        }

        let identityToken = makeIdentityToken()
        let grandSlamToken = Data(identityManagementToken.utf8).base64EncodedString()
        let account = AppleAccount(
            identifier: appleIdentifier,
            accountDirectoryServicesIdentifier: accountDirectoryServicesIdentifier,
            identityToken: identityToken,
            grandSlamToken: grandSlamToken,
            fullName: decrypted["fn"] as? String ?? decrypted["acname"] as? String
        )
        return .success(account)
    }

    func submitTwoFactorCode(_ code: String) async throws {
        let anisette = try await resolveAnisette()
        var request = URLRequest(url: validateURL)
        request.httpMethod = "GET"
        applyTwoFactorHeaders(to: &request, anisette: anisette)
        request.setValue(code, forHTTPHeaderField: "security-code")

        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw GrandSlamError.twoFactorRequestFailed(-1)
        }
        guard httpResponse.statusCode == 200 else {
            throw GrandSlamError.twoFactorRequestFailed(httpResponse.statusCode)
        }

        if let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
           let status = plist["Status"] as? [String: Any],
           let errorCode = integerValue(status["ec"]), errorCode != 0 {
            let message = status["em"] as? String ?? "Unknown error"
            throw GrandSlamError.twoFactorRejected(message: message)
        }
    }

    private func requestTwoFactorCode(anisette: AnisetteData) async throws {
        var request = URLRequest(url: trustedDeviceURL)
        request.httpMethod = "GET"
        applyTwoFactorHeaders(to: &request, anisette: anisette)
        _ = try? await session.data(for: request)
    }

    private func sendInitialRequest(
        appleIdentifier: String,
        clientPublicKey: Data,
        anisette: AnisetteData
    ) async throws -> [String: Any] {
        let body: [String: Any] = [
            "A2k": clientPublicKey,
            "cpd": clientProvidedData(appleIdentifier: appleIdentifier, anisette: anisette),
            "o": "init",
            "ps": ["s2k", "s2k_fo"],
            "u": appleIdentifier
        ]
        return try await performServiceRequest(body: body, anisette: anisette)
    }

    private func sendCompletionRequest(
        appleIdentifier: String,
        proof: Data,
        cookie: String,
        anisette: AnisetteData
    ) async throws -> [String: Any] {
        let body: [String: Any] = [
            "c": cookie,
            "cpd": clientProvidedData(appleIdentifier: appleIdentifier, anisette: anisette),
            "M1": proof,
            "o": "complete",
            "u": appleIdentifier
        ]
        return try await performServiceRequest(body: body, anisette: anisette)
    }

    private func performServiceRequest(body: [String: Any], anisette: AnisetteData) async throws -> [String: Any] {
        let payload: [String: Any] = [
            "Header": ["Version": "1.0.1"],
            "Request": body
        ]
        let encoded = try PropertyListSerialization.data(fromPropertyList: payload, format: .xml, options: 0)

        var request = URLRequest(url: serviceURL)
        request.httpMethod = "POST"
        request.httpBody = encoded
        request.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
        request.setValue("*/*", forHTTPHeaderField: "Accept")
        request.setValue(anisette.deviceDescription, forHTTPHeaderField: "X-MMe-Client-Info")
        request.setValue("akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0", forHTTPHeaderField: "User-Agent")

        let (data, response) = try await session.data(for: request)
        let statusCode = (response as? HTTPURLResponse)?.statusCode ?? -1

        guard let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            let snippet = String(data: data.prefix(240), encoding: .utf8) ?? "non-text body (\(data.count) bytes)"
            throw GrandSlamError.malformedServerResponse("HTTP \(statusCode): \(snippet)")
        }

        if let responseBody = plist["Response"] as? [String: Any] {
            return responseBody
        }
        if plist["Status"] != nil || plist["spd"] != nil || plist["sp"] != nil {
            return plist
        }

        let keys = plist.keys.sorted().joined(separator: ", ")
        throw GrandSlamError.malformedServerResponse("HTTP \(statusCode): keys [\(keys)]")
    }

    private func clientProvidedData(appleIdentifier: String, anisette: AnisetteData) -> [String: Any] {
        return [
            "AppleIDClientIdentifier": appleIdentifier,
            "X-Apple-I-Client-Time": anisette.clientTime,
            "X-Apple-I-TimeZone": anisette.timeZone,
            "X-Apple-Locale": anisette.locale,
            "X-Apple-I-MD": anisette.oneTimePassword,
            "X-Apple-I-MD-M": anisette.machineIdentifier,
            "X-Apple-I-MD-RINFO": anisette.routingInformation,
            "X-Apple-I-MD-LU": anisette.localUserIdentifier,
            "X-Apple-I-SRL-NO": anisette.deviceSerialNumber,
            "X-Mme-Device-Id": anisette.deviceUniqueIdentifier,
            "bootstrap": true,
            "icscrec": true,
            "pbe": false,
            "prkgen": true,
            "svct": "iCloud",
            "capp": "AppleAccount",
            "dc": "#d4",
            "loc": anisette.locale
        ]
    }

    private func applyTwoFactorHeaders(to request: inout URLRequest, anisette: AnisetteData) {
        request.setValue("application/x-buddyml", forHTTPHeaderField: "Accept")
        request.setValue("application/x-plist", forHTTPHeaderField: "Content-Type")
        request.setValue("Xcode", forHTTPHeaderField: "User-Agent")
        request.setValue(makeIdentityToken(), forHTTPHeaderField: "X-Apple-Identity-Token")
        request.setValue("com.apple.gs.xcode.auth", forHTTPHeaderField: "X-Apple-App-Info")
        request.setValue("11.2 (11B41)", forHTTPHeaderField: "X-Xcode-Version")
        request.setValue(anisette.oneTimePassword, forHTTPHeaderField: "X-Apple-I-MD")
        request.setValue(anisette.machineIdentifier, forHTTPHeaderField: "X-Apple-I-MD-M")
        request.setValue(anisette.routingInformation, forHTTPHeaderField: "X-Apple-I-MD-RINFO")
        request.setValue(anisette.localUserIdentifier, forHTTPHeaderField: "X-Apple-I-MD-LU")
        request.setValue(anisette.clientTime, forHTTPHeaderField: "X-Apple-I-Client-Time")
        request.setValue(anisette.timeZone, forHTTPHeaderField: "X-Apple-I-TimeZone")
        request.setValue(anisette.deviceSerialNumber, forHTTPHeaderField: "X-Apple-I-SRL-NO")
        request.setValue(anisette.deviceUniqueIdentifier, forHTTPHeaderField: "X-Mme-Device-Id")
    }

    private func makeIdentityToken() -> String {
        let combined = "\(accountDirectoryServicesIdentifier):\(identityManagementToken)"
        return Data(combined.utf8).base64EncodedString()
    }

    private func decryptSessionData(_ encrypted: Data, sessionKey: Data) -> [String: Any]? {
        let keyMaterial = CryptoUtilities.hmacSHA256(key: sessionKey, message: Data("extra data key:".utf8))
        let ivMaterial = CryptoUtilities.hmacSHA256(key: sessionKey, message: Data("extra data iv:".utf8))
        let initializationVector = ivMaterial.prefix(16)

        guard var decrypted = CryptoUtilities.aesCBCDecrypt(
            key: keyMaterial,
            initializationVector: Data(initializationVector),
            cipherText: encrypted
        ) else {
            return nil
        }

        if let paddingLength = decrypted.last, paddingLength > 0, Int(paddingLength) <= decrypted.count {
            decrypted.removeLast(Int(paddingLength))
        }

        return try? PropertyListSerialization.propertyList(from: decrypted, options: [], format: nil) as? [String: Any]
    }

    private func resolveAnisette() async throws -> AnisetteData {
        if let cached = cachedAnisette {
            return cached
        }
        let fresh = try await anisetteProvider.fetchAnisetteData()
        cachedAnisette = fresh
        return fresh
    }

    private func throwIfRejected(_ response: [String: Any]) throws {
        guard let status = response["Status"] as? [String: Any] else {
            return
        }
        guard let errorCode = integerValue(status["ec"]) else {
            return
        }
        if errorCode != 0 {
            let message = status["em"] as? String ?? "Authentication was rejected."
            throw GrandSlamError.authenticationRejected(code: errorCode, message: message)
        }
    }

    private func dataValue(_ value: Any?) -> Data? {
        if let data = value as? Data {
            return data
        }
        if let string = value as? String {
            return Data(base64Encoded: string)
        }
        return nil
    }

    private func integerValue(_ value: Any?) -> Int? {
        if let number = value as? Int {
            return number
        }
        if let number = value as? NSNumber {
            return number.intValue
        }
        if let string = value as? String {
            return Int(string)
        }
        return nil
    }
}
