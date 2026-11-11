import Foundation

final class DeveloperServicesClient {
    private let account: AppleAccount
    private let anisetteProvider: AnisetteProvider
    private let session: URLSession

    private let baseURL = "https://developerservices2.apple.com/services/QH65B2"
    private let clientIdentifier = "XABBG36SBA"
    private let protocolVersion = "QH65B2"

    init(account: AppleAccount, anisetteProvider: AnisetteProvider, session: URLSession = .shared) {
        self.account = account
        self.anisetteProvider = anisetteProvider
        self.session = session
    }

    func fetchTeams() async throws -> [DeveloperTeam] {
        let response = try await perform(action: "listTeams.action", body: [:])
        guard let teams = response["teams"] as? [[String: Any]] else {
            throw DeveloperServicesError.noTeamsFound
        }
        let parsed = teams.compactMap { entry -> DeveloperTeam? in
            guard let identifier = entry["teamId"] as? String else {
                return nil
            }
            let name = entry["name"] as? String ?? identifier
            let status = entry["status"] as? String ?? "active"
            return DeveloperTeam(id: identifier, name: name, status: status)
        }
        if parsed.isEmpty {
            throw DeveloperServicesError.noTeamsFound
        }
        return parsed
    }

    func obtainCertificate(teamId: String) async throws -> SigningCertificate {
        guard let generated = CertificateSigningRequest.generate(
            commonName: account.identifier,
            emailAddress: account.identifier
        ) else {
            throw DeveloperServicesError.certificateGenerationFailed
        }

        let body: [String: Any] = [
            "csrContent": generated.pem,
            "machineId": machineIdentifier(),
            "machineName": "SleepStore",
            "teamId": teamId
        ]

        let response = try await perform(action: "ios/submitDevelopmentCSR.action", body: body)

        guard let certificateRequest = response["certRequest"] as? [String: Any] else {
            throw DeveloperServicesError.missingCertificateContent
        }

        let serialNumber = certificateRequest["serialNumber"] as? String ?? ""
        let certificateData = extractCertificateData(certificateRequest)

        return SigningCertificate(
            serialNumber: serialNumber,
            certificateData: certificateData,
            privateKeyPEM: generated.privateKeyPEM
        )
    }

    func registerDevice(teamId: String, deviceIdentifier: String, name: String) async throws -> String {
        let body: [String: Any] = [
            "teamId": teamId,
            "deviceNumber": deviceIdentifier,
            "name": name
        ]
        do {
            let response = try await perform(action: "ios/addDevice.action", body: body)
            if let device = response["device"] as? [String: Any], let identifier = device["deviceId"] as? String {
                return identifier
            }
            return ""
        } catch DeveloperServicesError.apiError(let code, let message) {
            if message.lowercased().contains("already") || code == 35 {
                return ""
            }
            throw DeveloperServicesError.deviceRegistrationFailed(message: message)
        }
    }

    func listDevelopmentCertificates(teamId: String) async throws -> [SigningCertificate] {
        let response = try await perform(action: "ios/listAllDevelopmentCerts.action", body: ["teamId": teamId])
        guard let certificates = response["certificates"] as? [[String: Any]] else {
            return []
        }
        return certificates.compactMap { entry in
            guard let serialNumber = entry["serialNumber"] as? String else {
                return nil
            }
            let data = extractCertificateData(entry)
            return SigningCertificate(serialNumber: serialNumber, certificateData: data, privateKeyPEM: "")
        }
    }

    private func extractCertificateData(_ entry: [String: Any]) -> Data {
        for key in ["certContent", "certificate", "certificateContent"] {
            if let data = entry[key] as? Data {
                return data
            }
            if let string = entry[key] as? String, let decoded = Data(base64Encoded: string) {
                return decoded
            }
        }
        return Data()
    }

    private func perform(action: String, body: [String: Any]) async throws -> [String: Any] {
        let anisette = try await anisetteProvider.fetchAnisetteData()

        guard let url = URL(string: "\(baseURL)/\(action)?clientId=\(clientIdentifier)") else {
            throw DeveloperServicesError.malformedResponse
        }

        var payload: [String: Any] = body
        payload["clientId"] = clientIdentifier
        payload["protocolVersion"] = protocolVersion
        payload["requestId"] = UUID().uuidString.uppercased()
        payload["userLocale"] = [anisette.locale]

        let encoded = try PropertyListSerialization.data(fromPropertyList: payload, format: .xml, options: 0)

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = encoded
        applyHeaders(to: &request, anisette: anisette)

        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw DeveloperServicesError.malformedResponse
        }
        guard httpResponse.statusCode == 200 else {
            throw DeveloperServicesError.requestFailed(httpResponse.statusCode)
        }

        guard let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            throw DeveloperServicesError.malformedResponse
        }

        if let resultCode = integerValue(plist["resultCode"]), resultCode != 0 {
            let message = plist["userString"] as? String ?? plist["resultString"] as? String ?? "Unknown error"
            throw DeveloperServicesError.apiError(code: resultCode, message: message)
        }

        return plist
    }

    private func applyHeaders(to request: inout URLRequest, anisette: AnisetteData) {
        request.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
        request.setValue("text/x-xml-plist", forHTTPHeaderField: "Accept")
        request.setValue("en-us", forHTTPHeaderField: "Accept-Language")
        request.setValue("Xcode", forHTTPHeaderField: "User-Agent")
        request.setValue("com.apple.gs.xcode.auth", forHTTPHeaderField: "X-Apple-App-Info")
        request.setValue("11.2 (11B41)", forHTTPHeaderField: "X-Xcode-Version")
        request.setValue(account.accountDirectoryServicesIdentifier, forHTTPHeaderField: "X-Apple-I-Identity-Id")
        request.setValue(account.grandSlamToken, forHTTPHeaderField: "X-Apple-GS-Token")
        request.setValue(anisette.oneTimePassword, forHTTPHeaderField: "X-Apple-I-MD")
        request.setValue(anisette.machineIdentifier, forHTTPHeaderField: "X-Apple-I-MD-M")
        request.setValue(anisette.routingInformation, forHTTPHeaderField: "X-Apple-I-MD-RINFO")
        request.setValue(anisette.localUserIdentifier, forHTTPHeaderField: "X-Apple-I-MD-LU")
        request.setValue(anisette.clientTime, forHTTPHeaderField: "X-Apple-I-Client-Time")
        request.setValue(anisette.timeZone, forHTTPHeaderField: "X-Apple-I-TimeZone")
        request.setValue(anisette.deviceSerialNumber, forHTTPHeaderField: "X-Apple-I-SRL-NO")
        request.setValue(anisette.deviceUniqueIdentifier, forHTTPHeaderField: "X-Mme-Device-Id")
    }

    private func machineIdentifier() -> String {
        let key = "SleepStoreMachineIdentifier"
        if let stored = UserDefaults.standard.string(forKey: key) {
            return stored
        }
        let generated = UUID().uuidString.uppercased()
        UserDefaults.standard.set(generated, forKey: key)
        return generated
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
