import Foundation

protocol AnisetteProvider {
    func fetchAnisetteData() async throws -> AnisetteData
}

final class RemoteAnisetteProvider: AnisetteProvider {
    private let baseURL: String
    private let session: URLSession

    init(baseURL: String, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.session = session
    }

    func fetchAnisetteData() async throws -> AnisetteData {
        guard let url = URL(string: baseURL) else {
            throw GrandSlamError.invalidAnisetteResponse
        }

        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw GrandSlamError.invalidAnisetteResponse
        }
        guard httpResponse.statusCode == 200 else {
            throw GrandSlamError.anisetteRequestFailed(httpResponse.statusCode)
        }

        guard let payload = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw GrandSlamError.invalidAnisetteResponse
        }

        func value(_ keys: [String]) -> String {
            for key in keys {
                if let found = payload[key] as? String {
                    return found
                }
            }
            return ""
        }

        let machineIdentifier = value(["X-Apple-I-MD-M", "X-Apple-I-MD-M-Checksum"])
        let oneTimePassword = value(["X-Apple-I-MD"])
        let routingInformation = value(["X-Apple-I-MD-RINFO"])
        let localUserIdentifier = value(["X-Apple-I-MD-LU"])
        let deviceSerialNumber = value(["X-Apple-I-SRL-NO"])
        let deviceUniqueIdentifier = value(["X-Mme-Device-Id", "X-Apple-I-Device-UID"])
        let deviceDescription = value(["X-MMe-Client-Info", "X-Mme-Client-Info", "X-MMe-Client-Info-Checksum"])
        let timeZone = value(["X-Apple-I-TimeZone"])
        let locale = value(["X-Apple-Locale", "X-Apple-I-Locale"])

        let serverClientTime = value(["X-Apple-I-Client-Time"])
        let clientTime = serverClientTime.isEmpty ? ISO8601DateFormatter().string(from: Date()) : serverClientTime

        guard !machineIdentifier.isEmpty, !oneTimePassword.isEmpty else {
            throw GrandSlamError.invalidAnisetteResponse
        }

        return AnisetteData(
            machineIdentifier: machineIdentifier,
            oneTimePassword: oneTimePassword,
            routingInformation: routingInformation,
            localUserIdentifier: localUserIdentifier,
            deviceSerialNumber: deviceSerialNumber.isEmpty ? "0" : deviceSerialNumber,
            deviceUniqueIdentifier: deviceUniqueIdentifier,
            deviceDescription: deviceDescription.isEmpty ? "<MacBookPro15,1> <macOS;13.1;22C65> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>" : deviceDescription,
            clientTime: clientTime,
            timeZone: timeZone.isEmpty ? "GMT" : timeZone,
            locale: locale.isEmpty ? "en_US" : locale
        )
    }
}
