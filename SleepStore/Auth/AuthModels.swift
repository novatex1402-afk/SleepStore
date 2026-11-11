import Foundation

struct AppleAccount: Equatable {
    let identifier: String
    let accountDirectoryServicesIdentifier: String
    let identityToken: String
    let grandSlamToken: String
    let fullName: String?
}

enum AuthenticationResult {
    case success(AppleAccount)
    case needsTwoFactor
}

enum GrandSlamError: Error {
    case invalidAnisetteResponse
    case anisetteRequestFailed(Int)
    case malformedServerResponse
    case authenticationRejected(code: Int, message: String)
    case missingSessionData
    case sessionKeyDerivationFailed
    case twoFactorRequestFailed(Int)
    case twoFactorRejected(message: String)

    var readableMessage: String {
        switch self {
        case .invalidAnisetteResponse:
            return "Could not read anisette data from the server."
        case .anisetteRequestFailed(let status):
            return "Anisette server returned status \(status)."
        case .malformedServerResponse:
            return "Apple returned an unexpected response."
        case .authenticationRejected(let code, let message):
            return "Sign in failed (\(code)): \(message)"
        case .missingSessionData:
            return "Apple did not return session data."
        case .sessionKeyDerivationFailed:
            return "Could not decrypt the session. Check the password and anisette server."
        case .twoFactorRequestFailed(let status):
            return "Two factor request failed with status \(status)."
        case .twoFactorRejected(let message):
            return "Verification failed: \(message)"
        }
    }
}

struct AnisetteData {
    let machineIdentifier: String
    let oneTimePassword: String
    let routingInformation: String
    let localUserIdentifier: String
    let deviceSerialNumber: String
    let deviceUniqueIdentifier: String
    let deviceDescription: String
    let clientTime: String
    let timeZone: String
    let locale: String
}
