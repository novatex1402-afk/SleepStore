import Foundation
import Security

struct DeveloperTeam: Identifiable, Equatable {
    let id: String
    let name: String
    let status: String
}

struct SigningCertificate: Equatable {
    let serialNumber: String
    let certificateData: Data
    let privateKeyPEM: String

    static func == (lhs: SigningCertificate, rhs: SigningCertificate) -> Bool {
        lhs.serialNumber == rhs.serialNumber && lhs.certificateData == rhs.certificateData
    }
}

struct ProvisioningProfile: Equatable {
    let name: String
    let data: Data
}

enum DeveloperServicesError: Error {
    case notAuthenticated
    case requestFailed(Int)
    case malformedResponse
    case apiError(code: Int, message: String)
    case noTeamsFound
    case certificateGenerationFailed
    case missingCertificateContent
    case deviceRegistrationFailed(message: String)
    case profileDownloadFailed(message: String)

    var readableMessage: String {
        switch self {
        case .notAuthenticated:
            return "Sign in with your Apple ID first."
        case .requestFailed(let status):
            return "Developer services returned status \(status)."
        case .malformedResponse:
            return "Developer services returned an unexpected response."
        case .apiError(let code, let message):
            return "Developer services error (\(code)): \(message)"
        case .noTeamsFound:
            return "No development team is associated with this Apple ID."
        case .certificateGenerationFailed:
            return "Could not generate the signing request on this device."
        case .missingCertificateContent:
            return "Apple did not return a certificate."
        case .deviceRegistrationFailed(let message):
            return "Device registration failed: \(message)"
        case .profileDownloadFailed(let message):
            return "Provisioning profile download failed: \(message)"
        }
    }
}
