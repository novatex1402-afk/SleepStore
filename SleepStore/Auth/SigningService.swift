import Foundation

enum SigningServiceError: Error {
    case cannotReadBundleIdentifier
    case signingFailed(String)

    var readableMessage: String {
        switch self {
        case .cannotReadBundleIdentifier:
            return "Could not read the bundle identifier from the selected IPA."
        case .signingFailed(let message):
            return message
        }
    }
}

enum SigningService {
    static func bundleIdentifier(ofIPA url: URL) throws -> String {
        guard let identifier = ZSigner.bundleIdentifier(ofIPA: url.path) else {
            throw SigningServiceError.cannotReadBundleIdentifier
        }
        return identifier
    }

    static func sign(
        ipaURL: URL,
        certificate: SigningCertificate,
        profile: ProvisioningProfile
    ) throws -> URL {
        let workingDirectory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: workingDirectory, withIntermediateDirectories: true)

        let certificatePath = workingDirectory.appendingPathComponent("certificate.pem")
        let privateKeyPath = workingDirectory.appendingPathComponent("private-key.pem")
        let provisioningPath = workingDirectory.appendingPathComponent("profile.mobileprovision")
        let outputPath = workingDirectory.appendingPathComponent("Signed.ipa")

        try pemEncodedCertificate(from: certificate.certificateData).write(to: certificatePath, atomically: true, encoding: .utf8)
        try certificate.privateKeyPEM.write(to: privateKeyPath, atomically: true, encoding: .utf8)
        try profile.data.write(to: provisioningPath)

        var errorMessage: NSString?
        let success = ZSigner.signInputIPA(
            ipaURL.path,
            outputIPA: outputPath.path,
            certificate: certificatePath.path,
            privateKey: privateKeyPath.path,
            provisioning: provisioningPath.path,
            error: &errorMessage
        )

        if !success {
            throw SigningServiceError.signingFailed(errorMessage as String? ?? "Signing failed.")
        }
        return outputPath
    }

    private static func pemEncodedCertificate(from derData: Data) -> String {
        let base64 = derData.base64EncodedString()
        var lines: [String] = []
        var index = base64.startIndex
        while index < base64.endIndex {
            let end = base64.index(index, offsetBy: 64, limitedBy: base64.endIndex) ?? base64.endIndex
            lines.append(String(base64[index..<end]))
            index = end
        }
        return "-----BEGIN CERTIFICATE-----\n" + lines.joined(separator: "\n") + "\n-----END CERTIFICATE-----\n"
    }
}
