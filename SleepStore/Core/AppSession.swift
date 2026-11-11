import Foundation
import Combine

enum AuthStage: Equatable {
    case onboarding
    case signIn
    case twoFactor
    case authenticated
}

@MainActor
final class AppSession: ObservableObject {
    @Published var stage: AuthStage = .onboarding
    @Published var appleIdentifier: String = ""
    @Published var isWorking: Bool = false
    @Published var errorMessage: String?
    @Published var account: AppleAccount?

    @Published var isProvisioning: Bool = false
    @Published var provisioningError: String?
    @Published var team: DeveloperTeam?
    @Published var certificate: SigningCertificate?

    @Published var deviceIdentifier: String = ""
    @Published var isRegisteringDevice: Bool = false
    @Published var deviceRegistered: Bool = false

    @Published var isSigning: Bool = false
    @Published var signingStatus: String = ""
    @Published var signingError: String?
    @Published var signedIPAURL: URL?

    @Published var anisetteBaseURL: String = "https://new.ani.sidestore.io"
    @Published var clientInfo: String = ""

    private var pendingPassword: String = ""
    private var grandSlam: GrandSlamClient?

    func beginOnboarding() {
        stage = .signIn
    }

    func signIn(appleIdentifier: String, password: String) async {
        errorMessage = nil
        isWorking = true
        defer { isWorking = false }

        self.appleIdentifier = appleIdentifier
        self.pendingPassword = password

        let anisette = RemoteAnisetteProvider(baseURL: anisetteBaseURL)
        let client = GrandSlamClient(anisetteProvider: anisette, clientInfo: clientInfo)
        self.grandSlam = client

        do {
            let result = try await client.authenticate(appleIdentifier: appleIdentifier, password: password)
            switch result {
            case .success(let account):
                self.account = account
                self.pendingPassword = ""
                self.stage = .authenticated
            case .needsTwoFactor:
                self.stage = .twoFactor
            }
        } catch {
            self.errorMessage = describe(error)
        }
    }

    func submitTwoFactorCode(_ code: String) async {
        errorMessage = nil
        isWorking = true
        defer { isWorking = false }

        guard let client = grandSlam else {
            errorMessage = "Session expired. Sign in again."
            stage = .signIn
            return
        }

        do {
            try await client.submitTwoFactorCode(code)
            let result = try await client.authenticate(appleIdentifier: appleIdentifier, password: pendingPassword)
            switch result {
            case .success(let account):
                self.account = account
                self.pendingPassword = ""
                self.stage = .authenticated
            case .needsTwoFactor:
                self.errorMessage = "Verification failed. Enter the code again."
            }
        } catch {
            self.errorMessage = describe(error)
        }
    }

    func fetchCertificate() async {
        guard let client = makeDeveloperServicesClient() else {
            provisioningError = "Sign in with your Apple ID first."
            return
        }

        provisioningError = nil
        isProvisioning = true
        defer { isProvisioning = false }

        do {
            let selectedTeam = try await resolveTeam(using: client)
            let obtained = try await client.obtainCertificate(teamId: selectedTeam.id)
            self.certificate = obtained
        } catch {
            provisioningError = describeProvisioning(error)
        }
    }

    func registerDevice() async {
        guard let client = makeDeveloperServicesClient() else {
            provisioningError = "Sign in with your Apple ID first."
            return
        }

        let trimmed = deviceIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.count >= 24 else {
            provisioningError = "Enter a valid device UDID."
            return
        }

        provisioningError = nil
        isRegisteringDevice = true
        defer { isRegisteringDevice = false }

        do {
            let selectedTeam = try await resolveTeam(using: client)
            _ = try await client.registerDevice(
                teamId: selectedTeam.id,
                deviceIdentifier: trimmed,
                name: "SleepStore Device"
            )
            self.deviceRegistered = true
        } catch {
            provisioningError = describeProvisioning(error)
        }
    }

    func signIPA(at pickedURL: URL) async {
        guard let certificate = certificate, !certificate.privateKeyPEM.isEmpty else {
            signingError = "Fetch a signing certificate first."
            return
        }
        guard let client = makeDeveloperServicesClient() else {
            signingError = "Sign in with your Apple ID first."
            return
        }

        signingError = nil
        signedIPAURL = nil
        isSigning = true
        signingStatus = "Preparing"
        defer { isSigning = false }

        let needsScopedAccess = pickedURL.startAccessingSecurityScopedResource()
        defer {
            if needsScopedAccess {
                pickedURL.stopAccessingSecurityScopedResource()
            }
        }

        do {
            let workingCopy = FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString, isDirectory: true)
                .appendingPathComponent(pickedURL.lastPathComponent)
            try FileManager.default.createDirectory(
                at: workingCopy.deletingLastPathComponent(),
                withIntermediateDirectories: true
            )
            try FileManager.default.copyItem(at: pickedURL, to: workingCopy)

            signingStatus = "Reading bundle identifier"
            let bundleIdentifier = try SigningService.bundleIdentifier(ofIPA: workingCopy)

            let selectedTeam = try await resolveTeam(using: client)

            signingStatus = "Registering App ID"
            let appIdId = try await client.ensureAppIdentifier(
                teamId: selectedTeam.id,
                bundleIdentifier: bundleIdentifier,
                name: "SleepStore \(bundleIdentifier)"
            )

            signingStatus = "Downloading provisioning profile"
            let profile = try await client.downloadProvisioningProfile(teamId: selectedTeam.id, appIdId: appIdId)

            signingStatus = "Signing"
            let signedURL = try SigningService.sign(
                ipaURL: workingCopy,
                certificate: certificate,
                profile: profile
            )

            signingStatus = "Done"
            signedIPAURL = signedURL
        } catch let error as SigningServiceError {
            signingError = error.readableMessage
        } catch let error as DeveloperServicesError {
            signingError = error.readableMessage
        } catch {
            signingError = error.localizedDescription
        }
    }

    private func makeDeveloperServicesClient() -> DeveloperServicesClient? {
        guard let account = account else {
            return nil
        }
        let anisette = RemoteAnisetteProvider(baseURL: anisetteBaseURL)
        return DeveloperServicesClient(account: account, anisetteProvider: anisette)
    }

    private func resolveTeam(using client: DeveloperServicesClient) async throws -> DeveloperTeam {
        if let existing = team {
            return existing
        }
        let teams = try await client.fetchTeams()
        guard let selectedTeam = teams.first else {
            throw DeveloperServicesError.noTeamsFound
        }
        self.team = selectedTeam
        return selectedTeam
    }

    private func describeProvisioning(_ error: Error) -> String {
        if let developerError = error as? DeveloperServicesError {
            return developerError.readableMessage
        }
        return error.localizedDescription
    }

    func signOut() {
        account = nil
        pendingPassword = ""
        grandSlam = nil
        appleIdentifier = ""
        errorMessage = nil
        team = nil
        certificate = nil
        provisioningError = nil
        deviceIdentifier = ""
        deviceRegistered = false
        isSigning = false
        signingStatus = ""
        signingError = nil
        signedIPAURL = nil
        stage = .signIn
    }

    private func describe(_ error: Error) -> String {
        if let authError = error as? GrandSlamError {
            return authError.readableMessage
        }
        return error.localizedDescription
    }
}
