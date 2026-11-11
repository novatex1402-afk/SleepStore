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

    let anisetteBaseURL: String = "https://ani.sidestore.io"

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
        let client = GrandSlamClient(anisetteProvider: anisette)
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

    func signOut() {
        account = nil
        pendingPassword = ""
        grandSlam = nil
        appleIdentifier = ""
        errorMessage = nil
        stage = .signIn
    }

    private func describe(_ error: Error) -> String {
        if let authError = error as? GrandSlamError {
            return authError.readableMessage
        }
        return error.localizedDescription
    }
}
