import SwiftUI

struct RootView: View {
    @EnvironmentObject private var session: AppSession

    var body: some View {
        switch session.stage {
        case .onboarding:
            OnboardingView()
        case .signIn:
            SignInView()
        case .twoFactor:
            TwoFactorView()
        case .authenticated:
            AccountView()
        }
    }
}
