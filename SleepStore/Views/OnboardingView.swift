import SwiftUI

struct OnboardingView: View {
    @EnvironmentObject private var session: AppSession

    var body: some View {
        VStack(spacing: 28) {
            Spacer()

            Image(systemName: "moon.stars.fill")
                .font(.system(size: 72))
                .foregroundColor(.accentColor)

            VStack(spacing: 12) {
                Text("SleepStore")
                    .font(.largeTitle)
                    .fontWeight(.bold)

                Text("Sign in with your Apple ID to generate a free seven day signing certificate and sign your apps on device.")
                    .font(.body)
                    .foregroundColor(.secondary)
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 32)
            }

            Spacer()

            VStack(spacing: 16) {
                FeatureRow(systemImage: "person.badge.key.fill", title: "Apple ID sign in", detail: "Authenticates directly with Apple.")
                FeatureRow(systemImage: "checkmark.seal.fill", title: "Free certificate", detail: "Uses the seven day development entitlement.")
                FeatureRow(systemImage: "signature", title: "On device signing", detail: "No computer required.")
            }
            .padding(.horizontal, 24)

            Spacer()

            Button {
                session.beginOnboarding()
            } label: {
                Text("Get Started")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 14)
            }
            .buttonStyle(.borderedProminent)
            .padding(.horizontal, 24)
            .padding(.bottom, 24)
        }
    }
}

private struct FeatureRow: View {
    let systemImage: String
    let title: String
    let detail: String

    var body: some View {
        HStack(spacing: 16) {
            Image(systemName: systemImage)
                .font(.title2)
                .foregroundColor(.accentColor)
                .frame(width: 36)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline)
                    .fontWeight(.semibold)
                Text(detail)
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()
        }
    }
}
