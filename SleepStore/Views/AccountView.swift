import SwiftUI

struct AccountView: View {
    @EnvironmentObject private var session: AppSession

    var body: some View {
        NavigationView {
            Form {
                Section {
                    InfoRow(title: "Apple ID", value: session.account?.identifier ?? "")
                    if let fullName = session.account?.fullName, !fullName.isEmpty {
                        InfoRow(title: "Name", value: fullName)
                    }
                    InfoRow(title: "Account ID", value: session.account?.accountDirectoryServicesIdentifier ?? "")
                } header: {
                    Text("Signed In")
                }

                Section {
                    HStack {
                        Image(systemName: "checkmark.seal.fill")
                            .foregroundColor(.green)
                        Text("Apple authentication successful")
                            .font(.subheadline)
                    }
                } footer: {
                    Text("Next: fetch the free development certificate and provisioning profile, then sign an IPA on device.")
                }

                Section {
                    Button(role: .destructive) {
                        session.signOut()
                    } label: {
                        Text("Sign Out")
                    }
                }
            }
            .navigationTitle("Account")
        }
    }
}

private struct InfoRow: View {
    let title: String
    let value: String

    var body: some View {
        HStack {
            Text(title)
                .foregroundColor(.primary)
            Spacer()
            Text(value)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.trailing)
        }
    }
}
