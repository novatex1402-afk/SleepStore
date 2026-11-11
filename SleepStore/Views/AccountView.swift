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
                    if session.deviceRegistered {
                        HStack {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundColor(.green)
                            Text("Device registered")
                                .font(.subheadline)
                        }
                    } else {
                        TextField("Device UDID", text: $session.deviceIdentifier)
                            .autocapitalization(.none)
                            .disableAutocorrection(true)

                        Button {
                            Task {
                                await session.registerDevice()
                            }
                        } label: {
                            HStack {
                                Spacer()
                                if session.isRegisteringDevice {
                                    ProgressView()
                                } else {
                                    Text("Register Device")
                                        .fontWeight(.semibold)
                                }
                                Spacer()
                            }
                        }
                        .disabled(session.isRegisteringDevice || session.deviceIdentifier.count < 24)
                    }
                } header: {
                    Text("Device")
                } footer: {
                    Text("Find your UDID in Settings, General, About, or from a trusted computer. The device must be registered before a profile can be issued.")
                }

                Section {
                    if let team = session.team {
                        InfoRow(title: "Team", value: team.name)
                    }
                    if let certificate = session.certificate {
                        InfoRow(title: "Certificate", value: certificate.serialNumber.isEmpty ? "Issued" : certificate.serialNumber)
                        HStack {
                            Image(systemName: "checkmark.seal.fill")
                                .foregroundColor(.green)
                            Text("Seven day certificate ready")
                                .font(.subheadline)
                        }
                        NavigationLink {
                            SignView()
                        } label: {
                            HStack {
                                Image(systemName: "signature")
                                Text("Sign an IPA")
                            }
                        }
                    } else {
                        Button {
                            Task {
                                await session.fetchCertificate()
                            }
                        } label: {
                            HStack {
                                Spacer()
                                if session.isProvisioning {
                                    ProgressView()
                                } else {
                                    Text("Fetch Signing Certificate")
                                        .fontWeight(.semibold)
                                }
                                Spacer()
                            }
                        }
                        .disabled(session.isProvisioning)
                    }

                    if let provisioningError = session.provisioningError {
                        Text(provisioningError)
                            .font(.footnote)
                            .foregroundColor(.red)
                    }
                } header: {
                    Text("Signing Certificate")
                } footer: {
                    Text("Requests the free seven day development certificate from Apple for this account.")
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
