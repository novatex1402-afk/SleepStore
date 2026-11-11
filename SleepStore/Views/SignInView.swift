import SwiftUI

struct SignInView: View {
    @EnvironmentObject private var session: AppSession

    @State private var appleIdentifier: String = ""
    @State private var password: String = ""

    var body: some View {
        NavigationView {
            Form {
                Section {
                    TextField("Apple ID", text: $appleIdentifier)
                        .keyboardType(.emailAddress)
                        .textContentType(.username)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)

                    SecureField("Password", text: $password)
                        .textContentType(.password)
                } header: {
                    Text("Apple Account")
                } footer: {
                    Text("Your credentials are sent only to Apple to obtain a signing certificate.")
                }

                if let errorMessage = session.errorMessage {
                    Section {
                        Text(errorMessage)
                            .font(.footnote)
                            .foregroundColor(.red)
                    }
                }

                Section {
                    DisclosureGroup("Advanced") {
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Anisette Server")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            TextField("Anisette server URL", text: $session.anisetteBaseURL)
                                .keyboardType(.URL)
                                .autocapitalization(.none)
                                .disableAutocorrection(true)
                        }
                        VStack(alignment: .leading, spacing: 4) {
                            Text("Client Info")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            TextField("X-Mme-Client-Info", text: $session.clientInfo)
                                .autocapitalization(.none)
                                .disableAutocorrection(true)
                        }
                    }
                } footer: {
                    Text("If sign in fails with a 503 from Apple, try a different anisette server or client info string.")
                }

                Section {
                    Button {
                        Task {
                            await session.signIn(appleIdentifier: appleIdentifier, password: password)
                        }
                    } label: {
                        HStack {
                            Spacer()
                            if session.isWorking {
                                ProgressView()
                            } else {
                                Text("Sign In")
                                    .fontWeight(.semibold)
                            }
                            Spacer()
                        }
                    }
                    .disabled(session.isWorking || appleIdentifier.isEmpty || password.isEmpty)
                }
            }
            .navigationTitle("Sign In")
        }
    }
}
