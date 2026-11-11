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
