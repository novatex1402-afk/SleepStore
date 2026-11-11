import SwiftUI

struct TwoFactorView: View {
    @EnvironmentObject private var session: AppSession

    @State private var code: String = ""

    var body: some View {
        NavigationView {
            Form {
                Section {
                    TextField("Verification Code", text: $code)
                        .keyboardType(.numberPad)
                        .textContentType(.oneTimeCode)
                } header: {
                    Text("Two Factor Authentication")
                } footer: {
                    Text("Enter the six digit code sent to your trusted Apple devices.")
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
                            await session.submitTwoFactorCode(code)
                        }
                    } label: {
                        HStack {
                            Spacer()
                            if session.isWorking {
                                ProgressView()
                            } else {
                                Text("Verify")
                                    .fontWeight(.semibold)
                            }
                            Spacer()
                        }
                    }
                    .disabled(session.isWorking || code.count < 6)
                }

                Section {
                    Button(role: .cancel) {
                        session.signOut()
                    } label: {
                        Text("Cancel")
                    }
                }
            }
            .navigationTitle("Verify")
        }
    }
}
