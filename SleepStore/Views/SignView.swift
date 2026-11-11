import SwiftUI
import UniformTypeIdentifiers

struct SignView: View {
    @EnvironmentObject private var session: AppSession

    @State private var isImporting = false
    @State private var isExporting = false

    private var ipaContentTypes: [UTType] {
        if let ipaType = UTType(filenameExtension: "ipa") {
            return [ipaType, .data]
        }
        return [.data]
    }

    var body: some View {
        Form {
            Section {
                Button {
                    isImporting = true
                } label: {
                    HStack {
                        Image(systemName: "square.and.arrow.down")
                        Text("Select IPA")
                    }
                }
                .disabled(session.isSigning)
            } header: {
                Text("Input")
            } footer: {
                Text("Choose an unsigned IPA. It will be signed with your seven day certificate and a matching provisioning profile.")
            }

            if session.isSigning {
                Section {
                    HStack {
                        ProgressView()
                        Text(session.signingStatus)
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                    }
                }
            }

            if let signingError = session.signingError {
                Section {
                    Text(signingError)
                        .font(.footnote)
                        .foregroundColor(.red)
                }
            }

            if let signedURL = session.signedIPAURL {
                Section {
                    HStack {
                        Image(systemName: "checkmark.seal.fill")
                            .foregroundColor(.green)
                        Text("Signed: \(signedURL.lastPathComponent)")
                            .font(.subheadline)
                    }
                    Button {
                        isExporting = true
                    } label: {
                        HStack {
                            Image(systemName: "square.and.arrow.up")
                            Text("Export Signed IPA")
                        }
                    }
                } header: {
                    Text("Output")
                } footer: {
                    Text("Save the signed IPA to Files, then install it with KSign or ESign.")
                }
            }
        }
        .navigationTitle("Sign IPA")
        .fileImporter(
            isPresented: $isImporting,
            allowedContentTypes: ipaContentTypes,
            allowsMultipleSelection: false
        ) { result in
            switch result {
            case .success(let urls):
                if let url = urls.first {
                    Task {
                        await session.signIPA(at: url)
                    }
                }
            case .failure(let error):
                session.signingError = error.localizedDescription
            }
        }
        .sheet(isPresented: $isExporting) {
            if let signedURL = session.signedIPAURL {
                ActivityView(items: [signedURL])
            }
        }
    }
}
