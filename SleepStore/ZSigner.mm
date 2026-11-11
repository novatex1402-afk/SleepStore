#import "ZSigner.h"

#include <string>
#include <vector>

#include "openssl.h"
#include "bundle.h"
#include "archive.h"

@implementation ZSigner

+ (nullable NSString *)bundleIdentifierOfIPA:(NSString *)inputPath {
    @autoreleasepool {
        std::string inputFile = inputPath.UTF8String;
        NSString *temporaryFolder = [NSTemporaryDirectory() stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
        std::string workingFolder = temporaryFolder.UTF8String;

        if (!Zip::Extract(inputFile.c_str(), workingFolder.c_str())) {
            return nil;
        }

        NSFileManager *fileManager = [NSFileManager defaultManager];
        NSString *payloadFolder = [temporaryFolder stringByAppendingPathComponent:@"Payload"];
        NSArray<NSString *> *items = [fileManager contentsOfDirectoryAtPath:payloadFolder error:nil];

        for (NSString *item in items) {
            if ([item hasSuffix:@".app"]) {
                NSString *infoPath = [[payloadFolder stringByAppendingPathComponent:item] stringByAppendingPathComponent:@"Info.plist"];
                NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPath];
                NSString *identifier = info[@"CFBundleIdentifier"];
                if (identifier.length > 0) {
                    return identifier;
                }
            }
        }
        return nil;
    }
}

+ (BOOL)signInputIPA:(NSString *)inputPath
           outputIPA:(NSString *)outputPath
         certificate:(NSString *)certificatePath
          privateKey:(NSString *)privateKeyPath
        provisioning:(NSString *)provisioningPath
               error:(NSString * _Nullable * _Nullable)errorOut {
    @autoreleasepool {
        std::string inputFile = inputPath.UTF8String;
        std::string outputFile = outputPath.UTF8String;
        std::string certificateFile = certificatePath.UTF8String;
        std::string privateKeyFile = privateKeyPath.UTF8String;
        std::string provisioningFile = provisioningPath.UTF8String;

        ZSignAsset signAsset;
        if (!signAsset.Init(certificateFile, privateKeyFile, provisioningFile, "", "", false, false, false)) {
            if (errorOut) {
                *errorOut = @"Failed to load the certificate, key, or provisioning profile.";
            }
            return NO;
        }

        NSString *temporaryFolder = [NSTemporaryDirectory() stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
        std::string workingFolder = temporaryFolder.UTF8String;

        if (!Zip::Extract(inputFile.c_str(), workingFolder.c_str())) {
            if (errorOut) {
                *errorOut = @"Failed to extract the input archive.";
            }
            return NO;
        }

        ZBundle bundle;
        std::vector<std::string> injectDylibs;
        std::vector<std::string> removeDylibs;

        bool signed_ok = bundle.SignFolder(&signAsset,
                                           workingFolder,
                                           "",
                                           "",
                                           "",
                                           injectDylibs,
                                           removeDylibs,
                                           true,
                                           false,
                                           false,
                                           false);
        if (!signed_ok) {
            if (errorOut) {
                *errorOut = @"Signing failed while processing the application bundle.";
            }
            return NO;
        }

        size_t payloadPosition = bundle.m_strAppFolder.rfind("Payload");
        if (payloadPosition == std::string::npos || payloadPosition == 0) {
            if (errorOut) {
                *errorOut = @"Signed bundle layout was unexpected.";
            }
            return NO;
        }

        std::string baseFolder = bundle.m_strAppFolder.substr(0, payloadPosition - 1);
        if (!Zip::Archive(baseFolder.c_str(), outputFile.c_str(), 0)) {
            if (errorOut) {
                *errorOut = @"Failed to repackage the signed application.";
            }
            return NO;
        }

        return YES;
    }
}

@end
