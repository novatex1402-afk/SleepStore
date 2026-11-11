#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface ZSigner : NSObject

+ (nullable NSString *)bundleIdentifierOfIPA:(NSString *)inputPath;

+ (BOOL)signInputIPA:(NSString *)inputPath
           outputIPA:(NSString *)outputPath
         certificate:(NSString *)certificatePath
          privateKey:(NSString *)privateKeyPath
        provisioning:(NSString *)provisioningPath
               error:(NSString * _Nullable * _Nullable)errorOut;

@end

NS_ASSUME_NONNULL_END
