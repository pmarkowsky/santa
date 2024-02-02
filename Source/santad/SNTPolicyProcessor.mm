/// Copyright 2015 Google Inc. All rights reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License");
/// you may not use this file except in compliance with the License.
/// You may obtain a copy of the License at
///
///    http://www.apache.org/licenses/LICENSE-2.0
///
///    Unless required by applicable law or agreed to in writing, software
///    distributed under the License is distributed on an "AS IS" BASIS,
///    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
///    See the License for the specific language governing permissions and
///    limitations under the License.

#import "Source/santad/SNTPolicyProcessor.h"
#include <map>
#include <Foundation/Foundation.h>

#include <Kernel/kern/cs_blobs.h>
#import <MOLCodesignChecker/MOLCodesignChecker.h>
#import <Security/SecCode.h>
#import <Security/Security.h>

#import "Source/common/SNTCachedDecision.h"
#import "Source/common/SNTConfigurator.h"
#import "Source/common/SNTDeepCopy.h"
#import "Source/common/SNTFileInfo.h"
#import "Source/common/SNTLogging.h"
#import "Source/common/SNTRule.h"
#import "Source/common/String.h"
#import "Source/santad/DataLayer/SNTRuleTable.h"
#include "Source/santad/CEL/evaluator.h"
#include "absl/status/status.h"

@interface SNTPolicyProcessor ()
@property SNTRuleTable *ruleTable;
@property SNTConfigurator *configurator;
@end

@implementation SNTPolicyProcessor

- (instancetype)initWithRuleTable:(SNTRuleTable *)ruleTable {
  self = [super init];
  if (self) {
    _ruleTable = ruleTable;
    _configurator = [SNTConfigurator configurator];
  }
  return self;
}

// This method applies the rules to the cached decision object.
- (void)updateCachedDecision:(SNTCachedDecision *)cd 
                     ForRule:(SNTRule *)rule 
                WithContext:(santa::santad::cel::Context)context {
  std::map<std::pair<SNTRuleType, SNTRuleState>, SNTEventState> decisions {
    {{SNTRuleTypeBinary, SNTRuleStateAllow}, SNTEventStateAllowBinary},
    {{SNTRuleTypeBinary, SNTRuleStateAllowTransitive}, SNTEventStateAllowTransitive},
    {{SNTRuleTypeBinary, SNTRuleStateAllowCompiler}, SNTEventStateAllowCompiler},
    {{SNTRuleTypeBinary, SNTRuleStateSilentBlock}, SNTEventStateBlockBinary},
    {{SNTRuleTypeBinary, SNTRuleStateBlock}, SNTEventStateBlockBinary},
    {{SNTRuleTypeSigningID, SNTRuleStateAllow},  SNTEventStateAllowSigningID},
    {{SNTRuleTypeSigningID, SNTRuleStateAllowCompiler}, SNTEventStateAllowCompiler},
    {{SNTRuleTypeSigningID, SNTRuleStateSilentBlock}, SNTEventStateBlockSigningID},
    {{SNTRuleTypeSigningID, SNTRuleStateBlock}, SNTEventStateBlockSigningID},
    {{SNTRuleTypeCertificate, SNTRuleStateAllow} , SNTEventStateAllowCertificate},
    {{SNTRuleTypeCertificate, SNTRuleStateSilentBlock}, SNTEventStateBlockCertificate},
    {{SNTRuleTypeCertificate, SNTRuleStateBlock}, SNTEventStateBlockCertificate},
    {{SNTRuleTypeTeamID, SNTRuleStateAllow}, SNTEventStateAllowTeamID},
    {{SNTRuleTypeTeamID, SNTRuleStateSilentBlock}, SNTEventStateBlockTeamID},
    {{SNTRuleTypeTeamID, SNTRuleStateBlock}, SNTEventStateBlockTeamID},
  };

  cd.decision = decisions[std::pair<SNTRuleType, SNTRuleState>{rule.type, rule.state}];

  if (rule.state == SNTRuleStateSilentBlock) {
    cd.silentBlock = YES;
  } else if (rule.state == SNTRuleStateAllowCompiler) {
    if (![self.configurator enableTransitiveRules]) {
      cd.decision = SNTEventStateAllowBinary;
    }
  } else if (rule.state == SNTRuleStateAllowTransitive) {
    if (![self.configurator enableTransitiveRules]) {
      // check operating mode.
      SNTClientMode mode = [self.configurator clientMode];
      if (mode == SNTClientModeMonitor) {
        cd.decision = SNTEventStateAllowUnknown;
      } else {
        cd.decision = SNTEventStateBlockUnknown;
      }
    } 
  }

  if (rule.customMsg) {
    cd.customMsg = rule.customMsg;
  }

  if (rule.customURL) {
    cd.customURL = rule.customURL;
  }

  if (rule.cel) {
    LOGD(@"Evaluating CEL program: %@ Timestamp: %llu", rule.cel, context.timestamp);
    santa::santad::cel::Evaluator cel_evaluator = santa::santad::cel::Evaluator();
    absl::StatusOr<bool> result = cel_evaluator.Evaluate(santa::common::NSStringToUTF8String(rule.cel), context);

    // If the CEL program evaluated without error then check the result.
    LOGD(@"Evaluating CEL program decision value before evaling: %llu", cd.decision);
    if (result.ok()) {
      LOGD(@"CEL program evaluated without error");
      // If the CEL program doesn't match the context, then we treat this event
      // as if had fallen through on the match.
      if (!result.value()) {
        LOGD(@"CEL program did not match, falling through");
        SNTClientMode mode = [self.configurator clientMode];
        if (mode == SNTClientModeMonitor) {
          cd.decision = SNTEventStateAllowUnknown;
        } else {
          cd.decision = SNTEventStateBlockUnknown;
        }
      }
      LOGD(@"CEL program matched, decision: %llu", cd.decision);
    } else {
      LOGD(@"Failed to evaluate CEL program: %s", result.status().ToString().c_str());
    }
  }
}

- (nonnull SNTCachedDecision *)decisionForFileInfo:(nonnull SNTFileInfo *)fileInfo
                                        fileSHA256:(nullable NSString *)fileSHA256
                                 certificateSHA256:(nullable NSString *)certificateSHA256
                                            teamID:(nullable NSString *)teamID
                                         signingID:(nullable NSString *)signingID
                              isProdSignedCallback:(BOOL (^_Nonnull)())isProdSignedCallback
                        entitlementsFilterCallback:
                          (NSDictionary *_Nullable (^_Nullable)(
                            NSDictionary *_Nullable entitlements))entitlementsFilterCallback 
                              CelContext: (santa::santad::cel::Context) ctx {
  SNTCachedDecision *cd = [[SNTCachedDecision alloc] init];
  cd.sha256 = fileSHA256 ?: fileInfo.SHA256;
  cd.teamID = teamID;
  cd.signingID = signingID;

  SNTClientMode mode = [self.configurator clientMode];
  cd.decisionClientMode = mode;

  // If the binary is a critical system binary, don't check its signature.
  // The binary was validated at startup when the rule table was initialized.
  SNTCachedDecision *systemCd = self.ruleTable.criticalSystemBinaries[cd.sha256];
  if (systemCd) {
    systemCd.decisionClientMode = mode;
    return systemCd;
  }

  NSError *csInfoError;
  if (certificateSHA256.length) {
    cd.certSHA256 = certificateSHA256;
  } else {
    // Grab the code signature, if there's an error don't try to capture
    // any of the signature details.
    MOLCodesignChecker *csInfo = [fileInfo codesignCheckerWithError:&csInfoError];
    if (csInfoError) {
      csInfo = nil;
      cd.decisionExtra =
        [NSString stringWithFormat:@"Signature ignored due to error: %ld", (long)csInfoError.code];
      cd.teamID = nil;
      cd.signingID = nil;
    } else {
      cd.certSHA256 = csInfo.leafCertificate.SHA256;
      cd.certCommonName = csInfo.leafCertificate.commonName;
      cd.certChain = csInfo.certificates;
      cd.teamID = teamID
                    ?: [csInfo.signingInformation
                         objectForKey:(__bridge NSString *)kSecCodeInfoTeamIdentifier];


      // Add timestamp to the context for use in CEL expressions.
      NSDate *signingDate = [csInfo.signingInformation 
            objectForKey:(__bridge NSString *)kSecCodeInfoTimestamp];

      // If there isn't a timestamp, try to get the signing time that was
      // provided by the authors. Often platform binaries don't have a timestamp
      // but only have a signing date.
      //
      // We prefer timestamp because it's from the notary service where as the
      // signing date is supplied by the author.
      if (!signingDate) {
        signingDate = [csInfo.signingInformation 
            objectForKey:(__bridge NSString *)kSecCodeInfoTime];
      }

      if (signingDate) {
        ctx.timestamp = (uint64_t)[signingDate timeIntervalSince1970];
        LOGD(@"Setting timestamp to %llu", ctx.timestamp);
      } else {
        LOGD(@"No timestamp found");
      }

      // Ensure that if no teamID exists that the signing info confirms it is a
      // platform binary. If not, remove the signingID.
      if (!cd.teamID && cd.signingID) {
        id platformID = [csInfo.signingInformation
          objectForKey:(__bridge NSString *)kSecCodeInfoPlatformIdentifier];
        if (![platformID isKindOfClass:[NSNumber class]] || [platformID intValue] == 0) {
          cd.signingID = nil;
        }
      }

      NSDictionary *entitlements =
        csInfo.signingInformation[(__bridge NSString *)kSecCodeInfoEntitlementsDict];

      if (entitlementsFilterCallback) {
        cd.entitlements = entitlementsFilterCallback(entitlements);
        cd.entitlementsFiltered = (cd.entitlements.count == entitlements.count);
      } else {
        cd.entitlements = [entitlements sntDeepCopy];
        cd.entitlementsFiltered = NO;
      }
    }
  }
  cd.quarantineURL = fileInfo.quarantineDataURL;

  // Do not evaluate TeamID/SigningID rules for dev-signed code based on the
  // assumption that orgs are generally more relaxed about dev signed cert
  // protections and users can more easily produce dev-signed code that
  // would otherwise be inadvertently allowed.
  // Note: Only perform the check if the SigningID is still set, otherwise
  // it is unsigned or had issues above that already cleared the values.
  if (cd.signingID && !isProdSignedCallback()) {
    LOGD(@"Ignoring TeamID and SigningID rules for code not signed with production cert: %@",
         cd.signingID);
    cd.teamID = nil;
    cd.signingID = nil;
  }

  SNTRule *rule = [self.ruleTable ruleForBinarySHA256:cd.sha256
                                            signingID:cd.signingID
                                    certificateSHA256:cd.certSHA256
                                               teamID:cd.teamID];
  if (rule) {
    //TODO(plm) make this a C function to avoid the ObjC overhead.
    [self updateCachedDecision:cd ForRule:rule WithContext:ctx];
    if (cd.decision != SNTEventStateBlockUnknown || cd.decision != SNTEventStateAllowUnknown) {
      return cd;
    }
  }

  if ([[SNTConfigurator configurator] enableBadSignatureProtection] && csInfoError &&
      csInfoError.code != errSecCSUnsigned) {
    cd.decisionExtra =
      [NSString stringWithFormat:@"Blocked due to signature error: %ld", (long)csInfoError.code];
    cd.decision = SNTEventStateBlockCertificate;
    return cd;
  }

  NSString *msg = [self fileIsScopeBlocked:fileInfo];
  if (msg) {
    cd.decisionExtra = msg;
    cd.decision = SNTEventStateBlockScope;
    return cd;
  }

  msg = [self fileIsScopeAllowed:fileInfo];
  if (msg) {
    cd.decisionExtra = msg;
    cd.decision = SNTEventStateAllowScope;
    return cd;
  }

  switch (mode) {
    case SNTClientModeMonitor: cd.decision = SNTEventStateAllowUnknown; return cd;
    case SNTClientModeLockdown: cd.decision = SNTEventStateBlockUnknown; return cd;
    default: cd.decision = SNTEventStateBlockUnknown; return cd;
  }
}

- (nonnull SNTCachedDecision *)decisionForFileInfo:(nonnull SNTFileInfo *)fileInfo
                                     targetProcess:(nonnull const es_process_t *)targetProc
                        entitlementsFilterCallback:
                          (NSDictionary *_Nullable (^_Nonnull)(
                            const char *_Nullable teamID,
                            NSDictionary *_Nullable entitlements))entitlementsFilterCallback 
                            CelContext: (santa::santad::cel::Context)context {
  NSString *signingID;
  NSString *teamID;

  const char *entitlementsFilterTeamID = NULL;

  if (targetProc->signing_id.length > 0) {
    if (targetProc->team_id.length > 0) {
      entitlementsFilterTeamID = targetProc->team_id.data;
      teamID = [NSString stringWithUTF8String:targetProc->team_id.data];
      signingID =
        [NSString stringWithFormat:@"%@:%@", teamID,
                                   [NSString stringWithUTF8String:targetProc->signing_id.data]];
    } else if (targetProc->is_platform_binary) {
      entitlementsFilterTeamID = "platform";
      signingID =
        [NSString stringWithFormat:@"platform:%@",
                                   [NSString stringWithUTF8String:targetProc->signing_id.data]];
    }
  }

  return [self decisionForFileInfo:fileInfo
    fileSHA256:nil
    certificateSHA256:nil
    teamID:teamID
    signingID:signingID
    isProdSignedCallback:^BOOL {
      return ((targetProc->codesigning_flags & CS_DEV_CODE) == 0);
    }
    entitlementsFilterCallback:^NSDictionary *(NSDictionary *entitlements) {
      return entitlementsFilterCallback(entitlementsFilterTeamID, entitlements);
    }
    CelContext: context];
}

// Used by `$ santactl fileinfo`.
- (nonnull SNTCachedDecision *)decisionForFilePath:(nonnull NSString *)filePath
                                        fileSHA256:(nullable NSString *)fileSHA256
                                 certificateSHA256:(nullable NSString *)certificateSHA256
                                            teamID:(nullable NSString *)teamID
                                         signingID:(nullable NSString *)signingID 
                                         context:(santa::santad::cel::Context)context {
  MOLCodesignChecker *csInfo;
  NSError *error;

  SNTFileInfo *fileInfo = [[SNTFileInfo alloc] initWithPath:filePath error:&error];
  if (!fileInfo) {
    LOGW(@"Failed to read file %@: %@", filePath, error.localizedDescription);
  } else {
    csInfo = [fileInfo codesignCheckerWithError:&error];
    if (error) {
      LOGW(@"Failed to get codesign ingo for file %@: %@", filePath, error.localizedDescription);
    }
  }

  return [self decisionForFileInfo:fileInfo
                        fileSHA256:fileSHA256
                 certificateSHA256:certificateSHA256
                            teamID:teamID
                         signingID:signingID
              isProdSignedCallback:^BOOL {
                if (csInfo) {
                  // Development OID values defined by Apple and used by the Security Framework
                  // https://images.apple.com/certificateauthority/pdf/Apple_WWDR_CPS_v1.31.pdf
                  NSArray *keys = @[ @"1.2.840.113635.100.6.1.2", @"1.2.840.113635.100.6.1.12" ];
                  NSDictionary *vals = CFBridgingRelease(SecCertificateCopyValues(
                    csInfo.leafCertificate.certRef, (__bridge CFArrayRef)keys, NULL));
                  return vals.count == 0;
                } else {
                  return NO;
                }
              }
        entitlementsFilterCallback:nil
        CelContext: context];
}

///
///  Checks whether the file at @c path is in-scope for checking with Santa.
///
///  Files that are out of scope:
///    + Non Mach-O files that are not part of an installer package.
///    + Files in allowed path.
///
///  @return @c YES if file is in scope, @c NO otherwise.
///
- (NSString *)fileIsScopeAllowed:(SNTFileInfo *)fi {
  if (!fi) return nil;

  // Determine if file is within an allowed path
  NSRegularExpression *re = [[SNTConfigurator configurator] allowedPathRegex];
  if ([re numberOfMatchesInString:fi.path options:0 range:NSMakeRange(0, fi.path.length)]) {
    return @"Allowed Path Regex";
  }

  // If file is not a Mach-O file, we're not interested.
  if (!fi.isMachO) {
    return @"Not a Mach-O";
  }

  return nil;
}

- (NSString *)fileIsScopeBlocked:(SNTFileInfo *)fi {
  if (!fi) return nil;

  NSRegularExpression *re = [[SNTConfigurator configurator] blockedPathRegex];
  if ([re numberOfMatchesInString:fi.path options:0 range:NSMakeRange(0, fi.path.length)]) {
    return @"Blocked Path Regex";
  }

  if ([[SNTConfigurator configurator] enablePageZeroProtection] && fi.isMissingPageZero) {
    return @"Missing __PAGEZERO";
  }

  return nil;
}

@end
