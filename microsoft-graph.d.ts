// Type definitions for the Microsoft Graph API
// Project: https://github.com/microsoftgraph/msgraph-typescript-typings
// Definitions by: Microsoft Graph Team <https://github.com/microsoftgraph>

//
// Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
//


export as namespace microsoftgraphbeta;

export type Status = "active" | "updated" | "deleted" | "ignored" | "unknownFutureValue"
export type DayOfWeek = "sunday" | "monday" | "tuesday" | "wednesday" | "thursday" | "friday" | "saturday"
export type AutomaticRepliesStatus = "disabled" | "alwaysEnabled" | "scheduled"
export type ExternalAudienceScope = "none" | "contactsOnly" | "all"
export type AttendeeType = "required" | "optional" | "resource"
export type FreeBusyStatus = "free" | "tentative" | "busy" | "oof" | "workingElsewhere" | "unknown"
export type PhysicalAddressType = "unknown" | "home" | "business" | "other"
export type LocationType = "default" | "conferenceRoom" | "homeAddress" | "businessAddress" | "geoCoordinates" | "streetAddress" | "hotel" | "restaurant" | "localBusiness" | "postalAddress"
export type LocationUniqueIdType = "unknown" | "locationStore" | "directory" | "private" | "bing"
export type ActivityDomain = "unknown" | "work" | "personal" | "unrestricted"
export type RecipientScopeType = "none" | "internal" | "external" | "externalPartner" | "externalNonPartner"
export type MailTipsType = "automaticReplies" | "mailboxFullStatus" | "customMailTip" | "externalMemberCount" | "totalMemberCount" | "maxMessageSize" | "deliveryRestriction" | "moderationStatus" | "recipientScope" | "recipientSuggestions"
export type TimeZoneStandard = "windows" | "iana"
export type BodyType = "text" | "html"
export type Importance = "low" | "normal" | "high"
export type InferenceClassificationType = "focused" | "other"
export type FollowupFlagStatus = "notFlagged" | "complete" | "flagged"
export type CalendarColor = "lightBlue" | "lightGreen" | "lightOrange" | "lightGray" | "lightYellow" | "lightTeal" | "lightPink" | "lightBrown" | "lightRed" | "maxColor" | "auto"
export type ResponseType = "none" | "organizer" | "tentativelyAccepted" | "accepted" | "declined" | "notResponded"
export type Sensitivity = "normal" | "personal" | "private" | "confidential"
export type RecurrencePatternType = "daily" | "weekly" | "absoluteMonthly" | "relativeMonthly" | "absoluteYearly" | "relativeYearly"
export type WeekIndex = "first" | "second" | "third" | "fourth" | "last"
export type RecurrenceRangeType = "endDate" | "noEnd" | "numbered"
export type EventType = "singleInstance" | "occurrence" | "exception" | "seriesMaster"
export type PhoneType = "home" | "business" | "mobile" | "other" | "assistant" | "homeFax" | "businessFax" | "otherFax" | "pager" | "radio"
export type EmailType = "unknown" | "work" | "personal" | "main" | "other"
export type WebsiteType = "other" | "home" | "work" | "blog" | "profile"
export type MeetingMessageType = "none" | "meetingRequest" | "meetingCancelled" | "meetingAccepted" | "meetingTentativelyAccepted" | "meetingDeclined"
export type MessageActionFlag = "any" | "call" | "doNotForward" | "followUp" | "fyi" | "forward" | "noResponseNecessary" | "read" | "reply" | "replyToAll" | "review"
export type ReferenceAttachmentProvider = "other" | "oneDriveBusiness" | "oneDriveConsumer" | "dropbox"
export type ReferenceAttachmentPermission = "other" | "view" | "edit" | "anonymousView" | "anonymousEdit" | "organizationView" | "organizationEdit"
export type GroupAccessType = "none" | "private" | "secret" | "public"
export type CategoryColor = "preset0" | "preset1" | "preset2" | "preset3" | "preset4" | "preset5" | "preset6" | "preset7" | "preset8" | "preset9" | "preset10" | "preset11" | "preset12" | "preset13" | "preset14" | "preset15" | "preset16" | "preset17" | "preset18" | "preset19" | "preset20" | "preset21" | "preset22" | "preset23" | "preset24" | "none"
export type TaskStatus = "notStarted" | "inProgress" | "completed" | "waitingOnOthers" | "deferred"
export type PlannerPreviewType = "automatic" | "noPreview" | "checklist" | "description" | "reference"
export type OperationStatus = "NotStarted" | "Running" | "Completed" | "Failed"
export type OnenotePatchInsertPosition = "After" | "Before"
export type OnenotePatchActionType = "Replace" | "Append" | "Delete" | "Insert" | "Prepend"
export type OnenoteSourceService = "Unknown" | "OneDrive" | "OneDriveForBusiness" | "OnPremOneDriveForBusiness"
export type OnenoteUserRole = "Owner" | "Contributor" | "Reader" | "None"
export type RiskLevel = "low" | "medium" | "high"
export type ConditionalAccessPolicyResult = "success" | "failure" | "notApplied" | "notEnabled" | "unknown" | "unknownFutureValue"
export type ConditionalAccessStatus = "success" | "failure" | "notApplied" | "unknownFutureValue"
export type GroupType = "unifiedGroups" | "azureAD" | "unknownFutureValue"
export type OperationResult = "success" | "failure" | "timeout" | "unknownFutureValue"
export type RiskEventStatus = "active" | "remediated" | "dismissedAsFixed" | "dismissedAsFalsePositive" | "dismissedAsIgnore" | "loginBlocked" | "closedMfaAuto" | "closedMultipleReasons"
export type UserRiskLevel = "unknown" | "none" | "low" | "medium" | "high"
export type ApprovalState = "pending" | "approved" | "denied" | "aborted" | "canceled"
export type RoleSummaryStatus = "ok" | "bad"
export type SetupStatus = "unknown" | "notRegisteredYet" | "registeredSetupNotStarted" | "registeredSetupInProgress" | "registrationAndSetupCompleted" | "registrationFailed" | "registrationTimedOut" | "disabled"
export type AndroidForWorkBindStatus = "notBound" | "bound" | "boundAndValidated" | "unbinding"
export type AndroidForWorkSyncStatus = "success" | "credentialsNotValid" | "androidForWorkApiError" | "managementServiceError" | "unknownError" | "none"
export type AndroidForWorkEnrollmentTarget = "none" | "all" | "targeted" | "targetedAsEnrollmentRestrictions"
export type AndroidForWorkAppConfigurationSchemaItemDataType = "bool" | "integer" | "string" | "choice" | "multiselect" | "bundle" | "bundleArray" | "hidden"
export type AndroidManagedStoreAccountBindStatus = "notBound" | "bound" | "boundAndValidated" | "unbinding"
export type AndroidManagedStoreAccountAppSyncStatus = "success" | "credentialsNotValid" | "androidForWorkApiError" | "managementServiceError" | "unknownError" | "none"
export type AndroidManagedStoreAccountEnrollmentTarget = "none" | "all" | "targeted" | "targetedAsEnrollmentRestrictions"
export type AndroidManagedStoreAppConfigurationSchemaItemDataType = "bool" | "integer" | "string" | "choice" | "multiselect" | "bundle" | "bundleArray" | "hidden"
export type InstallIntent = "available" | "required" | "uninstall" | "availableWithoutEnrollment"
export type MobileAppPublishingState = "notPublished" | "processing" | "published"
export type ResultantAppState = "installed" | "failed" | "notInstalled" | "uninstallFailed" | "pendingInstall" | "unknown" | "notApplicable"
export type ResultantAppStateDetail = "noAdditionalDetails" | "seeInstallErrorCode" | "seeUninstallErrorCode" | "pendingReboot" | "platformNotApplicable" | "minimumCpuSpeedNotMet" | "minimumLogicalProcessorCountNotMet" | "minimumPhysicalMemoryNotMet" | "minimumOsVersionNotMet" | "minimumDiskSpaceNotMet" | "processorArchitectureNotApplicable"
export type OfficeProductId = "o365ProPlusRetail" | "o365BusinessRetail" | "visioProRetail" | "projectProRetail"
export type OfficeUpdateChannel = "none" | "current" | "deferred" | "firstReleaseCurrent" | "firstReleaseDeferred"
export type WindowsArchitecture = "none" | "x86" | "x64" | "arm" | "neutral"
export type OfficeSuiteInstallProgressDisplayLevel = "none" | "full"
export type ManagedAppAvailability = "global" | "lineOfBusiness"
export type MobileAppContentFileUploadState = "success" | "transientError" | "error" | "unknown" | "azureStorageUriRequestSuccess" | "azureStorageUriRequestPending" | "azureStorageUriRequestFailed" | "azureStorageUriRequestTimedOut" | "azureStorageUriRenewalSuccess" | "azureStorageUriRenewalPending" | "azureStorageUriRenewalFailed" | "azureStorageUriRenewalTimedOut" | "commitFileSuccess" | "commitFilePending" | "commitFileFailed" | "commitFileTimedOut"
export type WindowsDeviceType = "none" | "desktop" | "mobile" | "holographic" | "team"
export type MicrosoftStoreForBusinessLicenseType = "offline" | "online"
export type VppTokenAccountType = "business" | "education"
export type VppTokenActionFailureReason = "none" | "appleFailure" | "internalError" | "expiredVppToken" | "expiredApplePushNotificationCertificate"
export type ActionState = "none" | "pending" | "canceled" | "active" | "done" | "failed" | "notSupported"
export type CertificateStatus = "notProvisioned" | "provisioned"
export type ComplianceStatus = "unknown" | "notApplicable" | "compliant" | "remediated" | "nonCompliant" | "error" | "conflict" | "notAssigned"
export type AndroidPermissionActionType = "prompt" | "autoGrant" | "autoDeny"
export type MdmAppConfigKeyType = "stringType" | "integerType" | "realType" | "booleanType" | "tokenType"
export type ManagedDeviceRemoteAction = "retire" | "delete" | "fullScan" | "quickScan" | "signatureUpdate"
export type RemoteAction = "unknown" | "factoryReset" | "removeCompanyData" | "resetPasscode" | "remoteLock" | "enableLostMode" | "disableLostMode" | "locateDevice" | "rebootNow" | "recoverPasscode" | "cleanWindowsDevice" | "logoutSharedAppleDeviceActiveUser" | "quickScan" | "fullScan" | "windowsDefenderUpdateSignatures" | "factoryResetKeepEnrollmentData" | "updateDeviceAccount" | "automaticRedeployment" | "shutDown"
export type RunAsAccountType = "system" | "user"
export type RunState = "unknown" | "success" | "fail"
export type DeviceGuardVirtualizationBasedSecurityHardwareRequirementState = "meetHardwareRequirements" | "secureBootRequired" | "dmaProtectionRequired" | "hyperVNotSupportedForGuestVM" | "hyperVNotAvailable"
export type DeviceGuardVirtualizationBasedSecurityState = "running" | "rebootRequired" | "require64BitArchitecture" | "notLicensed" | "notConfigured" | "doesNotMeetHardwareRequirements" | "other"
export type DeviceGuardLocalSystemAuthorityCredentialGuardState = "running" | "rebootRequired" | "notLicensed" | "notConfigured" | "virtualizationBasedSecurityNotRunning"
export type OwnerType = "unknown" | "company" | "personal"
export type ManagedDeviceOwnerType = "unknown" | "company" | "personal"
export type ManagementState = "managed" | "retirePending" | "retireFailed" | "wipePending" | "wipeFailed" | "unhealthy" | "deletePending" | "retireIssued" | "wipeIssued" | "wipeCanceled" | "retireCanceled" | "discovered"
export type ChassisType = "unknown" | "desktop" | "laptop" | "worksWorkstation" | "enterpriseServer" | "phone" | "tablet" | "mobileOther" | "mobileUnknown"
export type DeviceType = "desktop" | "windowsRT" | "winMO6" | "nokia" | "windowsPhone" | "mac" | "winCE" | "winEmbedded" | "iPhone" | "iPad" | "iPod" | "android" | "iSocConsumer" | "unix" | "macMDM" | "holoLens" | "surfaceHub" | "androidForWork" | "androidEnterprise" | "blackberry" | "palm" | "unknown"
export type ComplianceState = "unknown" | "compliant" | "noncompliant" | "conflict" | "error" | "inGracePeriod" | "configManager"
export type ManagementAgentType = "eas" | "mdm" | "easMdm" | "intuneClient" | "easIntuneClient" | "configurationManagerClient" | "configurationManagerClientMdm" | "configurationManagerClientMdmEas" | "unknown" | "jamf" | "googleCloudDevicePolicyController" | "microsoft365ManagedMdm"
export type DeviceEnrollmentType = "unknown" | "userEnrollment" | "deviceEnrollmentManager" | "appleBulkWithUser" | "appleBulkWithoutUser" | "windowsAzureADJoin" | "windowsBulkUserless" | "windowsAutoEnrollment" | "windowsBulkAzureDomainJoin" | "windowsCoManagement"
export type LostModeState = "disabled" | "enabled"
export type DeviceRegistrationState = "notRegistered" | "registered" | "revoked" | "keyConflict" | "approvalPending" | "certificateReset" | "notRegisteredPendingEnrollment" | "unknown"
export type DeviceManagementExchangeAccessState = "none" | "unknown" | "allowed" | "blocked" | "quarantined"
export type DeviceManagementExchangeAccessStateReason = "none" | "unknown" | "exchangeGlobalRule" | "exchangeIndividualRule" | "exchangeDeviceRule" | "exchangeUpgrade" | "exchangeMailboxPolicy" | "other" | "compliant" | "notCompliant" | "notEnrolled" | "unknownLocation" | "mfaRequired" | "azureADBlockDueToAccessPolicy" | "compromisedPassword" | "deviceNotKnownWithManagedApp"
export type WindowsDeviceHealthState = "clean" | "fullScanPending" | "rebootPending" | "manualStepsPending" | "offlineScanPending" | "critical"
export type WindowsMalwareSeverity = "unknown" | "low" | "moderate" | "high" | "severe"
export type WindowsMalwareCategory = "invalid" | "adware" | "spyware" | "passwordStealer" | "trojanDownloader" | "worm" | "backdoor" | "remoteAccessTrojan" | "trojan" | "emailFlooder" | "keylogger" | "dialer" | "monitoringSoftware" | "browserModifier" | "cookie" | "browserPlugin" | "aolExploit" | "nuker" | "securityDisabler" | "jokeProgram" | "hostileActiveXControl" | "softwareBundler" | "stealthNotifier" | "settingsModifier" | "toolBar" | "remoteControlSoftware" | "trojanFtp" | "potentialUnwantedSoftware" | "icqExploit" | "trojanTelnet" | "exploit" | "filesharingProgram" | "malwareCreationTool" | "remote_Control_Software" | "tool" | "trojanDenialOfService" | "trojanDropper" | "trojanMassMailer" | "trojanMonitoringSoftware" | "trojanProxyServer" | "virus" | "known" | "unknown" | "spp" | "behavior" | "vulnerability" | "policy" | "enterpriseUnwantedSoftware" | "ransom" | "hipsRule"
export type WindowsMalwareExecutionState = "unknown" | "blocked" | "allowed" | "running" | "notRunning"
export type WindowsMalwareState = "unknown" | "detected" | "cleaned" | "quarantined" | "removed" | "allowed" | "blocked" | "cleanFailed" | "quarantineFailed" | "removeFailed" | "allowFailed" | "abandoned" | "blockFailed"
export type WindowsMalwareThreatState = "active" | "actionFailed" | "manualStepsRequired" | "fullScanRequired" | "rebootRequired" | "remediatedWithNonCriticalFailures" | "quarantined" | "removed" | "cleaned" | "allowed" | "noStatusCleared"
export type ManagedDevicePartnerReportedHealthState = "unknown" | "activated" | "deactivated" | "secured" | "lowSeverity" | "mediumSeverity" | "highSeverity" | "unresponsive" | "compromised" | "misconfigured"
export type ConfigurationManagerClientState = "unknown" | "installed" | "healthy" | "installFailed" | "updateFailed" | "communicationError"
export type DeviceManagementSubscriptionState = "pending" | "active" | "warning" | "disabled" | "deleted" | "blocked" | "lockedOut"
export type DeviceManagementSubscriptions = "none" | "intune" | "office365" | "intunePremium" | "intune_EDU" | "intune_SMB"
export type AdminConsentState = "notConfigured" | "granted" | "notGranted"
export type HealthState = "unknown" | "healthy" | "unhealthy"
export type AndroidDeviceOwnerAppAutoUpdatePolicyType = "notConfigured" | "userChoice" | "never" | "wiFiOnly" | "always"
export type AndroidDeviceOwnerDefaultAppPermissionPolicyType = "deviceDefault" | "prompt" | "autoGrant" | "autoDeny"
export type AndroidDeviceOwnerRequiredPasswordType = "deviceDefault" | "required" | "numeric" | "numericComplex" | "alphabetic" | "alphanumeric" | "alphanumericWithSymbols"
export type AndroidDeviceOwnerBatteryPluggedMode = "notConfigured" | "ac" | "usb" | "wireless"
export type AndroidDeviceOwnerSystemUpdateInstallType = "deviceDefault" | "postpone" | "windowed" | "automatic"
export type AndroidDeviceOwnerWiFiSecurityType = "open" | "wep" | "wpaPersonal"
export type EasAuthenticationMethod = "usernameAndPassword" | "certificate"
export type EmailSyncDuration = "userDefined" | "oneDay" | "threeDays" | "oneWeek" | "twoWeeks" | "oneMonth" | "unlimited"
export type UserEmailSource = "userPrincipalName" | "primarySmtpAddress"
export type SubjectNameFormat = "commonName" | "commonNameIncludingEmail" | "commonNameAsEmail" | "custom" | "commonNameAsIMEI" | "commonNameAsSerialNumber" | "commonNameAsAadDeviceId" | "commonNameAsIntuneDeviceId" | "commonNameAsDurableDeviceId"
export type SubjectAlternativeNameType = "none" | "emailAddress" | "userPrincipalName" | "customAzureADAttribute" | "domainNameService"
export type CertificateValidityPeriodScale = "days" | "months" | "years"
export type DevicePlatformType = "android" | "androidForWork" | "iOS" | "macOS" | "windowsPhone81" | "windows81AndLater" | "windows10AndLater" | "androidWorkProfile"
export type KeyUsages = "keyEncipherment" | "digitalSignature"
export type CertificateIssuanceStates = "unknown" | "challengeIssued" | "challengeIssueFailed" | "requestCreationFailed" | "requestSubmitFailed" | "challengeValidationSucceeded" | "challengeValidationFailed" | "issueFailed" | "issuePending" | "issued" | "responseProcessingFailed" | "responsePending" | "enrollmentSucceeded" | "enrollmentNotNeeded" | "revoked" | "removedFromCollection" | "renewVerified" | "installFailed" | "installed" | "deleteFailed" | "deleted" | "renewalRequested" | "requested"
export type KeyStorageProviderOption = "useTpmKspOtherwiseUseSoftwareKsp" | "useTpmKspOtherwiseFail" | "usePassportForWorkKspOtherwiseFail" | "useSoftwareKsp"
export type CertificateRevocationStatus = "none" | "pending" | "issued" | "failed" | "revoked"
export type KeySize = "size1024" | "size2048"
export type HashAlgorithms = "sha1" | "sha2"
export type AndroidUsernameSource = "username" | "userPrincipalName" | "samAccountName" | "primarySmtpAddress"
export type IntendedPurpose = "unassigned" | "smimeEncryption" | "smimeSigning" | "vpn" | "wifi"
export type EmailSyncSchedule = "userDefined" | "asMessagesArrive" | "manual" | "fifteenMinutes" | "thirtyMinutes" | "sixtyMinutes" | "basedOnMyUsage"
export type DomainNameSource = "fullDomainName" | "netBiosDomainName"
export type AndroidWiFiSecurityType = "open" | "wpaEnterprise"
export type WiFiAuthenticationMethod = "certificate" | "usernameAndPassword"
export type AndroidEapType = "eapTls" | "eapTtls" | "peap"
export type NonEapAuthenticationMethodForEapTtlsType = "unencryptedPassword" | "challengeHandshakeAuthenticationProtocol" | "microsoftChap" | "microsoftChapVersionTwo"
export type NonEapAuthenticationMethodForPeap = "none" | "microsoftChapVersionTwo"
export type AndroidForWorkRequiredPasswordType = "deviceDefault" | "lowSecurityBiometric" | "required" | "atLeastNumeric" | "numericComplex" | "atLeastAlphabetic" | "atLeastAlphanumeric" | "alphanumericWithSymbols"
export type AndroidForWorkCrossProfileDataSharingType = "deviceDefault" | "preventAny" | "allowPersonalToWork" | "noRestrictions"
export type AndroidForWorkDefaultAppPermissionPolicyType = "deviceDefault" | "prompt" | "autoGrant" | "autoDeny"
export type AndroidForWorkVpnConnectionType = "ciscoAnyConnect" | "pulseSecure" | "f5EdgeClient" | "dellSonicWallMobileConnect" | "checkPointCapsuleVpn" | "citrix"
export type VpnAuthenticationMethod = "certificate" | "usernameAndPassword"
export type AppListType = "none" | "appsInListCompliant" | "appsNotInListCompliant"
export type AndroidRequiredPasswordType = "deviceDefault" | "alphabetic" | "alphanumeric" | "alphanumericWithSymbols" | "lowSecurityBiometric" | "numeric" | "numericComplex" | "any"
export type WebBrowserCookieSettings = "browserDefault" | "blockAlways" | "allowCurrentWebSite" | "allowFromWebsitesVisited" | "allowAlways"
export type AndroidVpnConnectionType = "ciscoAnyConnect" | "pulseSecure" | "f5EdgeClient" | "dellSonicWallMobileConnect" | "checkPointCapsuleVpn" | "citrix"
export type AndroidWorkProfileRequiredPasswordType = "deviceDefault" | "lowSecurityBiometric" | "required" | "atLeastNumeric" | "numericComplex" | "atLeastAlphabetic" | "atLeastAlphanumeric" | "alphanumericWithSymbols"
export type AndroidWorkProfileCrossProfileDataSharingType = "deviceDefault" | "preventAny" | "allowPersonalToWork" | "noRestrictions"
export type AndroidWorkProfileDefaultAppPermissionPolicyType = "deviceDefault" | "prompt" | "autoGrant" | "autoDeny"
export type AndroidWorkProfileVpnConnectionType = "ciscoAnyConnect" | "pulseSecure" | "f5EdgeClient" | "dellSonicWallMobileConnect" | "checkPointCapsuleVpn" | "citrix"
export type AppleSubjectNameFormat = "commonName" | "commonNameAsEmail" | "custom" | "commonNameIncludingEmail" | "commonNameAsIMEI" | "commonNameAsSerialNumber"
export type CertificateStore = "user" | "machine"
export type RatingAustraliaMoviesType = "allAllowed" | "allBlocked" | "general" | "parentalGuidance" | "mature" | "agesAbove15" | "agesAbove18"
export type RatingAustraliaTelevisionType = "allAllowed" | "allBlocked" | "preschoolers" | "children" | "general" | "parentalGuidance" | "mature" | "agesAbove15" | "agesAbove15AdultViolence"
export type RatingCanadaMoviesType = "allAllowed" | "allBlocked" | "general" | "parentalGuidance" | "agesAbove14" | "agesAbove18" | "restricted"
export type RatingCanadaTelevisionType = "allAllowed" | "allBlocked" | "children" | "childrenAbove8" | "general" | "parentalGuidance" | "agesAbove14" | "agesAbove18"
export type RatingFranceMoviesType = "allAllowed" | "allBlocked" | "agesAbove10" | "agesAbove12" | "agesAbove16" | "agesAbove18"
export type RatingFranceTelevisionType = "allAllowed" | "allBlocked" | "agesAbove10" | "agesAbove12" | "agesAbove16" | "agesAbove18"
export type RatingGermanyMoviesType = "allAllowed" | "allBlocked" | "general" | "agesAbove6" | "agesAbove12" | "agesAbove16" | "adults"
export type RatingGermanyTelevisionType = "allAllowed" | "allBlocked" | "general" | "agesAbove6" | "agesAbove12" | "agesAbove16" | "adults"
export type RatingIrelandMoviesType = "allAllowed" | "allBlocked" | "general" | "parentalGuidance" | "agesAbove12" | "agesAbove15" | "agesAbove16" | "adults"
export type RatingIrelandTelevisionType = "allAllowed" | "allBlocked" | "general" | "children" | "youngAdults" | "parentalSupervision" | "mature"
export type RatingJapanMoviesType = "allAllowed" | "allBlocked" | "general" | "parentalGuidance" | "agesAbove15" | "agesAbove18"
export type RatingJapanTelevisionType = "allAllowed" | "allBlocked" | "explicitAllowed"
export type RatingNewZealandMoviesType = "allAllowed" | "allBlocked" | "general" | "parentalGuidance" | "mature" | "agesAbove13" | "agesAbove15" | "agesAbove16" | "agesAbove18" | "restricted" | "agesAbove16Restricted"
export type RatingNewZealandTelevisionType = "allAllowed" | "allBlocked" | "general" | "parentalGuidance" | "adults"
export type RatingUnitedKingdomMoviesType = "allAllowed" | "allBlocked" | "general" | "universalChildren" | "parentalGuidance" | "agesAbove12Video" | "agesAbove12Cinema" | "agesAbove15" | "adults"
export type RatingUnitedKingdomTelevisionType = "allAllowed" | "allBlocked" | "caution"
export type RatingUnitedStatesMoviesType = "allAllowed" | "allBlocked" | "general" | "parentalGuidance" | "parentalGuidance13" | "restricted" | "adults"
export type RatingUnitedStatesTelevisionType = "allAllowed" | "allBlocked" | "childrenAll" | "childrenAbove7" | "general" | "parentalGuidance" | "childrenAbove14" | "adults"
export type RatingAppsType = "allAllowed" | "allBlocked" | "agesAbove4" | "agesAbove9" | "agesAbove12" | "agesAbove17"
export type RequiredPasswordType = "deviceDefault" | "alphanumeric" | "numeric"
export type WiFiSecurityType = "open" | "wpaPersonal" | "wpaEnterprise" | "wep" | "wpa2Personal" | "wpa2Enterprise"
export type WiFiProxySetting = "none" | "manual" | "automatic"
export type EapType = "eapTls" | "leap" | "eapSim" | "eapTtls" | "peap" | "eapFast"
export type EapFastConfiguration = "noProtectedAccessCredential" | "useProtectedAccessCredential" | "useProtectedAccessCredentialAndProvision" | "useProtectedAccessCredentialAndProvisionAnonymously"
export type MacOSGatekeeperAppSources = "notConfigured" | "macAppStore" | "macAppStoreAndIdentifiedDevelopers" | "anywhere"
export type UsernameSource = "userPrincipalName" | "primarySmtpAddress" | "samAccountName"
export type IosNotificationAlertType = "deviceDefault" | "banner" | "modal" | "none"
export type AppleVpnConnectionType = "ciscoAnyConnect" | "pulseSecure" | "f5EdgeClient" | "dellSonicWallMobileConnect" | "checkPointCapsuleVpn" | "customVpn" | "ciscoIPSec" | "citrix" | "ciscoAnyConnectV2" | "paloAltoGlobalProtect" | "zscalerPrivateAccess" | "f5Access2018" | "citrixSso" | "paloAltoGlobalProtectV2"
export type VpnOnDemandRuleConnectionAction = "connect" | "evaluateConnection" | "ignore" | "disconnect"
export type VpnOnDemandRuleConnectionDomainAction = "connectIfNeeded" | "neverConnect"
export type VpnProviderType = "notConfigured" | "appProxy" | "packetTunnel"
export type EditionUpgradeLicenseType = "productKey" | "licenseFile" | "notConfigured"
export type Windows10EditionType = "windows10Enterprise" | "windows10EnterpriseN" | "windows10Education" | "windows10EducationN" | "windows10MobileEnterprise" | "windows10HolographicEnterprise" | "windows10Professional" | "windows10ProfessionalN" | "windows10ProfessionalEducation" | "windows10ProfessionalEducationN" | "windows10ProfessionalWorkstation" | "windows10ProfessionalWorkstationN" | "notConfigured"
export type WindowsSModeConfiguration = "noRestriction" | "block" | "unlock"
export type Enablement = "notConfigured" | "enabled" | "disabled"
export type StateManagementSetting = "notConfigured" | "blocked" | "allowed"
export type ServiceStartType = "manual" | "automatic" | "disabled"
export type LocalSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUserType = "notConfigured" | "administrators" | "administratorsAndPowerUsers" | "administratorsAndInteractiveUsers"
export type LocalSecurityOptionsMinimumSessionSecurity = "none" | "requireNtmlV2SessionSecurity" | "require128BitEncryption" | "ntlmV2And128BitEncryption"
export type LanManagerAuthenticationLevel = "lmAndNltm" | "lmNtlmAndNtlmV2" | "lmAndNtlmOnly" | "lmAndNtlmV2" | "lmNtlmV2AndNotLm" | "lmNtlmV2AndNotLmOrNtm"
export type LocalSecurityOptionsAdministratorElevationPromptBehaviorType = "notConfigured" | "elevateWithoutPrompting" | "promptForCredentialsOnTheSecureDesktop" | "promptForConsentOnTheSecureDesktop" | "promptForCredentials" | "promptForConsent" | "promptForConsentForNonWindowsBinaries"
export type LocalSecurityOptionsStandardUserElevationPromptBehaviorType = "notConfigured" | "automaticallyDenyElevationRequests" | "promptForCredentialsOnTheSecureDesktop" | "promptForCredentials"
export type LocalSecurityOptionsInformationShownOnLockScreenType = "notConfigured" | "userDisplayNameDomainUser" | "userDisplayNameOnly" | "doNotDisplayUser"
export type LocalSecurityOptionsInformationDisplayedOnLockScreenType = "notConfigured" | "administrators" | "administratorsAndPowerUsers" | "administratorsAndInteractiveUsers"
export type LocalSecurityOptionsSmartCardRemovalBehaviorType = "lockWorkstation" | "noAction" | "forceLogoff" | "disconnectRemoteDesktopSession"
export type DefenderSecurityCenterNotificationsFromAppType = "notConfigured" | "blockNoncriticalNotifications" | "blockAllNotifications"
export type DefenderSecurityCenterITContactDisplayType = "notConfigured" | "displayInAppAndInNotifications" | "displayOnlyInApp" | "displayOnlyInNotifications"
export type FirewallPreSharedKeyEncodingMethodType = "deviceDefault" | "none" | "utF8"
export type FirewallCertificateRevocationListCheckMethodType = "deviceDefault" | "none" | "attempt" | "require"
export type FirewallPacketQueueingMethodType = "deviceDefault" | "disabled" | "queueInbound" | "queueOutbound" | "queueBoth"
export type DefenderAttackSurfaceType = "userDefined" | "block" | "auditMode"
export type DefenderProtectionType = "userDefined" | "enable" | "auditMode"
export type FolderProtectionType = "userDefined" | "enable" | "auditMode" | "blockDiskModification" | "auditDiskModification"
export type AppLockerApplicationControlType = "notConfigured" | "enforceComponentsAndStoreApps" | "auditComponentsAndStoreApps" | "enforceComponentsStoreAppsAndSmartlocker" | "auditComponentsStoreAppsAndSmartlocker"
export type DeviceGuardLocalSystemAuthorityCredentialGuardType = "notConfigured" | "enableWithUEFILock" | "enableWithoutUEFILock"
export type ApplicationGuardBlockFileTransferType = "notConfigured" | "blockImageAndTextFile" | "blockImageFile" | "blockNone" | "blockTextFile"
export type ApplicationGuardBlockClipboardSharingType = "notConfigured" | "blockBoth" | "blockHostToContainer" | "blockContainerToHost" | "blockNone"
export type BitLockerEncryptionMethod = "aesCbc128" | "aesCbc256" | "xtsAes128" | "xtsAes256"
export type ConfigurationUsage = "blocked" | "required" | "allowed"
export type BitLockerRecoveryInformationType = "passwordAndKey" | "passwordOnly"
export type SignInAssistantOptions = "notConfigured" | "disabled"
export type DiagnosticDataSubmissionMode = "userDefined" | "none" | "basic" | "enhanced" | "full"
export type InkAccessSetting = "notConfigured" | "enabled" | "disabled"
export type EdgeCookiePolicy = "userDefined" | "allow" | "blockThirdParty" | "blockAll"
export type VisibilitySetting = "notConfigured" | "hide" | "show"
export type DefenderThreatAction = "deviceDefault" | "clean" | "quarantine" | "remove" | "allow" | "userDefined" | "block"
export type WeeklySchedule = "userDefined" | "everyday" | "sunday" | "monday" | "tuesday" | "wednesday" | "thursday" | "friday" | "saturday"
export type DefenderMonitorFileActivity = "userDefined" | "disable" | "monitorAllFiles" | "monitorIncomingFilesOnly" | "monitorOutgoingFilesOnly"
export type DefenderPotentiallyUnwantedAppAction = "deviceDefault" | "block" | "audit"
export type DefenderPromptForSampleSubmission = "userDefined" | "alwaysPrompt" | "promptBeforeSendingPersonalData" | "neverSendData" | "sendAllDataWithoutPrompting"
export type DefenderScanType = "userDefined" | "disabled" | "quick" | "full"
export type DefenderCloudBlockLevelType = "notConfigured" | "high" | "highPlus" | "zeroTolerance"
export type DefenderScheduleScanDay = "everyday" | "monday" | "tuesday" | "wednesday" | "thursday" | "friday" | "saturday" | "sunday" | "noScheduledScan"
export type DefenderSubmitSamplesConsentType = "sendSafeSamplesAutomatically" | "alwaysPrompt" | "neverSend" | "sendAllSamplesAutomatically"
export type WindowsPrivacyDataAccessLevel = "notConfigured" | "forceAllow" | "forceDeny" | "userInControl"
export type WindowsPrivacyDataCategory = "notConfigured" | "accountInfo" | "appsRunInBackground" | "calendar" | "callHistory" | "camera" | "contacts" | "diagnosticsInfo" | "email" | "location" | "messaging" | "microphone" | "motion" | "notifications" | "phone" | "radios" | "tasks" | "syncWithDevices" | "trustedDevices"
export type WindowsStartMenuAppListVisibilityType = "userDefined" | "collapse" | "remove" | "disableSettingsApp"
export type WindowsStartMenuModeType = "userDefined" | "fullScreen" | "nonFullScreen"
export type WindowsSpotlightEnablementSettings = "notConfigured" | "disabled" | "enabled"
export type AutomaticUpdateMode = "userDefined" | "notifyDownload" | "autoInstallAtMaintenanceTime" | "autoInstallAndRebootAtMaintenanceTime" | "autoInstallAndRebootAtScheduledTime" | "autoInstallAndRebootWithoutEndUserControl"
export type SafeSearchFilterType = "userDefined" | "strict" | "moderate"
export type EdgeSearchEngineType = "default" | "bing"
export type PrereleaseFeatures = "userDefined" | "settingsOnly" | "settingsAndExperimentations" | "notAllowed"
export type SharedPCAccountDeletionPolicyType = "immediate" | "diskSpaceThreshold" | "diskSpaceThresholdOrInactiveThreshold"
export type SharedPCAllowedAccountType = "guest" | "domain"
export type SecureAssessmentAccountType = "azureADAccount" | "domainAccount" | "localAccount"
export type NetworkSingleSignOnType = "disabled" | "prelogon" | "postlogon"
export type CertificateDestinationStore = "computerCertStoreRoot" | "computerCertStoreIntermediate" | "userCertStoreIntermediate"
export type WindowsDeliveryOptimizationMode = "userDefined" | "httpOnly" | "httpWithPeeringNat" | "httpWithPeeringPrivateGroup" | "httpWithInternetPeering" | "simpleDownload" | "bypassMode"
export type WindowsUpdateType = "userDefined" | "all" | "businessReadyOnly" | "windowsInsiderBuildFast" | "windowsInsiderBuildSlow" | "windowsInsiderBuildRelease"
export type WindowsUpdateForBusinessUpdateWeeks = "userDefined" | "firstWeek" | "secondWeek" | "thirdWeek" | "fourthWeek" | "everyWeek"
export type Windows10VpnProfileTarget = "user" | "device" | "autoPilotDevice"
export type Windows10VpnConnectionType = "pulseSecure" | "f5EdgeClient" | "dellSonicWallMobileConnect" | "checkPointCapsuleVpn" | "automatic" | "ikEv2" | "l2tp" | "pptp" | "citrix" | "paloAltoGlobalProtect"
export type Windows10VpnAuthenticationMethod = "certificate" | "usernameAndPassword" | "customEapXml"
export type Windows10AppType = "desktop" | "universal"
export type VpnTrafficRuleAppType = "none" | "desktop" | "universal"
export type VpnTrafficRuleRoutingPolicyType = "none" | "splitTunnel" | "forceTunnel"
export type WindowsVpnConnectionType = "pulseSecure" | "f5EdgeClient" | "dellSonicWallMobileConnect" | "checkPointCapsuleVpn"
export type InternetSiteSecurityLevel = "userDefined" | "medium" | "mediumHigh" | "high"
export type SiteSecurityLevel = "userDefined" | "low" | "mediumLow" | "medium" | "mediumHigh" | "high"
export type UpdateClassification = "userDefined" | "recommendedAndImportant" | "important" | "none"
export type WindowsUserAccountControlSettings = "userDefined" | "alwaysNotify" | "notifyOnAppChanges" | "notifyOnAppChangesWithoutDimming" | "neverNotify"
export type MiracastChannel = "userDefined" | "one" | "two" | "three" | "four" | "five" | "six" | "seven" | "eight" | "nine" | "ten" | "eleven" | "thirtySix" | "forty" | "fortyFour" | "fortyEight" | "oneHundredFortyNine" | "oneHundredFiftyThree" | "oneHundredFiftySeven" | "oneHundredSixtyOne" | "oneHundredSixtyFive"
export type WelcomeScreenMeetingInformation = "userDefined" | "showOrganizerAndTimeOnly" | "showOrganizerAndTimeAndSubject"
export type DeviceComplianceActionType = "noAction" | "notification" | "block" | "retire" | "wipe" | "removeResourceAccessProfiles" | "pushNotification"
export type DeviceThreatProtectionLevel = "unavailable" | "secured" | "low" | "medium" | "high" | "notSet"
export type PolicyPlatformType = "android" | "androidForWork" | "iOS" | "macOS" | "windowsPhone81" | "windows81AndLater" | "windows10AndLater" | "androidWorkProfile" | "all"
export type IosUpdatesInstallStatus = "success" | "available" | "idle" | "unknown" | "downloading" | "downloadFailed" | "downloadRequiresComputer" | "downloadInsufficientSpace" | "downloadInsufficientPower" | "downloadInsufficientNetwork" | "installing" | "installInsufficientSpace" | "installInsufficientPower" | "installPhoneCallInProgress" | "installFailed" | "notSupportedOperation" | "sharedDeviceUserLoggedInError"
export type NdesConnectorState = "none" | "active" | "inactive"
export type RestrictedAppsState = "prohibitedApps" | "notApprovedApps"
export type DeviceManagementExchangeConnectorSyncType = "fullSync" | "deltaSync"
export type MdmAuthority = "unknown" | "intune" | "sccm" | "office365"
export type WindowsHelloForBusinessPinUsage = "allowed" | "required" | "disallowed"
export type VppTokenState = "unknown" | "valid" | "expired" | "invalid" | "assignedToExternalMDM"
export type VppTokenSyncStatus = "none" | "inProgress" | "completed" | "failed"
export type DeviceManagementExchangeConnectorStatus = "none" | "connectionPending" | "connected" | "disconnected"
export type DeviceManagementExchangeConnectorType = "onPremises" | "hosted" | "serviceToService" | "dedicated"
export type DeviceManagementExchangeAccessLevel = "none" | "allow" | "block" | "quarantine"
export type DeviceManagementExchangeAccessRuleType = "family" | "model"
export type MobileThreatPartnerTenantState = "unavailable" | "available" | "enabled" | "unresponsive"
export type DeviceManagementPartnerTenantState = "unknown" | "unavailable" | "enabled" | "terminated" | "rejected" | "unresponsive"
export type DeviceManagementPartnerAppType = "unknown" | "singleTenantApp" | "multiTenantApp"
export type BinaryManagementConditionExpressionOperatorType = "or" | "and"
export type UnaryManagementConditionExpressionOperatorType = "not"
export type ManagedAppDataTransferLevel = "allApps" | "managedApps" | "none"
export type ManagedAppClipboardSharingLevel = "allApps" | "managedAppsWithPasteIn" | "managedApps" | "blocked"
export type ManagedAppPinCharacterSet = "numeric" | "alphanumericAndSymbol"
export type ManagedAppDataStorageLocation = "oneDriveForBusiness" | "sharePoint" | "localStorage"
export type ManagedAppRemediationAction = "block" | "wipe"
export type ManagedAppDataEncryptionType = "useDeviceSettings" | "afterDeviceRestart" | "whenDeviceLockedExceptOpenFiles" | "whenDeviceLocked"
export type AppManagementLevel = "unspecified" | "unmanaged" | "mdm" | "androidEnterprise"
export type WindowsInformationProtectionEnforcementLevel = "noProtection" | "encryptAndAuditOnly" | "encryptAuditAndPrompt" | "encryptAuditAndBlock"
export type WindowsInformationProtectionPinCharacterRequirements = "notAllow" | "requireAtLeastOne" | "allow"
export type ManagedAppFlaggedReason = "none" | "rootedDevice"
export type NotificationTemplateBrandingOptions = "none" | "includeCompanyLogo" | "includeCompanyName" | "includeContactInformation"
export type RoleAssignmentScopeType = "resourceScope" | "allDevices" | "allLicensedUsers" | "allDevicesAndLicensedUsers"
export type EmbeddedSIMDeviceStateValue = "notEvaluated" | "failed" | "installing" | "installed" | "deleting" | "error" | "deleted" | "removedByUser"
export type InstallState = "notApplicable" | "installed" | "failed" | "notInstalled" | "uninstallFailed" | "unknown"
export type WindowsAutopilotSyncStatus = "unknown" | "inProgress" | "completed" | "failed"
export type WindowsUserType = "administrator" | "standard"
export type WindowsDeviceUsageType = "singleUser" | "shared"
export type WindowsAutopilotProfileAssignmentStatus = "unknown" | "assignedInSync" | "assignedOutOfSync" | "assignedUnkownSyncState" | "notAssigned" | "pending" | "failed"
export type EnrollmentState = "unknown" | "enrolled" | "pendingReset" | "failed" | "notContacted" | "blocked"
export type ImportedDeviceIdentityType = "unknown" | "imei" | "serialNumber"
export type Platform = "unknown" | "ios" | "android" | "windows" | "windowsMobile" | "macOS"
export type DepTokenType = "none" | "dep" | "appleSchoolManager"
export type ITunesPairingMode = "disallow" | "allow" | "requiresCertificate"
export type DiscoverySource = "unknown" | "adminImport" | "deviceEnrollmentProgram"
export type ImportedWindowsAutopilotDeviceIdentityImportStatus = "unknown" | "pending" | "partial" | "complete" | "error"
export type RemoteAssistanceOnboardingStatus = "notOnboarded" | "onboarding" | "onboarded"
export type ApplicationType = "universal" | "desktop"
export type TeamVisibilityType = "private" | "public"
export type ClonableTeamParts = "apps" | "tabs" | "settings" | "channels" | "members"
export type GiphyRatingType = "moderate" | "strict"
export type ChatMessageBodyType = "text" | "html"
export type TeamsAsyncOperationType = "invalid" | "cloneTeam" | "archiveTeam" | "unarchiveTeam"
export type TeamsAsyncOperationStatus = "invalid" | "notStarted" | "inProgress" | "succeeded" | "failed"
export type TeamsCatalogAppDistributionMethod = "store" | "organization" | "sideloaded"
export type AttributeFlowType = "Always" | "ObjectAddOnly" | "MultiValueAddOnly"
export type AttributeFlowBehavior = "FlowWhenChanged" | "FlowAlways"
export type AttributeMappingSourceType = "Attribute" | "Constant" | "Function"
export type EntryExportStatus = "Noop" | "Success" | "RetryableError" | "PermanentError" | "Error"
export type AttributeType = "DateTime" | "Boolean" | "Binary" | "Reference" | "Integer" | "String"
export type EntrySyncOperation = "None" | "Add" | "Delete" | "Update"
export type Mutability = "ReadWrite" | "ReadOnly" | "Immutable" | "WriteOnly"
export type ObjectFlowTypes = "None" | "Add" | "Update" | "Delete"
export type SynchronizationSecret = "None" | "UserName" | "Password" | "SecretToken" | "AppKey" | "BaseAddress" | "ClientIdentifier" | "ClientSecret" | "SingleSignOnType" | "Sandbox" | "Url" | "Domain" | "ConsumerKey" | "ConsumerSecret" | "TokenKey" | "TokenExpiration" | "Oauth2AccessToken" | "Oauth2AccessTokenCreationTime" | "Oauth2RefreshToken" | "SyncAll" | "InstanceName" | "Oauth2ClientId" | "Oauth2ClientSecret" | "CompanyId" | "UpdateKeyOnSoftDelete" | "SynchronizationSchedule" | "SystemOfRecord" | "SandboxName" | "EnforceDomain" | "SyncNotificationSettings" | "Server" | "PerformInboundEntitlementGrants" | "HardDeletesEnabled" | "SyncAgentCompatibilityKey" | "SyncAgentADContainer" | "ValidateDomain" | "TestReferences"
export type SynchronizationStatusCode = "NotConfigured" | "NotRun" | "Active" | "Paused" | "Quarantine"
export type SynchronizationTaskExecutionResult = "Succeeded" | "Failed" | "EntryLevelErrors"
export type SynchronizationJobRestartScope = "Full" | "QuarantineState" | "Watermark" | "Escrows" | "ConnectorDataStore" | "None"
export type QuarantineReason = "EncounteredBaseEscrowThreshold" | "EncounteredTotalEscrowThreshold" | "EncounteredEscrowProportionThreshold" | "EncounteredQuarantineException" | "Unknown"
export type SynchronizationScheduleState = "Active" | "Disabled"
export type ScopeOperatorMultiValuedComparisonType = "All" | "Any"
export type ScopeOperatorType = "Binary" | "Unary"
export type EducationUserRole = "student" | "teacher" | "none" | "unknownFutureValue"
export type EducationSynchronizationProfileState = "deleting" | "deletionFailed" | "provisioningFailed" | "provisioned" | "provisioning" | "unknownFutureValue"
export type EducationSynchronizationStatus = "paused" | "inProgress" | "success" | "error" | "validationError" | "quarantined" | "unknownFutureValue"
export type EducationExternalSource = "sis" | "manual" | "unknownFutureValue"
export type EducationGender = "female" | "male" | "other" | "unknownFutureValue"
export type EducationAssignmentStatus = "draft" | "published" | "assigned" | "unknownFutureValue"
export type EducationSubmissionStatus = "working" | "submitted" | "released" | "returned" | "unknownFutureValue"
export type DeviceEnrollmentFailureReason = "unknown" | "authentication" | "authorization" | "accountValidation" | "userValidation" | "deviceNotSupported" | "inMaintenance" | "badRequest" | "featureNotSupported" | "enrollmentRestrictionsEnforced" | "clientDisconnected" | "userAbandonment"
export type MobileAppActionType = "unknown" | "installCommandSent" | "installed" | "uninstalled" | "userRequestedInstall"
export type MobileAppIntent = "available" | "notAvailable" | "requiredInstall" | "requiredUninstall" | "requiredAndAvailableInstall" | "availableInstallWithoutEnrollment" | "exclude"
export type DataPolicyOperationStatus = "notStarted" | "running" | "complete" | "failed" | "unknownFutureValue"
export type IdentityProviderType = "aad" | "phone" | "office365Connector"
export type ChatMessageType = "message" | "chatEvent" | "typing"
export type ChatMessageMentionType = "user" | "bot" | "channel" | "team"
export type ChatMessageImportance = "normal" | "high"
export type ChatMessageReactionType = "like" | "emoji" | "label"
export type AgreementAcceptanceState = "accepted" | "declined"
export type AccountStatus = "unknown" | "staged" | "active" | "suspended" | "deleted" | "unknownFutureValue"
export type AlertFeedback = "unknown" | "truePositive" | "falsePositive" | "benignPositive" | "unknownFutureValue"
export type AlertSeverity = "unknown" | "informational" | "low" | "medium" | "high" | "unknownFutureValue"
export type AlertStatus = "unknown" | "newAlert" | "inProgress" | "resolved" | "dismissed" | "unknownFutureValue"
export type ApplicationPermissionsRequired = "unknown" | "anonymous" | "guest" | "user" | "administrator" | "system" | "unknownFutureValue"
export type ConnectionDirection = "unknown" | "inbound" | "outbound" | "unknownFutureValue"
export type ConnectionStatus = "unknown" | "attempted" | "succeeded" | "blocked" | "failed" | "unknownFutureValue"
export type DiamondModel = "unknown" | "adversary" | "capability" | "infrastructure" | "victim" | "unknownFutureValue"
export type EmailRole = "unknown" | "sender" | "recipient" | "unknownFutureValue"
export type FileHashType = "unknown" | "sha1" | "sha256" | "md5" | "authenticodeHash256" | "lsHash" | "ctph" | "peSha1" | "peSha256" | "unknownFutureValue"
export type LogonType = "unknown" | "interactive" | "remoteInteractive" | "network" | "batch" | "service" | "unknownFutureValue"
export type ProcessIntegrityLevel = "unknown" | "untrusted" | "low" | "medium" | "high" | "system" | "unknownFutureValue"
export type RegistryHive = "unknown" | "currentConfig" | "currentUser" | "localMachineSam" | "localMachineSecurity" | "localMachineSoftware" | "localMachineSystem" | "usersDefault" | "unknownFutureValue"
export type RegistryOperation = "unknown" | "create" | "modify" | "delete" | "unknownFutureValue"
export type RegistryValueType = "unknown" | "binary" | "dword" | "dwordLittleEndian" | "dwordBigEndian" | "expandSz" | "link" | "multiSz" | "none" | "qword" | "qwordlittleEndian" | "sz" | "unknownFutureValue"
export type SecurityNetworkProtocol = "ip" | "icmp" | "igmp" | "ggp" | "ipv4" | "tcp" | "pup" | "udp" | "idp" | "ipv6" | "ipv6RoutingHeader" | "ipv6FragmentHeader" | "ipSecEncapsulatingSecurityPayload" | "ipSecAuthenticationHeader" | "icmpV6" | "ipv6NoNextHeader" | "ipv6DestinationOptions" | "nd" | "raw" | "ipx" | "spx" | "spxII" | "unknownFutureValue" | "unknown"
export type ThreatType = "unknown" | "botnet" | "bruteForce" | "c2" | "darknet" | "maliciousUrl" | "malware" | "phishing" | "proxy" | "watchList" | "unknownFutureValue"
export type TlpLevel = "unknown" | "white" | "green" | "amber" | "red" | "unknownFutureValue"
export type UserAccountSecurityType = "unknown" | "standard" | "power" | "administrator" | "unknownFutureValue"
export type BookingInvoiceStatus = "draft" | "reviewing" | "open" | "canceled" | "paid" | "corrective"
export type BookingPriceType = "undefined" | "fixedPrice" | "startingAt" | "hourly" | "free" | "priceVaries" | "callUs" | "notSet"
export type BookingReminderRecipients = "allAttendees" | "staff" | "customer"
export type BookingStaffRole = "guest" | "administrator" | "viewer" | "externalGuest"
export type UserPfxIntendedPurpose = "unassigned" | "smimeEncryption" | "smimeSigning" | "vpn" | "wifi"
export type UserPfxPaddingScheme = "none" | "pkcs1" | "oaepSha1" | "oaepSha256" | "oaepSha384" | "oaepSha512"
export type Priority = "None" | "High" | "Low"

export interface Entity {

	    /** Read-only. */
		id?: string

}

export interface Extension extends Entity {

}

export interface DirectoryObject extends Entity {

		deletedDateTime?: string

}

export interface User extends DirectoryObject {

	    /** true if the account is enabled; otherwise, false. This property is required when a user is created. Supports $filter. */
		accountEnabled?: boolean

		ageGroup?: string

	    /** The licenses that are assigned to the user. Not nullable. */
		assignedLicenses?: AssignedLicense[]

	    /** The plans that are assigned to the user. Read-only. Not nullable. */
		assignedPlans?: AssignedPlan[]

		businessPhones?: string[]

	    /** The city in which the user is located. Supports $filter. */
		city?: string

	    /** The company name which the user is associated. Read-only. */
		companyName?: string

		consentProvidedForMinor?: string

	    /** The country/region in which the user is located; for example, “US” or “UK”. Supports $filter. */
		country?: string

	    /** The name for the department in which the user works. Supports $filter. */
		department?: string

		deviceKeys?: DeviceKey[]

	    /** The name displayed in the address book for the user. This value is usually the combination of the user's first name, middle initial, and last name. This property is required when a user is created and it cannot be cleared during updates. Supports $filter and $orderby. */
		displayName?: string

		employeeId?: string

	    /** The given name (first name) of the user. Supports $filter. */
		givenName?: string

		imAddresses?: string[]

		isResourceAccount?: boolean

	    /** The user’s job title. Supports $filter. */
		jobTitle?: string

		legalAgeGroupClassification?: string

	    /** The SMTP address for the user, for example, "jeff@contoso.onmicrosoft.com". Read-Only. Supports $filter. */
		mail?: string

	    /** The mail alias for the user. This property must be specified when a user is created. Supports $filter. */
		mailNickname?: string

	    /** The primary cellular telephone number for the user. */
		mobilePhone?: string

	    /** Contains ExtensionAttributes 1-15 for the user. Note that the individual extension attributes are neither selectable nor filterable. For an onPremisesSyncEnabled user, this set of properties is mastered on-premises and is read-only. For a cloud-only user (where onPremisesSyncEnabled is false), these properties may be set during creation or update. */
		onPremisesExtensionAttributes?: OnPremisesExtensionAttributes

	    /** This property is used to associate an on-premises Active Directory user account to their Azure AD user object. This property must be specified when creating a new user account in the Graph if you are using a federated domain for the user’s userPrincipalName (UPN) property. Important: The $ and  characters cannot be used when specifying this property. Supports $filter. */
		onPremisesImmutableId?: string

	    /** Indicates the last time at which the object was synced with the on-premises directory; for example: "2013-02-16T03:04:54Z". The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. Read-only. */
		onPremisesLastSyncDateTime?: string

		onPremisesProvisioningErrors?: OnPremisesProvisioningError[]

	    /** Contains the on-premises security identifier (SID) for the user that was synchronized from on-premises to the cloud. Read-only. */
		onPremisesSecurityIdentifier?: string

	    /** true if this object is synced from an on-premises directory; false if this object was originally synced from an on-premises directory but is no longer synced; null if this object has never been synced from an on-premises directory (default). Read-only */
		onPremisesSyncEnabled?: boolean

		onPremisesDomainName?: string

		onPremisesSamAccountName?: string

		onPremisesUserPrincipalName?: string

	    /** Specifies password policies for the user. This value is an enumeration with one possible value being “DisableStrongPassword”, which allows weaker passwords than the default policy to be specified. “DisablePasswordExpiration” can also be specified. The two may be specified together; for example: "DisablePasswordExpiration, DisableStrongPassword". */
		passwordPolicies?: string

	    /** Specifies the password profile for the user. The profile contains the user’s password. This property is required when a user is created. The password in the profile must satisfy minimum requirements as specified by the passwordPolicies property. By default, a strong password is required. */
		passwordProfile?: PasswordProfile

	    /** The office location in the user's place of business. */
		officeLocation?: string

	    /** The postal code for the user's postal address. The postal code is specific to the user's country/region. In the United States of America, this attribute contains the ZIP code. */
		postalCode?: string

		preferredDataLocation?: string

	    /** The preferred language for the user. Should follow ISO 639-1 Code; for example "en-US". */
		preferredLanguage?: string

	    /** The plans that are provisioned for the user. Read-only. Not nullable. */
		provisionedPlans?: ProvisionedPlan[]

	    /** For example: ["SMTP: bob@contoso.com", "smtp: bob@sales.contoso.com"] The any operator is required for filter expressions on multi-valued properties. Read-only, Not nullable. Supports $filter. */
		proxyAddresses?: string[]

		refreshTokensValidFromDateTime?: string

		showInAddressList?: boolean

	    /** The state or province in the user's address. Supports $filter. */
		state?: string

	    /** The street address of the user's place of business. */
		streetAddress?: string

	    /** The user's surname (family name or last name). Supports $filter. */
		surname?: string

	    /** A two letter country code (ISO standard 3166). Required for users that will be assigned licenses due to legal requirement to check for availability of services in countries.  Examples include: "US", "JP", and "GB". Not nullable. Supports $filter. */
		usageLocation?: string

	    /** The user principal name (UPN) of the user. The UPN is an Internet-style login name for the user based on the Internet standard RFC 822. By convention, this should map to the user's email name. The general format is alias@domain, where domain must be present in the tenant’s collection of verified domains. This property is required when a user is created. The verified domains for the tenant can be accessed from the verifiedDomains property of organization. Supports $filter and $orderby. */
		userPrincipalName?: string

	    /** A string value that can be used to classify user types in your directory, such as “Member” and “Guest”. Supports $filter. */
		userType?: string

	    /** Settings for the primary mailbox of the signed-in user. You can get or update settings for sending automatic replies to incoming messages, locale, and time zone. */
		mailboxSettings?: MailboxSettings

	    /** A freeform text entry field for the user to describe themselves. */
		aboutMe?: string

	    /** The birthday of the user. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		birthday?: string

	    /** The hire date of the user. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		hireDate?: string

	    /** A list for the user to describe their interests. */
		interests?: string[]

	    /** The URL for the user's personal site. */
		mySite?: string

	    /** A list for the user to enumerate their past projects. */
		pastProjects?: string[]

	    /** The preferred name for the user. */
		preferredName?: string

	    /** A list for the user to enumerate their responsibilities. */
		responsibilities?: string[]

	    /** A list for the user to enumerate the schools they have attended. */
		schools?: string[]

	    /** A list for the user to enumerate their skills. */
		skills?: string[]

		identityUserRisk?: IdentityUserRisk

		deviceEnrollmentLimit?: number

	    /** The collection of open extensions defined for the user. Nullable. */
		extensions?: Extension[]

		appRoleAssignments?: AppRoleAssignment[]

	    /** Devices that are owned by the user. Read-only. Nullable. */
		ownedDevices?: DirectoryObject[]

	    /** Devices that are registered for the user. Read-only. Nullable. */
		registeredDevices?: DirectoryObject[]

	    /** The user or contact that is this user’s manager. Read-only. (HTTP Methods: GET, PUT, DELETE.) */
		manager?: DirectoryObject

	    /** The users and contacts that report to the user. (The users and contacts that have their manager property set to this user.) Read-only. Nullable. */
		directReports?: DirectoryObject[]

	    /** The groups, directory roles and administrative units that the user is a member of. Read-only. Nullable. */
		memberOf?: DirectoryObject[]

	    /** Directory objects that were created by the user. Read-only. Nullable. */
		createdObjects?: DirectoryObject[]

	    /** Directory objects that are owned by the user. Read-only. Nullable. */
		ownedObjects?: DirectoryObject[]

	    /** The scoped-role administrative unit memberships for this user. Read-only. Nullable. */
		scopedRoleMemberOf?: ScopedRoleMembership[]

		licenseDetails?: LicenseDetails[]

		activities?: UserActivity[]

	    /** Selective Outlook services available to the user. Read-only. Nullable. */
		outlook?: OutlookUser

	    /** The messages in a mailbox or folder. Read-only. Nullable. */
		messages?: Message[]

	    /** Read-only. Nullable. */
		joinedGroups?: Group[]

	    /** The user's mail folders. Read-only. Nullable. */
		mailFolders?: MailFolder[]

	    /** The user's primary calendar. Read-only. */
		calendar?: Calendar

	    /** The user's calendars. Read-only. Nullable. */
		calendars?: Calendar[]

	    /** The user's calendar groups. Read-only. Nullable. */
		calendarGroups?: CalendarGroup[]

	    /** The calendar view for the calendar. Read-only. Nullable. */
		calendarView?: Event[]

	    /** The user's events. Default is to show Events under the Default Calendar. Read-only. Nullable. */
		events?: Event[]

	    /** Read-only. The most relevant people to the user. The collection is ordered by their relevance to the user, which is determined by the user's communication, collaboration and business relationships. A person is an aggregation of information from across mail, contacts and social networks. */
		people?: Person[]

	    /** The user's contacts. Read-only. Nullable. */
		contacts?: Contact[]

	    /** The user's contacts folders. Read-only. Nullable. */
		contactFolders?: ContactFolder[]

	    /** Relevance classification of the user's messages based on explicit designations which override inferred relevance or importance. */
		inferenceClassification?: InferenceClassification

	    /** The user's profile photo. Read-only. */
		photo?: ProfilePhoto

	    /** Read-only. Nullable. */
		photos?: ProfilePhoto[]

	    /** The user's OneDrive. Read-only. */
		drive?: Drive

		drives?: Drive[]

	    /** Read-only. Nullable. */
		insights?: OfficeGraphInsights

	    /** Read-only. Nullable. */
		settings?: UserSettings

	    /** Selective Planner services available to the user. Read-only. Nullable. */
		planner?: PlannerUser

	    /** Read-only. */
		onenote?: Onenote

	    /** The managed devices associated with the user. */
		managedDevices?: ManagedDevice[]

	    /** Get enrollment configurations targeted to the user */
		deviceEnrollmentConfigurations?: DeviceEnrollmentConfiguration[]

	    /** Zero or more managed app registrations that belong to the user. */
		managedAppRegistrations?: ManagedAppRegistration[]

		devices?: Device[]

	    /** The Microsoft Teams that the user is a member of. Read-only. Nullable. */
		joinedTeams?: Group[]

	    /** The list of troubleshooting events for this user. */
		deviceManagementTroubleshootingEvents?: DeviceManagementTroubleshootingEvent[]

	    /** The list of troubleshooting events for this user. */
		mobileAppIntentAndStates?: MobileAppIntentAndState[]

	    /** The list of mobile app troubleshooting events for this user. */
		mobileAppTroubleshootingEvents?: MobileAppTroubleshootingEvent[]

	    /** The user's terms of use acceptance statuses. Read-only. Nullable. */
		agreementAcceptances?: AgreementAcceptance[]

		notifications?: Notification[]

}

export interface AppRoleAssignment extends Entity {

		appRoleId?: string

		creationTimestamp?: string

		principalDisplayName?: string

		principalId?: string

		principalType?: string

		resourceDisplayName?: string

		resourceId?: string

}

export interface ScopedRoleMembership extends Entity {

		roleId?: string

		administrativeUnitId?: string

		roleMemberInfo?: Identity

}

export interface LicenseDetails extends Entity {

	    /** Information about the service plans assigned with the license. Read-only, Not nullable */
		servicePlans?: ServicePlanInfo[]

	    /** Unique identifier (GUID) for the service SKU. Equal to the skuId property on the related SubscribedSku object. Read-only */
		skuId?: string

	    /** Unique SKU display name. Equal to the skuPartNumber on the related SubscribedSku object; for example: "AAD_Premium". Read-only */
		skuPartNumber?: string

}

export interface UserActivity extends Entity {

		visualElements?: VisualInfo

		activitySourceHost?: string

		activationUrl?: string

		appActivityId?: string

		appDisplayName?: string

		contentUrl?: string

		createdDateTime?: string

		expirationDateTime?: string

		fallbackUrl?: string

		lastModifiedDateTime?: string

		userTimezone?: string

		contentInfo?: any

		status?: Status

		historyItems?: ActivityHistoryItem[]

}

export interface OutlookUser extends Entity {

		masterCategories?: OutlookCategory[]

		taskGroups?: OutlookTaskGroup[]

		taskFolders?: OutlookTaskFolder[]

		tasks?: OutlookTask[]

}

export interface OutlookItem extends Entity {

		createdDateTime?: string

		lastModifiedDateTime?: string

		changeKey?: string

		categories?: string[]

}

export interface Message extends OutlookItem {

	    /** The date and time the message was received. */
		receivedDateTime?: string

	    /** The date and time the message was sent. */
		sentDateTime?: string

	    /** Indicates whether the message has attachments. This property doesn't include inline attachments, so if a message contains only inline attachments, this property is false. To verify the existence of inline attachments, parse the body property to look for a src attribute, such as <IMG src="cid:image001.jpg@01D26CD8.6C05F070">. */
		hasAttachments?: boolean

	    /** The message ID in the format specified by RFC5322. Updatable only if isDraft is true. */
		internetMessageId?: string

	    /** The collection of message headers, defined by RFC5322, that provide details of the network path taken by a message from the sender to the recipient. Read-only. */
		internetMessageHeaders?: InternetMessageHeader[]

	    /** The subject of the message. */
		subject?: string

	    /** The body of the message. It can be in HTML or text format. */
		body?: ItemBody

	    /** The first 255 characters of the message body. It is in text format. */
		bodyPreview?: string

	    /** The importance of the message: Low, Normal, High. */
		importance?: Importance

	    /** The unique identifier for the message's parent mailFolder. */
		parentFolderId?: string

	    /** The account that is actually used to generate the message. */
		sender?: Recipient

	    /** The mailbox owner and sender of the message. */
		from?: Recipient

	    /** The To: recipients for the message. */
		toRecipients?: Recipient[]

	    /** The Cc: recipients for the message. */
		ccRecipients?: Recipient[]

	    /** The Bcc: recipients for the message. */
		bccRecipients?: Recipient[]

	    /** The email addresses to use when replying. */
		replyTo?: Recipient[]

	    /** The ID of the conversation the email belongs to. */
		conversationId?: string

	    /** The Index of the conversation the email belongs to. */
		conversationIndex?: number

	    /** The part of the body of the message that is unique to the current message. uniqueBody is not returned by default but can be retrieved for a given message by use of the ?$select=uniqueBody query. It can be in HTML or text format. */
		uniqueBody?: ItemBody

	    /** Indicates whether a read receipt is requested for the message. */
		isDeliveryReceiptRequested?: boolean

	    /** Indicates whether a read receipt is requested for the message. */
		isReadReceiptRequested?: boolean

	    /** Indicates whether the message has been read. */
		isRead?: boolean

	    /** Indicates whether the message is a draft. A message is a draft if it hasn't been sent yet. */
		isDraft?: boolean

	    /** The URL to open the message in Outlook Web App.You can append an ispopout argument to the end of the URL to change how the message is displayed. If ispopout is not present or if it is set to 1, then the message is shown in a popout window. If ispopout is set to 0, then the browser will show the message in the Outlook Web App review pane.The message will open in the browser if you are logged in to your mailbox via Outlook Web App. You will be prompted to login if you are not already logged in with the browser.This URL can be accessed from within an iFrame. */
		webLink?: string

	    /** Information about mentions in the message. When processing a GET /messages request, the server sets this property and includes it in the response by default. The server returns null if there are no mentions in the message. Optional. */
		mentionsPreview?: MentionsPreview

	    /** The classification of the message for the user, based on inferred relevance or importance, or on an explicit override. Possible values are: focused, other. */
		inferenceClassification?: InferenceClassificationType

	    /** The valid entries parsed from the List-Unsubscribe header.  This is the data for the mail command in the List-Unsubscribe header if UnsubscribeEnabled property is true. */
		unsubscribeData?: string[]

	    /** Indicates whether the message is enabled for unsubscribe.  Its valueTrue if the list-Unsubscribe header conforms to rfc-2369. */
		unsubscribeEnabled?: boolean

	    /** The flag value that indicates the status, start date, due date, or completion date for the message. */
		flag?: FollowupFlag

	    /** The fileAttachment and itemAttachment attachments for the message. */
		attachments?: Attachment[]

	    /** The collection of open extensions defined for the message. Nullable. */
		extensions?: Extension[]

	    /** The collection of single-value extended properties defined for the message. Read-only. Nullable. */
		singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

	    /** The collection of multi-value extended properties defined for the message. Read-only. Nullable. */
		multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

	    /** A collection of mentions in the message, ordered by the createdDateTime from the newest to the oldest. By default, a GET /messages does not return this property unless you apply $expand on the property. */
		mentions?: Mention[]

}

export interface Group extends DirectoryObject {

		classification?: string

	    /** Timestamp of when the group was created. The value cannot be modified and is automatically populated when the group is created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. Read-only. */
		createdDateTime?: string

	    /** An optional description for the group. */
		description?: string

	    /** The display name for the group. This property is required when a group is created and it cannot be cleared during updates. Supports $filter and $orderby. */
		displayName?: string

	    /** Specifies the type of group to create. Possible values are Unified to create an Office 365 group, or DynamicMembership for dynamic groups.  For all other group types, like security-enabled groups and email-enabled security groups, do not set this property. */
		groupTypes?: string[]

	    /** The SMTP address for the group, for example, "serviceadmins@contoso.onmicrosoft.com". Read-only. Supports $filter. */
		mail?: string

	    /** Specifies whether the group is mail-enabled. If the securityEnabled property is also true, the group is a mail-enabled security group; otherwise, the group is a Microsoft Exchange distribution group. */
		mailEnabled?: boolean

	    /** The mail alias for the group, unique in the organization. This property must be specified when a group is created. Supports $filter. */
		mailNickname?: string

		membershipRule?: string

		membershipRuleProcessingState?: string

	    /** Indicates the last time at which the object was synced with the on-premises directory.The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. Read-only. Supports $filter. */
		onPremisesLastSyncDateTime?: string

	    /** Errors when using Microsoft synchronization product (including Azure AD Connect, DirSync and MIM + Connector) during provisioning. */
		onPremisesProvisioningErrors?: OnPremisesProvisioningError[]

	    /** Contains the on-premises security identifier (SID) for the group that was synchronized from on-premises to the cloud. Read-only. */
		onPremisesSecurityIdentifier?: string

	    /** true if this object is synced from an on-premises directory; false if this object was originally synced from an on-premises directory but is no longer synced; null if this object has never been synced from an on-premises directory (default). Read-only. Supports $filter. */
		onPremisesSyncEnabled?: boolean

		preferredDataLocation?: string

		preferredLanguage?: string

	    /** For example: ["SMTP: bob@contoso.com", "smtp: bob@sales.contoso.com"] The any operator is required for filter expressions on multi-valued properties. Read-only. Not nullable. Supports $filter. */
		proxyAddresses?: string[]

	    /** Timestamp of when the group was last renewed. This cannot be modified directly and is only updated via the renew service action. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. Read-only. */
		renewedDateTime?: string

		resourceBehaviorOptions?: string[]

		resourceProvisioningOptions?: string[]

	    /** Specifies whether the group is a security group. If the mailEnabled property is also true, the group is a mail-enabled security group; otherwise it is a security group. Must be false for Office 365 groups. Supports $filter. */
		securityEnabled?: boolean

		theme?: string

	    /** Specifies the visibility of an Office 365 group. Possible values are: Private, Public, HiddenMembership, or empty (which is interpreted as Public). */
		visibility?: string

		accessType?: GroupAccessType

	    /** Default is false. Indicates if people external to the organization can send messages to the group. */
		allowExternalSenders?: boolean

	    /** Default is false. Indicates if new members added to the group will be auto-subscribed to receive email notifications. You can set this property in a PATCH request for the group; do not set it in the initial POST request that creates the group. */
		autoSubscribeNewMembers?: boolean

		isFavorite?: boolean

	    /** Default value is true. Indicates whether the current user is subscribed to receive email conversations. */
		isSubscribedByMail?: boolean

	    /** Count of posts that the current  user has not seen since his last visit. */
		unseenCount?: number

		unseenConversationsCount?: number

		unseenMessagesCount?: number

		isArchived?: boolean

	    /** The collection of open extensions defined for the group. Nullable. */
		extensions?: Extension[]

		appRoleAssignments?: AppRoleAssignment[]

	    /** Users, contacts, and groups that are members of this group. HTTP Methods: GET (supported for all groups), POST (supported for security groups and mail-enabled security groups), DELETE (supported only for security groups) Read-only. Nullable. */
		members?: DirectoryObject[]

	    /** Groups and administrative units that this group is a member of. HTTP Methods: GET (supported for all groups). Read-only. Nullable. */
		memberOf?: DirectoryObject[]

	    /** Read-only. */
		createdOnBehalfOf?: DirectoryObject

	    /** The owners of the group. The owners are a set of non-admin users who are allowed to modify this object. HTTP Methods: GET (supported for all groups), POST (supported for security groups and mail-enabled security groups), DELETE (supported only for security groups) Read-only. Nullable. */
		owners?: DirectoryObject[]

	    /** Settings that can govern this group's behavior, like whether members can invite guest users to the group. Nullable. */
		settings?: DirectorySetting[]

	    /** Endpoints for the group. Read-only. Nullable. */
		endpoints?: Endpoint[]

	    /** The group's conversation threads. Nullable. */
		threads?: ConversationThread[]

	    /** The group's calendar. Read-only. */
		calendar?: Calendar

	    /** The calendar view for the calendar. Read-only. */
		calendarView?: Event[]

	    /** The group's events. */
		events?: Event[]

	    /** The group's conversations. */
		conversations?: Conversation[]

	    /** The group's profile photo. */
		photo?: ProfilePhoto

	    /** The profile photos owned by the group. Read-only. Nullable. */
		photos?: ProfilePhoto[]

	    /** The list of users or groups that are allowed to create post's or calendar events in this group. If this list is non-empty then only users or groups listed here are allowed to post. */
		acceptedSenders?: DirectoryObject[]

	    /** The list of users or groups that are not allowed to create posts or calendar events in this group. Nullable */
		rejectedSenders?: DirectoryObject[]

	    /** The group's drive. Read-only. */
		drive?: Drive

		drives?: Drive[]

	    /** The list of SharePoint sites in this group. Access the default site with /sites/root. */
		sites?: Site[]

	    /** Selective Planner services available to the group. Read-only. Nullable. */
		planner?: PlannerGroup

	    /** Read-only. */
		onenote?: Onenote

		team?: Team

		channels?: Channel[]

		groupLifecyclePolicies?: GroupLifecyclePolicy[]

}

export interface MailFolder extends Entity {

	    /** The mailFolder's display name. */
		displayName?: string

	    /** The unique identifier for the mailFolder's parent mailFolder. */
		parentFolderId?: string

	    /** The number of immediate child mailFolders in the current mailFolder. */
		childFolderCount?: number

	    /** The number of items in the mailFolder marked as unread. */
		unreadItemCount?: number

	    /** The number of items in the mailFolder. */
		totalItemCount?: number

		wellKnownName?: string

	    /** The collection of messages in the mailFolder. */
		messages?: Message[]

	    /** The collection of rules that apply to the user's Inbox folder. */
		messageRules?: MessageRule[]

	    /** The collection of child folders in the mailFolder. */
		childFolders?: MailFolder[]

		userConfigurations?: UserConfiguration[]

	    /** The collection of single-value extended properties defined for the mailFolder. Read-only. Nullable. */
		singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

	    /** The collection of multi-value extended properties defined for the mailFolder. Read-only. Nullable. */
		multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

}

export interface Calendar extends Entity {

	    /** The calendar name. */
		name?: string

	    /** Specifies the color theme to distinguish the calendar from other calendars in a UI. The property values are: LightBlue=0, LightGreen=1, LightOrange=2, LightGray=3, LightYellow=4, LightTeal=5, LightPink=6, LightBrown=7, LightRed=8, MaxColor=9, Auto=-1 */
		color?: CalendarColor

	    /** A color representing the calendar. The color is represented by a 6-digit, 3-byte hexadecimal number. Each byte represents one of the red, green, and blue components of the color, in the range 00 to FF in hexadecimal notation. */
		hexColor?: string

	    /** True if this calendar is the user's default calendar, false otherwise. */
		isDefaultCalendar?: boolean

	    /** Identifies the version of the calendar object. Every time the calendar is changed, changeKey changes as well. This allows Exchange to apply changes to the correct version of the object. Read-only. */
		changeKey?: string

	    /** True if the user has the permission to share the calendar, false otherwise. Only the user who created the calendar can share it. */
		canShare?: boolean

	    /** True if the user can read calendar items that have been marked private, false otherwise. */
		canViewPrivateItems?: boolean

	    /** True if the user has shared the calendar with other users, false otherwise. Since only the user who created the calendar can share it, isShared and isSharedWithMe cannot be true for the same user. */
		isShared?: boolean

	    /** True if the user has been shared this calendar, false otherwise. This property is always false for a calendar owner. */
		isSharedWithMe?: boolean

	    /** True if the user can write to the calendar, false otherwise. This property is true for the user who created the calendar. This property is also true for a user who has been shared a calendar and granted write access. */
		canEdit?: boolean

	    /** If set, this represents the user who created or added the calendar. For a calendar that the user created or added, the owner property is set to the user. For a calendar shared with the user, the owner property is set to the person who shared that calendar with the user. */
		owner?: EmailAddress

	    /** The events in the calendar. Navigation property. Read-only. */
		events?: Event[]

	    /** The calendar view for the calendar. Navigation property. Read-only. */
		calendarView?: Event[]

	    /** The collection of single-value extended properties defined for the calendar. Read-only. Nullable. */
		singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

	    /** The collection of multi-value extended properties defined for the calendar. Read-only. Nullable. */
		multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

}

export interface CalendarGroup extends Entity {

	    /** The group name. */
		name?: string

	    /** The class identifier. Read-only. */
		classId?: string

	    /** Identifies the version of the calendar group. Every time the calendar group is changed, ChangeKey changes as well. This allows Exchange to apply changes to the correct version of the object. Read-only. */
		changeKey?: string

	    /** The calendars in the calendar group. Navigation property. Read-only. Nullable. */
		calendars?: Calendar[]

}

export interface Event extends OutlookItem {

	    /** The start time zone that was set when the event was created. A value of tzone://Microsoft/Custom indicates that a legacy custom time zone was set in desktop Outlook. */
		originalStartTimeZone?: string

	    /** The end time zone that was set when the event was created. A value of tzone://Microsoft/Custom indicates that a legacy custom time zone was set in desktop Outlook. */
		originalEndTimeZone?: string

	    /** Indicates the type of response sent in response to an event message. */
		responseStatus?: ResponseStatus

	    /** A unique identifier that is shared by all instances of an event across different calendars. */
		iCalUId?: string

	    /** The number of minutes before the event start time that the reminder alert occurs. */
		reminderMinutesBeforeStart?: number

	    /** Set to true if an alert is set to remind the user of the event. */
		isReminderOn?: boolean

	    /** Set to true if the event has attachments. */
		hasAttachments?: boolean

	    /** The text of the event's subject line. */
		subject?: string

	    /** The body of the message associated with the event. It can be in HTML or text format. */
		body?: ItemBody

	    /** The preview of the message associated with the event. It is in text format. */
		bodyPreview?: string

	    /** The importance of the event. Possible values are: low, normal, high. */
		importance?: Importance

	    /** Possible values are: normal, personal, private, confidential. */
		sensitivity?: Sensitivity

	    /** The start time of the event. */
		start?: DateTimeTimeZone

	    /** The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		originalStart?: string

	    /** The date and time that the event ends. */
		end?: DateTimeTimeZone

	    /** The location of the event. */
		location?: Location

	    /** The locations where the event is held or attended from. The location and locations properties always correspond with each other. If you update the location property, any prior locations in the locations collection would be removed and replaced by the new location value. */
		locations?: Location[]

	    /** Set to true if the event lasts all day. */
		isAllDay?: boolean

	    /** Set to true if the event has been canceled. */
		isCancelled?: boolean

	    /** Set to true if the message sender is also the organizer. */
		isOrganizer?: boolean

	    /** The recurrence pattern for the event. */
		recurrence?: PatternedRecurrence

	    /** Set to true if the sender would like a response when the event is accepted or declined. */
		responseRequested?: boolean

	    /** The ID for the recurring series master item, if this event is part of a recurring series. */
		seriesMasterId?: string

	    /** The status to show. Possible values are: free, tentative, busy, oof, workingElsewhere, unknown. */
		showAs?: FreeBusyStatus

	    /** The event type. Possible values are: singleInstance, occurrence, exception, seriesMaster. Read-only */
		type?: EventType

	    /** The collection of attendees for the event. */
		attendees?: Attendee[]

	    /** The organizer of the event. */
		organizer?: Recipient

	    /** The URL to open the event in Outlook Web App.The event will open in the browser if you are logged in to your mailbox via Outlook Web App. You will be prompted to login if you are not already logged in with the browser.This URL can be accessed from within an iFrame. */
		webLink?: string

	    /** A URL for an online meeting. */
		onlineMeetingUrl?: string

		creationOptions?: EventCreationOptions

	    /** The calendar that contains the event. Navigation property. Read-only. */
		calendar?: Calendar

	    /** The instances of the event. Navigation property. Read-only. Nullable. */
		instances?: Event[]

	    /** The collection of open extensions defined for the event. Nullable. */
		extensions?: Extension[]

	    /** The collection of FileAttachment, ItemAttachment, and referenceAttachment attachments for the event. Navigation property. Read-only. Nullable. */
		attachments?: Attachment[]

	    /** The collection of single-value extended properties defined for the event. Read-only. Nullable. */
		singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

	    /** The collection of multi-value extended properties defined for the event. Read-only. Nullable. */
		multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

}

export interface Person extends Entity {

	    /** The person's display name. */
		displayName?: string

	    /** The person's given name. */
		givenName?: string

	    /** The person's surname. */
		surname?: string

	    /** The person's birthday. */
		birthday?: string

	    /** Free-form notes that the user has taken about this person. */
		personNotes?: string

	    /** true if the user has flagged this person as a favorite. */
		isFavorite?: boolean

	    /** The person's email addresses. */
		emailAddresses?: RankedEmailAddress[]

	    /** The person's phone numbers. */
		phones?: Phone[]

	    /** The person's addresses. */
		postalAddresses?: Location[]

	    /** The person's websites. */
		websites?: Website[]

	    /** The person's title. */
		title?: string

	    /** The name of the person's company. */
		companyName?: string

	    /** The phonetic Japanese name of the person's company. */
		yomiCompany?: string

	    /** The person's department. */
		department?: string

	    /** The location of the person's office. */
		officeLocation?: string

	    /** The person's profession. */
		profession?: string

	    /** The sources the user data comes from, for example Directory or Outlook Contacts. */
		sources?: PersonDataSource[]

	    /** The type of mailbox that is represented by the person's email address. */
		mailboxType?: string

	    /** The type of person, for example distribution list. */
		personType?: string

	    /** The user principal name (UPN) of the person. The UPN is an Internet-style login name for the person based on the Internet standard RFC 822. By convention, this should map to the person's email name. The general format is alias@domain. */
		userPrincipalName?: string

}

export interface Contact extends OutlookItem {

	    /** The ID of the contact's parent folder. */
		parentFolderId?: string

	    /** The contact's birthday. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		birthday?: string

	    /** The name the contact is filed under. */
		fileAs?: string

	    /** The contact's display name. */
		displayName?: string

	    /** The contact's given name. */
		givenName?: string

	    /** The contact's initials. */
		initials?: string

	    /** The contact's middle name. */
		middleName?: string

	    /** The contact's nickname. */
		nickName?: string

	    /** The contact's surname. */
		surname?: string

	    /** The contact's title. */
		title?: string

	    /** The phonetic Japanese given name (first name) of the contact. */
		yomiGivenName?: string

	    /** The phonetic Japanese surname (last name)  of the contact. */
		yomiSurname?: string

	    /** The phonetic Japanese company name of the contact. */
		yomiCompanyName?: string

	    /** The contact's generation. */
		generation?: string

	    /** The contact's email addresses. */
		emailAddresses?: TypedEmailAddress[]

	    /** Web sites associated with the contact. */
		websites?: Website[]

	    /** The contact's instant messaging (IM) addresses. */
		imAddresses?: string[]

	    /** The contact’s job title. */
		jobTitle?: string

	    /** The name of the contact's company. */
		companyName?: string

	    /** The contact's department. */
		department?: string

	    /** The location of the contact's office. */
		officeLocation?: string

	    /** The contact's profession. */
		profession?: string

	    /** The name of the contact's assistant. */
		assistantName?: string

	    /** The name of the contact's manager. */
		manager?: string

	    /** Phone numbers associated with the contact, for example, home phone, mobile phone, and business phone. */
		phones?: Phone[]

	    /** Addresses associated with the contact, for example, home address and business address. */
		postalAddresses?: PhysicalAddress[]

	    /** The name of the contact's spouse/partner. */
		spouseName?: string

	    /** The user's notes about the contact. */
		personalNotes?: string

	    /** The names of the contact's children. */
		children?: string[]

	    /** The contact's wedding anniversary. */
		weddingAnniversary?: string

	    /** The contact's gender. */
		gender?: string

		isFavorite?: boolean

	    /** The flag value that indicates the status, start date, due date, or completion date for the contact. */
		flag?: FollowupFlag

	    /** The collection of open extensions defined for the contact. Nullable. */
		extensions?: Extension[]

	    /** The collection of single-value extended properties defined for the contact. Read-only. Nullable. */
		singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

	    /** The collection of multi-value extended properties defined for the contact. Read-only. Nullable. */
		multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

	    /** Optional contact picture. You can get or set a photo for a contact. */
		photo?: ProfilePhoto

}

export interface ContactFolder extends Entity {

	    /** The ID of the folder's parent folder. */
		parentFolderId?: string

	    /** The folder's display name. */
		displayName?: string

	    /** The name of the folder if the folder is a recognized folder. Currently contacts is the only recognized contacts folder. */
		wellKnownName?: string

	    /** The contacts in the folder. Navigation property. Read-only. Nullable. */
		contacts?: Contact[]

	    /** The collection of child folders in the folder. Navigation property. Read-only. Nullable. */
		childFolders?: ContactFolder[]

	    /** The collection of single-value extended properties defined for the contactFolder. Read-only. Nullable. */
		singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

	    /** The collection of multi-value extended properties defined for the contactFolder. Read-only. Nullable. */
		multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

}

export interface InferenceClassification extends Entity {

	    /** A set of overrides for a user to always classify messages from specific senders in certain ways: focused, or other. Read-only. Nullable. */
		overrides?: InferenceClassificationOverride[]

}

export interface ProfilePhoto extends Entity {

	    /** The height of the photo. Read-only. */
		height?: number

	    /** The width of the photo. Read-only. */
		width?: number

}

export interface BaseItem extends Entity {

	    /** Identity of the user, device, or application which created the item. Read-only. */
		createdBy?: IdentitySet

	    /** Date and time of item creation. Read-only. */
		createdDateTime?: string

		description?: string

	    /** ETag for the item. Read-only. */
		eTag?: string

	    /** Identity of the user, device, and application which last modified the item. Read-only. */
		lastModifiedBy?: IdentitySet

	    /** Date and time the item was last modified. Read-only. */
		lastModifiedDateTime?: string

	    /** The name of the item. Read-write. */
		name?: string

	    /** Parent information, if the item has a parent. Read-write. */
		parentReference?: ItemReference

	    /** URL that displays the resource in the browser. Read-only. */
		webUrl?: string

		createdByUser?: User

		lastModifiedByUser?: User

}

export interface Drive extends BaseItem {

	    /** Describes the type of drive represented by this resource. OneDrive personal drives will return personal. OneDrive for Business will return business. SharePoint document libraries will return documentLibrary. Read-only. */
		driveType?: string

	    /** Optional. The user account that owns the drive. Read-only. */
		owner?: IdentitySet

	    /** Optional. Information about the drive's storage space quota. Read-only. */
		quota?: Quota

		sharePointIds?: SharepointIds

	    /** If present, indicates that this is a system-managed drive. Read-only. */
		system?: SystemFacet

	    /** The list of recent activities that took place under this drive. */
		activities?: ItemActivity[]

	    /** All items contained in the drive. Read-only. Nullable. */
		items?: DriveItem[]

		list?: List

	    /** The root folder of the drive. Read-only. */
		root?: DriveItem

	    /** Collection of common folders available in OneDrive. Read-only. Nullable. */
		special?: DriveItem[]

}

export interface OfficeGraphInsights extends Entity {

		trending?: Trending[]

		shared?: SharedInsight[]

		used?: UsedInsight[]

}

export interface UserSettings extends Entity {

		contributionToContentDiscoveryDisabled?: boolean

		contributionToContentDiscoveryAsOrganizationDisabled?: boolean

}

export interface PlannerUser extends Entity {

	    /** A collection containing the references to the plans that the user has marked as favorites. */
		favoritePlanReferences?: PlannerFavoritePlanReferenceCollection

	    /** A collection containing references to the plans that were viewed recently by the user in apps that support recent plans. */
		recentPlanReferences?: PlannerRecentPlanReferenceCollection

	    /** Read-only. Nullable. Returns the plannerTasks assigned to the user. */
		tasks?: PlannerTask[]

		plans?: PlannerPlan[]

	    /** Read-only. Nullable. Returns the plannerPlans that the user marked as favorites. */
		favoritePlans?: PlannerPlan[]

	    /** Read-only. Nullable. Returns the plannerPlans that have been recently viewed by the user in apps that support recent plans. */
		recentPlans?: PlannerPlan[]

		all?: PlannerDelta[]

}

export interface Onenote extends Entity {

		notebooks?: Notebook[]

		sections?: OnenoteSection[]

		sectionGroups?: SectionGroup[]

		pages?: OnenotePage[]

		resources?: OnenoteResource[]

		operations?: OnenoteOperation[]

}

export interface ManagedDevice extends Entity {

	    /** Unique Identifier for the user associated with the device */
		userId?: string

	    /** Name of the device */
		deviceName?: string

	    /** The hardward details for the device.  Includes information such as storage space, manufacturer, serial number, etc. */
		hardwareInformation?: HardwareInformation

	    /** Ownership of the device. Can be 'company' or 'personal'. Possible values are: unknown, company, personal. */
		ownerType?: OwnerType

	    /** Ownership of the device. Can be 'company' or 'personal'. Possible values are: unknown, company, personal. */
		managedDeviceOwnerType?: ManagedDeviceOwnerType

	    /** List of ComplexType deviceActionResult objects. */
		deviceActionResults?: DeviceActionResult[]

	    /** Management state of the device. Possible values are: managed, retirePending, retireFailed, wipePending, wipeFailed, unhealthy, deletePending, retireIssued, wipeIssued, wipeCanceled, retireCanceled, discovered. */
		managementState?: ManagementState

	    /** Enrollment time of the device. */
		enrolledDateTime?: string

	    /** The date and time that the device last completed a successful sync with Intune. */
		lastSyncDateTime?: string

	    /** Chassis type of the device. Possible values are: unknown, desktop, laptop, worksWorkstation, enterpriseServer, phone, tablet, mobileOther, mobileUnknown. */
		chassisType?: ChassisType

	    /** Operating system of the device. Windows, iOS, etc. */
		operatingSystem?: string

	    /** Platform of the device. Possible values are: desktop, windowsRT, winMO6, nokia, windowsPhone, mac, winCE, winEmbedded, iPhone, iPad, iPod, android, iSocConsumer, unix, macMDM, holoLens, surfaceHub, androidForWork, androidEnterprise, blackberry, palm, unknown. */
		deviceType?: DeviceType

	    /** Compliance state of the device. Possible values are: unknown, compliant, noncompliant, conflict, error, inGracePeriod, configManager. */
		complianceState?: ComplianceState

	    /** whether the device is jail broken or rooted. */
		jailBroken?: string

	    /** Management channel of the device. Intune, EAS, etc. Possible values are: eas, mdm, easMdm, intuneClient, easIntuneClient, configurationManagerClient, configurationManagerClientMdm, configurationManagerClientMdmEas, unknown, jamf, googleCloudDevicePolicyController. */
		managementAgent?: ManagementAgentType

	    /** Operating system version of the device. */
		osVersion?: string

	    /** Whether the device is Exchange ActiveSync activated. */
		easActivated?: boolean

	    /** Exchange ActiveSync Id of the device. */
		easDeviceId?: string

	    /** Exchange ActivationSync activation time of the device. */
		easActivationDateTime?: string

	    /** Whether the device is Azure Active Directory registered. */
		aadRegistered?: boolean

	    /** Whether the device is Azure Active Directory registered. */
		azureADRegistered?: boolean

	    /** Enrollment type of the device. Possible values are: unknown, userEnrollment, deviceEnrollmentManager, appleBulkWithUser, appleBulkWithoutUser, windowsAzureADJoin, windowsBulkUserless, windowsAutoEnrollment, windowsBulkAzureDomainJoin, windowsCoManagement. */
		deviceEnrollmentType?: DeviceEnrollmentType

	    /** Indicates if Lost mode is enabled or disabled. Possible values are: disabled, enabled. */
		lostModeState?: LostModeState

	    /** Code that allows the Activation Lock on a device to be bypassed. */
		activationLockBypassCode?: string

	    /** Email(s) for the user associated with the device */
		emailAddress?: string

	    /** The unique identifier for the Azure Active Directory device. Read only. */
		azureActiveDirectoryDeviceId?: string

	    /** The unique identifier for the Azure Active Directory device. Read only. */
		azureADDeviceId?: string

	    /** Device registration state. Possible values are: notRegistered, registered, revoked, keyConflict, approvalPending, certificateReset, notRegisteredPendingEnrollment, unknown. */
		deviceRegistrationState?: DeviceRegistrationState

	    /** Device category display name */
		deviceCategoryDisplayName?: string

	    /** Device supervised status */
		isSupervised?: boolean

	    /** Last time the device contacted Exchange. */
		exchangeLastSuccessfulSyncDateTime?: string

	    /** The Access State of the device in Exchange. Possible values are: none, unknown, allowed, blocked, quarantined. */
		exchangeAccessState?: DeviceManagementExchangeAccessState

	    /** The reason for the device's access state in Exchange. Possible values are: none, unknown, exchangeGlobalRule, exchangeIndividualRule, exchangeDeviceRule, exchangeUpgrade, exchangeMailboxPolicy, other, compliant, notCompliant, notEnrolled, unknownLocation, mfaRequired, azureADBlockDueToAccessPolicy, compromisedPassword, deviceNotKnownWithManagedApp. */
		exchangeAccessStateReason?: DeviceManagementExchangeAccessStateReason

	    /** Url that allows a Remote Assistance session to be established with the device. */
		remoteAssistanceSessionUrl?: string

	    /** An error string that identifies issues when creating Remote Assistance session objects. */
		remoteAssistanceSessionErrorDetails?: string

	    /** Device encryption status */
		isEncrypted?: boolean

	    /** Device user principal name */
		userPrincipalName?: string

	    /** Model of the device */
		model?: string

	    /** Manufacturer of the device */
		manufacturer?: string

	    /** IMEI */
		imei?: string

	    /** The DateTime when device compliance grace period expires */
		complianceGracePeriodExpirationDateTime?: string

	    /** SerialNumber */
		serialNumber?: string

	    /** Phone number of the device */
		phoneNumber?: string

	    /** Android security patch level */
		androidSecurityPatchLevel?: string

	    /** User display name */
		userDisplayName?: string

	    /** ConfigrMgr client enabled features */
		configurationManagerClientEnabledFeatures?: ConfigurationManagerClientEnabledFeatures

	    /** Wi-Fi MAC */
		wiFiMacAddress?: string

	    /** The device health attestation state. */
		deviceHealthAttestationState?: DeviceHealthAttestationState

	    /** Subscriber Carrier */
		subscriberCarrier?: string

	    /** MEID */
		meid?: string

	    /** Total Storage in Bytes */
		totalStorageSpaceInBytes?: number

	    /** Free Storage in Bytes */
		freeStorageSpaceInBytes?: number

	    /** Automatically generated name to identify a device. Can be overwritten to a user friendly name. */
		managedDeviceName?: string

	    /** Indicates the threat state of a device when a Mobile Threat Defense partner is in use by the account and device. Read Only. Possible values are: unknown, activated, deactivated, secured, lowSeverity, mediumSeverity, highSeverity, unresponsive. */
		partnerReportedThreatState?: ManagedDevicePartnerReportedHealthState

	    /** Indicates the last logged on users of a device */
		usersLoggedOn?: LoggedOnUser[]

	    /** Reports the DateTime the preferMdmOverGroupPolicy setting was set.  When set, the Intune MDM settings will override Group Policy settings if there is a conflict. Read Only. */
		preferMdmOverGroupPolicyAppliedDateTime?: string

	    /** Reports if the managed device is enrolled via auto-pilot. */
		autopilotEnrolled?: boolean

	    /** Reports if the managed iOS device is user approval enrollment. */
		requireUserEnrollmentApproval?: boolean

	    /** Reports device management certificate expiration date */
		managementCertificateExpirationDate?: string

	    /** Integrated Circuit Card Identifier, it is A SIM card's unique identification number. */
		iccid?: string

	    /** Unique Device Identifier for iOS and macOS devices. */
		udid?: string

		roleScopeTagIds?: string[]

		windowsActiveMalwareCount?: number

		windowsRemediatedMalwareCount?: number

		notes?: string

		configurationManagerClientHealthState?: ConfigurationManagerClientHealthState

		deviceConfigurationStates?: DeviceConfigurationState[]

	    /** All applications currently installed on the device */
		detectedApps?: DetectedApp[]

	    /** Device category */
		deviceCategory?: DeviceCategory

	    /** The device protection status. */
		windowsProtectionState?: WindowsProtectionState

		deviceCompliancePolicyStates?: DeviceCompliancePolicyState[]

		managedDeviceMobileAppConfigurationStates?: ManagedDeviceMobileAppConfigurationState[]

}

export interface DeviceEnrollmentConfiguration extends Entity {

	    /** Not yet documented */
		displayName?: string

	    /** Not yet documented */
		description?: string

	    /** Not yet documented */
		priority?: number

	    /** Not yet documented */
		createdDateTime?: string

	    /** Not yet documented */
		lastModifiedDateTime?: string

	    /** Not yet documented */
		version?: number

	    /** The list of group assignments for the device configuration profile. */
		assignments?: EnrollmentConfigurationAssignment[]

}

export interface ManagedAppRegistration extends Entity {

	    /** Date and time of creation */
		createdDateTime?: string

	    /** Date and time of last the app synced with management service. */
		lastSyncDateTime?: string

	    /** App version */
		applicationVersion?: string

	    /** App management SDK version */
		managementSdkVersion?: string

	    /** Operating System version */
		platformVersion?: string

	    /** Host device type */
		deviceType?: string

	    /** App management SDK generated tag, which helps relate apps hosted on the same device. Not guaranteed to relate apps in all conditions. */
		deviceTag?: string

	    /** Host device name */
		deviceName?: string

	    /** The Managed Device identifier of the host device. Value could be empty even when the host device is managed. */
		managedDeviceId?: string

	    /** The Azure Active Directory Device identifier of the host device. Value could be empty even when the host device is Azure Active Directory registered. */
		azureADDeviceId?: string

	    /** Zero or more reasons an app registration is flagged. E.g. app running on rooted device */
		flaggedReasons?: ManagedAppFlaggedReason[]

	    /** The user Id to who this app registration belongs. */
		userId?: string

	    /** The app package Identifier */
		appIdentifier?: MobileAppIdentifier

	    /** Version of the entity. */
		version?: string

	    /** Zero or more policys already applied on the registered app when it last synchronized with managment service. */
		appliedPolicies?: ManagedAppPolicy[]

	    /** Zero or more policies admin intended for the app as of now. */
		intendedPolicies?: ManagedAppPolicy[]

	    /** Zero or more long running operations triggered on the app registration. */
		operations?: ManagedAppOperation[]

}

export interface Device extends DirectoryObject {

	    /** true if the account is enabled; otherwise, false. default is true. */
		accountEnabled?: boolean

		alternativeSecurityIds?: AlternativeSecurityId[]

	    /** The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. Read-only. */
		approximateLastSignInDateTime?: string

		complianceExpirationDateTime?: string

	    /** Unique identifier set by Azure Device Registration Service at the time of registration. */
		deviceId?: string

	    /** For internal use only. Set to null. */
		deviceMetadata?: string

	    /** For internal use only. */
		deviceVersion?: number

	    /** The display name for the device. Required. */
		displayName?: string

	    /** true if the device complies with Mobile Device Management (MDM) policies; otherwise, false. Read-only. */
		isCompliant?: boolean

	    /** true if the device is managed by a Mobile Device Management (MDM) app; otherwise, false. */
		isManaged?: boolean

	    /** The last time at which the object was synced with the on-premises directory.The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' Read-only. */
		onPremisesLastSyncDateTime?: string

	    /** true if this object is synced from an on-premises directory; false if this object was originally synced from an on-premises directory but is no longer synced; null if this object has never been synced from an on-premises directory (default). Read-only. */
		onPremisesSyncEnabled?: boolean

	    /** The type of operating system on the device. Required. */
		operatingSystem?: string

	    /** Operating system version of the device. Required. */
		operatingSystemVersion?: string

	    /** For internal use only. Not nullable. */
		physicalIds?: string[]

		profileType?: string

		systemLabels?: string

	    /** Type of trust for the joined device. Read-only. Possible values: Workplace - indicates bring your own personal devicesAzureAd - Cloud only joined devicesServerAd - on-premises domain joined devices joined to Azure AD. For more details, see Introduction to device management in Azure Active Directory */
		trustType?: string

	    /** Friendly name of a device. Only returned if user signs in with a Microsoft account as part of Project Rome. */
		Name?: string

	    /** Manufacturer of device. Only returned if user signs in with a Microsoft account as part of Project Rome. */
		Manufacturer?: string

	    /** Model of device. Only returned if user signs in with a Microsoft account as part of Project Rome. */
		Model?: string

	    /** Form factor of device. Only returned if user signs in with a Microsoft account as part of Project Rome. */
		Kind?: string

	    /** Device is online or offline. Only returned if user signs in with a Microsoft account as part of Project Rome. */
		Status?: string

	    /** Platform of device. Only returned if user signs in with a Microsoft account as part of Project Rome. Only returned if user signs in with a Microsoft account as part of Project Rome. */
		Platform?: string

	    /** The collection of open extensions defined for the device. Read-only. Nullable. */
		extensions?: Extension[]

	    /** The user that cloud joined the device or registered their personal device. The registered owner is set at the time of registration. Currently, there can be only one owner. Read-only. Nullable. */
		registeredOwners?: DirectoryObject[]

	    /** Collection of registered users of the device. For cloud joined devices and registered personal devices, registered users are set to the same value as registered owners at the time of registration. Read-only. Nullable. */
		registeredUsers?: DirectoryObject[]

	    /** Set of commands sent to this device */
		commands?: Command[]

}

export interface DeviceManagementTroubleshootingEvent extends Entity {

	    /** Time when the event occurred . */
		eventDateTime?: string

	    /** Id used for tracing the failure in the service. */
		correlationId?: string

}

export interface MobileAppIntentAndState extends Entity {

	    /** Device identifier created or collected by Intune. */
		managedDeviceIdentifier?: string

	    /** Identifier for the user that tried to enroll the device. */
		userId?: string

	    /** The list of payload intents and states for the tenant. */
		mobileAppList?: MobileAppIntentAndStateDetail[]

}

export interface MobileAppTroubleshootingEvent extends DeviceManagementTroubleshootingEvent {

	    /** Device identifier created or collected by Intune. */
		managedDeviceIdentifier?: string

	    /** Identifier for the user that tried to enroll the device. */
		userId?: string

	    /** Intune application identifier. */
		applicationId?: string

	    /** Intune Mobile Application Troubleshooting History Item */
		history?: MobileAppTroubleshootingHistoryItem[]

}

export interface AgreementAcceptance extends Entity {

	    /** ID of the agreement. */
		agreementId?: string

	    /** ID of the user who accepted the agreement. */
		userId?: string

	    /** ID of the agreement file accepted by the user. */
		agreementFileId?: string

	    /** The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		recordedDateTime?: string

	    /** Display name of the user when the acceptance was recorded. */
		userDisplayName?: string

	    /** UPN of the user when the acceptance was recorded. */
		userPrincipalName?: string

	    /** Email of the user when the acceptance was recorded. */
		userEmail?: string

	    /** Possible values are: accepted, declined. */
		state?: AgreementAcceptanceState

}

export interface Notification extends Entity {

		targetHostName?: string

		expirationDateTime?: string

		payload?: PayloadTypes

		displayTimeToLive?: number

		priority?: Priority

		groupName?: string

		targetPolicy?: TargetPolicyEndpoints

}

export interface DirectorySetting extends Entity {

	    /** Display name of this group of settings, which comes from the associated template. Read-only. */
		displayName?: string

	    /** Unique identifier for the template used to create this group of settings. Read-only. */
		templateId?: string

	    /** Collection of name value pairs. Must contain and set all the settings defined in the template. */
		values?: SettingValue[]

}

export interface Endpoint extends DirectoryObject {

		capability?: string

		providerId?: string

		providerName?: string

		uri?: string

		providerResourceId?: string

}

export interface ConversationThread extends Entity {

	    /** The To: recipients for the thread. */
		toRecipients?: Recipient[]

	    /** The topic of the conversation. This property can be set when the conversation is created, but it cannot be updated. */
		topic?: string

	    /** Indicates whether any of the posts within this thread has at least one attachment. */
		hasAttachments?: boolean

	    /** The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		lastDeliveredDateTime?: string

	    /** All the users that sent a message to this thread. */
		uniqueSenders?: string[]

	    /** The Cc: recipients for the thread. */
		ccRecipients?: Recipient[]

	    /** A short summary from the body of the latest post in this converstaion. */
		preview?: string

	    /** Indicates if the thread is locked. */
		isLocked?: boolean

	    /** Read-only. Nullable. */
		posts?: Post[]

}

export interface Conversation extends Entity {

	    /** The topic of the conversation. This property can be set when the conversation is created, but it cannot be updated. */
		topic?: string

	    /** Indicates whether any of the posts within this Conversation has at least one attachment. */
		hasAttachments?: boolean

	    /** The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		lastDeliveredDateTime?: string

	    /** All the users that sent a message to this Conversation. */
		uniqueSenders?: string[]

	    /** A short summary from the body of the latest post in this converstaion. */
		preview?: string

	    /** A collection of all the conversation threads in the conversation. A navigation property. Read-only. Nullable. */
		threads?: ConversationThread[]

}

export interface Site extends BaseItem {

	    /** The full title for the site. Read-only. */
		displayName?: string

	    /** If present, indicates that this is the root site in the site collection. Read-only. */
		root?: Root

	    /** Returns identifiers useful for SharePoint REST compatibility. Read-only. */
		sharepointIds?: SharepointIds

	    /** Provides details about the site's site collection. Available only on the root site. Read-only. */
		siteCollection?: SiteCollection

	    /** The collection of column definitions reusable across lists under this site. */
		columns?: ColumnDefinition[]

	    /** The collection of content types defined for this site. */
		contentTypes?: ContentType[]

	    /** The default drive (document library) for this site. */
		drive?: Drive

	    /** The collection of drives (document libraries) under this site. */
		drives?: Drive[]

	    /** Used to address any item contained in this site. This collection cannot be enumerated. */
		items?: BaseItem[]

	    /** The collection of lists under this site. */
		lists?: List[]

	    /** The collection of the sub-sites under this site. */
		sites?: Site[]

	    /** Calls the OneNote service for notebook related operations. */
		onenote?: Onenote

}

export interface PlannerGroup extends Entity {

	    /** Read-only. Nullable. Returns the plannerPlans owned by the group. */
		plans?: PlannerPlan[]

}

export interface Team extends Entity {

	    /** A hyperlink that will go to the team in the Microsoft Teams client. This is the URL that you get when you right-click a team in the Microsoft Teams client and select Get link to team. This URL should be treated as an opaque blob, and not parsed. */
		webUrl?: string

	    /** Settings to configure whether members can perform certain actions, for example, create channels and add bots, in the team. */
		memberSettings?: TeamMemberSettings

	    /** Settings to configure whether guests can create, update, or delete channels in the team. */
		guestSettings?: TeamGuestSettings

	    /** Settings to configure messaging and mentions in the team. */
		messagingSettings?: TeamMessagingSettings

	    /** Settings to configure use of Giphy, memes, and stickers in the team. */
		funSettings?: TeamFunSettings

		isArchived?: boolean

	    /** The collection of channels associated with the team. */
		channels?: Channel[]

		apps?: TeamsCatalogApp[]

		operations?: TeamsAsyncOperation[]

}

export interface Channel extends Entity {

	    /** Channel name as it will appear to the user in Microsoft Teams. */
		displayName?: string

	    /** Optional textual description for the channel. */
		description?: string

		messages?: ChatMessage[]

	    /** A collection of all the chat threads in the channel. A navigation property. Nullable. */
		chatThreads?: ChatThread[]

}

export interface GroupLifecyclePolicy extends Entity {

	    /** Number of days before a group expires and needs to be renewed. Once renewed, the group expiration is extended by the number of days defined. */
		groupLifetimeInDays?: number

	    /** The group type for which the expiration policy applies. Possible values are All, Selected or None. */
		managedGroupTypes?: string

	    /** List of email address to send notifications for groups without owners. Multiple email address can be defined by separating email address with a semicolon. */
		alternateNotificationEmails?: string

}

export interface Command extends Entity {

		Status?: string

		Type?: string

		AppServiceName?: string

		PackageFamilyName?: string

		Error?: string

		Payload?: PayloadRequest

		PermissionTicket?: string

		PostBackUri?: string

		responsepayload?: PayloadResponse

}

export interface AdministrativeUnit extends DirectoryObject {

	    /** Display name for the administrative unit. */
		displayName?: string

	    /** An optional description for the administrative unit. */
		description?: string

	    /** Controls whether the adminstrative unit and its members are hidden or public. Can be set to HiddenMembership or Public. If not set, default behavior is Public. When set to HiddenMembership, only members of the administrative unit can list other members of the adminstrative unit. */
		visibility?: string

	    /** The collection of open extensions defined for this Administrative Unit. Nullable. */
		extensions?: Extension[]

	    /** Users and groups that are members of this Adminsitrative Unit. HTTP Methods: GET (list members), POST (add members), DELETE (remove members). */
		members?: DirectoryObject[]

	    /** Scoped-role members of this Administrative Unit.  HTTP Methods: GET (list scopedRoleMemberships), POST (add scopedRoleMembership), DELETE (remove scopedRoleMembership). */
		scopedRoleMembers?: ScopedRoleMembership[]

}

export interface Organization extends DirectoryObject {

	    /** The collection of service plans associated with the tenant. Not nullable. */
		assignedPlans?: AssignedPlan[]

		businessPhones?: string[]

	    /** City name of the address for the organization */
		city?: string

	    /** Country/region name of the address for the organization */
		country?: string

	    /** Country/region abbreviation for the organization */
		countryLetterCode?: string

	    /** The display name for the tenant. */
		displayName?: string

		isMultipleDataLocationsForServicesEnabled?: boolean

	    /** Not nullable. */
		marketingNotificationEmails?: string[]

		onPremisesLastSyncDateTime?: string

		onPremisesSyncEnabled?: boolean

	    /** Postal code of the address for the organization */
		postalCode?: string

	    /** The preferred language for the organization. Should follow ISO 639-1 Code; for example "en". */
		preferredLanguage?: string

	    /** The privacy profile of an organization. */
		privacyProfile?: PrivacyProfile

	    /** Not nullable. */
		provisionedPlans?: ProvisionedPlan[]

		securityComplianceNotificationMails?: string[]

		securityComplianceNotificationPhones?: string[]

	    /** State name of the address for the organization */
		state?: string

	    /** Street name of the address for organization */
		street?: string

	    /** Not nullable. */
		technicalNotificationMails?: string[]

	    /** The collection of domains associated with this tenant. Not nullable. */
		verifiedDomains?: VerifiedDomain[]

	    /** Mobile device management authority. Possible values are: unknown, intune, sccm, office365. */
		mobileDeviceManagementAuthority?: MdmAuthority

	    /** Certificate connector setting. */
		certificateConnectorSetting?: CertificateConnectorSetting

		extensions?: Extension[]

}

export interface SchemaExtension extends Entity {

	    /** Description for the schema extension. */
		description?: string

	    /** Set of Microsoft Graph types (that can support extensions) that the schema extension can be applied to. Select from administrativeUnit, contact, device, event, group, message, organization, post, or user. */
		targetTypes?: string[]

	    /** The collection of property names and types that make up the schema extension definition. */
		properties?: ExtensionSchemaProperty[]

	    /** The lifecycle state of the schema extension. Possible states are InDevelopment, Available, and Deprecated. Automatically set to InDevelopment on creation. Schema extensions provides more information on the possible state transitions and behaviors. */
		status?: string

	    /** The appId of the application that is the owner of the schema extension. This property can be supplied on creation, to set the owner.  If not supplied, then the calling application's appId will be set as the owner. In either case, the signed-in user must be the owner of the application. Once set, this property is read-only and cannot be changed. */
		owner?: string

}

export interface Directory extends Entity {

		deletedItems?: DirectoryObject[]

}

export interface ExtensionProperty extends DirectoryObject {

		appDisplayName?: string

		name?: string

		dataType?: string

		isSyncedFromOnPremises?: boolean

		targetObjects?: string[]

}

export interface AllowedDataLocation extends Entity {

		appId?: string

		location?: string

		isDefault?: boolean

		domain?: string

}

export interface Application extends DirectoryObject {

	    /** Specifies settings for an API application. */
		api?: ApiApplication

		appId?: string

		appRoles?: AppRole[]

	    /** The date and time the application was registered. */
		createdDateTime?: string

		isFallbackPublicClient?: boolean

		identifierUris?: string[]

	    /** The display name for the application. */
		displayName?: string

	    /** Basic profile information of the application. */
		info?: InformationalUrl

	    /** The collection of key credentials associated with the application Not nullable. */
		keyCredentials?: KeyCredential[]

	    /** The main logo for the application. Not nullable. */
		logo?: any

		optionalClaims?: OptionalClaims

	    /** The organizational tenantIds to which the application is restricted.  If the collection is empty, the application is multi-tenant (not restricted). If the collection contains tenantIds, the application is restricted to the organizational tenantIds in the collection. Specifying other tenants but not the tenantId where the application is registered implies that the application's own tenantId is indirectly included. */
		orgRestrictions?: string[]

		parentalControlSettings?: ParentalControlSettings

	    /** The collection of password credentials associated with the application. Not nullable. */
		passwordCredentials?: PasswordCredential[]

		publicClient?: PublicClientApplication

		publisherDomain?: string

	    /** Specifies resources that this application requires access to and the set of OAuth permission scopes and application roles that it needs under each of those resources. This pre-configuration of required resource access drives the consent experience. Not nullable. */
		requiredResourceAccess?: RequiredResourceAccess[]

		signInAudience?: string

	    /** Custom strings that can be used to categorize and identify the application. */
		tags?: string[]

		tokenEncryptionKeyId?: string

	    /** Specifies settings for a web application. */
		web?: WebApplication

		extensionProperties?: ExtensionProperty[]

	    /** Read-only. */
		createdOnBehalfOf?: DirectoryObject

	    /** Directory objects that are owners of the application. The owners are a set of non-admin users who are allowed to modify this object. Requires version 2013-11-08 or newer.  Read-only. Nullable. */
		owners?: DirectoryObject[]

		policies?: DirectoryObject[]

		synchronization?: Synchronization

}

export interface Synchronization extends Entity {

		secrets?: SynchronizationSecretKeyStringValuePair[]

		jobs?: SynchronizationJob[]

		templates?: SynchronizationTemplate[]

}

export interface OrgContact extends DirectoryObject {

		businessPhones?: string[]

		city?: string

		companyName?: string

		country?: string

		department?: string

		displayName?: string

		givenName?: string

		jobTitle?: string

		mail?: string

		mailNickname?: string

		mobilePhone?: string

		onPremisesSyncEnabled?: boolean

		onPremisesLastSyncDateTime?: string

		onPremisesProvisioningErrors?: OnPremisesProvisioningError[]

		officeLocation?: string

		postalCode?: string

		proxyAddresses?: string[]

		state?: string

		streetAddress?: string

		surname?: string

		manager?: DirectoryObject

		directReports?: DirectoryObject[]

		memberOf?: DirectoryObject[]

}

export interface DirectoryRole extends DirectoryObject {

	    /** The description for the directory role. Read-only. */
		description?: string

	    /** The display name for the directory role. Read-only. */
		displayName?: string

	    /** The id of the directoryRoleTemplate that this role is based on. The property must be specified when activating a directory role in a tenant with a POST operation. After the directory role has been activated, the property is read only. */
		roleTemplateId?: string

	    /** Users that are members of this directory role. HTTP Methods: GET, POST, DELETE. Read-only. Nullable. */
		members?: DirectoryObject[]

	    /** Members of this directory role that are scoped to administrative units. Read-only. Nullable. */
		scopedMembers?: ScopedRoleMembership[]

}

export interface DirectoryRoleTemplate extends DirectoryObject {

	    /** The description to set for the directory role. Read-only. */
		description?: string

	    /** The display name to set for the directory role. Read-only. */
		displayName?: string

}

export interface DirectorySettingTemplate extends DirectoryObject {

	    /** Display name of the template. Read-only. */
		displayName?: string

	    /** Description of the template. Read-only. */
		description?: string

	    /** Collection of settingTemplateValues that list the set of available settings, defaults and types that make up this template.  Read-only. */
		values?: SettingTemplateValue[]

}

export interface Domain extends Entity {

	    /** Indicates the configured authentication type for the domain. The value is either Managed or Federated. Managed indicates a cloud managed domain where Azure AD performs user authentication.Federated indicates authentication is federated with an identity provider such as the tenant's on-premises Active Directory via Active Directory Federation Services. Not nullable */
		authenticationType?: string

	    /** This property is always null except when the verify action is used. When the verify action is used, a domain entity is returned in the response. The availabilityStatus property of the domain entity in the response is either AvailableImmediately or EmailVerifiedDomainTakeoverScheduled. */
		availabilityStatus?: string

	    /** The value of the property is false if the DNS record management of the domain has been delegated to Office 365. Otherwise, the value is true. Not nullable */
		isAdminManaged?: boolean

	    /** True if this is the default domain that is used for user creation. There is only one default domain per company. Not nullable */
		isDefault?: boolean

	    /** True if this is the initial domain created by Microsoft Online Services (companyname.onmicrosoft.com). There is only one initial domain per company. Not nullable */
		isInitial?: boolean

	    /** True if the domain is a verified root domain. Otherwise, false if the domain is a subdomain or unverified. Not nullable */
		isRoot?: boolean

	    /** True if the domain has completed domain ownership verification. Not nullable */
		isVerified?: boolean

	    /** The capabilities assigned to the domain.Can include 0, 1 or more of following values: Email, Sharepoint, EmailInternalRelayOnly, OfficeCommunicationsOnline, SharePointDefaultDomain, FullRedelegation, SharePointPublic, OrgIdAuthentication, Yammer, Intune The values which you can add/remove using Graph API include: Email, OfficeCommunicationsOnline, YammerNot nullable */
		supportedServices?: string[]

	    /** Status of asynchronous operations scheduled for the domain. */
		state?: DomainState

	    /** DNS records the customer adds to the DNS zone file of the domain before the domain can be used by Microsoft Online services.Read-only, Nullable */
		serviceConfigurationRecords?: DomainDnsRecord[]

	    /** DNS records that the customer adds to the DNS zone file of the domain before the customer can complete domain ownership verification with Azure AD.Read-only, Nullable */
		verificationDnsRecords?: DomainDnsRecord[]

	    /** Read-only, Nullable */
		domainNameReferences?: DirectoryObject[]

}

export interface DomainDnsRecord extends Entity {

	    /** If false, this record must be configured by the customer at the DNS host for Microsoft Online Services to operate correctly with the domain. */
		isOptional?: boolean

	    /** Value used when configuring the name of the DNS record at the DNS host. */
		label?: string

	    /** Indicates what type of DNS record this entity represents.The value can be one of the following: CName, Mx, Srv, TxtKey */
		recordType?: string

	    /** Microsoft Online Service or feature that has a dependency on this DNS record.Can be one of the following values: null, Email, Sharepoint, EmailInternalRelayOnly, OfficeCommunicationsOnline, SharePointDefaultDomain, FullRedelegation, SharePointPublic, OrgIdAuthentication, Yammer, Intune */
		supportedService?: string

	    /** Value to use when configuring the time-to-live (ttl) property of the DNS record at the DNS host. Not nullable */
		ttl?: number

}

export interface DomainDnsCnameRecord extends DomainDnsRecord {

	    /** The canonical name of the CNAME record. Used to configure the CNAME record at the DNS host. */
		canonicalName?: string

}

export interface DomainDnsMxRecord extends DomainDnsRecord {

	    /** Value used when configuring the answer/destination/value of the MX record at the DNS host. */
		mailExchange?: string

	    /** Value used when configuring the Preference/Priority property of the MX record at the DNS host. */
		preference?: number

}

export interface DomainDnsSrvRecord extends DomainDnsRecord {

	    /** Value to use when configuring the Target property of the SRV record at the DNS host. */
		nameTarget?: string

	    /** Value to use when configuring the port property of the SRV record at the DNS host. */
		port?: number

	    /** Value to use when configuring the priority property of the SRV record at the DNS host. */
		priority?: number

	    /** Value to use when configuring the protocol property of the SRV record at the DNS host. */
		protocol?: string

	    /** Value to use when configuring the service property of the SRV record at the DNS host. */
		service?: string

	    /** Value to use when configuring the weight property of the SRV record at the DNS host. */
		weight?: number

}

export interface DomainDnsTxtRecord extends DomainDnsRecord {

	    /** Value used when configuring the text property at the DNS host. */
		text?: string

}

export interface DomainDnsUnavailableRecord extends DomainDnsRecord {

	    /** Provides the reason why the DomainDnsUnavailableRecord entity is returned. */
		description?: string

}

export interface OAuth2PermissionGrant extends Entity {

		clientId?: string

		consentType?: string

		expiryTime?: string

		principalId?: string

		resourceId?: string

		scope?: string

		startTime?: string

}

export interface Policy extends DirectoryObject {

		alternativeIdentifier?: string

		definition?: string[]

		displayName?: string

		isOrganizationDefault?: boolean

		keyCredentials?: KeyCredential[]

		type?: string

		appliesTo?: DirectoryObject[]

}

export interface ServicePrincipal extends DirectoryObject {

		accountEnabled?: boolean

		addIns?: AddIn[]

		appDisplayName?: string

		appId?: string

		appOwnerOrganizationId?: string

		appRoleAssignmentRequired?: boolean

		appRoles?: AppRole[]

		displayName?: string

		errorUrl?: string

		homepage?: string

		keyCredentials?: KeyCredential[]

		logoutUrl?: string

		oauth2Permissions?: OAuth2Permission[]

		passwordCredentials?: PasswordCredential[]

		preferredTokenSigningKeyThumbprint?: string

		publisherName?: string

		replyUrls?: string[]

		samlMetadataUrl?: string

		servicePrincipalNames?: string[]

		tags?: string[]

		appRoleAssignedTo?: AppRoleAssignment[]

		appRoleAssignments?: AppRoleAssignment[]

		oauth2PermissionGrants?: OAuth2PermissionGrant[]

		memberOf?: DirectoryObject[]

		createdObjects?: DirectoryObject[]

		licenseDetails?: LicenseDetails[]

		owners?: DirectoryObject[]

		ownedObjects?: DirectoryObject[]

		policies?: DirectoryObject[]

		synchronization?: Synchronization

}

export interface SubscribedSku extends Entity {

	    /** For example, "Enabled". */
		capabilityStatus?: string

	    /** The number of licenses that have been assigned. */
		consumedUnits?: number

	    /** Information about the number and status of prepaid licenses. */
		prepaidUnits?: LicenseUnitsDetail

	    /** Information about the service plans that are available with the SKU. Not nullable */
		servicePlans?: ServicePlanInfo[]

	    /** The unique identifier (GUID) for the service SKU. */
		skuId?: string

	    /** The SKU part number; for example: "AAD_PREMIUM" or "RMSBASIC". */
		skuPartNumber?: string

	    /** For example, "User" or "Company". */
		appliesTo?: string

}

export interface Contract extends DirectoryObject {

		contractType?: string

		customerId?: string

		defaultDomainName?: string

		displayName?: string

}

export interface ActivityHistoryItem extends Entity {

		status?: Status

		activeDurationSeconds?: number

		createdDateTime?: string

		lastActiveDateTime?: string

		lastModifiedDateTime?: string

		expirationDateTime?: string

		startedDateTime?: string

		userTimezone?: string

		activity?: UserActivity

}

export interface ColumnDefinition extends Entity {

	    /** This column stores boolean values. */
		boolean?: BooleanColumn

	    /** This column's data is calculated based on other columns. */
		calculated?: CalculatedColumn

	    /** This column stores data from a list of choices. */
		choice?: ChoiceColumn

	    /** For site columns, the name of the group this column belongs to. Helps organize related columns. */
		columnGroup?: string

	    /** This column stores currency values. */
		currency?: CurrencyColumn

	    /** This column stores DateTime values. */
		dateTime?: DateTimeColumn

	    /** The default value for this column. */
		defaultValue?: DefaultColumnValue

	    /** The user-facing description of the column. */
		description?: string

	    /** The user-facing name of the column. */
		displayName?: string

	    /** If true, no two list items may have the same value for this column. */
		enforceUniqueValues?: boolean

	    /** Specifies whether the column is displayed in the user interface. */
		hidden?: boolean

	    /** Specifies whether the column values can used for sorting and searching. */
		indexed?: boolean

	    /** This column's data is looked up from another source in the site. */
		lookup?: LookupColumn

	    /** The API-facing name of the column as it appears in the [fields][] on a [listItem][]. For the user-facing name, see displayName. */
		name?: string

	    /** This column stores number values. */
		number?: NumberColumn

	    /** This column stores Person or Group values. */
		personOrGroup?: PersonOrGroupColumn

	    /** Specifies whether the column values can be modified. */
		readOnly?: boolean

	    /** Specifies whether the column value is not optional. */
		required?: boolean

	    /** This column stores text values. */
		text?: TextColumn

}

export interface ContentType extends Entity {

	    /** The descriptive text for the item. */
		description?: string

	    /** The name of the group this content type belongs to. Helps organize related content types. */
		group?: string

	    /** Indicates whether the content type is hidden in the list's 'New' menu. */
		hidden?: boolean

	    /** If this content type is inherited from another scope (like a site), provides a reference to the item where the content type is defined. */
		inheritedFrom?: ItemReference

	    /** The name of the content type. */
		name?: string

	    /** Specifies the order in which the content type appears in the selection UI. */
		order?: ContentTypeOrder

	    /** The unique identifier of the content type. */
		parentId?: string

	    /** If true, the content type cannot be modified unless this value is first set to false. */
		readOnly?: boolean

	    /** If true, the content type cannot be modified by users or through push-down operations. Only site collection administrators can seal or unseal content types. */
		sealed?: boolean

	    /** The collection of columns that are required by this content type */
		columnLinks?: ColumnLink[]

}

export interface List extends BaseItem {

	    /** The displayable title of the list. */
		displayName?: string

	    /** Provides additional details about the list. */
		list?: ListInfo

		sharepointIds?: SharepointIds

	    /** If present, indicates that this is a system-managed list. Read-only. */
		system?: SystemFacet

	    /** The recent activities that took place within this list. */
		activities?: ItemActivity[]

		columns?: ColumnDefinition[]

		contentTypes?: ContentType[]

	    /** Only present on document libraries. Allows access to the list as a [drive][] resource with [driveItems][driveItem]. */
		drive?: Drive

	    /** All items contained in the list. */
		items?: ListItem[]

}

export interface ItemActivity extends Entity {

	    /** Details about the action that took place. Read-only. */
		action?: ItemActionSet

	    /** Identity of who performed the action. Read-only. */
		actor?: IdentitySet

	    /** Details about when the activity took place. Read-only. */
		times?: ItemActivityTimeSet

	    /** Exposes the driveItem that was the target of this activity. */
		driveItem?: DriveItem

	    /** Exposes the listItem that was the target of this activity. */
		listItem?: ListItem

}

export interface ListItem extends BaseItem {

	    /** The content type of this list item */
		contentType?: ContentTypeInfo

		sharepointIds?: SharepointIds

	    /** The list of recent activities that took place on this item. */
		activities?: ItemActivity[]

	    /** For document libraries, the driveItem relationship exposes the listItem as a [driveItem][] */
		driveItem?: DriveItem

		fields?: FieldValueSet

	    /** The list of previous versions of the list item. */
		versions?: ListItemVersion[]

}

export interface DriveItem extends BaseItem {

	    /** Audio metadata, if the item is an audio file. Read-only. */
		audio?: Audio

		content?: any

	    /** An eTag for the content of the item. This eTag is not changed if only the metadata is changed. Note This property is not returned if the item is a folder. Read-only. */
		cTag?: string

	    /** Information about the deleted state of the item. Read-only. */
		deleted?: Deleted

	    /** File metadata, if the item is a file. Read-only. */
		file?: File

	    /** File system information on client. Read-write. */
		fileSystemInfo?: FileSystemInfo

	    /** Folder metadata, if the item is a folder. Read-only. */
		folder?: Folder

	    /** Image metadata, if the item is an image. Read-only. */
		image?: Image

	    /** Location metadata, if the item has location data. Read-only. */
		location?: GeoCoordinates

	    /** If present, indicates that this item is a package instead of a folder or file. Packages are treated like files in some contexts and folders in others. Read-only. */
		package?: Package

	    /** Photo metadata, if the item is a photo. Read-only. */
		photo?: Photo

		publication?: PublicationFacet

	    /** Remote item data, if the item is shared from a drive other than the one being accessed. Read-only. */
		remoteItem?: RemoteItem

	    /** If this property is non-null, it indicates that the driveItem is the top-most driveItem in the drive. */
		root?: Root

	    /** Search metadata, if the item is from a search result. Read-only. */
		searchResult?: SearchResult

	    /** Indicates that the item has been shared with others and provides information about the shared state of the item. Read-only. */
		shared?: Shared

	    /** Returns identifiers useful for SharePoint REST compatibility. Read-only. */
		sharepointIds?: SharepointIds

	    /** Size of the item in bytes. Read-only. */
		size?: number

	    /** If the current item is also available as a special folder, this facet is returned. Read-only. */
		specialFolder?: SpecialFolder

	    /** Video metadata, if the item is a video. Read-only. */
		video?: Video

	    /** WebDAV compatible URL for the item. */
		webDavUrl?: string

		workbook?: Workbook

	    /** The list of recent activities that took place on this item. */
		activities?: ItemActivity[]

	    /** Collection containing Item objects for the immediate children of Item. Only items representing folders have children. Read-only. Nullable. */
		children?: DriveItem[]

		listItem?: ListItem

	    /** The set of permissions for the item. Read-only. Nullable. */
		permissions?: Permission[]

		subscriptions?: Subscription[]

	    /** Collection containing [ThumbnailSet][] objects associated with the item. For more info, see [getting thumbnails][]. Read-only. Nullable. */
		thumbnails?: ThumbnailSet[]

	    /** The list of previous versions of the item. For more info, see [getting previous versions][]. Read-only. Nullable. */
		versions?: DriveItemVersion[]

}

export interface Workbook extends Entity {

		application?: WorkbookApplication

		names?: WorkbookNamedItem[]

		tables?: WorkbookTable[]

		worksheets?: WorkbookWorksheet[]

		functions?: WorkbookFunctions

}

export interface Permission extends Entity {

		expirationDateTime?: string

	    /** For user type permissions, the details of the users & applications for this permission. Read-only. */
		grantedTo?: IdentitySet

		grantedToIdentities?: IdentitySet[]

	    /** Provides a reference to the ancestor of the current permission, if it is inherited from an ancestor. Read-only. */
		inheritedFrom?: ItemReference

	    /** Details of any associated sharing invitation for this permission. Read-only. */
		invitation?: SharingInvitation

	    /** Provides the link details of the current permission, if it is a link type permissions. Read-only. */
		link?: SharingLink

		roles?: string[]

	    /** A unique token that can be used to access this shared item via the **shares** API. Read-only. */
		shareId?: string

}

export interface Subscription extends Entity {

	    /** Specifies the resource that will be monitored for changes. Do not include the base URL (https://graph.microsoft.com/{version}/). */
		resource?: string

	    /** Indicates the type of change in the subscribed resource that will raise a notification. The supported values are: created, updated, deleted. Multiple values can be combined using a comma-separated list. Drive root Item notifications require the use of updated only. */
		changeType?: string

	    /** Specifies the value of the clientState property sent by the service in each notification. The maximum length is 255 characters. The client can check that the notification came from the service by comparing the value of the clientState property sent with the subscription with the value of the clientState property received with each notification. */
		clientState?: string

	    /** The URL of the endpoint that will receive the notifications. This URL has to make use of the HTTPS protocol. */
		notificationUrl?: string

	    /** Specifies the date and time when the webhook subscription expires. The time is in UTC, and can be an amount of time from subscription creation that varies for the resource subscribed to.  See the table below for maximum supported subscription length of time. */
		expirationDateTime?: string

	    /** Identifier of the application used to create the subscription. */
		applicationId?: string

	    /** Identifier of the user or service principal that created the subscription.If the app used delegated permissions to create the subscription, this field contains the id of the signed-in user the app called on behalf of.If the app used application permissions, this field contains the id of the service principal corresponding to the app. */
		creatorId?: string

}

export interface ThumbnailSet extends Entity {

	    /** A 1920x1920 scaled thumbnail. */
		large?: Thumbnail

	    /** A 176x176 scaled thumbnail. */
		medium?: Thumbnail

	    /** A 48x48 cropped thumbnail. */
		small?: Thumbnail

	    /** A custom thumbnail image or the original image used to generate other thumbnails. */
		source?: Thumbnail

}

export interface BaseItemVersion extends Entity {

	    /** Identity of the user which last modified the version. Read-only. */
		lastModifiedBy?: IdentitySet

	    /** Date and time the version was last modified. Read-only. */
		lastModifiedDateTime?: string

	    /** Indicates the publication status of this particular version. Read-only. */
		publication?: PublicationFacet

}

export interface DriveItemVersion extends BaseItemVersion {

		content?: any

		size?: number

}

export interface WorkbookApplication extends Entity {

		calculationMode?: string

}

export interface WorkbookNamedItem extends Entity {

		comment?: string

		name?: string

		scope?: string

		type?: string

		value?: any

		visible?: boolean

		worksheet?: WorkbookWorksheet

}

export interface WorkbookTable extends Entity {

		highlightFirstColumn?: boolean

		highlightLastColumn?: boolean

		name?: string

		showBandedColumns?: boolean

		showBandedRows?: boolean

		showFilterButton?: boolean

		showHeaders?: boolean

		showTotals?: boolean

		style?: string

		columns?: WorkbookTableColumn[]

		rows?: WorkbookTableRow[]

		sort?: WorkbookTableSort

		worksheet?: WorkbookWorksheet

}

export interface WorkbookWorksheet extends Entity {

		name?: string

		position?: number

		visibility?: string

		charts?: WorkbookChart[]

		names?: WorkbookNamedItem[]

		pivotTables?: WorkbookPivotTable[]

		protection?: WorkbookWorksheetProtection

		tables?: WorkbookTable[]

}

export interface WorkbookFunctions extends Entity {

}

export interface WorkbookChart extends Entity {

		height?: number

		left?: number

		name?: string

		top?: number

		width?: number

		axes?: WorkbookChartAxes

		dataLabels?: WorkbookChartDataLabels

		format?: WorkbookChartAreaFormat

		legend?: WorkbookChartLegend

		series?: WorkbookChartSeries[]

		title?: WorkbookChartTitle

		worksheet?: WorkbookWorksheet

}

export interface WorkbookChartAxes extends Entity {

		categoryAxis?: WorkbookChartAxis

		seriesAxis?: WorkbookChartAxis

		valueAxis?: WorkbookChartAxis

}

export interface WorkbookChartDataLabels extends Entity {

		position?: string

		separator?: string

		showBubbleSize?: boolean

		showCategoryName?: boolean

		showLegendKey?: boolean

		showPercentage?: boolean

		showSeriesName?: boolean

		showValue?: boolean

		format?: WorkbookChartDataLabelFormat

}

export interface WorkbookChartAreaFormat extends Entity {

		fill?: WorkbookChartFill

		font?: WorkbookChartFont

}

export interface WorkbookChartLegend extends Entity {

		overlay?: boolean

		position?: string

		visible?: boolean

		format?: WorkbookChartLegendFormat

}

export interface WorkbookChartSeries extends Entity {

		name?: string

		format?: WorkbookChartSeriesFormat

		points?: WorkbookChartPoint[]

}

export interface WorkbookChartTitle extends Entity {

		overlay?: boolean

		text?: string

		visible?: boolean

		format?: WorkbookChartTitleFormat

}

export interface WorkbookChartFill extends Entity {

}

export interface WorkbookChartFont extends Entity {

		bold?: boolean

		color?: string

		italic?: boolean

		name?: string

		size?: number

		underline?: string

}

export interface WorkbookChartAxis extends Entity {

		majorUnit?: any

		maximum?: any

		minimum?: any

		minorUnit?: any

		format?: WorkbookChartAxisFormat

		majorGridlines?: WorkbookChartGridlines

		minorGridlines?: WorkbookChartGridlines

		title?: WorkbookChartAxisTitle

}

export interface WorkbookChartAxisFormat extends Entity {

		font?: WorkbookChartFont

		line?: WorkbookChartLineFormat

}

export interface WorkbookChartGridlines extends Entity {

		visible?: boolean

		format?: WorkbookChartGridlinesFormat

}

export interface WorkbookChartAxisTitle extends Entity {

		text?: string

		visible?: boolean

		format?: WorkbookChartAxisTitleFormat

}

export interface WorkbookChartLineFormat extends Entity {

		color?: string

}

export interface WorkbookChartAxisTitleFormat extends Entity {

		font?: WorkbookChartFont

}

export interface WorkbookChartDataLabelFormat extends Entity {

		fill?: WorkbookChartFill

		font?: WorkbookChartFont

}

export interface WorkbookChartGridlinesFormat extends Entity {

		line?: WorkbookChartLineFormat

}

export interface WorkbookChartLegendFormat extends Entity {

		fill?: WorkbookChartFill

		font?: WorkbookChartFont

}

export interface WorkbookChartPoint extends Entity {

		value?: any

		format?: WorkbookChartPointFormat

}

export interface WorkbookChartPointFormat extends Entity {

		fill?: WorkbookChartFill

}

export interface WorkbookChartSeriesFormat extends Entity {

		fill?: WorkbookChartFill

		line?: WorkbookChartLineFormat

}

export interface WorkbookChartTitleFormat extends Entity {

		fill?: WorkbookChartFill

		font?: WorkbookChartFont

}

export interface WorkbookFilter extends Entity {

		criteria?: WorkbookFilterCriteria

}

export interface WorkbookFormatProtection extends Entity {

		formulaHidden?: boolean

		locked?: boolean

}

export interface WorkbookFunctionResult extends Entity {

		error?: string

		value?: any

}

export interface WorkbookPivotTable extends Entity {

	    /** Name of the PivotTable. */
		name?: string

	    /** The worksheet containing the current PivotTable. Read-only. */
		worksheet?: WorkbookWorksheet

}

export interface WorkbookRange extends Entity {

		address?: string

		addressLocal?: string

		cellCount?: number

		columnCount?: number

		columnHidden?: boolean

		columnIndex?: number

		formulas?: any

		formulasLocal?: any

		formulasR1C1?: any

		hidden?: boolean

		numberFormat?: any

		rowCount?: number

		rowHidden?: boolean

		rowIndex?: number

		text?: any

		valueTypes?: any

		values?: any

		format?: WorkbookRangeFormat

		sort?: WorkbookRangeSort

		worksheet?: WorkbookWorksheet

}

export interface WorkbookRangeFormat extends Entity {

		columnWidth?: number

		horizontalAlignment?: string

		rowHeight?: number

		verticalAlignment?: string

		wrapText?: boolean

		borders?: WorkbookRangeBorder[]

		fill?: WorkbookRangeFill

		font?: WorkbookRangeFont

		protection?: WorkbookFormatProtection

}

export interface WorkbookRangeSort extends Entity {

}

export interface WorkbookRangeBorder extends Entity {

		color?: string

		sideIndex?: string

		style?: string

		weight?: string

}

export interface WorkbookRangeFill extends Entity {

		color?: string

}

export interface WorkbookRangeFont extends Entity {

		bold?: boolean

		color?: string

		italic?: boolean

		name?: string

		size?: number

		underline?: string

}

export interface WorkbookRangeView extends Entity {

		cellAddresses?: any

	    /** Returns the number of visible columns. Read-only. */
		columnCount?: number

	    /** Represents the formula in A1-style notation. */
		formulas?: any

	    /** Represents the formula in A1-style notation, in the user's language and number-formatting locale. For example, the English "=SUM(A1, 1.5)" formula would become "=SUMME(A1; 1,5)" in German. */
		formulasLocal?: any

	    /** Represents the formula in R1C1-style notation. */
		formulasR1C1?: any

	    /** Index of the range. */
		index?: number

	    /** Represents Excel's number format code for the given cell. Read-only. */
		numberFormat?: any

	    /** Returns the number of visible rows. Read-only. */
		rowCount?: number

	    /** Text values of the specified range. The Text value will not depend on the cell width. The # sign substitution that happens in Excel UI will not affect the text value returned by the API. Read-only. */
		text?: any

	    /** Represents the type of data of each cell. Read-only. Possible values are: Unknown, Empty, String, Integer, Double, Boolean, Error. */
		valueTypes?: any

	    /** Represents the raw values of the specified range view. The data returned could be of type string, number, or a boolean. Cell that contain an error will return the error string. */
		values?: any

	    /** Represents a collection of range views associated with the range. Read-only. Read-only. */
		rows?: WorkbookRangeView[]

}

export interface WorkbookTableColumn extends Entity {

		index?: number

		name?: string

		values?: any

		filter?: WorkbookFilter

}

export interface WorkbookTableRow extends Entity {

		index?: number

		values?: any

}

export interface WorkbookTableSort extends Entity {

		fields?: WorkbookSortField[]

		matchCase?: boolean

		method?: string

}

export interface WorkbookWorksheetProtection extends Entity {

		options?: WorkbookWorksheetProtectionOptions

		protected?: boolean

}

export interface Attachment extends Entity {

	    /** The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		lastModifiedDateTime?: string

	    /** The display name of the attachment. This does not need to be the actual file name. */
		name?: string

	    /** The MIME type. */
		contentType?: string

	    /** The length of the attachment in bytes. */
		size?: number

	    /** true if the attachment is an inline attachment; otherwise, false. */
		isInline?: boolean

}

export interface OutlookCategory extends Entity {

	    /** A unique name that identifies a category in the user's mailbox. After a category is created, the name cannot be changed. Read-only. */
		displayName?: string

	    /** A pre-set color constant that characterizes a category, and that is mapped to one of 25 predefined colors. See the note below. */
		color?: CategoryColor

}

export interface OutlookTaskGroup extends Entity {

	    /** The version of the task group. */
		changeKey?: string

	    /** True if the task group is the default task group. */
		isDefaultGroup?: boolean

	    /** The name of the task group. */
		name?: string

	    /** The unique GUID identifier for the task group. */
		groupKey?: string

	    /** The collection of task folders in the task group. Read-only. Nullable. */
		taskFolders?: OutlookTaskFolder[]

}

export interface OutlookTaskFolder extends Entity {

	    /** The version of the task folder. */
		changeKey?: string

	    /** The name of the task folder. */
		name?: string

	    /** True if the folder is the default task folder. */
		isDefaultFolder?: boolean

	    /** The unique GUID identifier for the task folder's parent group. */
		parentGroupKey?: string

	    /** The tasks in this task folder. Read-only. Nullable. */
		tasks?: OutlookTask[]

	    /** The collection of single-value extended properties defined for the task folder. Read-only. Nullable. */
		singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

	    /** The collection of multi-value extended properties defined for the task folder. Read-only. Nullable. */
		multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

}

export interface OutlookTask extends OutlookItem {

	    /** The name of the person who has been assigned the task. */
		assignedTo?: string

	    /** The task body that typically contains information about the task. Note that only HTML type is supported. */
		body?: ItemBody

	    /** The date in the specified time zone that the task was finished. */
		completedDateTime?: DateTimeTimeZone

	    /** The date in the specified time zone that the task is to be finished. */
		dueDateTime?: DateTimeTimeZone

	    /** Set to true if the task has attachments. */
		hasAttachments?: boolean

	    /** The importance of the event. Possible values are: low, normal, high. */
		importance?: Importance

	    /** Set to true if an alert is set to remind the user of the task. */
		isReminderOn?: boolean

	    /** The name of the person who created the task. */
		owner?: string

	    /** The unique identifier for the task's parent folder. */
		parentFolderId?: string

	    /** The recurrence pattern for the task. */
		recurrence?: PatternedRecurrence

	    /** The date and time for a reminder alert of the task to occur. */
		reminderDateTime?: DateTimeTimeZone

	    /** Indicates the level of privacy for the task. Possible values are: normal, personal, private, confidential. */
		sensitivity?: Sensitivity

	    /** The date in the specified time zone when the task is to begin. */
		startDateTime?: DateTimeTimeZone

	    /** Indicates the state or progress of the task. Possible values are: notStarted, inProgress, completed, waitingOnOthers, deferred. */
		status?: TaskStatus

	    /** A brief description or title of the task. */
		subject?: string

	    /** The collection of single-value extended properties defined for the task. Read-only. Nullable. */
		singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

	    /** The collection of multi-value extended properties defined for the task. Read-only. Nullable. */
		multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

	    /** The collection of fileAttachment, itemAttachment, and referenceAttachment attachments for the task.  Read-only. Nullable. */
		attachments?: Attachment[]

}

export interface MessageRule extends Entity {

	    /** The display name of the rule. */
		displayName?: string

	    /** Indicates the order in which the rule is executed, among other rules. */
		sequence?: number

	    /** Conditions that when fulfilled, will trigger the corresponding actions for that rule. */
		conditions?: MessageRulePredicates

	    /** Actions to be taken on a message when the corresponding conditions are fulfilled. */
		actions?: MessageRuleActions

	    /** Exception conditions for the rule. */
		exceptions?: MessageRulePredicates

	    /** Indicates whether the rule is enabled to be applied to messages. */
		isEnabled?: boolean

	    /** Indicates whether the rule is in an error condition. Read-only. */
		hasError?: boolean

	    /** Indicates if the rule is read-only and cannot be modified or deleted by the rules REST API. */
		isReadOnly?: boolean

}

export interface UserConfiguration extends Entity {

		binaryData?: number

}

export interface SingleValueLegacyExtendedProperty extends Entity {

	    /** A property value. */
		value?: string

}

export interface MultiValueLegacyExtendedProperty extends Entity {

		value?: string[]

}

export interface Mention extends Entity {

	    /** The email information of the mentioned person. Required. */
		mentioned?: EmailAddress

	    /** Content for the mention. Optional. Not used and defaulted as null for message. */
		mentionText?: string

	    /** A unique identifier that represents a parent of the resource instance. Optional. Not used and defaulted as null for message. */
		clientReference?: string

	    /** The email information of the user who made the mention. */
		createdBy?: EmailAddress

	    /** The date and time that the mention is created on the client. */
		createdDateTime?: string

	    /** The date and time that the mention is created on the server. Optional. Not used and defaulted as null for message. */
		serverCreatedDateTime?: string

	    /** A deep web link to the context of the mention in the resource instance. Optional. Not used and defaulted as null for message. */
		deepLink?: string

	    /** The name of the application where the mention is created. Optional. Not used and defaulted as null for message. */
		application?: string

}

export interface FileAttachment extends Attachment {

	    /** The ID of the attachment in the Exchange store. */
		contentId?: string

	    /** The Uniform Resource Identifier (URI) that corresponds to the location of the content of the attachment. */
		contentLocation?: string

	    /** The base64-encoded contents of the file. */
		contentBytes?: number

}

export interface ItemAttachment extends Attachment {

	    /** The attached contact, message or event. Navigation property. */
		item?: OutlookItem

}

export interface EventMessage extends Message {

	    /** The type of event message: none, meetingRequest, meetingCancelled, meetingAccepted, meetingTenativelyAccepted, meetingDeclined. */
		meetingMessageType?: MeetingMessageType

	    /** The start time of the requested meeting. */
		startDateTime?: DateTimeTimeZone

	    /** The end time of the requested meeting. */
		endDateTime?: DateTimeTimeZone

	    /** The location of the requested meeting. */
		location?: Location

	    /** The type of requested meeting: singleInstance, occurence, exception, seriesMaster. */
		type?: EventType

	    /** The recurrence pattern of the requested meeting. */
		recurrence?: PatternedRecurrence

	    /** Indicates whether this meeting request has been made out-of-date by a more recent request. */
		isOutOfDate?: boolean

	    /** Indicates whether the event lasts the entire day. Adjusting this property requires adjusting the startDateTime and endDateTime properties of the event as well. */
		isAllDay?: boolean

		isDelegated?: boolean

	    /** The event associated with the event message. The assumption for attendees or room resources is that the Calendar Attendant is set to automatically update the calendar with an event when meeting request event messages arrive. Navigation property.  Read-only. */
		event?: Event

}

export interface MailSearchFolder extends MailFolder {

	    /** Indicates whether a search folder is editable using REST APIs. */
		isSupported?: boolean

	    /** Indicates how the mailbox folder hierarchy should be traversed. true means that a deep search should be done while false means a shallow search should be done instead. */
		includeNestedFolders?: boolean

	    /** The mailbox folders that should be mined. */
		sourceFolderIDs?: string[]

	    /** The OData query to filter the messages. */
		filterQuery?: string

}

export interface EventMessageRequest extends EventMessage {

	    /** The previous location of the requested meeting. */
		previousLocation?: Location

	    /** The previous start time of the requested meeting. */
		previousStartDateTime?: DateTimeTimeZone

	    /** The previous end time of the requested meeting. */
		previousEndDateTime?: DateTimeTimeZone

		responseRequested?: boolean

}

export interface ReferenceAttachment extends Attachment {

	    /** URL to get the attachment content. If this is a URL to a folder, then for the folder to be displayed correctly in Outlook or Outlook on the web, set isFolder to true. Required. */
		sourceUrl?: string

	    /** The type of provider that supports an attachment of this contentType. Possible values are: other, oneDriveBusiness, oneDriveConsumer, dropbox. Optional. */
		providerType?: ReferenceAttachmentProvider

	    /** Applies to only a reference attachment of an image - URL to get a thumbnail image. Use thumbnailUrl and previewUrl only when sourceUrl identifies an image file. Optional. */
		thumbnailUrl?: string

	    /** Applies to only a reference attachment of an image - URL to get a preview image. Use thumbnailUrl and previewUrl only when sourceUrl identifies an image file. Optional. */
		previewUrl?: string

	    /** Specifies the permissions granted for the attachment by the type of provider in providerType. Possible values are: other, view, edit, anonymousView, anonymousEdit, organizationView, organizationEdit. Optional. */
		permission?: ReferenceAttachmentPermission

	    /** Specifies whether the attachment is a link to a folder. Must set this to true if sourceUrl is a link to a folder. Optional. */
		isFolder?: boolean

}

export interface OpenTypeExtension extends Extension {

		extensionName?: string

}

export interface Post extends OutlookItem {

	    /** The contents of the chatMessage. This is a default property. */
		body?: ItemBody

	    /** Specifies when the post was received. The DateTimeOffset type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		receivedDateTime?: string

	    /** Indicates whether the post has at least one attachment. This is a default property. */
		hasAttachments?: boolean

	    /** Used in delegate access scenarios. Indicates who posted the message on behalf of another user. This is a default property. */
		from?: Recipient

	    /** Contains the address of the sender. The value of Sender is assumed to be the address of the authenticated user in the case when Sender is not specified. This is a default property. */
		sender?: Recipient

	    /** Unique ID of the conversation thread. Read-only. */
		conversationThreadId?: string

	    /** Conversation participants that were added to the thread as part of this post. */
		newParticipants?: Recipient[]

	    /** Unique ID of the conversation. Read-only. */
		conversationId?: string

	    /** The importance of a group post: low, normal, high. */
		importance?: Importance

	    /** The collection of open extensions defined for the post. Read-only. Nullable. */
		extensions?: Extension[]

	    /** The earlier post that this post is replying to in the conversationThread. Read-only. */
		inReplyTo?: Post

	    /** The collection of fileAttachment, itemAttachment, and referenceAttachment attachments for the post. Read-only. Nullable. */
		attachments?: Attachment[]

	    /** The collection of single-value extended properties defined for the post. Read-only. Nullable. */
		singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

	    /** The collection of multi-value extended properties defined for the post. Read-only. Nullable. */
		multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

		mentions?: Mention[]

}

export interface InferenceClassificationOverride extends Entity {

	    /** Specifies how incoming messages from a specific sender should always be classified as. Possible values are: focused, other. */
		classifyAs?: InferenceClassificationType

	    /** The email address information of the sender for whom the override is created. */
		senderEmailAddress?: EmailAddress

}

export interface ColumnLink extends Entity {

	    /** The name of the column  in this content type. */
		name?: string

}

export interface FieldValueSet extends Entity {

}

export interface ListItemVersion extends BaseItemVersion {

	    /** A collection of the fields and values for this version of the list item. */
		fields?: FieldValueSet

}

export interface SharedDriveItem extends BaseItem {

	    /** Information about the owner of the shared item being referenced. */
		owner?: IdentitySet

	    /** Used to access the underlying driveItem */
		driveItem?: DriveItem

	    /** All driveItems contained in the sharing root. This collection cannot be enumerated. */
		items?: DriveItem[]

	    /** Used to access the underlying list */
		list?: List

	    /** Used to access the underlying listItem */
		listItem?: ListItem

		root?: DriveItem

	    /** Used to access the underlying site */
		site?: Site

}

export interface Trending extends Entity {

		weight?: number

		resourceVisualization?: ResourceVisualization

		resourceReference?: ResourceReference

		lastModifiedDateTime?: string

		resource?: Entity

}

export interface SharedInsight extends Entity {

		lastShared?: SharingDetail

		sharingHistory?: SharingDetail[]

		resourceVisualization?: ResourceVisualization

		resourceReference?: ResourceReference

		lastSharedMethod?: Entity

		resource?: Entity

}

export interface UsedInsight extends Entity {

		lastUsed?: UsageDetails

		resourceVisualization?: ResourceVisualization

		resourceReference?: ResourceReference

		resource?: Entity

}

export interface PlannerTask extends Entity {

	    /** Identity of the user that created the task. */
		createdBy?: IdentitySet

	    /** Plan ID to which the task belongs. */
		planId?: string

	    /** Bucket ID to which the task belongs. The bucket needs to be in the plan that the task is in. It is 28 characters long and case sensitive. Format validation is done on the service. */
		bucketId?: string

	    /** Title of the task. */
		title?: string

	    /** Hint used to order items of this type in a list view. The format is defined as outlined here. */
		orderHint?: string

	    /** Hint used to order items of this type in a list view. The format is defined as outlined here. */
		assigneePriority?: string

	    /** Percentage of task completion. When set to 100, the task is considered completed. */
		percentComplete?: number

	    /** Date and time at which the task starts. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		startDateTime?: string

	    /** Read-only. Date and time at which the task is created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		createdDateTime?: string

	    /** Date and time at which the task is due. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		dueDateTime?: string

	    /** Read-only. Value is true if the details object of the task has a non-empty description and false otherwise. */
		hasDescription?: boolean

	    /** This sets the type of preview that shows up on the task. Possible values are: automatic, noPreview, checklist, description, reference. */
		previewType?: PlannerPreviewType

	    /** Read-only. Date and time at which the 'percentComplete' of the task is set to '100'. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		completedDateTime?: string

	    /** Identity of the user that completed the task. */
		completedBy?: IdentitySet

	    /** Number of external references that exist on the task. */
		referenceCount?: number

	    /** Number of checklist items that are present on the task. */
		checklistItemCount?: number

	    /** Number of checklist items with value set to 'false', representing incomplete items. */
		activeChecklistItemCount?: number

	    /** The categories to which the task has been applied. See applied Categories for possible values. */
		appliedCategories?: PlannerAppliedCategories

	    /** The set of assignees the task is assigned to. */
		assignments?: PlannerAssignments

	    /** Thread ID of the conversation on the task. This is the ID of the conversation thread object created in the group. */
		conversationThreadId?: string

	    /** Read-only. Nullable. Additional details about the task. */
		details?: PlannerTaskDetails

	    /** Read-only. Nullable. Used to render the task correctly in the task board view when grouped by assignedTo. */
		assignedToTaskBoardFormat?: PlannerAssignedToTaskBoardTaskFormat

	    /** Read-only. Nullable. Used to render the task correctly in the task board view when grouped by progress. */
		progressTaskBoardFormat?: PlannerProgressTaskBoardTaskFormat

	    /** Read-only. Nullable. Used to render the task correctly in the task board view when grouped by bucket. */
		bucketTaskBoardFormat?: PlannerBucketTaskBoardTaskFormat

}

export interface PlannerPlan extends Entity {

	    /** Read-only. The user who created the plan. */
		createdBy?: IdentitySet

	    /** Read-only. Date and time at which the plan is created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		createdDateTime?: string

	    /** ID of the Group that owns the plan. A valid group must exist before this field can be set. Once set, this can only be updated by the owner. */
		owner?: string

	    /** Required. Title of the plan. */
		title?: string

	    /** Read-only. Additional user experiences in which this plan is used, represented as plannerPlanContext entries. */
		contexts?: PlannerPlanContextCollection

	    /** Read-only. Nullable. Collection of tasks in the plan. */
		tasks?: PlannerTask[]

	    /** Read-only. Nullable. Collection of buckets in the plan. */
		buckets?: PlannerBucket[]

	    /** Read-only. Nullable. Additional details about the plan. */
		details?: PlannerPlanDetails

}

export interface PlannerDelta extends Entity {

}

export interface Planner extends Entity {

	    /** Read-only. Nullable. Returns a collection of the specified tasks */
		tasks?: PlannerTask[]

	    /** Read-only. Nullable. Returns a collection of the specified plans */
		plans?: PlannerPlan[]

	    /** Read-only. Nullable. Returns a collection of the specified buckets */
		buckets?: PlannerBucket[]

}

export interface PlannerBucket extends Entity {

	    /** Name of the bucket. */
		name?: string

	    /** Plan ID to which the bucket belongs. */
		planId?: string

	    /** Hint used to order items of this type in a list view. The format is defined as outlined here. */
		orderHint?: string

	    /** Read-only. Nullable. The collection of tasks in the bucket. */
		tasks?: PlannerTask[]

}

export interface PlannerTaskDetails extends Entity {

	    /** Description of the task */
		description?: string

	    /** This sets the type of preview that shows up on the task. Possible values are: automatic, noPreview, checklist, description, reference. When set to automatic the displayed preview is chosen by the app viewing the task. */
		previewType?: PlannerPreviewType

	    /** The collection of references on the task. */
		references?: PlannerExternalReferences

	    /** The collection of checklist items on the task. */
		checklist?: PlannerChecklistItems

}

export interface PlannerAssignedToTaskBoardTaskFormat extends Entity {

	    /** Hint value used to order the task on the AssignedTo view of the Task Board when the task is not assigned to anyone, or if the orderHintsByAssignee dictionary does not provide an order hint for the user the task is assigned to. The format is defined as outlined here. */
		unassignedOrderHint?: string

	    /** Dictionary of hints used to order tasks on the AssignedTo view of the Task Board. The key of each entry is one of the users the task is assigned to and the value is the order hint. The format of each value is defined as outlined here. */
		orderHintsByAssignee?: PlannerOrderHintsByAssignee

}

export interface PlannerProgressTaskBoardTaskFormat extends Entity {

	    /** Hint value used to order the task on the Progress view of the Task Board. The format is defined as outlined here. */
		orderHint?: string

}

export interface PlannerBucketTaskBoardTaskFormat extends Entity {

	    /** Hint used to order tasks in the Bucket view of the Task Board. The format is defined as outlined here. */
		orderHint?: string

}

export interface PlannerPlanDetails extends Entity {

	    /** The set of user IDs that this plan is shared with. If you are using Office 365 Groups, use the groups API to manage group membership to share the group's plan. You can also add existing members of the group to this collection, although it is not required in order for them to access the plan owned by the group. */
		sharedWith?: PlannerUserIds

	    /** An object that specifies the descriptions of the six categories that can be associated with tasks in the plan */
		categoryDescriptions?: PlannerCategoryDescriptions

	    /** Read-only. A collection of additional information associated with plannerPlanContext entries that are defined for the plannerPlan container. */
		contextDetails?: PlannerPlanContextDetailsCollection

}

export interface OnenoteEntityBaseModel extends Entity {

		self?: string

}

export interface OnenoteEntitySchemaObjectModel extends OnenoteEntityBaseModel {

		createdDateTime?: string

}

export interface OnenoteEntityHierarchyModel extends OnenoteEntitySchemaObjectModel {

		displayName?: string

		createdBy?: IdentitySet

		lastModifiedBy?: IdentitySet

		lastModifiedDateTime?: string

}

export interface Notebook extends OnenoteEntityHierarchyModel {

	    /** Indicates whether this is the user's default notebook. Read-only. */
		isDefault?: boolean

	    /** Possible values are: Owner, Contributor, Reader, None. Owner represents owner-level access to the notebook. Contributor represents read/write access to the notebook. Reader represents read-only access to the notebook. Read-only. */
		userRole?: OnenoteUserRole

	    /** Indicates whether the notebook is shared. If true, the contents of the notebook can be seen by people other than the owner. Read-only. */
		isShared?: boolean

	    /** The URL for the sections navigation property, which returns all the sections in the notebook. Read-only. */
		sectionsUrl?: string

	    /** The URL for the sectionGroups navigation property, which returns all the section groups in the notebook. Read-only. */
		sectionGroupsUrl?: string

	    /** Links for opening the notebook. The oneNoteClientURL link opens the notebook in the OneNote native client if it's installed. The oneNoteWebURL link opens the notebook in OneNote Online. */
		links?: NotebookLinks

	    /** The sections in the notebook. Read-only. Nullable. */
		sections?: OnenoteSection[]

	    /** The section groups in the notebook. Read-only. Nullable. */
		sectionGroups?: SectionGroup[]

}

export interface OnenoteSection extends OnenoteEntityHierarchyModel {

	    /** Indicates whether this is the user's default section. Read-only. */
		isDefault?: boolean

	    /** Links for opening the section. The oneNoteClientURL link opens the section in the OneNote native client if it's installed. The oneNoteWebURL link opens the section in OneNote Online. */
		links?: SectionLinks

	    /** The pages endpoint where you can get details for all the pages in the section. Read-only. */
		pagesUrl?: string

	    /** The notebook that contains the section.  Read-only. */
		parentNotebook?: Notebook

	    /** The section group that contains the section.  Read-only. */
		parentSectionGroup?: SectionGroup

	    /** The collection of pages in the section.  Read-only. Nullable. */
		pages?: OnenotePage[]

}

export interface SectionGroup extends OnenoteEntityHierarchyModel {

		sectionsUrl?: string

		sectionGroupsUrl?: string

		parentNotebook?: Notebook

		parentSectionGroup?: SectionGroup

		sections?: OnenoteSection[]

		sectionGroups?: SectionGroup[]

}

export interface OnenotePage extends OnenoteEntitySchemaObjectModel {

	    /** The title of the page. */
		title?: string

	    /** The unique identifier of the application that created the page. Read-only. */
		createdByAppId?: string

	    /** Links for opening the page. The oneNoteClientURL link opens the page in the OneNote native client if it 's installed. The oneNoteWebUrl link opens the page in OneNote Online. Read-only. */
		links?: PageLinks

	    /** The URL for the page's HTML content.  Read-only. */
		contentUrl?: string

	    /** The page's HTML content. */
		content?: any

	    /** The date and time when the page was last modified. The timestamp represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. Read-only. */
		lastModifiedDateTime?: string

	    /** The indentation level of the page. Read-only. */
		level?: number

	    /** The order of the page within its parent section. Read-only. */
		order?: number

		userTags?: string[]

	    /** The section that contains the page. Read-only. */
		parentSection?: OnenoteSection

	    /** The notebook that contains the page.  Read-only. */
		parentNotebook?: Notebook

}

export interface OnenoteResource extends OnenoteEntityBaseModel {

		content?: any

		contentUrl?: string

}

export interface Operation extends Entity {

		status?: OperationStatus

		createdDateTime?: string

		lastActionDateTime?: string

}

export interface OnenoteOperation extends Operation {

	    /** The resource URI for the object. For example, the resource URI for a copied page or section. */
		resourceLocation?: string

	    /** The resource id. */
		resourceId?: string

	    /** The error returned by the operation. */
		error?: OnenoteOperationError

	    /** The operation percent complete if the operation is still in running status */
		percentComplete?: string

}

export interface DirectoryAudit extends Entity {

	    /** Indicates which resource category that's targetted by the activity. (For example: User Management, Group Management etc..) */
		category?: string

	    /** Indicates a unique ID that helps correlate activities that span across various services. Can be used to trace logs across services. */
		correlationId?: string

	    /** Indicates the result of the activity.Possible values are: success, failure, timeout, unknownFutureValue. */
		result?: OperationResult

	    /** Indicates the reason for failure if the result is "Failure" or "timeout". */
		resultReason?: string

	    /** Indicates the activity name or the operation name (E.g. "Create User", "Add member to group"). For a list of activities logged,refer to Azure Ad activity list. */
		activityDisplayName?: string

	    /** Indicates the date and time the activity was performed. The Timestamp type is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		activityDateTime?: string

	    /** Indicates information about the user or app initiated the activity. */
		initiatedBy?: AuditActivityInitiator

	    /** Indicates information on which resource was changed due to the activity. Target Resource Type can be User, Device, Directory, App, Role, Group, Policy or Other. */
		targetResources?: TargetResource[]

	    /** Indicates information on which service initiated the activity (For example: Self-service Password Management, Core Directory, B2C, Invited Users, Microsoft Identity Manager, Privileged Identity Management. */
		loggedByService?: string

	    /** Indicates additional details on the activity. */
		additionalDetails?: KeyValue[]

}

export interface SignIn extends Entity {

	    /** Provides the date and time the sign-in was initiated. The Timestamp type is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		createdDateTime?: string

	    /** Indicates the display Name of the User. */
		userDisplayName?: string

	    /** Indicates the UPN of the user. */
		userPrincipalName?: string

	    /** Indicates the userId of the user. */
		userId?: string

	    /** Refers to the Unique GUID representing Application Id in the Azure Active Directory. */
		appId?: string

	    /** Refers to the application name displayed in the Azure Portal. */
		appDisplayName?: string

	    /** Provides the IP address of the client from where the sign-in occurred. */
		ipAddress?: string

	    /** Provides the sign-in status. Possible values include Success and Failure. */
		status?: SignInStatus

	    /** Provides the legacy client used for sign-in activty.E.g. includes Browser, Exchange Active Sync,Modern clients, IMAP, MAPI, SMTP, POP. */
		clientAppUsed?: string

	    /** Provides the device information from where the sign-in occurred. It inclules information like deviceId, OS, browser. */
		deviceDetail?: DeviceDetail

	    /** Provides the city, state and 2 letter country code from where the sign-in occurred. */
		location?: SignInLocation

	    /** Provides the MFA related information like MFA Required, MFA Status for the corresponding sign-in. */
		mfaDetail?: MfaDetail

	    /** Refers to the ID that's sent from the client when the sign-in is initiated. This is used for troubleshooting the corresponding sign-in activity when calling helpdesk or support. */
		correlationId?: string

	    /** Provides the status of the conditional access policy triggered. Possible values are: success, failure, notApplied, unknownFutureValue. */
		conditionalAccessStatus?: ConditionalAccessStatus

	    /** Provides a list of conditional access policies that are triggered by the corresponding sign-in activity. */
		conditionalAccessPolicies?: ConditionalAccessPolicy[]

	    /** Indicates if the sign-in has risk signals associated with it. */
		isRisky?: boolean

	    /** Provides the risk level associated with the sign-in.Possible values are: low, medium, high. */
		riskLevel?: RiskLevel

}

export interface RestrictedSignIn extends SignIn {

		targetTenantId?: string

}

export interface AuditLogRoot extends Entity {

		signIns?: SignIn[]

		directoryAudits?: DirectoryAudit[]

		restrictedSignIns?: RestrictedSignIn[]

}

export interface IdentityRiskEvent extends Entity {

	    /** The name of the user at risk */
		userDisplayName?: string

	    /** The user principal name of the user at risk */
		userPrincipalName?: string

	    /** The date and time when the risk event occurred */
		riskEventDateTime?: string

		riskEventType?: string

	    /** Possible values are: low, medium, high. */
		riskLevel?: RiskLevel

	    /** Possible values are: active, remediated, dismissedAsFixed, dismissedAsFalsePositive, dismissedAsIgnore, loginBlocked, closedMfaAuto, closedMultipleReasons. */
		riskEventStatus?: RiskEventStatus

	    /** The date and time that the risk event was closed */
		closedDateTime?: string

	    /** The date and time that the risk event was created. This is always greater than or equal to the datetime of the risk event itself. This is the correct property to use as a filter when querying risk events. */
		createdDateTime?: string

	    /** The id of the user at risk */
		userId?: string

	    /** Read-only. Nullable. */
		impactedUser?: User

}

export interface LocatedRiskEvent extends IdentityRiskEvent {

	    /** The location attached to the IP address of the sign-in */
		location?: SignInLocation

	    /** The IP address of the sign-in */
		ipAddress?: string

}

export interface ImpossibleTravelRiskEvent extends LocatedRiskEvent {

	    /** The browser's user agent string */
		userAgent?: string

	    /** Information about the device */
		deviceInformation?: string

	    /** If one of the locations is atypical for the user */
		isAtypicalLocation?: boolean

	    /** The date and time of the first sign-in */
		previousSigninDateTime?: string

	    /** The location attached to the IP address of the first sign-in */
		previousLocation?: SignInLocation

		previousIpAddress?: string

}

export interface LeakedCredentialsRiskEvent extends IdentityRiskEvent {

}

export interface AnonymousIpRiskEvent extends LocatedRiskEvent {

}

export interface SuspiciousIpRiskEvent extends LocatedRiskEvent {

}

export interface UnfamiliarLocationRiskEvent extends LocatedRiskEvent {

}

export interface MalwareRiskEvent extends LocatedRiskEvent {

	    /** Information about the device */
		deviceInformation?: string

	    /** The malware associated with this login */
		malwareName?: string

}

export interface PrivilegedRole extends Entity {

	    /** Role name. */
		name?: string

	    /** The settings for this role. Read-only. Nullable. */
		settings?: PrivilegedRoleSettings

	    /** The assignments for this role. Read-only. Nullable. */
		assignments?: PrivilegedRoleAssignment[]

	    /** The summary information for this role. Read-only. Nullable. */
		summary?: PrivilegedRoleSummary

}

export interface PrivilegedRoleSettings extends Entity {

		approverIds?: string[]

	    /** Minimal duration for the activated role. */
		minElevationDuration?: string

	    /** Maximal duration for the activated role. */
		maxElavationDuration?: string

	    /** The duration when the role is activated. */
		elevationDuration?: string

	    /** true if send notification to the end user when the role is activated. false if do not send notification when the role is activated. */
		notificationToUserOnElevation?: boolean

	    /** true if the ticketing information is required when activate the role. false if the ticketing information is not required when activate the role. */
		ticketingInfoOnElevation?: boolean

	    /** true if MFA is required to activate the role. false if MFA is not required to activate the role. */
		mfaOnElevation?: boolean

	    /** Internal used only. */
		lastGlobalAdmin?: boolean

	    /** true if mfaOnElevation is configurable. false if mfaOnElevation is not configurable. */
		isMfaOnElevationConfigurable?: boolean

		approvalOnElevation?: boolean

}

export interface PrivilegedRoleAssignment extends Entity {

	    /** User identifier. In GUID string format. */
		userId?: string

	    /** Role identifier. In GUID string format. */
		roleId?: string

	    /** true if the role assignment is activated. false if the role assignment is deactivated. */
		isElevated?: boolean

	    /** The UTC DateTime when the temporary privileged role assignment will be expired. For permanent role assignment, the value is null. */
		expirationDateTime?: string

	    /** Result message set by the service. */
		resultMessage?: string

	    /** Read-only. Nullable. The associated role information. */
		roleInfo?: PrivilegedRole

}

export interface PrivilegedRoleSummary extends Entity {

	    /** Possible values are: ok, bad. The value depends on the ratio of (managedCount / usersCount). If the ratio is less than a predefined threshold, ok is returned. Otherwise, bad is returned. */
		status?: RoleSummaryStatus

	    /** The number of users that are assigned with the role. */
		usersCount?: number

	    /** The number of users that have the role assigned but the role is deactivated. */
		managedCount?: number

	    /** The number of users that have the role assigned and the role is activated. */
		elevatedCount?: number

	    /** true if the role activation requires MFA. false if the role activation doesn't require MFA. */
		mfaEnabled?: boolean

}

export interface PrivilegedOperationEvent extends Entity {

	    /** The id of the user that is associated with the operation. */
		userId?: string

	    /** The user's display name. */
		userName?: string

	    /** The user's email. */
		userMail?: string

	    /** The id of of the role that is associated with the operation. */
		roleId?: string

	    /** The name of the role. */
		roleName?: string

	    /** This is only used when the requestType is "Activate", and it indicates the expiration time for the role activation. */
		expirationDateTime?: string

	    /** Indicates the time when the event is created. */
		creationDateTime?: string

	    /** The user id of the requestor who initiates the operation. */
		requestorId?: string

	    /** The user name of the requestor who initiates the operation. */
		requestorName?: string

	    /** The tenant (organization) id. */
		tenantId?: string

	    /** The request operation type. The requestType value can be: Assign (role assignment), Activate (role activation), Unassign (remove role assignment), Deactivate (role deactivation), ScanAlersNow (scan security alerts), DismissAlert (dismiss security alert), FixAlertItem (fix a security alert issue), AccessReview_Review (review an Access Review), AccessReview_Create (create an Access Review), AccessReview_Update (update an Access Review), and AccessReview_Delete (delete an Access Review). */
		requestType?: string

	    /** Detailed human readable information for the event. */
		additionalInformation?: string

		referenceKey?: string

		referenceSystem?: string

}

export interface PrivilegedSignupStatus extends Entity {

		isRegistered?: boolean

		status?: SetupStatus

}

export interface PrivilegedApproval extends Entity {

		userId?: string

		roleId?: string

		approvalType?: string

	    /** Possible values are: pending, approved, denied, aborted, canceled. */
		approvalState?: ApprovalState

		approvalDuration?: string

		requestorReason?: string

		approverReason?: string

	    /** The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		startDateTime?: string

	    /** The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		endDateTime?: string

	    /** Read-only. Nullable. */
		roleInfo?: PrivilegedRole

}

export interface TenantSetupInfo extends Entity {

		userRolesActions?: string

		firstTimeSetup?: boolean

		relevantRolesSettings?: string[]

		skipSetup?: boolean

		setupStatus?: SetupStatus

		defaultRolesSettings?: PrivilegedRoleSettings

}

export interface Invitation extends Entity {

		invitedUserDisplayName?: string

		invitedUserType?: string

		invitedUserEmailAddress?: string

		invitedUserMessageInfo?: InvitedUserMessageInfo

		sendInvitationMessage?: boolean

		inviteRedirectUrl?: string

		inviteRedeemUrl?: string

		status?: string

		invitedUser?: User

}

export interface DeviceManagement extends Entity {

	    /** Tenant mobile device management subscription state. Possible values are: pending, active, warning, disabled, deleted, blocked, lockedOut. */
		subscriptionState?: DeviceManagementSubscriptionState

		subscriptions?: DeviceManagementSubscriptions

		managedDeviceCleanupSettings?: ManagedDeviceCleanupSettings

		adminConsent?: AdminConsent

		deviceProtectionOverview?: DeviceProtectionOverview

		windowsMalwareOverview?: WindowsMalwareOverview

		accountMoveCompletionDateTime?: string

		settings?: DeviceManagementSettings

		maximumDepTokens?: number

		intuneAccountId?: string

		intuneBrand?: IntuneBrand

		termsAndConditions?: TermsAndConditions[]

		androidForWorkSettings?: AndroidForWorkSettings

		androidForWorkAppConfigurationSchemas?: AndroidForWorkAppConfigurationSchema[]

		androidForWorkEnrollmentProfiles?: AndroidForWorkEnrollmentProfile[]

		androidManagedStoreAccountEnterpriseSettings?: AndroidManagedStoreAccountEnterpriseSettings

		androidManagedStoreAppConfigurationSchemas?: AndroidManagedStoreAppConfigurationSchema[]

		androidDeviceOwnerEnrollmentProfiles?: AndroidDeviceOwnerEnrollmentProfile[]

		remoteActionAudits?: RemoteActionAudit[]

		applePushNotificationCertificate?: ApplePushNotificationCertificate

		deviceManagementScripts?: DeviceManagementScript[]

		managedDeviceOverview?: ManagedDeviceOverview

		detectedApps?: DetectedApp[]

		managedDevices?: ManagedDevice[]

		windowsMalwareInformation?: WindowsMalwareInformation[]

		dataSharingConsents?: DataSharingConsent[]

		deviceConfigurations?: DeviceConfiguration[]

		deviceCompliancePolicies?: DeviceCompliancePolicy[]

		softwareUpdateStatusSummary?: SoftwareUpdateStatusSummary

		deviceCompliancePolicyDeviceStateSummary?: DeviceCompliancePolicyDeviceStateSummary

		deviceCompliancePolicySettingStateSummaries?: DeviceCompliancePolicySettingStateSummary[]

		advancedThreatProtectionOnboardingStateSummary?: AdvancedThreatProtectionOnboardingStateSummary

		deviceConfigurationDeviceStateSummaries?: DeviceConfigurationDeviceStateSummary

		deviceConfigurationUserStateSummaries?: DeviceConfigurationUserStateSummary

		cartToClassAssociations?: CartToClassAssociation[]

		iosUpdateStatuses?: IosUpdateDeviceStatus[]

		ndesConnectors?: NdesConnector[]

		deviceConfigurationRestrictedAppsViolations?: RestrictedAppsViolation[]

		deviceCategories?: DeviceCategory[]

		exchangeConnectors?: DeviceManagementExchangeConnector[]

		deviceEnrollmentConfigurations?: DeviceEnrollmentConfiguration[]

		exchangeOnPremisesPolicy?: DeviceManagementExchangeOnPremisesPolicy

		exchangeOnPremisesPolicies?: DeviceManagementExchangeOnPremisesPolicy[]

		conditionalAccessSettings?: OnPremisesConditionalAccessSettings

		mobileThreatDefenseConnectors?: MobileThreatDefenseConnector[]

		deviceManagementPartners?: DeviceManagementPartner[]

		managementConditions?: ManagementCondition[]

		managementConditionStatements?: ManagementConditionStatement[]

		notificationMessageTemplates?: NotificationMessageTemplate[]

		roleDefinitions?: RoleDefinition[]

		roleAssignments?: DeviceAndAppManagementRoleAssignment[]

		roleScopeTags?: RoleScopeTag[]

		resourceOperations?: ResourceOperation[]

		embeddedSIMActivationCodePools?: EmbeddedSIMActivationCodePool[]

		telecomExpenseManagementPartners?: TelecomExpenseManagementPartner[]

		windowsAutopilotSettings?: WindowsAutopilotSettings

		windowsAutopilotDeviceIdentities?: WindowsAutopilotDeviceIdentity[]

		windowsAutopilotDeploymentProfiles?: WindowsAutopilotDeploymentProfile[]

		importedDeviceIdentities?: ImportedDeviceIdentity[]

		depOnboardingSettings?: DepOnboardingSetting[]

		importedWindowsAutopilotDeviceIdentities?: ImportedWindowsAutopilotDeviceIdentity[]

		remoteAssistancePartners?: RemoteAssistancePartner[]

		windowsInformationProtectionAppLearningSummaries?: WindowsInformationProtectionAppLearningSummary[]

		windowsInformationProtectionNetworkLearningSummaries?: WindowsInformationProtectionNetworkLearningSummary[]

		auditEvents?: AuditEvent[]

		troubleshootingEvents?: DeviceManagementTroubleshootingEvent[]

		userPfxCertificates?: UserPFXCertificate[]

}

export interface TermsAndConditions extends Entity {

	    /** DateTime the object was created. */
		createdDateTime?: string

	    /** DateTime the object was last modified. */
		modifiedDateTime?: string

	    /** DateTime the object was last modified. */
		lastModifiedDateTime?: string

	    /** Administrator-supplied name for the T&C policy. */
		displayName?: string

	    /** Administrator-supplied description of the T&C policy. */
		description?: string

	    /** Administrator-supplied title of the terms and conditions. This is shown to the user on prompts to accept the T&C policy. */
		title?: string

	    /** Administrator-supplied body text of the terms and conditions, typically the terms themselves. This is shown to the user on prompts to accept the T&C policy. */
		bodyText?: string

	    /** Administrator-supplied explanation of the terms and conditions, typically describing what it means to accept the terms and conditions set out in the T&C policy. This is shown to the user on prompts to accept the T&C policy. */
		acceptanceStatement?: string

	    /** Integer indicating the current version of the terms. Incremented when an administrator makes a change to the terms and wishes to require users to re-accept the modified T&C policy. */
		version?: number

	    /** The list of group assignments for this T&C policy. */
		groupAssignments?: TermsAndConditionsGroupAssignment[]

	    /** The list of assignments for this T&C policy. */
		assignments?: TermsAndConditionsAssignment[]

	    /** The list of acceptance statuses for this T&C policy. */
		acceptanceStatuses?: TermsAndConditionsAcceptanceStatus[]

}

export interface AndroidForWorkSettings extends Entity {

	    /** Bind status of the tenant with the Google EMM API. Possible values are: notBound, bound, boundAndValidated, unbinding. */
		bindStatus?: AndroidForWorkBindStatus

	    /** Last completion time for app sync */
		lastAppSyncDateTime?: string

	    /** Last application sync result. Possible values are: success, credentialsNotValid, androidForWorkApiError, managementServiceError, unknownError, none. */
		lastAppSyncStatus?: AndroidForWorkSyncStatus

	    /** Owner UPN that created the enterprise */
		ownerUserPrincipalName?: string

	    /** Organization name used when onboarding Android for Work */
		ownerOrganizationName?: string

	    /** Last modification time for Android for Work settings */
		lastModifiedDateTime?: string

	    /** Indicates which users can enroll devices in Android for Work device management. Possible values are: none, all, targeted, targetedAsEnrollmentRestrictions. */
		enrollmentTarget?: AndroidForWorkEnrollmentTarget

	    /** Specifies which AAD groups can enroll devices in Android for Work device management if enrollmentTarget is set to 'Targeted' */
		targetGroupIds?: string[]

	    /** Indicates if this account is flighting for Android Device Owner Management with CloudDPC. */
		deviceOwnerManagementEnabled?: boolean

}

export interface AndroidForWorkAppConfigurationSchema extends Entity {

	    /** UTF8 encoded byte array containing example JSON string conforming to this schema that demonstrates how to set the configuration for this app */
		exampleJson?: number

	    /** Collection of items each representing a named configuration option in the schema */
		schemaItems?: AndroidForWorkAppConfigurationSchemaItem[]

}

export interface AndroidForWorkEnrollmentProfile extends Entity {

	    /** Tenant GUID the enrollment profile belongs to. */
		accountId?: string

	    /** Display name for the enrollment profile. */
		displayName?: string

	    /** Description for the enrollment profile. */
		description?: string

	    /** Date time the enrollment profile was created. */
		createdDateTime?: string

	    /** Date time the enrollment profile was last modified. */
		lastModifiedDateTime?: string

	    /** Value of the most recently created token for this enrollment profile. */
		tokenValue?: string

	    /** Date time the most recently created token will expire. */
		tokenExpirationDateTime?: string

	    /** Total number of Android devices that have enrolled using this enrollment profile. */
		enrolledDeviceCount?: number

	    /** String used to generate a QR code for the token. */
		qrCodeContent?: string

	    /** String used to generate a QR code for the token. */
		qrCodeImage?: MimeContent

}

export interface AndroidManagedStoreAccountEnterpriseSettings extends Entity {

	    /** Bind status of the tenant with the Google EMM API. Possible values are: notBound, bound, boundAndValidated, unbinding. */
		bindStatus?: AndroidManagedStoreAccountBindStatus

	    /** Last completion time for app sync */
		lastAppSyncDateTime?: string

	    /** Last application sync result. Possible values are: success, credentialsNotValid, androidForWorkApiError, managementServiceError, unknownError, none. */
		lastAppSyncStatus?: AndroidManagedStoreAccountAppSyncStatus

	    /** Owner UPN that created the enterprise */
		ownerUserPrincipalName?: string

	    /** Organization name used when onboarding Android Enterprise */
		ownerOrganizationName?: string

	    /** Last modification time for Android enterprise settings */
		lastModifiedDateTime?: string

	    /** Indicates which users can enroll devices in Android Enterprise device management. Possible values are: none, all, targeted, targetedAsEnrollmentRestrictions. */
		enrollmentTarget?: AndroidManagedStoreAccountEnrollmentTarget

	    /** Specifies which AAD groups can enroll devices in Android for Work device management if enrollmentTarget is set to 'Targeted' */
		targetGroupIds?: string[]

	    /** Indicates if this account is flighting for Android Device Owner Management with CloudDPC. */
		deviceOwnerManagementEnabled?: boolean

}

export interface AndroidManagedStoreAppConfigurationSchema extends Entity {

	    /** UTF8 encoded byte array containing example JSON string conforming to this schema that demonstrates how to set the configuration for this app */
		exampleJson?: number

	    /** Collection of items each representing a named configuration option in the schema */
		schemaItems?: AndroidManagedStoreAppConfigurationSchemaItem[]

}

export interface AndroidDeviceOwnerEnrollmentProfile extends Entity {

	    /** Tenant GUID the enrollment profile belongs to. */
		accountId?: string

	    /** Display name for the enrollment profile. */
		displayName?: string

	    /** Description for the enrollment profile. */
		description?: string

	    /** Date time the enrollment profile was created. */
		createdDateTime?: string

	    /** Date time the enrollment profile was last modified. */
		lastModifiedDateTime?: string

	    /** Value of the most recently created token for this enrollment profile. */
		tokenValue?: string

	    /** Date time the most recently created token will expire. */
		tokenExpirationDateTime?: string

	    /** Total number of Android devices that have enrolled using this enrollment profile. */
		enrolledDeviceCount?: number

	    /** String used to generate a QR code for the token. */
		qrCodeContent?: string

	    /** String used to generate a QR code for the token. */
		qrCodeImage?: MimeContent

}

export interface RemoteActionAudit extends Entity {

	    /** Intune device name. */
		deviceDisplayName?: string

	    /** [deprecated] Please use InitiatedByUserPrincipalName instead. */
		userName?: string

	    /** User who initiated the device action, format is UPN. */
		initiatedByUserPrincipalName?: string

	    /** The action name. Possible values are: unknown, factoryReset, removeCompanyData, resetPasscode, remoteLock, enableLostMode, disableLostMode, locateDevice, rebootNow, recoverPasscode, cleanWindowsDevice, logoutSharedAppleDeviceActiveUser, quickScan, fullScan, windowsDefenderUpdateSignatures, factoryResetKeepEnrollmentData, updateDeviceAccount, automaticRedeployment, shutDown. */
		action?: RemoteAction

	    /** Time when the action was issued, given in UTC. */
		requestDateTime?: string

	    /** Upn of the device owner. */
		deviceOwnerUserPrincipalName?: string

	    /** IMEI of the device. */
		deviceIMEI?: string

	    /** Action state. Possible values are: none, pending, canceled, active, done, failed, notSupported. */
		actionState?: ActionState

}

export interface ApplePushNotificationCertificate extends Entity {

	    /** Apple Id of the account used to create the MDM push certificate. */
		appleIdentifier?: string

	    /** Topic Id. */
		topicIdentifier?: string

	    /** Last modified date and time for Apple push notification certificate. */
		lastModifiedDateTime?: string

	    /** The expiration date and time for Apple push notification certificate. */
		expirationDateTime?: string

	    /** The certificate upload status. */
		certificateUploadStatus?: string

	    /** The reason the certificate upload failed. */
		certificateUploadFailureReason?: string

	    /** Not yet documented */
		certificate?: string

}

export interface DeviceManagementScript extends Entity {

	    /** Name of the device management script. */
		displayName?: string

	    /** Optional description for the device management script. */
		description?: string

	    /** The interval for script to run. If not defined the script will run once */
		runSchedule?: RunSchedule

	    /** The script content. */
		scriptContent?: number

	    /** The date and time the device management script was created. */
		createdDateTime?: string

	    /** The date and time the device management script was last modified. */
		lastModifiedDateTime?: string

	    /** Indicates the type of execution context the device management script runs in. Possible values are: system, user. */
		runAsAccount?: RunAsAccountType

	    /** Indicate whether the script signature needs be checked. */
		enforceSignatureCheck?: boolean

	    /** Script file name. */
		fileName?: string

	    /** The list of group assignments for the device management script. */
		groupAssignments?: DeviceManagementScriptGroupAssignment[]

	    /** The list of group assignments for the device management script. */
		assignments?: DeviceManagementScriptAssignment[]

	    /** Run summary for device management script. */
		runSummary?: DeviceManagementScriptRunSummary

	    /** List of run states for this script across all devices. */
		deviceRunStates?: DeviceManagementScriptDeviceState[]

	    /** List of run states for this script across all users. */
		userRunStates?: DeviceManagementScriptUserState[]

}

export interface ManagedDeviceOverview extends Entity {

	    /** Total enrolled device count. Does not include PC devices managed via Intune PC Agent */
		enrolledDeviceCount?: number

	    /** The number of devices enrolled in MDM */
		mdmEnrolledCount?: number

	    /** The number of devices enrolled in both MDM and EAS */
		dualEnrolledDeviceCount?: number

	    /** Device operating system summary. */
		deviceOperatingSystemSummary?: DeviceOperatingSystemSummary

	    /** Distribution of Exchange Access State in Intune */
		deviceExchangeAccessStateSummary?: DeviceExchangeAccessStateSummary

	    /** Models and Manufactures meatadata for managed devices in the account */
		managedDeviceModelsAndManufacturers?: ManagedDeviceModelsAndManufacturers

	    /** Last modified date time of device overview */
		lastModifiedDateTime?: string

}

export interface DetectedApp extends Entity {

	    /** Name of the discovered application. Read-only */
		displayName?: string

	    /** Version of the discovered application. Read-only */
		version?: string

	    /** Discovered application size in bytes. Read-only */
		sizeInByte?: number

	    /** The number of devices that have installed this application */
		deviceCount?: number

	    /** The devices that have the discovered application installed */
		managedDevices?: ManagedDevice[]

}

export interface WindowsMalwareInformation extends Entity {

	    /** Malware name */
		displayName?: string

	    /** Information URL to learn more about the malware */
		additionalInformationUrl?: string

	    /** Severity of the malware. Possible values are: unknown, low, moderate, high, severe. */
		severity?: WindowsMalwareSeverity

	    /** Category of the malware. Possible values are: invalid, adware, spyware, passwordStealer, trojanDownloader, worm, backdoor, remoteAccessTrojan, trojan, emailFlooder, keylogger, dialer, monitoringSoftware, browserModifier, cookie, browserPlugin, aolExploit, nuker, securityDisabler, jokeProgram, hostileActiveXControl, softwareBundler, stealthNotifier, settingsModifier, toolBar, remoteControlSoftware, trojanFtp, potentialUnwantedSoftware, icqExploit, trojanTelnet, exploit, filesharingProgram, malwareCreationTool, remote_Control_Software, tool, trojanDenialOfService, trojanDropper, trojanMassMailer, trojanMonitoringSoftware, trojanProxyServer, virus, known, unknown, spp, behavior, vulnerability, policy. */
		category?: WindowsMalwareCategory

	    /** The last time the malware is detected */
		lastDetectionDateTime?: string

	    /** List of devices' protection status affected with the current malware */
		windowsDevicesProtectionState?: WindowsProtectionState[]

}

export interface DataSharingConsent extends Entity {

	    /** The display name of the service work flow */
		serviceDisplayName?: string

	    /** The TermsUrl for the data sharing consent */
		termsUrl?: string

	    /** The granted state for the data sharing consent */
		granted?: boolean

	    /** The time consent was granted for this account */
		grantDateTime?: string

	    /** The Upn of the user that granted consent for this account */
		grantedByUpn?: string

	    /** The UserId of the user that granted consent for this account */
		grantedByUserId?: string

}

export interface DeviceConfiguration extends Entity {

	    /** DateTime the object was last modified. */
		lastModifiedDateTime?: string

		roleScopeTagIds?: string[]

		supportsScopeTags?: boolean

	    /** DateTime the object was created. */
		createdDateTime?: string

	    /** Admin provided description of the Device Configuration. */
		description?: string

	    /** Admin provided name of the device configuration. */
		displayName?: string

	    /** Version of the device configuration. */
		version?: number

	    /** The list of group assignments for the device configuration profile. */
		groupAssignments?: DeviceConfigurationGroupAssignment[]

	    /** The list of assignments for the device configuration profile. */
		assignments?: DeviceConfigurationAssignment[]

	    /** Device configuration installation status by device. */
		deviceStatuses?: DeviceConfigurationDeviceStatus[]

	    /** Device configuration installation status by user. */
		userStatuses?: DeviceConfigurationUserStatus[]

	    /** Device Configuration devices status overview */
		deviceStatusOverview?: DeviceConfigurationDeviceOverview

	    /** Device Configuration users status overview */
		userStatusOverview?: DeviceConfigurationUserOverview

	    /** Device Configuration Setting State Device Summary */
		deviceSettingStateSummaries?: SettingStateDeviceSummary[]

}

export interface DeviceCompliancePolicy extends Entity {

		roleScopeTagIds?: string[]

	    /** DateTime the object was created. */
		createdDateTime?: string

	    /** Admin provided description of the Device Configuration. */
		description?: string

	    /** DateTime the object was last modified. */
		lastModifiedDateTime?: string

	    /** Admin provided name of the device configuration. */
		displayName?: string

	    /** Version of the device configuration. */
		version?: number

	    /** The list of scheduled action for this rule */
		scheduledActionsForRule?: DeviceComplianceScheduledActionForRule[]

	    /** List of DeviceComplianceDeviceStatus. */
		deviceStatuses?: DeviceComplianceDeviceStatus[]

	    /** List of DeviceComplianceUserStatus. */
		userStatuses?: DeviceComplianceUserStatus[]

	    /** Device compliance devices status overview */
		deviceStatusOverview?: DeviceComplianceDeviceOverview

	    /** Device compliance users status overview */
		userStatusOverview?: DeviceComplianceUserOverview

	    /** Compliance Setting State Device Summary */
		deviceSettingStateSummaries?: SettingStateDeviceSummary[]

	    /** The collection of assignments for this compliance policy. */
		assignments?: DeviceCompliancePolicyAssignment[]

}

export interface SoftwareUpdateStatusSummary extends Entity {

	    /** The name of the policy. */
		displayName?: string

	    /** Number of compliant devices. */
		compliantDeviceCount?: number

	    /** Number of non compliant devices. */
		nonCompliantDeviceCount?: number

	    /** Number of remediated devices. */
		remediatedDeviceCount?: number

	    /** Number of devices had error. */
		errorDeviceCount?: number

	    /** Number of unknown devices. */
		unknownDeviceCount?: number

	    /** Number of conflict devices. */
		conflictDeviceCount?: number

	    /** Number of not applicable devices. */
		notApplicableDeviceCount?: number

	    /** Number of compliant users. */
		compliantUserCount?: number

	    /** Number of non compliant users. */
		nonCompliantUserCount?: number

	    /** Number of remediated users. */
		remediatedUserCount?: number

	    /** Number of users had error. */
		errorUserCount?: number

	    /** Number of unknown users. */
		unknownUserCount?: number

	    /** Number of conflict users. */
		conflictUserCount?: number

	    /** Number of not applicable users. */
		notApplicableUserCount?: number

}

export interface DeviceCompliancePolicyDeviceStateSummary extends Entity {

	    /** Number of devices that are in grace period */
		inGracePeriodCount?: number

	    /** Number of devices that have compliance managed by System Center Configuration Manager */
		configManagerCount?: number

	    /** Number of unknown devices */
		unknownDeviceCount?: number

	    /** Number of not applicable devices */
		notApplicableDeviceCount?: number

	    /** Number of compliant devices */
		compliantDeviceCount?: number

	    /** Number of remediated devices */
		remediatedDeviceCount?: number

	    /** Number of NonCompliant devices */
		nonCompliantDeviceCount?: number

	    /** Number of error devices */
		errorDeviceCount?: number

	    /** Number of conflict devices */
		conflictDeviceCount?: number

}

export interface DeviceCompliancePolicySettingStateSummary extends Entity {

	    /** The setting class name and property name. */
		setting?: string

	    /** Name of the setting. */
		settingName?: string

	    /** Setting platform. Possible values are: android, androidForWork, iOS, macOS, windowsPhone81, windows81AndLater, windows10AndLater, androidWorkProfile, all. */
		platformType?: PolicyPlatformType

	    /** Number of unknown devices */
		unknownDeviceCount?: number

	    /** Number of not applicable devices */
		notApplicableDeviceCount?: number

	    /** Number of compliant devices */
		compliantDeviceCount?: number

	    /** Number of remediated devices */
		remediatedDeviceCount?: number

	    /** Number of NonCompliant devices */
		nonCompliantDeviceCount?: number

	    /** Number of error devices */
		errorDeviceCount?: number

	    /** Number of conflict devices */
		conflictDeviceCount?: number

	    /** Not yet documented */
		deviceComplianceSettingStates?: DeviceComplianceSettingState[]

}

export interface AdvancedThreatProtectionOnboardingStateSummary extends Entity {

		unknownDeviceCount?: number

		notApplicableDeviceCount?: number

		compliantDeviceCount?: number

		remediatedDeviceCount?: number

		nonCompliantDeviceCount?: number

		errorDeviceCount?: number

		conflictDeviceCount?: number

		notAssignedDeviceCount?: number

		advancedThreatProtectionOnboardingDeviceSettingStates?: AdvancedThreatProtectionOnboardingDeviceSettingState[]

}

export interface DeviceConfigurationDeviceStateSummary extends Entity {

	    /** Number of unknown devices */
		unknownDeviceCount?: number

	    /** Number of not applicable devices */
		notApplicableDeviceCount?: number

	    /** Number of compliant devices */
		compliantDeviceCount?: number

	    /** Number of remediated devices */
		remediatedDeviceCount?: number

	    /** Number of NonCompliant devices */
		nonCompliantDeviceCount?: number

	    /** Number of error devices */
		errorDeviceCount?: number

	    /** Number of conflict devices */
		conflictDeviceCount?: number

}

export interface DeviceConfigurationUserStateSummary extends Entity {

	    /** Number of unknown users */
		unknownUserCount?: number

	    /** Number of not applicable users */
		notApplicableUserCount?: number

	    /** Number of compliant users */
		compliantUserCount?: number

	    /** Number of remediated users */
		remediatedUserCount?: number

	    /** Number of NonCompliant users */
		nonCompliantUserCount?: number

	    /** Number of error users */
		errorUserCount?: number

	    /** Number of conflict users */
		conflictUserCount?: number

}

export interface CartToClassAssociation extends Entity {

	    /** DateTime the object was created. */
		createdDateTime?: string

	    /** DateTime the object was last modified. */
		lastModifiedDateTime?: string

	    /** Version of the CartToClassAssociation. */
		version?: number

	    /** Admin provided name of the device configuration. */
		displayName?: string

	    /** Admin provided description of the CartToClassAssociation. */
		description?: string

	    /** Identifiers of device carts to be associated with classes. */
		deviceCartIds?: string[]

	    /** Identifiers of classrooms to be associated with device carts. */
		classroomIds?: string[]

}

export interface IosUpdateDeviceStatus extends Entity {

	    /** The installation status of the policy report. Possible values are: success, available, idle, downloading, downloadFailed, downloadRequiresComputer, downloadInsufficientSpace, downloadInsufficientPower, downloadInsufficientNetwork, installing, installInsufficientSpace, installInsufficientPower, installPhoneCallInProgress, installFailed, notSupportedOperation, sharedDeviceUserLoggedInError. */
		installStatus?: IosUpdatesInstallStatus

	    /** The device version that is being reported. */
		osVersion?: string

	    /** The device id that is being reported. */
		deviceId?: string

	    /** The User id that is being reported. */
		userId?: string

	    /** Device name of the DevicePolicyStatus. */
		deviceDisplayName?: string

	    /** The User Name that is being reported */
		userName?: string

	    /** The device model that is being reported */
		deviceModel?: string

	    /** Platform of the device that is being reported */
		platform?: number

	    /** The DateTime when device compliance grace period expires */
		complianceGracePeriodExpirationDateTime?: string

	    /** Compliance status of the policy report. Possible values are: unknown, notApplicable, compliant, remediated, nonCompliant, error, conflict. */
		status?: ComplianceStatus

	    /** Last modified date time of the policy report. */
		lastReportedDateTime?: string

	    /** UserPrincipalName. */
		userPrincipalName?: string

}

export interface NdesConnector extends Entity {

	    /** Last connection time for the Ndes Connector */
		lastConnectionDateTime?: string

	    /** Ndes Connector Status. Possible values are: none, active, inactive. */
		state?: NdesConnectorState

	    /** The friendly name of the Ndes Connector. */
		displayName?: string

}

export interface RestrictedAppsViolation extends Entity {

	    /** User unique identifier, must be Guid */
		userId?: string

	    /** User name */
		userName?: string

	    /** Managed device unique identifier, must be Guid */
		managedDeviceId?: string

	    /** Device name */
		deviceName?: string

	    /** Device configuration profile unique identifier, must be Guid */
		deviceConfigurationId?: string

	    /** Device configuration profile name */
		deviceConfigurationName?: string

	    /** Platform type. Possible values are: android, androidForWork, iOS, macOS, windowsPhone81, windows81AndLater, windows10AndLater, androidWorkProfile, all. */
		platformType?: PolicyPlatformType

	    /** Restricted apps state. Possible values are: prohibitedApps, notApprovedApps. */
		restrictedAppsState?: RestrictedAppsState

	    /** List of violated restricted apps */
		restrictedApps?: ManagedDeviceReportedApp[]

}

export interface DeviceCategory extends Entity {

	    /** Display name for the device category. */
		displayName?: string

	    /** Optional description for the device category. */
		description?: string

}

export interface DeviceManagementExchangeConnector extends Entity {

	    /** Last sync time for the Exchange Connector */
		lastSyncDateTime?: string

	    /** Exchange Connector Status. Possible values are: none, connectionPending, connected, disconnected. */
		status?: DeviceManagementExchangeConnectorStatus

	    /** Email address used to configure the Service To Service Exchange Connector. */
		primarySmtpAddress?: string

	    /** The name of the server hosting the Exchange Connector. */
		serverName?: string

		connectorServerName?: string

	    /** The type of Exchange Connector Configured. Possible values are: onPremises, hosted, serviceToService, dedicated. */
		exchangeConnectorType?: DeviceManagementExchangeConnectorType

	    /** The version of the ExchangeConnectorAgent */
		version?: string

	    /** An alias assigned to the Exchange server */
		exchangeAlias?: string

	    /** Exchange Organization to the Exchange server */
		exchangeOrganization?: string

}

export interface DeviceManagementExchangeOnPremisesPolicy extends Entity {

	    /** Notification text that will be sent to users quarantined by this policy. This is UTF8 encoded byte array HTML. */
		notificationContent?: number

	    /** Default access state in Exchange. This rule applies globally to the entire Exchange organization. Possible values are: none, allow, block, quarantine. */
		defaultAccessLevel?: DeviceManagementExchangeAccessLevel

	    /** The list of device access rules in Exchange. The access rules apply globally to the entire Exchange organization */
		accessRules?: DeviceManagementExchangeAccessRule[]

	    /** The list of device classes known to Exchange */
		knownDeviceClasses?: DeviceManagementExchangeDeviceClass[]

	    /** The Exchange on premises conditional access settings. On premises conditional access will require devices to be both enrolled and compliant for mail access */
		conditionalAccessSettings?: OnPremisesConditionalAccessSettings

}

export interface OnPremisesConditionalAccessSettings extends Entity {

	    /** Indicates if on premises conditional access is enabled for this organization */
		enabled?: boolean

	    /** User groups that will be targeted by on premises conditional access. All users in these groups will be required to have mobile device managed and compliant for mail access. */
		includedGroups?: string[]

	    /** User groups that will be exempt by on premises conditional access. All users in these groups will be exempt from the conditional access policy. */
		excludedGroups?: string[]

	    /** Override the default access rule when allowing a device to ensure access is granted. */
		overrideDefaultRule?: boolean

}

export interface MobileThreatDefenseConnector extends Entity {

	    /** DateTime of last Heartbeat recieved from the Data Sync Partner */
		lastHeartbeatDateTime?: string

	    /** Data Sync Partner state for this account. Possible values are: unavailable, available, enabled, unresponsive. */
		partnerState?: MobileThreatPartnerTenantState

	    /** For Android, set whether data from the data sync partner should be used during compliance evaluations */
		androidEnabled?: boolean

	    /** For IOS, get or set whether data from the data sync partner should be used during compliance evaluations */
		iosEnabled?: boolean

	    /** For Windows, get or set whether data from the data sync partner should be used during compliance evaluations */
		windowsEnabled?: boolean

	    /** For Mac, get or set whether data from the data sync partner should be used during compliance evaluations */
		macEnabled?: boolean

	    /** For Android, set whether Intune must receive data from the data sync partner prior to marking a device compliant */
		androidDeviceBlockedOnMissingPartnerData?: boolean

	    /** For IOS, set whether Intune must receive data from the data sync partner prior to marking a device compliant */
		iosDeviceBlockedOnMissingPartnerData?: boolean

	    /** For Windows, set whether Intune must receive data from the data sync partner prior to marking a device compliant */
		windowsDeviceBlockedOnMissingPartnerData?: boolean

	    /** For Mac, get or set whether Intune must receive data from the data sync partner prior to marking a device compliant */
		macDeviceBlockedOnMissingPartnerData?: boolean

	    /** Get or set whether to block devices on the enabled platforms that do not meet the minimum version requirements of the Data Sync Partner */
		partnerUnsupportedOsVersionBlocked?: boolean

	    /** Get or Set days the per tenant tolerance to unresponsiveness for this partner integration */
		partnerUnresponsivenessThresholdInDays?: number

	    /** For IOS devices, allows the admin to configure whether the data sync partner may also collect metadata about installed applications from Intune */
		allowPartnerToCollectIOSApplicationMetadata?: boolean

}

export interface DeviceManagementPartner extends Entity {

	    /** Timestamp of last heartbeat after admin enabled option Connect to Device management Partner */
		lastHeartbeatDateTime?: string

	    /** Partner state of this tenant. Possible values are: unknown, unavailable, enabled, terminated, rejected, unresponsive. */
		partnerState?: DeviceManagementPartnerTenantState

	    /** Partner App type. Possible values are: unknown, singleTenantApp, multiTenantApp. */
		partnerAppType?: DeviceManagementPartnerAppType

	    /** Partner Single tenant App id */
		singleTenantAppId?: string

	    /** Partner display name */
		displayName?: string

	    /** Whether device management partner is configured or not */
		isConfigured?: boolean

	    /** DateTime in UTC when PartnerDevices will be removed. This will become obselete soon. */
		whenPartnerDevicesWillBeRemoved?: string

	    /** DateTime in UTC when PartnerDevices will be marked as NonCompliant. This will become obselete soon. */
		whenPartnerDevicesWillBeMarkedAsNonCompliant?: string

	    /** DateTime in UTC when PartnerDevices will be removed */
		whenPartnerDevicesWillBeRemovedDateTime?: string

	    /** DateTime in UTC when PartnerDevices will be marked as NonCompliant */
		whenPartnerDevicesWillBeMarkedAsNonCompliantDateTime?: string

}

export interface ManagementCondition extends Entity {

		uniqueName?: string

		displayName?: string

		description?: string

		createdDateTime?: string

		modifiedDateTime?: string

		eTag?: string

		applicablePlatforms?: DevicePlatformType[]

		managementConditionStatements?: ManagementConditionStatement[]

}

export interface ManagementConditionStatement extends Entity {

		displayName?: string

		description?: string

		createdDateTime?: string

		modifiedDateTime?: string

		expression?: ManagementConditionExpression

		eTag?: string

	    /** This is calculated from looking the management conditions associated to the management condition statement and finding the intersection of applicable platforms. */
		applicablePlatforms?: DevicePlatformType[]

		managementConditions?: ManagementCondition[]

}

export interface NotificationMessageTemplate extends Entity {

	    /** DateTime the object was last modified. */
		lastModifiedDateTime?: string

	    /** Display name for the Notification Message Template. */
		displayName?: string

	    /** The default locale to fallback onto when the requested locale is not available. */
		defaultLocale?: string

	    /** The Message Template Branding Options. Branding is defined in the Intune Admin Console. Possible values are: none, includeCompanyLogo, includeCompanyName, includeContactInformation. */
		brandingOptions?: NotificationTemplateBrandingOptions

		roleScopeTagIds?: string[]

	    /** The list of localized messages for this Notification Message Template. */
		localizedNotificationMessages?: LocalizedNotificationMessage[]

}

export interface RoleDefinition extends Entity {

	    /** Display Name of the Role definition. */
		displayName?: string

	    /** Description of the Role definition. */
		description?: string

	    /** List of Role Permissions this role is allowed to perform. These must match the actionName that is defined as part of the rolePermission. */
		permissions?: RolePermission[]

	    /** List of Role Permissions this role is allowed to perform. These must match the actionName that is defined as part of the rolePermission. */
		rolePermissions?: RolePermission[]

	    /** Type of Role. Set to True if it is built-in, or set to False if it is a custom role definition. */
		isBuiltInRoleDefinition?: boolean

	    /** Type of Role. Set to True if it is built-in, or set to False if it is a custom role definition. */
		isBuiltIn?: boolean

	    /** List of Role assignments for this role definition. */
		roleAssignments?: RoleAssignment[]

}

export interface RoleAssignment extends Entity {

	    /** The display or friendly name of the role Assignment. */
		displayName?: string

	    /** Description of the Role Assignment. */
		description?: string

	    /** List of ids of role scope member security groups.  These are IDs from Azure Active Directory. */
		scopeMembers?: string[]

	    /** Specifies the type of scope for a Role Assignment. Default type 'ResourceScope' allows assignment of ResourceScopes. For 'AllDevices', 'AllLicensedUsers', and 'AllDevicesAndLicensedUsers', the ResourceScopes property should be left empty. Possible values are: resourceScope, allDevices, allLicensedUsers, allDevicesAndLicensedUsers. */
		scopeType?: RoleAssignmentScopeType

	    /** List of ids of role scope member security groups.  These are IDs from Azure Active Directory. */
		resourceScopes?: string[]

	    /** Role definition this assignment is part of. */
		roleDefinition?: RoleDefinition

}

export interface DeviceAndAppManagementRoleAssignment extends RoleAssignment {

	    /** The list of ids of role member security groups. These are IDs from Azure Active Directory. */
		members?: string[]

		roleScopeTags?: RoleScopeTag[]

}

export interface RoleScopeTag extends Entity {

		displayName?: string

		description?: string

}

export interface ResourceOperation extends Entity {

		resource?: string

	    /** Name of the Resource this operation is performed on. */
		resourceName?: string

	    /** Type of action this operation is going to perform. The actionName should be concise and limited to as few words as possible. */
		actionName?: string

	    /** Description of the resource operation. The description is used in mouse-over text for the operation when shown in the Azure Portal. */
		description?: string

}

export interface EmbeddedSIMActivationCodePool extends Entity {

		displayName?: string

		createdDateTime?: string

		modifiedDateTime?: string

		activationCodes?: EmbeddedSIMActivationCode[]

		activationCodeCount?: number

		assignments?: EmbeddedSIMActivationCodePoolAssignment[]

		deviceStates?: EmbeddedSIMDeviceState[]

}

export interface TelecomExpenseManagementPartner extends Entity {

	    /** Display name of the TEM partner. */
		displayName?: string

	    /** URL of the TEM partner's administrative control panel, where an administrator can configure their TEM service. */
		url?: string

	    /** Whether the partner's AAD app has been authorized to access Intune. */
		appAuthorized?: boolean

	    /** Whether Intune's connection to the TEM service is currently enabled or disabled. */
		enabled?: boolean

	    /** Timestamp of the last request sent to Intune by the TEM partner. */
		lastConnectionDateTime?: string

}

export interface WindowsAutopilotSettings extends Entity {

	    /** Last data sync date time with DDS service. */
		lastSyncDateTime?: string

	    /** Last data sync date time with DDS service. */
		lastManualSyncTriggerDateTime?: string

	    /** Indicates the status of sync with Device data sync (DDS) service. Possible values are: unknown, inProgress, completed, failed. */
		syncStatus?: WindowsAutopilotSyncStatus

}

export interface WindowsAutopilotDeviceIdentity extends Entity {

	    /** Profile assignment status of the Windows autopilot device. Possible values are: unknown, assignedInSync, assignedOutOfSync, assignedUnkownSyncState, notAssigned, pending, failed. */
		deploymentProfileAssignmentStatus?: WindowsAutopilotProfileAssignmentStatus

	    /** Profile set time of the Windows autopilot device. */
		deploymentProfileAssignedDateTime?: string

	    /** Order Identifier of the Windows autopilot device. */
		orderIdentifier?: string

	    /** Purchase Order Identifier of the Windows autopilot device. */
		purchaseOrderIdentifier?: string

	    /** Serial number of the Windows autopilot device. */
		serialNumber?: string

	    /** Product Key of the Windows autopilot device. */
		productKey?: string

	    /** Oem manufacturer of the Windows autopilot device. */
		manufacturer?: string

	    /** Model name of the Windows autopilot device. */
		model?: string

	    /** Intune enrollment state of the Windows autopilot device. Possible values are: unknown, enrolled, pendingReset, failed, notContacted. */
		enrollmentState?: EnrollmentState

	    /** Intune Last Contacted Date Time of the Windows autopilot device. */
		lastContactedDateTime?: string

		addressableUserName?: string

		userPrincipalName?: string

	    /** Deployment profile assigned to the Windows autopilot device. */
		deploymentProfile?: WindowsAutopilotDeploymentProfile

}

export interface WindowsAutopilotDeploymentProfile extends Entity {

	    /** Name of the profile */
		displayName?: string

	    /** Description of the profile */
		description?: string

	    /** Language configured on the device */
		language?: string

	    /** Profile creation time */
		createdDateTime?: string

	    /** Profile last modified time */
		lastModifiedDateTime?: string

	    /** Out of box experience setting */
		outOfBoxExperienceSettings?: OutOfBoxExperienceSettings

	    /** Enrollment status screen setting */
		enrollmentStatusScreenSettings?: WindowsEnrollmentStatusScreenSettings

		extractHardwareHash?: boolean

		deviceNameTemplate?: string

	    /** The list of assigned devices for the profile. */
		assignedDevices?: WindowsAutopilotDeviceIdentity[]

	    /** The list of group assignments for the profile. */
		assignments?: WindowsAutopilotDeploymentProfileAssignment[]

}

export interface ImportedDeviceIdentity extends Entity {

	    /** Imported Device Identifier */
		importedDeviceIdentifier?: string

	    /** Type of Imported Device Identity. Possible values are: unknown, imei, serialNumber. */
		importedDeviceIdentityType?: ImportedDeviceIdentityType

	    /** Last Modified DateTime of the description */
		lastModifiedDateTime?: string

	    /** Created Date Time of the device */
		createdDateTime?: string

	    /** Last Contacted Date Time of the device */
		lastContactedDateTime?: string

	    /** The description of the device */
		description?: string

	    /** The state of the device in Intune. Possible values are: unknown, enrolled, pendingReset, failed, notContacted. */
		enrollmentState?: EnrollmentState

	    /** The platform of the Device. Possible values are: unknown, ios, android, windows, windowsMobile, macOS. */
		platform?: Platform

}

export interface DepOnboardingSetting extends Entity {

	    /** The Apple ID used to obtain the current token. */
		appleIdentifier?: string

	    /** When the token will expire. */
		tokenExpirationDateTime?: string

	    /** When the service was onboarded. */
		lastModifiedDateTime?: string

	    /** When the service last syned with Intune */
		lastSuccessfulSyncDateTime?: string

	    /** When Intune last requested a sync. */
		lastSyncTriggeredDateTime?: string

	    /** Whether or not the Dep token sharing is enabled with the School Data Sync service. */
		shareTokenWithSchoolDataSyncService?: boolean

	    /** Error code reported by Apple during last dep sync. */
		lastSyncErrorCode?: number

		tokenType?: DepTokenType

		tokenName?: string

		syncedDeviceCount?: number

		defaultProfileDisplayName?: string

		dataSharingConsentGranted?: boolean

		defaultIosEnrollmentProfile?: DepIOSEnrollmentProfile

		defaultMacOsEnrollmentProfile?: DepMacOSEnrollmentProfile

		enrollmentProfiles?: EnrollmentProfile[]

		importedAppleDeviceIdentities?: ImportedAppleDeviceIdentity[]

}

export interface ImportedWindowsAutopilotDeviceIdentity extends Entity {

	    /** Order Id of the Windows autopilot device. */
		orderIdentifier?: string

	    /** Serial number of the Windows autopilot device. */
		serialNumber?: string

	    /** Product Key of the Windows autopilot device. */
		productKey?: string

	    /** Hardware Blob of the Windows autopilot device. */
		hardwareIdentifier?: number

	    /** Current state of the imported device. */
		state?: ImportedWindowsAutopilotDeviceIdentityState

}

export interface RemoteAssistancePartner extends Entity {

	    /** Display name of the partner. */
		displayName?: string

	    /** URL of the partner's onboarding portal, where an administrator can configure their Remote Assistance service. */
		onboardingUrl?: string

	    /** TBD. Possible values are: notOnboarded, onboarding, onboarded. */
		onboardingStatus?: RemoteAssistanceOnboardingStatus

	    /** Timestamp of the last request sent to Intune by the TEM partner. */
		lastConnectionDateTime?: string

}

export interface WindowsInformationProtectionAppLearningSummary extends Entity {

	    /** Application Name */
		applicationName?: string

	    /** Application Type. Possible values are: universal, desktop. */
		applicationType?: ApplicationType

	    /** Device Count */
		deviceCount?: number

}

export interface WindowsInformationProtectionNetworkLearningSummary extends Entity {

	    /** Website url */
		url?: string

	    /** Device Count */
		deviceCount?: number

}

export interface AuditEvent extends Entity {

	    /** Event display name. */
		displayName?: string

	    /** Component name. */
		componentName?: string

	    /** AAD user and application that are associated with the audit event. */
		actor?: AuditActor

	    /** Friendly name of the activity. */
		activity?: string

	    /** The date time in UTC when the activity was performed. */
		activityDateTime?: string

	    /** The type of activity that was being performed. */
		activityType?: string

	    /** The HTTP operation type of the activity. */
		activityOperationType?: string

	    /** The result of the activity. */
		activityResult?: string

	    /** The client request Id that is used to correlate activity within the system. */
		correlationId?: string

	    /** Resources being modified. */
		resources?: AuditResource[]

	    /** Audit category. */
		category?: string

}

export interface UserPFXCertificate extends Entity {

		thumbprint?: string

		intendedPurpose?: UserPfxIntendedPurpose

		userPrincipalName?: string

		startDateTime?: string

		expirationDateTime?: string

		providerName?: string

		keyName?: string

		paddingScheme?: UserPfxPaddingScheme

		encryptedPfxBlob?: number

		encryptedPfxPassword?: string

		createdDateTime?: string

		lastModifiedDateTime?: string

}

export interface DeviceAppManagement extends Entity {

	    /** The last time the apps from the Microsoft Store for Business were synced successfully for the account. */
		microsoftStoreForBusinessLastSuccessfulSyncDateTime?: string

	    /** Whether the account is enabled for syncing applications from the Microsoft Store for Business. */
		isEnabledForMicrosoftStoreForBusiness?: boolean

	    /** The locale information used to sync applications from the Microsoft Store for Business. Cultures that are specific to a country/region. The names of these cultures follow RFC 4646 (Windows Vista and later). The format is -<country/regioncode2>, where  is a lowercase two-letter code derived from ISO 639-1 and <country/regioncode2> is an uppercase two-letter code derived from ISO 3166. For example, en-US for English (United States) is a specific culture. */
		microsoftStoreForBusinessLanguage?: string

	    /** The last time an application sync from the Microsoft Store for Business was completed. */
		microsoftStoreForBusinessLastCompletedApplicationSyncTime?: string

	    /** Windows management app. */
		windowsManagementApp?: WindowsManagementApp

	    /** The mobile apps. */
		mobileApps?: MobileApp[]

	    /** The mobile app categories. */
		mobileAppCategories?: MobileAppCategory[]

	    /** The Windows Enterprise Code Signing Certificate. */
		enterpriseCodeSigningCertificates?: EnterpriseCodeSigningCertificate[]

	    /** The IOS Lob App Provisioning Configurations. */
		iosLobAppProvisioningConfigurations?: IosLobAppProvisioningConfiguration[]

	    /** The WinPhone Symantec Code Signing Certificate. */
		symantecCodeSigningCertificate?: SymantecCodeSigningCertificate

	    /** The Managed Device Mobile Application Configurations. */
		mobileAppConfigurations?: ManagedDeviceMobileAppConfiguration[]

	    /** Side Loading Keys that are required for the Windows 8 and 8.1 Apps installation. */
		sideLoadingKeys?: SideLoadingKey[]

	    /** List of Vpp tokens for this organization. */
		vppTokens?: VppToken[]

	    /** Managed app policies. */
		managedAppPolicies?: ManagedAppPolicy[]

	    /** iOS managed app policies. */
		iosManagedAppProtections?: IosManagedAppProtection[]

	    /** Android managed app policies. */
		androidManagedAppProtections?: AndroidManagedAppProtection[]

	    /** Default managed app policies. */
		defaultManagedAppProtections?: DefaultManagedAppProtection[]

	    /** Targeted managed app configurations. */
		targetedManagedAppConfigurations?: TargetedManagedAppConfiguration[]

	    /** Windows information protection for apps running on devices which are MDM enrolled. */
		mdmWindowsInformationProtectionPolicies?: MdmWindowsInformationProtectionPolicy[]

	    /** Windows information protection for apps running on devices which are not MDM enrolled. */
		windowsInformationProtectionPolicies?: WindowsInformationProtectionPolicy[]

	    /** The managed app registrations. */
		managedAppRegistrations?: ManagedAppRegistration[]

	    /** The managed app statuses. */
		managedAppStatuses?: ManagedAppStatus[]

	    /** The Managed eBook. */
		managedEBooks?: ManagedEBook[]

	    /** The mobile eBook categories. */
		managedEBookCategories?: ManagedEBookCategory[]

}

export interface WindowsManagementApp extends Entity {

	    /** Windows management app available version. */
		availableVersion?: string

	    /** Health summary for Windows management app. */
		healthSummary?: WindowsManagementAppHealthSummary

	    /** The list of health states for installed Windows management app. */
		healthStates?: WindowsManagementAppHealthState[]

}

export interface MobileApp extends Entity {

	    /** The admin provided or imported title of the app. */
		displayName?: string

	    /** The description of the app. */
		description?: string

	    /** The publisher of the app. */
		publisher?: string

	    /** The large icon, to be displayed in the app details and used for upload of the icon. */
		largeIcon?: MimeContent

	    /** The date and time the app was created. */
		createdDateTime?: string

	    /** The date and time the app was last modified. */
		lastModifiedDateTime?: string

	    /** The value indicating whether the app is marked as featured by the admin. */
		isFeatured?: boolean

	    /** The privacy statement Url. */
		privacyInformationUrl?: string

	    /** The more information Url. */
		informationUrl?: string

	    /** The owner of the app. */
		owner?: string

	    /** The developer of the app. */
		developer?: string

	    /** Notes for the app. */
		notes?: string

	    /** The upload state. */
		uploadState?: number

	    /** The publishing state for the app. The app cannot be assigned unless the app is published. Possible values are: notPublished, processing, published. */
		publishingState?: MobileAppPublishingState

	    /** The list of categories for this app. */
		categories?: MobileAppCategory[]

	    /** The list of group assignments for this mobile app. */
		assignments?: MobileAppAssignment[]

	    /** Mobile App Install Summary. */
		installSummary?: MobileAppInstallSummary

	    /** The list of installation states for this mobile app. */
		deviceStatuses?: MobileAppInstallStatus[]

	    /** The list of installation states for this mobile app. */
		userStatuses?: UserAppInstallStatus[]

}

export interface MobileAppCategory extends Entity {

	    /** The name of the app category. */
		displayName?: string

	    /** The date and time the mobileAppCategory was last modified. */
		lastModifiedDateTime?: string

}

export interface EnterpriseCodeSigningCertificate extends Entity {

	    /** The Windows Enterprise Code-Signing Certificate in the raw data format. */
		content?: number

	    /** The Certificate Status Provisioned or not Provisioned. Possible values are: notProvisioned, provisioned. */
		status?: CertificateStatus

	    /** The Subject Name for the cert. */
		subjectName?: string

	    /** The Subject Value for the cert. */
		subject?: string

	    /** The Issuer Name for the cert. */
		issuerName?: string

	    /** The Issuer value for the cert. */
		issuer?: string

	    /** The Cert Expiration Date. */
		expirationDateTime?: string

	    /** The date time of CodeSigning Cert when it is uploaded. */
		uploadDateTime?: string

}

export interface IosLobAppProvisioningConfiguration extends Entity {

	    /** Optional profile expiration date and time. */
		expirationDateTime?: string

	    /** Payload file name (.mobileprovision */
		payloadFileName?: string

	    /** Payload. (UTF8 encoded byte array) */
		payload?: number

	    /** DateTime the object was created. */
		createdDateTime?: string

	    /** Admin provided description of the Device Configuration. */
		description?: string

	    /** DateTime the object was last modified. */
		lastModifiedDateTime?: string

	    /** Admin provided name of the device configuration. */
		displayName?: string

	    /** Version of the device configuration. */
		version?: number

	    /** The associated group assignments. */
		groupAssignments?: MobileAppProvisioningConfigGroupAssignment[]

	    /** The associated group assignments for IosLobAppProvisioningConfiguration. */
		assignments?: IosLobAppProvisioningConfigurationAssignment[]

	    /** The list of device installation states for this mobile app configuration. */
		deviceStatuses?: ManagedDeviceMobileAppConfigurationDeviceStatus[]

	    /** The list of user installation states for this mobile app configuration. */
		userStatuses?: ManagedDeviceMobileAppConfigurationUserStatus[]

}

export interface SymantecCodeSigningCertificate extends Entity {

	    /** The Windows Symantec Code-Signing Certificate in the raw data format. */
		content?: number

	    /** The Cert Status Provisioned or not Provisioned. Possible values are: notProvisioned, provisioned. */
		status?: CertificateStatus

	    /** The Password required for .pfx file. */
		password?: string

	    /** The Subject Name for the cert. */
		subjectName?: string

	    /** The Subject value for the cert. */
		subject?: string

	    /** The Issuer Name for the cert. */
		issuerName?: string

	    /** The Issuer value for the cert. */
		issuer?: string

	    /** The Cert Expiration Date. */
		expirationDateTime?: string

	    /** The Type of the CodeSigning Cert as Symantec Cert. */
		uploadDateTime?: string

}

export interface ManagedDeviceMobileAppConfiguration extends Entity {

	    /** the associated app. */
		targetedMobileApps?: string[]

	    /** DateTime the object was created. */
		createdDateTime?: string

	    /** Admin provided description of the Device Configuration. */
		description?: string

	    /** DateTime the object was last modified. */
		lastModifiedDateTime?: string

	    /** Admin provided name of the device configuration. */
		displayName?: string

	    /** Version of the device configuration. */
		version?: number

	    /** The list of group assignemenets for app configration. */
		assignments?: ManagedDeviceMobileAppConfigurationAssignment[]

	    /** List of ManagedDeviceMobileAppConfigurationDeviceStatus. */
		deviceStatuses?: ManagedDeviceMobileAppConfigurationDeviceStatus[]

	    /** List of ManagedDeviceMobileAppConfigurationUserStatus. */
		userStatuses?: ManagedDeviceMobileAppConfigurationUserStatus[]

	    /** App configuration device status summary. */
		deviceStatusSummary?: ManagedDeviceMobileAppConfigurationDeviceSummary

	    /** App configuration user status summary. */
		userStatusSummary?: ManagedDeviceMobileAppConfigurationUserSummary

}

export interface SideLoadingKey extends Entity {

	    /** Side Loading Key Value, it is 5x5 value, seperated by hiphens. */
		value?: string

	    /** Side Loading Key Name displayed to the ITPro Admins. */
		displayName?: string

	    /** Side Loading Key description displayed to the ITPro Admins.. */
		description?: string

	    /** Side Loading Key Total Activation displayed to the ITPro Admins. */
		totalActivation?: number

	    /** Side Loading Key Last Updated Date displayed to the ITPro Admins. */
		lastUpdatedDateTime?: string

}

export interface VppToken extends Entity {

	    /** The organization associated with the Apple Volume Purchase Program Token */
		organizationName?: string

	    /** The type of volume purchase program which the given Apple Volume Purchase Program Token is associated with. Possible values are: business, education. Possible values are: business, education. */
		vppTokenAccountType?: VppTokenAccountType

	    /** The apple Id associated with the given Apple Volume Purchase Program Token. */
		appleId?: string

	    /** The expiration date time of the Apple Volume Purchase Program Token. */
		expirationDateTime?: string

	    /** The last time when an application sync was done with the Apple volume purchase program service using the the Apple Volume Purchase Program Token. */
		lastSyncDateTime?: string

	    /** The Apple Volume Purchase Program Token string downloaded from the Apple Volume Purchase Program. */
		token?: string

	    /** Last modification date time associated with the Apple Volume Purchase Program Token. */
		lastModifiedDateTime?: string

	    /** Current state of the Apple Volume Purchase Program Token. Possible values are: unknown, valid, expired, invalid. Possible values are: unknown, valid, expired, invalid. */
		state?: VppTokenState

	    /** The collection of statuses of the actions performed on the Apple Volume Purchase Program Token. */
		tokenActionResults?: VppTokenActionResult[]

	    /** Current sync status of the last application sync which was triggered using the Apple Volume Purchase Program Token. Possible values are: none, inProgress, completed, failed. Possible values are: none, inProgress, completed, failed. */
		lastSyncStatus?: VppTokenSyncStatus

	    /** Whether or not apps for the VPP token will be automatically updated. */
		automaticallyUpdateApps?: boolean

	    /** Whether or not apps for the VPP token will be automatically updated. */
		countryOrRegion?: string

	    /** Consent granted for data sharing with the Apple Volume Purchase Program. */
		dataSharingConsentGranted?: boolean

		displayName?: string

		locationName?: string

}

export interface ManagedAppPolicy extends Entity {

	    /** Policy display name. */
		displayName?: string

	    /** The policy's description. */
		description?: string

	    /** The date and time the policy was created. */
		createdDateTime?: string

	    /** Last time the policy was modified. */
		lastModifiedDateTime?: string

	    /** Version of the entity. */
		version?: string

}

export interface ManagedAppProtection extends ManagedAppPolicy {

	    /** The period after which access is checked when the device is not connected to the internet. */
		periodOfflineBeforeAccessCheck?: string

	    /** The period after which access is checked when the device is connected to the internet. */
		periodOnlineBeforeAccessCheck?: string

	    /** Sources from which data is allowed to be transferred. Possible values are: allApps, managedApps, none. */
		allowedInboundDataTransferSources?: ManagedAppDataTransferLevel

	    /** Destinations to which data is allowed to be transferred. Possible values are: allApps, managedApps, none. */
		allowedOutboundDataTransferDestinations?: ManagedAppDataTransferLevel

	    /** Indicates whether organizational credentials are required for app use. */
		organizationalCredentialsRequired?: boolean

	    /** The level to which the clipboard may be shared between apps on the managed device. Possible values are: allApps, managedAppsWithPasteIn, managedApps, blocked. */
		allowedOutboundClipboardSharingLevel?: ManagedAppClipboardSharingLevel

	    /** Indicates whether the backup of a managed app's data is blocked. */
		dataBackupBlocked?: boolean

	    /** Indicates whether device compliance is required. */
		deviceComplianceRequired?: boolean

	    /** Indicates whether internet links should be opened in the managed browser app. */
		managedBrowserToOpenLinksRequired?: boolean

	    /** Indicates whether users may use the "Save As" menu item to save a copy of protected files. */
		saveAsBlocked?: boolean

	    /** The amount of time an app is allowed to remain disconnected from the internet before all managed data it is wiped. */
		periodOfflineBeforeWipeIsEnforced?: string

	    /** Indicates whether an app-level pin is required. */
		pinRequired?: boolean

	    /** Maximum number of incorrect pin retry attempts before the managed app is either blocked or wiped. */
		maximumPinRetries?: number

	    /** Indicates whether simplePin is blocked. */
		simplePinBlocked?: boolean

	    /** Minimum pin length required for an app-level pin if PinRequired is set to True */
		minimumPinLength?: number

	    /** Character set which may be used for an app-level pin if PinRequired is set to True. Possible values are: numeric, alphanumericAndSymbol. */
		pinCharacterSet?: ManagedAppPinCharacterSet

	    /** TimePeriod before the all-level pin must be reset if PinRequired is set to True. */
		periodBeforePinReset?: string

	    /** Data storage locations where a user may store managed data. */
		allowedDataStorageLocations?: ManagedAppDataStorageLocation[]

	    /** Indicates whether contacts can be synced to the user's device. */
		contactSyncBlocked?: boolean

	    /** Indicates whether printing is allowed from managed apps. */
		printBlocked?: boolean

	    /** Indicates whether use of the fingerprint reader is allowed in place of a pin if PinRequired is set to True. */
		fingerprintBlocked?: boolean

	    /** Indicates whether use of the app pin is required if the device pin is set. */
		disableAppPinIfDevicePinIsSet?: boolean

	    /** Versions less than the specified version will block the managed app from accessing company data. */
		minimumRequiredOsVersion?: string

	    /** Versions less than the specified version will result in warning message on the managed app from accessing company data. */
		minimumWarningOsVersion?: string

	    /** Versions less than the specified version will block the managed app from accessing company data. */
		minimumRequiredAppVersion?: string

	    /** Versions less than the specified version will result in warning message on the managed app. */
		minimumWarningAppVersion?: string

	    /** Versions less than or equal to the specified version will wipe the managed app and the associated company data. */
		minimumWipeOsVersion?: string

	    /** Versions less than or equal to the specified version will wipe the managed app and the associated company data. */
		minimumWipeAppVersion?: string

	    /** Defines a managed app behavior, either block or wipe, when the device is either rooted or jailbroken, if DeviceComplianceRequired is set to true. Possible values are: block, wipe. */
		appActionIfDeviceComplianceRequired?: ManagedAppRemediationAction

	    /** Defines a managed app behavior, either block or wipe, based on maximum number of incorrect pin retry attempts. Possible values are: block, wipe. */
		appActionIfMaximumPinRetriesExceeded?: ManagedAppRemediationAction

	    /** Requires an app pin on launch instead of non biometrics passcode */
		pinRequiredOnLaunchInsteadOfBiometric?: boolean

	    /** Timeout in minutes for an app pin instead of non biometrics passcode */
		pinRequiredInsteadOfBiometricTimeout?: string

}

export interface TargetedManagedAppProtection extends ManagedAppProtection {

	    /** Indicates if the policy is deployed to any inclusion groups or not. */
		isAssigned?: boolean

	    /** The intended app management levels for this policy. Possible values are: unspecified, unmanaged, mdm, androidEnterprise. */
		targetedAppManagementLevels?: AppManagementLevel

	    /** Navigation property to list of inclusion and exclusion groups to which the policy is deployed. */
		assignments?: TargetedManagedAppPolicyAssignment[]

}

export interface IosManagedAppProtection extends TargetedManagedAppProtection {

	    /** Type of encryption which should be used for data in a managed app. Possible values are: useDeviceSettings, afterDeviceRestart, whenDeviceLockedExceptOpenFiles, whenDeviceLocked. */
		appDataEncryptionType?: ManagedAppDataEncryptionType

	    /** Versions less than the specified version will block the managed app from accessing company data. */
		minimumRequiredSdkVersion?: string

	    /** Count of apps to which the current policy is deployed. */
		deployedAppCount?: number

	    /** Indicates whether use of the FaceID is allowed in place of a pin if PinRequired is set to True. */
		faceIdBlocked?: boolean

	    /** Apps in this list will be exempt from the policy and will be able to receive data from managed apps. */
		exemptedAppProtocols?: KeyValuePair[]

	    /** Versions less than the specified version will block the managed app from accessing company data. */
		minimumWipeSdkVersion?: string

	    /** Semicolon seperated list of device models allowed, as a string, for the managed app to work. */
		allowedIosDeviceModels?: string

	    /** Defines a managed app behavior, either block or wipe, if the specified device model is not allowed. Possible values are: block, wipe. */
		appActionIfIosDeviceModelNotAllowed?: ManagedAppRemediationAction

	    /** Defines if third party keyboards are allowed while accessing a managed app */
		thirdPartyKeyboardsBlocked?: boolean

	    /** Defines if open-in operation is supported from the managed app to the filesharing locations selected. */
		filterOpenInToOnlyManagedApps?: boolean

	    /** List of apps to which the policy is deployed. */
		apps?: ManagedMobileApp[]

	    /** Navigation property to deployment summary of the configuration. */
		deploymentSummary?: ManagedAppPolicyDeploymentSummary

}

export interface AndroidManagedAppProtection extends TargetedManagedAppProtection {

	    /** Indicates whether a managed user can take screen captures of managed apps */
		screenCaptureBlocked?: boolean

	    /** When this setting is enabled, app level encryption is disabled if device level encryption is enabled */
		disableAppEncryptionIfDeviceEncryptionIsEnabled?: boolean

	    /** Indicates whether application data for managed apps should be encrypted */
		encryptAppData?: boolean

	    /** Count of apps to which the current policy is deployed. */
		deployedAppCount?: number

	    /** Define the oldest required Android security patch level a user can have to gain secure access to the app. */
		minimumRequiredPatchVersion?: string

	    /** Define the oldest recommended Android security patch level a user can have for secure access to the app. */
		minimumWarningPatchVersion?: string

	    /** App packages in this list will be exempt from the policy and will be able to receive data from managed apps. */
		exemptedAppPackages?: KeyValuePair[]

	    /** Android security patch level  less than or equal to the specified value will wipe the managed app and the associated company data. */
		minimumWipePatchVersion?: string

	    /** Semicolon seperated list of device manufacturers allowed, as a string, for the managed app to work. */
		allowedAndroidDeviceManufacturers?: string

	    /** Defines a managed app behavior, either block or wipe, if the specified device manufacturer is not allowed. Possible values are: block, wipe. */
		appActionIfAndroidDeviceManufacturerNotAllowed?: ManagedAppRemediationAction

	    /** List of apps to which the policy is deployed. */
		apps?: ManagedMobileApp[]

	    /** Navigation property to deployment summary of the configuration. */
		deploymentSummary?: ManagedAppPolicyDeploymentSummary

}

export interface DefaultManagedAppProtection extends ManagedAppProtection {

	    /** Type of encryption which should be used for data in a managed app. (iOS Only). Possible values are: useDeviceSettings, afterDeviceRestart, whenDeviceLockedExceptOpenFiles, whenDeviceLocked. */
		appDataEncryptionType?: ManagedAppDataEncryptionType

	    /** Indicates whether screen capture is blocked. */
		screenCaptureBlocked?: boolean

	    /** Indicates whether managed-app data should be encrypted. (Android only) */
		encryptAppData?: boolean

	    /** When this setting is enabled, app level encryption is disabled if device level encryption is enabled */
		disableAppEncryptionIfDeviceEncryptionIsEnabled?: boolean

	    /** Versions less than the specified version will block the managed app from accessing company data. */
		minimumRequiredSdkVersion?: string

	    /** A set of string key and string value pairs to be sent to the affected users, unalterned by this service */
		customSettings?: KeyValuePair[]

	    /** Count of apps to which the current policy is deployed. */
		deployedAppCount?: number

	    /** Define the oldest required Android security patch level a user can have to gain secure access to the app. */
		minimumRequiredPatchVersion?: string

	    /** Define the oldest recommended Android security patch level a user can have for secure access to the app. */
		minimumWarningPatchVersion?: string

	    /** iOS Apps in this list will be exempt from the policy and will be able to receive data from managed apps. */
		exemptedAppProtocols?: KeyValuePair[]

	    /** Android App packages in this list will be exempt from the policy and will be able to receive data from managed apps. */
		exemptedAppPackages?: KeyValuePair[]

	    /** Indicates whether use of the FaceID is allowed in place of a pin if PinRequired is set to True. */
		faceIdBlocked?: boolean

	    /** Versions less than the specified version will block the managed app from accessing company data. */
		minimumWipeSdkVersion?: string

	    /** Android security patch level  less than or equal to the specified value will wipe the managed app and the associated company data. */
		minimumWipePatchVersion?: string

	    /** Semicolon seperated list of device models allowed, as a string, for the managed app to work. */
		allowedIosDeviceModels?: string

	    /** Defines a managed app behavior, either block or wipe, if the specified device model is not allowed. Possible values are: block, wipe. */
		appActionIfIosDeviceModelNotAllowed?: ManagedAppRemediationAction

	    /** Semicolon seperated list of device manufacturers allowed, as a string, for the managed app to work. */
		allowedAndroidDeviceManufacturers?: string

	    /** Defines a managed app behavior, either block or wipe, if the specified device manufacturer is not allowed. Possible values are: block, wipe. */
		appActionIfAndroidDeviceManufacturerNotAllowed?: ManagedAppRemediationAction

	    /** Defines if third party keyboards are allowed while accessing a managed app */
		thirdPartyKeyboardsBlocked?: boolean

	    /** Defines if open-in operation is supported from the managed app to the filesharing locations selected. */
		filterOpenInToOnlyManagedApps?: boolean

	    /** List of apps to which the policy is deployed. */
		apps?: ManagedMobileApp[]

	    /** Navigation property to deployment summary of the configuration. */
		deploymentSummary?: ManagedAppPolicyDeploymentSummary

}

export interface ManagedAppConfiguration extends ManagedAppPolicy {

	    /** A set of string key and string value pairs to be sent to apps for users to whom the configuration is scoped, unalterned by this service */
		customSettings?: KeyValuePair[]

}

export interface TargetedManagedAppConfiguration extends ManagedAppConfiguration {

	    /** Count of apps to which the current policy is deployed. */
		deployedAppCount?: number

	    /** Indicates if the policy is deployed to any inclusion groups or not. */
		isAssigned?: boolean

	    /** List of apps to which the policy is deployed. */
		apps?: ManagedMobileApp[]

	    /** Navigation property to deployment summary of the configuration. */
		deploymentSummary?: ManagedAppPolicyDeploymentSummary

	    /** Navigation property to list of inclusion and exclusion groups to which the policy is deployed. */
		assignments?: TargetedManagedAppPolicyAssignment[]

}

export interface WindowsInformationProtection extends ManagedAppPolicy {

	    /** WIP enforcement level.See the Enum definition for supported values. Possible values are: noProtection, encryptAndAuditOnly, encryptAuditAndPrompt, encryptAuditAndBlock. */
		enforcementLevel?: WindowsInformationProtectionEnforcementLevel

	    /** Primary enterprise domain */
		enterpriseDomain?: string

	    /** List of enterprise domains to be protected */
		enterpriseProtectedDomainNames?: WindowsInformationProtectionResourceCollection[]

	    /** Specifies whether the protection under lock feature (also known as encrypt under pin) should be configured */
		protectionUnderLockConfigRequired?: boolean

	    /** Specifies a recovery certificate that can be used for data recovery of encrypted files. This is the same as the data recovery agent(DRA) certificate for encrypting file system(EFS) */
		dataRecoveryCertificate?: WindowsInformationProtectionDataRecoveryCertificate

	    /** This policy controls whether to revoke the WIP keys when a device unenrolls from the management service. If set to 1 (Don't revoke keys), the keys will not be revoked and the user will continue to have access to protected files after unenrollment. If the keys are not revoked, there will be no revoked file cleanup subsequently. */
		revokeOnUnenrollDisabled?: boolean

	    /** TemplateID GUID to use for RMS encryption. The RMS template allows the IT admin to configure the details about who has access to RMS-protected file and how long they have access */
		rightsManagementServicesTemplateId?: string

	    /** Specifies whether to allow Azure RMS encryption for WIP */
		azureRightsManagementServicesAllowed?: boolean

	    /** Determines whether overlays are added to icons for WIP protected files in Explorer and enterprise only app tiles in the Start menu. Starting in Windows 10, version 1703 this setting also configures the visibility of the WIP icon in the title bar of a WIP-protected app */
		iconsVisible?: boolean

	    /** Protected applications can access enterprise data and the data handled by those applications are protected with encryption */
		protectedApps?: WindowsInformationProtectionApp[]

	    /** Exempt applications can also access enterprise data, but the data handled by those applications are not protected. This is because some critical enterprise applications may have compatibility problems with encrypted data. */
		exemptApps?: WindowsInformationProtectionApp[]

	    /** This is the list of domains that comprise the boundaries of the enterprise. Data from one of these domains that is sent to a device will be considered enterprise data and protected These locations will be considered a safe destination for enterprise data to be shared to */
		enterpriseNetworkDomainNames?: WindowsInformationProtectionResourceCollection[]

	    /** Contains a list of Enterprise resource domains hosted in the cloud that need to be protected. Connections to these resources are considered enterprise data. If a proxy is paired with a cloud resource, traffic to the cloud resource will be routed through the enterprise network via the denoted proxy server (on Port 80). A proxy server used for this purpose must also be configured using the EnterpriseInternalProxyServers policy */
		enterpriseProxiedDomains?: WindowsInformationProtectionProxiedDomainCollection[]

	    /** Sets the enterprise IP ranges that define the computers in the enterprise network. Data that comes from those computers will be considered part of the enterprise and protected. These locations will be considered a safe destination for enterprise data to be shared to */
		enterpriseIPRanges?: WindowsInformationProtectionIPRangeCollection[]

	    /** Boolean value that tells the client to accept the configured list and not to use heuristics to attempt to find other subnets. Default is false */
		enterpriseIPRangesAreAuthoritative?: boolean

	    /** This is a list of proxy servers. Any server not on this list is considered non-enterprise */
		enterpriseProxyServers?: WindowsInformationProtectionResourceCollection[]

	    /** This is the comma-separated list of internal proxy servers. For example, "157.54.14.28, 157.54.11.118, 10.202.14.167, 157.53.14.163, 157.69.210.59". These proxies have been configured by the admin to connect to specific resources on the Internet. They are considered to be enterprise network locations. The proxies are only leveraged in configuring the EnterpriseProxiedDomains policy to force traffic to the matched domains through these proxies */
		enterpriseInternalProxyServers?: WindowsInformationProtectionResourceCollection[]

	    /** Boolean value that tells the client to accept the configured list of proxies and not try to detect other work proxies. Default is false */
		enterpriseProxyServersAreAuthoritative?: boolean

	    /** List of domain names that can used for work or personal resource */
		neutralDomainResources?: WindowsInformationProtectionResourceCollection[]

	    /** This switch is for the Windows Search Indexer, to allow or disallow indexing of items */
		indexingEncryptedStoresOrItemsBlocked?: boolean

	    /** Specifies a list of file extensions, so that files with these extensions are encrypted when copying from an SMB share within the corporate boundary */
		smbAutoEncryptedFileExtensions?: WindowsInformationProtectionResourceCollection[]

	    /** Indicates if the policy is deployed to any inclusion groups or not. */
		isAssigned?: boolean

	    /** Another way to input protected apps through xml files */
		protectedAppLockerFiles?: WindowsInformationProtectionAppLockerFile[]

	    /** Another way to input exempt apps through xml files */
		exemptAppLockerFiles?: WindowsInformationProtectionAppLockerFile[]

	    /** Navigation property to list of security groups targeted for policy. */
		assignments?: TargetedManagedAppPolicyAssignment[]

}

export interface MdmWindowsInformationProtectionPolicy extends WindowsInformationProtection {

}

export interface WindowsInformationProtectionPolicy extends WindowsInformationProtection {

	    /** New property in RS2, pending documentation */
		revokeOnMdmHandoffDisabled?: boolean

	    /** Enrollment url for the MDM */
		mdmEnrollmentUrl?: string

	    /** Boolean value that sets Windows Hello for Business as a method for signing into Windows. */
		windowsHelloForBusinessBlocked?: boolean

	    /** Integer value that sets the minimum number of characters required for the PIN. Default value is 4. The lowest number you can configure for this policy setting is 4. The largest number you can configure must be less than the number configured in the Maximum PIN length policy setting or the number 127, whichever is the lowest. */
		pinMinimumLength?: number

	    /** Integer value that configures the use of uppercase letters in the Windows Hello for Business PIN. Default is NotAllow. Possible values are: notAllow, requireAtLeastOne, allow. */
		pinUppercaseLetters?: WindowsInformationProtectionPinCharacterRequirements

	    /** Integer value that configures the use of lowercase letters in the Windows Hello for Business PIN. Default is NotAllow. Possible values are: notAllow, requireAtLeastOne, allow. */
		pinLowercaseLetters?: WindowsInformationProtectionPinCharacterRequirements

	    /** Integer value that configures the use of special characters in the Windows Hello for Business PIN. Valid special characters for Windows Hello for Business PIN gestures include: ! " # $ % & ' ( )  + , - . / : ; < = > ? @ [ \ ] ^  ` { */
		pinSpecialCharacters?: WindowsInformationProtectionPinCharacterRequirements

	    /** Integer value specifies the period of time (in days) that a PIN can be used before the system requires the user to change it. The largest number you can configure for this policy setting is 730. The lowest number you can configure for this policy setting is 0. If this policy is set to 0, then the user's PIN will never expire. This node was added in Windows 10, version 1511. Default is 0. */
		pinExpirationDays?: number

	    /** Integer value that specifies the number of past PINs that can be associated to a user account that can't be reused. The largest number you can configure for this policy setting is 50. The lowest number you can configure for this policy setting is 0. If this policy is set to 0, then storage of previous PINs is not required. This node was added in Windows 10, version 1511. Default is 0. */
		numberOfPastPinsRemembered?: number

	    /** The number of authentication failures allowed before the device will be wiped. A value of 0 disables device wipe functionality. Range is an integer X where 4 <= X <= 16 for desktop and 0 <= X <= 999 for mobile devices. */
		passwordMaximumAttemptCount?: number

	    /** Specifies the maximum amount of time (in minutes) allowed after the device is idle that will cause the device to become PIN or password locked.   Range is an integer X where 0 <= X <= 999. */
		minutesOfInactivityBeforeDeviceLock?: number

	    /** Offline interval before app data is wiped (days) */
		daysWithoutContactBeforeUnenroll?: number

}

export interface ManagedAppStatus extends Entity {

	    /** Friendly name of the status report. */
		displayName?: string

	    /** Version of the entity. */
		version?: string

}

export interface ManagedEBook extends Entity {

	    /** Name of the eBook. */
		displayName?: string

	    /** Description. */
		description?: string

	    /** Publisher. */
		publisher?: string

	    /** The date and time when the eBook was published. */
		publishedDateTime?: string

	    /** Book cover. */
		largeCover?: MimeContent

	    /** The date and time when the eBook file was created. */
		createdDateTime?: string

	    /** The date and time when the eBook was last modified. */
		lastModifiedDateTime?: string

	    /** The more information Url. */
		informationUrl?: string

	    /** The privacy statement Url. */
		privacyInformationUrl?: string

	    /** The list of categories for this eBook. */
		categories?: ManagedEBookCategory[]

	    /** The list of assignments for this eBook. */
		assignments?: ManagedEBookAssignment[]

	    /** Mobile App Install Summary. */
		installSummary?: EBookInstallSummary

	    /** The list of installation states for this eBook. */
		deviceStates?: DeviceInstallState[]

	    /** The list of installation states for this eBook. */
		userStateSummary?: UserInstallStateSummary[]

}

export interface ManagedEBookCategory extends Entity {

	    /** The name of the eBook category. */
		displayName?: string

	    /** The date and time the ManagedEBookCategory was last modified. */
		lastModifiedDateTime?: string

}

export interface MobileAppAssignment extends Entity {

	    /** The install intent defined by the admin. Possible values are: available, required, uninstall, availableWithoutEnrollment. */
		intent?: InstallIntent

	    /** The target group assignment defined by the admin. */
		target?: DeviceAndAppManagementAssignmentTarget

	    /** The settings for target assignment defined by the admin. */
		settings?: MobileAppAssignmentSettings

}

export interface MobileAppInstallSummary extends Entity {

	    /** Number of Devices that have successfully installed this app. */
		installedDeviceCount?: number

	    /** Number of Devices that have failed to install this app. */
		failedDeviceCount?: number

	    /** Number of Devices that are not applicable for this app. */
		notApplicableDeviceCount?: number

	    /** Number of Devices that does not have this app installed. */
		notInstalledDeviceCount?: number

	    /** Number of Devices that have been notified to install this app. */
		pendingInstallDeviceCount?: number

	    /** Number of Users whose devices have all succeeded to install this app. */
		installedUserCount?: number

	    /** Number of Users that have 1 or more device that failed to install this app. */
		failedUserCount?: number

	    /** Number of Users whose devices were all not applicable for this app. */
		notApplicableUserCount?: number

	    /** Number of Users that have 1 or more devices that did not install this app. */
		notInstalledUserCount?: number

	    /** Number of Users that have 1 or more device that have been notified to install this app and have 0 devices with failures. */
		pendingInstallUserCount?: number

}

export interface MobileAppInstallStatus extends Entity {

	    /** Device name */
		deviceName?: string

	    /** Device ID */
		deviceId?: string

	    /** Last sync date time */
		lastSyncDateTime?: string

	    /** The install state of the app. Possible values are: installed, failed, notInstalled, uninstallFailed, pendingInstall, unknown, notApplicable. */
		mobileAppInstallStatusValue?: ResultantAppState

	    /** The install state of the app. Possible values are: installed, failed, notInstalled, uninstallFailed, pendingInstall, unknown, notApplicable. */
		installState?: ResultantAppState

		installStateDetail?: ResultantAppStateDetail

	    /** The error code for install failures. */
		errorCode?: number

	    /** OS Version */
		osVersion?: string

	    /** OS Description */
		osDescription?: string

	    /** Device User Name */
		userName?: string

	    /** User Principal Name */
		userPrincipalName?: string

	    /** Human readable version of the application */
		displayVersion?: string

	    /** The navigation link to the mobile app. */
		app?: MobileApp

}

export interface UserAppInstallStatus extends Entity {

	    /** User name. */
		userName?: string

	    /** User Principal Name. */
		userPrincipalName?: string

	    /** Installed Device Count. */
		installedDeviceCount?: number

	    /** Failed Device Count. */
		failedDeviceCount?: number

	    /** Not installed device count. */
		notInstalledDeviceCount?: number

	    /** The navigation link to the mobile app. */
		app?: MobileApp

	    /** The install state of the app on devices. */
		deviceStatuses?: MobileAppInstallStatus[]

}

export interface MobileAppContentFile extends Entity {

	    /** The Azure Storage URI. */
		azureStorageUri?: string

	    /** A value indicating whether the file is committed. */
		isCommitted?: boolean

	    /** The time the file was created. */
		createdDateTime?: string

	    /** the file name. */
		name?: string

	    /** The size of the file prior to encryption. */
		size?: number

	    /** The size of the file after encryption. */
		sizeEncrypted?: number

	    /** The time the Azure storage Uri expires. */
		azureStorageUriExpirationDateTime?: string

	    /** The manifest information. */
		manifest?: number

	    /** The state of the current upload request. Possible values are: success, transientError, error, unknown, azureStorageUriRequestSuccess, azureStorageUriRequestPending, azureStorageUriRequestFailed, azureStorageUriRequestTimedOut, azureStorageUriRenewalSuccess, azureStorageUriRenewalPending, azureStorageUriRenewalFailed, azureStorageUriRenewalTimedOut, commitFileSuccess, commitFilePending, commitFileFailed, commitFileTimedOut. */
		uploadState?: MobileAppContentFileUploadState

	    /** A value indicating whether the file is a framework file. */
		isFrameworkFile?: boolean

	    /** Whether the content file is a dependency for the main content file. */
		isDependency?: boolean

}

export interface MobileAppProvisioningConfigGroupAssignment extends Entity {

	    /** The ID of the AAD group in which the app provisioning configuration is being targeted. */
		targetGroupId?: string

}

export interface IosLobAppProvisioningConfigurationAssignment extends Entity {

	    /** The target group assignment defined by the admin. */
		target?: DeviceAndAppManagementAssignmentTarget

}

export interface ManagedDeviceMobileAppConfigurationDeviceStatus extends Entity {

	    /** Device name of the DevicePolicyStatus. */
		deviceDisplayName?: string

	    /** The User Name that is being reported */
		userName?: string

	    /** The device model that is being reported */
		deviceModel?: string

	    /** Platform of the device that is being reported */
		platform?: number

	    /** The DateTime when device compliance grace period expires */
		complianceGracePeriodExpirationDateTime?: string

	    /** Compliance status of the policy report. Possible values are: unknown, notApplicable, compliant, remediated, nonCompliant, error, conflict. */
		status?: ComplianceStatus

	    /** Last modified date time of the policy report. */
		lastReportedDateTime?: string

	    /** UserPrincipalName. */
		userPrincipalName?: string

}

export interface ManagedDeviceMobileAppConfigurationUserStatus extends Entity {

	    /** User name of the DevicePolicyStatus. */
		userDisplayName?: string

	    /** Devices count for that user. */
		devicesCount?: number

	    /** Compliance status of the policy report. Possible values are: unknown, notApplicable, compliant, remediated, nonCompliant, error, conflict. */
		status?: ComplianceStatus

	    /** Last modified date time of the policy report. */
		lastReportedDateTime?: string

	    /** UserPrincipalName. */
		userPrincipalName?: string

}

export interface ManagedDeviceMobileAppConfigurationAssignment extends Entity {

	    /** Assignment target that the T&C policy is assigned to. */
		target?: DeviceAndAppManagementAssignmentTarget

}

export interface ManagedDeviceMobileAppConfigurationDeviceSummary extends Entity {

	    /** Number of pending devices */
		pendingCount?: number

	    /** Number of not applicable devices */
		notApplicableCount?: number

	    /** Number of not applicable devices due to mismatch platform and policy */
		notApplicablePlatformCount?: number

	    /** Number of succeeded devices */
		successCount?: number

	    /** Number of error devices */
		errorCount?: number

	    /** Number of failed devices */
		failedCount?: number

	    /** Number of devices in conflict */
		conflictCount?: number

	    /** Last update time */
		lastUpdateDateTime?: string

	    /** Version of the policy for that overview */
		configurationVersion?: number

}

export interface ManagedDeviceMobileAppConfigurationUserSummary extends Entity {

	    /** Number of pending Users */
		pendingCount?: number

	    /** Number of not applicable users */
		notApplicableCount?: number

	    /** Number of succeeded Users */
		successCount?: number

	    /** Number of error Users */
		errorCount?: number

	    /** Number of failed Users */
		failedCount?: number

	    /** Number of users in conflict */
		conflictCount?: number

	    /** Last update time */
		lastUpdateDateTime?: string

	    /** Version of the policy for that overview */
		configurationVersion?: number

}

export interface IosVppApp extends MobileApp {

	    /** The number of VPP licenses in use. */
		usedLicenseCount?: number

	    /** The total number of VPP licenses. */
		totalLicenseCount?: number

	    /** The VPP application release date and time. */
		releaseDateTime?: string

	    /** The store URL. */
		appStoreUrl?: string

	    /** The supported License Type. */
		licensingType?: VppLicensingType

	    /** The applicable iOS Device Type. */
		applicableDeviceType?: IosDeviceType

	    /** The organization associated with the Apple Volume Purchase Program Token */
		vppTokenOrganizationName?: string

	    /** The type of volume purchase program which the given Apple Volume Purchase Program Token is associated with. Possible values are: business, education. Possible values are: business, education. */
		vppTokenAccountType?: VppTokenAccountType

	    /** The Apple Id associated with the given Apple Volume Purchase Program Token. */
		vppTokenAppleId?: string

	    /** The Identity Name. */
		bundleId?: string

		vppTokenId?: string

		revokeLicenseActionResults?: IosVppAppRevokeLicensesActionResult[]

		assignedLicenses?: IosVppAppAssignedLicense[]

}

export interface IosVppAppAssignedLicense extends Entity {

		userEmailAddress?: string

		userId?: string

		userName?: string

		userPrincipalName?: string

}

export interface MacOSOfficeSuiteApp extends MobileApp {

}

export interface OfficeSuiteApp extends MobileApp {

	    /** The value to accept the EULA automatically on the enduser's device. */
		autoAcceptEula?: boolean

	    /** The Product Ids that represent the Office365 Suite SKU. */
		productIds?: OfficeProductId[]

	    /** The property to represent the Apps which are excluded from the selected Office365 Product Id. */
		excludedApps?: ExcludedApps

	    /** The property to represent that whether the shared computer activation is used not for Office365 App Suite. */
		useSharedComputerActivation?: boolean

	    /** The property to represent the Office365 Update Channel. Possible values are: none, current, deferred, firstReleaseCurrent, firstReleaseDeferred. */
		updateChannel?: OfficeUpdateChannel

	    /** The property to represent the Office365 App Suite version. Possible values are: none, x86, x64, arm, neutral. */
		officePlatformArchitecture?: WindowsArchitecture

	    /** The property to represent the locales which are installed when the Apps from Office365 is installed. It uses standard RFC 6033. Ref: https://technet.microsoft.com/en-us/library/cc179219(v=office.16).aspx */
		localesToInstall?: string[]

	    /** To specify the level of display for the Installation Progress Setup UI on the Device. Possible values are: none, full. */
		installProgressDisplayLevel?: OfficeSuiteInstallProgressDisplayLevel

	    /** The property to determine whether to uninstall existing Office MSI if an OfficeSuiteApp is deployed to the device or not. */
		shouldUninstallOlderVersionsOfOffice?: boolean

		targetVersion?: string

		updateVersion?: string

}

export interface ManagedApp extends MobileApp {

	    /** The Application's availability. Possible values are: global, lineOfBusiness. */
		appAvailability?: ManagedAppAvailability

	    /** The Application's version. */
		version?: string

}

export interface ManagedAndroidStoreApp extends ManagedApp {

	    /** The app's package ID. */
		packageId?: string

	    /** The Android AppStoreUrl. */
		appStoreUrl?: string

	    /** The value for the minimum supported operating system. */
		minimumSupportedOperatingSystem?: AndroidMinimumOperatingSystem

}

export interface ManagedIOSStoreApp extends ManagedApp {

	    /** The app's Bundle ID. */
		bundleId?: string

	    /** The Apple AppStoreUrl. */
		appStoreUrl?: string

	    /** The iOS architecture for which this app can run on. */
		applicableDeviceType?: IosDeviceType

	    /** The value for the minimum supported operating system. */
		minimumSupportedOperatingSystem?: IosMinimumOperatingSystem

}

export interface ManagedMobileLobApp extends ManagedApp {

	    /** The internal committed content version. */
		committedContentVersion?: string

	    /** The name of the main Lob application file. */
		fileName?: string

	    /** The total size, including all uploaded files. */
		size?: number

	    /** The list of content versions for this app. */
		contentVersions?: MobileAppContent[]

}

export interface MobileAppContent extends Entity {

	    /** The list of files for this app content version. */
		files?: MobileAppContentFile[]

	    /** The collection of contained apps in a MobileLobApp acting as a package. */
		containedApps?: MobileContainedApp[]

}

export interface MobileContainedApp extends Entity {

}

export interface WindowsUniversalAppXContainedApp extends MobileContainedApp {

	    /** The app user model ID of the contained app of a WindowsUniversalAppX app. */
		appUserModelId?: string

}

export interface MicrosoftStoreForBusinessContainedApp extends MobileContainedApp {

	    /** The app user model ID of the contained app of a MicrosoftStoreForBusinessApp. */
		appUserModelId?: string

}

export interface ManagedAndroidLobApp extends ManagedMobileLobApp {

	    /** The package identifier. */
		packageId?: string

	    /** The Identity Name. */
		identityName?: string

	    /** The value for the minimum applicable operating system. */
		minimumSupportedOperatingSystem?: AndroidMinimumOperatingSystem

	    /** The version name of managed Android Line of Business (LoB) app. */
		versionName?: string

	    /** The version code of managed Android Line of Business (LoB) app. */
		versionCode?: string

	    /** The identity version. */
		identityVersion?: string

}

export interface ManagedIOSLobApp extends ManagedMobileLobApp {

	    /** The Identity Name. */
		bundleId?: string

	    /** The iOS architecture for which this app can run on. */
		applicableDeviceType?: IosDeviceType

	    /** The value for the minimum applicable operating system. */
		minimumSupportedOperatingSystem?: IosMinimumOperatingSystem

	    /** The expiration time. */
		expirationDateTime?: string

	    /** The version number of managed iOS Line of Business (LoB) app. */
		versionNumber?: string

	    /** The build number of managed iOS Line of Business (LoB) app. */
		buildNumber?: string

	    /** The identity version. */
		identityVersion?: string

}

export interface MobileLobApp extends MobileApp {

	    /** The internal committed content version. */
		committedContentVersion?: string

	    /** The name of the main Lob application file. */
		fileName?: string

	    /** The total size, including all uploaded files. */
		size?: number

	    /** The list of content versions for this app. */
		contentVersions?: MobileAppContent[]

}

export interface MacOSLobApp extends MobileLobApp {

	    /** The bundle id. */
		bundleId?: string

	    /** The value for the minimum applicable operating system. */
		minimumSupportedOperatingSystem?: MacOSMinimumOperatingSystem

	    /** The build number of MacOS Line of Business (LoB) app. */
		buildNumber?: string

	    /** The version number of MacOS Line of Business (LoB) app. */
		versionNumber?: string

	    /** The app list in this bundle package */
		childApps?: MacOSLobChildApp[]

	    /** The identity version. */
		identityVersion?: string

	    /** The chunk size for MD5 hash */
		md5HashChunkSize?: number

	    /** The MD5 hash codes */
		md5Hash?: string[]

	    /** A boolean to control whether the app's version will be used to detect the app after it is installed on a device. Set this to true for macOS Line of Business (LoB) apps that use a self update feature. */
		ignoreVersionDetection?: boolean

}

export interface WindowsMobileMSI extends MobileLobApp {

	    /** The command line. */
		commandLine?: string

	    /** The product code. */
		productCode?: string

	    /** The product version of Windows Mobile MSI Line of Business (LoB) app. */
		productVersion?: string

	    /** A boolean to control whether the app's version will be used to detect the app after it is installed on a device. Set this to true for Windows Mobile MSI Line of Business (LoB) apps that use a self update feature. */
		ignoreVersionDetection?: boolean

	    /** The identity version. */
		identityVersion?: string

	    /** Indicates whether to install a dual-mode MSI in the device context. If true, app will be installed for all users. If false, app will be installed per-user. If null, service will use the MSI package's default install context. In case of dual-mode MSI, this default will be per-user.  Cannot be set for non-dual-mode apps.  Cannot be changed after initial creation of the application. */
		useDeviceContext?: boolean

}

export interface WindowsPhone81AppX extends MobileLobApp {

	    /** The Windows architecture(s) for which this app can run on. Possible values are: none, x86, x64, arm, neutral. */
		applicableArchitectures?: WindowsArchitecture

	    /** The Identity Name. */
		identityName?: string

	    /** The Identity Publisher Hash. */
		identityPublisherHash?: string

	    /** The Identity Resource Identifier. */
		identityResourceIdentifier?: string

	    /** The value for the minimum applicable operating system. */
		minimumSupportedOperatingSystem?: WindowsMinimumOperatingSystem

	    /** The Phone Product Identifier. */
		phoneProductIdentifier?: string

	    /** The Phone Publisher Id. */
		phonePublisherId?: string

	    /** The identity version. */
		identityVersion?: string

}

export interface WindowsPhone81AppXBundle extends WindowsPhone81AppX {

	    /** The list of AppX Package Information. */
		appXPackageInformationList?: WindowsPackageInformation[]

}

export interface WindowsUniversalAppX extends MobileLobApp {

	    /** The Windows architecture(s) for which this app can run on. Possible values are: none, x86, x64, arm, neutral. */
		applicableArchitectures?: WindowsArchitecture

	    /** The Windows device type(s) for which this app can run on. Possible values are: none, desktop, mobile, holographic, team. */
		applicableDeviceTypes?: WindowsDeviceType

	    /** The Identity Name. */
		identityName?: string

	    /** The Identity Publisher Hash. */
		identityPublisherHash?: string

	    /** The Identity Resource Identifier. */
		identityResourceIdentifier?: string

	    /** Whether or not the app is a bundle. */
		isBundle?: boolean

	    /** The value for the minimum applicable operating system. */
		minimumSupportedOperatingSystem?: WindowsMinimumOperatingSystem

	    /** The identity version. */
		identityVersion?: string

	    /** The collection of contained apps in the committed mobileAppContent of a windowsUniversalAppX app. */
		committedContainedApps?: MobileContainedApp[]

}

export interface WindowsAppX extends MobileLobApp {

	    /** The Windows architecture(s) for which this app can run on. Possible values are: none, x86, x64, arm, neutral. */
		applicableArchitectures?: WindowsArchitecture

	    /** The Identity Name. */
		identityName?: string

	    /** The Identity Publisher Hash. */
		identityPublisherHash?: string

	    /** The Identity Resource Identifier. */
		identityResourceIdentifier?: string

	    /** Whether or not the app is a bundle. */
		isBundle?: boolean

	    /** The value for the minimum applicable operating system. */
		minimumSupportedOperatingSystem?: WindowsMinimumOperatingSystem

	    /** The identity version. */
		identityVersion?: string

}

export interface WindowsPhoneXAP extends MobileLobApp {

	    /** The value for the minimum applicable operating system. */
		minimumSupportedOperatingSystem?: WindowsMinimumOperatingSystem

	    /** The Product Identifier. */
		productIdentifier?: string

	    /** The identity version. */
		identityVersion?: string

}

export interface AndroidLobApp extends MobileLobApp {

	    /** The package identifier. */
		packageId?: string

	    /** The Identity Name. */
		identityName?: string

	    /** The value for the minimum applicable operating system. */
		minimumSupportedOperatingSystem?: AndroidMinimumOperatingSystem

	    /** The version name of Android Line of Business (LoB) app. */
		versionName?: string

	    /** The version code of Android Line of Business (LoB) app. */
		versionCode?: string

	    /** The identity version. */
		identityVersion?: string

}

export interface IosLobApp extends MobileLobApp {

	    /** The Identity Name. */
		bundleId?: string

	    /** The iOS architecture for which this app can run on. */
		applicableDeviceType?: IosDeviceType

	    /** The value for the minimum applicable operating system. */
		minimumSupportedOperatingSystem?: IosMinimumOperatingSystem

	    /** The expiration time. */
		expirationDateTime?: string

	    /** The version number of iOS Line of Business (LoB) app. */
		versionNumber?: string

	    /** The build number of iOS Line of Business (LoB) app. */
		buildNumber?: string

	    /** The identity version. */
		identityVersion?: string

}

export interface AndroidForWorkApp extends MobileApp {

	    /** The package identifier. */
		packageId?: string

	    /** The Identity Name. */
		appIdentifier?: string

	    /** The number of VPP licenses in use. */
		usedLicenseCount?: number

	    /** The total number of VPP licenses. */
		totalLicenseCount?: number

	    /** The Play for Work Store app URL. */
		appStoreUrl?: string

}

export interface AndroidManagedStoreApp extends MobileApp {

		packageId?: string

		appIdentifier?: string

		usedLicenseCount?: number

		totalLicenseCount?: number

		appStoreUrl?: string

}

export interface MicrosoftStoreForBusinessApp extends MobileApp {

	    /** The number of Microsoft Store for Business licenses in use. */
		usedLicenseCount?: number

	    /** The total number of Microsoft Store for Business licenses. */
		totalLicenseCount?: number

	    /** The app product key */
		productKey?: string

	    /** The app license type. Possible values are: offline, online. */
		licenseType?: MicrosoftStoreForBusinessLicenseType

	    /** The app package identifier */
		packageIdentityName?: string

	    /** The collection of contained apps in a mobileApp acting as a package. */
		containedApps?: MobileContainedApp[]

}

export interface WebApp extends MobileApp {

	    /** The web app URL. */
		appUrl?: string

	    /** Whether or not to use managed browser. This property is only applicable for Android and IOS. */
		useManagedBrowser?: boolean

}

export interface WindowsPhone81StoreApp extends MobileApp {

	    /** The Windows Phone 8.1 app store URL. */
		appStoreUrl?: string

}

export interface WindowsStoreApp extends MobileApp {

	    /** The Windows app store URL. */
		appStoreUrl?: string

}

export interface AndroidStoreApp extends MobileApp {

	    /** The package identifier. */
		packageId?: string

	    /** The Identity Name. */
		appIdentifier?: string

	    /** The Android app store URL. */
		appStoreUrl?: string

	    /** The value for the minimum applicable operating system. */
		minimumSupportedOperatingSystem?: AndroidMinimumOperatingSystem

}

export interface IosVppAppAssignedDeviceLicense extends IosVppAppAssignedLicense {

		managedDeviceId?: string

		deviceName?: string

}

export interface IosVppAppAssignedUserLicense extends IosVppAppAssignedLicense {

}

export interface IosStoreApp extends MobileApp {

	    /** The Identity Name. */
		bundleId?: string

	    /** The Apple App Store URL */
		appStoreUrl?: string

	    /** The iOS architecture for which this app can run on. */
		applicableDeviceType?: IosDeviceType

	    /** The value for the minimum applicable operating system. */
		minimumSupportedOperatingSystem?: IosMinimumOperatingSystem

}

export interface AndroidForWorkMobileAppConfiguration extends ManagedDeviceMobileAppConfiguration {

		packageId?: string

	    /** Android For Work app configuration JSON payload. */
		payloadJson?: string

	    /** List of Android app permissions and corresponding permission actions. */
		permissionActions?: AndroidPermissionAction[]

}

export interface AndroidManagedStoreAppConfiguration extends ManagedDeviceMobileAppConfiguration {

		packageId?: string

		payloadJson?: string

		permissionActions?: AndroidPermissionAction[]

}

export interface IosMobileAppConfiguration extends ManagedDeviceMobileAppConfiguration {

	    /** mdm app configuration Base64 binary. */
		encodedSettingXml?: number

	    /** app configuration setting items. */
		settings?: AppConfigurationSettingItem[]

}

export interface TermsAndConditionsGroupAssignment extends Entity {

	    /** Unique identifier of a group that the T&C policy is assigned to. */
		targetGroupId?: string

	    /** Navigation link to the terms and conditions that are assigned. */
		termsAndConditions?: TermsAndConditions

}

export interface TermsAndConditionsAssignment extends Entity {

	    /** Assignment target that the T&C policy is assigned to. */
		target?: DeviceAndAppManagementAssignmentTarget

}

export interface TermsAndConditionsAcceptanceStatus extends Entity {

	    /** Display name of the user whose acceptance the entity represents. */
		userDisplayName?: string

	    /** Most recent version number of the T&C accepted by the user. */
		acceptedVersion?: number

	    /** DateTime when the terms were last accepted by the user. */
		acceptedDateTime?: string

	    /** Navigation link to the terms and conditions that are assigned. */
		termsAndConditions?: TermsAndConditions

}

export interface DeviceManagementScriptAssignment extends Entity {

	    /** The Id of the Azure Active Directory group we are targeting the script to. */
		target?: DeviceAndAppManagementAssignmentTarget

}

export interface DeviceManagementScriptGroupAssignment extends Entity {

	    /** The Id of the Azure Active Directory group we are targeting the script to. */
		targetGroupId?: string

}

export interface DeviceManagementScriptRunSummary extends Entity {

	    /** Success device count. */
		successDeviceCount?: number

	    /** Error device count. */
		errorDeviceCount?: number

	    /** Success user count. */
		successUserCount?: number

	    /** Error user count. */
		errorUserCount?: number

}

export interface DeviceManagementScriptDeviceState extends Entity {

	    /** State of latest run of the device management script. Possible values are: unknown, success, fail. */
		runState?: RunState

	    /** Details of execution output. */
		resultMessage?: string

	    /** Latest time the device management script executes. */
		lastStateUpdateDateTime?: string

	    /** Error code corresponding to erroneous execution of the device management script. */
		errorCode?: number

	    /** Error description corresponding to erroneous execution of the device management script. */
		errorDescription?: string

	    /** The managed devices that executes the device management script. */
		managedDevice?: ManagedDevice

}

export interface DeviceManagementScriptUserState extends Entity {

	    /** Success device count for specific user. */
		successDeviceCount?: number

	    /** Error device count for specific user. */
		errorDeviceCount?: number

	    /** User principle name of specific user. */
		userPrincipalName?: string

	    /** List of run states for this script across all devices of specific user. */
		deviceRunStates?: DeviceManagementScriptDeviceState[]

}

export interface DeviceConfigurationState extends Entity {

		settingStates?: DeviceConfigurationSettingState[]

		displayName?: string

		version?: number

		platformType?: PolicyPlatformType

		state?: ComplianceStatus

		settingCount?: number

		userId?: string

		userPrincipalName?: string

}

export interface WindowsProtectionState extends Entity {

	    /** Anti malware is enabled or not */
		malwareProtectionEnabled?: boolean

	    /** Computer's state (like clean or pending full scan or pending reboot etc). Possible values are: clean, fullScanPending, rebootPending, manualStepsPending, offlineScanPending, critical. */
		deviceState?: WindowsDeviceHealthState

	    /** Real time protection is enabled or not? */
		realTimeProtectionEnabled?: boolean

	    /** Network inspection system enabled or not? */
		networkInspectionSystemEnabled?: boolean

	    /** Quick scan overdue or not? */
		quickScanOverdue?: boolean

	    /** Full scan overdue or not? */
		fullScanOverdue?: boolean

	    /** Signature out of date or not? */
		signatureUpdateOverdue?: boolean

	    /** Reboot required or not? */
		rebootRequired?: boolean

	    /** Full scan required or not? */
		fullScanRequired?: boolean

	    /** Current endpoint protection engine's version */
		engineVersion?: string

	    /** Current malware definitions version */
		signatureVersion?: string

	    /** Current anti malware version */
		antiMalwareVersion?: string

	    /** Last quick scan datetime */
		lastQuickScanDateTime?: string

	    /** Last quick scan datetime */
		lastFullScanDateTime?: string

	    /** Last quick scan signature version */
		lastQuickScanSignatureVersion?: string

	    /** Last full scan signature version */
		lastFullScanSignatureVersion?: string

	    /** Last device health status reported time */
		lastReportedDateTime?: string

	    /** Device malware list */
		detectedMalwareState?: WindowsDeviceMalwareState[]

}

export interface DeviceCompliancePolicyState extends Entity {

		settingStates?: DeviceCompliancePolicySettingState[]

		displayName?: string

		version?: number

		platformType?: PolicyPlatformType

		state?: ComplianceStatus

		settingCount?: number

		userId?: string

		userPrincipalName?: string

}

export interface ManagedDeviceMobileAppConfigurationState extends Entity {

		displayName?: string

		version?: number

		platformType?: PolicyPlatformType

		state?: ComplianceStatus

		settingCount?: number

		userId?: string

		userPrincipalName?: string

}

export interface WindowsDeviceMalwareState extends Entity {

	    /** Malware name */
		displayName?: string

	    /** Information URL to learn more about the malware */
		additionalInformationUrl?: string

	    /** Severity of the malware. Possible values are: unknown, low, moderate, high, severe. */
		severity?: WindowsMalwareSeverity

	    /** Category of the malware. Possible values are: invalid, adware, spyware, passwordStealer, trojanDownloader, worm, backdoor, remoteAccessTrojan, trojan, emailFlooder, keylogger, dialer, monitoringSoftware, browserModifier, cookie, browserPlugin, aolExploit, nuker, securityDisabler, jokeProgram, hostileActiveXControl, softwareBundler, stealthNotifier, settingsModifier, toolBar, remoteControlSoftware, trojanFtp, potentialUnwantedSoftware, icqExploit, trojanTelnet, exploit, filesharingProgram, malwareCreationTool, remote_Control_Software, tool, trojanDenialOfService, trojanDropper, trojanMassMailer, trojanMonitoringSoftware, trojanProxyServer, virus, known, unknown, spp, behavior, vulnerability, policy. */
		catetgory?: WindowsMalwareCategory

	    /** Execution status of the malware like blocked/executing etc. Possible values are: unknown, blocked, allowed, running, notRunning. */
		executionState?: WindowsMalwareExecutionState

	    /** Current status of the malware like cleaned/quarantined/allowed etc. Possible values are: unknown, detected, cleaned, quarantined, removed, allowed, blocked, cleanFailed, quarantineFailed, removeFailed, allowFailed, abandoned, blockFailed. */
		state?: WindowsMalwareState

		threatState?: WindowsMalwareThreatState

	    /** Initial detection datetime of the malware */
		initialDetectionDateTime?: string

	    /** The last time this particular threat was changed */
		lastStateChangeDateTime?: string

	    /** Number of times the malware is detected */
		detectionCount?: number

		category?: WindowsMalwareCategory

}

export interface WindowsManagedDevice extends ManagedDevice {

}

export interface WindowsManagementAppHealthSummary extends Entity {

	    /** Healthy device count. */
		healthyDeviceCount?: number

	    /** Unhealthy device count. */
		unhealthyDeviceCount?: number

	    /** Unknown device count. */
		unknownDeviceCount?: number

}

export interface WindowsManagementAppHealthState extends Entity {

	    /** Windows management app health state. Possible values are: unknown, healthy, unhealthy. */
		healthState?: HealthState

	    /** Windows management app installed version. */
		installedVersion?: string

	    /** Windows management app last check-in time. */
		lastCheckInDateTime?: string

	    /** Name of the device on which Windows management app is installed. */
		deviceName?: string

	    /** Windows 10 OS version of the device on which Windows management app is installed. */
		deviceOSVersion?: string

}

export interface ReportRoot extends Entity {

}

export interface DeviceConfigurationGroupAssignment extends Entity {

	    /** The Id of the AAD group we are targeting the device configuration to. */
		targetGroupId?: string

	    /** Indicates if this group is should be excluded. Defaults that the group should be included */
		excludeGroup?: boolean

	    /** The navigation link to the Device Configuration being targeted. */
		deviceConfiguration?: DeviceConfiguration

}

export interface DeviceConfigurationAssignment extends Entity {

	    /** The assignment target for the device configuration. */
		target?: DeviceAndAppManagementAssignmentTarget

}

export interface DeviceConfigurationDeviceStatus extends Entity {

	    /** Device name of the DevicePolicyStatus. */
		deviceDisplayName?: string

	    /** The User Name that is being reported */
		userName?: string

	    /** The device model that is being reported */
		deviceModel?: string

	    /** Platform of the device that is being reported */
		platform?: number

	    /** The DateTime when device compliance grace period expires */
		complianceGracePeriodExpirationDateTime?: string

	    /** Compliance status of the policy report. Possible values are: unknown, notApplicable, compliant, remediated, nonCompliant, error, conflict. */
		status?: ComplianceStatus

	    /** Last modified date time of the policy report. */
		lastReportedDateTime?: string

	    /** UserPrincipalName. */
		userPrincipalName?: string

}

export interface DeviceConfigurationUserStatus extends Entity {

	    /** User name of the DevicePolicyStatus. */
		userDisplayName?: string

	    /** Devices count for that user. */
		devicesCount?: number

	    /** Compliance status of the policy report. Possible values are: unknown, notApplicable, compliant, remediated, nonCompliant, error, conflict. */
		status?: ComplianceStatus

	    /** Last modified date time of the policy report. */
		lastReportedDateTime?: string

	    /** UserPrincipalName. */
		userPrincipalName?: string

}

export interface DeviceConfigurationDeviceOverview extends Entity {

	    /** Number of pending devices */
		pendingCount?: number

	    /** Number of not applicable devices */
		notApplicableCount?: number

	    /** Number of not applicable devices due to mismatch platform and policy */
		notApplicablePlatformCount?: number

	    /** Number of succeeded devices */
		successCount?: number

	    /** Number of error devices */
		errorCount?: number

	    /** Number of failed devices */
		failedCount?: number

	    /** Number of devices in conflict */
		conflictCount?: number

	    /** Last update time */
		lastUpdateDateTime?: string

	    /** Version of the policy for that overview */
		configurationVersion?: number

}

export interface DeviceConfigurationUserOverview extends Entity {

	    /** Number of pending Users */
		pendingCount?: number

	    /** Number of not applicable users */
		notApplicableCount?: number

	    /** Number of succeeded Users */
		successCount?: number

	    /** Number of error Users */
		errorCount?: number

	    /** Number of failed Users */
		failedCount?: number

	    /** Number of users in conflict */
		conflictCount?: number

	    /** Last update time */
		lastUpdateDateTime?: string

	    /** Version of the policy for that overview */
		configurationVersion?: number

}

export interface SettingStateDeviceSummary extends Entity {

	    /** Name of the setting */
		settingName?: string

	    /** Name of the InstancePath for the setting */
		instancePath?: string

	    /** Device Unkown count for the setting */
		unknownDeviceCount?: number

	    /** Device Not Applicable count for the setting */
		notApplicableDeviceCount?: number

	    /** Device Compliant count for the setting */
		compliantDeviceCount?: number

	    /** Device Compliant count for the setting */
		remediatedDeviceCount?: number

	    /** Device NonCompliant count for the setting */
		nonCompliantDeviceCount?: number

	    /** Device error count for the setting */
		errorDeviceCount?: number

	    /** Device conflict error count for the setting */
		conflictDeviceCount?: number

}

export interface DeviceCompliancePolicyAssignment extends Entity {

	    /** Target for the compliance policy assignment. */
		target?: DeviceAndAppManagementAssignmentTarget

}

export interface DeviceComplianceScheduledActionForRule extends Entity {

	    /** Name of the rule which this scheduled action applies to. */
		ruleName?: string

	    /** The list of scheduled action configurations for this compliance policy. */
		scheduledActionConfigurations?: DeviceComplianceActionItem[]

}

export interface DeviceComplianceDeviceStatus extends Entity {

	    /** Device name of the DevicePolicyStatus. */
		deviceDisplayName?: string

	    /** The User Name that is being reported */
		userName?: string

	    /** The device model that is being reported */
		deviceModel?: string

	    /** Platform of the device that is being reported */
		platform?: number

	    /** The DateTime when device compliance grace period expires */
		complianceGracePeriodExpirationDateTime?: string

	    /** Compliance status of the policy report. Possible values are: unknown, notApplicable, compliant, remediated, nonCompliant, error, conflict. */
		status?: ComplianceStatus

	    /** Last modified date time of the policy report. */
		lastReportedDateTime?: string

	    /** UserPrincipalName. */
		userPrincipalName?: string

}

export interface DeviceComplianceUserStatus extends Entity {

	    /** User name of the DevicePolicyStatus. */
		userDisplayName?: string

	    /** Devices count for that user. */
		devicesCount?: number

	    /** Compliance status of the policy report. Possible values are: unknown, notApplicable, compliant, remediated, nonCompliant, error, conflict. */
		status?: ComplianceStatus

	    /** Last modified date time of the policy report. */
		lastReportedDateTime?: string

	    /** UserPrincipalName. */
		userPrincipalName?: string

}

export interface DeviceComplianceDeviceOverview extends Entity {

	    /** Number of pending devices */
		pendingCount?: number

	    /** Number of not applicable devices */
		notApplicableCount?: number

	    /** Number of not applicable devices due to mismatch platform and policy */
		notApplicablePlatformCount?: number

	    /** Number of succeeded devices */
		successCount?: number

	    /** Number of error devices */
		errorCount?: number

	    /** Number of failed devices */
		failedCount?: number

	    /** Number of devices in conflict */
		conflictCount?: number

	    /** Last update time */
		lastUpdateDateTime?: string

	    /** Version of the policy for that overview */
		configurationVersion?: number

}

export interface DeviceComplianceUserOverview extends Entity {

	    /** Number of pending Users */
		pendingCount?: number

	    /** Number of not applicable users */
		notApplicableCount?: number

	    /** Number of succeeded Users */
		successCount?: number

	    /** Number of error Users */
		errorCount?: number

	    /** Number of failed Users */
		failedCount?: number

	    /** Number of users in conflict */
		conflictCount?: number

	    /** Last update time */
		lastUpdateDateTime?: string

	    /** Version of the policy for that overview */
		configurationVersion?: number

}

export interface DeviceComplianceActionItem extends Entity {

	    /** Number of hours to wait till the action will be enforced. Valid values 0 to 8760 */
		gracePeriodHours?: number

	    /** What action to take. Possible values are: noAction, notification, block, retire, wipe, removeResourceAccessProfiles. */
		actionType?: DeviceComplianceActionType

	    /** What notification Message template to use */
		notificationTemplateId?: string

	    /** A list of group IDs to speicify who to CC this notification message to. */
		notificationMessageCCList?: string[]

}

export interface WindowsPrivacyDataAccessControlItem extends Entity {

	    /** This indicates an access level for the privacy data category to which the specified application will be given to. Possible values are: notConfigured, forceAllow, forceDeny, userInControl. */
		accessLevel?: WindowsPrivacyDataAccessLevel

	    /** This indicates a privacy data category to which the specific access control will apply. Possible values are: notConfigured, accountInfo, appsRunInBackground, calendar, callHistory, camera, contacts, diagnosticsInfo, email, location, messaging, microphone, motion, notifications, phone, radios, tasks, syncWithDevices, trustedDevices. */
		dataCategory?: WindowsPrivacyDataCategory

	    /** The Package Family Name of a Windows app. When set, the access level applies to the specified application. */
		appPackageFamilyName?: string

	    /** The Package Family Name of a Windows app. When set, the access level applies to the specified application. */
		appDisplayName?: string

}

export interface WindowsAssignedAccessProfile extends Entity {

	    /** This is a friendly name used to identify a group of applications, the layout of these apps on the start menu and the users to whom this kiosk configuration is assigned. */
		profileName?: string

	    /** This setting allows the admin to specify whether the Task Bar is shown or not. */
		showTaskBar?: boolean

	    /** These are the only Windows Store Apps that will be available to launch from the Start menu. */
		appUserModelIds?: string[]

	    /** These are the paths of the Desktop Apps that will be available on the Start menu and the only apps the user will be able to launch. */
		desktopAppPaths?: string[]

	    /** The user accounts that will be locked to this kiosk configuration. */
		userAccounts?: string[]

	    /** Allows admins to override the default Start layout and prevents the user from changing it. The layout is modified by specifying an XML file based on a layout modification schema. XML needs to be in Binary format. */
		startMenuLayoutXml?: number

}

export interface AndroidDeviceOwnerGeneralDeviceConfiguration extends DeviceConfiguration {

	    /** Indicates whether or not adding or removing accounts is disabled. */
		accountsBlockModification?: boolean

	    /** Indicates whether or not the user is allowed to enable to unknown sources setting. */
		appsAllowInstallFromUnknownSources?: boolean

		appsAutoUpdatePolicy?: AndroidDeviceOwnerAppAutoUpdatePolicyType

	    /** Indicates the permission policy for requests for runtime permissions if one is not defined for the app specifically. Possible values are: deviceDefault, prompt, autoGrant, autoDeny. */
		appsDefaultPermissionPolicy?: AndroidDeviceOwnerDefaultAppPermissionPolicyType

		bluetoothBlockConfiguration?: boolean

		bluetoothBlockContactSharing?: boolean

	    /** Indicates whether or not to disable the use of the camera. */
		cameraBlocked?: boolean

		cellularBlockWiFiTethering?: boolean

		dataRoamingBlocked?: boolean

		dateTimeConfigurationBlocked?: boolean

	    /** List of Google account emails that will be required to authenticate after a device is factory reset before it can be set up. */
		factoryResetDeviceAdministratorEmails?: string[]

	    /** Indicates whether or not the factory reset option in settings is disabled. */
		factoryResetBlocked?: boolean

	    /** A list of managed apps that will be shown when the device is in Kiosk Mode. */
		kioskModeApps?: AppListItem[]

	    /** Indicates whether or not to block unmuting the microphone on the device. */
		microphoneForceMute?: boolean

	    /** Indicates whether or not the device will allow connecting to a temporary network connection at boot time. */
		networkEscapeHatchAllowed?: boolean

		nfcBlockOutgoingBeam?: boolean

	    /** Indicates whether or not the keyguard is disabled. */
		passwordBlockKeyguard?: boolean

	    /** Indicates the amount of time in seconds that a password can be set for before it expires and a new password will be required. */
		passwordExpirationDays?: number

	    /** Indicates the minimum length of the password required on the device. */
		passwordMinimumLength?: number

	    /** Milliseconds of inactivity before the screen times out. */
		passwordMinutesOfInactivityBeforeScreenTimeout?: number

	    /** Indicates the length of password history, where the user will not be able to enter a new password that is the same as any password in the history. */
		passwordPreviousPasswordCountToBlock?: number

	    /** Indicates the minimum password quality required on the device. Possible values are: deviceDefault, required, numeric, numericComplex, alphabetic, alphanumeric, alphanumericWithSymbols. */
		passwordRequiredType?: AndroidDeviceOwnerRequiredPasswordType

	    /** Indicates the number of times a user can enter an incorrect password before the device is wiped. */
		passwordSignInFailureCountBeforeFactoryReset?: number

	    /** Indicates whether or not rebooting the device into safe boot is disabled. */
		safeBootBlocked?: boolean

	    /** Indicates whether or not to disable the capability to take screenshots. */
		screenCaptureBlocked?: boolean

	    /** Indicates whether or not to block the user from enabling debugging features on the device. */
		securityAllowDebuggingFeatures?: boolean

		securityRequireVerifyApps?: boolean

	    /** Indicates whether or the status bar is disabled, including notifications, quick settings and other screen overlays. */
		statusBarBlocked?: boolean

	    /** List of modes in which the device's display will stay powered-on. */
		stayOnModes?: AndroidDeviceOwnerBatteryPluggedMode[]

		storageAllowUsb?: boolean

		storageBlockExternalMedia?: boolean

		storageBlockUsbFileTransfer?: boolean

		systemUpdateWindowStartMinutesAfterMidnight?: number

		systemUpdateWindowEndMinutesAfterMidnight?: number

		systemUpdateInstallType?: AndroidDeviceOwnerSystemUpdateInstallType

	    /** Indicates whether or not adding users and profiles is disabled. */
		usersBlockAdd?: boolean

	    /** Indicates whether or not to disable removing other users from the device. */
		usersBlockRemove?: boolean

	    /** Indicates whether or not adjusting the master volume is disabled. */
		volumeBlockAdjustment?: boolean

	    /** Indicates whether or not to block the user from editing the wifi connection settings. */
		wifiBlockEditConfigurations?: boolean

	    /** Indicates whether or not to block the user from editing just the networks defined by the policy. */
		wifiBlockEditPolicyDefinedConfigurations?: boolean

}

export interface AndroidDeviceOwnerWiFiConfiguration extends DeviceConfiguration {

		networkName?: string

		ssid?: string

		connectAutomatically?: boolean

		connectWhenNetworkNameIsHidden?: boolean

		wiFiSecurityType?: AndroidDeviceOwnerWiFiSecurityType

		preSharedKey?: string

		preSharedKeyIsSet?: boolean

}

export interface AndroidForWorkEasEmailProfileBase extends DeviceConfiguration {

	    /** Authentication method for Exchange ActiveSync. Possible values are: usernameAndPassword, certificate. */
		authenticationMethod?: EasAuthenticationMethod

	    /** Duration of time email should be synced to. Possible values are: userDefined, oneDay, threeDays, oneWeek, twoWeeks, oneMonth, unlimited. */
		durationOfEmailToSync?: EmailSyncDuration

	    /** Email attribute that is picked from AAD and injected into this profile before installing on the device. Possible values are: userPrincipalName, primarySmtpAddress. */
		emailAddressSource?: UserEmailSource

	    /** Exchange location (URL) that the mail app connects to. */
		hostName?: string

	    /** Indicates whether or not to use SSL. */
		requireSsl?: boolean

	    /** Username attribute that is picked from AAD and injected into this profile before installing on the device. Possible values are: username, userPrincipalName, samAccountName, primarySmtpAddress. */
		usernameSource?: AndroidUsernameSource

	    /** Identity certificate. */
		identityCertificate?: AndroidForWorkCertificateProfileBase

}

export interface AndroidForWorkCertificateProfileBase extends DeviceConfiguration {

	    /** Certificate renewal threshold percentage. Valid values 1 to 99 */
		renewalThresholdPercentage?: number

	    /** Certificate Subject Name Format. Possible values are: commonName, commonNameIncludingEmail, commonNameAsEmail, custom, commonNameAsIMEI, commonNameAsSerialNumber, commonNameAsAadDeviceId, commonNameAsIntuneDeviceId, commonNameAsDurableDeviceId. */
		subjectNameFormat?: SubjectNameFormat

	    /** Certificate Subject Alternative Name Type. Possible values are: none, emailAddress, userPrincipalName, customAzureADAttribute. */
		subjectAlternativeNameType?: SubjectAlternativeNameType

	    /** Value for the Certificate Validity Period. */
		certificateValidityPeriodValue?: number

	    /** Scale for the Certificate Validity Period. Possible values are: days, months, years. */
		certificateValidityPeriodScale?: CertificateValidityPeriodScale

	    /** Extended Key Usage (EKU) settings. This collection can contain a maximum of 500 elements. */
		extendedKeyUsages?: ExtendedKeyUsage[]

	    /** Trusted Root Certificate. */
		rootCertificate?: AndroidForWorkTrustedRootCertificate

}

export interface AndroidForWorkTrustedRootCertificate extends DeviceConfiguration {

	    /** Trusted Root Certificate */
		trustedRootCertificate?: number

	    /** File name to display in UI. */
		certFileName?: string

}

export interface AndroidForWorkPkcsCertificateProfile extends AndroidForWorkCertificateProfileBase {

	    /** PKCS Certification Authority */
		certificationAuthority?: string

	    /** PKCS Certification Authority Name */
		certificationAuthorityName?: string

	    /** PKCS Certificate Template Name */
		certificateTemplateName?: string

	    /** Custom String that defines the AAD Attribute. */
		subjectAlternativeNameFormatString?: string

		managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface ManagedDeviceCertificateState extends Entity {

	    /** Device platform. Possible values are: android, androidForWork, iOS, macOS, windowsPhone81, windows81AndLater, windows10AndLater. */
		devicePlatform?: DevicePlatformType

	    /** Key usage. Possible values are: keyEncipherment, digitalSignature. */
		certificateKeyUsage?: KeyUsages

		certificateValidityPeriodUnits?: CertificateValidityPeriodScale

		certificateIssuanceState?: CertificateIssuanceStates

		certificateKeyStorageProvider?: KeyStorageProviderOption

		certificateSubjectNameFormat?: SubjectNameFormat

		certificateSubjectAlternativeNameFormat?: SubjectAlternativeNameType

		certificateRevokeStatus?: CertificateRevocationStatus

	    /** Certificate profile display name */
		certificateProfileDisplayName?: string

	    /** Device display name */
		deviceDisplayName?: string

	    /** User display name */
		userDisplayName?: string

	    /** Certificate expiry date */
		certificateExpirationDateTime?: string

		certificateLastIssuanceStateChangedDateTime?: string

	    /** Last certificate issuance state change */
		lastCertificateStateChangeDateTime?: string

	    /** Issuer */
		certificateIssuer?: string

	    /** Thumbprint */
		certificateThumbprint?: string

	    /** Serial number */
		certificateSerialNumber?: string

	    /** Key length */
		certificateKeyLength?: number

		certificateEnhancedKeyUsage?: string

		certificateValidityPeriod?: number

		certificateSubjectNameFormatString?: string

		certificateSubjectAlternativeNameFormatString?: string

		certificateIssuanceDateTime?: string

		certificateErrorCode?: number

}

export interface AndroidForWorkScepCertificateProfile extends AndroidForWorkCertificateProfileBase {

	    /** SCEP Server Url(s) */
		scepServerUrls?: string[]

	    /** Custom format to use with SubjectNameFormat = Custom. Example: CN={{EmailAddress}},E={{EmailAddress}},OU=Enterprise Users,O=Contoso Corporation,L=Redmond,ST=WA,C=US */
		subjectNameFormatString?: string

	    /** SCEP Key Usage. Possible values are: keyEncipherment, digitalSignature. */
		keyUsage?: KeyUsages

	    /** SCEP Key Size. Possible values are: size1024, size2048. */
		keySize?: KeySize

	    /** SCEP Hash Algorithm. Possible values are: sha1, sha2. */
		hashAlgorithm?: HashAlgorithms

	    /** Custom String that defines the AAD Attribute. */
		subjectAlternativeNameFormatString?: string

	    /** Certificate state for devices */
		managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface AndroidForWorkGmailEasConfiguration extends AndroidForWorkEasEmailProfileBase {

}

export interface AndroidForWorkNineWorkEasConfiguration extends AndroidForWorkEasEmailProfileBase {

	    /** Toggles syncing the calendar. If set to false the calendar is turned off on the device. */
		syncCalendar?: boolean

	    /** Toggles syncing contacts. If set to false contacts are turned off on the device. */
		syncContacts?: boolean

	    /** Toggles syncing tasks. If set to false tasks are turned off on the device. */
		syncTasks?: boolean

}

export interface AndroidCertificateProfileBase extends DeviceConfiguration {

	    /** Certificate renewal threshold percentage. Valid values 1 to 99 */
		renewalThresholdPercentage?: number

	    /** Certificate Subject Name Format. Possible values are: commonName, commonNameIncludingEmail, commonNameAsEmail, custom, commonNameAsIMEI, commonNameAsSerialNumber, commonNameAsAadDeviceId, commonNameAsIntuneDeviceId, commonNameAsDurableDeviceId. */
		subjectNameFormat?: SubjectNameFormat

	    /** Certificate Subject Alternative Name Type. Possible values are: none, emailAddress, userPrincipalName, customAzureADAttribute. */
		subjectAlternativeNameType?: SubjectAlternativeNameType

	    /** Value for the Certificate Validity Period. */
		certificateValidityPeriodValue?: number

	    /** Scale for the Certificate Validity Period. Possible values are: days, months, years. */
		certificateValidityPeriodScale?: CertificateValidityPeriodScale

	    /** Extended Key Usage (EKU) settings. This collection can contain a maximum of 500 elements. */
		extendedKeyUsages?: ExtendedKeyUsage[]

	    /** Trusted Root Certificate. */
		rootCertificate?: AndroidTrustedRootCertificate

}

export interface AndroidTrustedRootCertificate extends DeviceConfiguration {

	    /** Trusted Root Certificate */
		trustedRootCertificate?: number

	    /** File name to display in UI. */
		certFileName?: string

}

export interface AndroidForWorkImportedPFXCertificateProfile extends AndroidCertificateProfileBase {

	    /** Not yet documented. Possible values are: unassigned, smimeEncryption, smimeSigning, vpn, wifi. */
		intendedPurpose?: IntendedPurpose

		managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface AndroidImportedPFXCertificateProfile extends AndroidCertificateProfileBase {

	    /** Not yet documented. Possible values are: unassigned, smimeEncryption, smimeSigning, vpn, wifi. */
		intendedPurpose?: IntendedPurpose

		managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface AndroidPkcsCertificateProfile extends AndroidCertificateProfileBase {

	    /** PKCS Certification Authority */
		certificationAuthority?: string

	    /** PKCS Certification Authority Name */
		certificationAuthorityName?: string

	    /** PKCS Certificate Template Name */
		certificateTemplateName?: string

	    /** Custom String that defines the AAD Attribute. */
		subjectAlternativeNameFormatString?: string

		managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface AndroidScepCertificateProfile extends AndroidCertificateProfileBase {

	    /** SCEP Server Url(s) */
		scepServerUrls?: string[]

	    /** Custom format to use with SubjectNameFormat = Custom. Example: CN={{EmailAddress}},E={{EmailAddress}},OU=Enterprise Users,O=Contoso Corporation,L=Redmond,ST=WA,C=US */
		subjectNameFormatString?: string

	    /** SCEP Key Usage. Possible values are: keyEncipherment, digitalSignature. */
		keyUsage?: KeyUsages

	    /** SCEP Key Size. Possible values are: size1024, size2048. */
		keySize?: KeySize

	    /** SCEP Hash Algorithm. Possible values are: sha1, sha2. */
		hashAlgorithm?: HashAlgorithms

	    /** Custom String that defines the AAD Attribute. */
		subjectAlternativeNameFormatString?: string

	    /** Certificate state for devices */
		managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface AndroidCustomConfiguration extends DeviceConfiguration {

	    /** OMA settings. This collection can contain a maximum of 1000 elements. */
		omaSettings?: OmaSetting[]

}

export interface AndroidEasEmailProfileConfiguration extends DeviceConfiguration {

	    /** Exchange ActiveSync account name, displayed to users as name of EAS (this) profile. */
		accountName?: string

	    /** Authentication method for Exchange ActiveSync. Possible values are: usernameAndPassword, certificate. */
		authenticationMethod?: EasAuthenticationMethod

	    /** Toggles syncing the calendar. If set to false calendar is turned off on the device. */
		syncCalendar?: boolean

	    /** Toggles syncing contacts. If set to false contacts are turned off on the device. */
		syncContacts?: boolean

	    /** Toggles syncing tasks. If set to false tasks are turned off on the device. */
		syncTasks?: boolean

	    /** Toggles syncing notes. If set to false notes are turned off on the device. */
		syncNotes?: boolean

	    /** Duration of time email should be synced to. Possible values are: userDefined, oneDay, threeDays, oneWeek, twoWeeks, oneMonth, unlimited. */
		durationOfEmailToSync?: EmailSyncDuration

	    /** Email attribute that is picked from AAD and injected into this profile before installing on the device. Possible values are: userPrincipalName, primarySmtpAddress. */
		emailAddressSource?: UserEmailSource

	    /** Email sync schedule. Possible values are: userDefined, asMessagesArrive, manual, fifteenMinutes, thirtyMinutes, sixtyMinutes, basedOnMyUsage. */
		emailSyncSchedule?: EmailSyncSchedule

	    /** Exchange location (URL) that the native mail app connects to. */
		hostName?: string

	    /** Indicates whether or not to use S/MIME certificate. */
		requireSmime?: boolean

	    /** Indicates whether or not to use SSL. */
		requireSsl?: boolean

	    /** Username attribute that is picked from AAD and injected into this profile before installing on the device. Possible values are: username, userPrincipalName, samAccountName, primarySmtpAddress. */
		usernameSource?: AndroidUsernameSource

	    /** UserDomainname attribute that is picked from AAD and injected into this profile before installing on the device. Possible values are: fullDomainName, netBiosDomainName. */
		userDomainNameSource?: DomainNameSource

	    /** Custom domain name value used while generating an email profile before installing on the device. */
		customDomainName?: string

	    /** Identity certificate. */
		identityCertificate?: AndroidCertificateProfileBase

	    /** S/MIME signing certificate. */
		smimeSigningCertificate?: AndroidCertificateProfileBase

}

export interface AndroidForWorkCustomConfiguration extends DeviceConfiguration {

	    /** OMA settings. This collection can contain a maximum of 500 elements. */
		omaSettings?: OmaSetting[]

}

export interface AndroidForWorkWiFiConfiguration extends DeviceConfiguration {

	    /** Network Name */
		networkName?: string

	    /** This is the name of the Wi-Fi network that is broadcast to all devices. */
		ssid?: string

	    /** Connect automatically when this network is in range. Setting this to true will skip the user prompt and automatically connect the device to Wi-Fi network. */
		connectAutomatically?: boolean

	    /** When set to true, this profile forces the device to connect to a network that doesn't broadcast its SSID to all devices. */
		connectWhenNetworkNameIsHidden?: boolean

	    /** Indicates whether Wi-Fi endpoint uses an EAP based security type. Possible values are: open, wpaEnterprise. */
		wiFiSecurityType?: AndroidWiFiSecurityType

}

export interface AndroidForWorkEnterpriseWiFiConfiguration extends AndroidForWorkWiFiConfiguration {

	    /** Indicates the type of EAP protocol set on the the Wi-Fi endpoint (router). Possible values are: eapTls, eapTtls, peap. */
		eapType?: AndroidEapType

	    /** Indicates the Authentication Method the client (device) needs to use when the EAP Type is configured to PEAP or EAP-TTLS. Possible values are: certificate, usernameAndPassword. */
		authenticationMethod?: WiFiAuthenticationMethod

	    /** Non-EAP Method for Authentication (Inner Identity) when EAP Type is EAP-TTLS and Authenticationmethod is Username and Password. Possible values are: unencryptedPassword, challengeHandshakeAuthenticationProtocol, microsoftChap, microsoftChapVersionTwo. */
		innerAuthenticationProtocolForEapTtls?: NonEapAuthenticationMethodForEapTtlsType

	    /** Non-EAP Method for Authentication (Inner Identity) when EAP Type is PEAP and Authenticationmethod is Username and Password. Possible values are: none, microsoftChapVersionTwo. */
		innerAuthenticationProtocolForPeap?: NonEapAuthenticationMethodForPeap

	    /** Enable identity privacy (Outer Identity) when EAP Type is configured to EAP-TTLS or PEAP. The String provided here is used to mask the username of individual users when they attempt to connect to Wi-Fi network. */
		outerIdentityPrivacyTemporaryValue?: string

	    /** Trusted Root Certificate for Server Validation when EAP Type is configured to EAP-TLS, EAP-TTLS or PEAP. This is the certificate presented by the Wi-Fi endpoint when the device attempts to connect to Wi-Fi endpoint. The device (or user) must accept this certificate to continue the connection attempt. */
		rootCertificateForServerValidation?: AndroidForWorkTrustedRootCertificate

	    /** Identity Certificate for client authentication when EAP Type is configured to EAP-TLS, EAP-TTLS (with Certificate Authentication), or PEAP (with Certificate Authentication). This is the certificate presented by client to the Wi-Fi endpoint. The authentication server sitting behind the Wi-Fi endpoint must accept this certificate to successfully establish a Wi-Fi connection. */
		identityCertificateForClientAuthentication?: AndroidForWorkCertificateProfileBase

}

export interface AndroidForWorkGeneralDeviceConfiguration extends DeviceConfiguration {

	    /** Indicates whether or not to block fingerprint unlock. */
		passwordBlockFingerprintUnlock?: boolean

	    /** Indicates whether or not to block Smart Lock and other trust agents. */
		passwordBlockTrustAgents?: boolean

	    /** Number of days before the password expires. Valid values 1 to 365 */
		passwordExpirationDays?: number

	    /** Minimum length of passwords. Valid values 4 to 16 */
		passwordMinimumLength?: number

	    /** Minutes of inactivity before the screen times out. */
		passwordMinutesOfInactivityBeforeScreenTimeout?: number

	    /** Number of previous passwords to block. Valid values 0 to 24 */
		passwordPreviousPasswordBlockCount?: number

	    /** Number of sign in failures allowed before factory reset. Valid values 4 to 11 */
		passwordSignInFailureCountBeforeFactoryReset?: number

	    /** Type of password that is required. Possible values are: deviceDefault, lowSecurityBiometric, required, atLeastNumeric, numericComplex, atLeastAlphabetic, atLeastAlphanumeric, alphanumericWithSymbols. */
		passwordRequiredType?: AndroidForWorkRequiredPasswordType

	    /** Type of data sharing that is allowed. Possible values are: deviceDefault, preventAny, allowPersonalToWork, noRestrictions. */
		workProfileDataSharingType?: AndroidForWorkCrossProfileDataSharingType

	    /** Indicates whether or not to block notifications while device locked. */
		workProfileBlockNotificationsWhileDeviceLocked?: boolean

	    /** Block users from adding/removing accounts in work profile. */
		workProfileBlockAddingAccounts?: boolean

	    /** Allow bluetooth devices to access enterprise contacts. */
		workProfileBluetoothEnableContactSharing?: boolean

	    /** Block screen capture in work profile. */
		workProfileBlockScreenCapture?: boolean

	    /** Block display work profile caller ID in personal profile. */
		workProfileBlockCrossProfileCallerId?: boolean

	    /** Block work profile camera. */
		workProfileBlockCamera?: boolean

	    /** Block work profile contacts availability in personal profile. */
		workProfileBlockCrossProfileContactsSearch?: boolean

	    /** Boolean that indicates if the setting disallow cross profile copy/paste is enabled. */
		workProfileBlockCrossProfileCopyPaste?: boolean

	    /** Type of password that is required. Possible values are: deviceDefault, prompt, autoGrant, autoDeny. */
		workProfileDefaultAppPermissionPolicy?: AndroidForWorkDefaultAppPermissionPolicyType

	    /** Indicates whether or not to block fingerprint unlock for work profile. */
		workProfilePasswordBlockFingerprintUnlock?: boolean

	    /** Indicates whether or not to block Smart Lock and other trust agents for work profile. */
		workProfilePasswordBlockTrustAgents?: boolean

	    /** Number of days before the work profile password expires. Valid values 1 to 365 */
		workProfilePasswordExpirationDays?: number

	    /** Minimum length of work profile password. Valid values 4 to 16 */
		workProfilePasswordMinimumLength?: number

		workProfilePasswordMinNumericCharacters?: number

		workProfilePasswordMinNonLetterCharacters?: number

		workProfilePasswordMinLetterCharacters?: number

		workProfilePasswordMinLowerCaseCharacters?: number

		workProfilePasswordMinUpperCaseCharacters?: number

		workProfilePasswordMinSymbolCharacters?: number

	    /** Minutes of inactivity before the screen times out. */
		workProfilePasswordMinutesOfInactivityBeforeScreenTimeout?: number

	    /** Number of previous work profile passwords to block. Valid values 0 to 24 */
		workProfilePasswordPreviousPasswordBlockCount?: number

	    /** Number of sign in failures allowed before work profile is removed and all corporate data deleted. Valid values 4 to 11 */
		workProfilePasswordSignInFailureCountBeforeFactoryReset?: number

	    /** Type of work profile password that is required. Possible values are: deviceDefault, lowSecurityBiometric, required, atLeastNumeric, numericComplex, atLeastAlphabetic, atLeastAlphanumeric, alphanumericWithSymbols. */
		workProfilePasswordRequiredType?: AndroidForWorkRequiredPasswordType

	    /** Password is required or not for work profile */
		workProfileRequirePassword?: boolean

	    /** Require the Android Verify apps feature is turned on. */
		securityRequireVerifyApps?: boolean

		vpnAlwaysOnPackageIdentifier?: string

		vpnEnableAlwaysOnLockdownMode?: boolean

}

export interface AndroidForWorkVpnConfiguration extends DeviceConfiguration {

	    /** Connection name displayed to the user. */
		connectionName?: string

	    /** Connection type. Possible values are: ciscoAnyConnect, pulseSecure, f5EdgeClient, dellSonicWallMobileConnect, checkPointCapsuleVpn, citrix. */
		connectionType?: AndroidForWorkVpnConnectionType

	    /** Role when connection type is set to Pulse Secure. */
		role?: string

	    /** Realm when connection type is set to Pulse Secure. */
		realm?: string

	    /** List of VPN Servers on the network. Make sure end users can access these network locations. This collection can contain a maximum of 500 elements. */
		servers?: VpnServer[]

	    /** Fingerprint is a string that will be used to verify the VPN server can be trusted, which is only applicable when connection type is Check Point Capsule VPN. */
		fingerprint?: string

	    /** Custom data when connection type is set to Citrix. This collection can contain a maximum of 25 elements. */
		customData?: KeyValue[]

		customKeyValueData?: KeyValuePair[]

	    /** Authentication method. Possible values are: certificate, usernameAndPassword. */
		authenticationMethod?: VpnAuthenticationMethod

	    /** Identity certificate for client authentication when authentication method is certificate. */
		identityCertificate?: AndroidForWorkCertificateProfileBase

}

export interface AndroidGeneralDeviceConfiguration extends DeviceConfiguration {

	    /** Indicates whether or not to block clipboard sharing to copy and paste between applications. */
		appsBlockClipboardSharing?: boolean

	    /** Indicates whether or not to block copy and paste within applications. */
		appsBlockCopyPaste?: boolean

	    /** Indicates whether or not to block the YouTube app. */
		appsBlockYouTube?: boolean

	    /** Indicates whether or not to block Bluetooth. */
		bluetoothBlocked?: boolean

	    /** Indicates whether or not to block the use of the camera. */
		cameraBlocked?: boolean

	    /** Indicates whether or not to block data roaming. */
		cellularBlockDataRoaming?: boolean

	    /** Indicates whether or not to block SMS/MMS messaging. */
		cellularBlockMessaging?: boolean

	    /** Indicates whether or not to block voice roaming. */
		cellularBlockVoiceRoaming?: boolean

	    /** Indicates whether or not to block syncing Wi-Fi tethering. */
		cellularBlockWiFiTethering?: boolean

	    /** List of apps in the compliance (either allow list or block list, controlled by CompliantAppListType). This collection can contain a maximum of 10000 elements. */
		compliantAppsList?: AppListItem[]

	    /** Type of list that is in the CompliantAppsList. Possible values are: none, appsInListCompliant, appsNotInListCompliant. */
		compliantAppListType?: AppListType

	    /** Indicates whether or not to block diagnostic data submission. */
		diagnosticDataBlockSubmission?: boolean

	    /** Indicates whether or not to block location services. */
		locationServicesBlocked?: boolean

	    /** Indicates whether or not to block Google account auto sync. */
		googleAccountBlockAutoSync?: boolean

	    /** Indicates whether or not to block the Google Play store. */
		googlePlayStoreBlocked?: boolean

	    /** Indicates whether or not to block the screen sleep button while in Kiosk Mode. */
		kioskModeBlockSleepButton?: boolean

	    /** Indicates whether or not to block the volume buttons while in Kiosk Mode. */
		kioskModeBlockVolumeButtons?: boolean

	    /** Indicates whether or not to block changing date and time while in KNOX Mode. */
		dateAndTimeBlockChanges?: boolean

	    /** A list of apps that will be allowed to run when the device is in Kiosk Mode. This collection can contain a maximum of 500 elements. */
		kioskModeApps?: AppListItem[]

	    /** Indicates whether or not to block Near-Field Communication. */
		nfcBlocked?: boolean

	    /** Indicates whether or not to block fingerprint unlock. */
		passwordBlockFingerprintUnlock?: boolean

	    /** Indicates whether or not to block Smart Lock and other trust agents. */
		passwordBlockTrustAgents?: boolean

	    /** Number of days before the password expires. Valid values 1 to 365 */
		passwordExpirationDays?: number

	    /** Minimum length of passwords. Valid values 4 to 16 */
		passwordMinimumLength?: number

	    /** Minutes of inactivity before the screen times out. */
		passwordMinutesOfInactivityBeforeScreenTimeout?: number

	    /** Number of previous passwords to block. Valid values 0 to 24 */
		passwordPreviousPasswordBlockCount?: number

	    /** Number of sign in failures allowed before factory reset. Valid values 4 to 11 */
		passwordSignInFailureCountBeforeFactoryReset?: number

	    /** Type of password that is required. Possible values are: deviceDefault, alphabetic, alphanumeric, alphanumericWithSymbols, lowSecurityBiometric, numeric, numericComplex, any. */
		passwordRequiredType?: AndroidRequiredPasswordType

	    /** Indicates whether or not to require a password. */
		passwordRequired?: boolean

	    /** Indicates whether or not to block powering off the device. */
		powerOffBlocked?: boolean

	    /** Indicates whether or not to block user performing a factory reset. */
		factoryResetBlocked?: boolean

	    /** Indicates whether or not to block screenshots. */
		screenCaptureBlocked?: boolean

	    /** Indicates whether or not to allow device sharing mode. */
		deviceSharingAllowed?: boolean

	    /** Indicates whether or not to block Google Backup. */
		storageBlockGoogleBackup?: boolean

	    /** Indicates whether or not to block removable storage usage. */
		storageBlockRemovableStorage?: boolean

	    /** Indicates whether or not to require device encryption. */
		storageRequireDeviceEncryption?: boolean

	    /** Indicates whether or not to require removable storage encryption. */
		storageRequireRemovableStorageEncryption?: boolean

	    /** Indicates whether or not to block the use of the Voice Assistant. */
		voiceAssistantBlocked?: boolean

	    /** Indicates whether or not to block voice dialing. */
		voiceDialingBlocked?: boolean

	    /** Indicates whether or not to block popups within the web browser. */
		webBrowserBlockPopups?: boolean

	    /** Indicates whether or not to block the web browser's auto fill feature. */
		webBrowserBlockAutofill?: boolean

	    /** Indicates whether or not to block JavaScript within the web browser. */
		webBrowserBlockJavaScript?: boolean

	    /** Indicates whether or not to block the web browser. */
		webBrowserBlocked?: boolean

	    /** Cookie settings within the web browser. Possible values are: browserDefault, blockAlways, allowCurrentWebSite, allowFromWebsitesVisited, allowAlways. */
		webBrowserCookieSettings?: WebBrowserCookieSettings

	    /** Indicates whether or not to block syncing Wi-Fi. */
		wiFiBlocked?: boolean

	    /** List of apps which can be installed on the KNOX device. This collection can contain a maximum of 500 elements. */
		appsInstallAllowList?: AppListItem[]

	    /** List of apps which are blocked from being launched on the KNOX device. This collection can contain a maximum of 500 elements. */
		appsLaunchBlockList?: AppListItem[]

	    /** List of apps to be hidden on the KNOX device. This collection can contain a maximum of 500 elements. */
		appsHideList?: AppListItem[]

	    /** Require the Android Verify apps feature is turned on. */
		securityRequireVerifyApps?: boolean

}

export interface AndroidVpnConfiguration extends DeviceConfiguration {

	    /** Connection name displayed to the user. */
		connectionName?: string

	    /** Connection type. Possible values are: ciscoAnyConnect, pulseSecure, f5EdgeClient, dellSonicWallMobileConnect, checkPointCapsuleVpn, citrix. */
		connectionType?: AndroidVpnConnectionType

	    /** Role when connection type is set to Pulse Secure. */
		role?: string

	    /** Realm when connection type is set to Pulse Secure. */
		realm?: string

	    /** List of VPN Servers on the network. Make sure end users can access these network locations. This collection can contain a maximum of 500 elements. */
		servers?: VpnServer[]

	    /** Fingerprint is a string that will be used to verify the VPN server can be trusted, which is only applicable when connection type is Check Point Capsule VPN. */
		fingerprint?: string

	    /** Custom data when connection type is set to Citrix. This collection can contain a maximum of 25 elements. */
		customData?: KeyValue[]

		customKeyValueData?: KeyValuePair[]

	    /** Authentication method. Possible values are: certificate, usernameAndPassword. */
		authenticationMethod?: VpnAuthenticationMethod

	    /** Identity certificate for client authentication when authentication method is certificate. */
		identityCertificate?: AndroidCertificateProfileBase

}

export interface AndroidWiFiConfiguration extends DeviceConfiguration {

	    /** Network Name */
		networkName?: string

	    /** This is the name of the Wi-Fi network that is broadcast to all devices. */
		ssid?: string

	    /** Connect automatically when this network is in range. Setting this to true will skip the user prompt and automatically connect the device to Wi-Fi network. */
		connectAutomatically?: boolean

	    /** When set to true, this profile forces the device to connect to a network that doesn't broadcast its SSID to all devices. */
		connectWhenNetworkNameIsHidden?: boolean

	    /** Indicates whether Wi-Fi endpoint uses an EAP based security type. Possible values are: open, wpaEnterprise. */
		wiFiSecurityType?: AndroidWiFiSecurityType

}

export interface AndroidEnterpriseWiFiConfiguration extends AndroidWiFiConfiguration {

	    /** Indicates the type of EAP protocol set on the the Wi-Fi endpoint (router). Possible values are: eapTls, eapTtls, peap. */
		eapType?: AndroidEapType

	    /** Indicates the Authentication Method the client (device) needs to use when the EAP Type is configured to PEAP or EAP-TTLS. Possible values are: certificate, usernameAndPassword. */
		authenticationMethod?: WiFiAuthenticationMethod

	    /** Non-EAP Method for Authentication (Inner Identity) when EAP Type is EAP-TTLS and Authenticationmethod is Username and Password. Possible values are: unencryptedPassword, challengeHandshakeAuthenticationProtocol, microsoftChap, microsoftChapVersionTwo. */
		innerAuthenticationProtocolForEapTtls?: NonEapAuthenticationMethodForEapTtlsType

	    /** Non-EAP Method for Authentication (Inner Identity) when EAP Type is PEAP and Authenticationmethod is Username and Password. Possible values are: none, microsoftChapVersionTwo. */
		innerAuthenticationProtocolForPeap?: NonEapAuthenticationMethodForPeap

	    /** Enable identity privacy (Outer Identity) when EAP Type is configured to EAP-TTLS or PEAP. The String provided here is used to mask the username of individual users when they attempt to connect to Wi-Fi network. */
		outerIdentityPrivacyTemporaryValue?: string

	    /** Trusted Root Certificate for Server Validation when EAP Type is configured to EAP-TLS, EAP-TTLS or PEAP. This is the certificate presented by the Wi-Fi endpoint when the device attempts to connect to Wi-Fi endpoint. The device (or user) must accept this certificate to continue the connection attempt. */
		rootCertificateForServerValidation?: AndroidTrustedRootCertificate

	    /** Identity Certificate for client authentication when EAP Type is configured to EAP-TLS, EAP-TTLS (with Certificate Authentication), or PEAP (with Certificate Authentication). This is the certificate presented by client to the Wi-Fi endpoint. The authentication server sitting behind the Wi-Fi endpoint must accept this certificate to successfully establish a Wi-Fi connection. */
		identityCertificateForClientAuthentication?: AndroidCertificateProfileBase

}

export interface AndroidWorkProfileCertificateProfileBase extends DeviceConfiguration {

	    /** Certificate renewal threshold percentage. Valid values 1 to 99 */
		renewalThresholdPercentage?: number

	    /** Certificate Subject Name Format. Possible values are: commonName, commonNameIncludingEmail, commonNameAsEmail, custom, commonNameAsIMEI, commonNameAsSerialNumber, commonNameAsAadDeviceId, commonNameAsIntuneDeviceId, commonNameAsDurableDeviceId. */
		subjectNameFormat?: SubjectNameFormat

	    /** Certificate Subject Alternative Name Type. Possible values are: none, emailAddress, userPrincipalName, customAzureADAttribute. */
		subjectAlternativeNameType?: SubjectAlternativeNameType

	    /** Value for the Certificate Validity Period. */
		certificateValidityPeriodValue?: number

	    /** Scale for the Certificate Validity Period. Possible values are: days, months, years. */
		certificateValidityPeriodScale?: CertificateValidityPeriodScale

	    /** Extended Key Usage (EKU) settings. This collection can contain a maximum of 500 elements. */
		extendedKeyUsages?: ExtendedKeyUsage[]

	    /** Trusted Root Certificate. */
		rootCertificate?: AndroidWorkProfileTrustedRootCertificate

}

export interface AndroidWorkProfileTrustedRootCertificate extends DeviceConfiguration {

	    /** Trusted Root Certificate */
		trustedRootCertificate?: number

	    /** File name to display in UI. */
		certFileName?: string

}

export interface AndroidWorkProfilePkcsCertificateProfile extends AndroidWorkProfileCertificateProfileBase {

	    /** PKCS Certification Authority */
		certificationAuthority?: string

	    /** PKCS Certification Authority Name */
		certificationAuthorityName?: string

	    /** PKCS Certificate Template Name */
		certificateTemplateName?: string

	    /** Custom String that defines the AAD Attribute. */
		subjectAlternativeNameFormatString?: string

}

export interface AndroidWorkProfileScepCertificateProfile extends AndroidWorkProfileCertificateProfileBase {

	    /** SCEP Server Url(s) */
		scepServerUrls?: string[]

	    /** Custom format to use with SubjectNameFormat = Custom. Example: CN={{EmailAddress}},E={{EmailAddress}},OU=Enterprise Users,O=Contoso Corporation,L=Redmond,ST=WA,C=US */
		subjectNameFormatString?: string

	    /** SCEP Key Usage. Possible values are: keyEncipherment, digitalSignature. */
		keyUsage?: KeyUsages

	    /** SCEP Key Size. Possible values are: size1024, size2048. */
		keySize?: KeySize

	    /** SCEP Hash Algorithm. Possible values are: sha1, sha2. */
		hashAlgorithm?: HashAlgorithms

	    /** Custom String that defines the AAD Attribute. */
		subjectAlternativeNameFormatString?: string

	    /** Certificate state for devices */
		managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface AndroidWorkProfileCustomConfiguration extends DeviceConfiguration {

	    /** OMA settings. This collection can contain a maximum of 500 elements. */
		omaSettings?: OmaSetting[]

}

export interface AndroidWorkProfileEasEmailProfileBase extends DeviceConfiguration {

	    /** Authentication method for Exchange ActiveSync. Possible values are: usernameAndPassword, certificate. */
		authenticationMethod?: EasAuthenticationMethod

	    /** Duration of time email should be synced to. Possible values are: userDefined, oneDay, threeDays, oneWeek, twoWeeks, oneMonth, unlimited. */
		durationOfEmailToSync?: EmailSyncDuration

	    /** Email attribute that is picked from AAD and injected into this profile before installing on the device. Possible values are: userPrincipalName, primarySmtpAddress. */
		emailAddressSource?: UserEmailSource

	    /** Exchange location (URL) that the mail app connects to. */
		hostName?: string

	    /** Indicates whether or not to use SSL. */
		requireSsl?: boolean

	    /** Username attribute that is picked from AAD and injected into this profile before installing on the device. Possible values are: username, userPrincipalName, samAccountName, primarySmtpAddress. */
		usernameSource?: AndroidUsernameSource

	    /** Identity certificate. */
		identityCertificate?: AndroidWorkProfileCertificateProfileBase

}

export interface AndroidWorkProfileGmailEasConfiguration extends AndroidWorkProfileEasEmailProfileBase {

}

export interface AndroidWorkProfileNineWorkEasConfiguration extends AndroidWorkProfileEasEmailProfileBase {

	    /** Toggles syncing the calendar. If set to false the calendar is turned off on the device. */
		syncCalendar?: boolean

	    /** Toggles syncing contacts. If set to false contacts are turned off on the device. */
		syncContacts?: boolean

	    /** Toggles syncing tasks. If set to false tasks are turned off on the device. */
		syncTasks?: boolean

}

export interface AndroidWorkProfileGeneralDeviceConfiguration extends DeviceConfiguration {

	    /** Indicates whether or not to block fingerprint unlock. */
		passwordBlockFingerprintUnlock?: boolean

	    /** Indicates whether or not to block Smart Lock and other trust agents. */
		passwordBlockTrustAgents?: boolean

	    /** Number of days before the password expires. Valid values 1 to 365 */
		passwordExpirationDays?: number

	    /** Minimum length of passwords. Valid values 4 to 16 */
		passwordMinimumLength?: number

	    /** Minutes of inactivity before the screen times out. */
		passwordMinutesOfInactivityBeforeScreenTimeout?: number

	    /** Number of previous passwords to block. Valid values 0 to 24 */
		passwordPreviousPasswordBlockCount?: number

	    /** Number of sign in failures allowed before factory reset. Valid values 4 to 11 */
		passwordSignInFailureCountBeforeFactoryReset?: number

	    /** Type of password that is required. Possible values are: deviceDefault, lowSecurityBiometric, required, atLeastNumeric, numericComplex, atLeastAlphabetic, atLeastAlphanumeric, alphanumericWithSymbols. */
		passwordRequiredType?: AndroidWorkProfileRequiredPasswordType

	    /** Type of data sharing that is allowed. Possible values are: deviceDefault, preventAny, allowPersonalToWork, noRestrictions. */
		workProfileDataSharingType?: AndroidWorkProfileCrossProfileDataSharingType

	    /** Indicates whether or not to block notifications while device locked. */
		workProfileBlockNotificationsWhileDeviceLocked?: boolean

	    /** Block users from adding/removing accounts in work profile. */
		workProfileBlockAddingAccounts?: boolean

	    /** Allow bluetooth devices to access enterprise contacts. */
		workProfileBluetoothEnableContactSharing?: boolean

	    /** Block screen capture in work profile. */
		workProfileBlockScreenCapture?: boolean

	    /** Block display work profile caller ID in personal profile. */
		workProfileBlockCrossProfileCallerId?: boolean

	    /** Block work profile camera. */
		workProfileBlockCamera?: boolean

	    /** Block work profile contacts availability in personal profile. */
		workProfileBlockCrossProfileContactsSearch?: boolean

	    /** Boolean that indicates if the setting disallow cross profile copy/paste is enabled. */
		workProfileBlockCrossProfileCopyPaste?: boolean

	    /** Type of password that is required. Possible values are: deviceDefault, prompt, autoGrant, autoDeny. */
		workProfileDefaultAppPermissionPolicy?: AndroidWorkProfileDefaultAppPermissionPolicyType

	    /** Indicates whether or not to block fingerprint unlock for work profile. */
		workProfilePasswordBlockFingerprintUnlock?: boolean

	    /** Indicates whether or not to block Smart Lock and other trust agents for work profile. */
		workProfilePasswordBlockTrustAgents?: boolean

	    /** Number of days before the work profile password expires. Valid values 1 to 365 */
		workProfilePasswordExpirationDays?: number

	    /** Minimum length of work profile password. Valid values 4 to 16 */
		workProfilePasswordMinimumLength?: number

		workProfilePasswordMinNumericCharacters?: number

		workProfilePasswordMinNonLetterCharacters?: number

		workProfilePasswordMinLetterCharacters?: number

		workProfilePasswordMinLowerCaseCharacters?: number

		workProfilePasswordMinUpperCaseCharacters?: number

		workProfilePasswordMinSymbolCharacters?: number

	    /** Minutes of inactivity before the screen times out. */
		workProfilePasswordMinutesOfInactivityBeforeScreenTimeout?: number

	    /** Number of previous work profile passwords to block. Valid values 0 to 24 */
		workProfilePasswordPreviousPasswordBlockCount?: number

	    /** Number of sign in failures allowed before work profile is removed and all corporate data deleted. Valid values 4 to 11 */
		workProfilePasswordSignInFailureCountBeforeFactoryReset?: number

	    /** Type of work profile password that is required. Possible values are: deviceDefault, lowSecurityBiometric, required, atLeastNumeric, numericComplex, atLeastAlphabetic, atLeastAlphanumeric, alphanumericWithSymbols. */
		workProfilePasswordRequiredType?: AndroidWorkProfileRequiredPasswordType

	    /** Password is required or not for work profile */
		workProfileRequirePassword?: boolean

	    /** Require the Android Verify apps feature is turned on. */
		securityRequireVerifyApps?: boolean

		vpnAlwaysOnPackageIdentifier?: string

		vpnEnableAlwaysOnLockdownMode?: boolean

}

export interface AndroidWorkProfileVpnConfiguration extends DeviceConfiguration {

	    /** Connection name displayed to the user. */
		connectionName?: string

	    /** Connection type. Possible values are: ciscoAnyConnect, pulseSecure, f5EdgeClient, dellSonicWallMobileConnect, checkPointCapsuleVpn, citrix. */
		connectionType?: AndroidWorkProfileVpnConnectionType

	    /** Role when connection type is set to Pulse Secure. */
		role?: string

	    /** Realm when connection type is set to Pulse Secure. */
		realm?: string

	    /** List of VPN Servers on the network. Make sure end users can access these network locations. This collection can contain a maximum of 500 elements. */
		servers?: VpnServer[]

	    /** Fingerprint is a string that will be used to verify the VPN server can be trusted, which is only applicable when connection type is Check Point Capsule VPN. */
		fingerprint?: string

	    /** Custom data when connection type is set to Citrix. This collection can contain a maximum of 25 elements. */
		customData?: KeyValue[]

		customKeyValueData?: KeyValuePair[]

	    /** Authentication method. Possible values are: certificate, usernameAndPassword. */
		authenticationMethod?: VpnAuthenticationMethod

	    /** Identity certificate for client authentication when authentication method is certificate. */
		identityCertificate?: AndroidWorkProfileCertificateProfileBase

}

export interface AndroidWorkProfileWiFiConfiguration extends DeviceConfiguration {

	    /** Network Name */
		networkName?: string

	    /** This is the name of the Wi-Fi network that is broadcast to all devices. */
		ssid?: string

	    /** Connect automatically when this network is in range. Setting this to true will skip the user prompt and automatically connect the device to Wi-Fi network. */
		connectAutomatically?: boolean

	    /** When set to true, this profile forces the device to connect to a network that doesn't broadcast its SSID to all devices. */
		connectWhenNetworkNameIsHidden?: boolean

	    /** Indicates whether Wi-Fi endpoint uses an EAP based security type. Possible values are: open, wpaEnterprise. */
		wiFiSecurityType?: AndroidWiFiSecurityType

}

export interface AndroidWorkProfileEnterpriseWiFiConfiguration extends AndroidWorkProfileWiFiConfiguration {

	    /** Indicates the type of EAP protocol set on the the Wi-Fi endpoint (router). Possible values are: eapTls, eapTtls, peap. */
		eapType?: AndroidEapType

	    /** Indicates the Authentication Method the client (device) needs to use when the EAP Type is configured to PEAP or EAP-TTLS. Possible values are: certificate, usernameAndPassword. */
		authenticationMethod?: WiFiAuthenticationMethod

	    /** Non-EAP Method for Authentication (Inner Identity) when EAP Type is EAP-TTLS and Authenticationmethod is Username and Password. Possible values are: unencryptedPassword, challengeHandshakeAuthenticationProtocol, microsoftChap, microsoftChapVersionTwo. */
		innerAuthenticationProtocolForEapTtls?: NonEapAuthenticationMethodForEapTtlsType

	    /** Non-EAP Method for Authentication (Inner Identity) when EAP Type is PEAP and Authenticationmethod is Username and Password. Possible values are: none, microsoftChapVersionTwo. */
		innerAuthenticationProtocolForPeap?: NonEapAuthenticationMethodForPeap

	    /** Enable identity privacy (Outer Identity) when EAP Type is configured to EAP-TTLS or PEAP. The String provided here is used to mask the username of individual users when they attempt to connect to Wi-Fi network. */
		outerIdentityPrivacyTemporaryValue?: string

	    /** Trusted Root Certificate for Server Validation when EAP Type is configured to EAP-TLS, EAP-TTLS or PEAP. This is the certificate presented by the Wi-Fi endpoint when the device attempts to connect to Wi-Fi endpoint. The device (or user) must accept this certificate to continue the connection attempt. */
		rootCertificateForServerValidation?: AndroidWorkProfileTrustedRootCertificate

	    /** Identity Certificate for client authentication when EAP Type is configured to EAP-TLS, EAP-TTLS (with Certificate Authentication), or PEAP (with Certificate Authentication). This is the certificate presented by client to the Wi-Fi endpoint. The authentication server sitting behind the Wi-Fi endpoint must accept this certificate to successfully establish a Wi-Fi connection. */
		identityCertificateForClientAuthentication?: AndroidWorkProfileCertificateProfileBase

}

export interface IosCertificateProfile extends DeviceConfiguration {

}

export interface IosCertificateProfileBase extends IosCertificateProfile {

	    /** Certificate renewal threshold percentage. Valid values 1 to 99 */
		renewalThresholdPercentage?: number

	    /** Certificate Subject Name Format. Possible values are: commonName, commonNameAsEmail, custom, commonNameIncludingEmail, commonNameAsIMEI, commonNameAsSerialNumber. */
		subjectNameFormat?: AppleSubjectNameFormat

	    /** Certificate Subject Alternative Name type. Possible values are: none, emailAddress, userPrincipalName, customAzureADAttribute. */
		subjectAlternativeNameType?: SubjectAlternativeNameType

	    /** Value for the Certificate Validity Period. */
		certificateValidityPeriodValue?: number

	    /** Scale for the Certificate Validity Period. Possible values are: days, months, years. */
		certificateValidityPeriodScale?: CertificateValidityPeriodScale

}

export interface IosPkcsCertificateProfile extends IosCertificateProfileBase {

	    /** PKCS Certification Authority. */
		certificationAuthority?: string

	    /** PKCS Certification Authority Name. */
		certificationAuthorityName?: string

	    /** PKCS Certificate Template Name. */
		certificateTemplateName?: string

	    /** Custom String that defines the AAD Attribute. */
		subjectAlternativeNameFormatString?: string

		managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface IosScepCertificateProfile extends IosCertificateProfileBase {

	    /** SCEP Server Url(s). */
		scepServerUrls?: string[]

	    /** Custom format to use with SubjectNameFormat = Custom. Example: CN={{EmailAddress}},E={{EmailAddress}},OU=Enterprise Users,O=Contoso Corporation,L=Redmond,ST=WA,C=US */
		subjectNameFormatString?: string

	    /** SCEP Key Usage. Possible values are: keyEncipherment, digitalSignature. */
		keyUsage?: KeyUsages

	    /** SCEP Key Size. Possible values are: size1024, size2048. */
		keySize?: KeySize

	    /** Extended Key Usage (EKU) settings. This collection can contain a maximum of 500 elements. */
		extendedKeyUsages?: ExtendedKeyUsage[]

	    /** Custom String that defines the AAD Attribute. */
		subjectAlternativeNameFormatString?: string

		certificateStore?: CertificateStore

		customSubjectAlternativeNames?: CustomSubjectAlternativeName[]

	    /** Trusted Root Certificate. */
		rootCertificate?: IosTrustedRootCertificate

	    /** Certificate state for devices */
		managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface IosTrustedRootCertificate extends DeviceConfiguration {

	    /** Trusted Root Certificate. */
		trustedRootCertificate?: number

	    /** File name to display in UI. */
		certFileName?: string

}

export interface IosImportedPFXCertificateProfile extends IosCertificateProfile {

	    /** Not yet documented. Possible values are: unassigned, smimeEncryption, smimeSigning, vpn, wifi. */
		intendedPurpose?: IntendedPurpose

		managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface IosCustomConfiguration extends DeviceConfiguration {

	    /** Name that is displayed to the user. */
		payloadName?: string

	    /** Payload file name (.mobileconfig */
		payloadFileName?: string

	    /** Payload. (UTF8 encoded byte array) */
		payload?: number

}

export interface IosEduDeviceConfiguration extends DeviceConfiguration {

	    /** The Trusted Root and PFX certificates for Teacher */
		teacherCertificateSettings?: IosEduCertificateSettings

	    /** The Trusted Root and PFX certificates for Student */
		studentCertificateSettings?: IosEduCertificateSettings

	    /** The Trusted Root and PFX certificates for Device */
		deviceCertificateSettings?: IosEduCertificateSettings

}

export interface IosEducationDeviceConfiguration extends DeviceConfiguration {

}

export interface IosGeneralDeviceConfiguration extends DeviceConfiguration {

	    /** Indicates whether or not to allow account modification when the device is in supervised mode. */
		accountBlockModification?: boolean

	    /** Indicates whether or not to allow activation lock when the device is in the supervised mode. */
		activationLockAllowWhenSupervised?: boolean

	    /** Indicates whether or not to allow AirDrop when the device is in supervised mode. */
		airDropBlocked?: boolean

	    /** Indicates whether or not to cause AirDrop to be considered an unmanaged drop target (iOS 9.0 and later). */
		airDropForceUnmanagedDropTarget?: boolean

	    /** Indicates whether or not to enforce all devices receiving AirPlay requests from this device to use a pairing password. */
		airPlayForcePairingPasswordForOutgoingRequests?: boolean

	    /** Indicates whether or not to allow Apple Watch pairing when the device is in supervised mode (iOS 9.0 and later). */
		appleWatchBlockPairing?: boolean

	    /** Indicates whether or not to force a paired Apple Watch to use Wrist Detection (iOS 8.2 and later). */
		appleWatchForceWristDetection?: boolean

	    /** Indicates whether or not to block the user from using News when the device is in supervised mode (iOS 9.0 and later). */
		appleNewsBlocked?: boolean

	    /** Gets or sets the list of iOS apps allowed to autonomously enter Single App Mode. Supervised only. iOS 7.0 and later. This collection can contain a maximum of 500 elements. */
		appsSingleAppModeList?: AppListItem[]

	    /** List of apps in the visibility list (either visible/launchable apps list or hidden/unlaunchable apps list, controlled by AppsVisibilityListType) (iOS 9.3 and later). This collection can contain a maximum of 10000 elements. */
		appsVisibilityList?: AppListItem[]

	    /** Type of list that is in the AppsVisibilityList. Possible values are: none, appsInListCompliant, appsNotInListCompliant. */
		appsVisibilityListType?: AppListType

	    /** Indicates whether or not to block the automatic downloading of apps purchased on other devices when the device is in supervised mode (iOS 9.0 and later). */
		appStoreBlockAutomaticDownloads?: boolean

	    /** Indicates whether or not to block the user from using the App Store. */
		appStoreBlocked?: boolean

	    /** Indicates whether or not to block the user from making in app purchases. */
		appStoreBlockInAppPurchases?: boolean

	    /** Indicates whether or not to block the App Store app, not restricting installation through Host apps. Applies to supervised mode only (iOS 9.0 and later). */
		appStoreBlockUIAppInstallation?: boolean

	    /** Indicates whether or not to require a password when using the app store. */
		appStoreRequirePassword?: boolean

	    /** Indicates whether or not to allow modification of Bluetooth settings when the device is in supervised mode (iOS 10.0 and later). */
		bluetoothBlockModification?: boolean

	    /** Indicates whether or not to block the user from accessing the camera of the device. */
		cameraBlocked?: boolean

	    /** Indicates whether or not to block data roaming. */
		cellularBlockDataRoaming?: boolean

	    /** Indicates whether or not to block global background fetch while roaming. */
		cellularBlockGlobalBackgroundFetchWhileRoaming?: boolean

	    /** Indicates whether or not to allow changes to cellular app data usage settings when the device is in supervised mode. */
		cellularBlockPerAppDataModification?: boolean

	    /** Indicates whether or not to block Personal Hotspot. */
		cellularBlockPersonalHotspot?: boolean

	    /** Indicates whether or not to block voice roaming. */
		cellularBlockVoiceRoaming?: boolean

	    /** Indicates whether or not to block untrusted TLS certificates. */
		certificatesBlockUntrustedTlsCertificates?: boolean

	    /** Indicates whether or not to allow remote screen observation by Classroom app when the device is in supervised mode (iOS 9.3 and later). */
		classroomAppBlockRemoteScreenObservation?: boolean

	    /** Indicates whether or not to automatically give permission to the teacher of a managed course on the Classroom app to view a student's screen without prompting when the device is in supervised mode. */
		classroomAppForceUnpromptedScreenObservation?: boolean

	    /** List of apps in the compliance (either allow list or block list, controlled by CompliantAppListType). This collection can contain a maximum of 10000 elements. */
		compliantAppsList?: AppListItem[]

	    /** List that is in the AppComplianceList. Possible values are: none, appsInListCompliant, appsNotInListCompliant. */
		compliantAppListType?: AppListType

	    /** Indicates whether or not to block the user from installing configuration profiles and certificates interactively when the device is in supervised mode. */
		configurationProfileBlockChanges?: boolean

	    /** Indicates whether or not to block definition lookup when the device is in supervised mode (iOS 8.1.3 and later ). */
		definitionLookupBlocked?: boolean

	    /** Indicates whether or not to allow the user to enables restrictions in the device settings when the device is in supervised mode. */
		deviceBlockEnableRestrictions?: boolean

	    /** Indicates whether or not to allow the use of the 'Erase all content and settings' option on the device when the device is in supervised mode. */
		deviceBlockEraseContentAndSettings?: boolean

	    /** Indicates whether or not to allow device name modification when the device is in supervised mode (iOS 9.0 and later). */
		deviceBlockNameModification?: boolean

	    /** Indicates whether or not to block diagnostic data submission. */
		diagnosticDataBlockSubmission?: boolean

	    /** Indicates whether or not to allow diagnostics submission settings modification when the device is in supervised mode (iOS 9.3.2 and later). */
		diagnosticDataBlockSubmissionModification?: boolean

	    /** Indicates whether or not to block the user from viewing managed documents in unmanaged apps. */
		documentsBlockManagedDocumentsInUnmanagedApps?: boolean

	    /** Indicates whether or not to block the user from viewing unmanaged documents in managed apps. */
		documentsBlockUnmanagedDocumentsInManagedApps?: boolean

	    /** An email address lacking a suffix that matches any of these strings will be considered out-of-domain. */
		emailInDomainSuffixes?: string[]

	    /** Indicates whether or not to block the user from trusting an enterprise app. */
		enterpriseAppBlockTrust?: boolean

	    /** Indicates whether or not to block the user from modifying the enterprise app trust settings. */
		enterpriseAppBlockTrustModification?: boolean

	    /** Indicates whether or not to block the user from using FaceTime. */
		faceTimeBlocked?: boolean

	    /** Indicates whether or not to block Find My Friends when the device is in supervised mode. */
		findMyFriendsBlocked?: boolean

	    /** Indicates whether or not to block the user from having friends in Game Center. */
		gamingBlockGameCenterFriends?: boolean

	    /** Indicates whether or not to block the user from using multiplayer gaming. */
		gamingBlockMultiplayer?: boolean

	    /** Indicates whether or not to block the user from using Game Center when the device is in supervised mode. */
		gameCenterBlocked?: boolean

	    /** indicates whether or not to allow host pairing to control the devices an iOS device can pair with when the iOS device is in supervised mode. */
		hostPairingBlocked?: boolean

	    /** Indicates whether or not to block the user from using the iBooks Store when the device is in supervised mode. */
		iBooksStoreBlocked?: boolean

	    /** Indicates whether or not to block the user from downloading media from the iBookstore that has been tagged as erotica. */
		iBooksStoreBlockErotica?: boolean

	    /** Indicates whether or not to block  the the user from continuing work they started on iOS device to another iOS or macOS device. */
		iCloudBlockActivityContinuation?: boolean

	    /** Indicates whether or not to block iCloud backup. */
		iCloudBlockBackup?: boolean

	    /** Indicates whether or not to block iCloud document sync. */
		iCloudBlockDocumentSync?: boolean

	    /** Indicates whether or not to block Managed Apps Cloud Sync. */
		iCloudBlockManagedAppsSync?: boolean

	    /** Indicates whether or not to block iCloud Photo Library. */
		iCloudBlockPhotoLibrary?: boolean

	    /** Indicates whether or not to block iCloud Photo Stream Sync. */
		iCloudBlockPhotoStreamSync?: boolean

	    /** Indicates whether or not to block Shared Photo Stream. */
		iCloudBlockSharedPhotoStream?: boolean

	    /** Indicates whether or not to require backups to iCloud be encrypted. */
		iCloudRequireEncryptedBackup?: boolean

	    /** Indicates whether or not to block the user from accessing explicit content in iTunes and the App Store. */
		iTunesBlockExplicitContent?: boolean

	    /** Indicates whether or not to block Music service and revert Music app to classic mode when the device is in supervised mode (iOS 9.3 and later and macOS 10.12 and later). */
		iTunesBlockMusicService?: boolean

	    /** Indicates whether or not to block the user from using iTunes Radio when the device is in supervised mode (iOS 9.3 and later). */
		iTunesBlockRadio?: boolean

	    /** Indicates whether or not to block keyboard auto-correction when the device is in supervised mode (iOS 8.1.3 and later). */
		keyboardBlockAutoCorrect?: boolean

	    /** Indicates whether or not to block the user from using dictation input when the device is in supervised mode. */
		keyboardBlockDictation?: boolean

	    /** Indicates whether or not to block predictive keyboards when device is in supervised mode (iOS 8.1.3 and later). */
		keyboardBlockPredictive?: boolean

	    /** Indicates whether or not to block keyboard shortcuts when the device is in supervised mode (iOS 9.0 and later). */
		keyboardBlockShortcuts?: boolean

	    /** Indicates whether or not to block keyboard spell-checking when the device is in supervised mode (iOS 8.1.3 and later). */
		keyboardBlockSpellCheck?: boolean

	    /** Indicates whether or not to allow assistive speak while in kiosk mode. */
		kioskModeAllowAssistiveSpeak?: boolean

	    /** Indicates whether or not to allow access to the Assistive Touch Settings while in kiosk mode. */
		kioskModeAllowAssistiveTouchSettings?: boolean

	    /** Indicates whether or not to allow device auto lock while in kiosk mode. */
		kioskModeAllowAutoLock?: boolean

	    /** Indicates whether or not to allow access to the Color Inversion Settings while in kiosk mode. */
		kioskModeAllowColorInversionSettings?: boolean

	    /** Indicates whether or not to allow use of the ringer switch while in kiosk mode. */
		kioskModeAllowRingerSwitch?: boolean

	    /** Indicates whether or not to allow screen rotation while in kiosk mode. */
		kioskModeAllowScreenRotation?: boolean

	    /** Indicates whether or not to allow use of the sleep button while in kiosk mode. */
		kioskModeAllowSleepButton?: boolean

	    /** Indicates whether or not to allow use of the touchscreen while in kiosk mode. */
		kioskModeAllowTouchscreen?: boolean

	    /** Indicates whether or not to allow access to the voice over settings while in kiosk mode. */
		kioskModeAllowVoiceOverSettings?: boolean

	    /** Indicates whether or not to allow use of the volume buttons while in kiosk mode. */
		kioskModeAllowVolumeButtons?: boolean

	    /** Indicates whether or not to allow access to the zoom settings while in kiosk mode. */
		kioskModeAllowZoomSettings?: boolean

	    /** URL in the app store to the app to use for kiosk mode. Use if KioskModeManagedAppId is not known. */
		kioskModeAppStoreUrl?: string

		kioskModeBuiltInAppId?: string

	    /** Indicates whether or not to require assistive touch while in kiosk mode. */
		kioskModeRequireAssistiveTouch?: boolean

	    /** Indicates whether or not to require color inversion while in kiosk mode. */
		kioskModeRequireColorInversion?: boolean

	    /** Indicates whether or not to require mono audio while in kiosk mode. */
		kioskModeRequireMonoAudio?: boolean

	    /** Indicates whether or not to require voice over while in kiosk mode. */
		kioskModeRequireVoiceOver?: boolean

	    /** Indicates whether or not to require zoom while in kiosk mode. */
		kioskModeRequireZoom?: boolean

	    /** Managed app id of the app to use for kiosk mode. If KioskModeManagedAppId is specified then KioskModeAppStoreUrl will be ignored. */
		kioskModeManagedAppId?: string

	    /** Indicates whether or not to block the user from using control center on the lock screen. */
		lockScreenBlockControlCenter?: boolean

	    /** Indicates whether or not to block the user from using the notification view on the lock screen. */
		lockScreenBlockNotificationView?: boolean

	    /** Indicates whether or not to block the user from using passbook when the device is locked. */
		lockScreenBlockPassbook?: boolean

	    /** Indicates whether or not to block the user from using the Today View on the lock screen. */
		lockScreenBlockTodayView?: boolean

	    /** Media content rating settings for Australia */
		mediaContentRatingAustralia?: MediaContentRatingAustralia

	    /** Media content rating settings for Canada */
		mediaContentRatingCanada?: MediaContentRatingCanada

	    /** Media content rating settings for France */
		mediaContentRatingFrance?: MediaContentRatingFrance

	    /** Media content rating settings for Germany */
		mediaContentRatingGermany?: MediaContentRatingGermany

	    /** Media content rating settings for Ireland */
		mediaContentRatingIreland?: MediaContentRatingIreland

	    /** Media content rating settings for Japan */
		mediaContentRatingJapan?: MediaContentRatingJapan

	    /** Media content rating settings for New Zealand */
		mediaContentRatingNewZealand?: MediaContentRatingNewZealand

	    /** Media content rating settings for United Kingdom */
		mediaContentRatingUnitedKingdom?: MediaContentRatingUnitedKingdom

	    /** Media content rating settings for United States */
		mediaContentRatingUnitedStates?: MediaContentRatingUnitedStates

	    /** List of managed apps and the network rules that applies to them. This collection can contain a maximum of 1000 elements. */
		networkUsageRules?: IosNetworkUsageRule[]

	    /** Media content rating settings for Apps. Possible values are: allAllowed, allBlocked, agesAbove4, agesAbove9, agesAbove12, agesAbove17. */
		mediaContentRatingApps?: RatingAppsType

	    /** Indicates whether or not to block the user from using the Messages app on the supervised device. */
		messagesBlocked?: boolean

	    /** Indicates whether or not to allow notifications settings modification (iOS 9.3 and later). */
		notificationsBlockSettingsModification?: boolean

	    /** Indicates whether or not to block fingerprint unlock. */
		passcodeBlockFingerprintUnlock?: boolean

	    /** Block modification of registered Touch ID fingerprints when in supervised mode. */
		passcodeBlockFingerprintModification?: boolean

	    /** Indicates whether or not to allow passcode modification on the supervised device (iOS 9.0 and later). */
		passcodeBlockModification?: boolean

	    /** Indicates whether or not to block simple passcodes. */
		passcodeBlockSimple?: boolean

	    /** Number of days before the passcode expires. Valid values 1 to 65535 */
		passcodeExpirationDays?: number

	    /** Minimum length of passcode. Valid values 4 to 14 */
		passcodeMinimumLength?: number

	    /** Minutes of inactivity before a passcode is required. */
		passcodeMinutesOfInactivityBeforeLock?: number

	    /** Minutes of inactivity before the screen times out. */
		passcodeMinutesOfInactivityBeforeScreenTimeout?: number

	    /** Number of character sets a passcode must contain. Valid values 0 to 4 */
		passcodeMinimumCharacterSetCount?: number

	    /** Number of previous passcodes to block. Valid values 1 to 24 */
		passcodePreviousPasscodeBlockCount?: number

	    /** Number of sign in failures allowed before wiping the device. Valid values 4 to 11 */
		passcodeSignInFailureCountBeforeWipe?: number

	    /** Type of passcode that is required. Possible values are: deviceDefault, alphanumeric, numeric. */
		passcodeRequiredType?: RequiredPasswordType

	    /** Indicates whether or not to require a passcode. */
		passcodeRequired?: boolean

	    /** Indicates whether or not to block the user from using podcasts on the supervised device (iOS 8.0 and later). */
		podcastsBlocked?: boolean

	    /** Indicates whether or not to block the user from using Auto fill in Safari. */
		safariBlockAutofill?: boolean

	    /** Indicates whether or not to block JavaScript in Safari. */
		safariBlockJavaScript?: boolean

	    /** Indicates whether or not to block popups in Safari. */
		safariBlockPopups?: boolean

	    /** Indicates whether or not to block the user from using Safari. */
		safariBlocked?: boolean

	    /** Cookie settings for Safari. Possible values are: browserDefault, blockAlways, allowCurrentWebSite, allowFromWebsitesVisited, allowAlways. */
		safariCookieSettings?: WebBrowserCookieSettings

	    /** URLs matching the patterns listed here will be considered managed. */
		safariManagedDomains?: string[]

	    /** Users can save passwords in Safari only from URLs matching the patterns listed here. Applies to devices in supervised mode (iOS 9.3 and later). */
		safariPasswordAutoFillDomains?: string[]

	    /** Indicates whether or not to require fraud warning in Safari. */
		safariRequireFraudWarning?: boolean

	    /** Indicates whether or not to block the user from taking Screenshots. */
		screenCaptureBlocked?: boolean

	    /** Indicates whether or not to block the user from using Siri. */
		siriBlocked?: boolean

	    /** Indicates whether or not to block the user from using Siri when locked. */
		siriBlockedWhenLocked?: boolean

	    /** Indicates whether or not to block Siri from querying user-generated content when used on a supervised device. */
		siriBlockUserGeneratedContent?: boolean

	    /** Indicates whether or not to prevent Siri from dictating, or speaking profane language on supervised device. */
		siriRequireProfanityFilter?: boolean

	    /** Indicates whether or not to block Spotlight search from returning internet results on supervised device. */
		spotlightBlockInternetResults?: boolean

	    /** Indicates whether or not to block voice dialing. */
		voiceDialingBlocked?: boolean

	    /** Indicates whether or not to allow wallpaper modification on supervised device (iOS 9.0 and later) . */
		wallpaperBlockModification?: boolean

	    /** Indicates whether or not to force the device to use only Wi-Fi networks from configuration profiles when the device is in supervised mode. */
		wiFiConnectOnlyToConfiguredNetworks?: boolean

}

export interface IosUpdateConfiguration extends DeviceConfiguration {

	    /** Is setting enabled in UI */
		isEnabled?: boolean

	    /** Active Hours Start (active hours mean the time window when updates install should not happen) */
		activeHoursStart?: string

	    /** Active Hours End (active hours mean the time window when updates install should not happen) */
		activeHoursEnd?: string

	    /** Days in week for which active hours are configured. This collection can contain a maximum of 7 elements. */
		scheduledInstallDays?: DayOfWeek[]

	    /** UTC Time Offset indicated in minutes */
		utcTimeOffsetInMinutes?: number

		enforcedSoftwareUpdateDelayInDays?: number

}

export interface IosWiFiConfiguration extends DeviceConfiguration {

	    /** Network Name */
		networkName?: string

	    /** This is the name of the Wi-Fi network that is broadcast to all devices. */
		ssid?: string

	    /** Connect automatically when this network is in range. Setting this to true will skip the user prompt and automatically connect the device to Wi-Fi network. */
		connectAutomatically?: boolean

	    /** Connect when the network is not broadcasting its name (SSID). When set to true, this profile forces the device to connect to a network that doesn't broadcast its SSID to all devices. */
		connectWhenNetworkNameIsHidden?: boolean

	    /** Indicates whether Wi-Fi endpoint uses an EAP based security type. Possible values are: open, wpaPersonal, wpaEnterprise, wep. */
		wiFiSecurityType?: WiFiSecurityType

	    /** Proxy Type for this Wi-Fi connection. Possible values are: none, manual, automatic. */
		proxySettings?: WiFiProxySetting

	    /** IP Address or DNS hostname of the proxy server when manual configuration is selected. */
		proxyManualAddress?: string

	    /** Port of the proxy server when manual configuration is selected. */
		proxyManualPort?: number

	    /** URL of the proxy server automatic configuration script when automatic configuration is selected. This URL is typically the location of PAC (Proxy Auto Configuration) file. */
		proxyAutomaticConfigurationUrl?: string

	    /** This is the pre-shared key for WPA Personal Wi-Fi network. */
		preSharedKey?: string

}

export interface IosEnterpriseWiFiConfiguration extends IosWiFiConfiguration {

	    /** Extensible Authentication Protocol (EAP). Indicates the type of EAP protocol set on the the Wi-Fi endpoint (router). Possible values are: eapTls, leap, eapSim, eapTtls, peap, eapFast. */
		eapType?: EapType

	    /** EAP-FAST Configuration Option when EAP-FAST is the selected EAP Type. Possible values are: noProtectedAccessCredential, useProtectedAccessCredential, useProtectedAccessCredentialAndProvision, useProtectedAccessCredentialAndProvisionAnonymously. */
		eapFastConfiguration?: EapFastConfiguration

	    /** Trusted server certificate names when EAP Type is configured to EAP-TLS/TTLS/FAST or PEAP. This is the common name used in the certificates issued by your trusted certificate authority (CA). If you provide this information, you can bypass the dynamic trust dialog that is displayed on end users' devices when they connect to this Wi-Fi network. */
		trustedServerCertificateNames?: string[]

	    /** Authentication Method when EAP Type is configured to PEAP or EAP-TTLS. Possible values are: certificate, usernameAndPassword. */
		authenticationMethod?: WiFiAuthenticationMethod

	    /** Non-EAP Method for Authentication when EAP Type is EAP-TTLS and Authenticationmethod is Username and Password. Possible values are: unencryptedPassword, challengeHandshakeAuthenticationProtocol, microsoftChap, microsoftChapVersionTwo. */
		innerAuthenticationProtocolForEapTtls?: NonEapAuthenticationMethodForEapTtlsType

	    /** Enable identity privacy (Outer Identity) when EAP Type is configured to EAP - TTLS, EAP - FAST or PEAP. This property masks usernames with the text you enter. For example, if you use 'anonymous', each user that authenticates with this Wi-Fi connection using their real username is displayed as 'anonymous'. */
		outerIdentityPrivacyTemporaryValue?: string

	    /** Trusted Root Certificates for Server Validation when EAP Type is configured to EAP-TLS/TTLS/FAST or PEAP. If you provide this value you do not need to provide trustedServerCertificateNames, and vice versa. */
		rootCertificatesForServerValidation?: IosTrustedRootCertificate[]

	    /** Identity Certificate for client authentication when EAP Type is configured to EAP-TLS, EAP-TTLS (with Certificate Authentication), or PEAP (with Certificate Authentication). */
		identityCertificateForClientAuthentication?: IosCertificateProfileBase

}

export interface MacOSCertificateProfileBase extends DeviceConfiguration {

	    /** Certificate renewal threshold percentage. */
		renewalThresholdPercentage?: number

	    /** Certificate Subject Name Format. Possible values are: commonName, commonNameAsEmail, custom, commonNameIncludingEmail, commonNameAsIMEI, commonNameAsSerialNumber. */
		subjectNameFormat?: AppleSubjectNameFormat

	    /** Certificate Subject Alternative Name Type. Possible values are: none, emailAddress, userPrincipalName, customAzureADAttribute. */
		subjectAlternativeNameType?: SubjectAlternativeNameType

	    /** Value for the Certificate Validity Period. */
		certificateValidityPeriodValue?: number

	    /** Scale for the Certificate Validity Period. Possible values are: days, months, years. */
		certificateValidityPeriodScale?: CertificateValidityPeriodScale

}

export interface MacOSImportedPFXCertificateProfile extends MacOSCertificateProfileBase {

	    /** Not yet documented. Possible values are: unassigned, smimeEncryption, smimeSigning, vpn, wifi. */
		intendedPurpose?: IntendedPurpose

		managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface MacOSScepCertificateProfile extends MacOSCertificateProfileBase {

	    /** SCEP Server Url(s). */
		scepServerUrls?: string[]

	    /** Custom format to use with SubjectNameFormat = Custom. Example: CN={{EmailAddress}},E={{EmailAddress}},OU=Enterprise Users,O=Contoso Corporation,L=Redmond,ST=WA,C=US */
		subjectNameFormatString?: string

	    /** SCEP Key Usage. Possible values are: keyEncipherment, digitalSignature. */
		keyUsage?: KeyUsages

	    /** SCEP Key Size. Possible values are: size1024, size2048. */
		keySize?: KeySize

	    /** SCEP Hash Algorithm. Possible values are: sha1, sha2. */
		hashAlgorithm?: HashAlgorithms

	    /** Extended Key Usage (EKU) settings. This collection can contain a maximum of 500 elements. */
		extendedKeyUsages?: ExtendedKeyUsage[]

	    /** Custom String that defines the AAD Attribute. */
		subjectAlternativeNameFormatString?: string

	    /** Trusted Root Certificate. */
		rootCertificate?: MacOSTrustedRootCertificate

	    /** Certificate state for devices */
		managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface MacOSTrustedRootCertificate extends DeviceConfiguration {

	    /** Trusted Root Certificate. */
		trustedRootCertificate?: number

	    /** File name to display in UI. */
		certFileName?: string

}

export interface MacOSCustomConfiguration extends DeviceConfiguration {

	    /** Name that is displayed to the user. */
		payloadName?: string

	    /** Payload file name (.mobileconfig */
		payloadFileName?: string

	    /** Payload. (UTF8 encoded byte array) */
		payload?: number

}

export interface MacOSEndpointProtectionConfiguration extends DeviceConfiguration {

	    /** System and Privacy setting that determines which download locations apps can be run from on a macOS device. Possible values are: notConfigured, macAppStore, macAppStoreAndIdentifiedDevelopers, anywhere. */
		gatekeeperAllowedAppSource?: MacOSGatekeeperAppSources

	    /** If set to true, the user override for Gatekeeper will be disabled. */
		gatekeeperBlockOverride?: boolean

	    /** Whether the firewall should be enabled or not. */
		firewallEnabled?: boolean

	    /** Corresponds to the “Block all incoming connections” option. */
		firewallBlockAllIncoming?: boolean

	    /** Corresponds to “Enable stealth mode.” */
		firewallEnableStealthMode?: boolean

	    /** List of applications with firewall settings. Firewall settings for applications not on this list are determined by the user. This collection can contain a maximum of 500 elements. */
		firewallApplications?: MacOSFirewallApplication[]

}

export interface MacOSGeneralDeviceConfiguration extends DeviceConfiguration {

	    /** List of apps in the compliance (either allow list or block list, controlled by CompliantAppListType). This collection can contain a maximum of 10000 elements. */
		compliantAppsList?: AppListItem[]

	    /** List that is in the CompliantAppsList. Possible values are: none, appsInListCompliant, appsNotInListCompliant. */
		compliantAppListType?: AppListType

	    /** An email address lacking a suffix that matches any of these strings will be considered out-of-domain. */
		emailInDomainSuffixes?: string[]

	    /** Block simple passwords. */
		passwordBlockSimple?: boolean

	    /** Number of days before the password expires. */
		passwordExpirationDays?: number

	    /** Number of character sets a password must contain. Valid values 0 to 4 */
		passwordMinimumCharacterSetCount?: number

	    /** Minimum length of passwords. */
		passwordMinimumLength?: number

	    /** Minutes of inactivity required before a password is required. */
		passwordMinutesOfInactivityBeforeLock?: number

	    /** Minutes of inactivity required before the screen times out. */
		passwordMinutesOfInactivityBeforeScreenTimeout?: number

	    /** Number of previous passwords to block. */
		passwordPreviousPasswordBlockCount?: number

	    /** Type of password that is required. Possible values are: deviceDefault, alphanumeric, numeric. */
		passwordRequiredType?: RequiredPasswordType

	    /** Whether or not to require a password. */
		passwordRequired?: boolean

		safariBlockAutofill?: boolean

		cameraBlocked?: boolean

		iTunesBlockMusicService?: boolean

		spotlightBlockInternetResults?: boolean

		keyboardBlockDictation?: boolean

		definitionLookupBlocked?: boolean

		appleWatchBlockAutoUnlock?: boolean

		iTunesBlockFileSharing?: boolean

		iCloudBlockDocumentSync?: boolean

		iCloudBlockMail?: boolean

		iCloudBlockAddressBook?: boolean

		iCloudBlockCalendar?: boolean

		iCloudBlockReminders?: boolean

		iCloudBlockBookmarks?: boolean

		iCloudBlockNotes?: boolean

		airDropBlocked?: boolean

		passwordBlockModification?: boolean

		passwordBlockFingerprintUnlock?: boolean

}

export interface MacOSWiFiConfiguration extends DeviceConfiguration {

	    /** Network Name */
		networkName?: string

	    /** This is the name of the Wi-Fi network that is broadcast to all devices. */
		ssid?: string

	    /** Connect automatically when this network is in range. Setting this to true will skip the user prompt and automatically connect the device to Wi-Fi network. */
		connectAutomatically?: boolean

	    /** Connect when the network is not broadcasting its name (SSID). When set to true, this profile forces the device to connect to a network that doesn't broadcast its SSID to all devices. */
		connectWhenNetworkNameIsHidden?: boolean

	    /** Indicates whether Wi-Fi endpoint uses an EAP based security type. Possible values are: open, wpaPersonal, wpaEnterprise, wep. */
		wiFiSecurityType?: WiFiSecurityType

	    /** Proxy Type for this Wi-Fi connection. Possible values are: none, manual, automatic. */
		proxySettings?: WiFiProxySetting

	    /** IP Address or DNS hostname of the proxy server when manual configuration is selected. */
		proxyManualAddress?: string

	    /** Port of the proxy server when manual configuration is selected. */
		proxyManualPort?: number

	    /** URL of the proxy server automatic configuration script when automatic configuration is selected. This URL is typically the location of PAC (Proxy Auto Configuration) file. */
		proxyAutomaticConfigurationUrl?: string

	    /** This is the pre-shared key for WPA Personal Wi-Fi network. */
		preSharedKey?: string

}

export interface MacOSEnterpriseWiFiConfiguration extends MacOSWiFiConfiguration {

	    /** Extensible Authentication Protocol (EAP). Indicates the type of EAP protocol set on the the Wi-Fi endpoint (router). Possible values are: eapTls, leap, eapSim, eapTtls, peap, eapFast. */
		eapType?: EapType

	    /** EAP-FAST Configuration Option when EAP-FAST is the selected EAP Type. Possible values are: noProtectedAccessCredential, useProtectedAccessCredential, useProtectedAccessCredentialAndProvision, useProtectedAccessCredentialAndProvisionAnonymously. */
		eapFastConfiguration?: EapFastConfiguration

	    /** Trusted server certificate names when EAP Type is configured to EAP-TLS/TTLS/FAST or PEAP. This is the common name used in the certificates issued by your trusted certificate authority (CA). If you provide this information, you can bypass the dynamic trust dialog that is displayed on end users devices when they connect to this Wi-Fi network. */
		trustedServerCertificateNames?: string[]

	    /** Authentication Method when EAP Type is configured to PEAP or EAP-TTLS. Possible values are: certificate, usernameAndPassword. */
		authenticationMethod?: WiFiAuthenticationMethod

	    /** Non-EAP Method for Authentication (Inner Identity) when EAP Type is EAP-TTLS and Authenticationmethod is Username and Password. Possible values are: unencryptedPassword, challengeHandshakeAuthenticationProtocol, microsoftChap, microsoftChapVersionTwo. */
		innerAuthenticationProtocolForEapTtls?: NonEapAuthenticationMethodForEapTtlsType

	    /** Enable identity privacy (Outer Identity) when EAP Type is configured to EAP-TTLS, EAP-FAST or PEAP. This property masks usernames with the text you enter. For example, if you use 'anonymous', each user that authenticates with this Wi-Fi connection using their real username is displayed as 'anonymous'. */
		outerIdentityPrivacyTemporaryValue?: string

	    /** Trusted Root Certificate for Server Validation when EAP Type is configured to EAP-TLS/TTLS/FAST or PEAP. */
		rootCertificateForServerValidation?: MacOSTrustedRootCertificate

	    /** Identity Certificate for client authentication when EAP Type is configured to EAP-TLS, EAP-TTLS (with Certificate Authentication), or PEAP (with Certificate Authentication). */
		identityCertificateForClientAuthentication?: MacOSCertificateProfileBase

}

export interface UnsupportedDeviceConfiguration extends DeviceConfiguration {

	    /** The type of entity that would be returned otherwise. */
		originalEntityTypeName?: string

	    /** Details describing why the entity is unsupported. This collection can contain a maximum of 1000 elements. */
		details?: UnsupportedDeviceConfigurationDetail[]

}

export interface EasEmailProfileConfigurationBase extends DeviceConfiguration {

	    /** Username attribute that is picked from AAD and injected into this profile before installing on the device. Possible values are: userPrincipalName, primarySmtpAddress. */
		usernameSource?: UserEmailSource

	    /** Name of the AAD field, that will be used to retrieve UserName for email profile. Possible values are: userPrincipalName, primarySmtpAddress, samAccountName. */
		usernameAADSource?: UsernameSource

	    /** UserDomainname attribute that is picked from AAD and injected into this profile before installing on the device. Possible values are: fullDomainName, netBiosDomainName. */
		userDomainNameSource?: DomainNameSource

	    /** Custom domain name value used while generating an email profile before installing on the device. */
		customDomainName?: string

}

export interface IosEasEmailProfileConfiguration extends EasEmailProfileConfigurationBase {

	    /** Account name. */
		accountName?: string

	    /** Authentication method for this Email profile. Possible values are: usernameAndPassword, certificate. */
		authenticationMethod?: EasAuthenticationMethod

	    /** Indicates whether or not to block moving messages to other email accounts. */
		blockMovingMessagesToOtherEmailAccounts?: boolean

	    /** Indicates whether or not to block sending email from third party apps. */
		blockSendingEmailFromThirdPartyApps?: boolean

	    /** Indicates whether or not to block syncing recently used email addresses, for instance - when composing new email. */
		blockSyncingRecentlyUsedEmailAddresses?: boolean

	    /** Duration of time email should be synced back to. . Possible values are: userDefined, oneDay, threeDays, oneWeek, twoWeeks, oneMonth, unlimited. */
		durationOfEmailToSync?: EmailSyncDuration

	    /** Email attribute that is picked from AAD and injected into this profile before installing on the device. Possible values are: userPrincipalName, primarySmtpAddress. */
		emailAddressSource?: UserEmailSource

	    /** Exchange location that (URL) that the native mail app connects to. */
		hostName?: string

	    /** Indicates whether or not to use S/MIME certificate. */
		requireSmime?: boolean

	    /** Indicates whether or not to allow unencrypted emails. */
		smimeEnablePerMessageSwitch?: boolean

	    /** Indicates whether or not to use SSL. */
		requireSsl?: boolean

	    /** Identity certificate. */
		identityCertificate?: IosCertificateProfileBase

	    /** S/MIME signing certificate. */
		smimeSigningCertificate?: IosCertificateProfile

	    /** S/MIME encryption certificate. */
		smimeEncryptionCertificate?: IosCertificateProfile

}

export interface Windows10EasEmailProfileConfiguration extends EasEmailProfileConfigurationBase {

	    /** Account name. */
		accountName?: string

	    /** Whether or not to sync the calendar. */
		syncCalendar?: boolean

	    /** Whether or not to sync contacts. */
		syncContacts?: boolean

	    /** Whether or not to sync tasks. */
		syncTasks?: boolean

	    /** Duration of email to sync. Possible values are: userDefined, oneDay, threeDays, oneWeek, twoWeeks, oneMonth, unlimited. */
		durationOfEmailToSync?: EmailSyncDuration

	    /** Email attribute that is picked from AAD and injected into this profile before installing on the device. Possible values are: userPrincipalName, primarySmtpAddress. */
		emailAddressSource?: UserEmailSource

	    /** Email sync schedule. Possible values are: userDefined, asMessagesArrive, manual, fifteenMinutes, thirtyMinutes, sixtyMinutes, basedOnMyUsage. */
		emailSyncSchedule?: EmailSyncSchedule

	    /** Exchange location that (URL) that the native mail app connects to. */
		hostName?: string

	    /** Indicates whether or not to use SSL. */
		requireSsl?: boolean

}

export interface WindowsPhoneEASEmailProfileConfiguration extends EasEmailProfileConfigurationBase {

	    /** Account name. */
		accountName?: string

	    /** Value indicating whether this policy only applies to Windows 8.1. This property is read-only. */
		applyOnlyToWindowsPhone81?: boolean

	    /** Whether or not to sync the calendar. */
		syncCalendar?: boolean

	    /** Whether or not to sync contacts. */
		syncContacts?: boolean

	    /** Whether or not to sync tasks. */
		syncTasks?: boolean

	    /** Duration of email to sync. Possible values are: userDefined, oneDay, threeDays, oneWeek, twoWeeks, oneMonth, unlimited. */
		durationOfEmailToSync?: EmailSyncDuration

	    /** Email attribute that is picked from AAD and injected into this profile before installing on the device. Possible values are: userPrincipalName, primarySmtpAddress. */
		emailAddressSource?: UserEmailSource

	    /** Email sync schedule. Possible values are: userDefined, asMessagesArrive, manual, fifteenMinutes, thirtyMinutes, sixtyMinutes, basedOnMyUsage. */
		emailSyncSchedule?: EmailSyncSchedule

	    /** Exchange location that (URL) that the native mail app connects to. */
		hostName?: string

	    /** Indicates whether or not to use SSL. */
		requireSsl?: boolean

}

export interface AppleDeviceFeaturesConfigurationBase extends DeviceConfiguration {

	    /** An array of AirPrint printers that should always be shown. This collection can contain a maximum of 500 elements. */
		airPrintDestinations?: AirPrintDestination[]

}

export interface IosDeviceFeaturesConfiguration extends AppleDeviceFeaturesConfigurationBase {

	    /** Asset tag information for the device, displayed on the login window and lock screen. */
		assetTagTemplate?: string

	    /** Gets or sets iOS Web Content Filter settings, supervised mode only */
		contentFilterSettings?: IosWebContentFilterBase

	    /** A footnote displayed on the login window and lock screen. Available in iOS 9.3.1 and later. */
		lockScreenFootnote?: string

	    /** A list of app and folders to appear on the Home Screen Dock. This collection can contain a maximum of 500 elements. */
		homeScreenDockIcons?: IosHomeScreenItem[]

	    /** A list of pages on the Home Screen. This collection can contain a maximum of 500 elements. */
		homeScreenPages?: IosHomeScreenPage[]

	    /** Notification settings for each bundle id. Applicable to devices in supervised mode only (iOS 9.3 and later). This collection can contain a maximum of 500 elements. */
		notificationSettings?: IosNotificationSettings[]

	    /** The Kerberos login settings that enable apps on receiving devices to authenticate smoothly. */
		singleSignOnSettings?: IosSingleSignOnSettings

	    /** Identity Certificate for the renewal of Kerberos ticket used in single sign-on settings. */
		identityCertificateForClientAuthentication?: IosCertificateProfileBase

}

export interface MacOSDeviceFeaturesConfiguration extends AppleDeviceFeaturesConfigurationBase {

}

export interface AppleVpnConfiguration extends DeviceConfiguration {

	    /** Connection name displayed to the user. */
		connectionName?: string

	    /** Connection type. Possible values are: ciscoAnyConnect, pulseSecure, f5EdgeClient, dellSonicWallMobileConnect, checkPointCapsuleVpn, customVpn, ciscoIPSec, citrix, ciscoAnyConnectV2, paloAltoGlobalProtect. */
		connectionType?: AppleVpnConnectionType

	    /** Login group or domain when connection type is set to Dell SonicWALL Mobile Connection. */
		loginGroupOrDomain?: string

	    /** Role when connection type is set to Pulse Secure. */
		role?: string

	    /** Realm when connection type is set to Pulse Secure. */
		realm?: string

	    /** VPN Server on the network. Make sure end users can access this network location. */
		server?: VpnServer

	    /** Identifier provided by VPN vendor when connection type is set to Custom VPN. For example: Cisco AnyConnect uses an identifier of the form com.cisco.anyconnect.applevpn.plugin */
		identifier?: string

	    /** Custom data when connection type is set to Custom VPN. Use this field to enable functionality not supported by Intune, but available in your VPN solution. Contact your VPN vendor to learn how to add these key/value pairs. This collection can contain a maximum of 25 elements. */
		customData?: KeyValue[]

		customKeyValueData?: KeyValuePair[]

	    /** Send all network traffic through VPN. */
		enableSplitTunneling?: boolean

	    /** Authentication method for this VPN connection. Possible values are: certificate, usernameAndPassword. */
		authenticationMethod?: VpnAuthenticationMethod

	    /** Setting this to true creates Per-App VPN payload which can later be associated with Apps that can trigger this VPN conneciton on the end user's iOS device. */
		enablePerApp?: boolean

	    /** Safari domains when this VPN per App setting is enabled. In addition to the apps associated with this VPN, Safari domains specified here will also be able to trigger this VPN connection. */
		safariDomains?: string[]

	    /** On-Demand Rules. This collection can contain a maximum of 500 elements. */
		onDemandRules?: VpnOnDemandRule[]

	    /** Proxy Server. */
		proxyServer?: VpnProxyServer

		optInToDeviceIdSharing?: boolean

}

export interface IosVpnConfiguration extends AppleVpnConfiguration {

		providerType?: VpnProviderType

		userDomain?: string

		strictEnforcement?: boolean

		cloudName?: string

		excludeList?: string[]

	    /** Identity certificate for client authentication when authentication method is certificate. */
		identityCertificate?: IosCertificateProfileBase

}

export interface MacOSVpnConfiguration extends AppleVpnConfiguration {

	    /** Identity certificate for client authentication when authentication method is certificate. */
		identityCertificate?: MacOSCertificateProfileBase

}

export interface WindowsDefenderAdvancedThreatProtectionConfiguration extends DeviceConfiguration {

	    /** Windows Defender AdvancedThreatProtection Onboarding Blob. */
		advancedThreatProtectionOnboardingBlob?: string

	    /** Name of the file from which AdvancedThreatProtectionOnboardingBlob was obtained. */
		advancedThreatProtectionOnboardingFilename?: string

		advancedThreatProtectionAutoPopulateOnboardingBlob?: boolean

	    /** Windows Defender AdvancedThreatProtection "Allow Sample Sharing" Rule */
		allowSampleSharing?: boolean

	    /** Expedite Windows Defender Advanced Threat Protection telemetry reporting frequency. */
		enableExpeditedTelemetryReporting?: boolean

	    /** Windows Defender AdvancedThreatProtection Offboarding Blob. */
		advancedThreatProtectionOffboardingBlob?: string

	    /** Name of the file from which AdvancedThreatProtectionOffboardingBlob was obtained. */
		advancedThreatProtectionOffboardingFilename?: string

}

export interface EditionUpgradeConfiguration extends DeviceConfiguration {

	    /** Edition Upgrade License Type. Possible values are: productKey, licenseFile. */
		licenseType?: EditionUpgradeLicenseType

	    /** Edition Upgrade Target Edition. Possible values are: windows10Enterprise, windows10EnterpriseN, windows10Education, windows10EducationN, windows10MobileEnterprise, windows10HolographicEnterprise, windows10Professional, windows10ProfessionalN, windows10ProfessionalEducation, windows10ProfessionalEducationN, windows10ProfessionalWorkstation, windows10ProfessionalWorkstationN. */
		targetEdition?: Windows10EditionType

	    /** Edition Upgrade License File Content. */
		license?: string

	    /** Edition Upgrade Product Key. */
		productKey?: string

		windowsSMode?: WindowsSModeConfiguration

}

export interface Windows10EndpointProtectionConfiguration extends DeviceConfiguration {

		userRightsAccessCredentialManagerAsTrustedCaller?: DeviceManagementUserRightsSetting

		userRightsAllowAccessFromNetwork?: DeviceManagementUserRightsSetting

		userRightsBlockAccessFromNetwork?: DeviceManagementUserRightsSetting

		userRightsActAsPartOfTheOperatingSystem?: DeviceManagementUserRightsSetting

		userRightsLocalLogOn?: DeviceManagementUserRightsSetting

		userRightsBackupData?: DeviceManagementUserRightsSetting

		userRightsChangeSystemTime?: DeviceManagementUserRightsSetting

		userRightsCreateGlobalObjects?: DeviceManagementUserRightsSetting

		userRightsCreatePageFile?: DeviceManagementUserRightsSetting

		userRightsCreatePermanentSharedObjects?: DeviceManagementUserRightsSetting

		userRightsCreateSymbolicLinks?: DeviceManagementUserRightsSetting

		userRightsCreateToken?: DeviceManagementUserRightsSetting

		userRightsDebugPrograms?: DeviceManagementUserRightsSetting

		userRightsRemoteDesktopServicesLogOn?: DeviceManagementUserRightsSetting

		userRightsDelegation?: DeviceManagementUserRightsSetting

		userRightsGenerateSecurityAudits?: DeviceManagementUserRightsSetting

		userRightsImpersonateClient?: DeviceManagementUserRightsSetting

		userRightsIncreaseSchedulingPriority?: DeviceManagementUserRightsSetting

		userRightsLoadUnloadDrivers?: DeviceManagementUserRightsSetting

		userRightsLockMemory?: DeviceManagementUserRightsSetting

		userRightsManageAuditingAndSecurityLogs?: DeviceManagementUserRightsSetting

		userRightsManageVolumes?: DeviceManagementUserRightsSetting

		userRightsModifyFirmwareEnvironment?: DeviceManagementUserRightsSetting

		userRightsModifyObjectLabels?: DeviceManagementUserRightsSetting

		userRightsProfileSingleProcess?: DeviceManagementUserRightsSetting

		userRightsRemoteShutdown?: DeviceManagementUserRightsSetting

		userRightsRestoreData?: DeviceManagementUserRightsSetting

		userRightsTakeOwnership?: DeviceManagementUserRightsSetting

		userRightsRegisterProcessAsService?: DeviceManagementUserRightsSetting

		xboxServicesEnableXboxGameSaveTask?: boolean

		xboxServicesAccessoryManagementServiceStartupMode?: ServiceStartType

		xboxServicesLiveAuthManagerServiceStartupMode?: ServiceStartType

		xboxServicesLiveGameSaveServiceStartupMode?: ServiceStartType

		xboxServicesLiveNetworkingServiceStartupMode?: ServiceStartType

	    /** Prevent users from adding new Microsoft accounts to this computer. */
		localSecurityOptionsBlockMicrosoftAccounts?: boolean

	    /** Enable Local accounts that are not password protected to log on from locations other than the physical device.Default is enabled */
		localSecurityOptionsBlockRemoteLogonWithBlankPassword?: boolean

	    /** Determines whether the Local Administrator account is enabled or disabled. */
		localSecurityOptionsEnableAdministratorAccount?: boolean

	    /** Define a different account name to be associated with the security identifier (SID) for the account “Administrator”. */
		localSecurityOptionsAdministratorAccountName?: string

	    /** Determines if the Guest account is enabled or disabled. */
		localSecurityOptionsEnableGuestAccount?: boolean

	    /** Define a different account name to be associated with the security identifier (SID) for the account “Guest”. */
		localSecurityOptionsGuestAccountName?: string

	    /** Prevent a portable computer from being undocked without having to log in. */
		localSecurityOptionsAllowUndockWithoutHavingToLogon?: boolean

	    /** Restrict installing printer drivers as part of connecting to a shared printer to admins only. */
		localSecurityOptionsBlockUsersInstallingPrinterDrivers?: boolean

	    /** Enabling this settings allows only interactively logged on user to access CD-ROM media. */
		localSecurityOptionsBlockRemoteOpticalDriveAccess?: boolean

	    /** Define who is allowed to format and eject removable NTFS media. Possible values are: notConfigured, administrators, administratorsAndPowerUsers, administratorsAndInteractiveUsers. */
		localSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUser?: LocalSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUserType

	    /** Define maximum minutes of inactivity on the interactive desktop’s login screen until the screen saver runs. Valid values 0 to 9999 */
		localSecurityOptionsMachineInactivityLimit?: number

	    /** Define maximum minutes of inactivity on the interactive desktop’s login screen until the screen saver runs. Valid values 0 to 9999 */
		localSecurityOptionsMachineInactivityLimitInMinutes?: number

	    /** Require CTRL+ALT+DEL to be pressed before a user can log on. */
		localSecurityOptionsDoNotRequireCtrlAltDel?: boolean

	    /** Do not display the username of the last person who signed in on this device. */
		localSecurityOptionsHideLastSignedInUser?: boolean

	    /** Do not display the username of the person signing in to this device after credentials are entered and before the device’s desktop is shown. */
		localSecurityOptionsHideUsernameAtSignIn?: boolean

	    /** Set message title for users attempting to log in. */
		localSecurityOptionsLogOnMessageTitle?: string

	    /** Set message text for users attempting to log in. */
		localSecurityOptionsLogOnMessageText?: string

	    /** Block PKU2U authentication requests to this device to use online identities. */
		localSecurityOptionsAllowPKU2UAuthenticationRequests?: boolean

	    /** UI helper boolean for LocalSecurityOptionsAllowRemoteCallsToSecurityAccountsManager entity */
		localSecurityOptionsAllowRemoteCallsToSecurityAccountsManagerHelperBool?: boolean

	    /** Edit the default Security Descriptor Definition Language string to allow or deny users and groups to make remote calls to the SAM. */
		localSecurityOptionsAllowRemoteCallsToSecurityAccountsManager?: string

		localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedClients?: LocalSecurityOptionsMinimumSessionSecurity

		localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedServers?: LocalSecurityOptionsMinimumSessionSecurity

		lanManagerAuthenticationLevel?: LanManagerAuthenticationLevel

		lanManagerWorkstationEnableInsecureGuestLogons?: boolean

	    /** This security setting determines whether the virtual memory pagefile is cleared when the system is shut down. */
		localSecurityOptionsClearVirtualMemoryPageFile?: boolean

	    /** This security setting determines whether a computer can be shut down without having to log on to Windows. */
		localSecurityOptionsAllowSystemToBeShutDownWithoutHavingToLogOn?: boolean

	    /** Allow UIAccess apps to prompt for elevation without using the secure desktop. */
		localSecurityOptionsAllowUIAccessApplicationElevation?: boolean

	    /** Virtualize file and registry write failures to per user locations */
		localSecurityOptionsVirtualizeFileAndRegistryWriteFailuresToPerUserLocations?: boolean

	    /** Enforce PKI certification path validation for a given executable file before it is permitted to run. */
		localSecurityOptionsOnlyElevateSignedExecutables?: boolean

	    /** Define the behavior of the elevation prompt for admins in Admin Approval Mode. Possible values are: notConfigured, elevateWithoutPrompting, promptForCredentialsOnTheSecureDesktop, promptForConsentOnTheSecureDesktop, promptForCredentials, promptForConsent, promptForConsentForNonWindowsBinaries. */
		localSecurityOptionsAdministratorElevationPromptBehavior?: LocalSecurityOptionsAdministratorElevationPromptBehaviorType

	    /** Define the behavior of the elevation prompt for standard users. Possible values are: notConfigured, automaticallyDenyElevationRequests, promptForCredentialsOnTheSecureDesktop, promptForCredentials. */
		localSecurityOptionsStandardUserElevationPromptBehavior?: LocalSecurityOptionsStandardUserElevationPromptBehaviorType

	    /** Enable all elevation requests to go to the interactive user's desktop rather than the secure desktop. Prompt behavior policy settings for admins and standard users are used. */
		localSecurityOptionsSwitchToSecureDesktopWhenPromptingForElevation?: boolean

	    /** App installations requiring elevated privileges will prompt for admin credentials.Default is enabled */
		localSecurityOptionsDetectApplicationInstallationsAndPromptForElevation?: boolean

	    /** Allow UIAccess apps to prompt for elevation without using the secure desktop.Default is enabled */
		localSecurityOptionsAllowUIAccessApplicationsForSecureLocations?: boolean

	    /** Defines whether the built-in admin account uses Admin Approval Mode or runs all apps with full admin privileges.Default is enabled */
		localSecurityOptionsUseAdminApprovalMode?: boolean

	    /** Define whether Admin Approval Mode and all UAC policy settings are enabled, default is enabled */
		localSecurityOptionsUseAdminApprovalModeForAdministrators?: boolean

	    /** Configure the user information that is displayed when the session is locked. If not configured, user display name, domain and username are shown. Possible values are: notConfigured, userDisplayNameDomainUser, userDisplayNameOnly, doNotDisplayUser. */
		localSecurityOptionsInformationShownOnLockScreen?: LocalSecurityOptionsInformationShownOnLockScreenType

	    /** Configure the user information that is displayed when the session is locked. If not configured, user display name, domain and username are shown. Possible values are: notConfigured, administrators, administratorsAndPowerUsers, administratorsAndInteractiveUsers. */
		localSecurityOptionsInformationDisplayedOnLockScreen?: LocalSecurityOptionsInformationDisplayedOnLockScreenType

	    /** This security setting determines whether the SMB client attempts to negotiate SMB packet signing. */
		localSecurityOptionsDisableClientDigitallySignCommunicationsIfServerAgrees?: boolean

		localSecurityOptionsClientDigitallySignCommunicationsAlways?: boolean

	    /** If this security setting is enabled, the Server Message Block (SMB) redirector is allowed to send plaintext passwords to non-Microsoft SMB servers that do not support password encryption during authentication. */
		localSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers?: boolean

	    /** This security setting determines whether packet signing is required by the SMB server component. */
		localSecurityOptionsDisableServerDigitallySignCommunicationsAlways?: boolean

	    /** This security setting determines whether the SMB server will negotiate SMB packet signing with clients that request it. */
		localSecurityOptionsDisableServerDigitallySignCommunicationsIfClientAgrees?: boolean

	    /** By default, this security setting restricts anonymous access to shares and pipes to the settings for named pipes that can be accessed anonymously and Shares that can be accessed anonymously */
		localSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares?: boolean

	    /** This security setting determines what additional permissions will be granted for anonymous connections to the computer. */
		localSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts?: boolean

	    /** This security setting determines whether to allows anonymous users to perform certain activities, such as enumerating the names of domain accounts and network shares. */
		localSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares?: boolean

	    /** This security setting determines if, at the next password change, the LAN Manager (LM) hash value for the new password is stored. It’s not stored by default. */
		localSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange?: boolean

	    /** This security setting determines what happens when the smart card for a logged-on user is removed from the smart card reader. Possible values are: lockWorkstation, noAction, forceLogoff, disconnectRemoteDesktopSession. */
		localSecurityOptionsSmartCardRemovalBehavior?: LocalSecurityOptionsSmartCardRemovalBehaviorType

	    /** Used to disable the display of the app and browser protection area. */
		defenderSecurityCenterDisableAppBrowserUI?: boolean

	    /** Used to disable the display of the family options area. */
		defenderSecurityCenterDisableFamilyUI?: boolean

	    /** Used to disable the display of the device performance and health area. */
		defenderSecurityCenterDisableHealthUI?: boolean

	    /** Used to disable the display of the firewall and network protection area. */
		defenderSecurityCenterDisableNetworkUI?: boolean

	    /** Used to disable the display of the virus and threat protection area. */
		defenderSecurityCenterDisableVirusUI?: boolean

	    /** Used to disable the display of the account protection area. */
		defenderSecurityCenterDisableAccountUI?: boolean

	    /** Used to disable the display of the hardware protection area. */
		defenderSecurityCenterDisableHardwareUI?: boolean

	    /** Used to disable the display of the ransomware protection area. */
		defenderSecurityCenterDisableRansomwareUI?: boolean

	    /** Used to disable the display of the secure boot area under Device security. */
		defenderSecurityCenterDisableSecureBootUI?: boolean

	    /** Used to disable the display of the security process troubleshooting under Device security. */
		defenderSecurityCenterDisableTroubleshootingUI?: boolean

	    /** The company name that is displayed to the users. */
		defenderSecurityCenterOrganizationDisplayName?: string

	    /** The email address that is displayed to users. */
		defenderSecurityCenterHelpEmail?: string

	    /** The phone number or Skype ID that is displayed to users. */
		defenderSecurityCenterHelpPhone?: string

	    /** The help portal URL this is displayed to users. */
		defenderSecurityCenterHelpURL?: string

	    /** Notifications to show from the displayed areas of app. Possible values are: notConfigured, blockNoncriticalNotifications, blockAllNotifications. */
		defenderSecurityCenterNotificationsFromApp?: DefenderSecurityCenterNotificationsFromAppType

	    /** Configure where to display IT contact information to end users. Possible values are: notConfigured, displayInAppAndInNotifications, displayOnlyInApp, displayOnlyInNotifications. */
		defenderSecurityCenterITContactDisplay?: DefenderSecurityCenterITContactDisplayType

	    /** Blocks stateful FTP connections to the device */
		firewallBlockStatefulFTP?: boolean

	    /** Configures the idle timeout for security associations, in seconds, from 300 to 3600 inclusive. This is the period after which security associations will expire and be deleted. Valid values 300 to 3600 */
		firewallIdleTimeoutForSecurityAssociationInSeconds?: number

	    /** Select the preshared key encoding to be used. Possible values are: deviceDefault, none, utF8. */
		firewallPreSharedKeyEncodingMethod?: FirewallPreSharedKeyEncodingMethodType

	    /** Configures IPSec exemptions to allow neighbor discovery IPv6 ICMP type-codes */
		firewallIPSecExemptionsAllowNeighborDiscovery?: boolean

	    /** Configures IPSec exemptions to allow ICMP */
		firewallIPSecExemptionsAllowICMP?: boolean

	    /** Configures IPSec exemptions to allow router discovery IPv6 ICMP type-codes */
		firewallIPSecExemptionsAllowRouterDiscovery?: boolean

	    /** Configures IPSec exemptions to allow both IPv4 and IPv6 DHCP traffic */
		firewallIPSecExemptionsAllowDHCP?: boolean

	    /** Specify how the certificate revocation list is to be enforced. Possible values are: deviceDefault, none, attempt, require. */
		firewallCertificateRevocationListCheckMethod?: FirewallCertificateRevocationListCheckMethodType

	    /** If an authentication set is not fully supported by a keying module, direct the module to ignore only unsupported authentication suites rather than the entire set */
		firewallMergeKeyingModuleSettings?: boolean

	    /** Configures how packet queueing should be applied in the tunnel gateway scenario. Possible values are: deviceDefault, disabled, queueInbound, queueOutbound, queueBoth. */
		firewallPacketQueueingMethod?: FirewallPacketQueueingMethodType

	    /** Configures the firewall profile settings for domain networks */
		firewallProfileDomain?: WindowsFirewallNetworkProfile

	    /** Configures the firewall profile settings for public networks */
		firewallProfilePublic?: WindowsFirewallNetworkProfile

	    /** Configures the firewall profile settings for private networks */
		firewallProfilePrivate?: WindowsFirewallNetworkProfile

	    /** List of exe files and folders to be excluded from attack surface reduction rules */
		defenderAttackSurfaceReductionExcludedPaths?: string[]

	    /** Value indicating the behavior of  Office applications injecting into other processes. Possible values are: userDefined, block, auditMode. */
		defenderOfficeAppsOtherProcessInjectionType?: DefenderAttackSurfaceType

		defenderOfficeAppsOtherProcessInjection?: DefenderProtectionType

	    /** Value indicating the behavior of Office applications/macros creating or launching executable content. Possible values are: userDefined, block, auditMode. */
		defenderOfficeAppsExecutableContentCreationOrLaunchType?: DefenderAttackSurfaceType

		defenderOfficeAppsExecutableContentCreationOrLaunch?: DefenderProtectionType

	    /** Value indicating the behavior of Office application launching child processes. Possible values are: userDefined, block, auditMode. */
		defenderOfficeAppsLaunchChildProcessType?: DefenderAttackSurfaceType

		defenderOfficeAppsLaunchChildProcess?: DefenderProtectionType

	    /** Value indicating the behavior of Win32 imports from Macro code in Office. Possible values are: userDefined, block, auditMode. */
		defenderOfficeMacroCodeAllowWin32ImportsType?: DefenderAttackSurfaceType

		defenderOfficeMacroCodeAllowWin32Imports?: DefenderProtectionType

	    /** Value indicating the behavior of obfuscated js/vbs/ps/macro code. Possible values are: userDefined, block, auditMode. */
		defenderScriptObfuscatedMacroCodeType?: DefenderAttackSurfaceType

		defenderScriptObfuscatedMacroCode?: DefenderProtectionType

	    /** Value indicating the behavior of js/vbs executing payload downloaded from Internet. Possible values are: userDefined, block, auditMode. */
		defenderScriptDownloadedPayloadExecutionType?: DefenderAttackSurfaceType

		defenderScriptDownloadedPayloadExecution?: DefenderProtectionType

	    /** Value indicating if credential stealing from the Windows local security authority subsystem is permitted. Possible values are: userDefined, enable, auditMode. */
		defenderPreventCredentialStealingType?: DefenderProtectionType

	    /** Value indicating response to process creations originating from PSExec and WMI commands. Possible values are: userDefined, block, auditMode. */
		defenderProcessCreationType?: DefenderAttackSurfaceType

		defenderProcessCreation?: DefenderProtectionType

	    /** Value indicating response to untrusted and unsigned processes that run from USB. Possible values are: userDefined, block, auditMode. */
		defenderUntrustedUSBProcessType?: DefenderAttackSurfaceType

		defenderUntrustedUSBProcess?: DefenderProtectionType

	    /** Value indicating response to executables that don't meet a prevalence, age, or trusted list criteria. Possible values are: userDefined, block, auditMode. */
		defenderUntrustedExecutableType?: DefenderAttackSurfaceType

		defenderUntrustedExecutable?: DefenderProtectionType

	    /** Value indicating if execution of executable content (exe, dll, ps, js, vbs, etc) should be dropped from email (webmail/mail-client). Possible values are: userDefined, block, auditMode. */
		defenderEmailContentExecutionType?: DefenderAttackSurfaceType

		defenderEmailContentExecution?: DefenderProtectionType

	    /** Value indicating use of advanced protection against ransomeware. Possible values are: userDefined, enable, auditMode. */
		defenderAdvancedRansomewareProtectionType?: DefenderProtectionType

	    /** Value indicating the behavior of protected folders. Possible values are: userDefined, enable, auditMode, blockDiskModification, auditDiskModification. */
		defenderGuardMyFoldersType?: FolderProtectionType

	    /** List of paths to exe that are allowed to access protected folders */
		defenderGuardedFoldersAllowedAppPaths?: string[]

	    /** List of folder paths to be added to the list of protected folders */
		defenderAdditionalGuardedFolders?: string[]

	    /** Value indicating the behavior of NetworkProtection. Possible values are: userDefined, enable, auditMode. */
		defenderNetworkProtectionType?: DefenderProtectionType

	    /** Xml content containing information regarding exploit protection details. */
		defenderExploitProtectionXml?: number

	    /** Name of the file from which DefenderExploitProtectionXml was obtained. */
		defenderExploitProtectionXmlFileName?: string

	    /** Indicates whether or not to block user from overriding Exploit Protection settings. */
		defenderSecurityCenterBlockExploitProtectionOverride?: boolean

	    /** Enables the Admin to choose what types of app to allow on devices. Possible values are: notConfigured, enforceComponentsAndStoreApps, auditComponentsAndStoreApps, enforceComponentsStoreAppsAndSmartlocker, auditComponentsStoreAppsAndSmartlocker. */
		appLockerApplicationControl?: AppLockerApplicationControlType

	    /** Turn on Credential Guard when Platform Security Level with Secure Boot and Virtualization Based Security are both enabled. Possible values are: notConfigured, enableWithUEFILock, enableWithoutUEFILock. */
		deviceGuardLocalSystemAuthorityCredentialGuardSettings?: DeviceGuardLocalSystemAuthorityCredentialGuardType

	    /** Turns On Virtualization Based Security(VBS). */
		deviceGuardEnableVirtualizationBasedSecurity?: boolean

	    /** Specifies whether Platform Security Level is enabled at next reboot. */
		deviceGuardEnableSecureBootWithDMA?: boolean

	    /** Allows IT Admins to configure SmartScreen for Windows. */
		smartScreenEnableInShell?: boolean

	    /** Allows IT Admins to control whether users can can ignore SmartScreen warnings and run malicious files. */
		smartScreenBlockOverrideForFiles?: boolean

	    /** Enable Windows Defender Application Guard */
		applicationGuardEnabled?: boolean

	    /** Block clipboard to transfer image file, text file or neither of them. Possible values are: notConfigured, blockImageAndTextFile, blockImageFile, blockNone, blockTextFile. */
		applicationGuardBlockFileTransfer?: ApplicationGuardBlockFileTransferType

	    /** Block enterprise sites to load non-enterprise content, such as third party plug-ins */
		applicationGuardBlockNonEnterpriseContent?: boolean

	    /** Allow persisting user generated data inside the App Guard Containter (favorites, cookies, web passwords, etc.) */
		applicationGuardAllowPersistence?: boolean

	    /** Force auditing will persist Windows logs and events to meet security/compliance criteria (sample events are user login-logoff, use of privilege rights, software installation, system changes, etc.) */
		applicationGuardForceAuditing?: boolean

	    /** Block clipboard to share data from Host to Container, or from Container to Host, or both ways, or neither ways. Possible values are: notConfigured, blockBoth, blockHostToContainer, blockContainerToHost, blockNone. */
		applicationGuardBlockClipboardSharing?: ApplicationGuardBlockClipboardSharingType

	    /** Allow printing to PDF from Container */
		applicationGuardAllowPrintToPDF?: boolean

	    /** Allow printing to XPS from Container */
		applicationGuardAllowPrintToXPS?: boolean

	    /** Allow printing to Local Printers from Container */
		applicationGuardAllowPrintToLocalPrinters?: boolean

	    /** Allow printing to Network Printers from Container */
		applicationGuardAllowPrintToNetworkPrinters?: boolean

	    /** Allow application guard to use virtual GPU */
		applicationGuardAllowVirtualGPU?: boolean

	    /** Allow users to download files from Edge in the application guard container and save them on the host file system */
		applicationGuardAllowFileSaveOnHost?: boolean

	    /** Allows the Admin to disable the warning prompt for other disk encryption on the user machines. */
		bitLockerDisableWarningForOtherDiskEncryption?: boolean

	    /** Allows the admin to require encryption to be turned on using BitLocker. This policy is valid only for a mobile SKU. */
		bitLockerEnableStorageCardEncryptionOnMobile?: boolean

	    /** Allows the admin to require encryption to be turned on using BitLocker. */
		bitLockerEncryptDevice?: boolean

	    /** BitLocker System Drive Policy. */
		bitLockerSystemDrivePolicy?: BitLockerSystemDrivePolicy

	    /** BitLocker Fixed Drive Policy. */
		bitLockerFixedDrivePolicy?: BitLockerFixedDrivePolicy

	    /** BitLocker Removable Drive Policy. */
		bitLockerRemovableDrivePolicy?: BitLockerRemovableDrivePolicy

}

export interface Windows10GeneralConfiguration extends DeviceConfiguration {

	    /** Allow users with administrative rights to delete all user data and settings using CTRL + Win + R at the device lock screen so that the device can be automatically re-configured and re-enrolled into management. */
		enableAutomaticRedeployment?: boolean

	    /** This policy setting allows to define the user account that will be locked to Single App Kiosk Mode. */
		assignedAccessSingleModeUserName?: string

	    /** This policy setting allows to define the Application User Model ID (AUMID) that will be locked to Single App Kiosk Mode. */
		assignedAccessSingleModeAppUserModelId?: string

	    /** Controls the Microsoft Account Sign-In Assistant (wlidsvc) NT service. Possible values are: notConfigured, disabled. */
		microsoftAccountSignInAssistantSettings?: SignInAssistantOptions

	    /** Allows secondary authentication devices to work with Windows. */
		authenticationAllowSecondaryDevice?: boolean

	    /** Indicates whether or not to allow authentication using FIDO device (https://fidoalliance.org/) */
		authenticationAllowFIDODevice?: boolean

	    /** Specify whether to allow or disallow the Federal Information Processing Standard (FIPS) policy. */
		cryptographyAllowFipsAlgorithmPolicy?: boolean

	    /** List of legacy applications that have GDI DPI Scaling turned on. */
		displayAppListWithGdiDPIScalingTurnedOn?: string[]

	    /** List of legacy applications that have GDI DPI Scaling turned off. */
		displayAppListWithGdiDPIScalingTurnedOff?: string[]

	    /** Endpoint for discovering cloud printers. */
		enterpriseCloudPrintDiscoveryEndPoint?: string

	    /** Authentication endpoint for acquiring OAuth tokens. */
		enterpriseCloudPrintOAuthAuthority?: string

	    /** GUID of a client application authorized to retrieve OAuth tokens from the OAuth Authority. */
		enterpriseCloudPrintOAuthClientIdentifier?: string

	    /** OAuth resource URI for print service as configured in the Azure portal. */
		enterpriseCloudPrintResourceIdentifier?: string

	    /** Maximum number of printers that should be queried from a discovery endpoint. This is a mobile only setting. Valid values 1 to 65535 */
		enterpriseCloudPrintDiscoveryMaxLimit?: number

	    /** OAuth resource URI for printer discovery service as configured in Azure portal. */
		enterpriseCloudPrintMopriaDiscoveryResourceIdentifier?: string

	    /** Indicates whether or not to block text message back up and restore and Messaging Everywhere. */
		messagingBlockSync?: boolean

	    /** Indicates whether or not to block the the MMS send/receive functionality on the device. */
		messagingBlockMMS?: boolean

	    /** Indicates whether or not to block the the RCS send/receive functionality on the device. */
		messagingBlockRichCommunicationServices?: boolean

	    /** Automatically provision printers based on their names (network host names). */
		printerNames?: string[]

	    /** Name (network host name) of an installed printer. */
		printerDefaultName?: string

	    /** Prevent user installation of additional printers from printers settings. */
		printerBlockAddition?: boolean

	    /** Specifies if search can use diacritics. */
		searchBlockDiacritics?: boolean

	    /** Specifies whether to use automatic language detection when indexing content and properties. */
		searchDisableAutoLanguageDetection?: boolean

	    /** Indicates whether or not to block indexing of WIP-protected items to prevent them from appearing in search results for Cortana or Explorer. */
		searchDisableIndexingEncryptedItems?: boolean

	    /** Indicates whether or not to block remote queries of this computer’s index. */
		searchEnableRemoteQueries?: boolean

	    /** Specifies if search can use location information. */
		searchDisableUseLocation?: boolean

		searchDisableLocation?: boolean

	    /** Indicates whether or not to disable the search indexer backoff feature. */
		searchDisableIndexerBackoff?: boolean

	    /** Indicates whether or not to allow users to add locations on removable drives to libraries and to be indexed. */
		searchDisableIndexingRemovableDrive?: boolean

	    /** Specifies minimum amount of hard drive space on the same drive as the index location before indexing stops. */
		searchEnableAutomaticIndexSizeManangement?: boolean

	    /** Indicates whether or not to block the web search. */
		searchBlockWebResults?: boolean

	    /** Specify whether to allow automatic device encryption during OOBE when the device is Azure AD joined (desktop only). */
		securityBlockAzureADJoinedDevicesAutoEncryption?: boolean

	    /** Gets or sets a value allowing the device to send diagnostic and usage telemetry data, such as Watson. Possible values are: userDefined, none, basic, enhanced, full. */
		diagnosticsDataSubmissionMode?: DiagnosticDataSubmissionMode

	    /** Gets or sets a value allowing IT admins to prevent apps and features from working with files on OneDrive. */
		oneDriveDisableFileSync?: boolean

	    /** Gets or sets the fully qualified domain name (FQDN) or IP address of a proxy server to forward Connected User Experiences and Telemetry requests. */
		systemTelemetryProxyServer?: string

	    /** Controls the user access to the ink workspace, from the desktop and from above the lock screen. Possible values are: notConfigured, enabled, disabled. */
		inkWorkspaceAccess?: InkAccessSetting

		inkWorkspaceAccessState?: StateManagementSetting

	    /** Specify whether to show recommended app suggestions in the ink workspace. */
		inkWorkspaceBlockSuggestedApps?: boolean

	    /** Allows IT Admins to control whether users are allowed to install apps from places other than the Store. */
		smartScreenEnableAppInstallControl?: boolean

	    /** A http or https Url to a jpg, jpeg or png image that needs to be downloaded and used as the Desktop Image or a file Url to a local image on the file system that needs to used as the Desktop Image. */
		personalizationDesktopImageUrl?: string

	    /** A http or https Url to a jpg, jpeg or png image that neeeds to be downloaded and used as the Lock Screen Image or a file Url to a local image on the file system that needs to be used as the Lock Screen Image. */
		personalizationLockScreenImageUrl?: string

	    /** Specify a list of allowed Bluetooth services and profiles in hex formatted strings. */
		bluetoothAllowedServices?: string[]

	    /** Whether or not to Block the user from using bluetooth advertising. */
		bluetoothBlockAdvertising?: boolean

	    /** Whether or not to Block the user from using bluetooth discoverable mode. */
		bluetoothBlockDiscoverableMode?: boolean

	    /** Whether or not to block specific bundled Bluetooth peripherals to automatically pair with the host device. */
		bluetoothBlockPrePairing?: boolean

	    /** Indicates whether or not to block auto fill. */
		edgeBlockAutofill?: boolean

	    /** Indicates whether or not to Block the user from using the Edge browser. */
		edgeBlocked?: boolean

	    /** Indicates which cookies to block in the Edge browser. Possible values are: userDefined, allow, blockThirdParty, blockAll. */
		edgeCookiePolicy?: EdgeCookiePolicy

	    /** Indicates whether or not to block developer tools in the Edge browser. */
		edgeBlockDeveloperTools?: boolean

	    /** Indicates whether or not to Block the user from sending the do not track header. */
		edgeBlockSendingDoNotTrackHeader?: boolean

	    /** Indicates whether or not to block extensions in the Edge browser. */
		edgeBlockExtensions?: boolean

	    /** Indicates whether or not to block InPrivate browsing on corporate networks, in the Edge browser. */
		edgeBlockInPrivateBrowsing?: boolean

	    /** Indicates whether or not to Block the user from using JavaScript. */
		edgeBlockJavaScript?: boolean

	    /** Indicates whether or not to Block password manager. */
		edgeBlockPasswordManager?: boolean

	    /** Block the address bar dropdown functionality in Microsoft Edge. Disable this settings to minimize network connections from Microsoft Edge to Microsoft services. */
		edgeBlockAddressBarDropdown?: boolean

	    /** Block Microsoft compatibility list in Microsoft Edge. This list from Microsoft helps Edge properly display sites with known compatibility issues. */
		edgeBlockCompatibilityList?: boolean

	    /** Clear browsing data on exiting Microsoft Edge. */
		edgeClearBrowsingDataOnExit?: boolean

	    /** Allow users to change Start pages on Edge. Use the EdgeHomepageUrls to specify the Start pages that the user would see by default when they open Edge. */
		edgeAllowStartPagesModification?: boolean

	    /** Block the Microsoft web page that opens on the first use of Microsoft Edge. This policy allows enterprises, like those enrolled in zero emissions configurations, to block this page. */
		edgeDisableFirstRunPage?: boolean

	    /** Block the collection of information by Microsoft for live tile creation when users pin a site to Start from Microsoft Edge. */
		edgeBlockLiveTileDataCollection?: boolean

	    /** Enable favorites sync between Internet Explorer and Microsoft Edge. Additions, deletions, modifications and order changes to favorites are shared between browsers. */
		edgeSyncFavoritesWithInternetExplorer?: boolean

	    /** The location of the favorites list to provision. Could be a local file, local network or http location. */
		edgeFavoritesListLocation?: string

	    /** Indicates whether or not to Block the user from making changes to Favorites. */
		edgeBlockEditFavorites?: boolean

	    /** Whether or not to Block the user from using data over cellular while roaming. */
		cellularBlockDataWhenRoaming?: boolean

	    /** Whether or not to Block the user from using VPN over cellular. */
		cellularBlockVpn?: boolean

	    /** Whether or not to Block the user from using VPN when roaming over cellular. */
		cellularBlockVpnWhenRoaming?: boolean

	    /** Whether or not to allow the cellular data channel on the device. If not configured, the cellular data channel is allowed and the user can turn it off. Possible values are: blocked, required, allowed. */
		cellularData?: ConfigurationUsage

	    /** Whether or not to block end user access to Defender. */
		defenderBlockEndUserAccess?: boolean

	    /** Number of days before deleting quarantined malware. Valid values 0 to 90 */
		defenderDaysBeforeDeletingQuarantinedMalware?: number

	    /** Gets or sets Defender’s actions to take on detected Malware per threat level. */
		defenderDetectedMalwareActions?: DefenderDetectedMalwareActions

	    /** Defender day of the week for the system scan. Possible values are: userDefined, everyday, sunday, monday, tuesday, wednesday, thursday, friday, saturday. */
		defenderSystemScanSchedule?: WeeklySchedule

	    /** Files and folder to exclude from scans and real time protection. */
		defenderFilesAndFoldersToExclude?: string[]

	    /** File extensions to exclude from scans and real time protection. */
		defenderFileExtensionsToExclude?: string[]

	    /** Max CPU usage percentage during scan. Valid values 0 to 100 */
		defenderScanMaxCpu?: number

	    /** Value for monitoring file activity. Possible values are: userDefined, disable, monitorAllFiles, monitorIncomingFilesOnly, monitorOutgoingFilesOnly. */
		defenderMonitorFileActivity?: DefenderMonitorFileActivity

	    /** Gets or sets Defender’s action to take on Potentially Unwanted Application (PUA), which includes software with behaviors of ad-injection, software bundling, persistent solicitation for payment or subscription, etc. Defender alerts user when PUA is being downloaded or attempts to install itself. Added in Windows 10 for desktop. Possible values are: deviceDefault, block, audit. */
		defenderPotentiallyUnwantedAppAction?: DefenderPotentiallyUnwantedAppAction

		defenderPotentiallyUnwantedAppActionSetting?: DefenderProtectionType

	    /** Processes to exclude from scans and real time protection. */
		defenderProcessesToExclude?: string[]

	    /** The configuration for how to prompt user for sample submission. Possible values are: userDefined, alwaysPrompt, promptBeforeSendingPersonalData, neverSendData, sendAllDataWithoutPrompting. */
		defenderPromptForSampleSubmission?: DefenderPromptForSampleSubmission

	    /** Indicates whether or not to require behavior monitoring. */
		defenderRequireBehaviorMonitoring?: boolean

	    /** Indicates whether or not to require cloud protection. */
		defenderRequireCloudProtection?: boolean

	    /** Indicates whether or not to require network inspection system. */
		defenderRequireNetworkInspectionSystem?: boolean

	    /** Indicates whether or not to require real time monitoring. */
		defenderRequireRealTimeMonitoring?: boolean

	    /** Indicates whether or not to scan archive files. */
		defenderScanArchiveFiles?: boolean

	    /** Indicates whether or not to scan downloads. */
		defenderScanDownloads?: boolean

	    /** Indicates whether or not to scan files opened from a network folder. */
		defenderScanNetworkFiles?: boolean

	    /** Indicates whether or not to scan incoming mail messages. */
		defenderScanIncomingMail?: boolean

	    /** Indicates whether or not to scan mapped network drives during full scan. */
		defenderScanMappedNetworkDrivesDuringFullScan?: boolean

	    /** Indicates whether or not to scan removable drives during full scan. */
		defenderScanRemovableDrivesDuringFullScan?: boolean

	    /** Indicates whether or not to scan scripts loaded in Internet Explorer browser. */
		defenderScanScriptsLoadedInInternetExplorer?: boolean

	    /** The signature update interval in hours. Specify 0 not to check. Valid values 0 to 24 */
		defenderSignatureUpdateIntervalInHours?: number

	    /** The defender system scan type. Possible values are: userDefined, disabled, quick, full. */
		defenderScanType?: DefenderScanType

	    /** The defender time for the system scan. */
		defenderScheduledScanTime?: string

	    /** The time to perform a daily quick scan. */
		defenderScheduledQuickScanTime?: string

	    /** Specifies the level of cloud-delivered protection. Possible values are: notConfigured, high, highPlus, zeroTolerance. */
		defenderCloudBlockLevel?: DefenderCloudBlockLevelType

	    /** Timeout extension for file scanning by the cloud. Valid values 0 to 50 */
		defenderCloudExtendedTimeout?: number

		defenderCloudExtendedTimeoutInSeconds?: number

	    /** Allows or disallows Windows Defender On Access Protection functionality. */
		defenderBlockOnAccessProtection?: boolean

	    /** Selects the day that the Windows Defender scan should run. Possible values are: everyday, monday, tuesday, wednesday, thursday, friday, saturday, sunday, noScheduledScan. */
		defenderScheduleScanDay?: DefenderScheduleScanDay

	    /** Checks for the user consent level in Windows Defender to send data. Possible values are: sendSafeSamplesAutomatically, alwaysPrompt, neverSend, sendAllSamplesAutomatically. */
		defenderSubmitSamplesConsentType?: DefenderSubmitSamplesConsentType

	    /** Specify whether to show a user-configurable setting to control the screen timeout while on the lock screen of Windows 10 Mobile devices. If this policy is set to Allow, the value set by lockScreenTimeoutInSeconds is ignored. */
		lockScreenAllowTimeoutConfiguration?: boolean

	    /** Indicates whether or not to block action center notifications over lock screen. */
		lockScreenBlockActionCenterNotifications?: boolean

	    /** Indicates whether or not the user can interact with Cortana using speech while the system is locked. */
		lockScreenBlockCortana?: boolean

	    /** Indicates whether to allow toast notifications above the device lock screen. */
		lockScreenBlockToastNotifications?: boolean

	    /** Set the duration (in seconds) from the screen locking to the screen turning off for Windows 10 Mobile devices. Supported values are 11-1800. Valid values 11 to 1800 */
		lockScreenTimeoutInSeconds?: number

	    /** Specify whether PINs or passwords such as "1111" or "1234" are allowed. For Windows 10 desktops, it also controls the use of picture passwords. */
		passwordBlockSimple?: boolean

	    /** The password expiration in days. Valid values 0 to 730 */
		passwordExpirationDays?: number

	    /** The minimum password length. Valid values 4 to 16 */
		passwordMinimumLength?: number

	    /** The minutes of inactivity before the screen times out. */
		passwordMinutesOfInactivityBeforeScreenTimeout?: number

	    /** The number of character sets required in the password. */
		passwordMinimumCharacterSetCount?: number

	    /** The number of previous passwords to prevent reuse of. Valid values 0 to 50 */
		passwordPreviousPasswordBlockCount?: number

	    /** Indicates whether or not to require the user to have a password. */
		passwordRequired?: boolean

	    /** Indicates whether or not to require a password upon resuming from an idle state. */
		passwordRequireWhenResumeFromIdleState?: boolean

	    /** The required password type. Possible values are: deviceDefault, alphanumeric, numeric. */
		passwordRequiredType?: RequiredPasswordType

	    /** The number of sign in failures before factory reset. Valid values 0 to 999 */
		passwordSignInFailureCountBeforeFactoryReset?: number

		passwordMinimumAgeInDays?: number

	    /** Enables or disables the use of advertising ID. Added in Windows 10, version 1607. Possible values are: notConfigured, blocked, allowed. */
		privacyAdvertisingId?: StateManagementSetting

	    /** Indicates whether or not to allow the automatic acceptance of the pairing and privacy user consent dialog when launching apps. */
		privacyAutoAcceptPairingAndConsentPrompts?: boolean

	    /** Indicates whether or not to block the usage of cloud based speech services for Cortana, Dictation, or Store applications. */
		privacyBlockInputPersonalization?: boolean

	    /** Blocks the shared experiences/discovery of recently used resources in task switcher etc. */
		privacyBlockPublishUserActivities?: boolean

	    /** Blocks the usage of cloud based speech services for Cortana, Dictation, or Store applications */
		privacyBlockActivityFeed?: boolean

	    /** Indicates whether or not to block the user from unpinning apps from taskbar. */
		startBlockUnpinningAppsFromTaskbar?: boolean

	    /** Setting the value of this collapses the app list, removes the app list entirely, or disables the corresponding toggle in the Settings app. Possible values are: userDefined, collapse, remove, disableSettingsApp. */
		startMenuAppListVisibility?: WindowsStartMenuAppListVisibilityType

	    /** Enabling this policy hides the change account setting from appearing in the user tile in the start menu. */
		startMenuHideChangeAccountSettings?: boolean

	    /** Enabling this policy hides the most used apps from appearing on the start menu and disables the corresponding toggle in the Settings app. */
		startMenuHideFrequentlyUsedApps?: boolean

	    /** Enabling this policy hides hibernate from appearing in the power button in the start menu. */
		startMenuHideHibernate?: boolean

	    /** Enabling this policy hides lock from appearing in the user tile in the start menu. */
		startMenuHideLock?: boolean

	    /** Enabling this policy hides the power button from appearing in the start menu. */
		startMenuHidePowerButton?: boolean

	    /** Enabling this policy hides recent jump lists from appearing on the start menu/taskbar and disables the corresponding toggle in the Settings app. */
		startMenuHideRecentJumpLists?: boolean

	    /** Enabling this policy hides recently added apps from appearing on the start menu and disables the corresponding toggle in the Settings app. */
		startMenuHideRecentlyAddedApps?: boolean

	    /** Enabling this policy hides “Restart/Update and Restart” from appearing in the power button in the start menu. */
		startMenuHideRestartOptions?: boolean

	    /** Enabling this policy hides shut down/update and shut down from appearing in the power button in the start menu. */
		startMenuHideShutDown?: boolean

	    /** Enabling this policy hides sign out from appearing in the user tile in the start menu. */
		startMenuHideSignOut?: boolean

	    /** Enabling this policy hides sleep from appearing in the power button in the start menu. */
		startMenuHideSleep?: boolean

	    /** Enabling this policy hides switch account from appearing in the user tile in the start menu. */
		startMenuHideSwitchAccount?: boolean

	    /** Enabling this policy hides the user tile from appearing in the start menu. */
		startMenuHideUserTile?: boolean

	    /** This policy setting allows you to import Edge assets to be used with startMenuLayoutXml policy. Start layout can contain secondary tile from Edge app which looks for Edge local asset file. Edge local asset would not exist and cause Edge secondary tile to appear empty in this case. This policy only gets applied when startMenuLayoutXml policy is modified. The value should be a UTF-8 Base64 encoded byte array. */
		startMenuLayoutEdgeAssetsXml?: number

	    /** Allows admins to override the default Start menu layout and prevents the user from changing it. The layout is modified by specifying an XML file based on a layout modification schema. XML needs to be in a UTF8 encoded byte array format. */
		startMenuLayoutXml?: number

	    /** Allows admins to decide how the Start menu is displayed. Possible values are: userDefined, fullScreen, nonFullScreen. */
		startMenuMode?: WindowsStartMenuModeType

	    /** Enforces the visibility (Show/Hide) of the Documents folder shortcut on the Start menu. Possible values are: notConfigured, hide, show. */
		startMenuPinnedFolderDocuments?: VisibilitySetting

	    /** Enforces the visibility (Show/Hide) of the Downloads folder shortcut on the Start menu. Possible values are: notConfigured, hide, show. */
		startMenuPinnedFolderDownloads?: VisibilitySetting

	    /** Enforces the visibility (Show/Hide) of the FileExplorer shortcut on the Start menu. Possible values are: notConfigured, hide, show. */
		startMenuPinnedFolderFileExplorer?: VisibilitySetting

	    /** Enforces the visibility (Show/Hide) of the HomeGroup folder shortcut on the Start menu. Possible values are: notConfigured, hide, show. */
		startMenuPinnedFolderHomeGroup?: VisibilitySetting

	    /** Enforces the visibility (Show/Hide) of the Music folder shortcut on the Start menu. Possible values are: notConfigured, hide, show. */
		startMenuPinnedFolderMusic?: VisibilitySetting

	    /** Enforces the visibility (Show/Hide) of the Network folder shortcut on the Start menu. Possible values are: notConfigured, hide, show. */
		startMenuPinnedFolderNetwork?: VisibilitySetting

	    /** Enforces the visibility (Show/Hide) of the PersonalFolder shortcut on the Start menu. Possible values are: notConfigured, hide, show. */
		startMenuPinnedFolderPersonalFolder?: VisibilitySetting

	    /** Enforces the visibility (Show/Hide) of the Pictures folder shortcut on the Start menu. Possible values are: notConfigured, hide, show. */
		startMenuPinnedFolderPictures?: VisibilitySetting

	    /** Enforces the visibility (Show/Hide) of the Settings folder shortcut on the Start menu. Possible values are: notConfigured, hide, show. */
		startMenuPinnedFolderSettings?: VisibilitySetting

	    /** Enforces the visibility (Show/Hide) of the Videos folder shortcut on the Start menu. Possible values are: notConfigured, hide, show. */
		startMenuPinnedFolderVideos?: VisibilitySetting

	    /** Indicates whether or not to block access to Settings app. */
		settingsBlockSettingsApp?: boolean

	    /** Indicates whether or not to block access to System in Settings app. */
		settingsBlockSystemPage?: boolean

	    /** Indicates whether or not to block access to Devices in Settings app. */
		settingsBlockDevicesPage?: boolean

	    /** Indicates whether or not to block access to Network & Internet in Settings app. */
		settingsBlockNetworkInternetPage?: boolean

	    /** Indicates whether or not to block access to Personalization in Settings app. */
		settingsBlockPersonalizationPage?: boolean

	    /** Indicates whether or not to block access to Accounts in Settings app. */
		settingsBlockAccountsPage?: boolean

	    /** Indicates whether or not to block access to Time & Language in Settings app. */
		settingsBlockTimeLanguagePage?: boolean

	    /** Indicates whether or not to block access to Ease of Access in Settings app. */
		settingsBlockEaseOfAccessPage?: boolean

	    /** Indicates whether or not to block access to Privacy in Settings app. */
		settingsBlockPrivacyPage?: boolean

	    /** Indicates whether or not to block access to Update & Security in Settings app. */
		settingsBlockUpdateSecurityPage?: boolean

	    /** Indicates whether or not to block access to Apps in Settings app. */
		settingsBlockAppsPage?: boolean

	    /** Indicates whether or not to block access to Gaming in Settings app. */
		settingsBlockGamingPage?: boolean

	    /** Allows IT admins to block experiences that are typically for consumers only, such as Start suggestions, Membership notifications, Post-OOBE app install and redirect tiles. */
		windowsSpotlightBlockConsumerSpecificFeatures?: boolean

	    /** Allows IT admins to turn off all Windows Spotlight features */
		windowsSpotlightBlocked?: boolean

	    /** Block suggestions from Microsoft that show after each OS clean install, upgrade or in an on-going basis to introduce users to what is new or changed */
		windowsSpotlightBlockOnActionCenter?: boolean

	    /** Block personalized content in Windows spotlight based on user’s device usage. */
		windowsSpotlightBlockTailoredExperiences?: boolean

	    /** Block third party content delivered via Windows Spotlight */
		windowsSpotlightBlockThirdPartyNotifications?: boolean

	    /** Block Windows Spotlight Windows welcome experience */
		windowsSpotlightBlockWelcomeExperience?: boolean

	    /** Allows IT admins to turn off the popup of Windows Tips. */
		windowsSpotlightBlockWindowsTips?: boolean

	    /** Specifies the type of Spotlight. Possible values are: notConfigured, disabled, enabled. */
		windowsSpotlightConfigureOnLockScreen?: WindowsSpotlightEnablementSettings

	    /** If set, proxy settings will be applied to all processes and accounts in the device. Otherwise, it will be applied to the user account that’s enrolled into MDM. */
		networkProxyApplySettingsDeviceWide?: boolean

	    /** Disable automatic detection of settings. If enabled, the system will try to find the path to a proxy auto-config (PAC) script. */
		networkProxyDisableAutoDetect?: boolean

	    /** Address to the proxy auto-config (PAC) script you want to use. */
		networkProxyAutomaticConfigurationUrl?: string

	    /** Specifies manual proxy server settings. */
		networkProxyServer?: Windows10NetworkProxyServer

	    /** Indicates whether or not to Block the user from adding email accounts to the device that are not associated with a Microsoft account. */
		accountsBlockAddingNonMicrosoftAccountEmail?: boolean

	    /** Indicates whether or not to block the user from selecting an AntiTheft mode preference (Windows 10 Mobile only). */
		antiTheftModeBlocked?: boolean

	    /** Whether or not to Block the user from using bluetooth. */
		bluetoothBlocked?: boolean

	    /** Whether or not to Block the user from accessing the camera of the device. */
		cameraBlocked?: boolean

	    /** Whether or not to block Connected Devices Service which enables discovery and connection to other devices, remote messaging, remote app sessions and other cross-device experiences. */
		connectedDevicesServiceBlocked?: boolean

	    /** Whether or not to Block the user from doing manual root certificate installation. */
		certificatesBlockManualRootCertificateInstallation?: boolean

	    /** Whether or not to Block the user from using copy paste. */
		copyPasteBlocked?: boolean

	    /** Whether or not to Block the user from using Cortana. */
		cortanaBlocked?: boolean

	    /** Indicates whether or not to Block the user from resetting their phone. */
		deviceManagementBlockFactoryResetOnMobile?: boolean

	    /** Indicates whether or not to Block the user from doing manual un-enrollment from device management. */
		deviceManagementBlockManualUnenroll?: boolean

	    /** Specifies what filter level of safe search is required. Possible values are: userDefined, strict, moderate. */
		safeSearchFilter?: SafeSearchFilterType

	    /** Indicates whether or not to block popups. */
		edgeBlockPopups?: boolean

	    /** Indicates whether or not to Block the user from using the search suggestions in the address bar. */
		edgeBlockSearchSuggestions?: boolean

	    /** Indicates whether or not to Block the user from sending Intranet traffic to Internet Explorer from Edge. */
		edgeBlockSendingIntranetTrafficToInternetExplorer?: boolean

	    /** Indicates whether or not to Require the user to use the smart screen filter. */
		edgeRequireSmartScreen?: boolean

	    /** Indicates the enterprise mode site list location. Could be a local file, local network or http location. */
		edgeEnterpriseModeSiteListLocation?: string

	    /** The first run URL for when Edge browser is opened for the first time. */
		edgeFirstRunUrl?: string

	    /** Allows IT admins to set a default search engine for MDM-Controlled devices. Users can override this and change their default search engine provided the AllowSearchEngineCustomization policy is not set. */
		edgeSearchEngine?: EdgeSearchEngineBase

	    /** The list of URLs for homepages shodwn on MDM-enrolled devices on Edge browser. */
		edgeHomepageUrls?: string[]

	    /** Indicates whether or not to prevent access to about flags on Edge browser. */
		edgeBlockAccessToAboutFlags?: boolean

	    /** Indicates whether or not users can override SmartScreen Filter warnings about potentially malicious websites. */
		smartScreenBlockPromptOverride?: boolean

	    /** Indicates whether or not users can override the SmartScreen Filter warnings about downloading unverified files */
		smartScreenBlockPromptOverrideForFiles?: boolean

	    /** Indicates whether or not user's localhost IP address is displayed while making phone calls using the WebRTC */
		webRtcBlockLocalhostIpAddress?: boolean

	    /** Indicates whether or not to Block the user from using internet sharing. */
		internetSharingBlocked?: boolean

	    /** Indicates whether or not to block the user from installing provisioning packages. */
		settingsBlockAddProvisioningPackage?: boolean

	    /** Indicates whether or not to block the runtime configuration agent from removing provisioning packages. */
		settingsBlockRemoveProvisioningPackage?: boolean

	    /** Indicates whether or not to block the user from changing date and time settings. */
		settingsBlockChangeSystemTime?: boolean

	    /** Indicates whether or not to block the user from editing the device name. */
		settingsBlockEditDeviceName?: boolean

	    /** Indicates whether or not to block the user from changing the region settings. */
		settingsBlockChangeRegion?: boolean

	    /** Indicates whether or not to block the user from changing the language settings. */
		settingsBlockChangeLanguage?: boolean

	    /** Indicates whether or not to block the user from changing power and sleep settings. */
		settingsBlockChangePowerSleep?: boolean

	    /** Indicates whether or not to Block the user from location services. */
		locationServicesBlocked?: boolean

	    /** Indicates whether or not to Block a Microsoft account. */
		microsoftAccountBlocked?: boolean

	    /** Indicates whether or not to Block Microsoft account settings sync. */
		microsoftAccountBlockSettingsSync?: boolean

	    /** Indicates whether or not to Block the user from using near field communication. */
		nfcBlocked?: boolean

	    /** Indicates whether or not to Block the user from reset protection mode. */
		resetProtectionModeBlocked?: boolean

	    /** Indicates whether or not to Block the user from taking Screenshots. */
		screenCaptureBlocked?: boolean

	    /** Indicates whether or not to Block the user from using removable storage. */
		storageBlockRemovableStorage?: boolean

	    /** Indicating whether or not to require encryption on a mobile device. */
		storageRequireMobileDeviceEncryption?: boolean

	    /** Indicates whether or not to Block the user from USB connection. */
		usbBlocked?: boolean

	    /** Indicates whether or not to Block the user from voice recording. */
		voiceRecordingBlocked?: boolean

	    /** Indicating whether or not to block automatically connecting to Wi-Fi hotspots. Has no impact if Wi-Fi is blocked. */
		wiFiBlockAutomaticConnectHotspots?: boolean

	    /** Indicates whether or not to Block the user from using Wi-Fi. */
		wiFiBlocked?: boolean

	    /** Indicates whether or not to Block the user from using Wi-Fi manual configuration. */
		wiFiBlockManualConfiguration?: boolean

	    /** Specify how often devices scan for Wi-Fi networks. Supported values are 1-500, where 100 = default, and 500 = low frequency. Valid values 1 to 500 */
		wiFiScanInterval?: number

	    /** Indicates whether or not to allow other devices from discovering this PC for projection. */
		wirelessDisplayBlockProjectionToThisDevice?: boolean

	    /** Indicates whether or not to allow user input from wireless display receiver. */
		wirelessDisplayBlockUserInputFromReceiver?: boolean

	    /** Indicates whether or not to require a PIN for new devices to initiate pairing. */
		wirelessDisplayRequirePinForPairing?: boolean

	    /** Indicates whether or not to Block the user from using the Windows store. */
		windowsStoreBlocked?: boolean

	    /** Indicates whether apps from AppX packages signed with a trusted certificate can be side loaded. Possible values are: notConfigured, blocked, allowed. */
		appsAllowTrustedAppsSideloading?: StateManagementSetting

	    /** Indicates whether or not to block automatic update of apps from Windows Store. */
		windowsStoreBlockAutoUpdate?: boolean

	    /** Indicates whether or not to allow developer unlock. Possible values are: notConfigured, blocked, allowed. */
		developerUnlockSetting?: StateManagementSetting

	    /** Indicates whether or not to block multiple users of the same app to share data. */
		sharedUserAppDataAllowed?: boolean

	    /** Indicates whether or not to disable the launch of all apps from Windows Store that came pre-installed or were downloaded. */
		appsBlockWindowsStoreOriginatedApps?: boolean

	    /** Indicates whether or not to enable Private Store Only. */
		windowsStoreEnablePrivateStoreOnly?: boolean

	    /** Indicates whether application data is restricted to the system drive. */
		storageRestrictAppDataToSystemVolume?: boolean

	    /** Indicates whether the installation of applications is restricted to the system drive. */
		storageRestrictAppInstallToSystemVolume?: boolean

	    /** Indicates whether or not to block DVR and broadcasting. */
		gameDvrBlocked?: boolean

	    /** Indicates whether or not to enable device discovery UX. */
		experienceBlockDeviceDiscovery?: boolean

	    /** Indicates whether or not to allow the error dialog from displaying if no SIM card is detected. */
		experienceBlockErrorDialogWhenNoSIM?: boolean

	    /** Indicates whether or not to enable task switching on the device. */
		experienceBlockTaskSwitcher?: boolean

	    /** Disables the ability to quickly switch between users that are logged on simultaneously without logging off. */
		logonBlockFastUserSwitching?: boolean

		tenantLockdownRequireNetworkDuringOutOfBoxExperience?: boolean

		appManagementMSIAllowUserControlOverInstall?: boolean

		appManagementMSIAlwaysInstallWithElevatedPrivileges?: boolean

		dataProtectionBlockDirectMemoryAccess?: boolean

	    /** This policy setting allows to define a list of assigned access profiles for multi app mode. */
		assignedAccessMultiModeProfiles?: WindowsAssignedAccessProfile[]

	    /** Indicates a list of applications with their access control levels over privacy data categories, and/or the default access levels per category. */
		privacyAccessControls?: WindowsPrivacyDataAccessControlItem[]

}

export interface Windows10NetworkBoundaryConfiguration extends DeviceConfiguration {

	    /** Windows Network Isolation Policy */
		windowsNetworkIsolationPolicy?: WindowsNetworkIsolationPolicy

}

export interface Windows10CustomConfiguration extends DeviceConfiguration {

	    /** OMA settings. This collection can contain a maximum of 1000 elements. */
		omaSettings?: OmaSetting[]

}

export interface WindowsIdentityProtectionConfiguration extends DeviceConfiguration {

		enhancedAntiSpoofingForFacialFeaturesEnabled?: boolean

		pinMinimumLength?: number

		pinMaximumLength?: number

		pinUppercaseCharactersUsage?: ConfigurationUsage

		pinLowercaseCharactersUsage?: ConfigurationUsage

		pinSpecialCharactersUsage?: ConfigurationUsage

		pinExpirationInDays?: number

		pinPreviousBlockCount?: number

		pinRecoveryEnabled?: boolean

		securityDeviceRequired?: boolean

		unlockWithBiometricsEnabled?: boolean

		useCertificatesForOnPremisesAuthEnabled?: boolean

		windowsHelloForBusinessBlocked?: boolean

}

export interface WindowsKioskConfiguration extends DeviceConfiguration {

	    /** This policy setting allows to define a list of Kiosk profiles for a Kiosk configuration. This collection can contain a maximum of 500 elements. */
		kioskProfiles?: WindowsKioskProfile[]

	    /** Specify the default URL the browser should navigate to on launch. */
		kioskBrowserDefaultUrl?: string

	    /** Enable the kiosk browser's home button. By default, the home button is disabled. */
		kioskBrowserEnableHomeButton?: boolean

	    /** Enable the kiosk browser's navigation buttons(forward/back). By default, the navigation buttons are disabled. */
		kioskBrowserEnableNavigationButtons?: boolean

		kioskBrowserEnableEndSessionButton?: boolean

	    /** Specify the number of minutes the session is idle until the kiosk browser restarts in a fresh state.  Valid values are 1-1440. Valid values 1 to 1440 */
		kioskBrowserRestartOnIdleTimeInMinutes?: number

	    /** Specify URLs that the kiosk browsers should not navigate to */
		kioskBrowserBlockedURLs?: string[]

	    /** Specify URLs that the kiosk browser is allowed to navigate to */
		kioskBrowserBlockedUrlExceptions?: string[]

}

export interface Windows10EnterpriseModernAppManagementConfiguration extends DeviceConfiguration {

	    /** Indicates whether or not to uninstall a fixed list of built-in Windows apps. */
		uninstallBuiltInApps?: boolean

}

export interface SharedPCConfiguration extends DeviceConfiguration {

	    /** Specifies how accounts are managed on a shared PC. Only applies when disableAccountManager is false. */
		accountManagerPolicy?: SharedPCAccountManagerPolicy

	    /** Indicates which type of accounts are allowed to use on a shared PC. Possible values are: guest, domain. */
		allowedAccounts?: SharedPCAllowedAccountType

		localStorage?: Enablement

	    /** Specifies whether local storage is allowed on a shared PC. */
		allowLocalStorage?: boolean

		setAccountManager?: Enablement

	    /** Disables the account manager for shared PC mode. */
		disableAccountManager?: boolean

		setEduPolicies?: Enablement

	    /** Specifies whether the default shared PC education environment policies should be disabled. For Windows 10 RS2 and later, this policy will be applied without setting Enabled to true. */
		disableEduPolicies?: boolean

		setPowerPolicies?: Enablement

	    /** Specifies whether the default shared PC power policies should be disabled. */
		disablePowerPolicies?: boolean

		signInOnResume?: Enablement

	    /** Disables the requirement to sign in whenever the device wakes up from sleep mode. */
		disableSignInOnResume?: boolean

	    /** Enables shared PC mode and applies the shared pc policies. */
		enabled?: boolean

	    /** Specifies the time in seconds that a device must sit idle before the PC goes to sleep. Setting this value to 0 prevents the sleep timeout from occurring. */
		idleTimeBeforeSleepInSeconds?: number

	    /** Specifies the display text for the account shown on the sign-in screen which launches the app specified by SetKioskAppUserModelId. Only applies when KioskAppUserModelId is set. */
		kioskAppDisplayName?: string

	    /** Specifies the application user model ID of the app to use with assigned access. */
		kioskAppUserModelId?: string

	    /** Specifies the daily start time of maintenance hour. */
		maintenanceStartTime?: string

}

export interface Windows10PFXImportCertificateProfile extends DeviceConfiguration {

	    /** Not yet documented. Possible values are: useTpmKspOtherwiseUseSoftwareKsp, useTpmKspOtherwiseFail, usePassportForWorkKspOtherwiseFail, useSoftwareKsp. */
		keyStorageProvider?: KeyStorageProviderOption

}

export interface Windows10SecureAssessmentConfiguration extends DeviceConfiguration {

	    /** Url link to an assessment that's automatically loaded when the secure assessment browser is launched. It has to be a valid Url (http[s]://msdn.microsoft.com/). */
		launchUri?: string

	    /** The account used to configure the Windows device for taking the test. The user can be a domain account (domain\user), an AAD account (username@tenant.com) or a local account (username). */
		configurationAccount?: string

	    /** The account type used to by ConfigurationAccount. Possible values are: azureADAccount, domainAccount, localAccount. */
		configurationAccountType?: SecureAssessmentAccountType

	    /** Indicates whether or not to allow the app from printing during the test. */
		allowPrinting?: boolean

	    /** Indicates whether or not to allow screen capture capability during a test. */
		allowScreenCapture?: boolean

	    /** Indicates whether or not to allow text suggestions during the test. */
		allowTextSuggestion?: boolean

}

export interface WindowsWifiConfiguration extends DeviceConfiguration {

		wifiSecurityType?: WiFiSecurityType

		ssid?: string

		networkName?: string

		connectAutomatically?: boolean

		connectToPreferredNetwork?: boolean

		connectWhenNetworkNameIsHidden?: boolean

		proxySetting?: WiFiProxySetting

		proxyManualAddress?: string

		proxyManualPort?: number

		proxyAutomaticConfigurationUrl?: string

		forceFIPSCompliance?: boolean

}

export interface WindowsWifiEnterpriseEAPConfiguration extends WindowsWifiConfiguration {

		networkSingleSignOn?: NetworkSingleSignOnType

		maximumAuthenticationTimeoutInSeconds?: number

		promptForAdditionalAuthenticationCredentials?: boolean

		enablePairwiseMasterKeyCaching?: boolean

		maximumPairwiseMasterKeyCacheTimeInMinutes?: number

		maximumNumberOfPairwiseMasterKeysInCache?: number

		enablePreAuthentication?: boolean

		maximumPreAuthenticationAttempts?: number

		eapType?: EapType

		trustedServerCertificateNames?: string[]

		authenticationMethod?: WiFiAuthenticationMethod

		innerAuthenticationProtocolForEAPTTLS?: NonEapAuthenticationMethodForEapTtlsType

		outerIdentityPrivacyTemporaryValue?: string

		rootCertificatesForServerValidation?: Windows81TrustedRootCertificate[]

		identityCertificateForClientAuthentication?: WindowsCertificateProfileBase

}

export interface Windows81TrustedRootCertificate extends DeviceConfiguration {

	    /** Trusted Root Certificate */
		trustedRootCertificate?: number

	    /** File name to display in UI. */
		certFileName?: string

	    /** Destination store location for the Trusted Root Certificate. Possible values are: computerCertStoreRoot, computerCertStoreIntermediate, userCertStoreIntermediate. */
		destinationStore?: CertificateDestinationStore

}

export interface WindowsCertificateProfileBase extends DeviceConfiguration {

	    /** Certificate renewal threshold percentage. Valid values 1 to 99 */
		renewalThresholdPercentage?: number

	    /** Key Storage Provider (KSP). Possible values are: useTpmKspOtherwiseUseSoftwareKsp, useTpmKspOtherwiseFail, usePassportForWorkKspOtherwiseFail, useSoftwareKsp. */
		keyStorageProvider?: KeyStorageProviderOption

	    /** Certificate Subject Name Format. Possible values are: commonName, commonNameIncludingEmail, commonNameAsEmail, custom, commonNameAsIMEI, commonNameAsSerialNumber, commonNameAsAadDeviceId, commonNameAsIntuneDeviceId, commonNameAsDurableDeviceId. */
		subjectNameFormat?: SubjectNameFormat

	    /** Certificate Subject Alternative Name Type. Possible values are: none, emailAddress, userPrincipalName, customAzureADAttribute. */
		subjectAlternativeNameType?: SubjectAlternativeNameType

	    /** Value for the Certificate Validity Period */
		certificateValidityPeriodValue?: number

	    /** Scale for the Certificate Validity Period. Possible values are: days, months, years. */
		certificateValidityPeriodScale?: CertificateValidityPeriodScale

}

export interface Windows10ImportedPFXCertificateProfile extends WindowsCertificateProfileBase {

	    /** Not yet documented. Possible values are: unassigned, smimeEncryption, smimeSigning, vpn, wifi. */
		intendedPurpose?: IntendedPurpose

		managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface WindowsPhone81ImportedPFXCertificateProfile extends WindowsCertificateProfileBase {

	    /** Not yet documented. Possible values are: unassigned, smimeEncryption, smimeSigning, vpn, wifi. */
		intendedPurpose?: IntendedPurpose

		managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface Windows10CertificateProfileBase extends WindowsCertificateProfileBase {

}

export interface Windows10PkcsCertificateProfile extends Windows10CertificateProfileBase {

	    /** PKCS Certification Authority */
		certificationAuthority?: string

	    /** PKCS Certification Authority Name */
		certificationAuthorityName?: string

	    /** PKCS Certificate Template Name */
		certificateTemplateName?: string

	    /** Custom String that defines the AAD Attribute. */
		subjectAlternativeNameFormatString?: string

		extendedKeyUsages?: ExtendedKeyUsage[]

		managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface Windows81CertificateProfileBase extends WindowsCertificateProfileBase {

	    /** Extended Key Usage (EKU) settings. This collection can contain a maximum of 500 elements. */
		extendedKeyUsages?: ExtendedKeyUsage[]

		customSubjectAlternativeNames?: CustomSubjectAlternativeName[]

}

export interface Windows81SCEPCertificateProfile extends Windows81CertificateProfileBase {

	    /** SCEP Server Url(s). */
		scepServerUrls?: string[]

	    /** Custom format to use with SubjectNameFormat = Custom. Example: CN={{EmailAddress}},E={{EmailAddress}},OU=Enterprise Users,O=Contoso Corporation,L=Redmond,ST=WA,C=US */
		subjectNameFormatString?: string

	    /** SCEP Key Usage. Possible values are: keyEncipherment, digitalSignature. */
		keyUsage?: KeyUsages

	    /** SCEP Key Size. Possible values are: size1024, size2048. */
		keySize?: KeySize

	    /** SCEP Hash Algorithm. Possible values are: sha1, sha2. */
		hashAlgorithm?: HashAlgorithms

	    /** Custom String that defines the AAD Attribute. */
		subjectAlternativeNameFormatString?: string

	    /** Target store certificate. Possible values are: user, machine. */
		certificateStore?: CertificateStore

	    /** Trusted Root Certificate */
		rootCertificate?: Windows81TrustedRootCertificate

	    /** Certificate state for devices */
		managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface Windows81WifiImportConfiguration extends DeviceConfiguration {

	    /** Payload file name (.xml). */
		payloadFileName?: string

	    /** Profile name displayed in the UI. */
		profileName?: string

	    /** Payload. (UTF8 encoded byte array). This is the XML file saved on the device you used to connect to the Wi-Fi endpoint. */
		payload?: number

}

export interface WindowsDomainJoinConfiguration extends DeviceConfiguration {

	    /** Fixed prefix to be used for computer name. */
		computerNameStaticPrefix?: string

	    /** Dynamically generated characters used as suffix for computer name. Valid values 3 to 14 */
		computerNameSuffixRandomCharCount?: number

	    /** Active Directory domain name to join. */
		activeDirectoryDomainName?: string

		organizationalUnit?: string

	    /** Reference to device configurations required for network connectivity */
		networkAccessConfigurations?: DeviceConfiguration[]

}

export interface WindowsPhone81CustomConfiguration extends DeviceConfiguration {

	    /** OMA settings. This collection can contain a maximum of 1000 elements. */
		omaSettings?: OmaSetting[]

}

export interface WindowsPhone81TrustedRootCertificate extends DeviceConfiguration {

	    /** Trusted Root Certificate */
		trustedRootCertificate?: number

	    /** File name to display in UI. */
		certFileName?: string

}

export interface WindowsUpdateForBusinessConfiguration extends DeviceConfiguration {

	    /** Delivery Optimization Mode. Possible values are: userDefined, httpOnly, httpWithPeeringNat, httpWithPeeringPrivateGroup, httpWithInternetPeering, simpleDownload, bypassMode. */
		deliveryOptimizationMode?: WindowsDeliveryOptimizationMode

	    /** The pre-release features. Possible values are: userDefined, settingsOnly, settingsAndExperimentations, notAllowed. */
		prereleaseFeatures?: PrereleaseFeatures

	    /** Automatic update mode. Possible values are: userDefined, notifyDownload, autoInstallAtMaintenanceTime, autoInstallAndRebootAtMaintenanceTime, autoInstallAndRebootAtScheduledTime, autoInstallAndRebootWithoutEndUserControl. */
		automaticUpdateMode?: AutomaticUpdateMode

	    /** Allow Microsoft Update Service */
		microsoftUpdateServiceAllowed?: boolean

	    /** Exclude Windows update Drivers */
		driversExcluded?: boolean

	    /** Installation schedule */
		installationSchedule?: WindowsUpdateInstallScheduleType

	    /** Defer Quality Updates by these many days */
		qualityUpdatesDeferralPeriodInDays?: number

	    /** Defer Feature Updates by these many days */
		featureUpdatesDeferralPeriodInDays?: number

	    /** Pause Quality Updates */
		qualityUpdatesPaused?: boolean

	    /** Pause Feature Updates */
		featureUpdatesPaused?: boolean

	    /** Quality Updates Pause Expiry datetime */
		qualityUpdatesPauseExpiryDateTime?: string

	    /** Feature Updates Pause Expiry datetime */
		featureUpdatesPauseExpiryDateTime?: string

	    /** Determines which branch devices will receive their updates from. Possible values are: userDefined, all, businessReadyOnly, windowsInsiderBuildFast, windowsInsiderBuildSlow, windowsInsiderBuildRelease. */
		businessReadyUpdatesOnly?: WindowsUpdateType

	    /** Set to skip all check before restart: Battery level = 40%, User presence, Display Needed, Presentation mode, Full screen mode, phone call state, game mode etc. */
		skipChecksBeforeRestart?: boolean

	    /** Scheduled the update installation on the weeks of the month. Possible values are: userDefined, firstWeek, secondWeek, thirdWeek, fourthWeek, everyWeek. */
		updateWeeks?: WindowsUpdateForBusinessUpdateWeeks

		qualityUpdatesPauseStartDateTime?: string

		featureUpdatesPauseStartDateTime?: string

		featureUpdatesRollbackWindowInDays?: number

		qualityUpdatesWillBeRolledBack?: boolean

		featureUpdatesWillBeRolledBack?: boolean

		qualityUpdatesRollbackStartDateTime?: string

		featureUpdatesRollbackStartDateTime?: string

}

export interface WindowsVpnConfiguration extends DeviceConfiguration {

	    /** Connection name displayed to the user. */
		connectionName?: string

	    /** List of VPN Servers on the network. Make sure end users can access these network locations. This collection can contain a maximum of 500 elements. */
		servers?: VpnServer[]

	    /** Custom XML commands that configures the VPN connection. (UTF8 encoded byte array) */
		customXml?: number

}

export interface Windows10VpnConfiguration extends WindowsVpnConfiguration {

	    /** Profile target type. Possible values are: user, device, autoPilotDevice. */
		profileTarget?: Windows10VpnProfileTarget

	    /** Connection type. Possible values are: pulseSecure, f5EdgeClient, dellSonicWallMobileConnect, checkPointCapsuleVpn, automatic, ikEv2, l2tp, pptp, citrix, paloAltoGlobalProtect. */
		connectionType?: Windows10VpnConnectionType

	    /** Enable split tunneling. */
		enableSplitTunneling?: boolean

	    /** Enable Always On mode. */
		enableAlwaysOn?: boolean

	    /** Enable device tunnel. */
		enableDeviceTunnel?: boolean

		enableDnsRegistration?: boolean

		dnsSuffixes?: string[]

	    /** Authentication method. Possible values are: certificate, usernameAndPassword, customEapXml. */
		authenticationMethod?: Windows10VpnAuthenticationMethod

	    /** Remember user credentials. */
		rememberUserCredentials?: boolean

	    /** Enable conditional access. */
		enableConditionalAccess?: boolean

	    /** Enable single sign-on (SSO) with alternate certificate. */
		enableSingleSignOnWithAlternateCertificate?: boolean

	    /** Single sign-on Extended Key Usage (EKU). */
		singleSignOnEku?: ExtendedKeyUsage

	    /** Single sign-on issuer hash. */
		singleSignOnIssuerHash?: string

	    /** Extensible Authentication Protocol (EAP) XML. (UTF8 encoded byte array) */
		eapXml?: number

	    /** Proxy Server. */
		proxyServer?: Windows10VpnProxyServer

	    /** Associated Apps. This collection can contain a maximum of 10000 elements. */
		associatedApps?: Windows10AssociatedApps[]

	    /** Only associated Apps can use connection (per-app VPN). */
		onlyAssociatedAppsCanUseConnection?: boolean

	    /** Windows Information Protection (WIP) domain to associate with this connection. */
		windowsInformationProtectionDomain?: string

	    /** Traffic rules. This collection can contain a maximum of 1000 elements. */
		trafficRules?: VpnTrafficRule[]

	    /** Routes (optional for third-party providers). This collection can contain a maximum of 1000 elements. */
		routes?: VpnRoute[]

	    /** DNS rules. This collection can contain a maximum of 1000 elements. */
		dnsRules?: VpnDnsRule[]

	    /** Identity certificate for client authentication when authentication method is certificate. */
		identityCertificate?: WindowsCertificateProfileBase

}

export interface Windows81VpnConfiguration extends WindowsVpnConfiguration {

	    /** Value indicating whether this policy only applies to Windows 8.1. This property is read-only. */
		applyOnlyToWindows81?: boolean

	    /** Connection type. Possible values are: pulseSecure, f5EdgeClient, dellSonicWallMobileConnect, checkPointCapsuleVpn. */
		connectionType?: WindowsVpnConnectionType

	    /** Login group or domain when connection type is set to Dell SonicWALL Mobile Connection. */
		loginGroupOrDomain?: string

	    /** Enable split tunneling for the VPN. */
		enableSplitTunneling?: boolean

	    /** Proxy Server. */
		proxyServer?: Windows81VpnProxyServer

}

export interface WindowsPhone81VpnConfiguration extends Windows81VpnConfiguration {

	    /** Bypass VPN on company Wi-Fi. */
		bypassVpnOnCompanyWifi?: boolean

	    /** Bypass VPN on home Wi-Fi. */
		bypassVpnOnHomeWifi?: boolean

	    /** Authentication method. Possible values are: certificate, usernameAndPassword. */
		authenticationMethod?: VpnAuthenticationMethod

	    /** Remember user credentials. */
		rememberUserCredentials?: boolean

	    /** DNS suffix search list. */
		dnsSuffixSearchList?: string[]

	    /** Identity certificate for client authentication when authentication method is certificate. */
		identityCertificate?: WindowsPhone81CertificateProfileBase

}

export interface WindowsPhone81CertificateProfileBase extends DeviceConfiguration {

	    /** Certificate renewal threshold percentage. */
		renewalThresholdPercentage?: number

	    /** Key Storage Provider (KSP). Possible values are: useTpmKspOtherwiseUseSoftwareKsp, useTpmKspOtherwiseFail, usePassportForWorkKspOtherwiseFail, useSoftwareKsp. */
		keyStorageProvider?: KeyStorageProviderOption

	    /** Certificate Subject Name Format. Possible values are: commonName, commonNameIncludingEmail, commonNameAsEmail, custom, commonNameAsIMEI, commonNameAsSerialNumber, commonNameAsAadDeviceId, commonNameAsIntuneDeviceId, commonNameAsDurableDeviceId. */
		subjectNameFormat?: SubjectNameFormat

	    /** Certificate Subject Alternative Name Type. Possible values are: none, emailAddress, userPrincipalName, customAzureADAttribute. */
		subjectAlternativeNameType?: SubjectAlternativeNameType

	    /** Value for the Certificate Validtiy Period. */
		certificateValidityPeriodValue?: number

	    /** Scale for the Certificate Validity Period. Possible values are: days, months, years. */
		certificateValidityPeriodScale?: CertificateValidityPeriodScale

	    /** Extended Key Usage (EKU) settings. This collection can contain a maximum of 500 elements. */
		extendedKeyUsages?: ExtendedKeyUsage[]

}

export interface WindowsPhone81SCEPCertificateProfile extends WindowsPhone81CertificateProfileBase {

	    /** SCEP Server Url(s). */
		scepServerUrls?: string[]

	    /** Custom format to use with SubjectNameFormat = Custom. Example: CN={{EmailAddress}},E={{EmailAddress}},OU=Enterprise Users,O=Contoso Corporation,L=Redmond,ST=WA,C=US */
		subjectNameFormatString?: string

	    /** SCEP Key Usage. Possible values are: keyEncipherment, digitalSignature. */
		keyUsage?: KeyUsages

	    /** SCEP Key Size. Possible values are: size1024, size2048. */
		keySize?: KeySize

	    /** SCEP Hash Algorithm. Possible values are: sha1, sha2. */
		hashAlgorithm?: HashAlgorithms

	    /** Custom String that defines the AAD Attribute. */
		subjectAlternativeNameFormatString?: string

	    /** Trusted Root Certificate. */
		rootCertificate?: WindowsPhone81TrustedRootCertificate

	    /** Certificate state for devices */
		managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface Windows81GeneralConfiguration extends DeviceConfiguration {

	    /** Indicates whether or not to Block the user from adding email accounts to the device that are not associated with a Microsoft account. */
		accountsBlockAddingNonMicrosoftAccountEmail?: boolean

	    /** Value indicating whether this policy only applies to Windows 8.1. This property is read-only. */
		applyOnlyToWindows81?: boolean

	    /** Indicates whether or not to block auto fill. */
		browserBlockAutofill?: boolean

	    /** Indicates whether or not to block automatic detection of Intranet sites. */
		browserBlockAutomaticDetectionOfIntranetSites?: boolean

	    /** Indicates whether or not to block enterprise mode access. */
		browserBlockEnterpriseModeAccess?: boolean

	    /** Indicates whether or not to Block the user from using JavaScript. */
		browserBlockJavaScript?: boolean

	    /** Indicates whether or not to block plug-ins. */
		browserBlockPlugins?: boolean

	    /** Indicates whether or not to block popups. */
		browserBlockPopups?: boolean

	    /** Indicates whether or not to Block the user from sending the do not track header. */
		browserBlockSendingDoNotTrackHeader?: boolean

	    /** Indicates whether or not to block a single word entry on Intranet sites. */
		browserBlockSingleWordEntryOnIntranetSites?: boolean

	    /** Indicates whether or not to require the user to use the smart screen filter. */
		browserRequireSmartScreen?: boolean

	    /** The enterprise mode site list location. Could be a local file, local network or http location. */
		browserEnterpriseModeSiteListLocation?: string

	    /** The internet security level. Possible values are: userDefined, medium, mediumHigh, high. */
		browserInternetSecurityLevel?: InternetSiteSecurityLevel

	    /** The Intranet security level. Possible values are: userDefined, low, mediumLow, medium, mediumHigh, high. */
		browserIntranetSecurityLevel?: SiteSecurityLevel

	    /** The logging report location. */
		browserLoggingReportLocation?: string

	    /** Indicates whether or not to require high security for restricted sites. */
		browserRequireHighSecurityForRestrictedSites?: boolean

	    /** Indicates whether or not to require a firewall. */
		browserRequireFirewall?: boolean

	    /** Indicates whether or not to require fraud warning. */
		browserRequireFraudWarning?: boolean

	    /** The trusted sites security level. Possible values are: userDefined, low, mediumLow, medium, mediumHigh, high. */
		browserTrustedSitesSecurityLevel?: SiteSecurityLevel

	    /** Indicates whether or not to block data roaming. */
		cellularBlockDataRoaming?: boolean

	    /** Indicates whether or not to block diagnostic data submission. */
		diagnosticsBlockDataSubmission?: boolean

	    /** Indicates whether or not to Block the user from using a pictures password and pin. */
		passwordBlockPicturePasswordAndPin?: boolean

	    /** Password expiration in days. */
		passwordExpirationDays?: number

	    /** The minimum password length. */
		passwordMinimumLength?: number

	    /** The minutes of inactivity before the screen times out. */
		passwordMinutesOfInactivityBeforeScreenTimeout?: number

	    /** The number of character sets required in the password. */
		passwordMinimumCharacterSetCount?: number

	    /** The number of previous passwords to prevent re-use of. Valid values 0 to 24 */
		passwordPreviousPasswordBlockCount?: number

	    /** The required password type. Possible values are: deviceDefault, alphanumeric, numeric. */
		passwordRequiredType?: RequiredPasswordType

	    /** The number of sign in failures before factory reset. */
		passwordSignInFailureCountBeforeFactoryReset?: number

	    /** Indicates whether or not to require encryption on a mobile device. */
		storageRequireDeviceEncryption?: boolean

	    /** The minimum update classification to install automatically. Possible values are: userDefined, recommendedAndImportant, important, none. */
		minimumAutoInstallClassification?: UpdateClassification

		updatesMinimumAutoInstallClassification?: UpdateClassification

	    /** Indicates whether or not to require automatic updates. */
		updatesRequireAutomaticUpdates?: boolean

	    /** The user account control settings. Possible values are: userDefined, alwaysNotify, notifyOnAppChanges, notifyOnAppChangesWithoutDimming, neverNotify. */
		userAccountControlSettings?: WindowsUserAccountControlSettings

	    /** The work folders url. */
		workFoldersUrl?: string

}

export interface WindowsPhone81GeneralConfiguration extends DeviceConfiguration {

	    /** Value indicating whether this policy only applies to Windows Phone 8.1. This property is read-only. */
		applyOnlyToWindowsPhone81?: boolean

	    /** Indicates whether or not to block copy paste. */
		appsBlockCopyPaste?: boolean

	    /** Indicates whether or not to block bluetooth. */
		bluetoothBlocked?: boolean

	    /** Indicates whether or not to block camera. */
		cameraBlocked?: boolean

	    /** Indicates whether or not to block Wi-Fi tethering. Has no impact if Wi-Fi is blocked. */
		cellularBlockWifiTethering?: boolean

	    /** List of apps in the compliance (either allow list or block list, controlled by CompliantAppListType). This collection can contain a maximum of 10000 elements. */
		compliantAppsList?: AppListItem[]

	    /** List that is in the AppComplianceList. Possible values are: none, appsInListCompliant, appsNotInListCompliant. */
		compliantAppListType?: AppListType

	    /** Indicates whether or not to block diagnostic data submission. */
		diagnosticDataBlockSubmission?: boolean

	    /** Indicates whether or not to block custom email accounts. */
		emailBlockAddingAccounts?: boolean

	    /** Indicates whether or not to block location services. */
		locationServicesBlocked?: boolean

	    /** Indicates whether or not to block using a Microsoft Account. */
		microsoftAccountBlocked?: boolean

	    /** Indicates whether or not to block Near-Field Communication. */
		nfcBlocked?: boolean

	    /** Indicates whether or not to block syncing the calendar. */
		passwordBlockSimple?: boolean

	    /** Number of days before the password expires. */
		passwordExpirationDays?: number

	    /** Minimum length of passwords. */
		passwordMinimumLength?: number

	    /** Minutes of inactivity before screen timeout. */
		passwordMinutesOfInactivityBeforeScreenTimeout?: number

	    /** Number of character sets a password must contain. */
		passwordMinimumCharacterSetCount?: number

	    /** Number of previous passwords to block. Valid values 0 to 24 */
		passwordPreviousPasswordBlockCount?: number

	    /** Number of sign in failures allowed before factory reset. */
		passwordSignInFailureCountBeforeFactoryReset?: number

	    /** Password type that is required. Possible values are: deviceDefault, alphanumeric, numeric. */
		passwordRequiredType?: RequiredPasswordType

	    /** Indicates whether or not to require a password. */
		passwordRequired?: boolean

	    /** Indicates whether or not to block screenshots. */
		screenCaptureBlocked?: boolean

	    /** Indicates whether or not to block removable storage. */
		storageBlockRemovableStorage?: boolean

	    /** Indicates whether or not to require encryption. */
		storageRequireEncryption?: boolean

	    /** Indicates whether or not to block the web browser. */
		webBrowserBlocked?: boolean

	    /** Indicates whether or not to block Wi-Fi. */
		wifiBlocked?: boolean

	    /** Indicates whether or not to block automatically connecting to Wi-Fi hotspots. Has no impact if Wi-Fi is blocked. */
		wifiBlockAutomaticConnectHotspots?: boolean

	    /** Indicates whether or not to block Wi-Fi hotspot reporting. Has no impact if Wi-Fi is blocked. */
		wifiBlockHotspotReporting?: boolean

	    /** Indicates whether or not to block the Windows Store. */
		windowsStoreBlocked?: boolean

}

export interface Windows10TeamGeneralConfiguration extends DeviceConfiguration {

	    /** Indicates whether or not to Block Azure Operational Insights. */
		azureOperationalInsightsBlockTelemetry?: boolean

	    /** The Azure Operational Insights workspace id. */
		azureOperationalInsightsWorkspaceId?: string

	    /** The Azure Operational Insights Workspace key. */
		azureOperationalInsightsWorkspaceKey?: string

	    /** Specifies whether to automatically launch the Connect app whenever a projection is initiated. */
		connectAppBlockAutoLaunch?: boolean

	    /** Indicates whether or not to Block setting a maintenance window for device updates. */
		maintenanceWindowBlocked?: boolean

	    /** Maintenance window duration for device updates. Valid values 0 to 5 */
		maintenanceWindowDurationInHours?: number

	    /** Maintenance window start time for device updates. */
		maintenanceWindowStartTime?: string

	    /** The channel. Possible values are: userDefined, one, two, three, four, five, six, seven, eight, nine, ten, eleven, thirtySix, forty, fortyFour, fortyEight, oneHundredFortyNine, oneHundredFiftyThree, oneHundredFiftySeven, oneHundredSixtyOne, oneHundredSixtyFive. */
		miracastChannel?: MiracastChannel

	    /** Indicates whether or not to Block wireless projection. */
		miracastBlocked?: boolean

	    /** Indicates whether or not to require a pin for wireless projection. */
		miracastRequirePin?: boolean

	    /** Specifies whether to disable the "My meetings and files" feature in the Start menu, which shows the signed-in user's meetings and files from Office 365. */
		settingsBlockMyMeetingsAndFiles?: boolean

	    /** Specifies whether to allow the ability to resume a session when the session times out. */
		settingsBlockSessionResume?: boolean

	    /** Specifies whether to disable auto-populating of the sign-in dialog with invitees from scheduled meetings. */
		settingsBlockSigninSuggestions?: boolean

	    /** Specifies the default volume value for a new session. Permitted values are 0-100. The default is 45. Valid values 0 to 100 */
		settingsDefaultVolume?: number

	    /** Specifies the number of minutes until the Hub screen turns off. */
		settingsScreenTimeoutInMinutes?: number

	    /** Specifies the number of minutes until the session times out. */
		settingsSessionTimeoutInMinutes?: number

	    /** Specifies the number of minutes until the Hub enters sleep mode. */
		settingsSleepTimeoutInMinutes?: number

	    /** Indicates whether or not to Block the welcome screen from waking up automatically when someone enters the room. */
		welcomeScreenBlockAutomaticWakeUp?: boolean

	    /** The welcome screen background image URL. The URL must use the HTTPS protocol and return a PNG image. */
		welcomeScreenBackgroundImageUrl?: string

	    /** The welcome screen meeting information shown. Possible values are: userDefined, showOrganizerAndTimeOnly, showOrganizerAndTimeAndSubject. */
		welcomeScreenMeetingInformation?: WelcomeScreenMeetingInformation

}

export interface DeviceCompliancePolicyGroupAssignment extends Entity {

		targetGroupId?: string

		excludeGroup?: boolean

		deviceCompliancePolicy?: DeviceCompliancePolicy

}

export interface AndroidForWorkCompliancePolicy extends DeviceCompliancePolicy {

	    /** Require a password to unlock device. */
		passwordRequired?: boolean

	    /** Minimum password length. Valid values 4 to 16 */
		passwordMinimumLength?: number

	    /** Type of characters in password. Possible values are: deviceDefault, alphabetic, alphanumeric, alphanumericWithSymbols, lowSecurityBiometric, numeric, numericComplex, any. */
		passwordRequiredType?: AndroidRequiredPasswordType

	    /** Minutes of inactivity before a password is required. */
		passwordMinutesOfInactivityBeforeLock?: number

	    /** Number of days before the password expires. Valid values 1 to 365 */
		passwordExpirationDays?: number

	    /** Number of previous passwords to block. */
		passwordPreviousPasswordBlockCount?: number

	    /** Require that devices disallow installation of apps from unknown sources. */
		securityPreventInstallAppsFromUnknownSources?: boolean

	    /** Disable USB debugging on Android devices. */
		securityDisableUsbDebugging?: boolean

	    /** Require the Android Verify apps feature is turned on. */
		securityRequireVerifyApps?: boolean

	    /** Require that devices have enabled device threat protection. */
		deviceThreatProtectionEnabled?: boolean

	    /** Require Mobile Threat Protection minimum risk level to report noncompliance. Possible values are: unavailable, secured, low, medium, high, notSet. */
		deviceThreatProtectionRequiredSecurityLevel?: DeviceThreatProtectionLevel

	    /** Devices must not be jailbroken or rooted. */
		securityBlockJailbrokenDevices?: boolean

	    /** Minimum Android version. */
		osMinimumVersion?: string

	    /** Maximum Android version. */
		osMaximumVersion?: string

	    /** Minimum Android security patch level. */
		minAndroidSecurityPatchLevel?: string

	    /** Require encryption on Android devices. */
		storageRequireEncryption?: boolean

	    /** Require the device to pass the SafetyNet basic integrity check. */
		securityRequireSafetyNetAttestationBasicIntegrity?: boolean

	    /** Require the device to pass the SafetyNet certified device check. */
		securityRequireSafetyNetAttestationCertifiedDevice?: boolean

	    /** Require Google Play Services to be installed and enabled on the device. */
		securityRequireGooglePlayServices?: boolean

	    /** Require the device to have up to date security providers. The device will require Google Play Services to be enabled and up to date. */
		securityRequireUpToDateSecurityProviders?: boolean

	    /** Require the device to pass the Company Portal client app runtime integrity check. */
		securityRequireCompanyPortalAppIntegrity?: boolean

		restrictedApps?: AppListItem[]

}

export interface AndroidCompliancePolicy extends DeviceCompliancePolicy {

	    /** Require a password to unlock device. */
		passwordRequired?: boolean

	    /** Minimum password length. Valid values 4 to 16 */
		passwordMinimumLength?: number

	    /** Type of characters in password. Possible values are: deviceDefault, alphabetic, alphanumeric, alphanumericWithSymbols, lowSecurityBiometric, numeric, numericComplex, any. */
		passwordRequiredType?: AndroidRequiredPasswordType

	    /** Minutes of inactivity before a password is required. */
		passwordMinutesOfInactivityBeforeLock?: number

	    /** Number of days before the password expires. Valid values 1 to 65535 */
		passwordExpirationDays?: number

	    /** Number of previous passwords to block. */
		passwordPreviousPasswordBlockCount?: number

	    /** Require that devices disallow installation of apps from unknown sources. */
		securityPreventInstallAppsFromUnknownSources?: boolean

	    /** Disable USB debugging on Android devices. */
		securityDisableUsbDebugging?: boolean

	    /** Require the Android Verify apps feature is turned on. */
		securityRequireVerifyApps?: boolean

	    /** Require that devices have enabled device threat protection. */
		deviceThreatProtectionEnabled?: boolean

	    /** Require Mobile Threat Protection minimum risk level to report noncompliance. Possible values are: unavailable, secured, low, medium, high, notSet. */
		deviceThreatProtectionRequiredSecurityLevel?: DeviceThreatProtectionLevel

	    /** Devices must not be jailbroken or rooted. */
		securityBlockJailbrokenDevices?: boolean

	    /** Minimum Android version. */
		osMinimumVersion?: string

	    /** Maximum Android version. */
		osMaximumVersion?: string

	    /** Minimum Android security patch level. */
		minAndroidSecurityPatchLevel?: string

	    /** Require encryption on Android devices. */
		storageRequireEncryption?: boolean

	    /** Require the device to pass the SafetyNet basic integrity check. */
		securityRequireSafetyNetAttestationBasicIntegrity?: boolean

	    /** Require the device to pass the SafetyNet certified device check. */
		securityRequireSafetyNetAttestationCertifiedDevice?: boolean

	    /** Require Google Play Services to be installed and enabled on the device. */
		securityRequireGooglePlayServices?: boolean

	    /** Require the device to have up to date security providers. The device will require Google Play Services to be enabled and up to date. */
		securityRequireUpToDateSecurityProviders?: boolean

	    /** Require the device to pass the Company Portal client app runtime integrity check. */
		securityRequireCompanyPortalAppIntegrity?: boolean

	    /** Condition statement id. */
		conditionStatementId?: string

}

export interface AndroidDeviceComplianceLocalActionBase extends Entity {

		gracePeriodInMinutes?: number

}

export interface AndroidDeviceComplianceLocalActionLockDevice extends AndroidDeviceComplianceLocalActionBase {

}

export interface AndroidDeviceComplianceLocalActionLockDeviceWithPasscode extends AndroidDeviceComplianceLocalActionBase {

		passcode?: string

		passcodeSignInFailureCountBeforeWipe?: number

}

export interface AndroidWorkProfileCompliancePolicy extends DeviceCompliancePolicy {

	    /** Require a password to unlock device. */
		passwordRequired?: boolean

	    /** Minimum password length. Valid values 4 to 16 */
		passwordMinimumLength?: number

	    /** Type of characters in password. Possible values are: deviceDefault, alphabetic, alphanumeric, alphanumericWithSymbols, lowSecurityBiometric, numeric, numericComplex, any. */
		passwordRequiredType?: AndroidRequiredPasswordType

	    /** Minutes of inactivity before a password is required. */
		passwordMinutesOfInactivityBeforeLock?: number

	    /** Number of days before the password expires. Valid values 1 to 365 */
		passwordExpirationDays?: number

	    /** Number of previous passwords to block. */
		passwordPreviousPasswordBlockCount?: number

	    /** Require that devices disallow installation of apps from unknown sources. */
		securityPreventInstallAppsFromUnknownSources?: boolean

	    /** Disable USB debugging on Android devices. */
		securityDisableUsbDebugging?: boolean

	    /** Require the Android Verify apps feature is turned on. */
		securityRequireVerifyApps?: boolean

	    /** Require that devices have enabled device threat protection. */
		deviceThreatProtectionEnabled?: boolean

	    /** Require Mobile Threat Protection minimum risk level to report noncompliance. Possible values are: unavailable, secured, low, medium, high, notSet. */
		deviceThreatProtectionRequiredSecurityLevel?: DeviceThreatProtectionLevel

	    /** Devices must not be jailbroken or rooted. */
		securityBlockJailbrokenDevices?: boolean

	    /** Minimum Android version. */
		osMinimumVersion?: string

	    /** Maximum Android version. */
		osMaximumVersion?: string

	    /** Minimum Android security patch level. */
		minAndroidSecurityPatchLevel?: string

	    /** Require encryption on Android devices. */
		storageRequireEncryption?: boolean

	    /** Require the device to pass the SafetyNet basic integrity check. */
		securityRequireSafetyNetAttestationBasicIntegrity?: boolean

	    /** Require the device to pass the SafetyNet certified device check. */
		securityRequireSafetyNetAttestationCertifiedDevice?: boolean

	    /** Require Google Play Services to be installed and enabled on the device. */
		securityRequireGooglePlayServices?: boolean

	    /** Require the device to have up to date security providers. The device will require Google Play Services to be enabled and up to date. */
		securityRequireUpToDateSecurityProviders?: boolean

	    /** Require the device to pass the Company Portal client app runtime integrity check. */
		securityRequireCompanyPortalAppIntegrity?: boolean

		restrictedApps?: AppListItem[]

}

export interface IosCompliancePolicy extends DeviceCompliancePolicy {

	    /** Indicates whether or not to block simple passcodes. */
		passcodeBlockSimple?: boolean

	    /** Number of days before the passcode expires. Valid values 1 to 65535 */
		passcodeExpirationDays?: number

	    /** Minimum length of passcode. Valid values 4 to 14 */
		passcodeMinimumLength?: number

	    /** Minutes of inactivity before a passcode is required. */
		passcodeMinutesOfInactivityBeforeLock?: number

	    /** Number of previous passcodes to block. Valid values 1 to 24 */
		passcodePreviousPasscodeBlockCount?: number

	    /** The number of character sets required in the password. */
		passcodeMinimumCharacterSetCount?: number

	    /** The required passcode type. Possible values are: deviceDefault, alphanumeric, numeric. */
		passcodeRequiredType?: RequiredPasswordType

	    /** Indicates whether or not to require a passcode. */
		passcodeRequired?: boolean

	    /** Minimum IOS version. */
		osMinimumVersion?: string

	    /** Maximum IOS version. */
		osMaximumVersion?: string

	    /** Devices must not be jailbroken or rooted. */
		securityBlockJailbrokenDevices?: boolean

	    /** Require that devices have enabled device threat protection . */
		deviceThreatProtectionEnabled?: boolean

	    /** Require Mobile Threat Protection minimum risk level to report noncompliance. Possible values are: unavailable, secured, low, medium, high, notSet. */
		deviceThreatProtectionRequiredSecurityLevel?: DeviceThreatProtectionLevel

	    /** Indicates whether or not to require a managed email profile. */
		managedEmailProfileRequired?: boolean

		restrictedApps?: AppListItem[]

}

export interface MacOSCompliancePolicy extends DeviceCompliancePolicy {

	    /** Whether or not to require a password. */
		passwordRequired?: boolean

	    /** Indicates whether or not to block simple passwords. */
		passwordBlockSimple?: boolean

	    /** Number of days before the password expires. Valid values 1 to 65535 */
		passwordExpirationDays?: number

	    /** Minimum length of password. Valid values 4 to 14 */
		passwordMinimumLength?: number

	    /** Minutes of inactivity before a password is required. */
		passwordMinutesOfInactivityBeforeLock?: number

	    /** Number of previous passwords to block. Valid values 1 to 24 */
		passwordPreviousPasswordBlockCount?: number

	    /** The number of character sets required in the password. */
		passwordMinimumCharacterSetCount?: number

	    /** The required password type. Possible values are: deviceDefault, alphanumeric, numeric. */
		passwordRequiredType?: RequiredPasswordType

	    /** Minimum IOS version. */
		osMinimumVersion?: string

	    /** Maximum IOS version. */
		osMaximumVersion?: string

	    /** Require that devices have enabled system integrity protection. */
		systemIntegrityProtectionEnabled?: boolean

	    /** Require that devices have enabled device threat protection . */
		deviceThreatProtectionEnabled?: boolean

	    /** Require Mobile Threat Protection minimum risk level to report noncompliance. Possible values are: unavailable, secured, low, medium, high, notSet. */
		deviceThreatProtectionRequiredSecurityLevel?: DeviceThreatProtectionLevel

	    /** Require encryption on Mac OS devices. */
		storageRequireEncryption?: boolean

		firewallEnabled?: boolean

		firewallBlockAllIncoming?: boolean

		firewallEnableStealthMode?: boolean

}

export interface DefaultDeviceCompliancePolicy extends DeviceCompliancePolicy {

}

export interface Windows10CompliancePolicy extends DeviceCompliancePolicy {

	    /** Require a password to unlock Windows device. */
		passwordRequired?: boolean

	    /** Indicates whether or not to block simple password. */
		passwordBlockSimple?: boolean

	    /** Require a password to unlock an idle device. */
		passwordRequiredToUnlockFromIdle?: boolean

	    /** Minutes of inactivity before a password is required. */
		passwordMinutesOfInactivityBeforeLock?: number

	    /** The password expiration in days. */
		passwordExpirationDays?: number

	    /** The minimum password length. */
		passwordMinimumLength?: number

	    /** The number of character sets required in the password. */
		passwordMinimumCharacterSetCount?: number

	    /** The required password type. Possible values are: deviceDefault, alphanumeric, numeric. */
		passwordRequiredType?: RequiredPasswordType

	    /** The number of previous passwords to prevent re-use of. */
		passwordPreviousPasswordBlockCount?: number

	    /** Require devices to be reported as healthy by Windows Device Health Attestation. */
		requireHealthyDeviceReport?: boolean

	    /** Minimum Windows 10 version. */
		osMinimumVersion?: string

	    /** Maximum Windows 10 version. */
		osMaximumVersion?: string

	    /** Minimum Windows Phone version. */
		mobileOsMinimumVersion?: string

	    /** Maximum Windows Phone version. */
		mobileOsMaximumVersion?: string

	    /** Require devices to be reported as healthy by Windows Device Health Attestation - early launch antimalware driver is enabled. */
		earlyLaunchAntiMalwareDriverEnabled?: boolean

	    /** Require devices to be reported healthy by Windows Device Health Attestation - bit locker is enabled */
		bitLockerEnabled?: boolean

	    /** Require devices to be reported as healthy by Windows Device Health Attestation - secure boot is enabled. */
		secureBootEnabled?: boolean

	    /** Require devices to be reported as healthy by Windows Device Health Attestation. */
		codeIntegrityEnabled?: boolean

	    /** Require encryption on windows devices. */
		storageRequireEncryption?: boolean

	    /** Require active firewall on Windows devices. */
		activeFirewallRequired?: boolean

	    /** Require Windows Defender Antimalware on Windows devices. */
		defenderEnabled?: boolean

	    /** Require Windows Defender Antimalware minimum version on Windows devices. */
		defenderVersion?: string

	    /** Require Windows Defender Antimalware Signature to be up to date on Windows devices. */
		signatureOutOfDate?: boolean

	    /** Require Windows Defender Antimalware Real-Time Protection on Windows devices. */
		rtpEnabled?: boolean

		antivirusRequired?: boolean

		antiSpywareRequired?: boolean

	    /** The valid operating system build ranges on Windows devices. This collection can contain a maximum of 10000 elements. */
		validOperatingSystemBuildRanges?: OperatingSystemVersionRange[]

	    /** Require that devices have enabled device threat protection. */
		deviceThreatProtectionEnabled?: boolean

	    /** Require Device Threat Protection minimum risk level to report noncompliance. Possible values are: unavailable, secured, low, medium, high, notSet. */
		deviceThreatProtectionRequiredSecurityLevel?: DeviceThreatProtectionLevel

		configurationManagerComplianceRequired?: boolean

}

export interface Windows10MobileCompliancePolicy extends DeviceCompliancePolicy {

	    /** Require a password to unlock Windows Phone device. */
		passwordRequired?: boolean

	    /** Whether or not to block syncing the calendar. */
		passwordBlockSimple?: boolean

	    /** Minimum password length. Valid values 4 to 16 */
		passwordMinimumLength?: number

	    /** The number of character sets required in the password. */
		passwordMinimumCharacterSetCount?: number

	    /** The required password type. Possible values are: deviceDefault, alphanumeric, numeric. */
		passwordRequiredType?: RequiredPasswordType

	    /** The number of previous passwords to prevent re-use of. */
		passwordPreviousPasswordBlockCount?: number

	    /** Number of days before password expiration. Valid values 1 to 255 */
		passwordExpirationDays?: number

	    /** Minutes of inactivity before a password is required. */
		passwordMinutesOfInactivityBeforeLock?: number

	    /** Require a password to unlock an idle device. */
		passwordRequireToUnlockFromIdle?: boolean

	    /** Minimum Windows Phone version. */
		osMinimumVersion?: string

	    /** Maximum Windows Phone version. */
		osMaximumVersion?: string

	    /** Require devices to be reported as healthy by Windows Device Health Attestation - early launch antimalware driver is enabled. */
		earlyLaunchAntiMalwareDriverEnabled?: boolean

	    /** Require devices to be reported healthy by Windows Device Health Attestation - bit locker is enabled */
		bitLockerEnabled?: boolean

	    /** Require devices to be reported as healthy by Windows Device Health Attestation - secure boot is enabled. */
		secureBootEnabled?: boolean

	    /** Require devices to be reported as healthy by Windows Device Health Attestation. */
		codeIntegrityEnabled?: boolean

	    /** Require encryption on windows devices. */
		storageRequireEncryption?: boolean

	    /** Require active firewall on Windows devices. */
		activeFirewallRequired?: boolean

	    /** The valid operating system build ranges on Windows devices. This collection can contain a maximum of 10000 elements. */
		validOperatingSystemBuildRanges?: OperatingSystemVersionRange[]

}

export interface Windows81CompliancePolicy extends DeviceCompliancePolicy {

	    /** Require a password to unlock Windows device. */
		passwordRequired?: boolean

	    /** Indicates whether or not to block simple password. */
		passwordBlockSimple?: boolean

	    /** Password expiration in days. */
		passwordExpirationDays?: number

	    /** The minimum password length. */
		passwordMinimumLength?: number

	    /** Minutes of inactivity before a password is required. */
		passwordMinutesOfInactivityBeforeLock?: number

	    /** The number of character sets required in the password. */
		passwordMinimumCharacterSetCount?: number

	    /** The required password type. Possible values are: deviceDefault, alphanumeric, numeric. */
		passwordRequiredType?: RequiredPasswordType

	    /** The number of previous passwords to prevent re-use of. Valid values 0 to 24 */
		passwordPreviousPasswordBlockCount?: number

	    /** Minimum Windows 8.1 version. */
		osMinimumVersion?: string

	    /** Maximum Windows 8.1 version. */
		osMaximumVersion?: string

	    /** Indicates whether or not to require encryption on a windows 8.1 device. */
		storageRequireEncryption?: boolean

}

export interface WindowsPhone81CompliancePolicy extends DeviceCompliancePolicy {

	    /** Whether or not to block syncing the calendar. */
		passwordBlockSimple?: boolean

	    /** Number of days before the password expires. */
		passwordExpirationDays?: number

	    /** Minimum length of passwords. */
		passwordMinimumLength?: number

	    /** Minutes of inactivity before a password is required. */
		passwordMinutesOfInactivityBeforeLock?: number

	    /** The number of character sets required in the password. */
		passwordMinimumCharacterSetCount?: number

	    /** The required password type. Possible values are: deviceDefault, alphanumeric, numeric. */
		passwordRequiredType?: RequiredPasswordType

	    /** Number of previous passwords to block. Valid values 0 to 24 */
		passwordPreviousPasswordBlockCount?: number

	    /** Whether or not to require a password. */
		passwordRequired?: boolean

	    /** Minimum Windows Phone version. */
		osMinimumVersion?: string

	    /** Maximum Windows Phone version. */
		osMaximumVersion?: string

	    /** Require encryption on windows phone devices. */
		storageRequireEncryption?: boolean

}

export interface DeviceSetupConfiguration extends Entity {

		createdDateTime?: string

		description?: string

		lastModifiedDateTime?: string

		displayName?: string

		version?: number

}

export interface DeviceComplianceSettingState extends Entity {

	    /** Device platform type. Possible values are: desktop, windowsRT, winMO6, nokia, windowsPhone, mac, winCE, winEmbedded, iPhone, iPad, iPod, android, iSocConsumer, unix, macMDM, holoLens, surfaceHub, androidForWork, androidEnterprise, blackberry, palm, unknown. */
		platformType?: DeviceType

	    /** The setting class name and property name. */
		setting?: string

	    /** The Setting Name that is being reported */
		settingName?: string

	    /** The Device Id that is being reported */
		deviceId?: string

	    /** The Device Name that is being reported */
		deviceName?: string

	    /** The user Id that is being reported */
		userId?: string

	    /** The User email address that is being reported */
		userEmail?: string

	    /** The User Name that is being reported */
		userName?: string

	    /** The User PrincipalName that is being reported */
		userPrincipalName?: string

	    /** The device model that is being reported */
		deviceModel?: string

	    /** The compliance state of the setting. Possible values are: unknown, notApplicable, compliant, remediated, nonCompliant, error, conflict. */
		state?: ComplianceStatus

	    /** The DateTime when device compliance grace period expires */
		complianceGracePeriodExpirationDateTime?: string

}

export interface AdvancedThreatProtectionOnboardingDeviceSettingState extends Entity {

		platformType?: DeviceType

		setting?: string

		settingName?: string

		deviceId?: string

		deviceName?: string

		userId?: string

		userEmail?: string

		userName?: string

		userPrincipalName?: string

		deviceModel?: string

		state?: ComplianceStatus

		complianceGracePeriodExpirationDateTime?: string

}

export interface EnrollmentConfigurationAssignment extends Entity {

	    /** Not yet documented */
		target?: DeviceAndAppManagementAssignmentTarget

}

export interface DeviceEnrollmentLimitConfiguration extends DeviceEnrollmentConfiguration {

	    /** Not yet documented */
		limit?: number

}

export interface DeviceEnrollmentPlatformRestrictionsConfiguration extends DeviceEnrollmentConfiguration {

	    /** Not yet documented */
		iosRestriction?: DeviceEnrollmentPlatformRestriction

	    /** Not yet documented */
		windowsRestriction?: DeviceEnrollmentPlatformRestriction

	    /** Not yet documented */
		windowsMobileRestriction?: DeviceEnrollmentPlatformRestriction

	    /** Not yet documented */
		androidRestriction?: DeviceEnrollmentPlatformRestriction

	    /** Not yet documented */
		androidForWorkRestriction?: DeviceEnrollmentPlatformRestriction

	    /** Not yet documented */
		macRestriction?: DeviceEnrollmentPlatformRestriction

	    /** Not yet documented */
		macOSRestriction?: DeviceEnrollmentPlatformRestriction

}

export interface Windows10EnrollmentCompletionPageConfiguration extends DeviceEnrollmentConfiguration {

	    /** Show or hide installation progress to user */
		showInstallationProgress?: boolean

	    /** Allow the user to retry the setup on installation failure */
		blockDeviceSetupRetryByUser?: boolean

	    /** Allow or block device reset on installation failure */
		allowDeviceResetOnInstallFailure?: boolean

	    /** Allow or block log collection on installation failure */
		allowLogCollectionOnInstallFailure?: boolean

	    /** Set custom error message to show upon installation failure */
		customErrorMessage?: string

	    /** Set installation progress timeout in minutes */
		installProgressTimeoutInMinutes?: number

	    /** Allow the user to continue using the device on installation failure */
		allowDeviceUseOnInstallFailure?: boolean

}

export interface DeviceEnrollmentWindowsHelloForBusinessConfiguration extends DeviceEnrollmentConfiguration {

	    /** Not yet documented */
		pinMinimumLength?: number

	    /** Not yet documented */
		pinMaximumLength?: number

	    /** Not yet documented. Possible values are: allowed, required, disallowed. */
		pinUppercaseCharactersUsage?: WindowsHelloForBusinessPinUsage

	    /** Not yet documented. Possible values are: allowed, required, disallowed. */
		pinLowercaseCharactersUsage?: WindowsHelloForBusinessPinUsage

	    /** Not yet documented. Possible values are: allowed, required, disallowed. */
		pinSpecialCharactersUsage?: WindowsHelloForBusinessPinUsage

	    /** Not yet documented. Possible values are: notConfigured, enabled, disabled. */
		state?: Enablement

	    /** Not yet documented */
		securityDeviceRequired?: boolean

	    /** Not yet documented */
		unlockWithBiometricsEnabled?: boolean

	    /** Not yet documented */
		remotePassportEnabled?: boolean

	    /** Not yet documented */
		pinPreviousBlockCount?: number

	    /** Not yet documented */
		pinExpirationInDays?: number

	    /** Not yet documented. Possible values are: notConfigured, enabled, disabled. */
		enhancedBiometricsState?: Enablement

}

export interface LocationManagementCondition extends ManagementCondition {

}

export interface CircularGeofenceManagementCondition extends LocationManagementCondition {

		latitude?: number

		longitude?: number

		radiusInMeters?: number

}

export interface NetworkManagementCondition extends ManagementCondition {

}

export interface NetworkIPv4ConfigurationManagementCondition extends NetworkManagementCondition {

		ipV4Prefix?: string

		ipV4Gateway?: string

		ipV4DHCPServer?: string

		ipV4DNSServerList?: string[]

		dnsSuffixList?: string[]

}

export interface NetworkIPv6ConfigurationManagementCondition extends NetworkManagementCondition {

		ipV6Prefix?: string

		ipV6Gateway?: string

		ipV6DNSServerList?: string[]

		dnsSuffixList?: string[]

}

export interface ManagedMobileApp extends Entity {

	    /** The identifier for an app with it's operating system type. */
		mobileAppIdentifier?: MobileAppIdentifier

	    /** Version of the entity. */
		version?: string

}

export interface TargetedManagedAppPolicyAssignment extends Entity {

	    /** Identifier for deployment of a group or app */
		target?: DeviceAndAppManagementAssignmentTarget

}

export interface ManagedAppOperation extends Entity {

	    /** The operation name. */
		displayName?: string

	    /** The last time the app operation was modified. */
		lastModifiedDateTime?: string

	    /** The current state of the operation */
		state?: string

	    /** Version of the entity. */
		version?: string

}

export interface ManagedAppPolicyDeploymentSummary extends Entity {

	    /** Not yet documented */
		displayName?: string

	    /** Not yet documented */
		configurationDeployedUserCount?: number

	    /** Not yet documented */
		lastRefreshTime?: string

	    /** Not yet documented */
		configurationDeploymentSummaryPerApp?: ManagedAppPolicyDeploymentSummaryPerApp[]

	    /** Version of the entity. */
		version?: string

}

export interface WindowsInformationProtectionAppLockerFile extends Entity {

	    /** The friendly name */
		displayName?: string

	    /** SHA256 hash of the file */
		fileHash?: string

	    /** File as a byte array */
		file?: number

	    /** Version of the entity. */
		version?: string

}

export interface IosManagedAppRegistration extends ManagedAppRegistration {

}

export interface AndroidManagedAppRegistration extends ManagedAppRegistration {

}

export interface ManagedAppStatusRaw extends ManagedAppStatus {

	    /** Status report content. */
		content?: any

}

export interface LocalizedNotificationMessage extends Entity {

	    /** DateTime the object was last modified. */
		lastModifiedDateTime?: string

	    /** The Locale for which this message is destined. */
		locale?: string

	    /** The Message Template Subject. */
		subject?: string

	    /** The Message Template content. */
		messageTemplate?: string

	    /** Flag to indicate whether or not this is the default locale for language fallback. This flag can only be set. To unset, set this property to true on another Localized Notification Message. */
		isDefault?: boolean

}

export interface DeviceAndAppManagementRoleDefinition extends RoleDefinition {

}

export interface EmbeddedSIMActivationCodePoolAssignment extends Entity {

		target?: DeviceAndAppManagementAssignmentTarget

}

export interface EmbeddedSIMDeviceState extends Entity {

		createdDateTime?: string

		modifiedDateTime?: string

		lastSyncDateTime?: string

		universalIntegratedCircuitCardIdentifier?: string

		deviceName?: string

		userName?: string

		state?: EmbeddedSIMDeviceStateValue

		stateDetails?: string

}

export interface ManagedEBookAssignment extends Entity {

	    /** The assignment target for eBook. */
		target?: DeviceAndAppManagementAssignmentTarget

	    /** The install intent for eBook. Possible values are: available, required, uninstall, availableWithoutEnrollment. */
		installIntent?: InstallIntent

}

export interface EBookInstallSummary extends Entity {

	    /** Number of Devices that have successfully installed this book. */
		installedDeviceCount?: number

	    /** Number of Devices that have failed to install this book. */
		failedDeviceCount?: number

	    /** Number of Devices that does not have this book installed. */
		notInstalledDeviceCount?: number

	    /** Number of Users whose devices have all succeeded to install this book. */
		installedUserCount?: number

	    /** Number of Users that have 1 or more device that failed to install this book. */
		failedUserCount?: number

	    /** Number of Users that did not install this book. */
		notInstalledUserCount?: number

}

export interface DeviceInstallState extends Entity {

	    /** Device name. */
		deviceName?: string

	    /** Device Id. */
		deviceId?: string

	    /** Last sync date and time. */
		lastSyncDateTime?: string

	    /** The install state of the eBook. Possible values are: notApplicable, installed, failed, notInstalled, uninstallFailed, unknown. */
		installState?: InstallState

	    /** The error code for install failures. */
		errorCode?: string

	    /** OS Version. */
		osVersion?: string

	    /** OS Description. */
		osDescription?: string

	    /** Device User Name. */
		userName?: string

}

export interface UserInstallStateSummary extends Entity {

	    /** User name. */
		userName?: string

	    /** Installed Device Count. */
		installedDeviceCount?: number

	    /** Failed Device Count. */
		failedDeviceCount?: number

	    /** Not installed device count. */
		notInstalledDeviceCount?: number

	    /** The install state of the eBook. */
		deviceStates?: DeviceInstallState[]

}

export interface IosVppEBookAssignment extends ManagedEBookAssignment {

}

export interface IosVppEBook extends ManagedEBook {

	    /** The Vpp token ID. */
		vppTokenId?: string

	    /** The Apple ID associated with Vpp token. */
		appleId?: string

	    /** The Vpp token's organization name. */
		vppOrganizationName?: string

	    /** Genres. */
		genres?: string[]

	    /** Language. */
		language?: string

	    /** Seller. */
		seller?: string

	    /** Total license count. */
		totalLicenseCount?: number

	    /** Used license count. */
		usedLicenseCount?: number

}

export interface ImportedDeviceIdentityResult extends ImportedDeviceIdentity {

	    /** Status of imported device identity */
		status?: boolean

}

export interface WindowsAutopilotDeploymentProfileAssignment extends Entity {

	    /** The assignment target for the Windows Autopilot deployment profile. */
		target?: DeviceAndAppManagementAssignmentTarget

}

export interface EnrollmentProfile extends Entity {

	    /** Name of the profile */
		displayName?: string

	    /** Description of the profile */
		description?: string

	    /** Indicates if the profile requires user authentication */
		requiresUserAuthentication?: boolean

	    /** Configuration endpoint url to use for Enrollment */
		configurationEndpointUrl?: string

	    /** Indicates to authenticate with Apple Setup Assistant instead of Company Portal. */
		enableAuthenticationViaCompanyPortal?: boolean

}

export interface DepEnrollmentBaseProfile extends EnrollmentProfile {

		isDefault?: boolean

		supervisedModeEnabled?: boolean

		supportDepartment?: string

		passCodeDisabled?: boolean

		isMandatory?: boolean

		locationDisabled?: boolean

		supportPhoneNumber?: string

		profileRemovalDisabled?: boolean

		restoreBlocked?: boolean

		appleIdDisabled?: boolean

		termsAndConditionsDisabled?: boolean

		touchIdDisabled?: boolean

		applePayDisabled?: boolean

		zoomDisabled?: boolean

		siriDisabled?: boolean

		diagnosticsDisabled?: boolean

}

export interface DepIOSEnrollmentProfile extends DepEnrollmentBaseProfile {

		iTunesPairingMode?: ITunesPairingMode

		managementCertificates?: ManagementCertificateWithThumbprint[]

		restoreFromAndroidDisabled?: boolean

		awaitDeviceConfiguredConfirmation?: boolean

		sharedIPadMaximumUserCount?: number

		enableSharedIPad?: boolean

		companyPortalVppTokenId?: string

		enableSingleAppEnrollmentMode?: boolean

}

export interface DepMacOSEnrollmentProfile extends DepEnrollmentBaseProfile {

		registrationDisabled?: boolean

		fileVaultDisabled?: boolean

		iCloudDiagnosticsDisabled?: boolean

}

export interface ImportedAppleDeviceIdentity extends Entity {

	    /** Device serial number */
		serialNumber?: string

	    /** Enrollment profile Id admin intends to apply to the device during next enrollment */
		requestedEnrollmentProfileId?: string

	    /** The time enrollment profile was assigned to the device */
		requestedEnrollmentProfileAssignmentDateTime?: string

	    /** Indicates if the Apple device is supervised. More information is at: https://support.apple.com/en-us/HT202837 */
		isSupervised?: boolean

	    /** Apple device discovery source. Possible values are: unknown, adminImport, deviceEnrollmentProgram. */
		discoverySource?: DiscoverySource

	    /** Created Date Time of the device */
		createdDateTime?: string

	    /** Last Contacted Date Time of the device */
		lastContactedDateTime?: string

	    /** The description of the device */
		description?: string

	    /** The state of the device in Intune. Possible values are: unknown, enrolled, pendingReset, failed, notContacted. */
		enrollmentState?: EnrollmentState

	    /** The platform of the Device. Possible values are: unknown, ios, android, windows, windowsMobile, macOS. */
		platform?: Platform

}

export interface ImportedAppleDeviceIdentityResult extends ImportedAppleDeviceIdentity {

	    /** Status of imported device identity */
		status?: boolean

}

export interface ActiveDirectoryWindowsAutopilotDeploymentProfile extends WindowsAutopilotDeploymentProfile {

	    /** Configuration to join Active Directory domain */
		domainJoinConfiguration?: WindowsDomainJoinConfiguration

}

export interface AzureADWindowsAutopilotDeploymentProfile extends WindowsAutopilotDeploymentProfile {

}

export interface DepEnrollmentProfile extends EnrollmentProfile {

		isDefault?: boolean

	    /** Supervised mode, True to enable, false otherwise. See https://docs.microsoft.com/en-us/intune/deploy-use/enroll-devices-in-microsoft-intune for additional information. */
		supervisedModeEnabled?: boolean

	    /** Support department information */
		supportDepartment?: string

	    /** Indicates if Passcode setup pane is disabled */
		passCodeDisabled?: boolean

	    /** Indicates if the profile is mandatory */
		isMandatory?: boolean

	    /** Indicates if Location service setup pane is disabled */
		locationDisabled?: boolean

	    /** Support phone number */
		supportPhoneNumber?: string

	    /** Indicates the iTunes pairing mode. Possible values are: disallow, allow, requiresCertificate. */
		iTunesPairingMode?: ITunesPairingMode

	    /** Indicates if the profile removal option is disabled */
		profileRemovalDisabled?: boolean

	    /** Management certificates for Apple Configurator */
		managementCertificates?: ManagementCertificateWithThumbprint[]

	    /** Indicates if Restore setup pane is blocked */
		restoreBlocked?: boolean

	    /** Indicates if Restore from Android is disabled */
		restoreFromAndroidDisabled?: boolean

	    /** Indicates if Apple id setup pane is disabled */
		appleIdDisabled?: boolean

	    /** Indicates if 'Terms and Conditions' setup pane is disabled */
		termsAndConditionsDisabled?: boolean

	    /** Indicates if touch id setup pane is disabled */
		touchIdDisabled?: boolean

	    /** Indicates if Apple pay setup pane is disabled */
		applePayDisabled?: boolean

	    /** Indicates if zoom setup pane is disabled */
		zoomDisabled?: boolean

	    /** Indicates if siri setup pane is disabled */
		siriDisabled?: boolean

	    /** Indicates if diagnostics setup pane is disabled */
		diagnosticsDisabled?: boolean

	    /** Indicates if Mac OS registration is disabled */
		macOSRegistrationDisabled?: boolean

	    /** Indicates if Mac OS file vault is disabled */
		macOSFileVaultDisabled?: boolean

	    /** Indicates if the device will need to wait for configured confirmation */
		awaitDeviceConfiguredConfirmation?: boolean

	    /** This specifies the maximum number of users that can use a shared iPad. Only applicable in shared iPad mode. */
		sharedIPadMaximumUserCount?: number

	    /** This indicates whether the device is to be enrolled in a mode which enables multi user scenarios. Only applicable in shared iPads. */
		enableSharedIPad?: boolean

}

export interface Office365ActivationsUserDetail extends Entity {

	    /** The latest date of the content. */
		reportRefreshDate?: string

	    /** The user principal name (UPN) of the user. The UPN is an Internet-style login name for the user based on the Internet standard RFC 822. By convention, this should map to the user's email name. The general format is alias@domain, where domain must be present in the tenant’s collection of verified domains. This property is required when a user is created. */
		userPrincipalName?: string

	    /** The name displayed in the address book for the user. This is usually the combination of the user's first name, middle initial, and last name. This property is required when a user is created and it cannot be cleared during updates. */
		displayName?: string

	    /** The user's latest product activation counts on all the platforms for all the assigned product types. */
		userActivationCounts?: UserActivationCounts[]

}

export interface Office365ActivationCounts extends Entity {

	    /** The latest date of the content. */
		reportRefreshDate?: string

	    /** The product type, such as "Office 365 ProPlus", "Project Client", or "Visio Pro for Office 365". */
		productType?: string

	    /** The activation count on Windows. This number includes every activation on any Windows computer. */
		windows?: number

	    /** The activation count on Mac OS. */
		mac?: number

	    /** The activation count on an Android device. */
		android?: number

	    /** The activation count on iOS. */
		ios?: number

	    /** The activation count on Windows 10 mobile. */
		windows10Mobile?: number

}

export interface Office365ActivationsUserCounts extends Entity {

	    /** The latest date of the content. */
		reportRefreshDate?: string

	    /** The product type such as "Office 365 ProPlus", "Project Client", or "Visio Pro for Office 365". */
		productType?: string

	    /** The number of users have been assigned for the product license. */
		assigned?: number

	    /** The number of users who have activated the product. */
		activated?: number

	    /** The number of users who have used the product on a shared computer. */
		sharedComputerActivation?: number

}

export interface Office365ActiveUserDetail extends Entity {

	    /** The latest date of the content. */
		reportRefreshDate?: string

	    /** The user principal name (UPN) of the user. The UPN is an Internet-style login name for the user based on the Internet standard RFC 822. By convention, this should map to the user's email name. The general format is alias@domain, where domain must be present in the tenant’s collection of verified domains. This property is required when a user is created. */
		userPrincipalName?: string

	    /** The name displayed in the address book for the user. This is usually the combination of the user's first name, middle initial, and last name. This property is required when a user is created and it cannot be cleared during updates. */
		displayName?: string

	    /** Whether this user has been deleted or soft deleted. */
		isDeleted?: boolean

	    /** The date when the delete operation happened. Default value is "null" when the user has not been deleted. */
		deletedDate?: string

	    /** Whether the user has been assigned an Exchange license. */
		hasExchangeLicense?: boolean

	    /** Whether the user has been assigned a OneDrive license. */
		hasOneDriveLicense?: boolean

	    /** Whether the user has been assigned a SharePoint license. */
		hasSharePointLicense?: boolean

	    /** Whether the user has been assigned a Skype For Business license. */
		hasSkypeForBusinessLicense?: boolean

	    /** Whether the user has been assigned a Yammer license. */
		hasYammerLicense?: boolean

	    /** Whether the user has been assigned a Teams license. */
		hasTeamsLicense?: boolean

	    /** The date when user last read or sent email. */
		exchangeLastActivityDate?: string

	    /** The date when user last viewed or edited files, shared files internally or externally, or synced files. */
		oneDriveLastActivityDate?: string

	    /** The date when user last viewed or edited files, shared files internally or externally, synced files, or viewed SharePoint pages. */
		sharePointLastActivityDate?: string

	    /** The date when user last organized or participated in conferences, or joined peer-to-peer sessions. */
		skypeForBusinessLastActivityDate?: string

	    /** The date when user last posted, read, or liked message. */
		yammerLastActivityDate?: string

	    /** The date when user last posted messages in team channels, sent messages in private chat sessions, or participated in meetings or calls. */
		teamsLastActivityDate?: string

	    /** The last date when the user was assigned an Exchange license. */
		exchangeLicenseAssignDate?: string

	    /** The last date when the user was assigned a OneDrive license. */
		oneDriveLicenseAssignDate?: string

	    /** The last date when the user was assigned a SharePoint license. */
		sharePointLicenseAssignDate?: string

	    /** The last date when the user was assigned a Skype For Business license. */
		skypeForBusinessLicenseAssignDate?: string

	    /** The last date when the user was assigned a Yammer license. */
		yammerLicenseAssignDate?: string

	    /** The last date when the user was assigned a Teams license. */
		teamsLicenseAssignDate?: string

	    /** All the products assigned for the user. */
		assignedProducts?: string[]

}

export interface Office365ServicesUserCounts extends Entity {

	    /** The latest date of the content. */
		reportRefreshDate?: string

	    /** The number of active users on Exchange. Any user who can read and send email is considered an active user. */
		exchangeActive?: number

	    /** The number of inactive users on Exchange. */
		exchangeInactive?: number

	    /** The number of active users on OneDrive. Any user who viewed or edited files, shared files internally or externally, or synced files is considered an active user. */
		oneDriveActive?: number

	    /** The number of inactive users on OneDrive. */
		oneDriveInactive?: number

	    /** The number of active users on SharePoint. Any user who viewed or edited files, shared files internally or externally, synced files, or viewed SharePoint pages is considered an active user. */
		sharePointActive?: number

	    /** The number of inactive users on SharePoint. */
		sharePointInactive?: number

	    /** The number of active users on Skype For Business. Any user who organized or participated in conferences, or joined peer-to-peer sessions is considered an active user. */
		skypeForBusinessActive?: number

	    /** The number of inactive users on Skype For Business. */
		skypeForBusinessInactive?: number

	    /** The number of active users on Yammer. Any user who can post, read, or like messages is considered an active user. */
		yammerActive?: number

	    /** The number of inactive users on Yammer. */
		yammerInactive?: number

	    /** The number of active users on Teams. Any user who posted messages in team channels, sent messages in private chat sessions, or participated in meetings or calls is considered an active user. */
		teamsActive?: number

	    /** The number of active users on Teams. */
		teamsInactive?: number

	    /** The number of days the report covers. */
		reportPeriod?: string

}

export interface Office365ActiveUserCounts extends Entity {

	    /** The latest date of the content. */
		reportRefreshDate?: string

	    /** The number of active users in Office 365. This number includes all the active users in Exchange, OneDrive, SharePoint, Skype For Business, Yammer, and Microsoft Teams. You can find the definition of active user for each product in the respective property description. */
		office365?: number

	    /** The number of active users in Exchange. Any user who can read and send email is considered an active user. */
		exchange?: number

	    /** The number of active users in OneDrive. Any user who viewed or edited files, shared files internally or externally, or synced files is considered an active user. */
		oneDrive?: number

	    /** The number of active users in SharePoint. Any user who viewed or edited files, shared files internally or externally, synced files, or viewed SharePoint pages is considered an active user. */
		sharePoint?: number

	    /** The number of active users in Skype For Business. Any user who organized or participated in conferences, or joined peer-to-peer sessions is considered an active user. */
		skypeForBusiness?: number

	    /** The number of active users in Yammer. Any user who can post, read, or like messages is considered an active user. */
		yammer?: number

	    /** The number of active users in Microsoft Teams. Any user who posted messages in team channels, sent messages in private chat sessions, or participated in meetings or calls is considered an active user. */
		teams?: number

	    /** The date on which a number of users were active. */
		reportDate?: string

	    /** The number of days the report covers. */
		reportPeriod?: string

}

export interface Office365GroupsActivityDetail extends Entity {

	    /** The latest date of the content. */
		reportRefreshDate?: string

	    /** The display name of the group. */
		groupDisplayName?: string

	    /** Whether this user has been deleted or soft deleted. */
		isDeleted?: boolean

	    /** The group owner principal name. */
		ownerPrincipalName?: string

	    /** The last activity date for the following scenarios:  group mailbox received email; user viewed, edited, shared, or synced files in SharePoint document library; user viewed SharePoint pages; user posted, read, or liked messages in Yammer groups. */
		lastActivityDate?: string

	    /** The group type. Possible values are: Public or Private. */
		groupType?: string

	    /** The group member count. */
		memberCount?: number

	    /** The group external member count. */
		externalMemberCount?: number

	    /** The number of email that the group mailbox received. */
		exchangeReceivedEmailCount?: number

	    /** The number of active files in SharePoint Group site. */
		sharePointActiveFileCount?: number

	    /** The number of messages posted to Yammer groups. */
		yammerPostedMessageCount?: number

	    /** The number of messages read in Yammer groups. */
		yammerReadMessageCount?: number

	    /** The number of messages liked in Yammer groups. */
		yammerLikedMessageCount?: number

	    /** The number of items in the group mailbox. */
		exchangeMailboxTotalItemCount?: number

	    /** The storage used of the group mailbox. */
		exchangeMailboxStorageUsedInBytes?: number

	    /** The total number of files in SharePoint Group site. */
		sharePointTotalFileCount?: number

	    /** The storage used by SharePoint Group site. */
		sharePointSiteStorageUsedInBytes?: number

	    /** The number of days the report covers. */
		reportPeriod?: string

}

export interface Office365GroupsActivityCounts extends Entity {

	    /** The latest date of the content. */
		reportRefreshDate?: string

	    /** The number of emails received by Group mailboxes. */
		exchangeEmailsReceived?: number

	    /** The number of messages posted to Yammer groups. */
		yammerMessagesPosted?: number

	    /** The number of messages read in Yammer groups. */
		yammerMessagesRead?: number

	    /** The number of messages liked in Yammer groups. */
		yammerMessagesLiked?: number

	    /** The date on which a number of emails were sent to a group mailbox or a number of messages were posted, read, or liked in a Yammer group */
		reportDate?: string

	    /** The number of days the report covers. */
		reportPeriod?: string

}

export interface Office365GroupsActivityGroupCounts extends Entity {

	    /** The latest date of the content. */
		reportRefreshDate?: string

	    /** The total number of groups. */
		total?: number

	    /** The number of active groups. A group is considered active if any of the following occurred: group mailbox received email; user viewed, edited, shared, or synced files in SharePoint document library; user viewed SharePoint pages; user posted, read, or liked messages in Yammer groups. */
		active?: number

	    /** The date on which a number of groups were active. */
		reportDate?: string

	    /** The number of days the report covers. */
		reportPeriod?: string

}

export interface Office365GroupsActivityStorage extends Entity {

	    /** The latest date of the content. */
		reportRefreshDate?: string

	    /** The storage used in group mailbox. */
		mailboxStorageUsedInBytes?: number

	    /** The storage used in SharePoint document library. */
		siteStorageUsedInBytes?: number

	    /** The snapshot date for Exchange and SharePoint used storage. */
		reportDate?: string

	    /** The number of days the report covers. */
		reportPeriod?: string

}

export interface Office365GroupsActivityFileCounts extends Entity {

	    /** The latest date of the content. */
		reportRefreshDate?: string

	    /** The total number of files in the group's SharePoint document library. */
		total?: number

	    /** The number of files that were viewed, edited, shared, or synced in the group's SharePoint document library. */
		active?: number

	    /** The date on which a number of files were active in the group's SharePoint site. */
		reportDate?: string

	    /** The number of days the report covers. */
		reportPeriod?: string

}

export interface EmailActivityUserDetail extends Entity {

		reportRefreshDate?: string

		userPrincipalName?: string

		displayName?: string

		isDeleted?: boolean

		deletedDate?: string

		lastActivityDate?: string

		sendCount?: number

		receiveCount?: number

		readCount?: number

		assignedProducts?: string[]

		reportPeriod?: string

}

export interface EmailActivitySummary extends Entity {

		reportRefreshDate?: string

		send?: number

		receive?: number

		read?: number

		reportDate?: string

		reportPeriod?: string

}

export interface EmailAppUsageUserDetail extends Entity {

		reportRefreshDate?: string

		userPrincipalName?: string

		displayName?: string

		isDeleted?: boolean

		deletedDate?: string

		lastActivityDate?: string

		mailForMac?: string[]

		outlookForMac?: string[]

		outlookForWindows?: string[]

		outlookForMobile?: string[]

		otherForMobile?: string[]

		outlookForWeb?: string[]

		pop3App?: string[]

		imap4App?: string[]

		smtpApp?: string[]

		reportPeriod?: string

}

export interface EmailAppUsageAppsUserCounts extends Entity {

		reportRefreshDate?: string

		mailForMac?: number

		outlookForMac?: number

		outlookForWindows?: number

		outlookForMobile?: number

		otherForMobile?: number

		outlookForWeb?: number

		pop3App?: number

		imap4App?: number

		smtpApp?: number

		reportPeriod?: string

}

export interface EmailAppUsageUserCounts extends Entity {

		reportRefreshDate?: string

		mailForMac?: number

		outlookForMac?: number

		outlookForWindows?: number

		outlookForMobile?: number

		otherForMobile?: number

		outlookForWeb?: number

		pop3App?: number

		imap4App?: number

		smtpApp?: number

		reportDate?: string

		reportPeriod?: string

}

export interface EmailAppUsageVersionsUserCounts extends Entity {

		reportRefreshDate?: string

		outlook2016?: number

		outlook2013?: number

		outlook2010?: number

		outlook2007?: number

		undetermined?: number

		reportPeriod?: string

}

export interface MailboxUsageDetail extends Entity {

		reportRefreshDate?: string

		userPrincipalName?: string

		displayName?: string

		isDeleted?: boolean

		deletedDate?: string

		createdDate?: string

		lastActivityDate?: string

		itemCount?: number

		storageUsedInBytes?: number

		issueWarningQuotaInBytes?: number

		prohibitSendQuotaInBytes?: number

		prohibitSendReceiveQuotaInBytes?: number

		reportPeriod?: string

}

export interface MailboxUsageMailboxCounts extends Entity {

		reportRefreshDate?: string

		total?: number

		active?: number

		reportDate?: string

		reportPeriod?: string

}

export interface MailboxUsageQuotaStatusMailboxCounts extends Entity {

		reportRefreshDate?: string

		underLimit?: number

		warningIssued?: number

		sendProhibited?: number

		sendReceiveProhibited?: number

		indeterminate?: number

		reportDate?: string

		reportPeriod?: string

}

export interface MailboxUsageStorage extends Entity {

		reportRefreshDate?: string

		storageUsedInBytes?: number

		reportDate?: string

		reportPeriod?: string

}

export interface OneDriveActivityUserDetail extends Entity {

		reportRefreshDate?: string

		userPrincipalName?: string

		isDeleted?: boolean

		deletedDate?: string

		lastActivityDate?: string

		viewedOrEditedFileCount?: number

		syncedFileCount?: number

		sharedInternallyFileCount?: number

		sharedExternallyFileCount?: number

		assignedProducts?: string[]

		reportPeriod?: string

}

export interface SiteActivitySummary extends Entity {

		reportRefreshDate?: string

		viewedOrEdited?: number

		synced?: number

		sharedInternally?: number

		sharedExternally?: number

		reportDate?: string

		reportPeriod?: string

}

export interface OneDriveUsageAccountDetail extends Entity {

		reportRefreshDate?: string

		siteUrl?: string

		ownerDisplayName?: string

		isDeleted?: boolean

		lastActivityDate?: string

		fileCount?: number

		activeFileCount?: number

		storageUsedInBytes?: number

		storageAllocatedInBytes?: number

		reportPeriod?: string

}

export interface OneDriveUsageAccountCounts extends Entity {

		reportRefreshDate?: string

		siteType?: string

		total?: number

		active?: number

		reportDate?: string

		reportPeriod?: string

}

export interface OneDriveUsageFileCounts extends Entity {

		reportRefreshDate?: string

		siteType?: string

		total?: number

		active?: number

		reportDate?: string

		reportPeriod?: string

}

export interface SiteUsageStorage extends Entity {

		reportRefreshDate?: string

		siteType?: string

		storageUsedInBytes?: number

		reportDate?: string

		reportPeriod?: string

}

export interface SharePointActivityUserDetail extends Entity {

		reportRefreshDate?: string

		userPrincipalName?: string

		isDeleted?: boolean

		deletedDate?: string

		lastActivityDate?: string

		viewedOrEditedFileCount?: number

		syncedFileCount?: number

		sharedInternallyFileCount?: number

		sharedExternallyFileCount?: number

		visitedPageCount?: number

		assignedProducts?: string[]

		reportPeriod?: string

}

export interface SharePointActivityUserCounts extends Entity {

		reportRefreshDate?: string

		visitedPage?: number

		viewedOrEdited?: number

		synced?: number

		sharedInternally?: number

		sharedExternally?: number

		reportDate?: string

		reportPeriod?: string

}

export interface SharePointActivityPages extends Entity {

		reportRefreshDate?: string

		visitedPageCount?: number

		reportDate?: string

		reportPeriod?: string

}

export interface SharePointSiteUsageDetail extends Entity {

		reportRefreshDate?: string

		siteId?: string

		siteUrl?: string

		ownerDisplayName?: string

		isDeleted?: boolean

		lastActivityDate?: string

		fileCount?: number

		activeFileCount?: number

		pageViewCount?: number

		visitedPageCount?: number

		storageUsedInBytes?: number

		storageAllocatedInBytes?: number

		rootWebTemplate?: string

		reportPeriod?: string

}

export interface SharePointSiteUsageFileCounts extends Entity {

		reportRefreshDate?: string

		siteType?: string

		total?: number

		active?: number

		reportDate?: string

		reportPeriod?: string

}

export interface SharePointSiteUsageSiteCounts extends Entity {

		reportRefreshDate?: string

		siteType?: string

		total?: number

		active?: number

		reportDate?: string

		reportPeriod?: string

}

export interface SharePointSiteUsagePages extends Entity {

		reportRefreshDate?: string

		siteType?: string

		pageViewCount?: number

		reportDate?: string

		reportPeriod?: string

}

export interface SkypeForBusinessActivityUserDetail extends Entity {

		totalPeerToPeerSessionCount?: number

		totalOrganizedConferenceCount?: number

		totalParticipatedConferenceCount?: number

		peerToPeerLastActivityDate?: string

		organizedConferenceLastActivityDate?: string

		participatedConferenceLastActivityDate?: string

		peerToPeerIMCount?: number

		peerToPeerAudioCount?: number

		peerToPeerAudioMinutes?: number

		peerToPeerVideoCount?: number

		peerToPeerVideoMinutes?: number

		peerToPeerAppSharingCount?: number

		peerToPeerFileTransferCount?: number

		organizedConferenceIMCount?: number

		organizedConferenceAudioVideoCount?: number

		organizedConferenceAudioVideoMinutes?: number

		organizedConferenceAppSharingCount?: number

		organizedConferenceWebCount?: number

		organizedConferenceDialInOut3rdPartyCount?: number

		organizedConferenceCloudDialInOutMicrosoftCount?: number

		organizedConferenceCloudDialInMicrosoftMinutes?: number

		organizedConferenceCloudDialOutMicrosoftMinutes?: number

		participatedConferenceIMCount?: number

		participatedConferenceAudioVideoCount?: number

		participatedConferenceAudioVideoMinutes?: number

		participatedConferenceAppSharingCount?: number

		participatedConferenceWebCount?: number

		participatedConferenceDialInOut3rdPartyCount?: number

		reportRefreshDate?: string

		userPrincipalName?: string

		isDeleted?: boolean

		deletedDate?: string

		lastActivityDate?: string

		assignedProducts?: string[]

		reportPeriod?: string

}

export interface SkypeForBusinessActivityCounts extends Entity {

		peerToPeer?: number

		organized?: number

		participated?: number

		reportRefreshDate?: string

		reportDate?: string

		reportPeriod?: string

}

export interface SkypeForBusinessActivityUserCounts extends Entity {

		peerToPeer?: number

		organized?: number

		participated?: number

		reportRefreshDate?: string

		reportDate?: string

		reportPeriod?: string

}

export interface SkypeForBusinessPeerToPeerActivityCounts extends Entity {

		im?: number

		audio?: number

		video?: number

		appSharing?: number

		fileTransfer?: number

		reportRefreshDate?: string

		reportDate?: string

		reportPeriod?: string

}

export interface SkypeForBusinessPeerToPeerActivityUserCounts extends Entity {

		im?: number

		audio?: number

		video?: number

		appSharing?: number

		fileTransfer?: number

		reportRefreshDate?: string

		reportDate?: string

		reportPeriod?: string

}

export interface SkypeForBusinessPeerToPeerActivityMinuteCounts extends Entity {

		audio?: number

		video?: number

		reportRefreshDate?: string

		reportDate?: string

		reportPeriod?: string

}

export interface SkypeForBusinessOrganizerActivityCounts extends Entity {

		im?: number

		audioVideo?: number

		appSharing?: number

		web?: number

		dialInOut3rdParty?: number

		dialInOutMicrosoft?: number

		reportRefreshDate?: string

		reportDate?: string

		reportPeriod?: string

}

export interface SkypeForBusinessOrganizerActivityUserCounts extends Entity {

		im?: number

		audioVideo?: number

		appSharing?: number

		web?: number

		dialInOut3rdParty?: number

		dialInOutMicrosoft?: number

		reportRefreshDate?: string

		reportDate?: string

		reportPeriod?: string

}

export interface SkypeForBusinessOrganizerActivityMinuteCounts extends Entity {

		audioVideo?: number

		dialInMicrosoft?: number

		dialOutMicrosoft?: number

		reportRefreshDate?: string

		reportDate?: string

		reportPeriod?: string

}

export interface SkypeForBusinessParticipantActivityCounts extends Entity {

		im?: number

		audioVideo?: number

		appSharing?: number

		web?: number

		dialInOut3rdParty?: number

		reportRefreshDate?: string

		reportDate?: string

		reportPeriod?: string

}

export interface SkypeForBusinessParticipantActivityUserCounts extends Entity {

		im?: number

		audioVideo?: number

		appSharing?: number

		web?: number

		dialInOut3rdParty?: number

		reportRefreshDate?: string

		reportDate?: string

		reportPeriod?: string

}

export interface SkypeForBusinessParticipantActivityMinuteCounts extends Entity {

		audiovideo?: number

		reportRefreshDate?: string

		reportDate?: string

		reportPeriod?: string

}

export interface SkypeForBusinessDeviceUsageUserDetail extends Entity {

		reportRefreshDate?: string

		userPrincipalName?: string

		lastActivityDate?: string

		usedWindows?: boolean

		usedWindowsPhone?: boolean

		usedAndroidPhone?: boolean

		usediPhone?: boolean

		usediPad?: boolean

		reportPeriod?: string

}

export interface SkypeForBusinessDeviceUsageDistributionUserCounts extends Entity {

		reportRefreshDate?: string

		windows?: number

		windowsPhone?: number

		androidPhone?: number

		iPhone?: number

		iPad?: number

		reportPeriod?: string

}

export interface SkypeForBusinessDeviceUsageUserCounts extends Entity {

		reportRefreshDate?: string

		windows?: number

		windowsPhone?: number

		androidPhone?: number

		iPhone?: number

		iPad?: number

		reportDate?: string

		reportPeriod?: string

}

export interface YammerActivityUserDetail extends Entity {

		reportRefreshDate?: string

		userPrincipalName?: string

		displayName?: string

		userState?: string

		stateChangeDate?: string

		lastActivityDate?: string

		postedCount?: number

		readCount?: number

		likedCount?: number

		assignedProducts?: string[]

		reportPeriod?: string

}

export interface YammerActivitySummary extends Entity {

		reportRefreshDate?: string

		liked?: number

		posted?: number

		read?: number

		reportDate?: string

		reportPeriod?: string

}

export interface YammerDeviceUsageUserDetail extends Entity {

		reportRefreshDate?: string

		userPrincipalName?: string

		displayName?: string

		userState?: string

		stateChangeDate?: string

		lastActivityDate?: string

		usedWeb?: boolean

		usedWindowsPhone?: boolean

		usedAndroidPhone?: boolean

		usediPhone?: boolean

		usediPad?: boolean

		usedOthers?: boolean

		reportPeriod?: string

}

export interface YammerDeviceUsageDistributionUserCounts extends Entity {

		reportRefreshDate?: string

		web?: number

		windowsPhone?: number

		androidPhone?: number

		iPhone?: number

		iPad?: number

		other?: number

		reportPeriod?: string

}

export interface YammerDeviceUsageUserCounts extends Entity {

		reportRefreshDate?: string

		web?: number

		windowsPhone?: number

		androidPhone?: number

		iPhone?: number

		iPad?: number

		other?: number

		reportDate?: string

		reportPeriod?: string

}

export interface YammerGroupsActivityDetail extends Entity {

		reportRefreshDate?: string

		groupDisplayName?: string

		isDeleted?: boolean

		ownerPrincipalName?: string

		lastActivityDate?: string

		groupType?: string

		office365Connected?: boolean

		memberCount?: number

		postedCount?: number

		readCount?: number

		likedCount?: number

		reportPeriod?: string

}

export interface YammerGroupsActivityGroupCounts extends Entity {

		reportRefreshDate?: string

		total?: number

		active?: number

		reportDate?: string

		reportPeriod?: string

}

export interface YammerGroupsActivityCounts extends Entity {

		reportRefreshDate?: string

		liked?: number

		posted?: number

		read?: number

		reportDate?: string

		reportPeriod?: string

}

export interface TeamsUserActivityUserDetail extends Entity {

		reportRefreshDate?: string

		userPrincipalName?: string

		lastActivityDate?: string

		isDeleted?: boolean

		deletedDate?: string

		assignedProducts?: string[]

		teamChatMessageCount?: number

		privateChatMessageCount?: number

		callCount?: number

		meetingCount?: number

		hasOtherAction?: boolean

		reportPeriod?: string

}

export interface TeamsUserActivityCounts extends Entity {

		reportRefreshDate?: string

		reportDate?: string

		teamChatMessages?: number

		privateChatMessages?: number

		calls?: number

		meetings?: number

		reportPeriod?: string

}

export interface TeamsUserActivityUserCounts extends Entity {

		reportRefreshDate?: string

		reportDate?: string

		teamChatMessages?: number

		privateChatMessages?: number

		calls?: number

		meetings?: number

		otherActions?: number

		reportPeriod?: string

}

export interface TeamsDeviceUsageUserDetail extends Entity {

		reportRefreshDate?: string

		userPrincipalName?: string

		lastActivityDate?: string

		isDeleted?: boolean

		deletedDate?: string

		usedWeb?: boolean

		usedWindowsPhone?: boolean

		usediOS?: boolean

		usedMac?: boolean

		usedAndroidPhone?: boolean

		usedWindows?: boolean

		reportPeriod?: string

}

export interface TeamsDeviceUsageUserCounts extends Entity {

		reportRefreshDate?: string

		web?: number

		windowsPhone?: number

		androidPhone?: number

		ios?: number

		mac?: number

		windows?: number

		reportDate?: string

		reportPeriod?: string

}

export interface TeamsDeviceUsageDistributionUserCounts extends Entity {

		reportRefreshDate?: string

		web?: number

		windowsPhone?: number

		androidPhone?: number

		ios?: number

		mac?: number

		windows?: number

		reportPeriod?: string

}

export interface PayloadResponse extends Entity {

}

export interface AppCatalogs extends Entity {

		teamsApps?: TeamsCatalogApp[]

}

export interface TeamsCatalogApp extends Entity {

		externalId?: string

		name?: string

		version?: string

		distributionMethod?: TeamsCatalogAppDistributionMethod

}

export interface TeamsAsyncOperation extends Entity {

		operationType?: TeamsAsyncOperationType

		createdDateTime?: string

		status?: TeamsAsyncOperationStatus

		lastActionDateTime?: string

		attemptsCount?: number

		targetResourceId?: string

		targetResourceLocation?: string

		error?: OperationError

}

export interface ChatMessage extends Entity {

		replyToId?: string

		from?: IdentitySet

		etag?: string

		messageType?: ChatMessageType

		createdDateTime?: string

		lastModifiedDateTime?: string

		deleted?: boolean

		subject?: string

		body?: ItemBody

		summary?: string

		attachments?: ChatMessageAttachment[]

		mentions?: ChatMessageMention[]

		importance?: ChatMessageImportance

		reactions?: ChatMessageReaction[]

		locale?: string

		replies?: ChatMessage[]

}

export interface ChatThread extends Entity {

	    /** Nullable. */
		rootMessage?: ChatMessage

}

export interface IdentityProvider extends Entity {

	    /** The identity provider type. It must be one of the following values: MicrosoftGoogleAmazonLinkedInFacebook */
		type?: string

	    /** The display name of the identity provider. */
		name?: string

	    /** The client ID for the application. This is the client ID obtained when registering the application with the identity provider. */
		clientId?: string

	    /** The client secret for the application. This is the client secret obtained when registering the application with the identity provider. This is write-only. A read operation will return "****". */
		clientSecret?: string

}

export interface SynchronizationJob extends Entity {

	    /** Identifier of the synchronization template this job is based on. */
		templateId?: string

	    /** Schedule used to run the job. Read-only. */
		schedule?: SynchronizationSchedule

	    /** Status of the job, which includes when the job was last run, current job state, and errors. */
		status?: SynchronizationStatus

	    /** The synchronization schema configured for the job. */
		schema?: SynchronizationSchema

}

export interface SynchronizationTemplate extends Entity {

	    /** Identifier of the application this template belongs to. */
		applicationId?: string

	    /** true if this template is recommended to be the default for the application. */
		default?: boolean

	    /** Description of the template. */
		description?: string

	    /** true if this template should appear in the collection of templates available for the application instance (service principal). */
		discoverable?: boolean

	    /** One of the well-known factory tags supported by the synchronization engine. The factoryTag tells the synchronization engine which implementation to use when processing jobs based on this template. */
		factoryTag?: string

	    /** Additional extension properties. Unless mentioned explicitly, metadata values should not be changed. */
		metadata?: MetadataEntry[]

	    /** Default synchronization schema for the jobs based on this template. */
		schema?: SynchronizationSchema

}

export interface SynchronizationSchema extends Entity {

	    /** Describes directories and objects that are part of the synchronizationJob or synchronizationTemplate. */
		directories?: DirectoryDefinition[]

	    /** A collection of synchronization rules configured for the synchronizationJob or synchronizationTemplate, */
		synchronizationRules?: SynchronizationRule[]

	    /** The version of the schema, updated automatically with every schema change. */
		version?: string

}

export interface AttributeMappingFunctionSchema extends Entity {

	    /** Collection of function parameters. */
		parameters?: AttributeMappingParameterSchema[]

}

export interface FilterOperatorSchema extends Entity {

	    /** Arity of the operator. Possible values are: Binary, Unary. The default is Binary. */
		arity?: ScopeOperatorType

	    /** Possible values are: All, Any. Applies only to multivalued attributes. All means that all values must satisfy the condition. Any means that at least one value has to satisfy the condition. The default is All. */
		multivaluedComparisonType?: ScopeOperatorMultiValuedComparisonType

	    /** Attribute types supported by the operator. Possible values are: Boolean, Binary, Reference, Integer, String. */
		supportedAttributeTypes?: AttributeType[]

}

export interface EducationRoot extends Entity {

		synchronizationProfiles?: EducationSynchronizationProfile[]

		classes?: EducationClass[]

		schools?: EducationSchool[]

		users?: EducationUser[]

		me?: EducationUser

}

export interface EducationSynchronizationProfile extends Entity {

		displayName?: string

		dataProvider?: EducationSynchronizationDataProvider

		identitySynchronizationConfiguration?: EducationIdentitySynchronizationConfiguration

		licensesToAssign?: EducationSynchronizationLicenseAssignment[]

		state?: EducationSynchronizationProfileState

		handleSpecialCharacterConstraint?: boolean

		termStartDate?: string

		termEndDate?: string

		dateFormat?: string

		errors?: EducationSynchronizationError[]

		profileStatus?: EducationSynchronizationProfileStatus

}

export interface EducationClass extends Entity {

	    /** Name of the class. */
		displayName?: string

	    /** Mail name for sending email to all members, if this is enabled. */
		mailNickname?: string

	    /** Description of the class. */
		description?: string

	    /** Entity who created the class */
		createdBy?: IdentitySet

	    /** Class code used by the school to identify the class. */
		classCode?: string

	    /** Name of the class in the syncing system. */
		externalName?: string

	    /** ID of the class from the syncing system. */
		externalId?: string

	    /** How this class was created. Possible values are: sis, manual, unknownFutureValue. */
		externalSource?: EducationExternalSource

	    /** Term for this class. */
		term?: EducationTerm

	    /** All schools that this class is associated with. Nullable. */
		schools?: EducationSchool[]

	    /** All users in the class. Nullable. */
		members?: EducationUser[]

	    /** All teachers in the class. Nullable. */
		teachers?: EducationUser[]

		group?: Group

	    /** All assignments associated with this class. Nullable. */
		assignments?: EducationAssignment[]

}

export interface EducationOrganization extends Entity {

	    /** Organization display name. */
		displayName?: string

	    /** Organization description. */
		description?: string

	    /** Source where this organization was created from. Possible values are: sis, manual, unknownFutureValue. */
		externalSource?: EducationExternalSource

}

export interface EducationSchool extends EducationOrganization {

	    /** Email address of the principal. */
		principalEmail?: string

	    /** Name of the principal. */
		principalName?: string

	    /** ID of principal in syncing system. */
		externalPrincipalId?: string

	    /** Lowest grade taught. */
		lowestGrade?: string

	    /** Highest grade taught. */
		highestGrade?: string

	    /** School Number. */
		schoolNumber?: string

	    /** ID of school in syncing system. */
		externalId?: string

	    /** Phone number of school. */
		phone?: string

	    /** Fax number of school. */
		fax?: string

	    /** Entity who created the school. */
		createdBy?: IdentitySet

	    /** Address of the school. */
		address?: PhysicalAddress

	    /** Classes taught at the school. Nullable. */
		classes?: EducationClass[]

	    /** Users in the school. Nullable. */
		users?: EducationUser[]

		administrativeUnit?: AdministrativeUnit

}

export interface EducationUser extends Entity {

	    /** Default role for a user. The user's role might be different in an individual class. Possible values are: student, teacher, enum_sentinel. Supports $filter. */
		primaryRole?: EducationUserRole

	    /** The middle name of user. */
		middleName?: string

	    /** Where this user was created from. Possible values are: sis, manual, unkownFutureValue. */
		externalSource?: EducationExternalSource

	    /** Address where user lives. */
		residenceAddress?: PhysicalAddress

	    /** Mail address of user. */
		mailingAddress?: PhysicalAddress

	    /** If the primary role is student, this block will contain student specific data. */
		student?: EducationStudent

	    /** If the primary role is teacher, this block will conatin teacher specific data. */
		teacher?: EducationTeacher

	    /** Entity who created the user. */
		createdBy?: IdentitySet

		accountEnabled?: boolean

		assignedLicenses?: AssignedLicense[]

		assignedPlans?: AssignedPlan[]

		businessPhones?: string[]

		department?: string

	    /** The name displayed in the address book for the user. This is usually the combination of the user's first name, middle initial, and last name. This property is required when a user is created and it cannot be cleared during updates. Supports $filter and $orderby. */
		displayName?: string

	    /** The given name (first name) of the user. Supports $filter. */
		givenName?: string

	    /** The SMTP address for the user; for example, "jeff@contoso.onmicrosoft.com". Read-Only. Supports $filter. */
		mail?: string

		mailNickname?: string

	    /** The primary cellular telephone number for the user. */
		mobilePhone?: string

		passwordPolicies?: string

		passwordProfile?: PasswordProfile

		officeLocation?: string

		preferredLanguage?: string

		provisionedPlans?: ProvisionedPlan[]

		refreshTokensValidFromDateTime?: string

		showInAddressList?: boolean

	    /** The user's surname (family name or last name). Supports $filter. */
		surname?: string

		usageLocation?: string

		userPrincipalName?: string

		userType?: string

	    /** Schools to which the user belongs. Nullable. */
		schools?: EducationSchool[]

	    /** Classes to which the user belongs. Nullable. */
		classes?: EducationClass[]

		user?: User

	    /** List of assignments for hte user. Nullable. */
		assignments?: EducationAssignment[]

}

export interface EducationSynchronizationError extends Entity {

		entryType?: string

		errorCode?: string

		errorMessage?: string

		joiningValue?: string

		recordedDateTime?: string

		reportableIdentifier?: string

}

export interface EducationSynchronizationProfileStatus extends Entity {

		status?: EducationSynchronizationStatus

		lastSynchronizationDateTime?: string

}

export interface EducationAssignment extends Entity {

	    /** Class which this assignment belongs. */
		classId?: string

	    /** Name of the assignment. */
		displayName?: string

	    /** Instructions for the assignment.  This along with the display name tell the student what to do. */
		instructions?: EducationItemBody

	    /** Date when the students assignment is due.  The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		dueDateTime?: string

	    /** The date when the assignment should become active.  If in the future, the assignment is not shown to the student until this date.  The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		assignDateTime?: string

	    /** The moment that the assignment was published to students and the assignment shows up on the students timeline.  The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		assignedDateTime?: string

	    /** How the assignment will be graded. */
		grading?: EducationAssignmentGradeType

	    /** Which users, or whole class should receive a submission object once the assignment is published. */
		assignTo?: EducationAssignmentRecipient

	    /** Identifies whether students can submit after the due date. */
		allowLateSubmissions?: boolean

	    /** Moment when the assignment was created.  The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		createdDateTime?: string

	    /** Who created the assignment. */
		createdBy?: IdentitySet

	    /** Moment when the assignment was last modified.  The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		lastModifiedDateTime?: string

	    /** Who last modified the assignment. */
		lastModifiedBy?: IdentitySet

	    /** Identifies whether students can add their own resources to a submission or if they can only modify resources added by the teacher. */
		allowStudentsToAddResourcesToSubmission?: boolean

	    /** Status of the Assignment.  You can not PATCH this value.  Possible values are: draft, published, assigned. */
		status?: EducationAssignmentStatus

	    /** Learning objects that are associated with this assignment.  Only teachers can modify this list. Nullable. */
		resources?: EducationAssignmentResource[]

	    /** Once published, there is a submission object for each student representing their work and grade.  Read-only. Nullable. */
		submissions?: EducationSubmission[]

}

export interface EducationAssignmentResource extends Entity {

	    /** Indicates whether this resource should be copied to each student submission for modification and submission. */
		distributeForStudentWork?: boolean

	    /** Resource object that has been associated with this assignment. */
		resource?: EducationResource

}

export interface EducationSubmission extends Entity {

	    /** Who this submission is assigned to. */
		recipient?: EducationSubmissionRecipient

	    /** Read-Only. Possible values are: working, submitted, completed. */
		status?: EducationSubmissionStatus

	    /** User who moved the resource into the submitted state. */
		submittedBy?: IdentitySet

	    /** Moment in time when the submission was moved into the submitted state. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		submittedDateTime?: string

		unsubmittedBy?: IdentitySet

		unsubmittedDateTime?: string

	    /** User who moved the status of this submission to released. */
		releasedBy?: IdentitySet

	    /** Moment in time when the submission was released. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		releasedDateTime?: string

		returnedBy?: IdentitySet

		returnedDateTime?: string

	    /** Holds the grade information a teacher assigns to this submission. */
		grade?: EducationAssignmentGrade

	    /** Holds the feedback property which stores the teacher's notes back to students. */
		feedback?: EducationFeedback

	    /** Folder where all file resources for this submission need to be stored. */
		resourcesFolderUrl?: string

	    /** Nullable. */
		resources?: EducationSubmissionResource[]

	    /** Read-only. Nullable. */
		submittedResources?: EducationSubmissionResource[]

}

export interface EducationSubmissionResource extends Entity {

	    /** Resource object. */
		resource?: EducationResource

	    /** Pointer to the assignment from which this resource was copied. If this is null, the student uploaded the resource. */
		assignmentResourceUrl?: string

}

export interface EnrollmentTroubleshootingEvent extends DeviceManagementTroubleshootingEvent {

	    /** Device identifier created or collected by Intune. */
		managedDeviceIdentifier?: string

	    /** Operating System. */
		operatingSystem?: string

	    /** OS Version. */
		osVersion?: string

	    /** Identifier for the user that tried to enroll the device. */
		userId?: string

	    /** Azure AD device identifier. */
		deviceId?: string

	    /** Type of the enrollment. Possible values are: unknown, userEnrollment, deviceEnrollmentManager, appleBulkWithUser, appleBulkWithoutUser, windowsAzureADJoin, windowsBulkUserless, windowsAutoEnrollment, windowsBulkAzureDomainJoin, windowsCoManagement, windowsAzureADJoinUsingDeviceAuth. */
		enrollmentType?: DeviceEnrollmentType

	    /** Highlevel failure category. Possible values are: unknown, authentication, authorization, accountValidation, userValidation, deviceNotSupported, inMaintenance, badRequest, featureNotSupported, enrollmentRestrictionsEnforced, clientDisconnected. */
		failureCategory?: DeviceEnrollmentFailureReason

	    /** Detailed failure reason. */
		failureReason?: string

}

export interface DataClassificationService extends Entity {

		sensitiveTypes?: SensitiveType[]

		jobs?: JobResponseBase[]

		classifyText?: TextClassificationRequest[]

		classifyFile?: FileClassificationRequest[]

}

export interface SensitiveType extends Entity {

		name?: string

		description?: string

		rulePackageId?: string

		rulePackageType?: string

		publisherName?: string

		state?: string

}

export interface JobResponseBase extends Entity {

		type?: string

		status?: string

		tenantId?: string

		creationDateTime?: string

		startDateTime?: string

		endDateTime?: string

		error?: CaasError

}

export interface TextClassificationRequest extends Entity {

		text?: string

		sensitiveTypeIds?: string[]

}

export interface FileClassificationRequest extends Entity {

		file?: any

		sensitiveTypeIds?: string[]

}

export interface ClassificationJobResponse extends JobResponseBase {

		result?: DetectedSensitiveContentWrapper

}

export interface DataPolicyOperation extends Entity {

	    /** Represents when the request for this data policy operation was completed, in UTC time, using the ISO 8601 format. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. Null until the operation completes. */
		completedDateTime?: string

	    /** Possible values are: notStarted, running, complete, failed, unknownFutureValue. */
		status?: DataPolicyOperationStatus

	    /** The URL location to where data is being exported for export requests. */
		storageLocation?: string

	    /** The id for the user on whom the operation is performed. */
		userId?: string

	    /** Represents when the request for this data operation was submitted, in UTC time, using the ISO 8601 format. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		submittedDateTime?: string

}

export interface Agreement extends Entity {

	    /** Display name of the agreement. */
		displayName?: string

	    /** Indicates whether the user has to expand and view the agreement before accepting. */
		isViewingBeforeAcceptanceRequired?: boolean

	    /** Read-only. PDFs linked to this agreement. */
		files?: AgreementFile[]

}

export interface AgreementFile extends Entity {

	    /** Culture of the agreement file in the format languagecode2-country/regioncode2. languagecode2 is a lowercase two-letter code derived from ISO 639-1. country/regioncode2 is derived from ISO 3166 and usually consists of two uppercase letters, or a BCP-47 language tag (for example, en-US). Read-only. */
		language?: string

	    /** Name of the agreement file (for example, TOU.pdf). Read-only. */
		fileName?: string

	    /** Data representing the terms of use PDF document. Read-only. */
		fileData?: AgreementFileData

	    /** Indicates whether this is the default agreement file if none of the cultures matches the client preference. If none of the files are marked as default, the first one will be treated as the default. Read-only. */
		isDefault?: boolean

}

export interface Security extends Entity {

		alerts?: Alert[]

		cloudAppSecurityProfiles?: CloudAppSecurityProfile[]

		domainSecurityProfiles?: DomainSecurityProfile[]

		fileSecurityProfiles?: FileSecurityProfile[]

		hostSecurityProfiles?: HostSecurityProfile[]

		ipSecurityProfiles?: IpSecurityProfile[]

		providerTenantSettings?: ProviderTenantSetting[]

		secureScoreControlProfiles?: SecureScoreControlProfile[]

		secureScores?: SecureScore[]

		tiIndicators?: TiIndicator[]

		userSecurityProfiles?: UserSecurityProfile[]

}

export interface Alert extends Entity {

		activityGroupName?: string

	    /** Name of the analyst the alert is assigned to for triage, investigation, or remediation (supports update). */
		assignedTo?: string

	    /** Azure subscription ID, present if this alert is related to an Azure resource. */
		azureSubscriptionId?: string

	    /** Azure Active Directory tenant ID. */
		azureTenantId?: string

	    /** Category of the alert (for example, credentialTheft, ransomware, etc.). */
		category?: string

	    /** Time at which the alert was closed. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' (supports update). */
		closedDateTime?: string

		cloudAppStates?: CloudAppSecurityState[]

	    /** Customer-provided comments on alert (for customer alert management) (supports update). */
		comments?: string[]

		confidence?: number

	    /** Time at which the alert was created by the alert provider. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. */
		createdDateTime?: string

	    /** Alert description. */
		description?: string

	    /** Set of alerts related to this alert entity (each alert is pushed to the SIEM as a separate record). */
		detectionIds?: string[]

	    /** Time at which the event(s) that served as the trigger(s) to generate the alert occurred. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. */
		eventDateTime?: string

	    /** Analyst feedback on the alert. Possible values are: unknown, truePositive, falsePositive, benignPositive. (supports update) */
		feedback?: AlertFeedback

	    /** Security-related stateful information generated by the provider about the file(s) related to this alert. */
		fileStates?: FileSecurityState[]

	    /** Security-related stateful information generated by the provider about the host(s) related to this alert. */
		hostStates?: HostSecurityState[]

	    /** Time at which the alert entity was last modified. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. */
		lastModifiedDateTime?: string

	    /** Threat Intelligence pertaining to malware related to this alert. */
		malwareStates?: MalwareState[]

	    /** Security-related stateful information generated by the provider about the network connection(s) related to this alert. */
		networkConnections?: NetworkConnection[]

	    /** Security-related stateful information generated by the provider about the process or processes related to this alert. */
		processes?: Process[]

	    /** Vendor/provider recommended action(s) to take as a result of the alert (for example, isolate machine, enforce2FA, reimage host). */
		recommendedActions?: string[]

		registryKeyStates?: RegistryKeyState[]

	    /** Alert severity - set by vendor/provider. */
		severity?: AlertSeverity

	    /** Hyperlinks (URIs) to the source material related to the alert, for example, provider's user interface for alerts or log search, etc. */
		sourceMaterials?: string[]

	    /** Alert lifecycle status (stage). Possible values are: unknown, newAlert, inProgress, resolved. (supports update) */
		status?: AlertStatus

	    /** User-definable labels that can be applied to an alert and can serve as filter conditions (for example "HVA", "SAW", etc.) (supports update). */
		tags?: string[]

	    /** Alert title. */
		title?: string

	    /** Security-related information about the specific properties that triggered the alert (properties appearing in the alert). Alerts might contain information about multiple users, hosts, files, ip addresses. This field indicates which properties triggered the alert generation. */
		triggers?: AlertTrigger[]

	    /** Security-related stateful information generated by the provider about the user accounts related to this alert. */
		userStates?: UserSecurityState[]

	    /** Complex type containing details about the security product/service vendor, provider, and subprovider (for example, vendor=Microsoft; provider=Windows Defender ATP; subProvider=AppLocker). */
		vendorInformation?: SecurityVendorInformation

	    /** Threat intelligence pertaining to one or more vulnerabilities related to this alert. */
		vulnerabilityStates?: VulnerabilityState[]

}

export interface CloudAppSecurityProfile extends Entity {

		azureSubscriptionId?: string

		azureTenantId?: string

		createdDateTime?: string

		deploymentPackageUrl?: string

		destinationServiceName?: string

		isSigned?: boolean

		lastModifiedDateTime?: string

		manifest?: string

		name?: string

		permissionsRequired?: ApplicationPermissionsRequired

		platform?: string

		policyName?: string

		publisher?: string

		riskScore?: string

		tags?: string[]

		type?: string

		vendorInformation?: SecurityVendorInformation

}

export interface DomainSecurityProfile extends Entity {

		activityGroupNames?: string[]

		azureSubscriptionId?: string

		azureTenantId?: string

		countHits?: number

		countInOrg?: number

		domainCategories?: ReputationCategory[]

		domainRegisteredDateTime?: string

		firstSeenDateTime?: string

		lastSeenDateTime?: string

		name?: string

		registrant?: DomainRegistrant

		riskScore?: string

		tags?: string[]

		vendorInformation?: SecurityVendorInformation

}

export interface FileSecurityProfile extends Entity {

		activityGroupNames?: string[]

		azureSubscriptionId?: string

		azureTenantId?: string

		certificateThumbprint?: string

		extensions?: string[]

		fileType?: string

		firstSeenDateTime?: string

		hashes?: FileHash[]

		lastSeenDateTime?: string

		malwareStates?: MalwareState[]

		names?: string[]

		riskScore?: string

		size?: number

		tags?: string[]

		vendorInformation?: SecurityVendorInformation

		vulnerabilityStates?: VulnerabilityState[]

}

export interface HostSecurityProfile extends Entity {

		azureSubscriptionId?: string

		azureTenantId?: string

		firstSeenDateTime?: string

		fqdn?: string

		isAzureAdJoined?: boolean

		isAzureAdRegistered?: boolean

		isHybridAzureDomainJoined?: boolean

		lastSeenDateTime?: string

		logonUsers?: LogonUser[]

		netBiosName?: string

		networkInterfaces?: NetworkInterface[]

		os?: string

		osVersion?: string

		parentHost?: string

		relatedHostIds?: string[]

		riskScore?: string

		tags?: string[]

		vendorInformation?: SecurityVendorInformation

}

export interface IpSecurityProfile extends Entity {

		activityGroupNames?: string[]

		address?: string

		azureSubscriptionId?: string

		azureTenantId?: string

		countHits?: number

		countHosts?: number

		firstSeenDateTime?: string

		ipCategories?: IpCategory[]

		ipReferenceData?: IpReferenceData[]

		lastSeenDateTime?: string

		riskScore?: string

		tags?: string[]

		vendorInformation?: SecurityVendorInformation

}

export interface ProviderTenantSetting extends Entity {

		azureTenantId?: string

		enabled?: boolean

		lastModifiedDateTime?: string

		provider?: string

		vendor?: string

}

export interface SecureScoreControlProfile extends Entity {

		actionType?: string

		actionUrl?: string

		azureTenantId?: string

		controlCategory?: string

		controlStateUpdates?: SecureScoreControlStateUpdate[]

		deprecated?: boolean

		implementationCost?: string

		lastModifiedDateTime?: string

		maxScore?: number

		rank?: number

		remediation?: string

		remediationImpact?: string

		service?: string

		threats?: string[]

		tier?: string

		title?: string

		userImpact?: string

		vendorInformation?: SecurityVendorInformation

}

export interface SecureScore extends Entity {

		activeUserCount?: number

		averageComparativeScores?: AverageComparativeScore[]

		azureTenantId?: string

		controlScores?: ControlScore[]

		createdDateTime?: string

		currentScore?: number

		enabledServices?: string[]

		licensedUserCount?: number

		maxScore?: number

		vendorInformation?: SecurityVendorInformation

}

export interface TiIndicator extends Entity {

		activityGroupNames?: string[]

		azureTenantId?: string

		certificateObservable?: CertificateObservable

		confidence?: number

		description?: string

		detectionProduct?: string

		detectionSignatureId?: string

		detectionSignatureName?: string

		detectionVendor?: string

		diamondModel?: DiamondModel

		emailObservable?: EmailObservable

		expirationDateTime?: string

		externalId?: string

		fileObservable?: FileObservable

		firstReportedDateTime?: string

		hostObservable?: HostObservable

		identityObservable?: IdentityObservable

		ingestedDateTime?: string

		isActive?: boolean

		killChain?: string[]

		knownFalsePositives?: string

		lastModifiedDateTime?: string

		lastReportedDateTime?: string

		malwareFamilyNames?: string[]

		networkObservable?: NetworkObservable

		passiveOnly?: boolean

		severity?: string

		tags?: string[]

		threatType?: ThreatType

		tlpLevel?: TlpLevel

		vendorInformation?: SecurityVendorInformation

		vulnerabilityStates?: VulnerabilityState[]

}

export interface UserSecurityProfile extends Entity {

		aadUserDisplayName?: string

		aadUserId?: string

		accountAliases?: AccountAlias[]

		accountInstance?: number

		accountService?: string

		accountStatus?: AccountStatus

		azureSubscriptionId?: string

		azureTenantId?: string

		domainName?: string

		firstSeenDateTime?: string

		lastSeenDateTime?: string

		lastVpnClientIp?: string

		mfaEnabled?: boolean

		riskScore?: string

		tags?: string[]

		userPrincipalName?: string

		vendorInformation?: SecurityVendorInformation

		vpnClientId?: string

}

export interface BookingNamedEntity extends Entity {

	    /** A name for the derived entity, which interfaces with customers. */
		displayName?: string

}

export interface BookingAppointment extends Entity {

	    /** An additional tracking ID for the appointment, if the appointment has been created directly by the customer on the scheduling page, as opposed to by a staff member on the behalf of the customer. */
		selfServiceAppointmentId?: string

	    /** The ID of the bookingCustomer for this appointment. If no ID is specified when an appointment is created, then a new bookingCustomer object is created. Once set, you should consider the customerId immutable. */
		customerId?: string

	    /** The customer's name. */
		customerName?: string

	    /** The SMTP address of the bookingCustomer who is booking the appointment. */
		customerEmailAddress?: string

	    /** The customer's phone number. */
		customerPhone?: string

	    /** Represents location information for the bookingCustomer who is booking the appointment. */
		customerLocation?: Location

	    /** Notes from the customer associated with this appointment. You can get the value only when reading this bookingAppointment by its ID.  You can set this property only when initially creating an appointment with a new customer. After that point, the value is computed from the customer represented by customerId. */
		customerNotes?: string

	    /** The ID of the bookingService associated with this appointment. */
		serviceId?: string

	    /** The name of the bookingService associated with this appointment.This property is optional when creating a new appointment. If not specified, it is computed from the service associated with the appointment by the serviceId property. */
		serviceName?: string

	    /** The date, time, and time zone that the appointment begins. */
		start?: DateTimeTimeZone

	    /** The date, time, and time zone that the appointment ends. */
		end?: DateTimeTimeZone

	    /** The length of the appointment, denoted in ISO8601 format. */
		duration?: string

	    /** The amount of time to reserve before the appointment begins, for preparation, as an example. The value is expressed in ISO8601 format. */
		preBuffer?: string

	    /** The amount of time to reserve after the appointment ends, for cleaning up, as an example. The value is expressed in ISO8601 format. */
		postBuffer?: string

	    /** The location where the service is delivered. */
		serviceLocation?: Location

	    /** A setting to provide flexibility for the pricing structure of services. Possible values are: undefined, fixedPrice, startingAt, hourly, free, priceVaries, callUs, notSet. */
		priceType?: BookingPriceType

	    /** The regular price for an appointment for the specified bookingService. */
		price?: number

	    /** Notes from a bookingStaffMember. The value of this property is available only when reading this bookingAppointment by its ID. */
		serviceNotes?: string

	    /** The collection of customer reminders sent for this appointment. The value of this property is available only when reading this bookingAppointment by its ID. */
		reminders?: BookingReminder[]

	    /** True indicates that the bookingCustomer for this appointment does not wish to receive a confirmation for this appointment. */
		optOutOfCustomerEmail?: boolean

	    /** The ID of each bookingStaffMember who is scheduled in this appointment. */
		staffMemberIds?: string[]

	    /** The billed amount on the invoice. */
		invoiceAmount?: number

	    /** The date, time, and time zone of the invoice for this appointment. */
		invoiceDate?: DateTimeTimeZone

	    /** The ID of the invoice. */
		invoiceId?: string

	    /** The status of the invoice. Possible values are: draft, reviewing, open, canceled, paid, corrective. */
		invoiceStatus?: BookingInvoiceStatus

	    /** The URL of the invoice in Microsoft Bookings. */
		invoiceUrl?: string

}

export interface BookingBusiness extends BookingNamedEntity {

	    /** The type of business. */
		businessType?: string

	    /** The street address of the business. The address property, together with phone and webSiteUrl, appear in the footer of a business scheduling page. */
		address?: PhysicalAddress

	    /** The telephone number for the business. The phone property, together with address and webSiteUrl, appear in the footer of a business scheduling page. */
		phone?: string

	    /** The email address for the business. */
		email?: string

	    /** The URL of the business web site. The webSiteUrl property, together with address, phone, appear in the footer of a business scheduling page. */
		webSiteUrl?: string

	    /** The code for the currency that the business operates in on Microsoft Bookings. */
		defaultCurrencyIso?: string

	    /** The hours of operation for the business. */
		businessHours?: BookingWorkHours[]

	    /** Specifies how bookings can be created for this business. */
		schedulingPolicy?: BookingSchedulingPolicy

	    /** The scheduling page has been made available to external customers. Use the publish and unpublish actions to set this property. Read-only. */
		isPublished?: boolean

	    /** The URL for the scheduling page, which is set after you publish or unpublish the page. Read-only. */
		publicUrl?: string

	    /** All the appointments in this business. Read-only. Nullable. */
		appointments?: BookingAppointment[]

		calendarView?: BookingAppointment[]

	    /** All the customers of this business. Read-only. Nullable. */
		customers?: BookingCustomer[]

	    /** All the services offered by this business. Read-only. Nullable. */
		services?: BookingService[]

	    /** All the staff members that provide services in this business. Read-only. Nullable. */
		staffMembers?: BookingStaffMember[]

}

export interface BookingPerson extends BookingNamedEntity {

	    /** The email address of the person. */
		emailAddress?: string

}

export interface BookingCustomer extends BookingPerson {

}

export interface BookingService extends BookingNamedEntity {

	    /** The default length of the service, represented in numbers of days, hours, minutes, and seconds. For example, P11D23H59M59.999999999999S. */
		defaultDuration?: string

	    /** The default physical location for the service. */
		defaultLocation?: Location

	    /** The default monetary price for the service. */
		defaultPrice?: number

	    /** The default way the service is charged. Possible values are: undefined, fixedPrice, startingAt, hourly, free, priceVaries, callUs, notSet. */
		defaultPriceType?: BookingPriceType

	    /** The default set of reminders for an appointment of this service. The value of this property is available only when reading this bookingService by its ID. */
		defaultReminders?: BookingReminder[]

	    /** A text description for the service. */
		description?: string

	    /** True means this service is not available to customers for booking. */
		isHiddenFromCustomers?: boolean

	    /** Additional information about this service. */
		notes?: string

	    /** The time to buffer before an appointment for this service can start. */
		preBuffer?: string

	    /** The time to buffer after an appointment for this service ends, and before the next customer appointment can be booked. */
		postBuffer?: string

	    /** The set of policies that determine how appointments for this type of service should be created and managed. */
		schedulingPolicy?: BookingSchedulingPolicy

	    /** Represents those staff members who provide this service. */
		staffMemberIds?: string[]

}

export interface BookingStaffMember extends BookingPerson {

	    /** True means that if the staff member is an Office 365 user, the Bookings API would verify the staff member's availability in their personal calendar in Office 365, before making a booking. */
		availabilityIsAffectedByPersonalCalendar?: boolean

	    /** Identifies a color to represent the staff member. The color corresponds to the color palette in the Staff details page in the Bookings app. */
		colorIndex?: number

	    /** The role of the staff member in the business. Possible values are: guest, administrator, viewer, externalGuest. Required. */
		role?: BookingStaffRole

	    /** True means the staff member's availability is as specified in the businessHours property of the business. False means the availability is determined by the staff member's workingHours property setting. */
		useBusinessHours?: boolean

	    /** The range of hours each day of the week that the staff member is available for booking. By default, they are initialized to be the same as the businessHours property of the business. */
		workingHours?: BookingWorkHours[]

}

export interface BookingCurrency extends Entity {

	    /** The currency symbol. For example, the currency symbol for the US dollar and for the Australian dollar is $. */
		symbol?: string

}

export interface PrivilegedAccess extends Entity {

		displayName?: string

		resources?: GovernanceResource[]

		roleDefinitions?: GovernanceRoleDefinition[]

		roleAssignments?: GovernanceRoleAssignment[]

		roleAssignmentRequests?: GovernanceRoleAssignmentRequest[]

		roleSettings?: GovernanceRoleSetting[]

}

export interface GovernanceResource extends Entity {

		externalId?: string

		type?: string

		displayName?: string

		status?: string

		onboardDateTime?: string

		parent?: GovernanceResource

		roleDefinitions?: GovernanceRoleDefinition[]

		roleAssignments?: GovernanceRoleAssignment[]

		roleAssignmentRequests?: GovernanceRoleAssignmentRequest[]

		roleSettings?: GovernanceRoleSetting[]

}

export interface GovernanceRoleDefinition extends Entity {

		resourceId?: string

		externalId?: string

		templateId?: string

		displayName?: string

		resource?: GovernanceResource

		roleSetting?: GovernanceRoleSetting

}

export interface GovernanceRoleAssignment extends Entity {

		resourceId?: string

		roleDefinitionId?: string

		subjectId?: string

		linkedEligibleRoleAssignmentId?: string

		externalId?: string

		isPermanent?: boolean

		startDateTime?: string

		endDateTime?: string

		memberType?: string

		assignmentState?: string

		status?: string

		resource?: GovernanceResource

		roleDefinition?: GovernanceRoleDefinition

		subject?: GovernanceSubject

		linkedEligibleRoleAssignment?: GovernanceRoleAssignment

}

export interface GovernanceRoleAssignmentRequest extends Entity {

		resourceId?: string

		roleDefinitionId?: string

		subjectId?: string

		linkedEligibleRoleAssignmentId?: string

		type?: string

		assignmentState?: string

		requestedDateTime?: string

		roleAssignmentStartDateTime?: string

		roleAssignmentEndDateTime?: string

		reason?: string

		status?: GovernanceRoleAssignmentRequestStatus

		schedule?: GovernanceSchedule

		resource?: GovernanceResource

		roleDefinition?: GovernanceRoleDefinition

		subject?: GovernanceSubject

}

export interface GovernanceRoleSetting extends Entity {

		resourceId?: string

		roleDefinitionId?: string

		isDefault?: boolean

		lastUpdatedDateTime?: string

		lastUpdatedBy?: string

		adminEligibleSettings?: GovernanceRuleSetting[]

		adminMemberSettings?: GovernanceRuleSetting[]

		userEligibleSettings?: GovernanceRuleSetting[]

		userMemberSettings?: GovernanceRuleSetting[]

		roleDefinition?: GovernanceRoleDefinition

		resource?: GovernanceResource

}

export interface GovernanceSubject extends Entity {

		type?: string

		displayName?: string

		principalName?: string

		email?: string

}

export interface AccessReview extends Entity {

		displayName?: string

		startDateTime?: string

		endDateTime?: string

		status?: string

		createdBy?: UserIdentity

		businessFlowTemplateId?: string

		reviewerType?: string

		description?: string

		settings?: AccessReviewSettings

		reviewedEntity?: Identity

		reviewers?: AccessReviewReviewer[]

		decisions?: AccessReviewDecision[]

		myDecisions?: AccessReviewDecision[]

		instances?: AccessReview[]

}

export interface AccessReviewReviewer extends Entity {

		displayName?: string

		userPrincipalName?: string

}

export interface AccessReviewDecision extends Entity {

		accessReviewId?: string

		reviewedBy?: UserIdentity

		reviewedDateTime?: string

		reviewResult?: string

		justification?: string

		appliedBy?: UserIdentity

		appliedDateTime?: string

		applyResult?: string

		accessRecommendation?: string

}

export interface BusinessFlowTemplate extends Entity {

		displayName?: string

}

export interface Program extends Entity {

		displayName?: string

		description?: string

		controls?: ProgramControl[]

}

export interface ProgramControl extends Entity {

		controlId?: string

		programId?: string

		controlTypeId?: string

		displayName?: string

		status?: string

		owner?: UserIdentity

		resource?: ProgramResource

		createdDateTime?: string

		program?: Program

}

export interface ProgramControlType extends Entity {

		controlTypeGroupId?: string

		displayName?: string

}
export interface AssignedLicense {

	    /** A collection of the unique identifiers for plans that have been disabled. */
		disabledPlans?: string[]

	    /** The unique identifier for the SKU. */
		skuId?: string

}
export interface AssignedPlan {

	    /** The date and time at which the plan was assigned; for example: 2013-01-02T19:32:30Z. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		assignedDateTime?: string

	    /** For example, “Enabled”. */
		capabilityStatus?: string

	    /** The name of the service; for example, “Exchange”. */
		service?: string

	    /** A GUID that identifies the service plan. */
		servicePlanId?: string

}
export interface DeviceKey {

		keyType?: string

		keyMaterial?: number

		deviceId?: string

}
export interface OnPremisesExtensionAttributes {

		extensionAttribute1?: string

		extensionAttribute2?: string

		extensionAttribute3?: string

		extensionAttribute4?: string

		extensionAttribute5?: string

		extensionAttribute6?: string

		extensionAttribute7?: string

		extensionAttribute8?: string

		extensionAttribute9?: string

		extensionAttribute10?: string

		extensionAttribute11?: string

		extensionAttribute12?: string

		extensionAttribute13?: string

		extensionAttribute14?: string

		extensionAttribute15?: string

}
export interface OnPremisesProvisioningError {

	    /** Value of the property causing the error. */
		value?: string

	    /** Category of the provisioning error. Note: Currently, there is only one possible value. Possible value: PropertyConflict - indicates a property value is not unique. Other objects contain the same value for the property. */
		category?: string

	    /** Name of the directory property causing the error. Current possible values: UserPrincipalName or ProxyAddress */
		propertyCausingError?: string

	    /** The date and time at which the error occurred. */
		occurredDateTime?: string

}
export interface PasswordProfile {

		password?: string

		forceChangePasswordNextSignIn?: boolean

}
export interface ProvisionedPlan {

		capabilityStatus?: string

		provisioningStatus?: string

		service?: string

}
export interface MailboxSettings {

	    /** Configuration settings to automatically notify the sender of an incoming email with a message from the signed-in user. */
		automaticRepliesSetting?: AutomaticRepliesSetting

	    /** Folder ID of an archive folder for the user. */
		archiveFolder?: string

	    /** The default time zone for the user's mailbox. */
		timeZone?: string

	    /** The locale information for the user, including the preferred language and country/region. */
		language?: LocaleInfo

	    /** The days of the week and hours in a specific time zone that the user works. */
		workingHours?: WorkingHours

}
export interface AutomaticRepliesSetting {

	    /** Configurations status for automatic replies. Possible values are: disabled, alwaysEnabled, scheduled. */
		status?: AutomaticRepliesStatus

	    /** The set of audience external to the signed-in user's organization who will receive the ExternalReplyMessage, if Status is AlwaysEnabled or Scheduled. Possible values are: none, contactsOnly, all. */
		externalAudience?: ExternalAudienceScope

	    /** The date and time that automatic replies are set to begin, if Status is set to Scheduled. */
		scheduledStartDateTime?: DateTimeTimeZone

	    /** The date and time that automatic replies are set to end, if Status is set to Scheduled. */
		scheduledEndDateTime?: DateTimeTimeZone

	    /** The automatic reply to send to the audience internal to the signed-in user's organization, if Status is AlwaysEnabled or Scheduled. */
		internalReplyMessage?: string

	    /** The automatic reply to send to the specified external audience, if Status is AlwaysEnabled or Scheduled. */
		externalReplyMessage?: string

}
export interface DateTimeTimeZone {

		dateTime?: string

		timeZone?: string

}
export interface LocaleInfo {

	    /** A locale representation for the user, which includes the user's preferred language and country/region. For example, "en-us". The language component follows 2-letter codes as defined in ISO 639-1, and the country component follows 2-letter codes as defined in ISO 3166-1 alpha-2. */
		locale?: string

	    /** A name representing the user's locale in natural language, for example, "English (United States)". */
		displayName?: string

}
export interface WorkingHours {

	    /** The days of the week on which the user works. */
		daysOfWeek?: DayOfWeek[]

	    /** The time of the day that the user starts working. */
		startTime?: string

	    /** The time of the day that the user stops working. */
		endTime?: string

	    /** The time zone to which the working hours apply. */
		timeZone?: TimeZoneBase

}
export interface TimeZoneBase {

	    /** The name of a time zone. It can be a standard time zone name such as "Hawaii-Aleutian Standard Time", or "Customized Time Zone" for a custom time zone. */
		name?: string

}
export interface IdentityUserRisk {

		level?: UserRiskLevel

		lastChangedDateTime?: string

}
export interface AlternativeSecurityId {

		type?: number

		identityProvider?: string

		key?: number

}
export interface PrivacyProfile {

	    /** A valid smtp email address for the privacy statement contact. Not required. */
		contactEmail?: string

	    /** A valid URL format that begins with http:// or https://. Maximum length is 255 characters. The URL that directs to the company's privacy statement. Not required. */
		statementUrl?: string

}
export interface VerifiedDomain {

		capabilities?: string

		isDefault?: boolean

		isInitial?: boolean

		name?: string

		type?: string

}
export interface CertificateConnectorSetting {

	    /** Certificate connector status */
		status?: number

	    /** Certificate expire time */
		certExpiryTime?: string

	    /** Certificate connector enrollment error */
		enrollmentError?: string

	    /** Last time certificate connector connected */
		lastConnectorConnectionTime?: string

	    /** Version of certificate connector */
		connectorVersion?: string

	    /** Version of last uploaded certificate connector */
		lastUploadVersion?: number

}
export interface ExtensionSchemaProperty {

	    /** The name of the strongly typed property defined as part of a schema extension. */
		name?: string

	    /** The type of the property that is defined as part of a schema extension.  Allowed values are Binary, Boolean, DateTime, Integer or String.  See the table below for more details. */
		type?: string

}
export interface ApiApplication {

		requestedAccessTokenVersion?: number

		oauth2PermissionScopes?: PermissionScope[]

}
export interface PermissionScope {

	    /** Permission help text that appears in the admin consent and app assignment experiences. */
		adminConsentDescription?: string

	    /** Display name for the permission that appears in the admin consent and app assignment experiences. */
		adminConsentDisplayName?: string

	    /** Unique scope permission identifier inside the oauth2Permissions collection. */
		id?: string

	    /** When creating or updating a permission, this property must be set to true (which is the default). To delete a permission, this property must first be set to false. At that point, in a subsequent call, the permission may be removed. */
		isEnabled?: boolean

	    /** For internal use. */
		origin?: string

	    /** Specifies whether this scope permission can be consented to by an end user, or whether it is a tenant-wide permission that must be consented to by a company administrator. Possible values are User or Admin. */
		type?: string

	    /** Permission help text that appears in the end-user consent experience. */
		userConsentDescription?: string

	    /** Display name for the permission that appears in the end-user consent experience. */
		userConsentDisplayName?: string

	    /** The value of the scope claim that the resource application should expect in the OAuth 2.0 access token. */
		value?: string

}
export interface AppRole {

		allowedMemberTypes?: string[]

		description?: string

		displayName?: string

		id?: string

		isEnabled?: boolean

		origin?: string

		value?: string

}
export interface InformationalUrl {

		logoUrl?: string

		marketingUrl?: string

		privacyStatementUrl?: string

		supportUrl?: string

		termsOfServiceUrl?: string

}
export interface KeyCredential {

	    /** Custom key identifier */
		customKeyIdentifier?: number

	    /** The date and time at which the credential expires.The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		endDateTime?: string

	    /** The unique identifier (GUID) for the key. */
		keyId?: string

	    /** The date and time at which the credential becomes valid.The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		startDateTime?: string

	    /** The type of key credential; for example, “Symmetric”. */
		type?: string

	    /** A string that describes the purpose for which the key can be used; for example, “Verify”. */
		usage?: string

		key?: number

}
export interface OptionalClaims {

		idToken?: OptionalClaim

		accessToken?: OptionalClaim

		saml2Token?: OptionalClaim

}
export interface OptionalClaim {

		name?: string

		source?: string

		essential?: boolean

		additionalProperties?: string[]

}
export interface ParentalControlSettings {

		countriesBlockedForMinors?: string[]

		legalAgeGroupRule?: string

}
export interface PasswordCredential {

		customKeyIdentifier?: number

	    /** The date and time at which the password expires.The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		endDateTime?: string

		keyId?: string

	    /** The date and time at which the password becomes valid.The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		startDateTime?: string

	    /** The passwords must be 16-64 characters in length */
		secretText?: string

		hint?: string

}
export interface PublicClientApplication {

		redirectUris?: string[]

}
export interface RequiredResourceAccess {

	    /** The unique identifier for the resource that the application requires access to.  This should be equal to the appId declared on the target resource application. */
		resourceAppId?: string

	    /** The list of OAuth2.0 permission scopes and app roles that the application requires from the specified resource. */
		resourceAccess?: ResourceAccess[]

}
export interface ResourceAccess {

	    /** The unique identifier for one of the oAuth2Permission or appRole instances that the resource application exposes. */
		id?: string

	    /** Specifies whether the id property references an oAuth2Permission or an appRole. Possible values are "scope" or "role". */
		type?: string

}
export interface WebApplication {

		redirectUris?: string[]

		oauth2AllowImplicitFlow?: boolean

		logoutUrl?: string

		implicitGrantSettings?: ImplicitGrantSettings

}
export interface ImplicitGrantSettings {

		enableIdTokenIssuance?: boolean

		enableAccessTokenIssuance?: boolean

}
export interface SettingValue {

	    /** Name of the setting (as defined by the directorySettingTemplate). */
		name?: string

	    /** Value of the setting. */
		value?: string

}
export interface SettingTemplateValue {

	    /** Name of the setting. Read-only. */
		name?: string

	    /** Type of the setting. Read-only. */
		type?: string

	    /** Default value for the setting. Read-only. */
		defaultValue?: string

	    /** Description of the setting. Read-only. */
		description?: string

}
export interface DomainState {

	    /** Current status of the operation.  Scheduled - Operation has been scheduled but has not started.  InProgress - Task has started and is in progress.  Failed - Operation has failed. */
		status?: string

	    /** Type of asynchronous operation. The values can be ForceDelete or Verification */
		operation?: string

	    /** Timestamp for when the last activity occurred. The value is updated when an operation is scheduled, the asynchronous task starts, and when the operation completes. */
		lastActionDateTime?: string

}
export interface ServicePlanInfo {

	    /** The unique identifier of the service plan. */
		servicePlanId?: string

	    /** The name of the service plan. */
		servicePlanName?: string

	    /** The provisioning status of the service plan. Possible values:"Success" - Service is fully provisioned."Disabled" - Service has been disabled."PendingInput" - Service is not yet provisioned; awaiting service confirmation."PendingActivation" - Service is provisioned but requires explicit activation by administrator (for example, Intune_O365 service plan)."PendingProvisioning" - Microsoft has added a new service to the product SKU and it has not been activated in the tenant, yet. */
		provisioningStatus?: string

	    /** The object the service plan can be assigned to. Possible values:"User" - service plan can be assigned to individual users."Company" - service plan can be assigned to the entire tenant. */
		appliesTo?: string

}
export interface AddIn {

		id?: string

		type?: string

		properties?: KeyValue[]

}
export interface KeyValue {

	    /** Key. */
		key?: string

	    /** Value. */
		value?: string

}
export interface OAuth2Permission {

	    /** Permission help text that appears in the admin consent and app assignment experiences. */
		adminConsentDescription?: string

	    /** Display name for the permission that appears in the admin consent and app assignment experiences. */
		adminConsentDisplayName?: string

	    /** Unique scope permission identifier inside the oauth2Permissions collection. */
		id?: string

	    /** When creating or updating a permission, this property must be set to true (which is the default). To delete a permission, this property must first be set to false.  At that point, in a subsequent call, the permission may be removed. */
		isEnabled?: boolean

		origin?: string

	    /** Specifies whether this scope permission can be consented to by an end user, or whether it is a tenant-wide permission that must be consented to by a Company Administrator.  Possible values are "User" or "Admin". */
		type?: string

	    /** Permission help text that appears in the end user consent experience. */
		userConsentDescription?: string

	    /** Display name for the permission that appears in the end user consent experience. */
		userConsentDisplayName?: string

	    /** The value of the scope claim that the resource application should expect in the OAuth 2.0 access token. */
		value?: string

}
export interface LicenseUnitsDetail {

	    /** The number of units that are enabled. */
		enabled?: number

	    /** The number of units that are suspended. */
		suspended?: number

	    /** The number of units that are in warning status. */
		warning?: number

}
export interface Identity {

	    /** Unique identifier for the identity. */
		id?: string

	    /** The identity's display name. Note that this may not always be available or up to date. For example, if a user changes their display name, the API may show the new value in a future response, but the items associated with the user won't show up as having changed when using delta. */
		displayName?: string

}
export interface ComplexExtensionValue {

}
export interface PreAuthorizedApplication {

	    /** The unique identifier for the application. */
		appId?: string

	    /** The unique identifier for either the publishedPermissionScope or appRole the application requires. */
		permissionIds?: string[]

}
export interface AllowedDataLocationInfo {

}
export interface ImageInfo {

	    /** Optional; URI that points to an icon which represents the application used to generate the activity */
		iconUrl?: string

		alternativeText?: string

	    /** Optional; alt-text accessible content for the image */
		alternateText?: string

	    /** Optional; parameter used to indicate the server is able to render image dynamically in response to parameterization. For example – a high contrast image */
		addImageQuery?: boolean

}
export interface VisualInfo {

	    /** Optional. JSON object used to represent an icon which represents the application used to generate the activity */
		attribution?: ImageInfo

	    /** Optional. Background color used to render the activity in the UI - brand color for the application source of the activity. Must be a valid hex color */
		backgroundColor?: string

	    /** Optional. Longer text description of the user's unique activity (example: document name, first sentence, and/or metadata) */
		description?: string

	    /** Required. Short text description of the user's unique activity (for example, document name in cases where an activity refers to document creation) */
		displayText?: string

	    /** Optional. Custom piece of data - JSON object used to provide custom content to render the activity in the Windows Shell UI */
		content?: any

}
export interface Root {

}
export interface SharepointIds {

	    /** The unique identifier (guid) for the item's list in SharePoint. */
		listId?: string

	    /** An integer identifier for the item within the containing list. */
		listItemId?: string

	    /** The unique identifier (guid) for the item within OneDrive for Business or a SharePoint site. */
		listItemUniqueId?: string

	    /** The unique identifier (guid) for the item's site collection (SPSite). */
		siteId?: string

	    /** The SharePoint URL for the site that contains the item. */
		siteUrl?: string

	    /** The unique identifier (guid) for the tenancy. */
		tenantId?: string

	    /** The unique identifier (guid) for the item's site (SPWeb). */
		webId?: string

}
export interface SiteCollection {

	    /** The geographic region code for where this site collection resides. Read-only. */
		dataLocationCode?: string

	    /** The hostname for the site collection. Read-only. */
		hostname?: string

	    /** If present, indicates that this is a root site collection in SharePoint. Read-only. */
		root?: Root

}
export interface ListInfo {

	    /** If true, indicates that content types are enabled for this list. */
		contentTypesEnabled?: boolean

	    /** If true, indicates that the list is not normally visible in the SharePoint user experience. */
		hidden?: boolean

	    /** An enumerated value that represents the base list template used in creating the list. Possible values include documentLibrary, genericList, task, survey, announcements, contacts, and more. */
		template?: string

}
export interface SystemFacet {

}
export interface IdentitySet {

	    /** Optional. The application associated with this action. */
		application?: Identity

	    /** Optional. The device associated with this action. */
		device?: Identity

	    /** Optional. The user associated with this action. */
		user?: Identity

}
export interface Quota {

	    /** Total space consumed by files in the recycle bin, in bytes. Read-only. */
		deleted?: number

	    /** Total space remaining before reaching the quota limit, in bytes. Read-only. */
		remaining?: number

	    /** Enumeration value that indicates the state of the storage space. Read-only. */
		state?: string

	    /** Total allowed storage space, in bytes. Read-only. */
		total?: number

	    /** Total space used, in bytes. Read-only. */
		used?: number

}
export interface Audio {

	    /** The title of the album for this audio file. */
		album?: string

	    /** The artist named on the album for the audio file. */
		albumArtist?: string

	    /** The performing artist for the audio file. */
		artist?: string

	    /** Bitrate expressed in kbps. */
		bitrate?: number

	    /** The name of the composer of the audio file. */
		composers?: string

	    /** Copyright information for the audio file. */
		copyright?: string

	    /** The number of the disc this audio file came from. */
		disc?: number

	    /** The total number of discs in this album. */
		discCount?: number

	    /** Duration of the audio file, expressed in milliseconds */
		duration?: number

	    /** The genre of this audio file. */
		genre?: string

	    /** Indicates if the file is protected with digital rights management. */
		hasDrm?: boolean

	    /** Indicates if the file is encoded with a variable bitrate. */
		isVariableBitrate?: boolean

	    /** The title of the audio file. */
		title?: string

	    /** The number of the track on the original disc for this audio file. */
		track?: number

	    /** The total number of tracks on the original disc for this audio file. */
		trackCount?: number

	    /** The year the audio file was recorded. */
		year?: number

}
export interface Deleted {

	    /** Represents the state of the deleted item. */
		state?: string

}
export interface File {

	    /** Hashes of the file's binary content, if available. Read-only. */
		hashes?: Hashes

	    /** The MIME type for the file. This is determined by logic on the server and might not be the value provided when the file was uploaded. Read-only. */
		mimeType?: string

		processingMetadata?: boolean

}
export interface Hashes {

	    /** The CRC32 value of the file (if available). Read-only. */
		crc32Hash?: string

	    /** A proprietary hash of the file that can be used to determine if the contents of the file have changed (if available). Read-only. */
		quickXorHash?: string

	    /** SHA1 hash for the contents of the file (if available). Read-only. */
		sha1Hash?: string

}
export interface FileSystemInfo {

	    /** The UTC date and time the file was created on a client. */
		createdDateTime?: string

	    /** The UTC date and time the file was last accessed. Available for the recent file list only. */
		lastAccessedDateTime?: string

	    /** The UTC date and time the file was last modified on a client. */
		lastModifiedDateTime?: string

}
export interface Folder {

	    /** Number of children contained immediately within this container. */
		childCount?: number

	    /** A collection of properties defining the recommended view for the folder. */
		view?: FolderView

}
export interface FolderView {

	    /** The method by which the folder should be sorted. */
		sortBy?: string

		sortOrder?: string

	    /** The type of view that should be used to represent the folder. */
		viewType?: string

}
export interface Image {

	    /** Optional. Height of the image, in pixels. Read-only. */
		height?: number

	    /** Optional. Width of the image, in pixels. Read-only. */
		width?: number

}
export interface GeoCoordinates {

	    /** Optional. The altitude (height), in feet,  above sea level for the item. Read-only. */
		altitude?: number

	    /** Optional. The latitude, in decimal, for the item. Read-only. */
		latitude?: number

	    /** Optional. The longitude, in decimal, for the item. Read-only. */
		longitude?: number

}
export interface Package {

		type?: string

}
export interface Photo {

	    /** Camera manufacturer. Read-only. */
		cameraMake?: string

	    /** Camera model. Read-only. */
		cameraModel?: string

	    /** The denominator for the exposure time fraction from the camera. Read-only. */
		exposureDenominator?: number

	    /** The numerator for the exposure time fraction from the camera. Read-only. */
		exposureNumerator?: number

	    /** The F-stop value from the camera. Read-only. */
		fNumber?: number

	    /** The focal length from the camera. Read-only. */
		focalLength?: number

	    /** The ISO value from the camera. Read-only. */
		iso?: number

	    /** Represents the date and time the photo was taken. Read-only. */
		takenDateTime?: string

}
export interface PublicationFacet {

	    /** The state of publication for this document. Either published or checkout. Read-only. */
		level?: string

	    /** The unique identifier for the version that is visible to the current caller. Read-only. */
		versionId?: string

}
export interface RemoteItem {

	    /** Identity of the user, device, and application which created the item. Read-only. */
		createdBy?: IdentitySet

	    /** Date and time of item creation. Read-only. */
		createdDateTime?: string

	    /** Indicates that the remote item is a file. Read-only. */
		file?: File

	    /** Information about the remote item from the local file system. Read-only. */
		fileSystemInfo?: FileSystemInfo

	    /** Indicates that the remote item is a folder. Read-only. */
		folder?: Folder

	    /** Unique identifier for the remote item in its drive. Read-only. */
		id?: string

	    /** Identity of the user, device, and application which last modified the item. Read-only. */
		lastModifiedBy?: IdentitySet

	    /** Date and time the item was last modified. Read-only. */
		lastModifiedDateTime?: string

	    /** Optional. Filename of the remote item. Read-only. */
		name?: string

	    /** If present, indicates that this item is a package instead of a folder or file. Packages are treated like files in some contexts and folders in others. Read-only. */
		package?: Package

	    /** Properties of the parent of the remote item. Read-only. */
		parentReference?: ItemReference

	    /** Indicates that the item has been shared with others and provides information about the shared state of the item. Read-only. */
		shared?: Shared

	    /** Provides interop between items in OneDrive for Business and SharePoint with the full set of item identifiers. Read-only. */
		sharepointIds?: SharepointIds

	    /** Size of the remote item. Read-only. */
		size?: number

		specialFolder?: SpecialFolder

	    /** DAV compatible URL for the item. */
		webDavUrl?: string

	    /** URL that displays the resource in the browser. Read-only. */
		webUrl?: string

}
export interface ItemReference {

	    /** Unique identifier of the drive instance that contains the item. Read-only. */
		driveId?: string

	    /** Identifies the type of drive. See [drive][] resource for values. */
		driveType?: string

	    /** Unique identifier of the item in the drive. Read-only. */
		id?: string

	    /** The name of the item being referenced. Read-only. */
		name?: string

		parent?: ItemReference

	    /** Path that can be used to navigate to the item. Read-only. */
		path?: string

	    /** A unique identifier for a shared resource that can be accessed via the [Shares][] API. */
		shareId?: string

	    /** Returns identifiers useful for SharePoint REST compatibility. Read-only. */
		sharepointIds?: SharepointIds

}
export interface Shared {

	    /** The identity of the owner of the shared item. Read-only. */
		owner?: IdentitySet

	    /** Indicates the scope of how the item is shared: anonymous, organization, or users. Read-only. */
		scope?: string

	    /** The identity of the user who shared the item. Read-only. */
		sharedBy?: IdentitySet

	    /** The UTC date and time when the item was shared. Read-only. */
		sharedDateTime?: string

}
export interface SpecialFolder {

	    /** The unique identifier for this item in the /drive/special collection */
		name?: string

}
export interface SearchResult {

	    /** A callback URL that can be used to record telemetry information. The application should issue a GET on this URL if the user interacts with this item to improve the quality of results. */
		onClickTelemetryUrl?: string

}
export interface Video {

	    /** Number of audio bits per sample. */
		audioBitsPerSample?: number

	    /** Number of audio channels. */
		audioChannels?: number

	    /** Name of the audio format (AAC, MP3, etc.). */
		audioFormat?: string

	    /** Number of audio samples per second. */
		audioSamplesPerSecond?: number

	    /** Bit rate of the video in bits per second. */
		bitrate?: number

	    /** Duration of the file in milliseconds. */
		duration?: number

	    /** "Four character code" name of the video format. */
		fourCC?: string

		frameRate?: number

	    /** Height of the video, in pixels. */
		height?: number

	    /** Width of the video, in pixels. */
		width?: number

}
export interface WorkbookSessionInfo {

	    /** Id of the workbook session. */
		id?: string

	    /** true for persistent session. false for non-persistent session (view mode) */
		persistChanges?: boolean

}
export interface WorkbookFilterCriteria {

		color?: string

		criterion1?: string

		criterion2?: string

		dynamicCriteria?: string

		filterOn?: string

		icon?: WorkbookIcon

		operator?: string

		values?: any

}
export interface WorkbookIcon {

		index?: number

		set?: string

}
export interface WorkbookSortField {

		ascending?: boolean

		color?: string

		dataOption?: string

		icon?: WorkbookIcon

		key?: number

		sortOn?: string

}
export interface WorkbookWorksheetProtectionOptions {

		allowAutoFilter?: boolean

		allowDeleteColumns?: boolean

		allowDeleteRows?: boolean

		allowFormatCells?: boolean

		allowFormatColumns?: boolean

		allowFormatRows?: boolean

		allowInsertColumns?: boolean

		allowInsertHyperlinks?: boolean

		allowInsertRows?: boolean

		allowPivotTables?: boolean

		allowSort?: boolean

}
export interface WorkbookFilterDatetime {

		date?: string

		specificity?: string

}
export interface WorkbookRangeReference {

		address?: string

}
export interface CustomTimeZone extends TimeZoneBase {

	    /** The time offset of the time zone from Coordinated Universal Time (UTC). This value is in minutes. Time zones that are ahead of UTC have a positive offset; time zones that are behind UTC have a negative offset. */
		bias?: number

	    /** Specifies when the time zone switches from daylight saving time to standard time. */
		standardOffset?: StandardTimeZoneOffset

	    /** Specifies when the time zone switches from standard time to daylight saving time. */
		daylightOffset?: DaylightTimeZoneOffset

}
export interface StandardTimeZoneOffset {

	    /** Represents the time of day when the transition from daylight saving time to standard time occurs. */
		time?: string

	    /** Represents the nth occurrence of the day of week that the transition from daylight saving time to standard time occurs. */
		dayOccurrence?: number

	    /** Represents the day of the week when the transition from daylight saving time to standard time. */
		dayOfWeek?: DayOfWeek

	    /** Represents the month of the year when the transition from daylight saving time to standard time occurs. */
		month?: number

	    /** Represents how frequently in terms of years the change from daylight saving time to standard time occurs. For example, a value of 0 means every year. */
		year?: number

}
export interface DaylightTimeZoneOffset extends StandardTimeZoneOffset {

	    /** The time offset from Coordinated Universal Time (UTC) for daylight saving time. This value is in minutes. */
		daylightBias?: number

}
export interface Recipient {

	    /** The recipient's email address. */
		emailAddress?: EmailAddress

}
export interface EmailAddress {

	    /** The display name of the person or entity. */
		name?: string

	    /** The email address of the person or entity. */
		address?: string

}
export interface AttendeeBase extends Recipient {

	    /** The type of attendee. Possible values are: required, optional, resource. Currently if the attendee is a person, findMeetingTimes always considers the person is of the Required type. */
		type?: AttendeeType

}
export interface MeetingTimeSuggestionsResult {

	    /** An array of meeting suggestions. */
		meetingTimeSuggestions?: MeetingTimeSuggestion[]

	    /** A reason for not returning any meeting suggestions. Possible values are: attendeesUnavailable, attendeesUnavailableOrUnknown, locationsUnavailable, organizerUnavailable, or unknown. This property is an empty string if the meetingTimeSuggestions property does include any meeting suggestions. */
		emptySuggestionsReason?: string

}
export interface MeetingTimeSuggestion {

	    /** A time period suggested for the meeting. */
		meetingTimeSlot?: TimeSlot

	    /** A percentage that represents the likelhood of all the attendees attending. */
		confidence?: number

	    /** Availability of the meeting organizer for this meeting suggestion. Possible values are: free, tentative, busy, oof, workingElsewhere, unknown. */
		organizerAvailability?: FreeBusyStatus

	    /** An array that shows the availability status of each attendee for this meeting suggestion. */
		attendeeAvailability?: AttendeeAvailability[]

	    /** An array that specifies the name and geographic location of each meeting location for this meeting suggestion. */
		locations?: Location[]

	    /** Reason for suggesting the meeting time. */
		suggestionReason?: string

}
export interface TimeSlot {

	    /** The time the period ends. */
		start?: DateTimeTimeZone

	    /** The time a period begins. */
		end?: DateTimeTimeZone

}
export interface AttendeeAvailability {

	    /** The type of attendee - whether it's a person or a resource, and whether required or optional if it's a person. */
		attendee?: AttendeeBase

	    /** The availability status of the attendee. Possible values are: free, tentative, busy, oof, workingElsewhere, unknown. */
		availability?: FreeBusyStatus

}
export interface Location {

	    /** The name associated with the location. */
		displayName?: string

	    /** Optional email address of the location. */
		locationEmailAddress?: string

	    /** The street address of the location. */
		address?: PhysicalAddress

	    /** The geographic coordinates and elevation of the location. */
		coordinates?: OutlookGeoCoordinates

	    /** Optional URI representing the location. */
		locationUri?: string

	    /** The type of location. Possible values are: default, conferenceRoom, homeAddress, businessAddress,geoCoordinates, streetAddress, hotel, restaurant, localBusiness, postalAddress. Read-only. */
		locationType?: LocationType

	    /** For internal use only. */
		uniqueId?: string

	    /** For internal use only. */
		uniqueIdType?: LocationUniqueIdType

}
export interface PhysicalAddress {

	    /** The type of address. Possible values are: unknown, home, business, other. */
		type?: PhysicalAddressType

	    /** The post office box number. */
		postOfficeBox?: string

	    /** The street. */
		street?: string

	    /** The city. */
		city?: string

	    /** The state. */
		state?: string

	    /** The country or region. It's a free-format string value, for example, "United States". */
		countryOrRegion?: string

	    /** The postal code. */
		postalCode?: string

}
export interface OutlookGeoCoordinates {

	    /** The altitude of the location. */
		altitude?: number

	    /** The latitude of the location. */
		latitude?: number

	    /** The longitude of the location. */
		longitude?: number

	    /** The accuracy of the latitude and longitude. As an example, the accuracy can be measured in meters, such as the latitude and longitude are accurate to within 50 meters. */
		accuracy?: number

	    /** The accuracy of the altitude. */
		altitudeAccuracy?: number

}
export interface LocationConstraint {

		isRequired?: boolean

		suggestLocation?: boolean

		locations?: LocationConstraintItem[]

}
export interface LocationConstraintItem extends Location {

	    /** If set to true and the specified resource is busy, findMeetingTimes looks for another resource that is free. If set to false and the specified resource is busy, findMeetingTimes returns the resource best ranked in the user's cache without checking if it's free. Default is true. */
		resolveAvailability?: boolean

}
export interface TimeConstraint {

		activityDomain?: ActivityDomain

		timeslots?: TimeSlot[]

}
export interface MeetingTimeCandidatesResult {

	    /** An array of meeting suggestions. */
		meetingTimeSlots?: MeetingTimeCandidate[]

	    /** A reason for not returning any meeting suggestions. Possible values are: attendeesUnavailable, attendeesUnavailableOrUnknown, locationsUnavailable, organizerUnavailable, or unknown. */
		emptySuggestionsHint?: string

}
export interface MeetingTimeCandidate {

	    /** A time period suggested for the meeting. */
		meetingTimeSlot?: TimeSlotOLD

	    /** A percentage that represents the likelhood of all the attendees attending. */
		confidence?: number

	    /** Availability of the meeting organizer for this meeting suggestion. Possible values are: free, tentative, busy, oof, workingElsewhere, unknown. */
		organizerAvailability?: FreeBusyStatus

	    /** An array that shows the availability status of each attendee for this meeting suggestion. */
		attendeeAvailability?: AttendeeAvailability[]

	    /** An array that specifies the name and geographic location of each meeting location for this meeting suggestion. */
		locations?: Location[]

	    /** Reason for suggesting the meeting time. */
		suggestionHint?: string

}
export interface TimeSlotOLD {

		start?: TimeStamp

		end?: TimeStamp

}
export interface TimeStamp {

	    /** The date portion of the timestamp. */
		date?: string

	    /** The time portion of the timestamp. */
		time?: string

	    /** The timezone portion of the timestamp, which is one of the 24 longitudinal areas in the world. */
		timeZone?: string

}
export interface MailTips {

	    /** The email address of the recipient to get mailtips for. */
		emailAddress?: EmailAddress

	    /** Mail tips for automatic reply if it has been set up by the recipient. */
		automaticReplies?: AutomaticRepliesMailTips

	    /** The mailbox full status of the recipient. */
		mailboxFull?: boolean

	    /** A custom mail tip that can be set on the recipient's mailbox. */
		customMailTip?: string

	    /** The number of external members if the recipient is a distribution list. */
		externalMemberCount?: number

	    /** The number of members if the recipient is a distribution list. */
		totalMemberCount?: number

	    /** Whether the recipient's mailbox is restricted, for example, accepting messages from only a predefined list of senders, rejecting messages from a predefined list of senders, or accepting messages from only authenticated senders. */
		deliveryRestricted?: boolean

	    /** Whether sending messages to the recipient requires approval. For example, if the recipient is a large distribution list and a moderator has been set up to approve messages sent to that distribution list, or if sending messages to a recipient requires approval of the recipient's manager. */
		isModerated?: boolean

	    /** The scope of the recipient. Possible values are: none, internal, external, externalPartner, externalNonParther. For example, an administrator can set another organization to be its "partner". The scope is useful if an administrator wants certain mailtips to be accessible to certain scopes. It's also useful to senders to inform them that their message may leave the organization, helping them make the correct decisions about wording, tone and content. */
		recipientScope?: RecipientScopeType

	    /** Recipients suggested based on previous contexts where they appear in the same message. */
		recipientSuggestions?: Recipient[]

	    /** The maximum message size that has been configured for the recipient's organization or mailbox. */
		maxMessageSize?: number

	    /** Errors that occur during the getMailTips action. */
		error?: MailTipsError

}
export interface AutomaticRepliesMailTips {

	    /** The automatic reply message. */
		message?: string

	    /** The language that the automatic reply message is in. */
		messageLanguage?: LocaleInfo

	    /** The date and time that automatic replies are set to begin. */
		scheduledStartTime?: DateTimeTimeZone

	    /** The date and time that automatic replies are set to end. */
		scheduledEndTime?: DateTimeTimeZone

}
export interface MailTipsError {

	    /** The error message. */
		message?: string

	    /** The error code. */
		code?: string

}
export interface Reminder {

	    /** The unique ID of the event. Read only. */
		eventId?: string

	    /** The date, time, and time zone that the event starts. */
		eventStartTime?: DateTimeTimeZone

	    /** The date, time and time zone that the event ends. */
		eventEndTime?: DateTimeTimeZone

	    /** Identifies the version of the reminder. Every time the reminder is changed, changeKey changes as well. This allows Exchange to apply changes to the correct version of the object. */
		changeKey?: string

	    /** The text of the event's subject line. */
		eventSubject?: string

	    /** The location of the event. */
		eventLocation?: Location

	    /** The URL to open the event in Outlook on the web.The event will open in the browser if you are logged in to your mailbox via Outlook on the web. You will be prompted to login if you are not already logged in with the browser.This URL can be accessed from within an iFrame. */
		eventWebLink?: string

	    /** The date, time, and time zone that the reminder is set to occur. */
		reminderFireTime?: DateTimeTimeZone

}
export interface TimeZoneInformation {

	    /** An identifier for the time zone. */
		alias?: string

	    /** A display string that represents the time zone. */
		displayName?: string

}
export interface InternetMessageHeader {

	    /** Represents the key in a key-value pair. */
		name?: string

	    /** The value in a key-value pair. */
		value?: string

}
export interface ItemBody {

	    /** The type of the content. Possible values are Text and HTML. */
		contentType?: BodyType

	    /** The content of the item. */
		content?: string

}
export interface MentionsPreview {

	    /** True if the signed-in user is mentioned in the parent resource instance. Read-only. Supports filter. */
		isMentioned?: boolean

}
export interface FollowupFlag {

	    /** The date and time that the follow-up was finished. */
		completedDateTime?: DateTimeTimeZone

	    /** The date and time that the follow-up is to be finished. */
		dueDateTime?: DateTimeTimeZone

	    /** The date and time that the follow-up is to begin. */
		startDateTime?: DateTimeTimeZone

	    /** The status for follow-up for an item. Possible values are notFlagged, complete, and flagged. */
		flagStatus?: FollowupFlagStatus

}
export interface ScheduleInformation {

		scheduleId?: string

		scheduleItems?: ScheduleItem[]

		availabilityView?: string

		error?: FreeBusyError

		workingHours?: WorkingHours

}
export interface ScheduleItem {

		start?: DateTimeTimeZone

		end?: DateTimeTimeZone

		isPrivate?: boolean

		status?: FreeBusyStatus

		subject?: string

		location?: string

}
export interface FreeBusyError {

		message?: string

		responseCode?: string

}
export interface ResponseStatus {

	    /** The response type. Possible values are: None, Organizer, TentativelyAccepted, Accepted, Declined, NotResponded. */
		response?: ResponseType

	    /** The date and time that the response was returned. It uses ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		time?: string

}
export interface PatternedRecurrence {

	    /** The frequency of an event. */
		pattern?: RecurrencePattern

	    /** The duration of an event. */
		range?: RecurrenceRange

}
export interface RecurrencePattern {

	    /** The recurrence pattern type: daily, weekly, absoluteMonthly, relativeMonthly, absoluteYearly, relativeYearly. Required. */
		type?: RecurrencePatternType

	    /** The number of units between occurrences, where units can be in days, weeks, months, or years, depending on the type. Required. */
		interval?: number

	    /** The month in which the event occurs.  This is a number from 1 to 12. */
		month?: number

	    /** The day of the month on which the event occurs. Required if type is absoluteMonthly or absoluteYearly. */
		dayOfMonth?: number

	    /** A collection of the days of the week on which the event occurs. Possible values are: sunday, monday, tuesday, wednesday, thursday, friday, saturday. If type is relativeMonthly or relativeYearly, and daysOfWeek specifies more than one day, the event falls on the first day that satisfies the pattern.  Required if type is weekly, relativeMonthly, or relativeYearly. */
		daysOfWeek?: DayOfWeek[]

	    /** The first day of the week. Possible values are: sunday, monday, tuesday, wednesday, thursday, friday, saturday. Default is sunday. Required if type is weekly. */
		firstDayOfWeek?: DayOfWeek

	    /** Specifies on which instance of the allowed days specified in daysOfsWeek the event occurs, counted from the first instance in the month. Possible values are: first, second, third, fourth, last. Default is first. Optional and used if type is relativeMonthly or relativeYearly. */
		index?: WeekIndex

}
export interface RecurrenceRange {

	    /** The recurrence range. Possible values are: endDate, noEnd, numbered. Required. */
		type?: RecurrenceRangeType

	    /** The date to start applying the recurrence pattern. The first occurrence of the meeting may be this date or later, depending on the recurrence pattern of the event. Must be the same value as the start property of the recurring event. Required. */
		startDate?: string

	    /** The date to stop applying the recurrence pattern. Depending on the recurrence pattern of the event, the last occurrence of the meeting may not be this date. Required if type is endDate. */
		endDate?: string

	    /** Time zone for the startDate and endDate properties. Optional. If not specified, the time zone of the event is used. */
		recurrenceTimeZone?: string

	    /** The number of times to repeat the event. Required and must be positive if type is numbered. */
		numberOfOccurrences?: number

}
export interface Attendee extends AttendeeBase {

	    /** The attendee's response (none, accepted, declined, etc.) for the event and date-time that the response was sent. */
		status?: ResponseStatus

}
export interface EventCreationOptions {

		saveToGroupCalendarOnly?: boolean

}
export interface Phone {

	    /** The type of phone number. Possible values are: home, business, mobile, other, assistant, homeFax, businessFax, otherFax, pager, radio. */
		type?: PhoneType

	    /** The phone number. */
		number?: string

}
export interface TypedEmailAddress extends EmailAddress {

		type?: EmailType

		otherLabel?: string

}
export interface Website {

	    /** Possible values are: other, home, work, blog, profile. */
		type?: WebsiteType

	    /** The URL of the website. */
		address?: string

	    /** The display name of the web site. */
		displayName?: string

}
export interface MessageRulePredicates {

	    /** Represents the categories that an incoming message should be labeled with in order for the condition or exception to apply. */
		categories?: string[]

	    /** Represents the strings that appear in the subject of an incoming message in order for the condition or exception to apply. */
		subjectContains?: string[]

	    /** Represents the strings that should appear in the body of an incoming message in order for the condition or exception to apply. */
		bodyContains?: string[]

	    /** Represents the strings that should appear in the body or subject of an incoming message in order for the condition or exception to apply. */
		bodyOrSubjectContains?: string[]

	    /** Represents the strings that appear in the from property of an incoming message in order for the condition or exception to apply. */
		senderContains?: string[]

	    /** Represents the strings that appear in either the toRecipients or ccRecipients properties of an incoming message in order for the condition or exception to apply. */
		recipientContains?: string[]

	    /** Represents the strings that appear in the headers of an incoming message in order for the condition or exception to apply. */
		headerContains?: string[]

	    /** Represents the flag-for-action value that appears on an incoming message in order for the condition or exception to apply. Possible values are: any, call, doNotForward, followUp, fyi, forward, noResponseNecessary, read, reply, replyToAll, review. */
		messageActionFlag?: MessageActionFlag

	    /** The importance that is stamped on an incoming message in order for the condition or exception to apply: low, normal, high. */
		importance?: Importance

	    /** Represents the sensitivity level that must be stamped on an incoming message in order for the condition or exception to apply. Possible values are: normal, personal, private, confidential. */
		sensitivity?: Sensitivity

	    /** Represents the specific sender email addresses of an incoming message in order for the condition or exception to apply. */
		fromAddresses?: Recipient[]

	    /** Represents the email addresses that an incoming message must have been sent to in order for the condition or exception to apply. */
		sentToAddresses?: Recipient[]

	    /** Indicates whether the owner of the mailbox must be in the toRecipients property of an incoming message in order for the condition or exception to apply. */
		sentToMe?: boolean

	    /** Indicates whether the owner of the mailbox must be the only recipient in an incoming message in order for the condition or exception to apply. */
		sentOnlyToMe?: boolean

	    /** Indicates whether the owner of the mailbox must be in the ccRecipients property of an incoming message in order for the condition or exception to apply. */
		sentCcMe?: boolean

	    /** Indicates whether the owner of the mailbox must be in either a toRecipients or ccRecipients property of an incoming message in order for the condition or exception to apply. */
		sentToOrCcMe?: boolean

	    /** Indicates whether the owner of the mailbox must not be a recipient of an incoming message in order for the condition or exception to apply. */
		notSentToMe?: boolean

	    /** Indicates whether an incoming message must have attachments in order for the condition or exception to apply. */
		hasAttachments?: boolean

	    /** Indicates whether an incoming message must be an approval request in order for the condition or exception to apply. */
		isApprovalRequest?: boolean

	    /** Indicates whether an incoming message must be automatically forwarded in order for the condition or exception to apply. */
		isAutomaticForward?: boolean

	    /** Indicates whether an incoming message must be an auto reply in order for the condition or exception to apply. */
		isAutomaticReply?: boolean

	    /** Indicates whether an incoming message must be encrypted in order for the condition or exception to apply. */
		isEncrypted?: boolean

	    /** Indicates whether an incoming message must be a meeting request in order for the condition or exception to apply. */
		isMeetingRequest?: boolean

	    /** Indicates whether an incoming message must be a meeting response in order for the condition or exception to apply. */
		isMeetingResponse?: boolean

	    /** Indicates whether an incoming message must be a non-delivery report in order for the condition or exception to apply. */
		isNonDeliveryReport?: boolean

	    /** Indicates whether an incoming message must be permission controlled (RMS-protected) in order for the condition or exception to apply. */
		isPermissionControlled?: boolean

	    /** Indicates whether an incoming message must be a read receipt in order for the condition or exception to apply. */
		isReadReceipt?: boolean

	    /** Indicates whether an incoming message must be S/MIME-signed in order for the condition or exception to apply. */
		isSigned?: boolean

	    /** Indicates whether an incoming message must be a voice mail in order for the condition or exception to apply. */
		isVoicemail?: boolean

	    /** Represents the minimum and maximum sizes (in kilobytes) that an incoming message must fall in between in order for the condition or exception to apply. */
		withinSizeRange?: SizeRange

}
export interface SizeRange {

	    /** The minimum size (in kilobytes) that an incoming message must have in order for a condition or exception to apply. */
		minimumSize?: number

	    /** The maximum size (in kilobytes) that an incoming message must have in order for a condition or exception to apply. */
		maximumSize?: number

}
export interface MessageRuleActions {

	    /** The ID of the folder that a message will be moved to. */
		moveToFolder?: string

	    /** The ID of a folder that a message is to be copied to. */
		copyToFolder?: string

	    /** Indicates whether a message should be moved to the Deleted Items folder. */
		delete?: boolean

	    /** Indicates whether a message should be permanently deleted and not saved to the Deleted Items folder. */
		permanentDelete?: boolean

	    /** Indicates whether a message should be marked as read. */
		markAsRead?: boolean

	    /** Sets the importance of the message, which can be: low, normal, high. */
		markImportance?: Importance

	    /** The email addresses of the recipients to which a message should be forwarded. */
		forwardTo?: Recipient[]

	    /** The email addresses of the recipients to which a message should be forwarded as an attachment. */
		forwardAsAttachmentTo?: Recipient[]

	    /** The email address to which a message should be redirected. */
		redirectTo?: Recipient[]

	    /** A list of categories to be assigned to a message. */
		assignCategories?: string[]

	    /** Indicates whether subsequent rules should be evaluated. */
		stopProcessingRules?: boolean

}
export interface RankedEmailAddress {

	    /** The email address. */
		address?: string

	    /** The rank of the email address. A rank is used as a sort key, in relation to the other returned results. A higher rank value corresponds to a more relevant result. Relevance is determined by communication, collaboration, and business relationship signals. */
		rank?: number

}
export interface PersonDataSource {

	    /** The type of data source. */
		type?: string

}
export interface BooleanColumn {

}
export interface CalculatedColumn {

	    /** For dateTime output types, the format of the value. Must be one of dateOnly or dateTime. */
		format?: string

	    /** The formula used to compute the value for this column. */
		formula?: string

	    /** The output type used to format values in this column. Must be one of boolean, currency, dateTime, number, or text. */
		outputType?: string

}
export interface ChoiceColumn {

	    /** If true, allows custom values that aren't in the configured choices. */
		allowTextEntry?: boolean

	    /** The list of values available for this column. */
		choices?: string[]

	    /** How the choices are to be presented in the UX. Must be one of checkBoxes, dropDownMenu, or radioButtons */
		displayAs?: string

}
export interface CurrencyColumn {

	    /** Specifies the locale from which to infer the currency symbol. */
		locale?: string

}
export interface DateTimeColumn {

	    /** How the value should be presented in the UX. Must be one of default, friendly, or standard. See below for more details. If unspecified, treated as default. */
		displayAs?: string

	    /** Indicates whether the value should be presented as a date only or a date and time. Must be one of dateOnly or dateTime */
		format?: string

}
export interface DefaultColumnValue {

	    /** The formula used to compute the default value for this column. */
		formula?: string

	    /** The direct value to use as the default value for this column. */
		value?: string

}
export interface LookupColumn {

	    /** Indicates whether multiple values can be selected from the source. */
		allowMultipleValues?: boolean

	    /** Indicates whether values in the column should be able to exceed the standard limit of 255 characters. */
		allowUnlimitedLength?: boolean

	    /** The name of the lookup source column. */
		columnName?: string

	    /** The unique identifier of the lookup source list. */
		listId?: string

	    /** If specified, this column is a secondary lookup, pulling an additional field from the list item looked up by the primary lookup. Use the list item looked up by the primary as the source for the column named here. */
		primaryLookupColumnId?: string

}
export interface NumberColumn {

	    /** How many decimal places to display. See below for information about the possible values. */
		decimalPlaces?: string

	    /** How the value should be presented in the UX. Must be one of number or percentage. If unspecified, treated as number. */
		displayAs?: string

	    /** The maximum permitted value. */
		maximum?: number

	    /** The minimum permitted value. */
		minimum?: number

}
export interface PersonOrGroupColumn {

	    /** Indicates whether multiple values can be selected from the source. */
		allowMultipleSelection?: boolean

	    /** Whether to allow selection of people only, or people and groups. Must be one of peopleAndGroups or peopleOnly. */
		chooseFromType?: string

	    /** How to display the information about the person or group chosen. See below. */
		displayAs?: string

}
export interface TextColumn {

	    /** Whether to allow multiple lines of text. */
		allowMultipleLines?: boolean

	    /** Whether updates to this column should replace existing text, or append to it. */
		appendChangesToExistingText?: boolean

	    /** The size of the text box. */
		linesForEditing?: number

	    /** The maximum number of characters for the value. */
		maxLength?: number

	    /** The type of text being stored. Must be one of plain or richText */
		textType?: string

}
export interface ContentTypeOrder {

	    /** Whether this is the default Content Type */
		default?: boolean

	    /** Specifies the position in which the Content Type appears in the selection UI. */
		position?: number

}
export interface ItemActionSet {

	    /** A comment was added to the item. */
		comment?: CommentAction

	    /** An item was created. */
		create?: CreateAction

	    /** An item was deleted. */
		delete?: DeleteAction

	    /** An item was edited. */
		edit?: EditAction

	    /** A user was mentioned in the item. */
		mention?: MentionAction

	    /** An item was moved. */
		move?: MoveAction

	    /** An item was renamed. */
		rename?: RenameAction

	    /** An item was restored. */
		restore?: RestoreAction

	    /** An item was shared. */
		share?: ShareAction

	    /** An item was versioned. */
		version?: VersionAction

}
export interface CommentAction {

	    /** If true, this activity was a reply to an existing comment thread. */
		isReply?: boolean

	    /** The identity of the user who started the comment thread. */
		parentAuthor?: IdentitySet

	    /** The identities of the users participating in this comment thread. */
		participants?: IdentitySet[]

}
export interface CreateAction {

}
export interface DeleteAction {

	    /** The name of the item that was deleted. */
		name?: string

	    /** File or Folder, depending on the type of the deleted item. */
		objectType?: string

}
export interface EditAction {

}
export interface MentionAction {

	    /** The identities of the users mentioned in this action. */
		mentionees?: IdentitySet[]

}
export interface MoveAction {

	    /** The name of the location the item was moved from. */
		from?: string

	    /** The name of the location the item was moved to. */
		to?: string

}
export interface RenameAction {

	    /** The new name of the item. */
		newName?: string

	    /** The previous name of the item. */
		oldName?: string

}
export interface RestoreAction {

}
export interface ShareAction {

	    /** The identities the item was shared with in this action. */
		recipients?: IdentitySet[]

}
export interface VersionAction {

	    /** The name of the new version that was created by this action. */
		newVersion?: string

}
export interface ItemActivityTimeSet {

		lastRecordedDateTime?: string

	    /** When the activity was observed to take place. */
		observedDateTime?: string

	    /** When the observation was recorded on the service. */
		recordedDateTime?: string

}
export interface ContentTypeInfo {

	    /** The id of the content type. */
		id?: string

	    /** The name of the content type. */
		name?: string

}
export interface SharingInvitation {

	    /** The email address provided for the recipient of the sharing invitation. Read-only. */
		email?: string

	    /** Provides information about who sent the invitation that created this permission, if that information is available. Read-only. */
		invitedBy?: IdentitySet

		redeemedBy?: string

	    /** If true the recipient of the invitation needs to sign in in order to access the shared item. Read-only. */
		signInRequired?: boolean

}
export interface SharingLink {

	    /** The app the link is associated with. */
		application?: Identity

		configuratorUrl?: string

	    /** The scope of the link represented by this permission. Value anonymous indicates the link is usable by anyone, organization indicates the link is only usable for users signed into the same tenant. */
		scope?: string

	    /** The type of the link created. */
		type?: string

	    /** For embed links, this property contains the HTML code for an <iframe> element that will embed the item in a webpage. */
		webHtml?: string

	    /** A URL that opens the item in the browser on the OneDrive website. */
		webUrl?: string

}
export interface Thumbnail {

		content?: any

	    /** The height of the thumbnail, in pixels. */
		height?: number

	    /** The unique identifier of the item that provided the thumbnail. This is only available when a folder thumbnail is requested. */
		sourceItemId?: string

	    /** The URL used to fetch the thumbnail content. */
		url?: string

	    /** The width of the thumbnail, in pixels. */
		width?: number

}
export interface DriveItemUploadableProperties {

		description?: string

		fileSystemInfo?: FileSystemInfo

		name?: string

}
export interface DriveRecipient {

	    /** The alias of the domain object, for cases where an email address is unavailable (e.g. security groups). */
		alias?: string

	    /** The email address for the recipient, if the recipient has an associated email address. */
		email?: string

	    /** The unique identifier for the recipient in the directory. */
		objectId?: string

}
export interface FlexSchemaContainer {

}
export interface ItemPreviewInfo {

		getUrl?: string

		postParameters?: string

		postUrl?: string

}
export interface UploadSession {

	    /** The date and time in UTC that the upload session will expire. The complete file must be uploaded before this expiration time is reached. */
		expirationDateTime?: string

	    /** A collection of byte ranges that the server is missing for the file. These ranges are zero indexed and of the format "start-end" (e.g. "0-26" to indicate the first 27 bytes of the file). */
		nextExpectedRanges?: string[]

	    /** The URL endpoint that accepts PUT requests for byte ranges of the file. */
		uploadUrl?: string

}
export interface ResourceVisualization {

		title?: string

		type?: string

		mediaType?: string

		previewImageUrl?: string

		previewText?: string

		containerWebUrl?: string

		containerDisplayName?: string

		containerType?: string

}
export interface ResourceReference {

		webUrl?: string

		id?: string

		type?: string

}
export interface SharingDetail {

		sharedBy?: InsightIdentity

		sharedDateTime?: string

		sharingSubject?: string

		sharingType?: string

		sharingReference?: ResourceReference

}
export interface InsightIdentity {

		displayName?: string

		id?: string

		address?: string

}
export interface UsageDetails {

		lastAccessedDateTime?: string

		lastModifiedDateTime?: string

}
export interface PlannerFavoritePlanReferenceCollection {

}
export interface PlannerRecentPlanReferenceCollection {

}
export interface PlannerAppliedCategories {

}
export interface PlannerAssignments {

}
export interface PlannerPlanContextCollection {

}
export interface PlannerExternalReference {

	    /** A name alias to describe the reference. */
		alias?: string

	    /** Used to describe the type of the reference. Types include: PowerPoint, Word, Excel, Other. */
		type?: string

	    /** Used to set the relative priority order in which the reference will be shown as a preview on the task. */
		previewPriority?: string

	    /** Read-only. User ID by which this is last modified. */
		lastModifiedBy?: IdentitySet

	    /** Read-only. Date and time at which this is last modified. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		lastModifiedDateTime?: string

}
export interface PlannerChecklistItem {

	    /** Value is true if the item is checked and false otherwise. */
		isChecked?: boolean

	    /** Title of the checklist item */
		title?: string

	    /** Used to set the relative order of items in the checklist. The format is defined as outlined here. */
		orderHint?: string

	    /** Read-only. User ID by which this is last modified. */
		lastModifiedBy?: IdentitySet

	    /** Read-only. Date and time at which this is last modified. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		lastModifiedDateTime?: string

}
export interface PlannerAssignment {

	    /** The identity of the user that performed the assignment of the task, i.e. the assignor. */
		assignedBy?: IdentitySet

	    /** The time at which the task was assigned. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		assignedDateTime?: string

	    /** Hint used to order assignees in a task. The format is defined as outlined here. */
		orderHint?: string

}
export interface PlannerFavoritePlanReference {

	    /** Hint used to order items of this type in a list view. The format is defined in Using order hints in Planner. */
		orderHint?: string

	    /** Title of the plan at the time the user marked it as a favorite. */
		planTitle?: string

}
export interface PlannerRecentPlanReference {

	    /** The date and time the plan was last viewed by the user. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. */
		lastAccessedDateTime?: string

	    /** The title of the plan at the time the user viewed it. */
		planTitle?: string

}
export interface PlannerPlanContext {

	    /** Nullable. An app-defined type of association between the plannerPlan and the app. The app can use this information to track different kinds of relationships to the same plannerPlan. */
		associationType?: string

	    /** Read-only. The date and time when the plannerPlanContext was created. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. */
		createdDateTime?: string

	    /** The segments of the name of the external experience. Segments represent a hierarchical structure that allows other apps to display the relationship. */
		displayNameSegments?: string[]

	    /** Read-only. ID of the app that created the plannerPlanContext. */
		ownerAppId?: string

}
export interface PlannerPlanContextDetails {

	    /** URL of the user experience represented by the associated plannerPlanContext. */
		url?: string

}
export interface PlannerExternalReferences {

}
export interface PlannerChecklistItems {

}
export interface PlannerOrderHintsByAssignee {

}
export interface PlannerUserIds {

}
export interface PlannerCategoryDescriptions {

	    /** The label associated with Category 1 */
		category1?: string

	    /** The label associated with Category 2 */
		category2?: string

	    /** The label associated with Category 3 */
		category3?: string

	    /** The label associated with Category 4 */
		category4?: string

	    /** The label associated with Category 5 */
		category5?: string

	    /** The label associated with Category 6 */
		category6?: string

}
export interface PlannerPlanContextDetailsCollection {

}
export interface NotebookLinks {

	    /** Opens the notebook in the OneNote native client if it's installed. */
		oneNoteClientUrl?: ExternalLink

	    /** Opens the notebook in OneNote Online. */
		oneNoteWebUrl?: ExternalLink

}
export interface ExternalLink {

	    /** The url of the link. */
		href?: string

}
export interface SectionLinks {

	    /** Opens the section in the OneNote native client if it's installed. */
		oneNoteClientUrl?: ExternalLink

	    /** Opens the section in OneNote Online. */
		oneNoteWebUrl?: ExternalLink

}
export interface PageLinks {

	    /** Opens the page in the OneNote native client if it's installed. */
		oneNoteClientUrl?: ExternalLink

	    /** Opens the page in OneNote Online. */
		oneNoteWebUrl?: ExternalLink

}
export interface OnenoteOperationError {

	    /** The error code. */
		code?: string

	    /** The error message. */
		message?: string

}
export interface Diagnostic {

	    /** The message describing the condition that triggered the error or warning. */
		message?: string

	    /** The link to the documentation for this issue. */
		url?: string

}
export interface OnenotePatchContentCommand {

	    /** The action to perform on the target element. Possible values are: replace, append, delete, insert, or prepend. */
		action?: OnenotePatchActionType

	    /** The element to update. Must be the #<data-id> or the generated <id> of the element, or the body or title keyword. */
		target?: string

	    /** A string of well-formed HTML to add to the page, and any image or file binary data. If the content contains binary data, the request must be sent using the multipart/form-data content type with a "Commands" part. */
		content?: string

	    /** The location to add the supplied content, relative to the target element. Possible values are: after (default) or before. */
		position?: OnenotePatchInsertPosition

}
export interface OnenotePagePreview {

		previewText?: string

		links?: OnenotePagePreviewLinks

}
export interface OnenotePagePreviewLinks {

		previewImageUrl?: ExternalLink

}
export interface RecentNotebook {

		displayName?: string

	    /** The date and time when the notebook was last modified. The timestamp represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. Read-only. */
		lastAccessedTime?: string

	    /** Links for opening the notebook. The oneNoteClientURL link opens the notebook in the OneNote client, if it's installed. The oneNoteWebURL link opens the notebook in OneNote Online. */
		links?: RecentNotebookLinks

	    /** The backend store where the Notebook resides, either OneDriveForBusiness or OneDrive. */
		sourceService?: OnenoteSourceService

}
export interface RecentNotebookLinks {

	    /** Opens the notebook in the OneNote client, if it's installed. */
		oneNoteClientUrl?: ExternalLink

	    /** Opens the notebook in OneNote Online. */
		oneNoteWebUrl?: ExternalLink

}
export interface AuditActivityInitiator {

	    /** If the resource initiating the activity is a user, this property Indicates all the user related information like userId, Name, UserPrinicpalName. */
		user?: UserIdentity

	    /** If the resource initiating the activity is an app, this property indicates all the app related information like appId, Name, servicePrincipalId, Name. */
		app?: AppIdentity

}
export interface UserIdentity {

	    /** Indicates the User Id of the user */
		id?: string

	    /** indicates the Display Name of the User */
		displayName?: string

	    /** Indicates the client IP address used by user performing the activity */
		ipAddress?: string

	    /** Indicates the UPN of the user */
		userPrincipalName?: string

}
export interface AppIdentity {

	    /** Refers to the Unique GUID representing Application Id in the Azure Active Directory. */
		appId?: string

	    /** Refers to the Application Name displayed in the Azure Portal. */
		displayName?: string

	    /** Refers to the Unique GUID indicating Service Principal Id in Azure Active Directory for the corresponding App. */
		servicePrincipalId?: string

	    /** Refers to the Service Principal Name is the Application name in the tenant. */
		servicePrincipalName?: string

}
export interface TargetResource {

	    /** Indicates the display name of the resources outlined under Target Resource Types below. */
		displayName?: string

	    /** Indicates the Unique Id of the resource (For example: UserId, AppId, RoleId.). */
		id?: string

	    /** Indicates name, old value and new value of each attribute that changed. This is applicable for any "Update" activities */
		modifiedProperties?: ModifiedProperty[]

}
export interface ModifiedProperty {

	    /** Indicates the property name of the target attribute that was changed. */
		displayName?: string

	    /** Indicates the previous value (before the update) for the property. */
		oldValue?: string

	    /** Indicates the updated value for the propery. */
		newValue?: string

}
export interface TargetResourceUser extends TargetResource {

	    /** Indicates the Unique Id of the User. Refers to User Id for a specific user. */
		userPrincipalName?: string

}
export interface TargetResourceApp extends TargetResource {

}
export interface TargetResourcePolicy extends TargetResource {

	    /** Indicates the Policy Name that changed or was targetted for change */
		policyType?: string

}
export interface TargetResourceDevice extends TargetResource {

}
export interface TargetResourceDirectory extends TargetResource {

}
export interface TargetResourceGroup extends TargetResource {

	    /** Possible values are: unifiedGroups, azureAD, unknownFutureValue. */
		groupType?: GroupType

}
export interface TargetResourceRole extends TargetResource {

}
export interface TargetResourceOther extends TargetResource {

}
export interface TargetResourceServicePrincipal extends TargetResource {

	    /** Indicates the Unique Id of the application. Refers to App Id for a specfic app. */
		appId?: string

}
export interface SignInStatus {

	    /** Provides the 5-6digit error code that's generated during a sign-in failure. Check out the list of error codes and messages. */
		errorCode?: number

	    /** Provides the error message or the reason for failure for the corresponding sign-in activity. Check out the list of error codes and messages. */
		failureReason?: string

	    /** Provides additional details on the sign-in activity */
		additionalDetails?: string

}
export interface DeviceDetail {

	    /** Refers to the UniqueID of the device used for signing-in. */
		deviceId?: string

	    /** Refers to the name of the device used for signing-in. */
		displayName?: string

	    /** Indicates the OS name and version used for signing-in. */
		operatingSystem?: string

	    /** Indicates the browser information of the used for signing-in. */
		browser?: string

	    /** Indicates whether the device is compliant or not. */
		isCompliant?: boolean

	    /** Indicates if the device is managed or not. */
		isManaged?: boolean

	    /** Indicates information on whether the signed-in device is Workplace Joined, AzureAD Joined, Domain Joined. */
		trustType?: string

}
export interface SignInLocation {

	    /** Provides the city where the sign-in originated. This is calculated using latitude/longitude information from the sign-in activity. */
		city?: string

	    /** Provides the State where the sign-in originated. This is calculated using latitude/longitude information from the sign-in activity. */
		state?: string

	    /** Provides the country code info (2 letter code) where the sign-in originated.  This is calculated using latitude/longitude information from the sign-in activity. */
		countryOrRegion?: string

	    /** Provides the latitude, longitude and altitude where the sign-in originated. */
		geoCoordinates?: GeoCoordinates

}
export interface MfaDetail {

	    /** Indicates the MFA Auth methods (SMS, Phone, Authenticator App are some of the value) for the corresponding sign-in activity when the MFA Required field is "Yes". */
		authMethod?: string

	    /** Indicates the MFA auth detail for the corresponding Sign-in activity when the MFA Required is "Yes". */
		authDetail?: string

}
export interface ConditionalAccessPolicy {

	    /** Unique GUID of the conditional access policy */
		id?: string

	    /** Refers to the Name of the conditional access policy (example: “Require MFA for Salesforce”). */
		displayName?: string

	    /** Refers to the grant controls enforced by the conditional access policy (example: “Require multi-factor authentication”). */
		enforcedGrantControls?: string[]

	    /** Refers to the session controls enforced by the conditional access policy (example: “Require app enforced controls”). */
		enforcedSessionControls?: string[]

	    /** Indicates the result of the CA policy that was triggered.Possible values are: success  failure  notApplied - Policy isn't applied because policy conditions were not met.  notEnabled - This is due to the policy in disabled state. */
		result?: ConditionalAccessPolicyResult

}
export interface RoleSuccessStatistics {

		roleId?: string

		roleName?: string

		temporarySuccess?: number

		temporaryFail?: number

		permanentSuccess?: number

		permanentFail?: number

		removeSuccess?: number

		removeFail?: number

		unknownFail?: number

}
export interface InvitedUserMessageInfo {

	    /** Additional recipients the invitation message should be sent to. Currently only 1 additional recipient is supported. */
		ccRecipients?: Recipient[]

	    /** The language you want to send the default message in. If the customizedMessageBody is specified, this property is ignored, and the message is sent using the customizedMessageBody. The language format should be in ISO 639. The default is en-US. */
		messageLanguage?: string

	    /** Customized message body you want to send if you don't want the default message. */
		customizedMessageBody?: string

}
export interface ManagedDeviceCleanupSettings {

	    /** Number of days when the device has not contacted Intune. */
		deviceInactivityBeforeRetirementInDays?: string

}
export interface AdminConsent {

	    /** The admin consent state of sharing user and device data to Apple. Possible values are: notConfigured, granted, notGranted. */
		shareAPNSData?: AdminConsentState

}
export interface DeviceProtectionOverview {

	    /** Total device count. */
		totalReportedDeviceCount?: number

	    /** Device with inactive threat agent count */
		inactiveThreatAgentDeviceCount?: number

	    /** Device with threat agent state as unknown count. */
		unknownStateThreatAgentDeviceCount?: number

	    /** Device with old signature count. */
		pendingSignatureUpdateDeviceCount?: number

	    /** Clean device count. */
		cleanDeviceCount?: number

	    /** Pending full scan device count. */
		pendingFullScanDeviceCount?: number

	    /** Pending restart device count. */
		pendingRestartDeviceCount?: number

	    /** Pending manual steps device count. */
		pendingManualStepsDeviceCount?: number

	    /** Pending offline scan device count. */
		pendingOfflineScanDeviceCount?: number

	    /** Critical failures device count. */
		criticalFailuresDeviceCount?: number

}
export interface WindowsMalwareOverview {

		malwareDetectedDeviceCount?: number

		malwareStateSummary?: WindowsMalwareStateCount[]

		malwareExecutionStateSummary?: WindowsMalwareExecutionStateCount[]

		malwareCategorySummary?: WindowsMalwareCategoryCount[]

		malwareNameSummary?: WindowsMalwareNameCount[]

		osVersionsSummary?: OsVersionCount[]

}
export interface WindowsMalwareStateCount {

		state?: WindowsMalwareThreatState

		deviceCount?: number

}
export interface WindowsMalwareExecutionStateCount {

		executionState?: WindowsMalwareExecutionState

		deviceCount?: number

}
export interface WindowsMalwareCategoryCount {

		category?: WindowsMalwareCategory

		deviceCount?: number

}
export interface WindowsMalwareNameCount {

		malwareIdentifier?: string

		name?: string

		deviceCount?: number

}
export interface OsVersionCount {

		osVersion?: string

		deviceCount?: number

}
export interface DeviceManagementSettings {

	    /** The number of days a device is allowed to go without checking in to remain compliant. Valid values 0 to 120 */
		deviceComplianceCheckinThresholdDays?: number

	    /** Is feature enabled or not for scheduled action for rule. */
		isScheduledActionEnabled?: boolean

	    /** Device should be noncompliant when there is no compliance policy targeted when this is true */
		secureByDefault?: boolean

	    /** Is feature enabled or not for enhanced jailbreak detection. */
		enhancedJailBreak?: boolean

	    /** When the device does not check in for specified number of days, the company data might be removed and the device will not be under management. Valid values 30 to 270 */
		deviceInactivityBeforeRetirementInDay?: number

}
export interface IntuneBrand {

	    /** Company/organization name that is displayed to end users. */
		displayName?: string

	    /** Name of the person/organization responsible for IT support. */
		contactITName?: string

	    /** Phone number of the person/organization responsible for IT support. */
		contactITPhoneNumber?: string

	    /** Email address of the person/organization responsible for IT support. */
		contactITEmailAddress?: string

	    /** Text comments regarding the person/organization responsible for IT support. */
		contactITNotes?: string

	    /** URL to the company/organization’s privacy policy. */
		privacyUrl?: string

	    /** URL to the company/organization’s IT helpdesk site. */
		onlineSupportSiteUrl?: string

	    /** Display name of the company/organization’s IT helpdesk site. */
		onlineSupportSiteName?: string

	    /** Primary theme color used in the Company Portal applications and web portal. */
		themeColor?: RgbColor

	    /** Boolean that represents whether the administrator-supplied logo images are shown or not shown. */
		showLogo?: boolean

	    /** Logo image displayed in Company Portal apps which have a light background behind the logo. */
		lightBackgroundLogo?: MimeContent

	    /** Logo image displayed in Company Portal apps which have a dark background behind the logo. */
		darkBackgroundLogo?: MimeContent

	    /** Boolean that represents whether the administrator-supplied display name will be shown next to the logo image. */
		showNameNextToLogo?: boolean

	    /** Customized image displayed in Compnay Portal app landing page */
		landingPageCustomizedImage?: MimeContent

	    /** Boolean that represents whether the administrator-supplied display name will be shown next to the logo image. */
		showDisplayNameNextToLogo?: boolean

}
export interface RgbColor {

	    /** Red value */
		r?: number

	    /** Green value */
		g?: number

	    /** Blue value */
		b?: number

}
export interface MimeContent {

	    /** Indicates the content mime type. */
		type?: string

	    /** The byte array that contains the actual content. */
		value?: number

}
export interface AndroidForWorkAppConfigurationSchemaItem {

	    /** Unique key the application uses to identify the item */
		schemaItemKey?: string

	    /** Human readable name */
		displayName?: string

	    /** Description of what the item controls within the application */
		description?: string

	    /** Default value for boolean type items, if specified by the app developer */
		defaultBoolValue?: boolean

	    /** Default value for integer type items, if specified by the app developer */
		defaultIntValue?: number

	    /** Default value for string type items, if specified by the app developer */
		defaultStringValue?: string

	    /** Default value for string array type items, if specified by the app developer */
		defaultStringArrayValue?: string[]

	    /** The type of value this item describes. Possible values are: bool, integer, string, choice, multiselect, bundle, bundleArray, hidden. */
		dataType?: AndroidForWorkAppConfigurationSchemaItemDataType

	    /** List of human readable name/value pairs for the valid values that can be set for this item (Choice and Multiselect items only) */
		selections?: KeyValuePair[]

}
export interface KeyValuePair {

	    /** Name for this key-value pair */
		name?: string

	    /** Value for this key-value pair */
		value?: string

}
export interface AndroidManagedStoreAppConfigurationSchemaItem {

	    /** Unique key the application uses to identify the item */
		schemaItemKey?: string

	    /** Human readable name */
		displayName?: string

	    /** Description of what the item controls within the application */
		description?: string

	    /** Default value for boolean type items, if specified by the app developer */
		defaultBoolValue?: boolean

	    /** Default value for integer type items, if specified by the app developer */
		defaultIntValue?: number

	    /** Default value for string type items, if specified by the app developer */
		defaultStringValue?: string

	    /** Default value for string array type items, if specified by the app developer */
		defaultStringArrayValue?: string[]

	    /** The type of value this item describes. Possible values are: bool, integer, string, choice, multiselect, bundle, bundleArray, hidden. */
		dataType?: AndroidManagedStoreAppConfigurationSchemaItemDataType

	    /** List of human readable name/value pairs for the valid values that can be set for this item (Choice and Multiselect items only) */
		selections?: KeyValuePair[]

}
export interface DeviceAndAppManagementAssignmentTarget {

}
export interface MobileAppAssignmentSettings {

}
export interface FileEncryptionInfo {

	    /** The key used to encrypt the file content. */
		encryptionKey?: number

	    /** The initialization vector used for the encryption algorithm. */
		initializationVector?: number

	    /** The hash of the encrypted file content + IV (content hash). */
		mac?: number

	    /** The key used to get mac. */
		macKey?: number

	    /** The the profile identifier. */
		profileIdentifier?: string

	    /** The file digest prior to encryption. */
		fileDigest?: number

	    /** The file digest algorithm. */
		fileDigestAlgorithm?: string

}
export interface VppLicensingType {

	    /** Whether the program supports the user licensing type. */
		supportUserLicensing?: boolean

	    /** Whether the program supports the device licensing type. */
		supportDeviceLicensing?: boolean

	    /** Whether the program supports the user licensing type. */
		supportsUserLicensing?: boolean

	    /** Whether the program supports the device licensing type. */
		supportsDeviceLicensing?: boolean

}
export interface IosDeviceType {

	    /** Whether the app should run on iPads. */
		iPad?: boolean

	    /** Whether the app should run on iPhones and iPods. */
		iPhoneAndIPod?: boolean

}
export interface IosVppAppRevokeLicensesActionResult {

		userId?: string

		managedDeviceId?: string

		totalLicensesCount?: number

		failedLicensesCount?: number

		actionFailureReason?: VppTokenActionFailureReason

		actionName?: string

		actionState?: ActionState

		startDateTime?: string

		lastUpdatedDateTime?: string

}
export interface AllLicensedUsersAssignmentTarget extends DeviceAndAppManagementAssignmentTarget {

}
export interface GroupAssignmentTarget extends DeviceAndAppManagementAssignmentTarget {

	    /** The group Id that is the target of the assignment. */
		groupId?: string

}
export interface ExclusionGroupAssignmentTarget extends GroupAssignmentTarget {

}
export interface AllDevicesAssignmentTarget extends DeviceAndAppManagementAssignmentTarget {

}
export interface IosLobAppAssignmentSettings extends MobileAppAssignmentSettings {

	    /** The VPN Configuration Id to apply for this app. */
		vpnConfigurationId?: string

}
export interface IosStoreAppAssignmentSettings extends MobileAppAssignmentSettings {

	    /** The VPN Configuration Id to apply for this app. */
		vpnConfigurationId?: string

}
export interface IosVppAppAssignmentSettings extends MobileAppAssignmentSettings {

	    /** Whether or not to use device licensing. */
		useDeviceLicensing?: boolean

	    /** The VPN Configuration Id to apply for this app. */
		vpnConfigurationId?: string

}
export interface WindowsUniversalAppXAppAssignmentSettings extends MobileAppAssignmentSettings {

	    /** Whether or not to use device execution context for Windows Universal AppX mobile app. */
		useDeviceContext?: boolean

}
export interface WindowsAppXAppAssignmentSettings extends MobileAppAssignmentSettings {

	    /** Whether or not to use device execution context for Windows AppX mobile app. */
		useDeviceContext?: boolean

}
export interface MicrosoftStoreForBusinessAppAssignmentSettings extends MobileAppAssignmentSettings {

	    /** Whether or not to use device execution context for Microsoft Store for Business mobile app. */
		useDeviceContext?: boolean

}
export interface ExcludedApps {

	    /** The value for if MS Office Access should be excluded or not. */
		access?: boolean

	    /** The value for if MS Office Excel should be excluded or not. */
		excel?: boolean

	    /** The value for if MS Office OneDrive for Business - Groove should be excluded or not. */
		groove?: boolean

	    /** The value for if MS Office InfoPath should be excluded or not. */
		infoPath?: boolean

	    /** The value for if MS Office Skype for Business - Lync should be excluded or not. */
		lync?: boolean

	    /** The value for if MS Office OneDrive should be excluded or not. */
		oneDrive?: boolean

	    /** The value for if MS Office OneNote should be excluded or not. */
		oneNote?: boolean

	    /** The value for if MS Office Outlook should be excluded or not. */
		outlook?: boolean

	    /** The value for if MS Office PowerPoint should be excluded or not. */
		powerPoint?: boolean

	    /** The value for if MS Office Publisher should be excluded or not. */
		publisher?: boolean

	    /** The value for if MS Office SharePointDesigner should be excluded or not. */
		sharePointDesigner?: boolean

	    /** The value for if MS Office Visio should be excluded or not. */
		visio?: boolean

	    /** The value for if MS Office Word should be excluded or not. */
		word?: boolean

}
export interface AndroidMinimumOperatingSystem {

	    /** Version 4.0 or later. */
		v4_0?: boolean

	    /** Version 4.0.3 or later. */
		v4_0_3?: boolean

	    /** Version 4.1 or later. */
		v4_1?: boolean

	    /** Version 4.2 or later. */
		v4_2?: boolean

	    /** Version 4.3 or later. */
		v4_3?: boolean

	    /** Version 4.4 or later. */
		v4_4?: boolean

	    /** Version 5.0 or later. */
		v5_0?: boolean

	    /** Version 5.1 or later. */
		v5_1?: boolean

}
export interface IosMinimumOperatingSystem {

	    /** Version 8.0 or later. */
		v8_0?: boolean

	    /** Version 9.0 or later. */
		v9_0?: boolean

	    /** Version 10.0 or later. */
		v10_0?: boolean

	    /** Version 11.0 or later. */
		v11_0?: boolean

}
export interface WindowsMinimumOperatingSystem {

	    /** Windows version 8.0 or later. */
		v8_0?: boolean

	    /** Windows version 8.1 or later. */
		v8_1?: boolean

	    /** Windows version 10.0 or later. */
		v10_0?: boolean

}
export interface MacOSMinimumOperatingSystem {

	    /** Mac OS 10.7 or later. */
		v10_7?: boolean

	    /** Mac OS 10.8 or later. */
		v10_8?: boolean

	    /** Mac OS 10.9 or later. */
		v10_9?: boolean

	    /** Mac OS 10.10 or later. */
		v10_10?: boolean

	    /** Mac OS 10.11 or later. */
		v10_11?: boolean

	    /** Mac OS 10.12 or later. */
		v10_12?: boolean

	    /** Mac OS 10.13 or later. */
		v10_13?: boolean

}
export interface MacOSLobChildApp {

	    /** The Identity Name. */
		bundleId?: string

	    /** The build number of MacOS Line of Business (LoB) app. */
		buildNumber?: string

	    /** The version number of MacOS Line of Business (LoB) app. */
		versionNumber?: string

}
export interface WindowsPackageInformation {

	    /** The Windows architecture for which this app can run on. Possible values are: none, x86, x64, arm, neutral. */
		applicableArchitecture?: WindowsArchitecture

	    /** The Display Name. */
		displayName?: string

	    /** The Identity Name. */
		identityName?: string

	    /** The Identity Publisher. */
		identityPublisher?: string

	    /** The Identity Resource Identifier. */
		identityResourceIdentifier?: string

	    /** The Identity Version. */
		identityVersion?: string

	    /** The value for the minimum applicable operating system. */
		minimumSupportedOperatingSystem?: WindowsMinimumOperatingSystem

}
export interface AndroidPermissionAction {

	    /** Android permission string, defined in the official Android documentation.  Example 'android.permission.READ_CONTACTS'. */
		permission?: string

	    /** Type of Android permission action. Possible values are: prompt, autoGrant, autoDeny. */
		action?: AndroidPermissionActionType

}
export interface AppConfigurationSettingItem {

	    /** app configuration key. */
		appConfigKey?: string

	    /** app configuration key type. Possible values are: stringType, integerType, realType, booleanType, tokenType. */
		appConfigKeyType?: MdmAppConfigKeyType

	    /** app configuration key value. */
		appConfigKeyValue?: string

}
export interface RunSchedule {

}
export interface HardwareInformation {

	    /** Serial number. */
		serialNumber?: string

	    /** Total storage space of the device. */
		totalStorageSpace?: number

	    /** Free storage space of the device. */
		freeStorageSpace?: number

	    /** IMEI */
		imei?: string

	    /** MEID */
		meid?: string

	    /** Manufacturer of the device */
		manufacturer?: string

	    /** Model of the device */
		model?: string

	    /** Phone number of the device */
		phoneNumber?: string

	    /** Subscriber carrier of the device */
		subscriberCarrier?: string

	    /** Cellular technology of the device */
		cellularTechnology?: string

	    /** WiFi MAC address of the device */
		wifiMac?: string

	    /** Operating system language of the device */
		operatingSystemLanguage?: string

	    /** Supervised mode of the device */
		isSupervised?: boolean

	    /** Encryption status of the device */
		isEncrypted?: boolean

	    /** Shared iPad */
		isSharedDevice?: boolean

	    /** All users on the shared Apple device */
		sharedDeviceCachedUsers?: SharedAppleDeviceUser[]

	    /** String that specifies the specification version. */
		tpmSpecificationVersion?: string

	    /** String that specifies the OS edition. */
		operatingSystemEdition?: string

	    /** Returns the fully qualified domain name of the device (if any). If the device is not domain-joined, it returns an empty string. */
		deviceFullQualifiedDomainName?: string

	    /** Virtualization-based security hardware requirement status. Possible values are: meetHardwareRequirements, secureBootRequired, dmaProtectionRequired, hyperVNotSupportedForGuestVM, hyperVNotAvailable. */
		deviceGuardVirtualizationBasedSecurityHardwareRequirementState?: DeviceGuardVirtualizationBasedSecurityHardwareRequirementState

	    /** Virtualization-based security status. . Possible values are: running, rebootRequired, require64BitArchitecture, notLicensed, notConfigured, doesNotMeetHardwareRequirements, other. */
		deviceGuardVirtualizationBasedSecurityState?: DeviceGuardVirtualizationBasedSecurityState

	    /** Local System Authority (LSA) credential guard status. . Possible values are: running, rebootRequired, notLicensed, notConfigured, virtualizationBasedSecurityNotRunning. */
		deviceGuardLocalSystemAuthorityCredentialGuardState?: DeviceGuardLocalSystemAuthorityCredentialGuardState

}
export interface SharedAppleDeviceUser {

	    /** User name */
		userPrincipalName?: string

	    /** Data to sync */
		dataToSync?: boolean

	    /** Data quota */
		dataQuota?: number

	    /** Data quota */
		dataUsed?: number

}
export interface DeviceActionResult {

	    /** Action name */
		actionName?: string

	    /** State of the action. Possible values are: none, pending, canceled, active, done, failed, notSupported. */
		actionState?: ActionState

	    /** Time the action was initiated */
		startDateTime?: string

	    /** Time the action state was last updated */
		lastUpdatedDateTime?: string

}
export interface ConfigurationManagerClientEnabledFeatures {

	    /** Whether inventory is managed by Intune */
		inventory?: boolean

	    /** Whether modern application is managed by Intune */
		modernApps?: boolean

	    /** Whether resource access is managed by Intune */
		resourceAccess?: boolean

	    /** Whether device configuration is managed by Intune */
		deviceConfiguration?: boolean

	    /** Whether compliance policy is managed by Intune */
		compliancePolicy?: boolean

	    /** Whether Windows Update for Business is managed by Intune */
		windowsUpdateForBusiness?: boolean

}
export interface DeviceHealthAttestationState {

	    /** The Timestamp of the last update. */
		lastUpdateDateTime?: string

	    /** The DHA report version. (Namespace version) */
		contentNamespaceUrl?: string

	    /** The DHA report version. (Namespace version) */
		deviceHealthAttestationStatus?: string

	    /** The HealthAttestation state schema version */
		contentVersion?: string

	    /** The DateTime when device was evaluated or issued to MDM */
		issuedDateTime?: string

	    /** TWhen an Attestation Identity Key (AIK) is present on a device, it indicates that the device has an endorsement key (EK) certificate. */
		attestationIdentityKey?: string

	    /** The number of times a PC device has hibernated or resumed */
		resetCount?: number

	    /** The number of times a PC device has rebooted */
		restartCount?: number

	    /** DEP Policy defines a set of hardware and software technologies that perform additional checks on memory */
		dataExcutionPolicy?: string

	    /** On or Off of BitLocker Drive Encryption */
		bitLockerStatus?: string

	    /** The version of the Boot Manager */
		bootManagerVersion?: string

	    /** The version of the Boot Manager */
		codeIntegrityCheckVersion?: string

	    /** When Secure Boot is enabled, the core components must have the correct cryptographic signatures */
		secureBoot?: string

	    /** When bootDebugging is enabled, the device is used in development and testing */
		bootDebugging?: string

	    /** When operatingSystemKernelDebugging is enabled, the device is used in development and testing */
		operatingSystemKernelDebugging?: string

	    /** When code integrity is enabled, code execution is restricted to integrity verified code */
		codeIntegrity?: string

	    /** When test signing is allowed, the device does not enforce signature validation during boot */
		testSigning?: string

	    /** Safe mode is a troubleshooting option for Windows that starts your computer in a limited state */
		safeMode?: string

	    /** Operating system running with limited services that is used to prepare a computer for Windows */
		windowsPE?: string

	    /** ELAM provides protection for the computers in your network when they start up */
		earlyLaunchAntiMalwareDriverProtection?: string

	    /** VSM is a container that protects high value assets from a compromised kernel */
		virtualSecureMode?: string

	    /** Informational attribute that identifies the HASH algorithm that was used by TPM */
		pcrHashAlgorithm?: string

	    /** The security version number of the Boot Application */
		bootAppSecurityVersion?: string

	    /** The security version number of the Boot Application */
		bootManagerSecurityVersion?: string

	    /** The security version number of the Boot Application */
		tpmVersion?: string

	    /** The measurement that is captured in PCR[0] */
		pcr0?: string

	    /** Fingerprint of the Custom Secure Boot Configuration Policy */
		secureBootConfigurationPolicyFingerPrint?: string

	    /** The Code Integrity policy that is controlling the security of the boot environment */
		codeIntegrityPolicy?: string

	    /** The Boot Revision List that was loaded during initial boot on the attested device */
		bootRevisionListInfo?: string

	    /** The Operating System Revision List that was loaded during initial boot on the attested device */
		operatingSystemRevListInfo?: string

	    /** This attribute appears if DHA-Service detects an integrity issue */
		healthStatusMismatchInfo?: string

	    /** This attribute indicates if DHA is supported for the device */
		healthAttestationSupportedStatus?: string

}
export interface LoggedOnUser {

	    /** User id */
		userId?: string

	    /** Date time when user logs on */
		lastLogOnDateTime?: string

}
export interface ConfigurationManagerClientHealthState {

		state?: ConfigurationManagerClientState

		errorCode?: number

		lastSyncDateTime?: string

}
export interface BulkManagedDeviceActionResult {

	    /** Successful devices */
		successfulDeviceIds?: string[]

	    /** Failed devices */
		failedDeviceIds?: string[]

	    /** Not found devices */
		notFoundDeviceIds?: string[]

	    /** Not supported devices */
		notSupportedDeviceIds?: string[]

}
export interface UpdateWindowsDeviceAccountActionParameter {

	    /** Not yet documented */
		deviceAccount?: WindowsDeviceAccount

	    /** Not yet documented */
		passwordRotationEnabled?: boolean

	    /** Not yet documented */
		calendarSyncEnabled?: boolean

	    /** Not yet documented */
		deviceAccountEmail?: string

	    /** Not yet documented */
		exchangeServer?: string

	    /** Not yet documented */
		sessionInitiationProtocalAddress?: string

}
export interface WindowsDeviceAccount {

	    /** Not yet documented */
		password?: string

}
export interface DailySchedule extends RunSchedule {

	    /** Interval in number of days */
		interval?: number

}
export interface HourlySchedule extends RunSchedule {

	    /** Interval in number of hours */
		interval?: number

}
export interface RevokeAppleVppLicensesActionResult extends DeviceActionResult {

	    /** Total number of Apple Vpp licenses associated */
		totalLicensesCount?: number

	    /** Total number of Apple Vpp licenses that failed to revoke */
		failedLicensesCount?: number

}
export interface WindowsDefenderScanActionResult extends DeviceActionResult {

	    /** Scan type either full scan or quick scan */
		scanType?: string

}
export interface DeleteUserFromSharedAppleDeviceActionResult extends DeviceActionResult {

	    /** User principal name of the user to be deleted */
		userPrincipalName?: string

}
export interface DeviceGeoLocation {

	    /** Time at which location was recorded, relative to UTC */
		lastCollectedDateTimeUtc?: string

	    /** Time at which location was recorded, relative to UTC */
		lastCollectedDateTime?: string

	    /** Longitude coordinate of the device's location */
		longitude?: number

	    /** Latitude coordinate of the device's location */
		latitude?: number

	    /** Altitude, given in meters above sea level */
		altitude?: number

	    /** Accuracy of longitude and latitude in meters */
		horizontalAccuracy?: number

	    /** Accuracy of altitude in meters */
		verticalAccuracy?: number

	    /** Heading in degrees from true north */
		heading?: number

	    /** Speed the device is traveling in meters per second */
		speed?: number

}
export interface LocateDeviceActionResult extends DeviceActionResult {

	    /** device location */
		deviceLocation?: DeviceGeoLocation

}
export interface RemoteLockActionResult extends DeviceActionResult {

	    /** Pin to unlock the client */
		unlockPin?: string

}
export interface ResetPasscodeActionResult extends DeviceActionResult {

	    /** Newly generated passcode for the device */
		passcode?: string

}
export interface DeviceOperatingSystemSummary {

	    /** Number of android device count. */
		androidCount?: number

	    /** Number of iOS device count. */
		iosCount?: number

	    /** Number of Mac OS X device count. */
		macOSCount?: number

	    /** Number of Windows mobile device count. */
		windowsMobileCount?: number

	    /** Number of Windows device count. */
		windowsCount?: number

	    /** Number of unknown device count. */
		unknownCount?: number

}
export interface DeviceExchangeAccessStateSummary {

	    /** Total count of devices with Exchange Access State: Allowed. */
		allowedDeviceCount?: number

	    /** Total count of devices with Exchange Access State: Blocked. */
		blockedDeviceCount?: number

	    /** Total count of devices with Exchange Access State: Quarantined. */
		quarantinedDeviceCount?: number

	    /** Total count of devices with Exchange Access State: Unknown. */
		unknownDeviceCount?: number

	    /** Total count of devices for which no Exchange Access State could be found. */
		unavailableDeviceCount?: number

}
export interface ManagedDeviceModelsAndManufacturers {

	    /** List of Models for managed devices in the account */
		deviceModels?: string[]

	    /** List of Manufactures for managed devices in the account */
		deviceManufacturers?: string[]

}
export interface WindowsDeviceADAccount extends WindowsDeviceAccount {

	    /** Not yet documented */
		domainName?: string

	    /** Not yet documented */
		userName?: string

}
export interface WindowsDeviceAzureADAccount extends WindowsDeviceAccount {

	    /** Not yet documented */
		userPrincipalName?: string

}
export interface Report {

	    /** Report content. */
		content?: any

}
export interface AppListItem {

	    /** The application name */
		name?: string

	    /** The publisher of the application */
		publisher?: string

	    /** The Store URL of the application */
		appStoreUrl?: string

	    /** The application or bundle identifier of the application */
		appId?: string

}
export interface ExtendedKeyUsage {

	    /** Extended Key Usage Name */
		name?: string

	    /** Extended Key Usage Object Identifier */
		objectIdentifier?: string

}
export interface OmaSetting {

	    /** Display Name. */
		displayName?: string

	    /** Description. */
		description?: string

	    /** OMA. */
		omaUri?: string

}
export interface OmaSettingInteger extends OmaSetting {

	    /** Value. */
		value?: number

}
export interface OmaSettingFloatingPoint extends OmaSetting {

	    /** Value. */
		value?: number

}
export interface OmaSettingString extends OmaSetting {

	    /** Value. */
		value?: string

}
export interface OmaSettingDateTime extends OmaSetting {

	    /** Value. */
		value?: string

}
export interface OmaSettingStringXml extends OmaSetting {

	    /** File name associated with the Value property (.xml). */
		fileName?: string

	    /** Value. (UTF8 encoded byte array) */
		value?: number

}
export interface OmaSettingBoolean extends OmaSetting {

	    /** Value. */
		value?: boolean

}
export interface OmaSettingBase64 extends OmaSetting {

	    /** File name associated with the Value property (.cer */
		fileName?: string

	    /** Value. (Base64 encoded string) */
		value?: string

}
export interface VpnServer {

	    /** Description. */
		description?: string

	    /** Address (IP address, FQDN or URL) */
		address?: string

	    /** Default server. */
		isDefaultServer?: boolean

}
export interface CustomSubjectAlternativeName {

		sanType?: SubjectAlternativeNameType

		name?: string

}
export interface IosEduCertificateSettings {

	    /** Trusted Root Certificate. */
		trustedRootCertificate?: number

	    /** File name to display in UI. */
		certFileName?: string

	    /** PKCS Certification Authority. */
		certificationAuthority?: string

	    /** PKCS Certification Authority Name. */
		certificationAuthorityName?: string

	    /** PKCS Certificate Template Name. */
		certificateTemplateName?: string

	    /** Certificate renewal threshold percentage. Valid values 1 to 99 */
		renewalThresholdPercentage?: number

	    /** Value for the Certificate Validity Period. */
		certificateValidityPeriodValue?: number

	    /** Scale for the Certificate Validity Period. Possible values are: days, months, years. */
		certificateValidityPeriodScale?: CertificateValidityPeriodScale

}
export interface MediaContentRatingAustralia {

	    /** Movies rating selected for Australia. Possible values are: allAllowed, allBlocked, general, parentalGuidance, mature, agesAbove15, agesAbove18. */
		movieRating?: RatingAustraliaMoviesType

	    /** TV rating selected for Australia. Possible values are: allAllowed, allBlocked, preschoolers, children, general, parentalGuidance, mature, agesAbove15, agesAbove15AdultViolence. */
		tvRating?: RatingAustraliaTelevisionType

}
export interface MediaContentRatingCanada {

	    /** Movies rating selected for Canada. Possible values are: allAllowed, allBlocked, general, parentalGuidance, agesAbove14, agesAbove18, restricted. */
		movieRating?: RatingCanadaMoviesType

	    /** TV rating selected for Canada. Possible values are: allAllowed, allBlocked, children, childrenAbove8, general, parentalGuidance, agesAbove14, agesAbove18. */
		tvRating?: RatingCanadaTelevisionType

}
export interface MediaContentRatingFrance {

	    /** Movies rating selected for France. Possible values are: allAllowed, allBlocked, agesAbove10, agesAbove12, agesAbove16, agesAbove18. */
		movieRating?: RatingFranceMoviesType

	    /** TV rating selected for France. Possible values are: allAllowed, allBlocked, agesAbove10, agesAbove12, agesAbove16, agesAbove18. */
		tvRating?: RatingFranceTelevisionType

}
export interface MediaContentRatingGermany {

	    /** Movies rating selected for Germany. Possible values are: allAllowed, allBlocked, general, agesAbove6, agesAbove12, agesAbove16, adults. */
		movieRating?: RatingGermanyMoviesType

	    /** TV rating selected for Germany. Possible values are: allAllowed, allBlocked, general, agesAbove6, agesAbove12, agesAbove16, adults. */
		tvRating?: RatingGermanyTelevisionType

}
export interface MediaContentRatingIreland {

	    /** Movies rating selected for Ireland. Possible values are: allAllowed, allBlocked, general, parentalGuidance, agesAbove12, agesAbove15, agesAbove16, adults. */
		movieRating?: RatingIrelandMoviesType

	    /** TV rating selected for Ireland. Possible values are: allAllowed, allBlocked, general, children, youngAdults, parentalSupervision, mature. */
		tvRating?: RatingIrelandTelevisionType

}
export interface MediaContentRatingJapan {

	    /** Movies rating selected for Japan. Possible values are: allAllowed, allBlocked, general, parentalGuidance, agesAbove15, agesAbove18. */
		movieRating?: RatingJapanMoviesType

	    /** TV rating selected for Japan. Possible values are: allAllowed, allBlocked, explicitAllowed. */
		tvRating?: RatingJapanTelevisionType

}
export interface MediaContentRatingNewZealand {

	    /** Movies rating selected for New Zealand. Possible values are: allAllowed, allBlocked, general, parentalGuidance, mature, agesAbove13, agesAbove15, agesAbove16, agesAbove18, restricted, agesAbove16Restricted. */
		movieRating?: RatingNewZealandMoviesType

	    /** TV rating selected for New Zealand. Possible values are: allAllowed, allBlocked, general, parentalGuidance, adults. */
		tvRating?: RatingNewZealandTelevisionType

}
export interface MediaContentRatingUnitedKingdom {

	    /** Movies rating selected for United Kingdom. Possible values are: allAllowed, allBlocked, general, universalChildren, parentalGuidance, agesAbove12Video, agesAbove12Cinema, agesAbove15, adults. */
		movieRating?: RatingUnitedKingdomMoviesType

	    /** TV rating selected for United Kingdom. Possible values are: allAllowed, allBlocked, caution. */
		tvRating?: RatingUnitedKingdomTelevisionType

}
export interface MediaContentRatingUnitedStates {

	    /** Movies rating selected for United States. Possible values are: allAllowed, allBlocked, general, parentalGuidance, parentalGuidance13, restricted, adults. */
		movieRating?: RatingUnitedStatesMoviesType

	    /** TV rating selected for United States. Possible values are: allAllowed, allBlocked, childrenAll, childrenAbove7, general, parentalGuidance, childrenAbove14, adults. */
		tvRating?: RatingUnitedStatesTelevisionType

}
export interface IosNetworkUsageRule {

	    /** Information about the managed apps that this rule is going to apply to. This collection can contain a maximum of 500 elements. */
		managedApps?: AppListItem[]

	    /** If set to true, corresponding managed apps will not be allowed to use cellular data when roaming. */
		cellularDataBlockWhenRoaming?: boolean

	    /** If set to true, corresponding managed apps will not be allowed to use cellular data at any time. */
		cellularDataBlocked?: boolean

}
export interface MacOSFirewallApplication {

	    /** BundleId of the application. */
		bundleId?: string

	    /** Whether or not incoming connections are allowed. */
		allowsIncomingConnections?: boolean

}
export interface UnsupportedDeviceConfigurationDetail {

	    /** A message explaining why an entity is unsupported. */
		message?: string

	    /** If message is related to a specific property in the original entity, then the name of that property. */
		propertyName?: string

}
export interface AirPrintDestination {

	    /** The IP Address of the AirPrint destination. */
		ipAddress?: string

	    /** The Resource Path associated with the printer. This corresponds to the rp parameter of the ipps.tcp Bonjour record. For example: printers/Canon_MG5300_series, printers/Xerox_Phaser_7600, ipp/print, Epson_IPP_Printer. */
		resourcePath?: string

	    /** The listening port of the AirPrint destination. If this key is not specified AirPrint will use the default port. Available in iOS 11.0 and later. */
		port?: number

	    /** If true AirPrint connections are secured by Transport Layer Security (TLS). Default is false. Available in iOS 11.0 and later. */
		forceTls?: boolean

}
export interface IosWebContentFilterBase {

}
export interface IosHomeScreenItem {

	    /** Name of the app */
		displayName?: string

}
export interface IosHomeScreenPage {

	    /** Name of the page */
		displayName?: string

	    /** A list of apps and folders to appear on a page. This collection can contain a maximum of 500 elements. */
		icons?: IosHomeScreenItem[]

}
export interface IosNotificationSettings {

	    /** Bundle id of app to which to apply these notification settings. */
		bundleID?: string

	    /** Application name to be associated with the bundleID. */
		appName?: string

	    /** Publisher to be associated with the bundleID. */
		publisher?: string

	    /** Indicates whether notifications are allowed for this app. */
		enabled?: boolean

	    /** Indicates whether notifications can be shown in notification center. */
		showInNotificationCenter?: boolean

	    /** Indicates whether notifications can be shown on the lock screen. */
		showOnLockScreen?: boolean

	    /** Indicates the type of alert for notifications for this app. Possible values are: deviceDefault, banner, modal, none. */
		alertType?: IosNotificationAlertType

	    /** Indicates whether badges are allowed for this app. */
		badgesEnabled?: boolean

	    /** Indicates whether sounds are allowed for this app. */
		soundsEnabled?: boolean

}
export interface IosSingleSignOnSettings {

	    /** List of app identifiers that are allowed to use this login. If this field is omitted, the login applies to all applications on the device. This collection can contain a maximum of 500 elements. */
		allowedAppsList?: AppListItem[]

	    /** List of HTTP URLs that must be matched in order to use this login. With iOS 9.0 or later, a wildcard characters may be used. */
		allowedUrls?: string[]

	    /** The display name of login settings shown on the receiving device. */
		displayName?: string

	    /** A Kerberos principal name. If not provided, the user is prompted for one during profile installation. */
		kerberosPrincipalName?: string

	    /** A Kerberos realm name. Case sensitive. */
		kerberosRealm?: string

}
export interface IosWebContentFilterSpecificWebsitesAccess extends IosWebContentFilterBase {

	    /** URL bookmarks which will be installed into built-in browser and user is only allowed to access websites through bookmarks. This collection can contain a maximum of 500 elements. */
		specificWebsitesOnly?: IosBookmark[]

		websiteList?: IosBookmark[]

}
export interface IosBookmark {

	    /** URL allowed to access */
		url?: string

	    /** The folder into which the bookmark should be added in Safari */
		bookmarkFolder?: string

	    /** The display name of the bookmark */
		displayName?: string

}
export interface IosWebContentFilterAutoFilter extends IosWebContentFilterBase {

	    /** Additional URLs allowed for access */
		allowedUrls?: string[]

	    /** Additional URLs blocked for access */
		blockedUrls?: string[]

}
export interface IosHomeScreenFolder extends IosHomeScreenItem {

	    /** Pages of Home Screen Layout Icons which must be Application Type. This collection can contain a maximum of 500 elements. */
		pages?: IosHomeScreenFolderPage[]

}
export interface IosHomeScreenFolderPage {

	    /** Name of the folder page */
		displayName?: string

	    /** A list of apps to appear on a page within a folder. This collection can contain a maximum of 500 elements. */
		apps?: IosHomeScreenApp[]

}
export interface IosHomeScreenApp extends IosHomeScreenItem {

	    /** BundleID of app */
		bundleID?: string

}
export interface VpnOnDemandRule {

	    /** Network Service Set Identifiers (SSIDs). */
		ssids?: string[]

	    /** DNS Search Domains. */
		dnsSearchDomains?: string[]

	    /** A URL to probe. If this URL is successfully fetched (returning a 200 HTTP status code) without redirection, this rule matches. */
		probeUrl?: string

	    /** Action. Possible values are: connect, evaluateConnection, ignore, disconnect. */
		action?: VpnOnDemandRuleConnectionAction

	    /** Domain Action (Only applicable when Action is evaluate connection). Possible values are: connectIfNeeded, neverConnect. */
		domainAction?: VpnOnDemandRuleConnectionDomainAction

	    /** Domains (Only applicable when Action is evaluate connection). */
		domains?: string[]

	    /** Probe Required Url (Only applicable when Action is evaluate connection and DomainAction is connect if needed). */
		probeRequiredUrl?: string

}
export interface VpnProxyServer {

	    /** Proxy's automatic configuration script url. */
		automaticConfigurationScriptUrl?: string

	    /** Address. */
		address?: string

	    /** Port. Valid values 0 to 65535 */
		port?: number

}
export interface Windows81VpnProxyServer extends VpnProxyServer {

	    /** Automatically detect proxy settings. */
		automaticallyDetectProxySettings?: boolean

	    /** Bypass proxy server for local address. */
		bypassProxyServerForLocalAddress?: boolean

}
export interface Windows10VpnProxyServer extends VpnProxyServer {

	    /** Bypass proxy server for local address. */
		bypassProxyServerForLocalAddress?: boolean

}
export interface DeviceManagementUserRightsSetting {

		state?: StateManagementSetting

		localUsersOrGroups?: DeviceManagementUserRightsLocalUserOrGroup[]

}
export interface DeviceManagementUserRightsLocalUserOrGroup {

		name?: string

		description?: string

		securityIdentifier?: string

}
export interface WindowsFirewallNetworkProfile {

	    /** Turn on the firewall and advanced security enforcement. Possible values are: notConfigured, blocked, allowed. */
		firewallEnabled?: StateManagementSetting

		stealthModeRequired?: boolean

	    /** Prevent the server from operating in stealth mode */
		stealthModeBlocked?: boolean

		incomingTrafficRequired?: boolean

	    /** Configures the firewall to block all incoming traffic regardless of other policy settings */
		incomingTrafficBlocked?: boolean

		unicastResponsesToMulticastBroadcastsRequired?: boolean

	    /** Configures the firewall to block unicast responses to multicast broadcast traffic */
		unicastResponsesToMulticastBroadcastsBlocked?: boolean

		inboundNotificationsRequired?: boolean

	    /** Prevents the firewall from displaying notifications when an application is blocked from listening on a port */
		inboundNotificationsBlocked?: boolean

	    /** Configures the firewall to merge authorized application rules from group policy with those from local store instead of ignoring the local store rules */
		authorizedApplicationRulesFromGroupPolicyMerged?: boolean

		authorizedApplicationRulesFromGroupPolicyNotMerged?: boolean

	    /** Configures the firewall to merge global port rules from group policy with those from local store instead of ignoring the local store rules */
		globalPortRulesFromGroupPolicyMerged?: boolean

		globalPortRulesFromGroupPolicyNotMerged?: boolean

	    /** Configures the firewall to merge connection security rules from group policy with those from local store instead of ignoring the local store rules */
		connectionSecurityRulesFromGroupPolicyMerged?: boolean

		connectionSecurityRulesFromGroupPolicyNotMerged?: boolean

		outboundConnectionsRequired?: boolean

	    /** Configures the firewall to block all outgoing connections by default */
		outboundConnectionsBlocked?: boolean

		inboundConnectionsRequired?: boolean

	    /** Configures the firewall to block all incoming connections by default */
		inboundConnectionsBlocked?: boolean

	    /** Configures the firewall to allow the host computer to respond to unsolicited network traffic of that traffic is secured by IPSec even when stealthModeBlocked is set to true */
		securedPacketExemptionAllowed?: boolean

		securedPacketExemptionBlocked?: boolean

	    /** Configures the firewall to merge Firewall Rule policies from group policy with those from local store instead of ignoring the local store rules */
		policyRulesFromGroupPolicyMerged?: boolean

		policyRulesFromGroupPolicyNotMerged?: boolean

}
export interface BitLockerSystemDrivePolicy {

	    /** Select the encryption method for operating system drives. Possible values are: aesCbc128, aesCbc256, xtsAes128, xtsAes256. */
		encryptionMethod?: BitLockerEncryptionMethod

	    /** Require additional authentication at startup. */
		startupAuthenticationRequired?: boolean

	    /** Indicates whether to allow BitLocker without a compatible TPM (requires a password or a startup key on a USB flash drive). */
		startupAuthenticationBlockWithoutTpmChip?: boolean

	    /** Indicates if TPM startup is allowed/required/disallowed. Possible values are: blocked, required, allowed. */
		startupAuthenticationTpmUsage?: ConfigurationUsage

	    /** Indicates if TPM startup pin is allowed/required/disallowed. Possible values are: blocked, required, allowed. */
		startupAuthenticationTpmPinUsage?: ConfigurationUsage

	    /** Indicates if TPM startup key is allowed/required/disallowed. Possible values are: blocked, required, allowed. */
		startupAuthenticationTpmKeyUsage?: ConfigurationUsage

	    /** Indicates if TPM startup pin key and key are allowed/required/disallowed. Possible values are: blocked, required, allowed. */
		startupAuthenticationTpmPinAndKeyUsage?: ConfigurationUsage

	    /** Indicates the minimum length of startup pin. Valid values 4 to 20 */
		minimumPinLength?: number

	    /** Allows to recover BitLocker encrypted operating system drives in the absence of the required startup key information. This policy setting is applied when you turn on BitLocker. */
		recoveryOptions?: BitLockerRecoveryOptions

	    /** Enable pre-boot recovery message and Url. If requireStartupAuthentication is false, this value does not affect. */
		prebootRecoveryEnableMessageAndUrl?: boolean

	    /** Defines a custom recovery message. */
		prebootRecoveryMessage?: string

	    /** Defines a custom recovery URL. */
		prebootRecoveryUrl?: string

}
export interface BitLockerRecoveryOptions {

	    /** Indicates whether to block certificate-based data recovery agent. */
		blockDataRecoveryAgent?: boolean

	    /** Indicates whether users are allowed or required to generate a 48-digit recovery password for fixed or system disk. Possible values are: blocked, required, allowed. */
		recoveryPasswordUsage?: ConfigurationUsage

	    /** Indicates whether users are allowed or required to generate a 256-bit recovery key for fixed or system disk. Possible values are: blocked, required, allowed. */
		recoveryKeyUsage?: ConfigurationUsage

	    /** Indicates whether or not to allow showing recovery options in BitLocker Setup Wizard for fixed or system disk. */
		hideRecoveryOptions?: boolean

	    /** Indicates whether or not to allow BitLocker recovery information to store in AD DS. */
		enableRecoveryInformationSaveToStore?: boolean

	    /** Configure what pieces of BitLocker recovery information are stored to AD DS. Possible values are: passwordAndKey, passwordOnly. */
		recoveryInformationToStore?: BitLockerRecoveryInformationType

	    /** Indicates whether or not to enable BitLocker until recovery information is stored in AD DS. */
		enableBitLockerAfterRecoveryInformationToStore?: boolean

}
export interface BitLockerFixedDrivePolicy {

	    /** Select the encryption method for fixed drives. Possible values are: aesCbc128, aesCbc256, xtsAes128, xtsAes256. */
		encryptionMethod?: BitLockerEncryptionMethod

	    /** This policy setting determines whether BitLocker protection is required for fixed data drives to be writable on a computer. */
		requireEncryptionForWriteAccess?: boolean

	    /** This policy setting allows you to control how BitLocker-protected fixed data drives are recovered in the absence of the required credentials. This policy setting is applied when you turn on BitLocker. */
		recoveryOptions?: BitLockerRecoveryOptions

}
export interface BitLockerRemovableDrivePolicy {

	    /** Select the encryption method for removable  drives. Possible values are: aesCbc128, aesCbc256, xtsAes128, xtsAes256. */
		encryptionMethod?: BitLockerEncryptionMethod

	    /** Indicates whether to block write access to devices configured in another organization.  If requireEncryptionForWriteAccess is false, this value does not affect. */
		requireEncryptionForWriteAccess?: boolean

	    /** This policy setting determines whether BitLocker protection is required for removable data drives to be writable on a computer. */
		blockCrossOrganizationWriteAccess?: boolean

}
export interface DefenderDetectedMalwareActions {

	    /** Indicates a Defender action to take for low severity Malware threat detected. Possible values are: deviceDefault, clean, quarantine, remove, allow, userDefined, block. */
		lowSeverity?: DefenderThreatAction

	    /** Indicates a Defender action to take for moderate severity Malware threat detected. Possible values are: deviceDefault, clean, quarantine, remove, allow, userDefined, block. */
		moderateSeverity?: DefenderThreatAction

	    /** Indicates a Defender action to take for high severity Malware threat detected. Possible values are: deviceDefault, clean, quarantine, remove, allow, userDefined, block. */
		highSeverity?: DefenderThreatAction

	    /** Indicates a Defender action to take for severe severity Malware threat detected. Possible values are: deviceDefault, clean, quarantine, remove, allow, userDefined, block. */
		severeSeverity?: DefenderThreatAction

}
export interface Windows10NetworkProxyServer {

	    /** Address to the proxy server. Specify an address in the format [“:”] */
		address?: string

	    /** Addresses that should not use the proxy server. The system will not use the proxy server for addresses beginning with what is specified in this node. */
		exceptions?: string[]

	    /** Specifies whether the proxy server should be used for local (intranet) addresses. */
		useForLocalAddresses?: boolean

}
export interface EdgeSearchEngineBase {

}
export interface EdgeSearchEngineCustom extends EdgeSearchEngineBase {

	    /** Points to a https link containing the OpenSearch xml file that contains, at minimum, the short name and the URL to the search Engine. */
		edgeSearchEngineOpenSearchXmlUrl?: string

}
export interface EdgeSearchEngine extends EdgeSearchEngineBase {

	    /** Allows IT admins to set a predefined default search engine for MDM-Controlled devices. Possible values are: default, bing. */
		edgeSearchEngineType?: EdgeSearchEngineType

}
export interface WindowsNetworkIsolationPolicy {

	    /** This is the list of domains that comprise the boundaries of the enterprise. Data from one of these domains that is sent to a device will be considered enterprise data and protected. These locations will be considered a safe destination for enterprise data to be shared to. */
		enterpriseNetworkDomainNames?: string[]

	    /** Contains a list of enterprise resource domains hosted in the cloud that need to be protected. Connections to these resources are considered enterprise data. If a proxy is paired with a cloud resource, traffic to the cloud resource will be routed through the enterprise network via the denoted proxy server (on Port 80). A proxy server used for this purpose must also be configured using the EnterpriseInternalProxyServers policy. This collection can contain a maximum of 500 elements. */
		enterpriseCloudResources?: ProxiedDomain[]

	    /** Sets the enterprise IP ranges that define the computers in the enterprise network. Data that comes from those computers will be considered part of the enterprise and protected. These locations will be considered a safe destination for enterprise data to be shared to. This collection can contain a maximum of 500 elements. */
		enterpriseIPRanges?: IpRange[]

	    /** This is the comma-separated list of internal proxy servers. For example, "157.54.14.28, 157.54.11.118, 10.202.14.167, 157.53.14.163, 157.69.210.59". These proxies have been configured by the admin to connect to specific resources on the Internet. They are considered to be enterprise network locations. The proxies are only leveraged in configuring the EnterpriseCloudResources policy to force traffic to the matched cloud resources through these proxies. */
		enterpriseInternalProxyServers?: string[]

	    /** Boolean value that tells the client to accept the configured list and not to use heuristics to attempt to find other subnets. Default is false. */
		enterpriseIPRangesAreAuthoritative?: boolean

	    /** This is a list of proxy servers. Any server not on this list is considered non-enterprise. */
		enterpriseProxyServers?: string[]

	    /** Boolean value that tells the client to accept the configured list of proxies and not try to detect other work proxies. Default is false */
		enterpriseProxyServersAreAuthoritative?: boolean

	    /** List of domain names that can used for work or personal resource. */
		neutralDomainResources?: string[]

}
export interface ProxiedDomain {

	    /** The IP address or FQDN */
		ipAddressOrFQDN?: string

	    /** Proxy IP */
		proxy?: string

}
export interface IpRange {

}
export interface IPv6Range extends IpRange {

	    /** Lower IP Address */
		lowerAddress?: string

	    /** Upper IP Address */
		upperAddress?: string

}
export interface IPv4Range extends IpRange {

	    /** Lower IP Address */
		lowerAddress?: string

	    /** Upper IP Address */
		upperAddress?: string

}
export interface WindowsKioskProfile {

	    /** Key of the entity. */
		profileId?: string

	    /** This is a friendly name used to identify a group of applications, the layout of these apps on the start menu and the users to whom this kiosk configuration is assigned. */
		profileName?: string

	    /** The App configuration that will be used for this kiosk configuration. */
		appConfiguration?: WindowsKioskAppConfiguration

	    /** The user accounts that will be locked to this kiosk configuration. This collection can contain a maximum of 500 elements. */
		userAccountsConfiguration?: WindowsKioskUser[]

}
export interface WindowsKioskAppConfiguration {

}
export interface WindowsKioskUser {

}
export interface WindowsKioskMultipleApps extends WindowsKioskAppConfiguration {

	    /** These are the only Windows Store Apps that will be available to launch from the Start menu. */
		apps?: WindowsKioskAppBase[]

	    /** This setting allows the admin to specify whether the Task Bar is shown or not. */
		showTaskBar?: boolean

	    /** Allows admins to override the default Start layout and prevents the user from changing it. The layout is modified by specifying an XML file based on a layout modification schema. XML needs to be in Binary format. */
		startMenuLayoutXml?: number

}
export interface WindowsKioskAppBase {

}
export interface WindowsKioskUWPApp extends WindowsKioskAppBase {

	    /** This is the only Application User Model ID (AUMID) that will be available to launch use while in Kiosk Mode */
		appUserModelId?: string

	    /** This references an Intune App that will be target to the same assignments as Kiosk configuration */
		appId?: string

	    /** This references an contained App from an Intune App */
		containedAppId?: string

}
export interface WindowsKioskSingleUWPApp extends WindowsKioskAppConfiguration {

	    /** This is the only Application User Model ID (AUMID) that will be available to launch use while in Kiosk Mode */
		uwpApp?: WindowsKioskUWPApp

}
export interface WindowsKioskDesktopApp extends WindowsKioskAppBase {

	    /** Represents the friendly name of an app */
		name?: string

	    /** Define the path of a desktop app */
		path?: string

}
export interface WindowsKioskVisitor extends WindowsKioskUser {

}
export interface WindowsKioskAutologon extends WindowsKioskUser {

}
export interface WindowsKioskLocalGroup extends WindowsKioskUser {

	    /** The name of the local group that will be locked to this kiosk configuration */
		groupName?: string

}
export interface WindowsKioskActiveDirectoryGroup extends WindowsKioskUser {

	    /** The name of the AD group that will be locked to this kiosk configuration */
		groupName?: string

}
export interface WindowsKioskAzureADGroup extends WindowsKioskUser {

	    /** The display name of the AzureAD group that will be locked to this kiosk configuration */
		displayName?: string

	    /** The ID of the AzureAD group that will be locked to this kiosk configuration */
		groupId?: string

}
export interface WindowsKioskAzureADUser extends WindowsKioskUser {

	    /** The ID of the AzureAD user that will be locked to this kiosk configuration */
		userId?: string

	    /** The user accounts that will be locked to this kiosk configuration */
		userPrincipalName?: string

}
export interface WindowsKioskLocalUser extends WindowsKioskUser {

	    /** The local user that will be locked to this kiosk configuration */
		userName?: string

}
export interface SharedPCAccountManagerPolicy {

	    /** Configures when accounts are deleted. Possible values are: immediate, diskSpaceThreshold, diskSpaceThresholdOrInactiveThreshold. */
		accountDeletionPolicy?: SharedPCAccountDeletionPolicyType

	    /** Sets the percentage of available disk space a PC should have before it stops deleting cached shared PC accounts. Only applies when AccountDeletionPolicy is DiskSpaceThreshold or DiskSpaceThresholdOrInactiveThreshold. Valid values 0 to 100 */
		cacheAccountsAboveDiskFreePercentage?: number

	    /** Specifies when the accounts will start being deleted when they have not been logged on during the specified period, given as number of days. Only applies when AccountDeletionPolicy is DiskSpaceThreshold or DiskSpaceThresholdOrInactiveThreshold. */
		inactiveThresholdDays?: number

	    /** Sets the percentage of disk space remaining on a PC before cached accounts will be deleted to free disk space. Accounts that have been inactive the longest will be deleted first. Only applies when AccountDeletionPolicy is DiskSpaceThresholdOrInactiveThreshold. Valid values 0 to 100 */
		removeAccountsBelowDiskFreePercentage?: number

}
export interface WindowsUpdateInstallScheduleType {

}
export interface WindowsUpdateScheduledInstall extends WindowsUpdateInstallScheduleType {

	    /** Scheduled Install Day in week. Possible values are: userDefined, everyday, sunday, monday, tuesday, wednesday, thursday, friday, saturday. */
		scheduledInstallDay?: WeeklySchedule

	    /** Scheduled Install Time during day */
		scheduledInstallTime?: string

}
export interface WindowsUpdateActiveHoursInstall extends WindowsUpdateInstallScheduleType {

	    /** Active Hours Start */
		activeHoursStart?: string

	    /** Active Hours End */
		activeHoursEnd?: string

}
export interface Windows10AssociatedApps {

	    /** Application type. Possible values are: desktop, universal. */
		appType?: Windows10AppType

	    /** Identifier. */
		identifier?: string

}
export interface VpnTrafficRule {

	    /** Name. */
		name?: string

	    /** Protocols (0-255). Valid values 0 to 255 */
		protocols?: number

	    /** Local port range can be set only when protocol is either TCP or UDP (6 or 17). This collection can contain a maximum of 500 elements. */
		localPortRanges?: NumberRange[]

	    /** Remote port range can be set only when protocol is either TCP or UDP (6 or 17). This collection can contain a maximum of 500 elements. */
		remotePortRanges?: NumberRange[]

	    /** Local address range. This collection can contain a maximum of 500 elements. */
		localAddressRanges?: IPv4Range[]

	    /** Remote address range. This collection can contain a maximum of 500 elements. */
		remoteAddressRanges?: IPv4Range[]

	    /** App identifier, if this traffic rule is triggered by an app. */
		appId?: string

	    /** App type, if this traffic rule is triggered by an app. Possible values are: none, desktop, universal. */
		appType?: VpnTrafficRuleAppType

	    /** When app triggered, indicates whether to enable split tunneling along this route. Possible values are: none, splitTunnel, forceTunnel. */
		routingPolicyType?: VpnTrafficRuleRoutingPolicyType

	    /** Claims associated with this traffic rule. */
		claims?: string

}
export interface NumberRange {

	    /** Lower number. */
		lowerNumber?: number

	    /** Upper number. */
		upperNumber?: number

}
export interface VpnRoute {

	    /** Destination prefix (IPv4/v6 address). */
		destinationPrefix?: string

	    /** Prefix size. (1-32). Valid values 1 to 32 */
		prefixSize?: number

}
export interface VpnDnsRule {

	    /** Name. */
		name?: string

	    /** Servers. */
		servers?: string[]

	    /** Proxy Server Uri. */
		proxyServerUri?: string

}
export interface OperatingSystemVersionRange {

	    /** The description of this range (e.g. Valid 1702 builds) */
		description?: string

	    /** The lowest inclusive version that this range contains. */
		lowestVersion?: string

	    /** The highest inclusive version that this range contains. */
		highestVersion?: string

}
export interface DeviceConfigurationSettingState {

	    /** The setting that is being reported */
		setting?: string

	    /** Localized/user friendly setting name that is being reported */
		settingName?: string

	    /** Name of setting instance that is being reported. */
		instanceDisplayName?: string

	    /** The compliance state of the setting. Possible values are: unknown, notApplicable, compliant, remediated, nonCompliant, error, conflict. */
		state?: ComplianceStatus

	    /** Error code for the setting */
		errorCode?: number

	    /** Error description */
		errorDescription?: string

	    /** UserId */
		userId?: string

	    /** UserName */
		userName?: string

	    /** UserEmail */
		userEmail?: string

	    /** UserPrincipalName. */
		userPrincipalName?: string

	    /** Contributing policies */
		sources?: SettingSource[]

	    /** Current value of setting on device */
		currentValue?: string

}
export interface SettingSource {

	    /** Not yet documented */
		id?: string

	    /** Not yet documented */
		displayName?: string

}
export interface DeviceCompliancePolicySettingState {

	    /** The setting that is being reported */
		setting?: string

	    /** Localized/user friendly setting name that is being reported */
		settingName?: string

	    /** Name of setting instance that is being reported. */
		instanceDisplayName?: string

	    /** The compliance state of the setting. Possible values are: unknown, notApplicable, compliant, remediated, nonCompliant, error, conflict. */
		state?: ComplianceStatus

	    /** Error code for the setting */
		errorCode?: number

	    /** Error description */
		errorDescription?: string

	    /** UserId */
		userId?: string

	    /** UserName */
		userName?: string

	    /** UserEmail */
		userEmail?: string

	    /** UserPrincipalName. */
		userPrincipalName?: string

	    /** Contributing policies */
		sources?: SettingSource[]

	    /** Current value of setting on device */
		currentValue?: string

}
export interface ManagedDeviceReportedApp {

	    /** The application or bundle identifier of the application */
		appId?: string

}
export interface DeviceAndAppManagementData {

	    /** Not yet documented */
		content?: any

}
export interface VppTokenActionResult {

	    /** Action name */
		actionName?: string

	    /** State of the action. Possible values are: none, pending, canceled, active, done, failed, notSupported. */
		actionState?: ActionState

	    /** Time the action was initiated */
		startDateTime?: string

	    /** Time the action state was last updated */
		lastUpdatedDateTime?: string

}
export interface VppTokenLicenseSummary {

		vppTokenId?: string

		appleId?: string

		organizationName?: string

		availableLicenseCount?: number

		usedLicenseCount?: number

}
export interface DeviceEnrollmentPlatformRestriction {

	    /** Block the platform from enrolling */
		platformBlocked?: boolean

	    /** Block personally owned devices from enrolling */
		personalDeviceEnrollmentBlocked?: boolean

	    /** Min OS version supported */
		osMinimumVersion?: string

	    /** Max OS version supported */
		osMaximumVersion?: string

}
export interface VppTokenRevokeLicensesActionResult extends VppTokenActionResult {

	    /** A count of the number of licenses that were attempted to revoke. */
		totalLicensesCount?: number

	    /** A count of the number of licenses that failed to revoke. */
		failedLicensesCount?: number

	    /** The reason for the revoke licenses action failure. Possible values are: none, appleFailure, internalError, expiredVppToken, expiredApplePushNotificationCertificate. */
		actionFailureReason?: VppTokenActionFailureReason

}
export interface DeviceManagementExchangeAccessRule {

	    /** Device Class which will be impacted by this rule. */
		deviceClass?: DeviceManagementExchangeDeviceClass

	    /** Access Level for Exchange granted by this rule. Possible values are: none, allow, block, quarantine. */
		accessLevel?: DeviceManagementExchangeAccessLevel

}
export interface DeviceManagementExchangeDeviceClass {

	    /** Name of the device class which will be impacted by this rule. */
		name?: string

	    /** Type of device which is impacted by this rule e.g. Model, Family. Possible values are: family, model. */
		type?: DeviceManagementExchangeAccessRuleType

}
export interface ManagementConditionExpression {

}
export interface ManagementConditionExpressionString extends ManagementConditionExpression {

		value?: string

}
export interface ManagementConditionExpressionModel extends ManagementConditionExpression {

}
export interface BinaryManagementConditionExpression extends ManagementConditionExpressionModel {

		operator?: BinaryManagementConditionExpressionOperatorType

		firstOperand?: ManagementConditionExpressionModel

		secondOperand?: ManagementConditionExpressionModel

}
export interface UnaryManagementConditionExpression extends ManagementConditionExpressionModel {

		operator?: UnaryManagementConditionExpressionOperatorType

		operand?: ManagementConditionExpressionModel

}
export interface VariableManagementConditionExpression extends ManagementConditionExpressionModel {

		managementConditionId?: string

}
export interface MobileAppIdentifier {

}
export interface ManagedAppDiagnosticStatus {

	    /** The validation friendly name */
		validationName?: string

	    /** The state of the operation */
		state?: string

	    /** Instruction on how to mitigate a failed validation */
		mitigationInstruction?: string

}
export interface WindowsInformationProtectionResourceCollection {

	    /** Display name */
		displayName?: string

	    /** Collection of resources */
		resources?: string[]

}
export interface WindowsInformationProtectionDataRecoveryCertificate {

	    /** Data recovery Certificate subject name */
		subjectName?: string

	    /** Data recovery Certificate description */
		description?: string

	    /** Data recovery Certificate expiration datetime */
		expirationDateTime?: string

	    /** Data recovery Certificate */
		certificate?: number

}
export interface WindowsInformationProtectionApp {

	    /** App display name. */
		displayName?: string

	    /** The app's description. */
		description?: string

	    /** The publisher name */
		publisherName?: string

	    /** The product name. */
		productName?: string

	    /** If true, app is denied protection or exemption. */
		denied?: boolean

}
export interface WindowsInformationProtectionProxiedDomainCollection {

	    /** Display name */
		displayName?: string

	    /** Collection of proxied domains */
		proxiedDomains?: ProxiedDomain[]

}
export interface WindowsInformationProtectionIPRangeCollection {

	    /** Display name */
		displayName?: string

	    /** Collection of ip ranges */
		ranges?: IpRange[]

}
export interface AndroidMobileAppIdentifier extends MobileAppIdentifier {

	    /** The identifier for an app, as specified in the play store. */
		packageId?: string

}
export interface IosMobileAppIdentifier extends MobileAppIdentifier {

	    /** The identifier for an app, as specified in the app store. */
		bundleId?: string

}
export interface ManagedAppPolicyDeploymentSummaryPerApp {

	    /** Deployment of an app. */
		mobileAppIdentifier?: MobileAppIdentifier

	    /** Number of users the policy is applied. */
		configurationAppliedUserCount?: number

}
export interface WindowsInformationProtectionStoreApp extends WindowsInformationProtectionApp {

}
export interface WindowsInformationProtectionDesktopApp extends WindowsInformationProtectionApp {

	    /** The binary name. */
		binaryName?: string

	    /** The lower binary version. */
		binaryVersionLow?: string

	    /** The high binary version. */
		binaryVersionHigh?: string

}
export interface RolePermission {

	    /** Allowed Actions */
		actions?: string[]

	    /** Actions */
		resourceActions?: ResourceAction[]

}
export interface ResourceAction {

	    /** Allowed Actions */
		allowedResourceActions?: string[]

	    /** Not Allowed Actions */
		notAllowedResourceActions?: string[]

}
export interface EmbeddedSIMActivationCode {

	    /** The input must match the following regular expression: '^[0-9]{19}[0-9]?$'. */
		integratedCircuitCardIdentifier?: string

	    /** The input must match the following regular expression: '^[a-zA-Z0-9\-]*$'. */
		matchingIdentifier?: string

	    /** The input must match the following regular expression: '^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$'. */
		smdpPlusServerAddress?: string

}
export interface OutOfBoxExperienceSettings {

	    /** Show or hide privacy settings to user */
		hidePrivacySettings?: boolean

	    /** Show or hide EULA to user */
		hideEULA?: boolean

	    /** Type of user. Possible values are: administrator, standard. */
		userType?: WindowsUserType

	    /** AAD join authentication type. Possible values are: singleUser, shared. */
		deviceUsageType?: WindowsDeviceUsageType

	    /** If set, then skip the keyboard selection page if Language and Region are set */
		skipKeyboardSelectionPage?: boolean

		hideEscapeLink?: boolean

}
export interface WindowsEnrollmentStatusScreenSettings {

	    /** Show or hide installation progress to user */
		hideInstallationProgress?: boolean

	    /** Allow or block user to use device before profile and app installation complete */
		allowDeviceUseBeforeProfileAndAppInstallComplete?: boolean

	    /** Allow the user to retry the setup on installation failure */
		blockDeviceSetupRetryByUser?: boolean

	    /** Allow or block log collection on installation failure */
		allowLogCollectionOnInstallFailure?: boolean

	    /** Set custom error message to show upon installation failure */
		customErrorMessage?: string

	    /** Set installation progress timeout in minutes */
		installProgressTimeoutInMinutes?: number

	    /** Allow the user to continue using the device on installation failure */
		allowDeviceUseOnInstallFailure?: boolean

}
export interface ManagementCertificateWithThumbprint {

	    /** Not yet documented */
		thumbprint?: string

	    /** Not yet documented */
		certificate?: string

}
export interface ImportedWindowsAutopilotDeviceIdentityState {

	    /** Device status reported by Device Directory Service(DDS). Possible values are: unknown, pending, partial, complete, error. */
		deviceImportStatus?: ImportedWindowsAutopilotDeviceIdentityImportStatus

	    /** Device Registration ID for successfully added device reported by Device Directory Service(DDS). */
		deviceRegistrationId?: string

	    /** Device error code reported by Device Directory Service(DDS). */
		deviceErrorCode?: number

	    /** Device error name reported by Device Directory Service(DDS). */
		deviceErrorName?: string

}
export interface UserActivationCounts {

	    /** The product type, such as "Office 365 ProPlus", "Project Client", or "Visio Pro for Office 365". */
		productType?: string

	    /** The date of the latest activation. */
		lastActivatedDate?: string

	    /** The activation count on Windows. This number includes every activation on any Windows computer. */
		windows?: number

	    /** The activation count on Mac OS. */
		mac?: number

	    /** The activation count on Windows 10 mobile. */
		windows10Mobile?: number

	    /** The activation count on iOS. */
		ios?: number

	    /** The activation count on an Android device. */
		android?: number

	    /** True if the user used the product on a shared computer before. */
		activatedOnSharedComputer?: boolean

}
export interface PayloadRequest {

}
export interface TeamMemberSettings {

	    /** If set to true, members can add and update channels. */
		allowCreateUpdateChannels?: boolean

	    /** If set to true, members can delete channels. */
		allowDeleteChannels?: boolean

	    /** If set to true, members can add and remove apps. */
		allowAddRemoveApps?: boolean

	    /** If set to true, members can add, update, and remove tabs. */
		allowCreateUpdateRemoveTabs?: boolean

	    /** If set to true, members can add, update, and remove connectors. */
		allowCreateUpdateRemoveConnectors?: boolean

}
export interface TeamGuestSettings {

	    /** If set to true, guests can add and update channels. */
		allowCreateUpdateChannels?: boolean

	    /** If set to true, guests can delete channels. */
		allowDeleteChannels?: boolean

}
export interface TeamMessagingSettings {

	    /** If set to true, users can edit their messages. */
		allowUserEditMessages?: boolean

	    /** If set to true, users can delete their messages. */
		allowUserDeleteMessages?: boolean

	    /** If set to true, owners can delete any message. */
		allowOwnerDeleteMessages?: boolean

	    /** If set to true, @team mentions are allowed. */
		allowTeamMentions?: boolean

	    /** If set to true, @channel mentions are allowed. */
		allowChannelMentions?: boolean

}
export interface TeamFunSettings {

	    /** If set to true, enables Giphy use. */
		allowGiphy?: boolean

	    /** Giphy content rating. Possible values are: moderate, strict. */
		giphyContentRating?: GiphyRatingType

	    /** If set to true, enables users to include stickers and memes. */
		allowStickersAndMemes?: boolean

	    /** If set to true, enables users to include custom memes. */
		allowCustomMemes?: boolean

}
export interface TeamClassSettings {

		notifyGuardiansAboutAssignments?: boolean

}
export interface ChatMessageAttachment {

		id?: string

		contentType?: string

		contentUrl?: string

		content?: string

		name?: string

		thumbnailUrl?: string

}
export interface ChatMessageMention {

		type?: ChatMessageMentionType

		id?: string

		mentionText?: string

}
export interface ChatMessageReaction {

		type?: ChatMessageReactionType

		createdDateTime?: string

		user?: IdentitySet

		content?: string

}
export interface ChatMessageBody {

		content?: string

		contentType?: ChatMessageBodyType

}
export interface OperationError {

		code?: string

		message?: string

}
export interface SynchronizationSecretKeyStringValuePair {

	    /** Possible values are: None, UserName, Password, SecretToken, AppKey, BaseAddress, ClientIdentifier, ClientSecret, SingleSignOnType, Sandbox, Url, Domain, ConsumerKey, ConsumerSecret, TokenKey, TokenExpiration, Oauth2AccessToken, Oauth2AccessTokenCreationTime, Oauth2RefreshToken, SyncAll, InstanceName, Oauth2ClientId, Oauth2ClientSecret, CompanyId, UpdateKeyOnSoftDelete, SynchronizationSchedule, SystemOfRecord, SandboxName, EnforceDomain, SyncNotificationSettings, Server, PerformInboundEntitlementGrants, HardDeletesEnabled, SyncAgentCompatibilityKey, SyncAgentADContainer, ValidateDomain, TestReferences. */
		key?: SynchronizationSecret

	    /** The value of the secret. */
		value?: string

}
export interface MetadataEntry {

	    /** Name of the metadata property. */
		key?: string

	    /** Value of the metadata property. */
		value?: string

}
export interface SynchronizationSchedule {

	    /** Date and time when this job will expire. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. */
		expiration?: string

	    /** The interval between synchronization iterations. */
		interval?: string

	    /** Possible values are: Active, Disabled. */
		state?: SynchronizationScheduleState

}
export interface SynchronizationStatus {

	    /** Number of consecutive times this job failed. */
		countSuccessiveCompleteFailures?: number

	    /** true if the job's escrows (object-level errors) were pruned during initial synchronization. Escrows can be pruned if during the initial synchronization, you reach the threshold of errors that would normally put the job in quarantine. Instead of going into quarantine, the synchronization process clears the job's errors and continues until the initial synchronization is completed. When the initial synchronization is completed, the job will pause and wait for the customer to clean up the errors. */
		escrowsPruned?: boolean

	    /** High-level status code of the synchronization job. Possible values are: NotConfigured, NotRun, Active, Paused, Quarantine. */
		code?: SynchronizationStatusCode

	    /** Details of the last execution of the job. */
		lastExecution?: SynchronizationTaskExecution

	    /** Details of the last execution of this job, which didn't have any errors. */
		lastSuccessfulExecution?: SynchronizationTaskExecution

	    /** Details of the last execution of the job, which exported objects into the target directory. */
		lastSuccessfulExecutionWithExports?: SynchronizationTaskExecution

		progress?: SynchronizationProgress[]

	    /** If job is in quarantine, quarantine details. */
		quarantine?: SynchronizationQuarantine

	    /** The time when steady state (no more changes to the process) was first achieved. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. */
		steadyStateFirstAchievedTime?: string

	    /** The time when steady state (no more changes to the process) was last achieved. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. */
		steadyStateLastAchievedTime?: string

	    /** Count of synchronized objects, listed by object type. */
		synchronizedEntryCountByType?: StringKeyLongValuePair[]

	    /** In the event of an error, the URL with the troubleshooting steps for the issue. */
		troubleshootingUrl?: string

}
export interface SynchronizationTaskExecution {

	    /** Identifier of the job run. */
		activityIdentifier?: string

	    /** Count of processed entries that were assigned for this application. */
		countEntitled?: number

	    /** Count of processed entries that were assigned for provisioning. */
		countEntitledForProvisioning?: number

	    /** Count of entries that were escrowed (errors). */
		countEscrowed?: number

	    /** Count of entries that were escrowed, including system-generated escrows. */
		countEscrowedRaw?: number

	    /** Count of exported entries. */
		countExported?: number

	    /** Count of entries that were expected to be exported. */
		countExports?: number

	    /** Count of imported entries. */
		countImported?: number

	    /** Count of imported delta-changes. */
		countImportedDeltas?: number

	    /** Count of imported delta-changes pertaining to reference changes. */
		countImportedReferenceDeltas?: number

	    /** Code summarizing the result of this run. Possible values are: Succeeded, Failed, EntryLevelErrors. */
		state?: SynchronizationTaskExecutionResult

	    /** If an error was encountered, contains a synchronizationError object with details. */
		error?: SynchronizationError

	    /** Time when this job run began. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. */
		timeBegan?: string

	    /** Time when this job run ended. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. */
		timeEnded?: string

}
export interface SynchronizationError {

		code?: string

		message?: string

		tenantActionable?: boolean

}
export interface SynchronizationProgress {

		completedUnits?: number

		progressObservationDateTime?: string

		totalUnits?: number

		units?: string

}
export interface SynchronizationQuarantine {

	    /** Date and time when the quarantine was last evaluated and imposed. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. */
		currentBegan?: string

	    /** Date and time when the next attempt to re-evaluate the quarantine will be made. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. */
		nextAttempt?: string

	    /** A code that signifies why the quarantine was imposed. Possible values are: EncounteredBaseEscrowThreshold, EncounteredTotalEscrowThreshold, EncounteredEscrowProportionThreshold, EncounteredQuarantineException, Unknown. */
		reason?: QuarantineReason

	    /** Date and time when the quarantine was first imposed in this series (a series starts when a quarantine is first imposed, and is reset as soon as the quarantine is lifted). The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. */
		seriesBegan?: string

	    /** Number of times in this series the quarantine was re-evaluated and left in effect (a series starts when quarantine is first imposed, and is reset as soon as quarantine is lifted). */
		seriesCount?: number

}
export interface StringKeyLongValuePair {

	    /** Key. */
		key?: string

	    /** Value. */
		value?: number

}
export interface SynchronizationJobRestartCriteria {

	    /** Comma-separated combination of the following values: Full, QuarantineState, Watermark, Escrows, ConnectorDataStore. Use Full if you want all of the options. */
		resetScope?: SynchronizationJobRestartScope

}
export interface DirectoryDefinition {

		id?: string

		name?: string

		objects?: ObjectDefinition[]

}
export interface ObjectDefinition {

		attributes?: AttributeDefinition[]

		metadata?: MetadataEntry[]

		name?: string

		supportedApis?: string[]

}
export interface AttributeDefinition {

	    /** true if the attribute should be used as the anchor for the object. Anchor attributes must have a unique value identifying an object, and must be immutable. Default is false. One, and only one, of the object's attributes must be designated as the anchor to support synchronization. */
		anchor?: boolean

		apiExpressions?: StringKeyStringValuePair[]

	    /** true if value of this attribute should be treated as case-sensitive. This setting affects how the synchronization engine detects changes for the attribute. */
		caseExact?: boolean

		defaultValue?: string

	    /** Additional extension properties. Unless mentioned explicitly, metadata values should not be changed. */
		metadata?: MetadataEntry[]

	    /** true if an attribute can have multiple values. Default is false. */
		multivalued?: boolean

	    /** An attribute's mutability. Possible values are:  ReadWrite, ReadOnly, Immutable, WriteOnly. Default is ReadWrite. */
		mutability?: Mutability

	    /** Name of the attribute. Must be unique within the object definition. Not nullable. */
		name?: string

	    /** true if attribute is required. Object can not be created if any of the required attributes are missing. If during synchronization, the required attribute has no value, the default value will be used. If default the value was not set, synchronization will record an error. */
		required?: boolean

	    /** For attributes with reference type, lists referenced objects (for example, the manager attribute would list User as the referenced object). */
		referencedObjects?: ReferencedObject[]

	    /** Attribute value type. Possible values are: String, Integer, Reference, Binary, Boolean. Default is String. */
		type?: AttributeType

}
export interface StringKeyStringValuePair {

	    /** Key. */
		key?: string

	    /** Value. */
		value?: string

}
export interface ReferencedObject {

	    /** Name of the referenced object. Must match one of the objects in the directory definition. */
		referencedObjectName?: string

	    /** Currently not supported. Name of the property in the referenced object, the value for which is used as the reference. */
		referencedProperty?: string

}
export interface SynchronizationRule {

	    /** true if the synchronization rule can be customized; false if this rule is read-only and should not be changed. */
		editable?: boolean

	    /** Synchronization rule identifier. Must be one of the identifiers recognized by the synchronization engine. Supported rule identifiers can be found in the synchronization template returned by the API. */
		id?: string

	    /** Additional extension properties. Unless instructed explicitly by the support team, metadata values should not be changed. */
		metadata?: StringKeyStringValuePair[]

	    /** Human-readable name of the synchronization rule. Not nullable. */
		name?: string

	    /** Collection of object mappings supported by the rule. Tells the synchronization engine which objects should be synchronized. */
		objectMappings?: ObjectMapping[]

	    /** Priority relative to other rules in the synchronizationSchema. Rules with the lowest priority number will be processed first. */
		priority?: number

	    /** Name of the source directory. Must match one of the directory definitions in synchronizationSchema. */
		sourceDirectoryName?: string

	    /** Name of the target directory. Must match one of the directory definitions in synchronizationSchema. */
		targetDirectoryName?: string

}
export interface ObjectMapping {

		attributeMappings?: AttributeMapping[]

		enabled?: boolean

		flowTypes?: ObjectFlowTypes

		metadata?: MetadataEntry[]

		name?: string

		scope?: Filter

		sourceObjectName?: string

		targetObjectName?: string

}
export interface AttributeMapping {

	    /** Default value to be used in case the source property was evaluated to null. Optional. */
		defaultValue?: string

	    /** For internal use only. */
		exportMissingReferences?: boolean

	    /** Defines when this attribute should be exported to the target directory. Possible values are: FlowWhenChanged and FlowAlways. Default is FlowWhenChanged. */
		flowBehavior?: AttributeFlowBehavior

	    /** Defines when this attribute should be updated in the target directory. Possible values are: Always (default), ObjectAddOnly (only when new object is created), MultiValueAddOnly (only when the change is adding new values to a multi-valued attribute). */
		flowType?: AttributeFlowType

	    /** If higher than 0, this attribute will be used to perform an initial match of the objects between source and target directories. The synchronization engine will try to find the matching object using attribute with lowest value of matching priority first. If not found, the attribute with the next matching priority will be used, and so on a until match is found or no more matching attributes are left. Only attributes that are expected to have unique values, such as email, should be used as matching attributes. */
		matchingPriority?: number

	    /** Defines how a value should be extracted (or transformed) from the source object. */
		source?: AttributeMappingSource

	    /** Name of the attribute on the target object. */
		targetAttributeName?: string

}
export interface AttributeMappingSource {

		expression?: string

		name?: string

		parameters?: StringKeyAttributeMappingSourceValuePair[]

		type?: AttributeMappingSourceType

}
export interface StringKeyAttributeMappingSourceValuePair {

	    /** The name of the parameter. */
		key?: string

	    /** The value of the parameter. */
		value?: AttributeMappingSource

}
export interface Filter {

	    /** Filter group set used to decide whether given object is in scope for provisioning. This is the filter which should be used in most cases. If an object used to satisfy this filter at a given moment, and then the object or the filter was changed so that filter is not satisfied any longer, such object will get de-provisioned". An object is considered in scope if ANY of the groups in the collection is evaluated to true. */
		groups?: FilterGroup[]

	    /** *Experimental* Filter group set used to filter out objects at the early stage of reading them from the directory. If an object doesn't satisfy this filter it will not be processed further. Important to understand is that if an object used to satisfy this filter at a given moment, and then the object or the filter was changed so that filter is no longer satisfied, such object will NOT get de-provisioned. An object is considered in scope if ANY of the groups in the collection is evaluated to true. */
		inputFilterGroups?: FilterGroup[]

	    /** *Experimental* Filter group set used to decide whether given object belongs and should be processed as part of this object mapping. An object is considered in scope if ANY of the groups in the collection is evaluated to true. */
		categoryFilterGroups?: FilterGroup[]

}
export interface FilterGroup {

	    /** Filter clauses (conditions) of this group. All clauses in a group must be satisfied in order for the filter group to evaluate to true. */
		clauses?: FilterClause[]

	    /** Human-readable name of the filter group. */
		name?: string

}
export interface FilterClause {

	    /** Name of the operator to be applied to the source and target operands. Must be one of the supported operators. Supported operators can be discovered. */
		operatorName?: string

	    /** Name of source operand (the operand being tested). The source operand name must match one of the attribute names on the source object. */
		sourceOperandName?: string

	    /** Values that the source operand will be tested against. */
		targetOperand?: FilterOperand

}
export interface FilterOperand {

	    /** Collection of values. */
		values?: string[]

}
export interface AttributeMappingParameterSchema {

	    /** The given parameter can be provided multiple times (for example, multiple input strings in the Concatenate(string,string,...) function). */
		allowMultipleOccurrences?: boolean

	    /** Parameter name. */
		name?: string

	    /** true if the parameter is required; otherwise false. */
		required?: boolean

	    /** Possible values are: Boolean, Binary, Reference, Integer, String. Default is String. */
		type?: AttributeType

}
export interface ExpressionInputObject {

	    /** Definition of the test object. */
		definition?: ObjectDefinition

	    /** Property values of the test object. */
		properties?: StringKeyObjectValuePair[]

}
export interface StringKeyObjectValuePair {

	    /** Key. */
		key?: string

}
export interface ParseExpressionResponse {

	    /** Error details, if expression evaluation resulted in an error. */
		error?: PublicError

	    /** true if the evaluation was successful. */
		evaluationSucceeded?: boolean

	    /** A collection of values produced by the evaluation of the expression. */
		evaluationResult?: string[]

	    /** An attributeMappingSource object representing the parsed expression. */
		parsedExpression?: AttributeMappingSource

	    /** true if the expression was parsed successfully. */
		parsingSucceeded?: boolean

}
export interface PublicError {

		code?: string

		message?: string

		target?: string

		details?: PublicErrorDetail[]

		innerError?: PublicInnerError

}
export interface PublicErrorDetail {

		code?: string

		message?: string

		target?: string

}
export interface PublicInnerError {

		code?: string

		details?: PublicErrorDetail[]

		message?: string

		target?: string

}
export interface PublicErrorResponse {

		error?: PublicError

}
export interface EducationSynchronizationDataProvider {

}
export interface EducationIdentitySynchronizationConfiguration {

}
export interface EducationSynchronizationLicenseAssignment {

		appliesTo?: EducationUserRole

		skuIds?: string[]

}
export interface EducationFileSynchronizationVerificationMessage {

	    /** Type of the message. Possible values are: error, warning, information. */
		type?: string

		fileName?: string

	    /** Detailed information about the message type. */
		description?: string

}
export interface EducationSynchronizationCustomizationsBase {

}
export interface EducationSynchronizationCustomization {

		optionalPropertiesToSync?: string[]

		synchronizationStartDate?: string

		isSyncDeferred?: boolean

		allowDisplayNameUpdate?: boolean

}
export interface EducationSynchronizationCustomizations extends EducationSynchronizationCustomizationsBase {

		school?: EducationSynchronizationCustomization

		section?: EducationSynchronizationCustomization

		student?: EducationSynchronizationCustomization

		teacher?: EducationSynchronizationCustomization

		studentEnrollment?: EducationSynchronizationCustomization

		teacherRoster?: EducationSynchronizationCustomization

}
export interface EducationPowerSchoolDataProvider extends EducationSynchronizationDataProvider {

		connectionUrl?: string

		clientId?: string

		clientSecret?: string

		schoolsIds?: string[]

		schoolYear?: string

		allowTeachersInMultipleSchools?: boolean

		customizations?: EducationSynchronizationCustomizations

}
export interface EducationCsvDataProvider extends EducationSynchronizationDataProvider {

		customizations?: EducationSynchronizationCustomizations

}
export interface EducationOneRosterApiDataProvider extends EducationSynchronizationDataProvider {

		connectionUrl?: string

		connectionSettings?: EducationSynchronizationConnectionSettings

		schoolsIds?: string[]

		providerName?: string

		customizations?: EducationSynchronizationCustomizations

}
export interface EducationSynchronizationConnectionSettings {

		clientId?: string

		clientSecret?: string

}
export interface EducationSynchronizationOAuth1ConnectionSettings extends EducationSynchronizationConnectionSettings {

}
export interface EducationSynchronizationOAuth2ClientCredentialsConnectionSettings extends EducationSynchronizationConnectionSettings {

		tokenUrl?: string

		scope?: string

}
export interface EducationIdentityMatchingConfiguration extends EducationIdentitySynchronizationConfiguration {

		matchingOptions?: EducationIdentityMatchingOptions[]

}
export interface EducationIdentityMatchingOptions {

		appliesTo?: EducationUserRole

		sourcePropertyName?: string

		targetPropertyName?: string

		targetDomain?: string

}
export interface EducationIdentityDomain {

		appliesTo?: EducationUserRole

		name?: string

}
export interface EducationIdentityCreationConfiguration extends EducationIdentitySynchronizationConfiguration {

		userDomains?: EducationIdentityDomain[]

}
export interface EducationStudent {

	    /** Year the student is graduating from the school. */
		graduationYear?: string

	    /** Current grade level of the student. */
		grade?: string

	    /** Birth date of the student. */
		birthDate?: string

	    /** Possible values are: female, male, other, unkownFutureValue. */
		gender?: EducationGender

	    /** Student Number. */
		studentNumber?: string

	    /** ID of the student in the source system. */
		externalId?: string

}
export interface EducationTeacher {

	    /** Teacher number. */
		teacherNumber?: string

	    /** ID of the teacher in the source system. */
		externalId?: string

}
export interface EducationTerm {

	    /** ID of term in the syncing system. */
		externalId?: string

	    /** Start of the term. */
		startDate?: string

	    /** End of the term. */
		endDate?: string

	    /** Display name of the term. */
		displayName?: string

}
export interface EducationItemBody {

		contentType?: BodyType

		content?: string

}
export interface EducationAssignmentGradeType {

}
export interface EducationAssignmentPointsGradeType extends EducationAssignmentGradeType {

	    /** Max points possible for this assignment. */
		maxPoints?: number

}
export interface EducationAssignmentGrade {

	    /** User who did the grading. */
		gradedBy?: IdentitySet

	    /** Moment in time when the grade was applied to this submission object. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		gradedDateTime?: string

}
export interface EducationAssignmentPointsGrade extends EducationAssignmentGrade {

	    /** Number of points a teacher is giving this submission object. */
		points?: number

}
export interface EducationAssignmentRecipient {

}
export interface EducationAssignmentClassRecipient extends EducationAssignmentRecipient {

}
export interface EducationAssignmentGroupRecipient extends EducationAssignmentRecipient {

}
export interface EducationAssignmentIndividualRecipient extends EducationAssignmentRecipient {

}
export interface EducationResource {

	    /** Display name of resource. */
		displayName?: string

	    /** The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		createdDateTime?: string

	    /** Who created the resource. */
		createdBy?: IdentitySet

	    /** Moment in time when the resource was last modified.  The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		lastModifiedDateTime?: string

	    /** Who was the last user to modify the resource. */
		lastModifiedBy?: IdentitySet

}
export interface EducationWordResource extends EducationResource {

	    /** Location of the file on disk. */
		fileUrl?: string

}
export interface EducationPowerPointResource extends EducationResource {

	    /** Location of the file on disk. */
		fileUrl?: string

}
export interface EducationExcelResource extends EducationResource {

	    /** Pointer to the Excel file object. */
		fileUrl?: string

}
export interface EducationOneNoteResource extends EducationResource {

	    /** Section name that distributions should be copied into or were copied into. */
		sectionName?: string

	    /** The Microsoft Graph URL to the page in OneNote. */
		pageUrl?: string

}
export interface EducationFileResource extends EducationResource {

	    /** Location on disk of the file resource. */
		fileUrl?: string

}
export interface EducationLinkResource extends EducationResource {

	    /** URL to the resource. */
		link?: string

}
export interface EducationSubmissionRecipient {

}
export interface EducationSubmissionIndividualRecipient extends EducationSubmissionRecipient {

	    /** User ID of the user to whom the submission is assigned. */
		userId?: string

}
export interface EducationFeedback {

	    /** Feedback. */
		text?: EducationItemBody

	    /** Moment in time when the feedback was given. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
		feedbackDateTime?: string

	    /** User who created the feedback. */
		feedbackBy?: IdentitySet

}
export interface AuditActor {

	    /** Actor Type. */
		type?: string

	    /** List of user permissions when the audit was performed. */
		userPermissions?: string[]

	    /** AAD Application Id. */
		applicationId?: string

	    /** Name of the Application. */
		applicationDisplayName?: string

	    /** User Principal Name (UPN). */
		userPrincipalName?: string

	    /** Service Principal Name (SPN). */
		servicePrincipalName?: string

	    /** IPAddress. */
		ipAddress?: string

	    /** User Id. */
		userId?: string

}
export interface AuditResource {

	    /** Display name. */
		displayName?: string

	    /** List of modified properties. */
		modifiedProperties?: AuditProperty[]

	    /** Audit resource's type. */
		type?: string

	    /** Audit resource's Id. */
		resourceId?: string

}
export interface AuditProperty {

	    /** Display name. */
		displayName?: string

	    /** Old value. */
		oldValue?: string

	    /** New value. */
		newValue?: string

}
export interface MobileAppTroubleshootingHistoryItem {

	    /** Time when the history item occurred. */
		occurrenceDateTime?: string

}
export interface MobileAppTroubleshootingDeviceCheckinHistory extends MobileAppTroubleshootingHistoryItem {

}
export interface MobileAppTroubleshootingAppUpdateHistory extends MobileAppTroubleshootingHistoryItem {

}
export interface MobileAppTroubleshootingAppStateHistory extends MobileAppTroubleshootingHistoryItem {

	    /** AAD security group id to which it was targeted. Possible values are: unknown, installCommandSent, installed, uninstalled. */
		actionType?: MobileAppActionType

	    /** Status of the item. Possible values are: unknown, success, fail. */
		runState?: RunState

	    /** Error code for the failure, empty if no failure. */
		errorCode?: string

}
export interface MobileAppTroubleshootingAppTargetHistory extends MobileAppTroubleshootingHistoryItem {

	    /** AAD security group id to which it was targeted. */
		securityGroupId?: string

	    /** Status of the item. Possible values are: unknown, success, fail. */
		runState?: RunState

	    /** Error code for the failure, empty if no failure. */
		errorCode?: string

}
export interface MobileAppTroubleshootingAppPolicyCreationHistory extends MobileAppTroubleshootingHistoryItem {

	    /** Status of the item. Possible values are: unknown, success, fail. */
		runState?: RunState

	    /** Error code for the failure, empty if no failure. */
		errorCode?: string

}
export interface MobileAppIntentAndStateDetail {

	    /** MobieApp identifier. */
		applicationId?: string

	    /** The admin provided or imported title of the app. */
		displayName?: string

	    /** Mobile App Intent. Possible values are: available, notAvailable, requiredInstall, requiredUninstall, requiredAndAvailableInstall, availableInstallWithoutEnrollment, exclude. */
		mobileAppIntent?: MobileAppIntent

	    /** Human readable version of the application */
		displayVersion?: string

	    /** The install state of the app. Possible values are: installed, failed, notInstalled, uninstallFailed, pendingInstall, unknown, notApplicable. */
		installState?: ResultantAppState

		supportedDeviceTypes?: MobileAppSupportedDeviceType[]

}
export interface MobileAppSupportedDeviceType {

		type?: DeviceType

		minimumOperatingSystemVersion?: string

		maximumOperatingSystemVersion?: string

}
export interface CaasChildError {

		code?: string

		message?: string

		target?: string

}
export interface CaasError extends CaasChildError {

		details?: CaasChildError[]

}
export interface DetectedSensitiveContentWrapper {

		classification?: DetectedSensitiveContent[]

}
export interface DetectedSensitiveContent {

		id?: string

		displayName?: string

		uniqueCount?: number

		confidence?: number

		matches?: SensitiveContentLocation[]

}
export interface SensitiveContentLocation {

		idMatch?: string

		offset?: number

		length?: number

		evidences?: SensitiveContentEvidence[]

}
export interface SensitiveContentEvidence {

		match?: string

		offset?: number

		length?: number

}
export interface AgreementFileData {

		data?: number

}
export interface CloudAppSecurityState {

		destinationServiceIp?: string

		destinationServiceName?: string

		riskScore?: string

}
export interface FileSecurityState {

		fileHash?: FileHash

	    /** File name (without path). */
		name?: string

	    /** Full file path of the file/imageFile. */
		path?: string

	    /** Provider generated/calculated risk score of the alert file. */
		riskScore?: string

}
export interface FileHash {

		hashType?: FileHashType

		hashValue?: string

}
export interface HostSecurityState {

	    /** Host FQDN (Fully Qualified Domain Name) (for example, machine.company.com). */
		fqdn?: string

		isAzureAdJoined?: boolean

		isAzureAdRegistered?: boolean

	    /** True if the host is domain joined to an on-premises Active Directory domain. */
		isHybridAzureDomainJoined?: boolean

	    /** The local host name, without the DNS domain name. */
		netBiosName?: string

		os?: string

	    /** Private (not routable) IPv4 or IPv6 address (see RFC 1918) at the time of the alert. */
		privateIpAddress?: string

	    /** Publicly routable IPv4 or IPv6 address (see RFC 1918) at time of the alert. */
		publicIpAddress?: string

	    /** Provider-generated/calculated risk score of the host. */
		riskScore?: string

}
export interface MalwareState {

		category?: string

		family?: string

	    /** STIX 2.0 standard display name for the malware. */
		name?: string

	    /** Base CVSS severity score for this malware. */
		severity?: string

		wasRunning?: boolean

}
export interface NetworkConnection {

		applicationName?: string

	    /** Destination IP address (of the network connection). */
		destinationAddress?: string

		destinationDomain?: string

	    /** Destination port (of the network connection). */
		destinationPort?: string

		destinationUrl?: string

		direction?: ConnectionDirection

		domainRegisteredDateTime?: string

		localDnsName?: string

		natDestinationAddress?: string

		natDestinationPort?: string

		natSourceAddress?: string

		natSourcePort?: string

	    /** Network protocol. Possible values are: unknown, ip, icmp, igmp, ggp, ipv4, tcp, pup, udp, idp, ipv6, ipv6RoutingHeader, ipv6FragmentHeader, ipSecEncapsulatingSecurityPayload, ipSecAuthenticationHeader, icmpV6, ipv6NoNextHeader, ipv6DestinationOptions, nd, raw, ipx, spx, spxII. */
		protocol?: SecurityNetworkProtocol

		riskScore?: string

	    /** Source (i.e. origin) IP address (of the network connection). */
		sourceAddress?: string

	    /** Source (i.e. origin) IP port (of the network connection). */
		sourcePort?: string

		status?: ConnectionStatus

		urlParameters?: string

}
export interface Process {

	    /** User account identifier (user account context the process ran under) for example, AccountName, SID, and so on. */
		accountName?: string

	    /** The full process invocation commandline including all parameters. */
		commandLine?: string

	    /** Time at which the process was started. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. */
		createdDateTime?: string

		fileHash?: FileHash

	    /** The integrity level of the process. Possible values are: unknown, untrusted, low, medium, high, system. */
		integrityLevel?: ProcessIntegrityLevel

	    /** True if the process is elevated. */
		isElevated?: boolean

	    /** The name of the process' Image file. */
		name?: string

	    /** DateTime at which the parent process was started. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. */
		parentProcessCreatedDateTime?: string

	    /** The Process ID (PID) of the parent process. */
		parentProcessId?: number

	    /** The name of the image file of the parent process. */
		parentProcessName?: string

	    /** Full path, including filename. */
		path?: string

	    /** The Process ID (PID) of the process. */
		processId?: number

}
export interface RegistryKeyState {

		hive?: RegistryHive

		key?: string

		oldKey?: string

		oldValueData?: string

		oldValueName?: string

		operation?: RegistryOperation

		processId?: number

		valueData?: string

		valueName?: string

		valueType?: RegistryValueType

}
export interface AlertTrigger {

	    /** Name of the property serving as a detection trigger. */
		name?: string

	    /** Type of the property in the key:value pair for interpretation. For example, String, Boolean, and so on. */
		type?: string

	    /** Value of the property serving as a detection trigger. */
		value?: string

}
export interface UserSecurityState {

		aadUserId?: string

	    /** Account name of user account (without Active Directory domain or DNS domain) - (also called mailNickName). */
		accountName?: string

	    /** NetBIOS/Active Directory domain of user account (that is, domain\account format). */
		domainName?: string

		emailRole?: EmailRole

		isVpn?: boolean

	    /** Time at which the sign in occurred. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. */
		logonDateTime?: string

	    /** User sign-in ID. */
		logonId?: string

		logonIp?: string

	    /** Location (by IP address mapping) associated with a user sign-in event by this user. */
		logonLocation?: string

	    /** Method of user signin. Possible values are: unknown, interactive, remoteInteractive, network, batch, service. */
		logonType?: LogonType

	    /** Active Directory (on-premises) Security Identifier (SID) of the user. */
		onPremisesSecurityIdentifier?: string

	    /** Provider-generated/calculated risk score of the user account. */
		riskScore?: string

	    /** User account type (group membership), per Windows definition. Possible values are: unknown, standard, power, administrator. */
		userAccountType?: UserAccountSecurityType

	    /** User sign-in name - internet format: (user account name)@(user account DNS domain name). */
		userPrincipalName?: string

}
export interface SecurityVendorInformation {

	    /** Specific provider (product/service - not vendor company); for example, WindowsDefenderATP. */
		provider?: string

	    /** Version of the provider or subprovider, if it exists, that generated the alert. */
		providerVersion?: string

	    /** Specific subprovider (under aggregating provider); for example, WindowsDefenderATP.SmartScreen. */
		subProvider?: string

	    /** Name of the alert vendor (for example, Microsoft, Dell, FireEye). */
		vendor?: string

}
export interface VulnerabilityState {

	    /** Common Vulnerabilities and Exposures (CVE) for the vulnerability. */
		cve?: string

	    /** Base Common Vulnerability Scoring System (CVSS) severity score for this vulnerability. */
		severity?: string

		wasRunning?: boolean

}
export interface ReputationCategory {

		description?: string

		name?: string

		vendor?: string

}
export interface DomainRegistrant {

		countryOrRegionCode?: string

		organization?: string

		url?: string

		vendor?: string

}
export interface LogonUser {

	    /** Domain of user account used to logon. */
		accountDomain?: string

	    /** Account name of user account used to logon. */
		accountName?: string

	    /** User Account type, per Windows definition. Possible values are: unknown, standard, power, administrator. */
		accountType?: UserAccountSecurityType

	    /** DateTime at which the earliest logon by this user account occurred (provider-determined period). The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. */
		firstSeenDateTime?: string

	    /** DateTime at which the latest logon by this user account occurred. The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. */
		lastSeenDateTime?: string

	    /** User logon ID. */
		logonId?: string

	    /** Collection of the logon types observed for the logged on user from when first to last seen. Possible values are: unknown, interactive, remoteInteractive, network, batch, service. */
		logonTypes?: LogonType[]

}
export interface NetworkInterface {

	    /** Description of the NIC (e.g. Ethernet adapter, Wireless LAN adapter Local Area Connection <#>, etc.). */
		description?: string

	    /** Last IPv4 address associated with this NIC. */
		ipV4Address?: string

	    /** Last Public (aka global) IPv6 address associated with this NIC. */
		ipV6Address?: string

	    /** Last local (link-local or site-local) IPv6 address associated with this NIC. */
		localIpV6Address?: string

	    /** MAC address of the NIC on this host. */
		macAddress?: string

}
export interface IpCategory {

		description?: string

		name?: string

		vendor?: string

}
export interface IpReferenceData {

		asn?: number

		city?: string

		countryOrRegionCode?: string

		organization?: string

		state?: string

		vendor?: string

}
export interface AverageComparativeScore {

		averageScore?: number

		basis?: string

}
export interface ControlScore {

		controlCategory?: string

		description?: string

		score?: number

		controlName?: string

}
export interface SecureScoreControlStateUpdate {

		assignedTo?: string

		comment?: string

		state?: string

		updatedBy?: string

		updatedDateTime?: string

}
export interface CertificateObservable {

		issuer?: number

		publicKey?: string

		subject?: string

		thumbprint?: string

}
export interface EmailObservable {

		encoding?: string

		language?: string

		recipient?: string

		senderAddress?: string

		senderName?: string

		sourceDomain?: string

		sourceIPAddress?: string

		subject?: string

		xmailer?: string

}
export interface FileObservable {

		compileDateTime?: string

		createdDateTime?: string

		hash?: FileHash

		mutexName?: string

		packer?: string

		path?: string

		size?: number

		type?: string

}
export interface HostObservable {

		hostGuid?: string

		hostName?: string

		registryKey?: string

		registryValue?: string

		systemCommandLine?: string

		systemServiceName?: string

}
export interface IdentityObservable {

		identityIndividualName?: string

		password?: string

		username?: string

}
export interface NetworkObservable {

		destinatioIPv6?: string

		destinationAsn?: number

		destinationCidrBlock?: string

		destinationIPv4?: string

		destinationPort?: string

		dnsDomainName?: string

		dnsDomainLookupDateTime?: string

		dnsRegistrantEmail?: string

		dnsRegistrantName?: string

		nameServer?: string

		protocol?: SecurityNetworkProtocol

		sourceAsn?: number

		sourceCidrBlock?: string

		sourceIPv4?: string

		sourceIPv6?: string

		sourcePort?: string

		url?: string

		userAgent?: string

}
export interface AccountAlias {

		id?: string

		idType?: string

}
export interface EntitySetNames {

}
export interface BookingReminder {

	    /** The amount of time before the start of an appointment that the reminder should be sent. It's denoted in ISO 8601 format. */
		offset?: string

	    /** The persons who shouold receive the reminder. Possible values are: allAttendees, staff, customer. */
		recipients?: BookingReminderRecipients

	    /** The message in the reminder. */
		message?: string

}
export interface BookingWorkHours {

	    /** The day of the week represented by this instance. Possible values are: sunday, monday, tuesday, wednesday, thursday, friday, saturday. */
		day?: DayOfWeek

	    /** A list of start/end times during a day. */
		timeSlots?: BookingWorkTimeSlot[]

}
export interface BookingWorkTimeSlot {

	    /** The time of the day that work stops. For example, 17:00:00.0000000. */
		start?: string

	    /** The time of the day that work starts. For example, 08:00:00.0000000. */
		end?: string

}
export interface BookingSchedulingPolicy {

	    /** Duration of each time slot, denoted in ISO 8601 format. */
		timeSlotInterval?: string

	    /** The minimum amount of time before which bookings and cancellations must be made. It follows the ISO 8601 format. */
		minimumLeadTime?: string

	    /** Maximum number of days in advance that a booking can be made. It follows the ISO 8601 format. */
		maximumAdvance?: string

	    /** True to notify the business via email when a booking is created or changed. Use the email address specified in the email property of the bookingBusiness entity for the business. */
		sendConfirmationsToOwner?: boolean

	    /** True if to allow customers to choose a specific person for the booking. */
		allowStaffSelection?: boolean

}
export interface GovernancePermission {

		accessLevel?: string

		isActive?: boolean

		isEligible?: boolean

}
export interface GovernanceRoleAssignmentRequestStatus {

		status?: string

		subStatus?: string

		statusDetails?: KeyValue[]

}
export interface GovernanceSchedule {

		type?: string

		startDateTime?: string

		endDateTime?: string

		duration?: string

}
export interface GovernanceRuleSetting {

		ruleIdentifier?: string

		setting?: string

}
export interface AccessReviewSettings {

		mailNotificationsEnabled?: boolean

		remindersEnabled?: boolean

		justificationRequiredOnApproval?: boolean

		recurrenceSettings?: AccessReviewRecurrenceSettings

		autoReviewEnabled?: boolean

		activityDurationInDays?: number

		autoReviewSettings?: AutoReviewSettings

		autoApplyReviewResultsEnabled?: boolean

		accessRecommendationsEnabled?: boolean

}
export interface AccessReviewRecurrenceSettings {

		recurrenceType?: string

		recurrenceEndType?: string

		durationInDays?: number

		recurrenceCount?: number

}
export interface AutoReviewSettings {

		notReviewedResult?: string

}
export interface ProgramResource extends Identity {

		type?: string

}
export interface PayloadTypes {

		rawContent?: string

		visualContent?: VisualProperties

}
export interface VisualProperties {

		title?: string

		body?: string

}
export interface TargetPolicyEndpoints {

		platformTypes?: string[]

}
