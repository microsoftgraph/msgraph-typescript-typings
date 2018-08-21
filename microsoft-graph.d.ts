// Type definitions for the Microsoft Graph API
// Project: https://github.com/microsoftgraph/msgraph-typescript-typings
// Definitions by: Microsoft Graph Team <https://github.com/microsoftgraph>

//
// Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
//


export as namespace microsoftgraphbeta;

export type Status = "active" | "updated" | "deleted" | "ignored"
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
export type RiskEventStatus = "active" | "remediated" | "dismissedAsFixed" | "dismissedAsFalsePositive" | "dismissedAsIgnore" | "loginBlocked" | "closedMfaAuto" | "closedMultipleReasons"
export type RiskLevel = "low" | "medium" | "high"
export type UserRiskLevel = "unknown" | "none" | "low" | "medium" | "high"
export type ApprovalState = "pending" | "approved" | "denied" | "aborted" | "canceled"
export type RoleSummaryStatus = "ok" | "bad"
export type SetupStatus = "unknown" | "notRegisteredYet" | "registeredSetupNotStarted" | "registeredSetupInProgress" | "registrationAndSetupCompleted" | "registrationFailed" | "registrationTimedOut" | "disabled"
export type AndroidForWorkBindStatus = "notBound" | "bound" | "boundAndValidated" | "unbinding"
export type AndroidForWorkSyncStatus = "success" | "credentialsNotValid" | "androidForWorkApiError" | "managementServiceError" | "unknownError" | "none"
export type AndroidForWorkEnrollmentTarget = "none" | "all" | "targeted" | "targetedAsEnrollmentRestrictions"
export type AndroidForWorkAppConfigurationSchemaItemDataType = "bool" | "integer" | "string" | "choice" | "multiselect" | "bundle" | "bundleArray" | "hidden"
export type InstallIntent = "available" | "required" | "uninstall" | "availableWithoutEnrollment"
export type MobileAppPublishingState = "notPublished" | "processing" | "published"
export type ResultantAppState = "installed" | "failed" | "notInstalled" | "uninstallFailed" | "pendingInstall" | "unknown" | "notApplicable"
export type OfficeProductId = "o365ProPlusRetail" | "o365BusinessRetail" | "visioProRetail" | "projectProRetail"
export type OfficeUpdateChannel = "none" | "current" | "deferred" | "firstReleaseCurrent" | "firstReleaseDeferred"
export type WindowsArchitecture = "none" | "x86" | "x64" | "arm" | "neutral"
export type OfficeSuiteInstallProgressDisplayLevel = "none" | "full"
export type ManagedAppAvailability = "global" | "lineOfBusiness"
export type MobileAppContentFileUploadState = "success" | "transientError" | "error" | "unknown" | "azureStorageUriRequestSuccess" | "azureStorageUriRequestPending" | "azureStorageUriRequestFailed" | "azureStorageUriRequestTimedOut" | "azureStorageUriRenewalSuccess" | "azureStorageUriRenewalPending" | "azureStorageUriRenewalFailed" | "azureStorageUriRenewalTimedOut" | "commitFileSuccess" | "commitFilePending" | "commitFileFailed" | "commitFileTimedOut"
export type WindowsDeviceType = "none" | "desktop" | "mobile" | "holographic" | "team"
export type MicrosoftStoreForBusinessLicenseType = "offline" | "online"
export type VolumePurchaseProgramTokenAccountType = "business" | "education"
export type VolumePurchaseProgramTokenState = "unknown" | "valid" | "expired" | "invalid"
export type VolumePurchaseProgramTokenSyncStatus = "none" | "inProgress" | "completed" | "failed"
export type VppTokenAccountType = "business" | "education"
export type CertificateStatus = "notProvisioned" | "provisioned"
export type ComplianceStatus = "unknown" | "notApplicable" | "compliant" | "remediated" | "nonCompliant" | "error" | "conflict"
export type AndroidPermissionActionType = "prompt" | "autoGrant" | "autoDeny"
export type MdmAppConfigKeyType = "stringType" | "integerType" | "realType" | "booleanType" | "tokenType"
export type ITunesPairingMode = "disallow" | "allow" | "requiresCertificate"
export type ImportedDeviceIdentityType = "unknown" | "imei" | "serialNumber"
export type EnrollmentState = "unknown" | "enrolled" | "pendingReset" | "failed" | "notContacted"
export type Platform = "unknown" | "ios" | "android" | "windows" | "windowsMobile" | "macOS"
export type DiscoverySource = "unknown" | "adminImport" | "deviceEnrollmentProgram"
export type ManagedDeviceRemoteAction = "retire" | "delete" | "fullScan" | "quickScan" | "signatureUpdate"
export type RemoteAction = "unknown" | "factoryReset" | "removeCompanyData" | "resetPasscode" | "remoteLock" | "enableLostMode" | "disableLostMode" | "locateDevice" | "rebootNow" | "recoverPasscode" | "cleanWindowsDevice" | "logoutSharedAppleDeviceActiveUser" | "quickScan" | "fullScan" | "windowsDefenderUpdateSignatures" | "factoryResetKeepEnrollmentData" | "updateDeviceAccount" | "automaticRedeployment" | "shutDown"
export type ActionState = "none" | "pending" | "canceled" | "active" | "done" | "failed" | "notSupported"
export type RunAsAccountType = "system" | "user"
export type RunState = "unknown" | "success" | "fail"
export type DeviceGuardVirtualizationBasedSecurityHardwareRequirementState = "meetHardwareRequirements" | "secureBootRequired" | "dmaProtectionRequired" | "hyperVNotSupportedForGuestVM" | "hyperVNotAvailable"
export type DeviceGuardVirtualizationBasedSecurityState = "running" | "rebootRequired" | "require64BitArchitecture" | "notLicensed" | "notConfigured" | "doesNotMeetHardwareRequirements" | "other"
export type DeviceGuardLocalSystemAuthorityCredentialGuardState = "running" | "rebootRequired" | "notLicensed" | "notConfigured" | "virtualizationBasedSecurityNotRunning"
export type OwnerType = "unknown" | "company" | "personal"
export type ManagementState = "managed" | "retirePending" | "retireFailed" | "wipePending" | "wipeFailed" | "unhealthy" | "deletePending" | "retireIssued" | "wipeIssued" | "wipeCanceled" | "retireCanceled" | "discovered"
export type ChassisType = "unknown" | "desktop" | "laptop" | "worksWorkstation" | "enterpriseServer" | "phone" | "tablet" | "mobileOther" | "mobileUnknown"
export type DeviceType = "desktop" | "windowsRT" | "winMO6" | "nokia" | "windowsPhone" | "mac" | "winCE" | "winEmbedded" | "iPhone" | "iPad" | "iPod" | "android" | "iSocConsumer" | "unix" | "macMDM" | "holoLens" | "surfaceHub" | "androidForWork" | "androidEnterprise" | "blackberry" | "palm" | "unknown"
export type ComplianceState = "unknown" | "compliant" | "noncompliant" | "conflict" | "error" | "inGracePeriod" | "configManager"
export type ManagementAgentType = "eas" | "mdm" | "easMdm" | "intuneClient" | "easIntuneClient" | "configurationManagerClient" | "configurationManagerClientMdm" | "configurationManagerClientMdmEas" | "unknown" | "jamf" | "googleCloudDevicePolicyController"
export type DeviceEnrollmentType = "unknown" | "userEnrollment" | "deviceEnrollmentManager" | "appleBulkWithUser" | "appleBulkWithoutUser" | "windowsAzureADJoin" | "windowsBulkUserless" | "windowsAutoEnrollment" | "windowsBulkAzureDomainJoin" | "windowsCoManagement"
export type LostModeState = "disabled" | "enabled"
export type DeviceRegistrationState = "notRegistered" | "registered" | "revoked" | "keyConflict" | "approvalPending" | "certificateReset" | "notRegisteredPendingEnrollment" | "unknown"
export type DeviceManagementExchangeAccessState = "none" | "unknown" | "allowed" | "blocked" | "quarantined"
export type DeviceManagementExchangeAccessStateReason = "none" | "unknown" | "exchangeGlobalRule" | "exchangeIndividualRule" | "exchangeDeviceRule" | "exchangeUpgrade" | "exchangeMailboxPolicy" | "other" | "compliant" | "notCompliant" | "notEnrolled" | "unknownLocation" | "mfaRequired" | "azureADBlockDueToAccessPolicy" | "compromisedPassword" | "deviceNotKnownWithManagedApp"
export type WindowsDeviceHealthState = "clean" | "fullScanPending" | "rebootPending" | "manualStepsPending" | "offlineScanPending" | "critical"
export type WindowsMalwareSeverity = "unknown" | "low" | "moderate" | "high" | "severe"
export type WindowsMalwareCategory = "invalid" | "adware" | "spyware" | "passwordStealer" | "trojanDownloader" | "worm" | "backdoor" | "remoteAccessTrojan" | "trojan" | "emailFlooder" | "keylogger" | "dialer" | "monitoringSoftware" | "browserModifier" | "cookie" | "browserPlugin" | "aolExploit" | "nuker" | "securityDisabler" | "jokeProgram" | "hostileActiveXControl" | "softwareBundler" | "stealthNotifier" | "settingsModifier" | "toolBar" | "remoteControlSoftware" | "trojanFtp" | "potentialUnwantedSoftware" | "icqExploit" | "trojanTelnet" | "exploit" | "filesharingProgram" | "malwareCreationTool" | "remote_Control_Software" | "tool" | "trojanDenialOfService" | "trojanDropper" | "trojanMassMailer" | "trojanMonitoringSoftware" | "trojanProxyServer" | "virus" | "known" | "unknown" | "spp" | "behavior" | "vulnerability" | "policy"
export type WindowsMalwareExecutionState = "unknown" | "blocked" | "allowed" | "running" | "notRunning"
export type WindowsMalwareState = "unknown" | "detected" | "cleaned" | "quarantined" | "removed" | "allowed" | "blocked" | "cleanFailed" | "quarantineFailed" | "removeFailed" | "allowFailed" | "abandoned" | "blockFailed"
export type ManagedDevicePartnerReportedHealthState = "unknown" | "activated" | "deactivated" | "secured" | "lowSeverity" | "mediumSeverity" | "highSeverity" | "unresponsive"
export type DeviceManagementSubscriptionState = "pending" | "active" | "warning" | "disabled" | "deleted" | "blocked" | "lockedOut"
export type DeviceManagementSubscriptions = "none" | "intune" | "office365" | "intunePremium" | "intune_EDU" | "intune_SMB"
export type AdminConsentState = "notConfigured" | "granted" | "notGranted"
export type HealthState = "unknown" | "healthy" | "unhealthy"
export type EasAuthenticationMethod = "usernameAndPassword" | "certificate"
export type EmailSyncDuration = "userDefined" | "oneDay" | "threeDays" | "oneWeek" | "twoWeeks" | "oneMonth" | "unlimited"
export type UserEmailSource = "userPrincipalName" | "primarySmtpAddress"
export type SubjectNameFormat = "commonName" | "commonNameIncludingEmail" | "commonNameAsEmail" | "custom" | "commonNameAsIMEI" | "commonNameAsSerialNumber"
export type SubjectAlternativeNameType = "emailAddress" | "userPrincipalName" | "customAzureADAttribute"
export type CertificateValidityPeriodScale = "days" | "months" | "years"
export type KeyUsages = "keyEncipherment" | "digitalSignature"
export type KeySize = "size1024" | "size2048"
export type HashAlgorithms = "sha1" | "sha2"
export type DevicePlatformType = "android" | "androidForWork" | "iOS" | "macOS" | "windowsPhone81" | "windows81AndLater" | "windows10AndLater"
export type AndroidUsernameSource = "username" | "userPrincipalName"
export type EmailSyncSchedule = "userDefined" | "asMessagesArrive" | "manual" | "fifteenMinutes" | "thirtyMinutes" | "sixtyMinutes" | "basedOnMyUsage"
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
export type AppleSubjectNameFormat = "commonName" | "commonNameAsEmail" | "custom" | "commonNameIncludingEmail" | "commonNameAsIMEI" | "commonNameAsSerialNumber"
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
export type WiFiSecurityType = "open" | "wpaPersonal" | "wpaEnterprise" | "wep"
export type WiFiProxySetting = "none" | "manual" | "automatic"
export type EapType = "eapTls" | "leap" | "eapSim" | "eapTtls" | "peap" | "eapFast"
export type EapFastConfiguration = "noProtectedAccessCredential" | "useProtectedAccessCredential" | "useProtectedAccessCredentialAndProvision" | "useProtectedAccessCredentialAndProvisionAnonymously"
export type IosNotificationAlertType = "deviceDefault" | "banner" | "modal" | "none"
export type AppleVpnConnectionType = "ciscoAnyConnect" | "pulseSecure" | "f5EdgeClient" | "dellSonicWallMobileConnect" | "checkPointCapsuleVpn" | "customVpn" | "ciscoIPSec" | "citrix"
export type VpnOnDemandRuleConnectionAction = "connect" | "evaluateConnection" | "ignore" | "disconnect"
export type VpnOnDemandRuleConnectionDomainAction = "connectIfNeeded" | "neverConnect"
export type DefenderSecurityCenterNotificationsFromAppType = "notConfigured" | "blockNoncriticalNotifications" | "blockAllNotifications"
export type DefenderSecurityCenterITContactDisplayType = "notConfigured" | "displayInAppAndInNotifications" | "displayOnlyInApp" | "displayOnlyInNotifications"
export type FirewallPreSharedKeyEncodingMethodType = "deviceDefault" | "none" | "utF8"
export type FirewallCertificateRevocationListCheckMethodType = "deviceDefault" | "none" | "attempt" | "require"
export type FirewallPacketQueueingMethodType = "deviceDefault" | "disabled" | "queueInbound" | "queueOutbound" | "queueBoth"
export type StateManagementSetting = "notConfigured" | "blocked" | "allowed"
export type DefenderAttackSurfaceType = "userDefined" | "block" | "auditMode"
export type DefenderProtectionType = "userDefined" | "enable" | "auditMode"
export type FolderProtectionType = "userDefined" | "enable" | "auditMode" | "blockDiskModification" | "auditDiskModification"
export type AppLockerApplicationControlType = "notConfigured" | "enforceComponentsAndStoreApps" | "auditComponentsAndStoreApps" | "enforceComponentsStoreAppsAndSmartlocker" | "auditComponentsStoreAppsAndSmartlocker"
export type ApplicationGuardBlockFileTransferType = "notConfigured" | "blockImageAndTextFile" | "blockImageFile" | "blockNone" | "blockTextFile"
export type ApplicationGuardBlockClipboardSharingType = "notConfigured" | "blockBoth" | "blockHostToContainer" | "blockContainerToHost" | "blockNone"
export type BitLockerEncryptionMethod = "aesCbc128" | "aesCbc256" | "xtsAes128" | "xtsAes256"
export type ConfigurationUsage = "blocked" | "required" | "allowed"
export type BitLockerRecoveryinformationType = "passwordAndKey" | "passwordOnly"
export type SignInAssistantOptions = "notConfigured" | "disabled"
export type DiagnosticDataSubmissionMode = "userDefined" | "none" | "basic" | "enhanced" | "full"
export type InkAccessSetting = "notConfigured" | "enabled" | "disabled"
export type EdgeCookiePolicy = "userDefined" | "allow" | "blockThirdParty" | "blockAll"
export type DefenderThreatAction = "deviceDefault" | "clean" | "quarantine" | "remove" | "allow" | "userDefined" | "block"
export type WeeklySchedule = "userDefined" | "everyday" | "sunday" | "monday" | "tuesday" | "wednesday" | "thursday" | "friday" | "saturday"
export type DefenderMonitorFileActivity = "userDefined" | "disable" | "monitorAllFiles" | "monitorIncomingFilesOnly" | "monitorOutgoingFilesOnly"
export type DefenderPotentiallyUnwantedAppAction = "deviceDefault" | "block" | "audit"
export type DefenderPromptForSampleSubmission = "userDefined" | "alwaysPrompt" | "promptBeforeSendingPersonalData" | "neverSendData" | "sendAllDataWithoutPrompting"
export type DefenderScanType = "userDefined" | "disabled" | "quick" | "full"
export type DefenderCloudBlockLevelType = "notConfigured" | "high" | "highPlus" | "zeroTolerance"
export type WindowsPrivacyDataAccessLevel = "notConfigured" | "forceAllow" | "forceDeny" | "userInControl"
export type WindowsPrivacyDataCategory = "notConfigured" | "accountInfo" | "appsRunInBackground" | "calendar" | "callHistory" | "camera" | "contacts" | "diagnosticsInfo" | "email" | "location" | "messaging" | "microphone" | "motion" | "notifications" | "phone" | "radios" | "tasks" | "syncWithDevices" | "trustedDevices"
export type WindowsStartMenuAppListVisibilityType = "userDefined" | "collapse" | "remove" | "disableSettingsApp"
export type WindowsStartMenuModeType = "userDefined" | "fullScreen" | "nonFullScreen"
export type VisibilitySetting = "notConfigured" | "hide" | "show"
export type WindowsSpotlightEnablementSettings = "notConfigured" | "disabled" | "enabled"
export type AutomaticUpdateMode = "userDefined" | "notifyDownload" | "autoInstallAtMaintenanceTime" | "autoInstallAndRebootAtMaintenanceTime" | "autoInstallAndRebootAtScheduledTime" | "autoInstallAndRebootWithoutEndUserControl"
export type SafeSearchFilterType = "userDefined" | "strict" | "moderate"
export type EdgeSearchEngineType = "default" | "bing"
export type PrereleaseFeatures = "userDefined" | "settingsOnly" | "settingsAndExperimentations" | "notAllowed"
export type SharedPCAccountDeletionPolicyType = "immediate" | "diskSpaceThreshold" | "diskSpaceThresholdOrInactiveThreshold"
export type SharedPCAllowedAccountType = "guest" | "domain"
export type KeyStorageProviderOption = "useTpmKspOtherwiseUseSoftwareKsp" | "useTpmKspOtherwiseFail" | "usePassportForWorkKspOtherwiseFail" | "useSoftwareKsp"
export type SecureAssessmentAccountType = "azureADAccount" | "domainAccount" | "localAccount"
export type CertificateDestinationStore = "computerCertStoreRoot" | "computerCertStoreIntermediate" | "userCertStoreIntermediate"
export type WindowsDeliveryOptimizationMode = "userDefined" | "httpOnly" | "httpWithPeeringNat" | "httpWithPeeringPrivateGroup" | "httpWithInternetPeering" | "simpleDownload" | "bypassMode"
export type WindowsUpdateRestartMode = "userDefined" | "batteryLevelCheckEnabled" | "batteryLevelCheckDisabled"
export type WindowsUpdateType = "userDefined" | "all" | "businessReadyOnly" | "windowsInsiderBuildFast" | "windowsInsiderBuildSlow" | "windowsInsiderBuildRelease"
export type WindowsUpdateInsiderBuildControl = "userDefined" | "allowed" | "notAllowed"
export type Windows10VpnConnectionType = "pulseSecure" | "f5EdgeClient" | "dellSonicWallMobileConnect" | "checkPointCapsuleVpn" | "automatic" | "ikEv2" | "l2tp" | "pptp" | "citrix"
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
export type EditionUpgradeLicenseType = "productKey" | "licenseFile"
export type Windows10EditionType = "windows10Enterprise" | "windows10EnterpriseN" | "windows10Education" | "windows10EducationN" | "windows10MobileEnterprise" | "windows10HolographicEnterprise" | "windows10Professional" | "windows10ProfessionalN" | "windows10ProfessionalEducation" | "windows10ProfessionalEducationN" | "windows10ProfessionalWorkstation" | "windows10ProfessionalWorkstationN"
export type DeviceComplianceActionType = "noAction" | "notification" | "block" | "retire" | "wipe" | "removeResourceAccessProfiles"
export type DeviceThreatProtectionLevel = "unavailable" | "secured" | "low" | "medium" | "high" | "notSet"
export type PolicyPlatformType = "android" | "androidForWork" | "iOS" | "macOS" | "windowsPhone81" | "windows81AndLater" | "windows10AndLater" | "all"
export type IosUpdatesInstallStatus = "success" | "available" | "idle" | "downloading" | "downloadFailed" | "downloadRequiresComputer" | "downloadInsufficientSpace" | "downloadInsufficientPower" | "downloadInsufficientNetwork" | "installing" | "installInsufficientSpace" | "installInsufficientPower" | "installPhoneCallInProgress" | "installFailed" | "notSupportedOperation" | "sharedDeviceUserLoggedInError"
export type NdesConnectorState = "none" | "active" | "inactive"
export type DeviceManagementExchangeConnectorSyncType = "fullSync" | "deltaSync"
export type MdmAuthority = "unknown" | "intune" | "sccm" | "office365"
export type WindowsHelloForBusinessPinUsage = "allowed" | "required" | "disallowed"
export type Enablement = "notConfigured" | "enabled" | "disabled"
export type VppTokenState = "unknown" | "valid" | "expired" | "invalid"
export type VppTokenActionFailureReason = "none" | "appleFailure" | "internalError" | "expiredVppToken" | "expiredApplePushNotificationCertificate"
export type VppTokenSyncStatus = "none" | "inProgress" | "completed" | "failed"
export type DeviceManagementExchangeConnectorStatus = "none" | "connectionPending" | "connected" | "disconnected"
export type DeviceManagementExchangeConnectorType = "onPremises" | "hosted" | "serviceToService" | "dedicated"
export type DeviceManagementExchangeAccessLevel = "none" | "allow" | "block" | "quarantine"
export type DeviceManagementExchangeAccessRuleType = "family" | "model"
export type MobileThreatPartnerTenantState = "unavailable" | "available" | "enabled" | "unresponsive"
export type DeviceManagementPartnerTenantState = "unknown" | "unavailable" | "enabled" | "terminated" | "rejected" | "unresponsive"
export type DeviceManagementPartnerAppType = "unknown" | "singleTenantApp" | "multiTenantApp"
export type ManagedAppDataTransferLevel = "allApps" | "managedApps" | "none"
export type ManagedAppClipboardSharingLevel = "allApps" | "managedAppsWithPasteIn" | "managedApps" | "blocked"
export type ManagedAppPinCharacterSet = "numeric" | "alphanumericAndSymbol"
export type ManagedAppDataStorageLocation = "oneDriveForBusiness" | "sharePoint" | "localStorage"
export type ManagedAppDataEncryptionType = "useDeviceSettings" | "afterDeviceRestart" | "whenDeviceLockedExceptOpenFiles" | "whenDeviceLocked"
export type AppManagementLevel = "unspecified" | "unmanaged" | "mdm" | "androidEnterprise"
export type WindowsInformationProtectionEnforcementLevel = "noProtection" | "encryptAndAuditOnly" | "encryptAuditAndPrompt" | "encryptAuditAndBlock"
export type WindowsInformationProtectionPinCharacterRequirements = "notAllow" | "requireAtLeastOne" | "allow"
export type ManagedAppFlaggedReason = "none" | "rootedDevice"
export type NotificationTemplateBrandingOptions = "none" | "includeCompanyLogo" | "includeCompanyName" | "includeContactInformation"
export type InstallState = "notApplicable" | "installed" | "failed" | "notInstalled" | "uninstallFailed" | "unknown"
export type WindowsAutopilotSyncStatus = "unknown" | "inProgress" | "completed" | "failed"
export type WindowsUserType = "administrator" | "standard"
export type WindowsDeviceUsageType = "singleUser" | "shared"
export type WindowsAutopilotProfileAssignmentStatus = "unknown" | "assignedInSync" | "assignedOutOfSync" | "assignedUnkownSyncState" | "notAssigned" | "pending" | "failed"
export type DepTokenType = "none" | "dep" | "appleSchoolManager"
export type ImportedWindowsAutopilotDeviceIdentityImportStatus = "unknown" | "pending" | "partial" | "complete" | "error"
export type RemoteAssistanceOnboardingStatus = "notOnboarded" | "onboarding" | "onboarded"
export type ApplicationType = "universal" | "desktop"
export type GiphyRatingType = "moderate" | "strict"
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
export type EducationSubmissionStatus = "working" | "submitted" | "completed" | "unknownFutureValue"
export type DeviceEnrollmentFailureReason = "unknown" | "authentication" | "authorization" | "accountValidation" | "userValidation" | "deviceNotSupported" | "inMaintenance" | "badRequest" | "featureNotSupported" | "enrollmentRestrictionsEnforced" | "clientDisconnected"

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

	    /** The licenses that are assigned to the user. Not nullable. */
	    assignedLicenses?: AssignedLicense[]

	    /** The plans that are assigned to the user. Read-only. Not nullable. */
	    assignedPlans?: AssignedPlan[]

	    /** The telephone numbers for the user. NOTE: Although this is a string collection, only one number can be set for this property. */
	    businessPhones?: string[]

	    /** The city in which the user is located. Supports $filter. */
	    city?: string

	    /** The company name which the user is associated. Read-only. */
	    companyName?: string

	    /** The country/region in which the user is located; for example, “US” or “UK”. Supports $filter. */
	    country?: string

	    /** The name for the department in which the user works. Supports $filter. */
	    department?: string

	    deviceKeys?: DeviceKey[]

	    /** The name displayed in the address book for the user. This is usually the combination of the user's first name, middle initial and last name. This property is required when a user is created and it cannot be cleared during updates. Supports $filter and $orderby. */
	    displayName?: string

	    employeeId?: string

	    /** The given name (first name) of the user. Supports $filter. */
	    givenName?: string

	    imAddresses?: string[]

	    /** The user’s job title. Supports $filter. */
	    jobTitle?: string

	    /** The SMTP address for the user, for example, "jeff@contoso.onmicrosoft.com". Read-Only. Supports $filter. */
	    mail?: string

	    /** The mail alias for the user. This property must be specified when a user is created. Supports $filter. */
	    mailNickname?: string

	    /** The primary cellular telephone number for the user. */
	    mobilePhone?: string

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

	    /** Settings for the primary mailbox of the signed-in user. You can get or update settings for sending automatic replies to incoming messages, locale and time zone. */
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

	    /** The limit on the maximum number of devices that the user is permitted to enroll. Allowed values are 5 or 1000. */
	    deviceEnrollmentLimit?: number

	    /** The collection of open extensions defined for the user. Read-only. Nullable. */
	    extensions?: Extension[]

	    /** Devices that are owned by the user. Read-only. Nullable. */
	    ownedDevices?: DirectoryObject[]

	    /** Devices that are registered for the user. Read-only. Nullable. */
	    registeredDevices?: DirectoryObject[]

	    /** The user or contact that is this user’s manager. Read-only. (HTTP Methods: GET, PUT, DELETE.) */
	    manager?: DirectoryObject

	    /** The users and contacts that report to the user. (The users and contacts that have their manager property set to this user.) Read-only. Nullable. */
	    directReports?: DirectoryObject[]

	    /** The groups and directory roles that the user is a member of. Read-only. Nullable. */
	    memberOf?: DirectoryObject[]

	    /** Directory objects that were created by the user. Read-only. Nullable. */
	    createdObjects?: DirectoryObject[]

	    /** Directory objects that are owned by the user. Read-only. Nullable. */
	    ownedObjects?: DirectoryObject[]

	    scopedRoleMemberOf?: ScopedRoleMembership[]

	    licenseDetails?: LicenseDetails[]

	    activities?: Activity[]

	    outlook?: OutlookUser

	    /** The messages in a mailbox or folder. Read-only. Nullable. */
	    messages?: Message[]

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

	    people?: Person[]

	    /** The user's contacts. Read-only. Nullable. */
	    contacts?: Contact[]

	    /** The user's contacts folders. Read-only. Nullable. */
	    contactFolders?: ContactFolder[]

	    /** Relevance classification of the user's messages based on explicit designations which override inferred relevance or importance. */
	    inferenceClassification?: InferenceClassification

	    /** The user's profile photo. Read-only. */
	    photo?: ProfilePhoto

	    photos?: ProfilePhoto[]

	    /** The user's OneDrive. Read-only. */
	    drive?: Drive

	    /** A collection of drives available for this user. Read-only. */
	    drives?: Drive[]

	    insights?: OfficeGraphInsights

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

	    joinedTeams?: Group[]

	    /** The list of troubleshooting events for this user. */
	    deviceManagementTroubleshootingEvents?: DeviceManagementTroubleshootingEvent[]

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

export interface Activity extends Entity {

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

	    historyItems?: HistoryItem[]

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

	    /** The message ID in the format specified by RFC2822. */
	    internetMessageId?: string

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

	    mentionsPreview?: MentionsPreview

	    /** The classification of the message for the user, based on inferred relevance or importance, or on an explicit override. Possible values are: focused or other. */
	    inferenceClassification?: InferenceClassificationType

	    unsubscribeData?: string[]

	    unsubscribeEnabled?: boolean

	    flag?: FollowupFlag

	    /** The fileAttachment and itemAttachment attachments for the message. */
	    attachments?: Attachment[]

	    /** The collection of open extensions defined for the message. Read-only. Nullable. */
	    extensions?: Extension[]

	    /** The collection of single-value extended properties defined for the message. Read-only. Nullable. */
	    singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

	    /** The collection of multi-value extended properties defined for the message. Read-only. Nullable. */
	    multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

	    mentions?: Mention[]

}

export interface Group extends DirectoryObject {

	    classification?: string

	    /** The date and time the group was created. */
	    createdDateTime?: string

	    /** An optional description for the group. */
	    description?: string

	    /** The display name for the group. This property is required when a group is created and it cannot be cleared during updates. Supports $filter and $orderby. */
	    displayName?: string

	    /** Specifies the type of group to create. Possible values are Unified to create an Office 365 group, or DynamicMembership for dynamic groups.  For all other group types, like security-enabled groups and email-enabled security groups, do not set this property. Supports $filter. */
	    groupTypes?: string[]

	    /** The SMTP address for the group, for example, "serviceadmins@contoso.onmicrosoft.com". Read-only. Supports $filter. */
	    mail?: string

	    /** Specifies whether the group is mail-enabled. If the securityEnabled property is also true, the group is a mail-enabled security group; otherwise, the group is a Microsoft Exchange distribution group. */
	    mailEnabled?: boolean

	    /** The mail alias for the group. This property must be specified when a group is created. Supports $filter. */
	    mailNickname?: string

	    membershipRule?: string

	    membershipRuleProcessingState?: string

	    /** Indicates the last time at which the group was synced with the on-premises directory.The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z'. Read-only. Supports $filter. */
	    onPremisesLastSyncDateTime?: string

	    onPremisesProvisioningErrors?: OnPremisesProvisioningError[]

	    /** Contains the on-premises security identifier (SID) for the group that was synchronized from on-premises to the cloud. Read-only. */
	    onPremisesSecurityIdentifier?: string

	    /** true if this group is synced from an on-premises directory; false if this group was originally synced from an on-premises directory but is no longer synced; null if this object has never been synced from an on-premises directory (default). Read-only. Supports $filter. */
	    onPremisesSyncEnabled?: boolean

	    preferredLanguage?: string

	    /** The any operator is required for filter expressions on multi-valued properties. Read-only. Not nullable. Supports $filter. */
	    proxyAddresses?: string[]

	    renewedDateTime?: string

	    resourceBehaviorOptions?: string[]

	    resourceProvisioningOptions?: string[]

	    /** Specifies whether the group is a security group. If the mailEnabled property is also true, the group is a mail-enabled security group; otherwise it is a security group. Must be false for Office 365 groups. Supports $filter. */
	    securityEnabled?: boolean

	    theme?: string

	    /** Specifies the visibility of an Office 365 group. Possible values are: Private, Public, or empty (which is interpreted as Public). */
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

	    /** The collection of open extensions defined for the group. Read-only. Nullable. */
	    extensions?: Extension[]

	    /** Users and groups that are members of this group. HTTP Methods: GET (supported for all groups), POST (supported for Office 365 groups, security groups and mail-enabled security groups), DELETE (supported for Office 365 groups and security groups) Nullable. */
	    members?: DirectoryObject[]

	    /** Groups that this group is a member of. HTTP Methods: GET (supported for all groups). Read-only. Nullable. */
	    memberOf?: DirectoryObject[]

	    /** The user (or application) that created the group. NOTE: This is not set if the user is an administrator. Read-only. */
	    createdOnBehalfOf?: DirectoryObject

	    /** The owners of the group. The owners are a set of non-admin users who are allowed to modify this object. Limited to 10 owners. HTTP Methods: GET (supported for all groups), POST (supported for Office 365 groups, security groups and mail-enabled security groups), DELETE (supported for Office 365 groups and security groups). Nullable. */
	    owners?: DirectoryObject[]

	    /** Read-only. Nullable. */
	    settings?: DirectorySetting[]

	    endpoints?: Endpoint[]

	    /** The group's conversation threads. Nullable. */
	    threads?: ConversationThread[]

	    /** The group's calendar. Read-only. */
	    calendar?: Calendar

	    /** The calendar view for the calendar. Read-only. */
	    calendarView?: Event[]

	    /** The group's calendar events. */
	    events?: Event[]

	    /** The group's conversations. */
	    conversations?: Conversation[]

	    /** The group's profile photo */
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

	    /** Entry-point to Planner resource that might exist for a Unified Group. */
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

	    hexColor?: string

	    isDefaultCalendar?: boolean

	    /** Identifies the version of the calendar object. Every time the calendar is changed, changeKey changes as well. This allows Exchange to apply changes to the correct version of the object. Read-only. */
	    changeKey?: string

	    /** True if the user has the permission to share the calendar, false otherwise. Only the user who created the calendar can share it. */
	    canShare?: boolean

	    /** True if the user can read calendar items that have been marked private, false otherwise. */
	    canViewPrivateItems?: boolean

	    isShared?: boolean

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

	    /** The end time zone that was set when the event was created. A value of tzone://Microsoft/Customindicates that a legacy custom time zone was set in desktop Outlook. */
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

	    /** The importance of the event. Possible values are: Low, Normal, High. */
	    importance?: Importance

	    /** Possible values are: Normal, Personal, Private, Confidential. */
	    sensitivity?: Sensitivity

	    /** The date, time, and time zone that the event starts. */
	    start?: DateTimeTimeZone

	    /** The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' */
	    originalStart?: string

	    /** The date, time, and time zone that the event ends. */
	    end?: DateTimeTimeZone

	    /** The location of the event. */
	    location?: Location

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

	    /** The categories assigned to the item. */
	    seriesMasterId?: string

	    /** The status to show. Possible values are: Free, Tentative, Busy, Oof, WorkingElsewhere, Unknown. */
	    showAs?: FreeBusyStatus

	    /** The event type. Possible values are: SingleInstance, Occurrence, Exception, SeriesMaster. Read-only. */
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

	    /** The collection of open extensions defined for the event. Read-only. Nullable. */
	    extensions?: Extension[]

	    /** The collection of fileAttachment and itemAttachment attachments for the event. Navigation property. Read-only. Nullable. */
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

	    emailAddresses?: RankedEmailAddress[]

	    /** The person's phone numbers. */
	    phones?: Phone[]

	    /** The person's addresses. */
	    postalAddresses?: Location[]

	    /** The person's websites. */
	    websites?: Website[]

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

	    sources?: PersonDataSource[]

	    mailboxType?: string

	    /** The type of person. */
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
	    emailAddresses?: EmailAddress[]

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

	    phones?: Phone[]

	    postalAddresses?: PhysicalAddress[]

	    /** The name of the contact's spouse/partner. */
	    spouseName?: string

	    /** The user's notes about the contact. */
	    personalNotes?: string

	    /** The names of the contact's children. */
	    children?: string[]

	    weddingAnniversary?: string

	    gender?: string

	    isFavorite?: boolean

	    flag?: FollowupFlag

	    /** The collection of open extensions defined for the contact. Read-only. Nullable. */
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

export interface PlannerUser extends Entity {

	    favoritePlanReferences?: PlannerFavoritePlanReferenceCollection

	    recentPlanReferences?: PlannerRecentPlanReferenceCollection

	    /** Read-only. Nullable. Returns the plannerPlans shared with the user. */
	    tasks?: PlannerTask[]

	    /** Read-only. Nullable. Returns the plannerTasks assigned to the user. */
	    plans?: PlannerPlan[]

	    favoritePlans?: PlannerPlan[]

	    recentPlans?: PlannerPlan[]

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

	    hardwareInformation?: HardwareInformation

	    ownerType?: OwnerType

	    /** List of ComplexType deviceActionResult objects. */
	    deviceActionResults?: DeviceActionResult[]

	    managementState?: ManagementState

	    /** Enrollment time of the device. */
	    enrolledDateTime?: string

	    /** The date and time that the device last completed a successful sync with Intune. */
	    lastSyncDateTime?: string

	    chassisType?: ChassisType

	    /** Operating system of the device. Windows, iOS, etc. */
	    operatingSystem?: string

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

	    aadRegistered?: boolean

	    /** Whether the device is Azure Active Directory registered. */
	    azureADRegistered?: boolean

	    /** Enrollment type of the device. Possible values are: unknown, userEnrollment, deviceEnrollmentManager, appleBulkWithUser, appleBulkWithoutUser, windowsAzureADJoin, windowsBulkUserless, windowsAutoEnrollment, windowsBulkAzureDomainJoin, windowsCoManagement. */
	    deviceEnrollmentType?: DeviceEnrollmentType

	    lostModeState?: LostModeState

	    /** Code that allows the Activation Lock on a device to be bypassed. */
	    activationLockBypassCode?: string

	    /** Email(s) for the user associated with the device */
	    emailAddress?: string

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

	    remoteAssistanceSessionErrorString?: string

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

	    lastLoggedOnUserId?: string

	    /** Device configuration states for this device. */
	    deviceConfigurationStates?: DeviceConfigurationState[]

	    detectedApps?: DetectedApp[]

	    /** Device category */
	    deviceCategory?: DeviceCategory

	    windowsProtectionState?: WindowsProtectionState

	    /** Device compliance policy states for this device. */
	    deviceCompliancePolicyStates?: DeviceCompliancePolicyState[]

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

	    /** true if the account is enabled; otherwise, false. Required. */
	    accountEnabled?: boolean

	    alternativeSecurityIds?: AlternativeSecurityId[]

	    /** The Timestamp type represents date and time information using ISO 8601 format and is always in UTC time. For example, midnight UTC on Jan 1, 2014 would look like this: '2014-01-01T00:00:00Z' Read-only. */
	    approximateLastSignInDateTime?: string

	    /** Unique identifier set by Azure Device Registration Service at the time of registration. */
	    deviceId?: string

	    /** For interal use only. Set to null. */
	    deviceMetadata?: string

	    /** For interal use only. */
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

	    /** The version of the operating system on the device. Required. */
	    operatingSystemVersion?: string

	    /** For interal use only. Not nullable. */
	    physicalIds?: string[]

	    /** Type of trust for the joined device. Read-only. Possible values: Workplace - indicates bring your own personal devicesAzureAd - Cloud only joined devicesServerAd - on-premises domain joined devices joined to Azure AD. For more details, see Introduction to device management in Azure Active Directory */
	    trustType?: string

	    Name?: string

	    Manufacturer?: string

	    Model?: string

	    Kind?: string

	    Status?: string

	    Platform?: string

	    /** The collection of open extensions defined for the device. Read-only. Nullable. */
	    extensions?: Extension[]

	    /** The user that cloud joined the device or registered their personal device. The registered owner is set at the time of registration. Currently, there can be only one owner. Read-only. Nullable. */
	    registeredOwners?: DirectoryObject[]

	    /** Collection of registered users of the device. For cloud joined devices and registered personal devices, registered users are set to the same value as registered owners at the time of registration. Read-only. Nullable. */
	    registeredUsers?: DirectoryObject[]

	    commands?: Command[]

}

export interface DeviceManagementTroubleshootingEvent extends Entity {

	    /** Time when the event occurred . */
	    eventDateTime?: string

	    /** Id used for tracing the failure in the service. */
	    correlationId?: string

}

export interface DirectorySetting extends Entity {

	    displayName?: string

	    templateId?: string

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

	    memberSettings?: TeamMemberSettings

	    messagingSettings?: TeamMessagingSettings

	    funSettings?: TeamFunSettings

	    guestSettings?: TeamGuestSettings

	    channels?: Channel[]

}

export interface Channel extends Entity {

	    displayName?: string

	    description?: string

	    chatThreads?: ChatThread[]

}

export interface GroupLifecyclePolicy extends Entity {

	    groupLifetimeInDays?: number

	    managedGroupTypes?: string

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

	    displayName?: string

	    description?: string

	    visibility?: string

	    extensions?: Extension[]

	    members?: DirectoryObject[]

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

	    certificateConnectorSetting?: CertificateConnectorSetting

	    /** The collection of open extensions defined for the organization. Read-only. Nullable. */
	    extensions?: Extension[]

}

export interface SchemaExtension extends Entity {

	    /** Description for the schema extension. */
	    description?: string

	    /** Set of Microsoft Graph types (that can support extensions) that the schema extension can be applied to. Select from contact, device, event, group, message, organization, post, or user. */
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

	    api?: Api

	    allowPublicClient?: boolean

	    applicationAliases?: string[]

	    appRoles?: AppRole[]

	    createdDateTime?: string

	    installedClients?: InstalledClient

	    displayName?: string

	    info?: InformationalUrl

	    keyCredentials?: KeyCredential[]

	    logo?: any

	    orgRestrictions?: string[]

	    passwordCredentials?: PasswordCredential[]

	    preAuthorizedApplications?: PreAuthorizedApplication[]

	    requiredResourceAccess?: RequiredResourceAccess[]

	    tags?: string[]

	    web?: Web

	    extensionProperties?: ExtensionProperty[]

	    createdOnBehalfOf?: DirectoryObject

	    owners?: DirectoryObject[]

	    policies?: DirectoryObject[]

	    synchronization?: Synchronization

}

export interface Synchronization extends Entity {

	    secrets?: SynchronizationSecretKeyStringValuePair[]

	    jobs?: SynchronizationJob[]

	    templates?: SynchronizationTemplate[]

}

export interface AppRoleAssignment extends Entity {

	    creationTimestamp?: string

	    principalDisplayName?: string

	    principalId?: string

	    principalType?: string

	    resourceDisplayName?: string

	    resourceId?: string

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

	    scopedMembers?: ScopedRoleMembership[]

}

export interface DirectoryRoleTemplate extends DirectoryObject {

	    /** The description to set for the directory role. Read-only. */
	    description?: string

	    /** The display name to set for the directory role. Read-only. */
	    displayName?: string

}

export interface DirectorySettingTemplate extends DirectoryObject {

	    displayName?: string

	    description?: string

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

export interface HistoryItem extends Entity {

	    status?: Status

	    activeDurationSeconds?: number

	    createdDateTime?: string

	    lastActiveDateTime?: string

	    lastModifiedDateTime?: string

	    expirationDateTime?: string

	    startedDateTime?: string

	    userTimezone?: string

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

	    activities?: ItemActivity[]

	    columns?: ColumnDefinition[]

	    contentTypes?: ContentType[]

	    /** Only present on document libraries. Allows access to the list as a [drive][] resource with [driveItems][driveItem]. */
	    drive?: Drive

	    /** All items contained in the list. */
	    items?: ListItem[]

}

export interface ItemActivity extends Entity {

	    action?: ItemActionSet

	    actor?: IdentitySet

	    times?: ItemActivityTimeSet

	    driveItem?: DriveItem

	    listItem?: ListItem

}

export interface ListItem extends BaseItem {

	    /** The content type of this list item */
	    contentType?: ContentTypeInfo

	    sharepointIds?: SharepointIds

	    activities?: ItemActivity[]

	    /** For document libraries, the driveItem relationship exposes the listItem as a [driveItem][] */
	    driveItem?: DriveItem

	    fields?: FieldValueSet

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

	    activities?: ItemActivity[]

	    /** Collection containing Item objects for the immediate children of Item. Only items representing folders have children. Read-only. Nullable. */
	    children?: DriveItem[]

	    listItem?: ListItem

	    /** The set of permissions for the item. Read-only. Nullable. */
	    permissions?: Permission[]

	    /** Collection containing [ThumbnailSet][] objects associated with the item. For more info, see [getting thumbnails][]. Read-only. Nullable. */
	    thumbnails?: ThumbnailSet[]

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

	    lastModifiedBy?: IdentitySet

	    lastModifiedDateTime?: string

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

	    /** The attachment's file name. */
	    name?: string

	    /** The MIME type. */
	    contentType?: string

	    /** The length of the attachment in bytes. */
	    size?: number

	    /** true if the attachment is an inline attachment; otherwise, false. */
	    isInline?: boolean

}

export interface OutlookCategory extends Entity {

	    displayName?: string

	    color?: CategoryColor

}

export interface OutlookTaskGroup extends Entity {

	    changeKey?: string

	    isDefaultGroup?: boolean

	    name?: string

	    groupKey?: string

	    taskFolders?: OutlookTaskFolder[]

}

export interface OutlookTaskFolder extends Entity {

	    changeKey?: string

	    name?: string

	    isDefaultFolder?: boolean

	    parentGroupKey?: string

	    tasks?: OutlookTask[]

	    singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

	    multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

}

export interface OutlookTask extends OutlookItem {

	    assignedTo?: string

	    body?: ItemBody

	    completedDateTime?: DateTimeTimeZone

	    dueDateTime?: DateTimeTimeZone

	    hasAttachments?: boolean

	    importance?: Importance

	    isReminderOn?: boolean

	    owner?: string

	    parentFolderId?: string

	    recurrence?: PatternedRecurrence

	    reminderDateTime?: DateTimeTimeZone

	    sensitivity?: Sensitivity

	    startDateTime?: DateTimeTimeZone

	    status?: TaskStatus

	    subject?: string

	    singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

	    multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

	    attachments?: Attachment[]

}

export interface MessageRule extends Entity {

	    displayName?: string

	    sequence?: number

	    conditions?: MessageRulePredicates

	    actions?: MessageRuleActions

	    exceptions?: MessageRulePredicates

	    isEnabled?: boolean

	    hasError?: boolean

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

	    mentioned?: EmailAddress

	    mentionText?: string

	    clientReference?: string

	    createdBy?: EmailAddress

	    createdDateTime?: string

	    serverCreatedDateTime?: string

	    deepLink?: string

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

	    /** The attached message or event. Navigation property. */
	    item?: OutlookItem

}

export interface EventMessage extends Message {

	    /** The type of event message: none, meetingRequest, meetingCancelled, meetingAccepted, meetingTenativelyAccepted, meetingDeclined. */
	    meetingMessageType?: MeetingMessageType

	    startDateTime?: DateTimeTimeZone

	    endDateTime?: DateTimeTimeZone

	    location?: Location

	    type?: EventType

	    recurrence?: PatternedRecurrence

	    isOutOfDate?: boolean

	    isAllDay?: boolean

	    isDelegated?: boolean

	    /** The event associated with the event message. The assumption for attendees or room resources is that the Calendar Attendant is set to automatically update the calendar with an event when meeting request event messages arrive. Navigation property.  Read-only. */
	    event?: Event

}

export interface EventMessageRequest extends EventMessage {

	    previousLocation?: Location

	    previousStartDateTime?: DateTimeTimeZone

	    previousEndDateTime?: DateTimeTimeZone

	    responseRequested?: boolean

}

export interface ReferenceAttachment extends Attachment {

	    sourceUrl?: string

	    providerType?: ReferenceAttachmentProvider

	    thumbnailUrl?: string

	    previewUrl?: string

	    permission?: ReferenceAttachmentPermission

	    isFolder?: boolean

}

export interface OpenTypeExtension extends Extension {

	    extensionName?: string

}

export interface Post extends OutlookItem {

	    /** The contents of the post. This is a default property. This property can be null. */
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

	    /** The collection of open extensions defined for the post. Read-only. Nullable. */
	    extensions?: Extension[]

	    /** Read-only. */
	    inReplyTo?: Post

	    /** Read-only. Nullable. */
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

	    contexts?: PlannerPlanContextCollection

	    /** Read-only. Nullable. Collection of tasks in the plan. */
	    tasks?: PlannerTask[]

	    /** Read-only. Nullable. Collection of buckets in the plan. */
	    buckets?: PlannerBucket[]

	    /** Read-only. Nullable. Additional details about the plan. */
	    details?: PlannerPlanDetails

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

	    /** Set of user ids that this plan is shared with. If you are leveraging Office 365 Groups, use the Groups API to manage group membership to share the group's plan. You can also add existing members of the group to this collection though it is not required for them to access the plan owned by the group. */
	    sharedWith?: PlannerUserIds

	    /** An object that specifies the descriptions of the six categories that can be associated with tasks in the plan */
	    categoryDescriptions?: PlannerCategoryDescriptions

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

export interface Subscription extends Entity {

	    /** Specifies the resource that will be monitored for changes. Do not include the base URL ("https://graph.microsoft.com/v1.0/"). */
	    resource?: string

	    /** Indicates the type of change in the subscribed resource that will raise a notification. The supported values are: created, updated, deleted. Multiple values can be combined using a comma-separated list. */
	    changeType?: string

	    /** Specifies the value of the clientState property sent by the service in each notification. The maximum length is 128 characters. The client can check that the notification came from the service by comparing the value of the clientState property sent with the subscription with the value of the clientState property received with each notification. */
	    clientState?: string

	    /** The URL of the endpoint that will receive the notifications. This URL has to make use of the HTTPS protocol. */
	    notificationUrl?: string

	    /** Specifies the date and time when the webhook subscription expires. The time is in UTC, and can be an amount of time from subscription creation that varies for the resource subscribed to.  See the table below for maximum supported subscription length of time. */
	    expirationDateTime?: string

}

export interface IdentityRiskEvent extends Entity {

	    userDisplayName?: string

	    userPrincipalName?: string

	    riskEventDateTime?: string

	    riskEventType?: string

	    riskLevel?: RiskLevel

	    riskEventStatus?: RiskEventStatus

	    closedDateTime?: string

	    createdDateTime?: string

	    userId?: string

	    impactedUser?: User

}

export interface LocatedRiskEvent extends IdentityRiskEvent {

	    location?: SignInLocation

	    ipAddress?: string

}

export interface ImpossibleTravelRiskEvent extends LocatedRiskEvent {

	    userAgent?: string

	    deviceInformation?: string

	    isAtypicalLocation?: boolean

	    previousSigninDateTime?: string

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

	    deviceInformation?: string

	    malwareName?: string

}

export interface PrivilegedRole extends Entity {

	    name?: string

	    settings?: PrivilegedRoleSettings

	    assignments?: PrivilegedRoleAssignment[]

	    summary?: PrivilegedRoleSummary

}

export interface PrivilegedRoleSettings extends Entity {

	    approverIds?: string[]

	    minElevationDuration?: string

	    maxElavationDuration?: string

	    elevationDuration?: string

	    notificationToUserOnElevation?: boolean

	    ticketingInfoOnElevation?: boolean

	    mfaOnElevation?: boolean

	    lastGlobalAdmin?: boolean

	    isMfaOnElevationConfigurable?: boolean

	    approvalOnElevation?: boolean

}

export interface PrivilegedRoleAssignment extends Entity {

	    userId?: string

	    roleId?: string

	    isElevated?: boolean

	    expirationDateTime?: string

	    resultMessage?: string

	    roleInfo?: PrivilegedRole

}

export interface PrivilegedRoleSummary extends Entity {

	    status?: RoleSummaryStatus

	    usersCount?: number

	    managedCount?: number

	    elevatedCount?: number

	    mfaEnabled?: boolean

}

export interface PrivilegedOperationEvent extends Entity {

	    userId?: string

	    userName?: string

	    userMail?: string

	    roleId?: string

	    roleName?: string

	    expirationDateTime?: string

	    creationDateTime?: string

	    requestorId?: string

	    requestorName?: string

	    tenantId?: string

	    requestType?: string

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

	    approvalState?: ApprovalState

	    approvalDuration?: string

	    requestorReason?: string

	    approverReason?: string

	    startDateTime?: string

	    endDateTime?: string

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

	    adminConsent?: AdminConsent

	    deviceProtectionOverview?: DeviceProtectionOverview

	    /** Account level settings. */
	    settings?: DeviceManagementSettings

	    maximumDepTokens?: number

	    intuneAccountId?: string

	    /** intuneBrand contains data which is used in customizing the appearance of the Company Portal applications as well as the end user web portal. */
	    intuneBrand?: IntuneBrand

	    /** The terms and conditions associated with device management of the company. */
	    termsAndConditions?: TermsAndConditions[]

	    /** The singleton Android for Work settings entity. */
	    androidForWorkSettings?: AndroidForWorkSettings

	    /** Android for Work app configuration schema entities. */
	    androidForWorkAppConfigurationSchemas?: AndroidForWorkAppConfigurationSchema[]

	    /** Android for Work enrollment profile entities. */
	    androidForWorkEnrollmentProfiles?: AndroidForWorkEnrollmentProfile[]

	    enrollmentProfiles?: EnrollmentProfile[]

	    importedDeviceIdentities?: ImportedDeviceIdentity[]

	    importedAppleDeviceIdentities?: ImportedAppleDeviceIdentity[]

	    remoteActionAudits?: RemoteActionAudit[]

	    /** Apple push notification certificate. */
	    applePushNotificationCertificate?: ApplePushNotificationCertificate

	    deviceManagementScripts?: DeviceManagementScript[]

	    /** Device overview */
	    managedDeviceOverview?: ManagedDeviceOverview

	    /** The list of detected apps associated with a device. */
	    detectedApps?: DetectedApp[]

	    /** The list of managed devices. */
	    managedDevices?: ManagedDevice[]

	    windowsMalwareInformation?: WindowsMalwareInformation[]

	    /** The device configurations. */
	    deviceConfigurations?: DeviceConfiguration[]

	    /** The device compliance policies. */
	    deviceCompliancePolicies?: DeviceCompliancePolicy[]

	    deviceSetupConfigurations?: DeviceSetupConfiguration[]

	    /** The software update status summary. */
	    softwareUpdateStatusSummary?: SoftwareUpdateStatusSummary

	    /** The device compliance state summary for this account. */
	    deviceCompliancePolicyDeviceStateSummary?: DeviceCompliancePolicyDeviceStateSummary

	    /** The summary states of compliance policy settings for this account. */
	    deviceCompliancePolicySettingStateSummaries?: DeviceCompliancePolicySettingStateSummary[]

	    /** The device configuration device state summary for this account. */
	    deviceConfigurationDeviceStateSummaries?: DeviceConfigurationDeviceStateSummary

	    cartToClassAssociations?: CartToClassAssociation[]

	    /** The IOS software update installation statuses for this account. */
	    iosUpdateStatuses?: IosUpdateDeviceStatus[]

	    ndesConnectors?: NdesConnector[]

	    /** The list of device categories with the tenant. */
	    deviceCategories?: DeviceCategory[]

	    /** The list of Exchange Connectors configured by the tenant. */
	    exchangeConnectors?: DeviceManagementExchangeConnector[]

	    /** The list of device enrollment configurations */
	    deviceEnrollmentConfigurations?: DeviceEnrollmentConfiguration[]

	    exchangeOnPremisesPolicy?: DeviceManagementExchangeOnPremisesPolicy

	    exchangeOnPremisesPolicies?: DeviceManagementExchangeOnPremisesPolicy[]

	    /** The Exchange on premises conditional access settings. On premises conditional access will require devices to be both enrolled and compliant for mail access */
	    conditionalAccessSettings?: OnPremisesConditionalAccessSettings

	    /** The list of Mobile threat Defense connectors configured by the tenant. */
	    mobileThreatDefenseConnectors?: MobileThreatDefenseConnector[]

	    /** The list of Device Management Partners configured by the tenant. */
	    deviceManagementPartners?: DeviceManagementPartner[]

	    depOnboardingSettings?: DepOnboardingSetting[]

	    /** The Notification Message Templates. */
	    notificationMessageTemplates?: NotificationMessageTemplate[]

	    /** The Role Definitions. */
	    roleDefinitions?: RoleDefinition[]

	    /** The Role Assignments. */
	    roleAssignments?: DeviceAndAppManagementRoleAssignment[]

	    /** The Resource Operations. */
	    resourceOperations?: ResourceOperation[]

	    /** The telecom expense management partners. */
	    telecomExpenseManagementPartners?: TelecomExpenseManagementPartner[]

	    windowsAutopilotSettings?: WindowsAutopilotSettings

	    windowsAutopilotDeviceIdentities?: WindowsAutopilotDeviceIdentity[]

	    windowsAutopilotDeploymentProfiles?: WindowsAutopilotDeploymentProfile[]

	    importedWindowsAutopilotDeviceIdentities?: ImportedWindowsAutopilotDeviceIdentity[]

	    /** The remote assist partners. */
	    remoteAssistancePartners?: RemoteAssistancePartner[]

	    /** The windows information protection app learning summaries. */
	    windowsInformationProtectionAppLearningSummaries?: WindowsInformationProtectionAppLearningSummary[]

	    /** The windows information protection network learning summaries. */
	    windowsInformationProtectionNetworkLearningSummaries?: WindowsInformationProtectionNetworkLearningSummary[]

	    /** The Audit Events */
	    auditEvents?: AuditEvent[]

	    /** The list of troubleshooting events for the tenant. */
	    troubleshootingEvents?: DeviceManagementTroubleshootingEvent[]

}

export interface TermsAndConditions extends Entity {

	    /** DateTime the object was created. */
	    createdDateTime?: string

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

	    groupAssignments?: TermsAndConditionsGroupAssignment[]

	    /** The list of assignments for this T&C policy. */
	    assignments?: TermsAndConditionsAssignment[]

	    /** The list of acceptance statuses for this T&C policy. */
	    acceptanceStatuses?: TermsAndConditionsAcceptanceStatus[]

}

export interface AndroidForWorkSettings extends Entity {

	    /** Bind status of the tenant with the Google EMM API Possible values are: notBound, bound, boundAndValidated, unbinding. */
	    bindStatus?: AndroidForWorkBindStatus

	    /** Last completion time for app sync */
	    lastAppSyncDateTime?: string

	    /** Last application sync result Possible values are: success, credentialsNotValid, androidForWorkApiError, managementServiceError, unknownError, none. */
	    lastAppSyncStatus?: AndroidForWorkSyncStatus

	    /** Owner UPN that created the enterprise */
	    ownerUserPrincipalName?: string

	    /** Organization name used when onboarding Android for Work */
	    ownerOrganizationName?: string

	    /** Last modification time for Android for Work settings */
	    lastModifiedDateTime?: string

	    /** Indicates which users can enroll devices in Android for Work device management Possible values are: none, all, targeted, targetedAsEnrollmentRestrictions. */
	    enrollmentTarget?: AndroidForWorkEnrollmentTarget

	    /** Specifies which AAD groups can enroll devices in Android for Work device management if enrollmentTarget is set to 'Targeted' */
	    targetGroupIds?: string[]

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

export interface EnrollmentProfile extends Entity {

	    displayName?: string

	    description?: string

	    requiresUserAuthentication?: boolean

	    configurationEndpointUrl?: string

	    enableAuthenticationViaCompanyPortal?: boolean

}

export interface ImportedDeviceIdentity extends Entity {

	    importedDeviceIdentifier?: string

	    importedDeviceIdentityType?: ImportedDeviceIdentityType

	    lastModifiedDateTime?: string

	    createdDateTime?: string

	    lastContactedDateTime?: string

	    description?: string

	    enrollmentState?: EnrollmentState

	    platform?: Platform

}

export interface ImportedAppleDeviceIdentity extends Entity {

	    serialNumber?: string

	    requestedEnrollmentProfileId?: string

	    requestedEnrollmentProfileAssignmentDateTime?: string

	    isSupervised?: boolean

	    discoverySource?: DiscoverySource

	    createdDateTime?: string

	    lastContactedDateTime?: string

	    description?: string

	    enrollmentState?: EnrollmentState

	    platform?: Platform

}

export interface RemoteActionAudit extends Entity {

	    deviceDisplayName?: string

	    userName?: string

	    initiatedByUserPrincipalName?: string

	    action?: RemoteAction

	    requestDateTime?: string

	    deviceOwnerUserPrincipalName?: string

	    deviceIMEI?: string

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

	    certificateUploadStatus?: string

	    certificateUploadFailureReason?: string

	    /** Not yet documented */
	    certificate?: string

}

export interface DeviceManagementScript extends Entity {

	    displayName?: string

	    description?: string

	    runSchedule?: RunSchedule

	    scriptContent?: number

	    createdDateTime?: string

	    lastModifiedDateTime?: string

	    runAsAccount?: RunAsAccountType

	    enforceSignatureCheck?: boolean

	    fileName?: string

	    groupAssignments?: DeviceManagementScriptGroupAssignment[]

	    assignments?: DeviceManagementScriptAssignment[]

	    runSummary?: DeviceManagementScriptRunSummary

	    deviceRunStates?: DeviceManagementScriptDeviceState[]

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

	    displayName?: string

	    additionalInformationUrl?: string

	    severity?: WindowsMalwareSeverity

	    category?: WindowsMalwareCategory

	    lastDetectionDateTime?: string

	    windowsDevicesProtectionState?: WindowsProtectionState[]

}

export interface DeviceConfiguration extends Entity {

	    /** DateTime the object was last modified. */
	    lastModifiedDateTime?: string

	    /** DateTime the object was created. */
	    createdDateTime?: string

	    /** Admin provided description of the Device Configuration. */
	    description?: string

	    /** Admin provided name of the device configuration. */
	    displayName?: string

	    /** Version of the device configuration. */
	    version?: number

	    groupAssignments?: DeviceConfigurationGroupAssignment[]

	    /** The list of assignments for the device configuration profile. */
	    assignments?: DeviceConfigurationAssignment[]

	    /** Device configuration installation status by device. */
	    deviceStatuses?: DeviceConfigurationDeviceStatus[]

	    /** Device configuration installation stauts by user. */
	    userStatuses?: DeviceConfigurationUserStatus[]

	    /** Device Configuration devices status overview */
	    deviceStatusOverview?: DeviceConfigurationDeviceOverview

	    /** Device Configuration users status overview */
	    userStatusOverview?: DeviceConfigurationUserOverview

	    /** Device Configuration Setting State Device Summary */
	    deviceSettingStateSummaries?: SettingStateDeviceSummary[]

}

export interface DeviceCompliancePolicy extends Entity {

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

export interface DeviceSetupConfiguration extends Entity {

	    createdDateTime?: string

	    description?: string

	    lastModifiedDateTime?: string

	    displayName?: string

	    version?: number

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

	    /** Setting platform Possible values are: android, iOS, macOS, windowsPhone81, windows81AndLater, windows10AndLater, all. */
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

export interface CartToClassAssociation extends Entity {

	    createdDateTime?: string

	    lastModifiedDateTime?: string

	    version?: number

	    displayName?: string

	    description?: string

	    deviceCartIds?: string[]

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

	    lastConnectionDateTime?: string

	    state?: NdesConnectorState

	    displayName?: string

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

	    /** Exchange Connector Status Possible values are: none, connectionPending, connected, disconnected. */
	    status?: DeviceManagementExchangeConnectorStatus

	    /** Email address used to configure the Service To Service Exchange Connector. */
	    primarySmtpAddress?: string

	    /** The name of the server hosting the Exchange Connector. */
	    serverName?: string

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

	    notificationContent?: number

	    defaultAccessLevel?: DeviceManagementExchangeAccessLevel

	    accessRules?: DeviceManagementExchangeAccessRule[]

	    knownDeviceClasses?: DeviceManagementExchangeDeviceClass[]

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

	    /** Timestamp of last heartbeat after admin enabled option Connect to MTP */
	    lastHeartbeatDateTime?: string

	    /** Partner state of this tenant Possible values are: unavailable, available, enabled, unresponsive. */
	    partnerState?: MobileThreatPartnerTenantState

	    /** Android Toggle On or Off */
	    androidEnabled?: boolean

	    /** For Android, Allows admin to config must receive data from the data sync partner prior to being considered compliant */
	    androidDeviceBlockedOnMissingPartnerData?: boolean

	    /** For IOS, Allows admin to config must receive data from the data sync partner prior to being considered compliant */
	    iosDeviceBlockedOnMissingPartnerData?: boolean

	    /** Allows admin to block devices on the enabled platforms that do not meet minimum version requirements */
	    partnerUnsupportedOsVersionBlocked?: boolean

	    /** IOS Toggle On or Off */
	    iosEnabled?: boolean

	    /** Get or Set days the per tenant tolerance to unresponsiveness for this partner integration */
	    partnerUnresponsivenessThresholdInDays?: number

	    allowPartnerToCollectIOSApplicationMetadata?: boolean

}

export interface DeviceManagementPartner extends Entity {

	    /** Timestamp of last heartbeat after admin enabled option Connect to Device management Partner */
	    lastHeartbeatDateTime?: string

	    /** Partner state of this tenant Possible values are: unknown, unavailable, enabled, terminated, rejected, unresponsive. */
	    partnerState?: DeviceManagementPartnerTenantState

	    /** Partner App type Possible values are: unknown, singleTenantApp, multiTenantApp. */
	    partnerAppType?: DeviceManagementPartnerAppType

	    /** Partner Single tenant App id */
	    singleTenantAppId?: string

	    /** Partner display name */
	    displayName?: string

	    /** Whether device management partner is configured or not */
	    isConfigured?: boolean

	    whenPartnerDevicesWillBeRemoved?: string

	    whenPartnerDevicesWillBeMarkedAsNonCompliant?: string

	    /** DateTime in UTC when PartnerDevices will be removed */
	    whenPartnerDevicesWillBeRemovedDateTime?: string

	    /** DateTime in UTC when PartnerDevices will be marked as NonCompliant */
	    whenPartnerDevicesWillBeMarkedAsNonCompliantDateTime?: string

}

export interface DepOnboardingSetting extends Entity {

	    appleIdentifier?: string

	    tokenExpirationDateTime?: string

	    lastModifiedDateTime?: string

	    lastSuccessfulSyncDateTime?: string

	    lastSyncTriggeredDateTime?: string

	    shareTokenWithSchoolDataSyncService?: boolean

	    lastSyncErrorCode?: number

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

	    /** The list of localized messages for this Notification Message Template. */
	    localizedNotificationMessages?: LocalizedNotificationMessage[]

}

export interface RoleDefinition extends Entity {

	    /** Display Name of the Role definition. */
	    displayName?: string

	    /** Description of the Role definition. */
	    description?: string

	    permissions?: RolePermission[]

	    /** List of Role Permissions this role is allowed to perform. These must match the actionName that is defined as part of the rolePermission. */
	    rolePermissions?: RolePermission[]

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

	    scopeMembers?: string[]

	    /** List of ids of role scope member security groups.  These are IDs from Azure Active Directory. */
	    resourceScopes?: string[]

	    /** Role definition this assignment is part of. */
	    roleDefinition?: RoleDefinition

}

export interface DeviceAndAppManagementRoleAssignment extends RoleAssignment {

	    /** The list of ids of role member security groups. These are IDs from Azure Active Directory. */
	    members?: string[]

}

export interface ResourceOperation extends Entity {

	    /** Name of the Resource this operation is performed on. */
	    resourceName?: string

	    /** Type of action this operation is going to perform. The actionName should be concise and limited to as few words as possible. */
	    actionName?: string

	    /** Description of the resource operation. The description is used in mouse-over text for the operation when shown in the Azure Portal. */
	    description?: string

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

	    lastSyncDateTime?: string

	    lastManualSyncTriggerDateTime?: string

	    syncStatus?: WindowsAutopilotSyncStatus

}

export interface WindowsAutopilotDeviceIdentity extends Entity {

	    deploymentProfileAssignmentStatus?: WindowsAutopilotProfileAssignmentStatus

	    deploymentProfileAssignedDateTime?: string

	    orderIdentifier?: string

	    serialNumber?: string

	    productKey?: string

	    manufacturer?: string

	    model?: string

	    enrollmentState?: EnrollmentState

	    lastContactedDateTime?: string

	    deploymentProfile?: WindowsAutopilotDeploymentProfile

}

export interface WindowsAutopilotDeploymentProfile extends Entity {

	    displayName?: string

	    description?: string

	    createdDateTime?: string

	    lastModifiedDateTime?: string

	    outOfBoxExperienceSettings?: OutOfBoxExperienceSettings

	    assignedDevices?: WindowsAutopilotDeviceIdentity[]

}

export interface ImportedWindowsAutopilotDeviceIdentity extends Entity {

	    orderIdentifier?: string

	    serialNumber?: string

	    productKey?: string

	    hardwareIdentifier?: number

	    state?: ImportedWindowsAutopilotDeviceIdentityState

}

export interface RemoteAssistancePartner extends Entity {

	    /** Display name of the partner. */
	    displayName?: string

	    /** URL of the partner's onboarding portal, where an administrator can configure their Remote Assistance service. */
	    onboardingUrl?: string

	    /** TBD Possible values are: notOnboarded, onboarding, onboarded. */
	    onboardingStatus?: RemoteAssistanceOnboardingStatus

	    /** Timestamp of the last request sent to Intune by the TEM partner. */
	    lastConnectionDateTime?: string

}

export interface WindowsInformationProtectionAppLearningSummary extends Entity {

	    /** Application Name */
	    applicationName?: string

	    /** Application Type Possible values are: universal, desktop. */
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

export interface DeviceAppManagement extends Entity {

	    /** The last time the apps from the Microsoft Store for Business were synced successfully for the account. */
	    microsoftStoreForBusinessLastSuccessfulSyncDateTime?: string

	    /** Whether the account is enabled for syncing applications from the Microsoft Store for Business. */
	    isEnabledForMicrosoftStoreForBusiness?: boolean

	    /** The locale information used to sync applications from the Microsoft Store for Business. Cultures that are specific to a country/region. The names of these cultures follow RFC 4646 (Windows Vista and later). The format is -<country/regioncode2>, where  is a lowercase two-letter code derived from ISO 639-1 and <country/regioncode2> is an uppercase two-letter code derived from ISO 3166. For example, en-US for English (United States) is a specific culture. */
	    microsoftStoreForBusinessLanguage?: string

	    /** The last time an application sync from the Microsoft Store for Business was completed. */
	    microsoftStoreForBusinessLastCompletedApplicationSyncTime?: string

	    windowsManagementApp?: WindowsManagementApp

	    /** The mobile apps. */
	    mobileApps?: MobileApp[]

	    /** The mobile app categories. */
	    mobileAppCategories?: MobileAppCategory[]

	    enterpriseCodeSigningCertificates?: EnterpriseCodeSigningCertificate[]

	    iosLobAppProvisioningConfigurations?: IosLobAppProvisioningConfiguration[]

	    symantecCodeSigningCertificate?: SymantecCodeSigningCertificate

	    /** The Managed Device Mobile Application Configurations. */
	    mobileAppConfigurations?: ManagedDeviceMobileAppConfiguration[]

	    sideLoadingKeys?: SideLoadingKey[]

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

}

export interface WindowsManagementApp extends Entity {

	    availableVersion?: string

	    healthSummary?: WindowsManagementAppHealthSummary

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

	    uploadState?: number

	    /** The publishing state for the app. The app cannot be assigned unless the app is published. Possible values are: notPublished, processing, published. */
	    publishingState?: MobileAppPublishingState

	    /** The list of categories for this app. */
	    categories?: MobileAppCategory[]

	    /** The list of group assignments for this mobile app. */
	    assignments?: MobileAppAssignment[]

	    installSummary?: MobileAppInstallSummary

	    deviceStatuses?: MobileAppInstallStatus[]

	    userStatuses?: UserAppInstallStatus[]

}

export interface MobileAppCategory extends Entity {

	    /** The name of the app category. */
	    displayName?: string

	    /** The date and time the mobileAppCategory was last modified. */
	    lastModifiedDateTime?: string

}

export interface EnterpriseCodeSigningCertificate extends Entity {

	    content?: number

	    status?: CertificateStatus

	    subjectName?: string

	    subject?: string

	    issuerName?: string

	    issuer?: string

	    expirationDateTime?: string

	    uploadDateTime?: string

}

export interface IosLobAppProvisioningConfiguration extends Entity {

	    expirationDateTime?: string

	    payloadFileName?: string

	    payload?: number

	    createdDateTime?: string

	    description?: string

	    lastModifiedDateTime?: string

	    displayName?: string

	    version?: number

	    groupAssignments?: MobileAppProvisioningConfigGroupAssignment[]

	    assignments?: IosLobAppProvisioningConfigurationAssignment[]

	    deviceStatuses?: ManagedDeviceMobileAppConfigurationDeviceStatus[]

	    userStatuses?: ManagedDeviceMobileAppConfigurationUserStatus[]

}

export interface SymantecCodeSigningCertificate extends Entity {

	    content?: number

	    status?: CertificateStatus

	    password?: string

	    subjectName?: string

	    subject?: string

	    issuerName?: string

	    issuer?: string

	    expirationDateTime?: string

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

	    groupAssignments?: MdmAppConfigGroupAssignment[]

	    /** The list of group assignemenets for app configration. */
	    assignments?: ManagedDeviceMobileAppConfigurationAssignment[]

	    deviceStatuses?: ManagedDeviceMobileAppConfigurationDeviceStatus[]

	    /** List of ManagedDeviceMobileAppConfigurationUserStatus. */
	    userStatuses?: ManagedDeviceMobileAppConfigurationUserStatus[]

	    /** App configuration device status summary. */
	    deviceStatusSummary?: ManagedDeviceMobileAppConfigurationDeviceSummary

	    /** App configuration user status summary. */
	    userStatusSummary?: ManagedDeviceMobileAppConfigurationUserSummary

}

export interface SideLoadingKey extends Entity {

	    value?: string

	    displayName?: string

	    description?: string

	    totalActivation?: number

	    lastUpdatedDateTime?: string

}

export interface VppToken extends Entity {

	    organizationName?: string

	    vppTokenAccountType?: VppTokenAccountType

	    appleId?: string

	    expirationDateTime?: string

	    lastSyncDateTime?: string

	    token?: string

	    lastModifiedDateTime?: string

	    state?: VppTokenState

	    tokenActionResults?: VppTokenActionResult[]

	    lastSyncStatus?: VppTokenSyncStatus

	    automaticallyUpdateApps?: boolean

	    countryOrRegion?: string

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

	    /** Maximum number of incorrect pin retry attempts before the managed app is wiped. */
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

}

export interface TargetedManagedAppProtection extends ManagedAppProtection {

	    /** Indicates if the policy is deployed to any inclusion groups or not. */
	    isAssigned?: boolean

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

	    exemptedAppProtocols?: KeyValuePair[]

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

	    exemptedAppPackages?: KeyValuePair[]

	    /** List of apps to which the policy is deployed. */
	    apps?: ManagedMobileApp[]

	    /** Navigation property to deployment summary of the configuration. */
	    deploymentSummary?: ManagedAppPolicyDeploymentSummary

}

export interface DefaultManagedAppProtection extends ManagedAppProtection {

	    /** Type of encryption which should be used for data in a managed app. (iOS Only) Possible values are: useDeviceSettings, afterDeviceRestart, whenDeviceLockedExceptOpenFiles, whenDeviceLocked. */
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

	    exemptedAppProtocols?: KeyValuePair[]

	    exemptedAppPackages?: KeyValuePair[]

	    /** Indicates whether use of the FaceID is allowed in place of a pin if PinRequired is set to True. */
	    faceIdBlocked?: boolean

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

	    /** WIP enforcement level.See the Enum definition for supported values Possible values are: noProtection, encryptAndAuditOnly, encryptAuditAndPrompt, encryptAuditAndBlock. */
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

	    /** The date and time when teh eBook was last modified. */
	    lastModifiedDateTime?: string

	    /** The more information Url. */
	    informationUrl?: string

	    /** The privacy statement Url. */
	    privacyInformationUrl?: string

	    /** The list of assignments for this eBook. */
	    assignments?: ManagedEBookAssignment[]

	    /** Mobile App Install Summary. */
	    installSummary?: EBookInstallSummary

	    /** The list of installation states for this eBook. */
	    deviceStates?: DeviceInstallState[]

	    /** The list of installation states for this eBook. */
	    userStateSummary?: UserInstallStateSummary[]

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

	    installedDeviceCount?: number

	    failedDeviceCount?: number

	    notApplicableDeviceCount?: number

	    notInstalledDeviceCount?: number

	    pendingInstallDeviceCount?: number

	    installedUserCount?: number

	    failedUserCount?: number

	    notApplicableUserCount?: number

	    notInstalledUserCount?: number

	    pendingInstallUserCount?: number

}

export interface MobileAppInstallStatus extends Entity {

	    deviceName?: string

	    deviceId?: string

	    lastSyncDateTime?: string

	    mobileAppInstallStatusValue?: ResultantAppState

	    installState?: ResultantAppState

	    errorCode?: number

	    osVersion?: string

	    osDescription?: string

	    userName?: string

	    userPrincipalName?: string

	    displayVersion?: string

	    app?: MobileApp

}

export interface UserAppInstallStatus extends Entity {

	    userName?: string

	    userPrincipalName?: string

	    installedDeviceCount?: number

	    failedDeviceCount?: number

	    notInstalledDeviceCount?: number

	    app?: MobileApp

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

	    isFrameworkFile?: boolean

}

export interface MobileAppProvisioningConfigGroupAssignment extends Entity {

	    targetGroupId?: string

}

export interface IosLobAppProvisioningConfigurationAssignment extends Entity {

	    target?: DeviceAndAppManagementAssignmentTarget

}

export interface ManagedDeviceMobileAppConfigurationDeviceStatus extends Entity {

	    deviceDisplayName?: string

	    userName?: string

	    deviceModel?: string

	    platform?: number

	    complianceGracePeriodExpirationDateTime?: string

	    status?: ComplianceStatus

	    lastReportedDateTime?: string

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

export interface MdmAppConfigGroupAssignment extends Entity {

	    appConfiguration?: string

	    targetGroupId?: string

}

export interface ManagedDeviceMobileAppConfigurationDeviceSummary extends Entity {

	    /** Number of pending devices */
	    pendingCount?: number

	    /** Number of not applicable devices */
	    notApplicableCount?: number

	    /** Number of succeeded devices */
	    successCount?: number

	    /** Number of error devices */
	    errorCount?: number

	    /** Number of failed devices */
	    failedCount?: number

	    /** Last update time */
	    lastUpdateDateTime?: string

	    /** Version of the policy for that overview */
	    configurationVersion?: number

}

export interface ManagedDeviceMobileAppConfigurationUserSummary extends Entity {

	    /** Number of pending Users */
	    pendingCount?: number

	    /** Number of not applicable devices */
	    notApplicableCount?: number

	    /** Number of succeeded Users */
	    successCount?: number

	    /** Number of error Users */
	    errorCount?: number

	    /** Number of failed Users */
	    failedCount?: number

	    /** Last update time */
	    lastUpdateDateTime?: string

	    /** Version of the policy for that overview */
	    configurationVersion?: number

}

export interface MacOSOfficeSuiteApp extends MobileApp {

}

export interface OfficeSuiteApp extends MobileApp {

	    autoAcceptEula?: boolean

	    productIds?: OfficeProductId[]

	    excludedApps?: ExcludedApps

	    useSharedComputerActivation?: boolean

	    updateChannel?: OfficeUpdateChannel

	    officePlatformArchitecture?: WindowsArchitecture

	    localesToInstall?: string[]

	    installProgressDisplayLevel?: OfficeSuiteInstallProgressDisplayLevel

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

}

export interface ManagedAndroidLobApp extends ManagedMobileLobApp {

	    /** The package identifier. */
	    packageId?: string

	    identityName?: string

	    /** The value for the minimum applicable operating system. */
	    minimumSupportedOperatingSystem?: AndroidMinimumOperatingSystem

	    /** The version name of managed Android Line of Business (LoB) app. */
	    versionName?: string

	    /** The version code of managed Android Line of Business (LoB) app. */
	    versionCode?: string

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

export interface WindowsMobileMSI extends MobileLobApp {

	    /** The command line. */
	    commandLine?: string

	    /** The product code. */
	    productCode?: string

	    /** The product version of Windows Mobile MSI Line of Business (LoB) app. */
	    productVersion?: string

	    /** A boolean to control whether the app's version will be used to detect the app after it is installed on a device. Set this to true for Windows Mobile MSI Line of Business (LoB) apps that use a self update feature. */
	    ignoreVersionDetection?: boolean

	    identityVersion?: string

}

export interface WindowsPhone81AppX extends MobileLobApp {

	    applicableArchitectures?: WindowsArchitecture

	    identityName?: string

	    identityPublisherHash?: string

	    identityResourceIdentifier?: string

	    minimumSupportedOperatingSystem?: WindowsMinimumOperatingSystem

	    phoneProductIdentifier?: string

	    phonePublisherId?: string

	    identityVersion?: string

}

export interface WindowsPhone81AppXBundle extends WindowsPhone81AppX {

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

}

export interface WindowsAppX extends MobileLobApp {

	    applicableArchitectures?: WindowsArchitecture

	    identityName?: string

	    identityPublisherHash?: string

	    identityResourceIdentifier?: string

	    isBundle?: boolean

	    minimumSupportedOperatingSystem?: WindowsMinimumOperatingSystem

	    identityVersion?: string

}

export interface WindowsPhoneXAP extends MobileLobApp {

	    minimumSupportedOperatingSystem?: WindowsMinimumOperatingSystem

	    productIdentifier?: string

	    identityVersion?: string

}

export interface AndroidLobApp extends MobileLobApp {

	    /** The package identifier. */
	    packageId?: string

	    identityName?: string

	    /** The value for the minimum applicable operating system. */
	    minimumSupportedOperatingSystem?: AndroidMinimumOperatingSystem

	    /** The version name of Android Line of Business (LoB) app. */
	    versionName?: string

	    /** The version code of Android Line of Business (LoB) app. */
	    versionCode?: string

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

	    identityVersion?: string

}

export interface AndroidForWorkApp extends MobileApp {

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

	    /** The app license type Possible values are: offline, online. */
	    licenseType?: MicrosoftStoreForBusinessLicenseType

	    /** The app package identifier */
	    packageIdentityName?: string

}

export interface WebApp extends MobileApp {

	    /** The web app URL. */
	    appUrl?: string

	    /** Whether or not to use managed browser. This property is only applicable for Android and IOS. */
	    useManagedBrowser?: boolean

}

export interface WindowsPhone81StoreApp extends MobileApp {

	    appStoreUrl?: string

}

export interface WindowsStoreApp extends MobileApp {

	    appStoreUrl?: string

}

export interface AndroidStoreApp extends MobileApp {

	    /** The package identifier. */
	    packageId?: string

	    appIdentifier?: string

	    /** The Android app store URL. */
	    appStoreUrl?: string

	    /** The value for the minimum applicable operating system. */
	    minimumSupportedOperatingSystem?: AndroidMinimumOperatingSystem

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

}

export interface AppleVolumePurchaseProgramToken extends Entity {

	    organizationName?: string

	    volumePurchaseProgramTokenAccountType?: VolumePurchaseProgramTokenAccountType

	    appleId?: string

	    expirationDateTime?: string

	    lastSyncDateTime?: string

	    token?: string

	    lastModifiedDateTime?: string

	    state?: VolumePurchaseProgramTokenState

	    lastSyncStatus?: VolumePurchaseProgramTokenSyncStatus

	    automaticallyUpdateApps?: boolean

	    countryOrRegion?: string

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

	    packageName?: string

	    payloadJson?: string

	    permissionActions?: AndroidPermissionAction[]

}

export interface IosMobileAppConfiguration extends ManagedDeviceMobileAppConfiguration {

	    settingXml?: string

	    settings?: AppConfigurationSettingItem[]

}

export interface TermsAndConditionsGroupAssignment extends Entity {

	    targetGroupId?: string

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

export interface ImportedDeviceIdentityResult extends ImportedDeviceIdentity {

	    status?: boolean

}

export interface ImportedAppleDeviceIdentityResult extends ImportedAppleDeviceIdentity {

	    status?: boolean

}

export interface DepEnrollmentProfile extends EnrollmentProfile {

	    supervisedModeEnabled?: boolean

	    supportDepartment?: string

	    passCodeDisabled?: boolean

	    isMandatory?: boolean

	    locationDisabled?: boolean

	    supportPhoneNumber?: string

	    iTunesPairingMode?: ITunesPairingMode

	    profileRemovalDisabled?: boolean

	    managementCertificates?: ManagementCertificateWithThumbprint[]

	    restoreBlocked?: boolean

	    restoreFromAndroidDisabled?: boolean

	    appleIdDisabled?: boolean

	    termsAndConditionsDisabled?: boolean

	    touchIdDisabled?: boolean

	    applePayDisabled?: boolean

	    zoomDisabled?: boolean

	    siriDisabled?: boolean

	    diagnosticsDisabled?: boolean

	    macOSRegistrationDisabled?: boolean

	    macOSFileVaultDisabled?: boolean

	    awaitDeviceConfiguredConfirmation?: boolean

	    sharedIPadMaximumUserCount?: number

	    enableSharedIPad?: boolean

}

export interface DeviceManagementScriptAssignment extends Entity {

	    target?: DeviceAndAppManagementAssignmentTarget

}

export interface DeviceManagementScriptGroupAssignment extends Entity {

	    targetGroupId?: string

}

export interface DeviceManagementScriptRunSummary extends Entity {

	    successDeviceCount?: number

	    errorDeviceCount?: number

	    successUserCount?: number

	    errorUserCount?: number

}

export interface DeviceManagementScriptDeviceState extends Entity {

	    runState?: RunState

	    resultMessage?: string

	    lastStateUpdateDateTime?: string

	    errorCode?: number

	    errorDescription?: string

	    managedDevice?: ManagedDevice

}

export interface DeviceManagementScriptUserState extends Entity {

	    successDeviceCount?: number

	    errorDeviceCount?: number

	    userPrincipalName?: string

	    deviceRunStates?: DeviceManagementScriptDeviceState[]

}

export interface DeviceConfigurationState extends Entity {

	    /** Not yet documented */
	    settingStates?: DeviceConfigurationSettingState[]

	    /** The name of the policy for this policyBase */
	    displayName?: string

	    /** The version of the policy */
	    version?: number

	    /** Platform type that the policy applies to Possible values are: android, iOS, macOS, windowsPhone81, windows81AndLater, windows10AndLater, all. */
	    platformType?: PolicyPlatformType

	    /** The compliance state of the policy Possible values are: unknown, notApplicable, compliant, remediated, nonCompliant, error, conflict. */
	    state?: ComplianceStatus

	    /** Count of how many setting a policy holds */
	    settingCount?: number

}

export interface WindowsProtectionState extends Entity {

	    malwareProtectionEnabled?: boolean

	    deviceState?: WindowsDeviceHealthState

	    realTimeProtectionEnabled?: boolean

	    networkInspectionSystemEnabled?: boolean

	    quickScanOverdue?: boolean

	    fullScanOverdue?: boolean

	    signatureUpdateOverdue?: boolean

	    rebootRequired?: boolean

	    fullScanRequired?: boolean

	    engineVersion?: string

	    signatureVersion?: string

	    antiMalwareVersion?: string

	    lastQuickScanDateTime?: string

	    lastFullScanDateTime?: string

	    lastQuickScanSignatureVersion?: string

	    lastFullScanSignatureVersion?: string

	    lastReportedDateTime?: string

	    detectedMalwareState?: WindowsDeviceMalwareState[]

}

export interface DeviceCompliancePolicyState extends Entity {

	    /** Not yet documented */
	    settingStates?: DeviceCompliancePolicySettingState[]

	    /** The name of the policy for this policyBase */
	    displayName?: string

	    /** The version of the policy */
	    version?: number

	    /** Platform type that the policy applies to Possible values are: android, iOS, macOS, windowsPhone81, windows81AndLater, windows10AndLater, all. */
	    platformType?: PolicyPlatformType

	    /** The compliance state of the policy Possible values are: unknown, notApplicable, compliant, remediated, nonCompliant, error, conflict. */
	    state?: ComplianceStatus

	    /** Count of how many setting a policy holds */
	    settingCount?: number

}

export interface WindowsDeviceMalwareState extends Entity {

	    displayName?: string

	    additionalInformationUrl?: string

	    severity?: WindowsMalwareSeverity

	    catetgory?: WindowsMalwareCategory

	    executionState?: WindowsMalwareExecutionState

	    state?: WindowsMalwareState

	    initialDetectionDateTime?: string

	    lastStateChangeDateTime?: string

	    detectionCount?: number

}

export interface WindowsManagedDevice extends ManagedDevice {

}

export interface WindowsManagementAppHealthSummary extends Entity {

	    healthyDeviceCount?: number

	    unhealthyDeviceCount?: number

	    unknownDeviceCount?: number

}

export interface WindowsManagementAppHealthState extends Entity {

	    healthState?: HealthState

	    installedVersion?: string

	    lastCheckInDateTime?: string

	    deviceName?: string

	    deviceOSVersion?: string

}

export interface ReportRoot extends Entity {

}

export interface DeviceConfigurationGroupAssignment extends Entity {

	    targetGroupId?: string

	    excludeGroup?: boolean

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

	    /** Number of succeeded devices */
	    successCount?: number

	    /** Number of error devices */
	    errorCount?: number

	    /** Number of failed devices */
	    failedCount?: number

	    /** Last update time */
	    lastUpdateDateTime?: string

	    /** Version of the policy for that overview */
	    configurationVersion?: number

}

export interface DeviceConfigurationUserOverview extends Entity {

	    /** Number of pending Users */
	    pendingCount?: number

	    /** Number of not applicable devices */
	    notApplicableCount?: number

	    /** Number of succeeded Users */
	    successCount?: number

	    /** Number of error Users */
	    errorCount?: number

	    /** Number of failed Users */
	    failedCount?: number

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

	    /** Number of succeeded devices */
	    successCount?: number

	    /** Number of error devices */
	    errorCount?: number

	    /** Number of failed devices */
	    failedCount?: number

	    /** Last update time */
	    lastUpdateDateTime?: string

	    /** Version of the policy for that overview */
	    configurationVersion?: number

}

export interface DeviceComplianceUserOverview extends Entity {

	    /** Number of pending Users */
	    pendingCount?: number

	    /** Number of not applicable devices */
	    notApplicableCount?: number

	    /** Number of succeeded Users */
	    successCount?: number

	    /** Number of error Users */
	    errorCount?: number

	    /** Number of failed Users */
	    failedCount?: number

	    /** Last update time */
	    lastUpdateDateTime?: string

	    /** Version of the policy for that overview */
	    configurationVersion?: number

}

export interface DeviceComplianceActionItem extends Entity {

	    /** Number of hours to wait till the action will be enforced. Valid values 0 to 8760 */
	    gracePeriodHours?: number

	    /** What action to take Possible values are: noAction, notification, block, retire, wipe, removeResourceAccessProfiles. */
	    actionType?: DeviceComplianceActionType

	    /** What notification Message template to use */
	    notificationTemplateId?: string

	    /** A list of group IDs to speicify who to CC this notification message to. */
	    notificationMessageCCList?: string[]

}

export interface AndroidDeviceComplianceLocalActionBase extends Entity {

	    gracePeriodInMinutes?: number

}

export interface WindowsPrivacyDataAccessControlItem extends Entity {

	    accessLevel?: WindowsPrivacyDataAccessLevel

	    dataCategory?: WindowsPrivacyDataCategory

	    appPackageFamilyName?: string

	    appDisplayName?: string

}

export interface WindowsAssignedAccessProfile extends Entity {

	    profileName?: string

	    showTaskBar?: boolean

	    appUserModelIds?: string[]

	    desktopAppPaths?: string[]

	    userAccounts?: string[]

	    startMenuLayoutXml?: number

}

export interface AndroidForWorkEasEmailProfileBase extends DeviceConfiguration {

	    authenticationMethod?: EasAuthenticationMethod

	    durationOfEmailToSync?: EmailSyncDuration

	    emailAddressSource?: UserEmailSource

	    hostName?: string

	    requireSsl?: boolean

	    usernameSource?: AndroidUsernameSource

	    identityCertificate?: AndroidForWorkCertificateProfileBase

}

export interface AndroidForWorkCertificateProfileBase extends DeviceConfiguration {

	    renewalThresholdPercentage?: number

	    subjectNameFormat?: SubjectNameFormat

	    subjectAlternativeNameType?: SubjectAlternativeNameType

	    certificateValidityPeriodValue?: number

	    certificateValidityPeriodScale?: CertificateValidityPeriodScale

	    extendedKeyUsages?: ExtendedKeyUsage[]

	    rootCertificate?: AndroidForWorkTrustedRootCertificate

}

export interface AndroidForWorkTrustedRootCertificate extends DeviceConfiguration {

	    trustedRootCertificate?: number

	    certFileName?: string

}

export interface AndroidForWorkPkcsCertificateProfile extends AndroidForWorkCertificateProfileBase {

	    certificationAuthority?: string

	    certificationAuthorityName?: string

	    certificateTemplateName?: string

	    subjectAlternativeNameFormatString?: string

}

export interface AndroidForWorkScepCertificateProfile extends AndroidForWorkCertificateProfileBase {

	    scepServerUrls?: string[]

	    subjectNameFormatString?: string

	    keyUsage?: KeyUsages

	    keySize?: KeySize

	    hashAlgorithm?: HashAlgorithms

	    subjectAlternativeNameFormatString?: string

	    managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface ManagedDeviceCertificateState extends Entity {

	    devicePlatform?: DevicePlatformType

	    certificateKeyUsage?: KeyUsages

	    certificateProfileDisplayName?: string

	    deviceDisplayName?: string

	    userDisplayName?: string

	    serverUrl?: string

	    certificateExpirationDateTime?: string

	    lastCertificateStateChangeDateTime?: string

	    certificateIssuer?: string

	    certificateThumbprint?: string

	    certificateSerialNumber?: string

	    certificateKeyLength?: number

	    enhancedKeyUsage?: string

}

export interface AndroidForWorkGmailEasConfiguration extends AndroidForWorkEasEmailProfileBase {

}

export interface AndroidForWorkNineWorkEasConfiguration extends AndroidForWorkEasEmailProfileBase {

	    syncCalendar?: boolean

	    syncContacts?: boolean

	    syncTasks?: boolean

}

export interface AndroidCertificateProfileBase extends DeviceConfiguration {

	    renewalThresholdPercentage?: number

	    subjectNameFormat?: SubjectNameFormat

	    subjectAlternativeNameType?: SubjectAlternativeNameType

	    certificateValidityPeriodValue?: number

	    certificateValidityPeriodScale?: CertificateValidityPeriodScale

	    extendedKeyUsages?: ExtendedKeyUsage[]

	    rootCertificate?: AndroidTrustedRootCertificate

}

export interface AndroidTrustedRootCertificate extends DeviceConfiguration {

	    trustedRootCertificate?: number

	    certFileName?: string

}

export interface AndroidForWorkImportedPFXCertificateProfile extends AndroidCertificateProfileBase {

}

export interface AndroidImportedPFXCertificateProfile extends AndroidCertificateProfileBase {

}

export interface AndroidPkcsCertificateProfile extends AndroidCertificateProfileBase {

	    certificationAuthority?: string

	    certificationAuthorityName?: string

	    certificateTemplateName?: string

	    subjectAlternativeNameFormatString?: string

}

export interface AndroidScepCertificateProfile extends AndroidCertificateProfileBase {

	    scepServerUrls?: string[]

	    subjectNameFormatString?: string

	    keyUsage?: KeyUsages

	    keySize?: KeySize

	    hashAlgorithm?: HashAlgorithms

	    subjectAlternativeNameFormatString?: string

	    managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface AndroidCustomConfiguration extends DeviceConfiguration {

	    /** OMA settings. This collection can contain a maximum of 1000 elements. */
	    omaSettings?: OmaSetting[]

}

export interface AndroidEasEmailProfileConfiguration extends DeviceConfiguration {

	    accountName?: string

	    authenticationMethod?: EasAuthenticationMethod

	    syncCalendar?: boolean

	    syncContacts?: boolean

	    syncTasks?: boolean

	    syncNotes?: boolean

	    durationOfEmailToSync?: EmailSyncDuration

	    emailAddressSource?: UserEmailSource

	    emailSyncSchedule?: EmailSyncSchedule

	    hostName?: string

	    requireSmime?: boolean

	    requireSsl?: boolean

	    usernameSource?: AndroidUsernameSource

	    identityCertificate?: AndroidCertificateProfileBase

	    smimeSigningCertificate?: AndroidCertificateProfileBase

}

export interface AndroidForWorkCustomConfiguration extends DeviceConfiguration {

	    omaSettings?: OmaSetting[]

}

export interface AndroidForWorkWiFiConfiguration extends DeviceConfiguration {

	    networkName?: string

	    ssid?: string

	    connectAutomatically?: boolean

	    connectWhenNetworkNameIsHidden?: boolean

	    wiFiSecurityType?: AndroidWiFiSecurityType

}

export interface AndroidForWorkEnterpriseWiFiConfiguration extends AndroidForWorkWiFiConfiguration {

	    eapType?: AndroidEapType

	    authenticationMethod?: WiFiAuthenticationMethod

	    innerAuthenticationProtocolForEapTtls?: NonEapAuthenticationMethodForEapTtlsType

	    innerAuthenticationProtocolForPeap?: NonEapAuthenticationMethodForPeap

	    outerIdentityPrivacyTemporaryValue?: string

	    rootCertificateForServerValidation?: AndroidForWorkTrustedRootCertificate

	    identityCertificateForClientAuthentication?: AndroidForWorkCertificateProfileBase

}

export interface AndroidForWorkGeneralDeviceConfiguration extends DeviceConfiguration {

	    passwordBlockFingerprintUnlock?: boolean

	    passwordBlockTrustAgents?: boolean

	    passwordExpirationDays?: number

	    passwordMinimumLength?: number

	    passwordMinutesOfInactivityBeforeScreenTimeout?: number

	    passwordPreviousPasswordBlockCount?: number

	    passwordSignInFailureCountBeforeFactoryReset?: number

	    passwordRequiredType?: AndroidForWorkRequiredPasswordType

	    workProfileDataSharingType?: AndroidForWorkCrossProfileDataSharingType

	    workProfileBlockNotificationsWhileDeviceLocked?: boolean

	    workProfileBlockAddingAccounts?: boolean

	    workProfileBlockCrossProfileCopyPaste?: boolean

	    workProfileDefaultAppPermissionPolicy?: AndroidForWorkDefaultAppPermissionPolicyType

	    workProfilePasswordBlockFingerprintUnlock?: boolean

	    workProfilePasswordBlockTrustAgents?: boolean

	    workProfilePasswordExpirationDays?: number

	    workProfilePasswordMinimumLength?: number

	    workProfilePasswordMinutesOfInactivityBeforeScreenTimeout?: number

	    workProfilePasswordPreviousPasswordBlockCount?: number

	    workProfilePasswordSignInFailureCountBeforeFactoryReset?: number

	    workProfilePasswordRequiredType?: AndroidForWorkRequiredPasswordType

	    workProfileRequirePassword?: boolean

	    securityRequireVerifyApps?: boolean

}

export interface AndroidForWorkVpnConfiguration extends DeviceConfiguration {

	    connectionName?: string

	    connectionType?: AndroidForWorkVpnConnectionType

	    role?: string

	    realm?: string

	    servers?: VpnServer[]

	    fingerprint?: string

	    customData?: KeyValue[]

	    authenticationMethod?: VpnAuthenticationMethod

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

	    connectionName?: string

	    connectionType?: AndroidVpnConnectionType

	    role?: string

	    realm?: string

	    servers?: VpnServer[]

	    fingerprint?: string

	    customData?: KeyValue[]

	    authenticationMethod?: VpnAuthenticationMethod

	    identityCertificate?: AndroidCertificateProfileBase

}

export interface AndroidWiFiConfiguration extends DeviceConfiguration {

	    networkName?: string

	    ssid?: string

	    connectAutomatically?: boolean

	    connectWhenNetworkNameIsHidden?: boolean

	    wiFiSecurityType?: AndroidWiFiSecurityType

}

export interface AndroidEnterpriseWiFiConfiguration extends AndroidWiFiConfiguration {

	    eapType?: AndroidEapType

	    authenticationMethod?: WiFiAuthenticationMethod

	    innerAuthenticationProtocolForEapTtls?: NonEapAuthenticationMethodForEapTtlsType

	    innerAuthenticationProtocolForPeap?: NonEapAuthenticationMethodForPeap

	    outerIdentityPrivacyTemporaryValue?: string

	    rootCertificateForServerValidation?: AndroidTrustedRootCertificate

	    identityCertificateForClientAuthentication?: AndroidCertificateProfileBase

}

export interface IosCertificateProfile extends DeviceConfiguration {

}

export interface IosCertificateProfileBase extends IosCertificateProfile {

	    renewalThresholdPercentage?: number

	    subjectNameFormat?: AppleSubjectNameFormat

	    subjectAlternativeNameType?: SubjectAlternativeNameType

	    certificateValidityPeriodValue?: number

	    certificateValidityPeriodScale?: CertificateValidityPeriodScale

}

export interface IosPkcsCertificateProfile extends IosCertificateProfileBase {

	    certificationAuthority?: string

	    certificationAuthorityName?: string

	    certificateTemplateName?: string

	    subjectAlternativeNameFormatString?: string

}

export interface IosScepCertificateProfile extends IosCertificateProfileBase {

	    scepServerUrls?: string[]

	    subjectNameFormatString?: string

	    keyUsage?: KeyUsages

	    keySize?: KeySize

	    extendedKeyUsages?: ExtendedKeyUsage[]

	    subjectAlternativeNameFormatString?: string

	    rootCertificate?: IosTrustedRootCertificate

	    managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface IosTrustedRootCertificate extends DeviceConfiguration {

	    trustedRootCertificate?: number

	    certFileName?: string

}

export interface IosImportedPFXCertificateProfile extends IosCertificateProfile {

}

export interface IosCustomConfiguration extends DeviceConfiguration {

	    /** Name that is displayed to the user. */
	    payloadName?: string

	    /** Payload file name (.mobileconfig */
	    payloadFileName?: string

	    /** Payload. (UTF8 encoded byte array) */
	    payload?: number

}

export interface IosEasEmailProfileConfiguration extends DeviceConfiguration {

	    accountName?: string

	    authenticationMethod?: EasAuthenticationMethod

	    blockMovingMessagesToOtherEmailAccounts?: boolean

	    blockSendingEmailFromThirdPartyApps?: boolean

	    blockSyncingRecentlyUsedEmailAddresses?: boolean

	    durationOfEmailToSync?: EmailSyncDuration

	    emailAddressSource?: UserEmailSource

	    hostName?: string

	    requireSmime?: boolean

	    smimeEnablePerMessageSwitch?: boolean

	    requireSsl?: boolean

	    usernameSource?: UserEmailSource

	    identityCertificate?: IosCertificateProfileBase

	    smimeSigningCertificate?: IosCertificateProfile

	    smimeEncryptionCertificate?: IosCertificateProfile

}

export interface IosEduDeviceConfiguration extends DeviceConfiguration {

	    teacherCertificateSettings?: IosEduCertificateSettings

	    studentCertificateSettings?: IosEduCertificateSettings

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

	    /** Indicates whether or not to block  the user from continuing work they started on iOS device to another iOS or macOS device. */
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

	    /** Media content rating settings for Apps Possible values are: allAllowed, allBlocked, agesAbove4, agesAbove9, agesAbove12, agesAbove17. */
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

	    isEnabled?: boolean

	    /** Active Hours Start (active hours mean the time window when updates install should not happen) */
	    activeHoursStart?: string

	    /** Active Hours End (active hours mean the time window when updates install should not happen) */
	    activeHoursEnd?: string

	    /** Days in week for which active hours are configured. This collection can contain a maximum of 7 elements. */
	    scheduledInstallDays?: DayOfWeek[]

	    /** UTC Time Offset indicated in minutes */
	    utcTimeOffsetInMinutes?: number

}

export interface IosWiFiConfiguration extends DeviceConfiguration {

	    networkName?: string

	    ssid?: string

	    connectAutomatically?: boolean

	    connectWhenNetworkNameIsHidden?: boolean

	    wiFiSecurityType?: WiFiSecurityType

	    proxySettings?: WiFiProxySetting

	    proxyManualAddress?: string

	    proxyManualPort?: number

	    proxyAutomaticConfigurationUrl?: string

	    preSharedKey?: string

}

export interface IosEnterpriseWiFiConfiguration extends IosWiFiConfiguration {

	    eapType?: EapType

	    eapFastConfiguration?: EapFastConfiguration

	    trustedServerCertificateNames?: string[]

	    authenticationMethod?: WiFiAuthenticationMethod

	    innerAuthenticationProtocolForEapTtls?: NonEapAuthenticationMethodForEapTtlsType

	    outerIdentityPrivacyTemporaryValue?: string

	    rootCertificatesForServerValidation?: IosTrustedRootCertificate[]

	    identityCertificateForClientAuthentication?: IosCertificateProfileBase

}

export interface MacOSCertificateProfileBase extends DeviceConfiguration {

	    renewalThresholdPercentage?: number

	    subjectNameFormat?: AppleSubjectNameFormat

	    subjectAlternativeNameType?: SubjectAlternativeNameType

	    certificateValidityPeriodValue?: number

	    certificateValidityPeriodScale?: CertificateValidityPeriodScale

}

export interface MacOSScepCertificateProfile extends MacOSCertificateProfileBase {

	    scepServerUrls?: string[]

	    subjectNameFormatString?: string

	    keyUsage?: KeyUsages

	    keySize?: KeySize

	    hashAlgorithm?: HashAlgorithms

	    extendedKeyUsages?: ExtendedKeyUsage[]

	    subjectAlternativeNameFormatString?: string

	    rootCertificate?: MacOSTrustedRootCertificate

	    managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface MacOSTrustedRootCertificate extends DeviceConfiguration {

	    trustedRootCertificate?: number

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

}

export interface MacOSWiFiConfiguration extends DeviceConfiguration {

	    networkName?: string

	    ssid?: string

	    connectAutomatically?: boolean

	    connectWhenNetworkNameIsHidden?: boolean

	    wiFiSecurityType?: WiFiSecurityType

	    proxySettings?: WiFiProxySetting

	    proxyManualAddress?: string

	    proxyManualPort?: number

	    proxyAutomaticConfigurationUrl?: string

	    preSharedKey?: string

}

export interface MacOSEnterpriseWiFiConfiguration extends MacOSWiFiConfiguration {

	    eapType?: EapType

	    eapFastConfiguration?: EapFastConfiguration

	    trustedServerCertificateNames?: string[]

	    authenticationMethod?: WiFiAuthenticationMethod

	    innerAuthenticationProtocolForEapTtls?: NonEapAuthenticationMethodForEapTtlsType

	    outerIdentityPrivacyTemporaryValue?: string

	    rootCertificateForServerValidation?: MacOSTrustedRootCertificate

	    identityCertificateForClientAuthentication?: MacOSCertificateProfileBase

}

export interface AppleDeviceFeaturesConfigurationBase extends DeviceConfiguration {

	    airPrintDestinations?: AirPrintDestination[]

}

export interface IosDeviceFeaturesConfiguration extends AppleDeviceFeaturesConfigurationBase {

	    /** Asset tag information for the device, displayed on the login window and lock screen. */
	    assetTagTemplate?: string

	    contentFilterSettings?: IosWebContentFilterBase

	    /** A footnote displayed on the login window and lock screen. Available in iOS 9.3.1 and later. */
	    lockScreenFootnote?: string

	    /** A list of app and folders to appear on the Home Screen Dock. This collection can contain a maximum of 500 elements. */
	    homeScreenDockIcons?: IosHomeScreenItem[]

	    /** A list of pages on the Home Screen. This collection can contain a maximum of 500 elements. */
	    homeScreenPages?: IosHomeScreenPage[]

	    /** Notification settings for each bundle id. Applicable to devices in supervised mode only (iOS 9.3 and later). This collection can contain a maximum of 500 elements. */
	    notificationSettings?: IosNotificationSettings[]

	    singleSignOnSettings?: IosSingleSignOnSettings

	    identityCertificateForClientAuthentication?: IosCertificateProfileBase

}

export interface MacOSDeviceFeaturesConfiguration extends AppleDeviceFeaturesConfigurationBase {

}

export interface AppleVpnConfiguration extends DeviceConfiguration {

	    connectionName?: string

	    connectionType?: AppleVpnConnectionType

	    loginGroupOrDomain?: string

	    role?: string

	    realm?: string

	    server?: VpnServer

	    identifier?: string

	    customData?: KeyValue[]

	    enableSplitTunneling?: boolean

	    authenticationMethod?: VpnAuthenticationMethod

	    enablePerApp?: boolean

	    safariDomains?: string[]

	    onDemandRules?: VpnOnDemandRule[]

	    proxyServer?: VpnProxyServer

}

export interface IosVpnConfiguration extends AppleVpnConfiguration {

	    identityCertificate?: IosCertificateProfileBase

}

export interface MacOSVpnConfiguration extends AppleVpnConfiguration {

	    identityCertificate?: MacOSCertificateProfileBase

}

export interface WindowsDefenderAdvancedThreatProtectionConfiguration extends DeviceConfiguration {

	    advancedThreatProtectionOnboardingBlob?: string

	    /** Windows Defender AdvancedThreatProtection "Allow Sample Sharing" Rule */
	    allowSampleSharing?: boolean

	    /** Expedite Windows Defender Advanced Threat Protection telemetry reporting frequency. */
	    enableExpeditedTelemetryReporting?: boolean

	    advancedThreatProtectionOffboardingBlob?: string

}

export interface Windows10EndpointProtectionConfiguration extends DeviceConfiguration {

	    localSecurityOptionsBlockMicrosoftAccounts?: boolean

	    localSecurityOptionsEnableAdministratorAccount?: boolean

	    defenderSecurityCenterDisableAppBrowserUI?: boolean

	    defenderSecurityCenterDisableFamilyUI?: boolean

	    defenderSecurityCenterDisableHealthUI?: boolean

	    defenderSecurityCenterDisableNetworkUI?: boolean

	    defenderSecurityCenterDisableVirusUI?: boolean

	    defenderSecurityCenterOrganizationDisplayName?: string

	    defenderSecurityCenterHelpEmail?: string

	    defenderSecurityCenterHelpPhone?: string

	    defenderSecurityCenterHelpURL?: string

	    defenderSecurityCenterNotificationsFromApp?: DefenderSecurityCenterNotificationsFromAppType

	    defenderSecurityCenterITContactDisplay?: DefenderSecurityCenterITContactDisplayType

	    /** Blocks stateful FTP connections to the device */
	    firewallBlockStatefulFTP?: boolean

	    /** Configures the idle timeout for security associations, in seconds, from 300 to 3600 inclusive. This is the period after which security associations will expire and be deleted. Valid values 300 to 3600 */
	    firewallIdleTimeoutForSecurityAssociationInSeconds?: number

	    /** Select the preshared key encoding to be used Possible values are: deviceDefault, none, utF8. */
	    firewallPreSharedKeyEncodingMethod?: FirewallPreSharedKeyEncodingMethodType

	    /** Configures IPSec exemptions to allow neighbor discovery IPv6 ICMP type-codes */
	    firewallIPSecExemptionsAllowNeighborDiscovery?: boolean

	    /** Configures IPSec exemptions to allow ICMP */
	    firewallIPSecExemptionsAllowICMP?: boolean

	    /** Configures IPSec exemptions to allow router discovery IPv6 ICMP type-codes */
	    firewallIPSecExemptionsAllowRouterDiscovery?: boolean

	    /** Configures IPSec exemptions to allow both IPv4 and IPv6 DHCP traffic */
	    firewallIPSecExemptionsAllowDHCP?: boolean

	    /** Specify how the certificate revocation list is to be enforced Possible values are: deviceDefault, none, attempt, require. */
	    firewallCertificateRevocationListCheckMethod?: FirewallCertificateRevocationListCheckMethodType

	    /** If an authentication set is not fully supported by a keying module, direct the module to ignore only unsupported authentication suites rather than the entire set */
	    firewallMergeKeyingModuleSettings?: boolean

	    /** Configures how packet queueing should be applied in the tunnel gateway scenario Possible values are: deviceDefault, disabled, queueInbound, queueOutbound, queueBoth. */
	    firewallPacketQueueingMethod?: FirewallPacketQueueingMethodType

	    /** Configures the firewall profile settings for domain networks */
	    firewallProfileDomain?: WindowsFirewallNetworkProfile

	    /** Configures the firewall profile settings for public networks */
	    firewallProfilePublic?: WindowsFirewallNetworkProfile

	    /** Configures the firewall profile settings for private networks */
	    firewallProfilePrivate?: WindowsFirewallNetworkProfile

	    /** List of exe files and folders to be excluded from attack surface reduction rules */
	    defenderAttackSurfaceReductionExcludedPaths?: string[]

	    defenderOfficeAppsOtherProcessInjectionType?: DefenderAttackSurfaceType

	    defenderOfficeAppsExecutableContentCreationOrLaunchType?: DefenderAttackSurfaceType

	    defenderOfficeAppsLaunchChildProcessType?: DefenderAttackSurfaceType

	    defenderOfficeMacroCodeAllowWin32ImportsType?: DefenderAttackSurfaceType

	    defenderScriptObfuscatedMacroCodeType?: DefenderAttackSurfaceType

	    defenderScriptDownloadedPayloadExecutionType?: DefenderAttackSurfaceType

	    defenderPreventCredentialStealingType?: DefenderProtectionType

	    defenderProcessCreationType?: DefenderAttackSurfaceType

	    defenderUntrustedUSBProcessType?: DefenderAttackSurfaceType

	    defenderUntrustedExecutableType?: DefenderAttackSurfaceType

	    defenderEmailContentExecutionType?: DefenderAttackSurfaceType

	    defenderPasswordProtectedEmailContentExecutionType?: DefenderAttackSurfaceType

	    defenderAdvancedRansomewareProtectionType?: DefenderProtectionType

	    defenderGuardMyFoldersType?: FolderProtectionType

	    /** List of paths to exe that are allowed to access protected folders */
	    defenderGuardedFoldersAllowedAppPaths?: string[]

	    /** List of folder paths to be added to the list of protected folders */
	    defenderAdditionalGuardedFolders?: string[]

	    defenderNetworkProtectionType?: DefenderProtectionType

	    /** Xml content containing information regarding exploit protection details. */
	    defenderExploitProtectionXml?: number

	    /** Name of the file from which DefenderExploitProtectionXml was obtained. */
	    defenderExploitProtectionXmlFileName?: string

	    /** Indicates whether or not to block user from overriding Exploit Protection settings. */
	    defenderSecurityCenterBlockExploitProtectionOverride?: boolean

	    /** Enables the Admin to choose what types of app to allow on devices. Possible values are: notConfigured, enforceComponentsAndStoreApps, auditComponentsAndStoreApps, enforceComponentsStoreAppsAndSmartlocker, auditComponentsStoreAppsAndSmartlocker. */
	    appLockerApplicationControl?: AppLockerApplicationControlType

	    /** Allows IT Admins to configure SmartScreen for Windows. */
	    smartScreenEnableInShell?: boolean

	    /** Allows IT Admins to control whether users can can ignore SmartScreen warnings and run malicious files. */
	    smartScreenBlockOverrideForFiles?: boolean

	    /** Enable Windows Defender Application Guard */
	    applicationGuardEnabled?: boolean

	    /** Block clipboard to transfer image file, text file or neither of them Possible values are: notConfigured, blockImageAndTextFile, blockImageFile, blockNone, blockTextFile. */
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

	    applicationGuardAllowVirtualGPU?: boolean

	    applicationGuardAllowFileSaveOnHost?: boolean

	    /** Allows the Admin to disable the warning prompt for other disk encryption on the user machines. */
	    bitLockerDisableWarningForOtherDiskEncryption?: boolean

	    /** Allows the admin to require encryption to be turned on using BitLocker. This policy is valid only for a mobile SKU. */
	    bitLockerEnableStorageCardEncryptionOnMobile?: boolean

	    /** Allows the admin to require encryption to be turned on using BitLocker. */
	    bitLockerEncryptDevice?: boolean

	    bitLockerSystemDrivePolicy?: BitLockerSystemDrivePolicy

	    bitLockerFixedDrivePolicy?: BitLockerFixedDrivePolicy

	    /** BitLocker Removable Drive Policy. */
	    bitLockerRemovableDrivePolicy?: BitLockerRemovableDrivePolicy

}

export interface Windows10GeneralConfiguration extends DeviceConfiguration {

	    enableAutomaticRedeployment?: boolean

	    assignedAccessSingleModeUserName?: string

	    assignedAccessSingleModeAppUserModelId?: string

	    microsoftAccountSignInAssistantSettings?: SignInAssistantOptions

	    authenticationAllowSecondaryDevice?: boolean

	    authenticationAllowFIDODevice?: boolean

	    cryptographyAllowFipsAlgorithmPolicy?: boolean

	    displayAppListWithGdiDPIScalingTurnedOn?: string[]

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

	    messagingBlockSync?: boolean

	    messagingBlockMMS?: boolean

	    messagingBlockRichCommunicationServices?: boolean

	    /** Specifies if search can use diacritics. */
	    searchBlockDiacritics?: boolean

	    /** Specifies whether to use automatic language detection when indexing content and properties. */
	    searchDisableAutoLanguageDetection?: boolean

	    /** Indicates whether or not to block indexing of WIP-protected items to prevent them from appearing in search results for Cortana or Explorer. */
	    searchDisableIndexingEncryptedItems?: boolean

	    /** Indicates whether or not to block remote queries of this computer’s index. */
	    searchEnableRemoteQueries?: boolean

	    searchDisableUseLocation?: boolean

	    /** Indicates whether or not to disable the search indexer backoff feature. */
	    searchDisableIndexerBackoff?: boolean

	    /** Indicates whether or not to allow users to add locations on removable drives to libraries and to be indexed. */
	    searchDisableIndexingRemovableDrive?: boolean

	    /** Specifies minimum amount of hard drive space on the same drive as the index location before indexing stops. */
	    searchEnableAutomaticIndexSizeManangement?: boolean

	    securityBlockAzureADJoinedDevicesAutoEncryption?: boolean

	    /** Gets or sets a value allowing the device to send diagnostic and usage telemetry data, such as Watson. Possible values are: userDefined, none, basic, enhanced, full. */
	    diagnosticsDataSubmissionMode?: DiagnosticDataSubmissionMode

	    /** Gets or sets a value allowing IT admins to prevent apps and features from working with files on OneDrive. */
	    oneDriveDisableFileSync?: boolean

	    systemTelemetryProxyServer?: string

	    inkWorkspaceAccess?: InkAccessSetting

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

	    edgeFavoritesListLocation?: string

	    edgeBlockEditFavorites?: boolean

	    /** Whether or not to Block the user from using data over cellular while roaming. */
	    cellularBlockDataWhenRoaming?: boolean

	    /** Whether or not to Block the user from using VPN over cellular. */
	    cellularBlockVpn?: boolean

	    /** Whether or not to Block the user from using VPN when roaming over cellular. */
	    cellularBlockVpnWhenRoaming?: boolean

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

	    defenderPotentiallyUnwantedAppAction?: DefenderPotentiallyUnwantedAppAction

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

	    defenderCloudExtendedTimeout?: number

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

	    /** Enables or disables the use of advertising ID. Added in Windows 10, version 1607. Possible values are: notConfigured, blocked, allowed. */
	    privacyAdvertisingId?: StateManagementSetting

	    /** Indicates whether or not to allow the automatic acceptance of the pairing and privacy user consent dialog when launching apps. */
	    privacyAutoAcceptPairingAndConsentPrompts?: boolean

	    /** Indicates whether or not to block the usage of cloud based speech services for Cortana, Dictation, or Store applications. */
	    privacyBlockInputPersonalization?: boolean

	    privacyBlockPublishUserActivities?: boolean

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

	    /** Specifies the type of Spotlight Possible values are: notConfigured, disabled, enabled. */
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

	    assignedAccessMultiModeProfiles?: WindowsAssignedAccessProfile[]

	    privacyAccessControls?: WindowsPrivacyDataAccessControlItem[]

}

export interface Windows10NetworkBoundaryConfiguration extends DeviceConfiguration {

	    windowsNetworkIsolationPolicy?: WindowsNetworkIsolationPolicy

}

export interface Windows10CustomConfiguration extends DeviceConfiguration {

	    /** OMA settings. This collection can contain a maximum of 1000 elements. */
	    omaSettings?: OmaSetting[]

}

export interface Windows10KioskConfiguration extends DeviceConfiguration {

}

export interface Windows10EasEmailProfileConfiguration extends DeviceConfiguration {

	    accountName?: string

	    syncCalendar?: boolean

	    syncContacts?: boolean

	    syncTasks?: boolean

	    durationOfEmailToSync?: EmailSyncDuration

	    emailAddressSource?: UserEmailSource

	    emailSyncSchedule?: EmailSyncSchedule

	    hostName?: string

	    requireSsl?: boolean

	    usernameSource?: UserEmailSource

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

	    /** Specifies whether local storage is allowed on a shared PC. */
	    allowLocalStorage?: boolean

	    /** Disables the account manager for shared PC mode. */
	    disableAccountManager?: boolean

	    /** Specifies whether the default shared PC education environment policies should be disabled. For Windows 10 RS2 and later, this policy will be applied without setting Enabled to true. */
	    disableEduPolicies?: boolean

	    /** Specifies whether the default shared PC power policies should be disabled. */
	    disablePowerPolicies?: boolean

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

	    keyStorageProvider?: KeyStorageProviderOption

}

export interface Windows10SecureAssessmentConfiguration extends DeviceConfiguration {

	    /** Url link to an assessment that's automatically loaded when the secure assessment browser is launched. It has to be a valid Url (http[s]://msdn.microsoft.com/). */
	    launchUri?: string

	    /** The account used to configure the Windows device for taking the test. The user can be a domain account (domain\user), an AAD account (username@tenant.com) or a local account (username). */
	    configurationAccount?: string

	    configurationAccountType?: SecureAssessmentAccountType

	    /** Indicates whether or not to allow the app from printing during the test. */
	    allowPrinting?: boolean

	    /** Indicates whether or not to allow screen capture capability during a test. */
	    allowScreenCapture?: boolean

	    /** Indicates whether or not to allow text suggestions during the test. */
	    allowTextSuggestion?: boolean

	    printerNames?: string[]

	    defaultPrinterName?: string

	    blockAddingNewPrinter?: boolean

}

export interface Windows81WifiImportConfiguration extends DeviceConfiguration {

	    payloadFileName?: string

	    profileName?: string

	    payload?: number

}

export interface WindowsCertificateProfileBase extends DeviceConfiguration {

	    renewalThresholdPercentage?: number

	    keyStorageProvider?: KeyStorageProviderOption

	    subjectNameFormat?: SubjectNameFormat

	    subjectAlternativeNameType?: SubjectAlternativeNameType

	    certificateValidityPeriodValue?: number

	    certificateValidityPeriodScale?: CertificateValidityPeriodScale

}

export interface Windows10ImportedPFXCertificateProfile extends WindowsCertificateProfileBase {

}

export interface WindowsPhone81ImportedPFXCertificateProfile extends WindowsCertificateProfileBase {

}

export interface Windows10CertificateProfileBase extends WindowsCertificateProfileBase {

}

export interface Windows10PkcsCertificateProfile extends Windows10CertificateProfileBase {

	    certificationAuthority?: string

	    certificationAuthorityName?: string

	    certificateTemplateName?: string

	    subjectAlternativeNameFormatString?: string

}

export interface Windows81CertificateProfileBase extends WindowsCertificateProfileBase {

	    extendedKeyUsages?: ExtendedKeyUsage[]

}

export interface Windows81SCEPCertificateProfile extends Windows81CertificateProfileBase {

	    scepServerUrls?: string[]

	    subjectNameFormatString?: string

	    keyUsage?: KeyUsages

	    keySize?: KeySize

	    hashAlgorithm?: HashAlgorithms

	    subjectAlternativeNameFormatString?: string

	    rootCertificate?: Windows81TrustedRootCertificate

	    managedDeviceCertificateStates?: ManagedDeviceCertificateState[]

}

export interface Windows81TrustedRootCertificate extends DeviceConfiguration {

	    trustedRootCertificate?: number

	    certFileName?: string

	    destinationStore?: CertificateDestinationStore

}

export interface WindowsPhone81CustomConfiguration extends DeviceConfiguration {

	    /** OMA settings. This collection can contain a maximum of 1000 elements. */
	    omaSettings?: OmaSetting[]

}

export interface WindowsPhone81TrustedRootCertificate extends DeviceConfiguration {

	    trustedRootCertificate?: number

	    certFileName?: string

}

export interface WindowsPhoneEASEmailProfileConfiguration extends DeviceConfiguration {

	    accountName?: string

	    applyOnlyToWindowsPhone81?: boolean

	    syncCalendar?: boolean

	    syncContacts?: boolean

	    syncTasks?: boolean

	    durationOfEmailToSync?: EmailSyncDuration

	    emailAddressSource?: UserEmailSource

	    emailSyncSchedule?: EmailSyncSchedule

	    hostName?: string

	    requireSsl?: boolean

	    usernameSource?: UserEmailSource

}

export interface WindowsUpdateForBusinessConfiguration extends DeviceConfiguration {

	    /** Delivery Optimization Mode Possible values are: userDefined, httpOnly, httpWithPeeringNat, httpWithPeeringPrivateGroup, httpWithInternetPeering, simpleDownload, bypassMode. */
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

	    /** Determines which branch devices will receive their updates from Possible values are: userDefined, all, businessReadyOnly. */
	    businessReadyUpdatesOnly?: WindowsUpdateType

	    previewBuildSetting?: WindowsUpdateInsiderBuildControl

}

export interface WindowsVpnConfiguration extends DeviceConfiguration {

	    connectionName?: string

	    servers?: VpnServer[]

	    customXml?: number

}

export interface Windows10VpnConfiguration extends WindowsVpnConfiguration {

	    connectionType?: Windows10VpnConnectionType

	    enableSplitTunneling?: boolean

	    authenticationMethod?: Windows10VpnAuthenticationMethod

	    rememberUserCredentials?: boolean

	    enableConditionalAccess?: boolean

	    enableSingleSignOnWithAlternateCertificate?: boolean

	    singleSignOnEku?: ExtendedKeyUsage

	    singleSignOnIssuerHash?: string

	    eapXml?: number

	    proxyServer?: Windows10VpnProxyServer

	    associatedApps?: Windows10AssociatedApps[]

	    onlyAssociatedAppsCanUseConnection?: boolean

	    windowsInformationProtectionDomain?: string

	    trafficRules?: VpnTrafficRule[]

	    routes?: VpnRoute[]

	    dnsRules?: VpnDnsRule[]

	    identityCertificate?: WindowsCertificateProfileBase

}

export interface Windows81VpnConfiguration extends WindowsVpnConfiguration {

	    applyOnlyToWindows81?: boolean

	    connectionType?: WindowsVpnConnectionType

	    loginGroupOrDomain?: string

	    enableSplitTunneling?: boolean

	    proxyServer?: Windows81VpnProxyServer

}

export interface WindowsPhone81VpnConfiguration extends Windows81VpnConfiguration {

	    bypassVpnOnCompanyWifi?: boolean

	    bypassVpnOnHomeWifi?: boolean

	    authenticationMethod?: VpnAuthenticationMethod

	    rememberUserCredentials?: boolean

	    dnsSuffixSearchList?: string[]

	    identityCertificate?: WindowsPhone81CertificateProfileBase

}

export interface WindowsPhone81CertificateProfileBase extends DeviceConfiguration {

	    renewalThresholdPercentage?: number

	    keyStorageProvider?: KeyStorageProviderOption

	    subjectNameFormat?: SubjectNameFormat

	    subjectAlternativeNameType?: SubjectAlternativeNameType

	    certificateValidityPeriodValue?: number

	    certificateValidityPeriodScale?: CertificateValidityPeriodScale

	    extendedKeyUsages?: ExtendedKeyUsage[]

}

export interface WindowsPhone81SCEPCertificateProfile extends WindowsPhone81CertificateProfileBase {

	    scepServerUrls?: string[]

	    subjectNameFormatString?: string

	    keyUsage?: KeyUsages

	    keySize?: KeySize

	    hashAlgorithm?: HashAlgorithms

	    subjectAlternativeNameFormatString?: string

	    rootCertificate?: WindowsPhone81TrustedRootCertificate

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

	    minimumAutoInstallClassification?: UpdateClassification

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

	    /** Maintenance window duration for device updates. Valid values 1 to 5 */
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

export interface EditionUpgradeConfiguration extends DeviceConfiguration {

	    /** Edition Upgrade License Type. Possible values are: productKey, licenseFile. */
	    licenseType?: EditionUpgradeLicenseType

	    /** Edition Upgrade Target Edition. Possible values are: windows10Enterprise, windows10EnterpriseN, windows10Education, windows10EducationN, windows10MobileEnterprise, windows10HolographicEnterprise, windows10Professional, windows10ProfessionalN, windows10ProfessionalEducation, windows10ProfessionalEducationN, windows10ProfessionalWorkstation, windows10ProfessionalWorkstationN. */
	    targetEdition?: Windows10EditionType

	    /** Edition Upgrade License File Content. */
	    license?: string

	    /** Edition Upgrade Product Key. */
	    productKey?: string

}

export interface DeviceCompliancePolicyGroupAssignment extends Entity {

	    targetGroupId?: string

	    excludeGroup?: boolean

	    deviceCompliancePolicy?: DeviceCompliancePolicy

}

export interface AndroidForWorkCompliancePolicy extends DeviceCompliancePolicy {

	    passwordRequired?: boolean

	    passwordMinimumLength?: number

	    passwordRequiredType?: AndroidRequiredPasswordType

	    passwordMinutesOfInactivityBeforeLock?: number

	    passwordExpirationDays?: number

	    passwordPreviousPasswordBlockCount?: number

	    securityPreventInstallAppsFromUnknownSources?: boolean

	    securityDisableUsbDebugging?: boolean

	    securityRequireVerifyApps?: boolean

	    deviceThreatProtectionEnabled?: boolean

	    deviceThreatProtectionRequiredSecurityLevel?: DeviceThreatProtectionLevel

	    securityBlockJailbrokenDevices?: boolean

	    osMinimumVersion?: string

	    osMaximumVersion?: string

	    minAndroidSecurityPatchLevel?: string

	    storageRequireEncryption?: boolean

	    securityRequireSafetyNetAttestationBasicIntegrity?: boolean

	    securityRequireSafetyNetAttestationCertifiedDevice?: boolean

	    securityRequireGooglePlayServices?: boolean

	    securityRequireUpToDateSecurityProviders?: boolean

	    securityRequireCompanyPortalAppIntegrity?: boolean

}

export interface AndroidCompliancePolicy extends DeviceCompliancePolicy {

	    /** Require a password to unlock device. */
	    passwordRequired?: boolean

	    /** Minimum password length. Valid values 4 to 16 */
	    passwordMinimumLength?: number

	    /** Type of characters in password Possible values are: deviceDefault, alphabetic, alphanumeric, alphanumericWithSymbols, lowSecurityBiometric, numeric, numericComplex, any. */
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

	    conditionStatementId?: string

	    localActions?: AndroidDeviceComplianceLocalActionBase[]

}

export interface AndroidDeviceComplianceLocalActionLockDevice extends AndroidDeviceComplianceLocalActionBase {

}

export interface AndroidDeviceComplianceLocalActionLockDeviceWithPasscode extends AndroidDeviceComplianceLocalActionBase {

	    passcode?: string

	    passcodeSignInFailureCountBeforeWipe?: number

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

	    activeFirewallRequired?: boolean

	    uacRequired?: boolean

	    defenderEnabled?: boolean

	    defenderVersion?: string

	    signatureOutOfDate?: boolean

	    rtpEnabled?: boolean

	    validOperatingSystemBuildRanges?: OperatingSystemVersionRange[]

	    deviceThreatProtectionEnabled?: boolean

	    deviceThreatProtectionRequiredSecurityLevel?: DeviceThreatProtectionLevel

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

	    activeFirewallRequired?: boolean

	    uacRequired?: boolean

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

export interface WindowsDomainJoinConfiguration extends DeviceSetupConfiguration {

	    computerNameStaticPrefix?: string

	    computerNameSuffixRandomCharCount?: number

	    activeDirectoryDomainName?: string

}

export interface DeviceComplianceSettingState extends Entity {

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

	    /** The compliance state of the setting Possible values are: unknown, notApplicable, compliant, remediated, nonCompliant, error, conflict. */
	    state?: ComplianceStatus

	    /** The DateTime when device compliance grace period expires */
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

	    androidForWorkRestriction?: DeviceEnrollmentPlatformRestriction

	    macRestriction?: DeviceEnrollmentPlatformRestriction

	    /** Not yet documented */
	    macOSRestriction?: DeviceEnrollmentPlatformRestriction

}

export interface Windows10EnrollmentCompletionPageConfiguration extends DeviceEnrollmentConfiguration {

	    title?: string

	    bodyText?: string

	    moreInfoUrl?: string

	    moreInfoText?: string

}

export interface DeviceEnrollmentWindowsHelloForBusinessConfiguration extends DeviceEnrollmentConfiguration {

	    /** Not yet documented */
	    pinMinimumLength?: number

	    /** Not yet documented */
	    pinMaximumLength?: number

	    /** Not yet documented Possible values are: allowed, required, disallowed. */
	    pinUppercaseCharactersUsage?: WindowsHelloForBusinessPinUsage

	    /** Not yet documented Possible values are: allowed, required, disallowed. */
	    pinLowercaseCharactersUsage?: WindowsHelloForBusinessPinUsage

	    /** Not yet documented Possible values are: allowed, required, disallowed. */
	    pinSpecialCharactersUsage?: WindowsHelloForBusinessPinUsage

	    /** Not yet documented Possible values are: notConfigured, enabled, disabled. */
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

	    /** Not yet documented Possible values are: notConfigured, enabled, disabled. */
	    enhancedBiometricsState?: Enablement

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

export interface ActiveDirectoryWindowsAutopilotDeploymentProfile extends WindowsAutopilotDeploymentProfile {

	    domainJoinConfiguration?: WindowsDomainJoinConfiguration

}

export interface AzureADWindowsAutopilotDeploymentProfile extends WindowsAutopilotDeploymentProfile {

}

export interface Office365ActivationsUserDetail extends Entity {

	    reportRefreshDate?: string

	    userPrincipalName?: string

	    displayName?: string

	    userActivationCounts?: UserActivationCounts[]

}

export interface Office365ActivationCounts extends Entity {

	    reportRefreshDate?: string

	    productType?: string

	    windows?: number

	    mac?: number

	    android?: number

	    ios?: number

	    windows10Mobile?: number

}

export interface Office365ActivationsUserCounts extends Entity {

	    reportRefreshDate?: string

	    productType?: string

	    assigned?: number

	    activated?: number

	    sharedComputerActivation?: number

}

export interface Office365ActiveUserDetail extends Entity {

	    reportRefreshDate?: string

	    userPrincipalName?: string

	    displayName?: string

	    isDeleted?: boolean

	    deletedDate?: string

	    hasExchangeLicense?: boolean

	    hasOneDriveLicense?: boolean

	    hasSharePointLicense?: boolean

	    hasSkypeForBusinessLicense?: boolean

	    hasYammerLicense?: boolean

	    hasTeamsLicense?: boolean

	    exchangeLastActivityDate?: string

	    oneDriveLastActivityDate?: string

	    sharePointLastActivityDate?: string

	    skypeForBusinessLastActivityDate?: string

	    yammerLastActivityDate?: string

	    teamsLastActivityDate?: string

	    exchangeLicenseAssignDate?: string

	    oneDriveLicenseAssignDate?: string

	    sharePointLicenseAssignDate?: string

	    skypeForBusinessLicenseAssignDate?: string

	    yammerLicenseAssignDate?: string

	    teamsLicenseAssignDate?: string

	    assignedProducts?: string[]

}

export interface Office365ServicesUserCounts extends Entity {

	    reportRefreshDate?: string

	    exchangeActive?: number

	    exchangeInactive?: number

	    oneDriveActive?: number

	    oneDriveInactive?: number

	    sharePointActive?: number

	    sharePointInactive?: number

	    skypeForBusinessActive?: number

	    skypeForBusinessInactive?: number

	    yammerActive?: number

	    yammerInactive?: number

	    teamsActive?: number

	    teamsInactive?: number

	    reportPeriod?: string

}

export interface Office365ActiveUserCounts extends Entity {

	    reportRefreshDate?: string

	    office365?: number

	    exchange?: number

	    oneDrive?: number

	    sharePoint?: number

	    skypeForBusiness?: number

	    yammer?: number

	    teams?: number

	    reportDate?: string

	    reportPeriod?: string

}

export interface Office365GroupsActivityDetail extends Entity {

	    reportRefreshDate?: string

	    groupDisplayName?: string

	    isDeleted?: boolean

	    ownerPrincipalName?: string

	    lastActivityDate?: string

	    groupType?: string

	    memberCount?: number

	    externalMemberCount?: number

	    exchangeReceivedEmailCount?: number

	    sharePointActiveFileCount?: number

	    yammerPostedMessageCount?: number

	    yammerReadMessageCount?: number

	    yammerLikedMessageCount?: number

	    exchangeMailboxTotalItemCount?: number

	    exchangeMailboxStorageUsedInBytes?: number

	    sharePointTotalFileCount?: number

	    sharePointSiteStorageUsedInBytes?: number

	    reportPeriod?: string

}

export interface Office365GroupsActivityCounts extends Entity {

	    reportRefreshDate?: string

	    exchangeEmailsReceived?: number

	    yammerMessagesPosted?: number

	    yammerMessagesRead?: number

	    yammerMessagesLiked?: number

	    reportDate?: string

	    reportPeriod?: string

}

export interface Office365GroupsActivityGroupCounts extends Entity {

	    reportRefreshDate?: string

	    total?: number

	    active?: number

	    reportDate?: string

	    reportPeriod?: string

}

export interface Office365GroupsActivityStorage extends Entity {

	    reportRefreshDate?: string

	    mailboxStorageUsedInBytes?: number

	    siteStorageUsedInBytes?: number

	    reportDate?: string

	    reportPeriod?: string

}

export interface Office365GroupsActivityFileCounts extends Entity {

	    reportRefreshDate?: string

	    total?: number

	    active?: number

	    reportDate?: string

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

export interface ChatThread extends Entity {

	    chatMessages?: ChatMessage[]

	    rootMessage?: ChatMessage

}

export interface ChatMessage extends Entity {

	    body?: ItemBody

	    inReplyTo?: ChatMessage

	    replies?: ChatMessage[]

	    from?: User

}

export interface IdentityProvider extends Entity {

	    type?: string

	    name?: string

	    clientId?: string

	    clientSecret?: string

}

export interface SynchronizationJob extends Entity {

	    templateId?: string

	    schedule?: SynchronizationSchedule

	    status?: SynchronizationStatus

	    schema?: SynchronizationSchema

}

export interface SynchronizationTemplate extends Entity {

	    applicationId?: string

	    default?: boolean

	    description?: string

	    discoverable?: boolean

	    factoryTag?: string

	    metadata?: MetadataEntry[]

	    schema?: SynchronizationSchema

}

export interface SynchronizationSchema extends Entity {

	    directories?: DirectoryDefinition[]

	    synchronizationRules?: SynchronizationRule[]

	    version?: string

}

export interface AttributeMappingFunctionSchema extends Entity {

	    parameters?: AttributeMappingParameterSchema[]

}

export interface FilterOperatorSchema extends Entity {

	    arity?: ScopeOperatorType

	    multivaluedComparisonType?: ScopeOperatorMultiValuedComparisonType

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

	    assignments?: EducationAssignment[]

}

export interface EducationOrganization extends Entity {

	    displayName?: string

	    description?: string

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

	    classId?: string

	    displayName?: string

	    instructions?: EducationItemBody

	    dueDateTime?: string

	    assignDateTime?: string

	    assignedDateTime?: string

	    grading?: EducationAssignmentGradeType

	    assignTo?: EducationAssignmentRecipient

	    allowLateSubmissions?: boolean

	    createdDateTime?: string

	    createdBy?: IdentitySet

	    lastModifiedDateTime?: string

	    lastModifiedBy?: IdentitySet

	    allowStudentsToAddResourcesToSubmission?: boolean

	    status?: EducationAssignmentStatus

	    resources?: EducationAssignmentResource[]

	    submissions?: EducationSubmission[]

}

export interface EducationAssignmentResource extends Entity {

	    distributeForStudentWork?: boolean

	    resource?: EducationResource

}

export interface EducationSubmission extends Entity {

	    recipient?: EducationSubmissionRecipient

	    status?: EducationSubmissionStatus

	    submittedBy?: IdentitySet

	    submittedDateTime?: string

	    releasedBy?: IdentitySet

	    releasedDateTime?: string

	    grade?: EducationAssignmentGrade

	    feedback?: EducationFeedback

	    resourcesFolderUrl?: string

	    resources?: EducationSubmissionResource[]

	    submittedResources?: EducationSubmissionResource[]

}

export interface EducationSubmissionResource extends Entity {

	    resource?: EducationResource

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

	    /** Type of the enrollment. Possible values are: unknown, userEnrollment, deviceEnrollmentManager, appleBulkWithUser, appleBulkWithoutUser, windowsAzureADJoin, windowsBulkUserless, windowsAutoEnrollment, windowsBulkAzureDomainJoin, windowsCoManagement. */
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
export interface OnPremisesProvisioningError {

	    value?: string

	    category?: string

	    propertyCausingError?: string

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

	    archiveFolder?: string

	    /** The default time zone for the user's mailbox. */
	    timeZone?: string

	    /** The locale information for the user, including the preferred language and country/region. */
	    language?: LocaleInfo

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

	    daysOfWeek?: DayOfWeek[]

	    startTime?: string

	    endTime?: string

	    timeZone?: TimeZoneBase

}
export interface TimeZoneBase {

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
export interface VerifiedDomain {

	    capabilities?: string

	    isDefault?: boolean

	    isInitial?: boolean

	    name?: string

	    type?: string

}
export interface CertificateConnectorSetting {

	    status?: number

	    certExpiryTime?: string

	    enrollmentError?: string

	    lastConnectorConnectionTime?: string

	    connectorVersion?: string

	    lastUploadVersion?: number

}
export interface ExtensionSchemaProperty {

	    /** The name of the strongly-typed property defined as part of a schema extension. */
	    name?: string

	    /** The type of the property that is defined as part of a schema extension.  Allowed values are Binary, Boolean, DateTime, Integer or String.  See the table below for more details. */
	    type?: string

}
export interface Api {

	    acceptedAccessTokenVersion?: number

	    publishedPermissionScopes?: PermissionScope[]

}
export interface PermissionScope {

	    adminConsentDescription?: string

	    adminConsentDisplayName?: string

	    id?: string

	    isEnabled?: boolean

	    origin?: string

	    type?: string

	    userConsentDescription?: string

	    userConsentDisplayName?: string

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
export interface InstalledClient {

	    redirectUrls?: string[]

}
export interface InformationalUrl {

	    logoUrl?: string

	    marketingUrl?: string

	    privacyStatementUrl?: string

	    supportUrl?: string

	    termsOfServiceUrl?: string

}
export interface KeyCredential {

	    customKeyIdentifier?: number

	    endDateTime?: string

	    keyId?: string

	    startDateTime?: string

	    type?: string

	    usage?: string

	    key?: number

}
export interface PasswordCredential {

	    customKeyIdentifier?: number

	    endDateTime?: string

	    keyId?: string

	    startDateTime?: string

	    secretText?: string

	    hint?: string

}
export interface PreAuthorizedApplication {

	    appId?: string

	    permissionIds?: string[]

}
export interface RequiredResourceAccess {

	    resourceAppId?: string

	    resourceAccess?: ResourceAccess[]

}
export interface ResourceAccess {

	    id?: string

	    type?: string

}
export interface Web {

	    redirectUrls?: string[]

	    logoutUrl?: string

	    oauth2AllowImplicitFlow?: boolean

}
export interface SettingValue {

	    /** Name of the setting (as defined by the groupSettingTemplate). */
	    name?: string

	    /** Value of the setting. */
	    value?: string

}
export interface SettingTemplateValue {

	    /** Name of the setting. */
	    name?: string

	    /** Type of the setting. */
	    type?: string

	    /** Default value for the setting. */
	    defaultValue?: string

	    /** Description of the setting. */
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

	    /** The provisioning status of the service plan. Possible values:"Success" - Service is fully provisioned."Disabled" - Service has been disabled."PendingInput" - Service is not yet provisioned; awaiting service confirmation."PendingActivation" - Service is provisioned but requires explicit activation by administrator (for example, Intune_O365 service plan)"PendingProvisioning" - Microsoft has added a new service to the product SKU and it has not been activated in the tenant, yet. */
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

	    key?: string

	    value?: string

}
export interface OAuth2Permission {

	    adminConsentDescription?: string

	    adminConsentDisplayName?: string

	    id?: string

	    isEnabled?: boolean

	    origin?: string

	    type?: string

	    userConsentDescription?: string

	    userConsentDisplayName?: string

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
export interface AllowedDataLocationInfo {

}
export interface ImageInfo {

	    iconUrl?: string

	    alternativeText?: string

	    addImageQuery?: boolean

}
export interface VisualInfo {

	    attribution?: ImageInfo

	    backgroundColor?: string

	    description?: string

	    displayText?: string

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

	    /** The unique identifier (guid) for the item's site (SPWeb). */
	    webId?: string

}
export interface SiteCollection {

	    dataLocationCode?: string

	    /** The hostname for the site collection. Read-only. */
	    hostname?: string

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

	    level?: string

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

	    bias?: number

	    standardOffset?: StandardTimeZoneOffset

	    daylightOffset?: DaylightTimeZoneOffset

}
export interface StandardTimeZoneOffset {

	    time?: string

	    dayOccurrence?: number

	    dayOfWeek?: DayOfWeek

	    month?: number

	    year?: number

}
export interface DaylightTimeZoneOffset extends StandardTimeZoneOffset {

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

	    coordinates?: OutlookGeoCoordinates

	    locationUri?: string

	    locationType?: LocationType

	    uniqueId?: string

	    uniqueIdType?: LocationUniqueIdType

}
export interface PhysicalAddress {

	    type?: PhysicalAddressType

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

	    altitude?: number

	    latitude?: number

	    longitude?: number

	    accuracy?: number

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

	    meetingTimeSlots?: MeetingTimeCandidate[]

	    emptySuggestionsHint?: string

}
export interface MeetingTimeCandidate {

	    meetingTimeSlot?: TimeSlotOLD

	    confidence?: number

	    organizerAvailability?: FreeBusyStatus

	    attendeeAvailability?: AttendeeAvailability[]

	    locations?: Location[]

	    suggestionHint?: string

}
export interface TimeSlotOLD {

	    start?: TimeStamp

	    end?: TimeStamp

}
export interface TimeStamp {

	    date?: string

	    time?: string

	    timeZone?: string

}
export interface MailTips {

	    emailAddress?: EmailAddress

	    automaticReplies?: AutomaticRepliesMailTips

	    mailboxFull?: boolean

	    customMailTip?: string

	    externalMemberCount?: number

	    totalMemberCount?: number

	    deliveryRestricted?: boolean

	    isModerated?: boolean

	    recipientScope?: RecipientScopeType

	    recipientSuggestions?: Recipient[]

	    maxMessageSize?: number

	    error?: MailTipsError

}
export interface AutomaticRepliesMailTips {

	    message?: string

	    messageLanguage?: LocaleInfo

	    scheduledStartTime?: DateTimeTimeZone

	    scheduledEndTime?: DateTimeTimeZone

}
export interface MailTipsError {

	    message?: string

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

	    alias?: string

	    displayName?: string

}
export interface InternetMessageHeader {

	    name?: string

	    value?: string

}
export interface ItemBody {

	    /** The type of the content. Possible values are Text and HTML. */
	    contentType?: BodyType

	    /** The content of the item. */
	    content?: string

}
export interface MentionsPreview {

	    isMentioned?: boolean

}
export interface FollowupFlag {

	    completedDateTime?: DateTimeTimeZone

	    dueDateTime?: DateTimeTimeZone

	    startDateTime?: DateTimeTimeZone

	    flagStatus?: FollowupFlagStatus

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
export interface Website {

	    /** Possible values are: other, home, work, blog, profile. */
	    type?: WebsiteType

	    /** The URL of the website. */
	    address?: string

	    /** The display name of the web site. */
	    displayName?: string

}
export interface MessageRulePredicates {

	    categories?: string[]

	    subjectContains?: string[]

	    bodyContains?: string[]

	    bodyOrSubjectContains?: string[]

	    senderContains?: string[]

	    recipientContains?: string[]

	    headerContains?: string[]

	    messageActionFlag?: MessageActionFlag

	    importance?: Importance

	    sensitivity?: Sensitivity

	    fromAddresses?: Recipient[]

	    sentToAddresses?: Recipient[]

	    sentToMe?: boolean

	    sentOnlyToMe?: boolean

	    sentCcMe?: boolean

	    sentToOrCcMe?: boolean

	    notSentToMe?: boolean

	    hasAttachments?: boolean

	    isApprovalRequest?: boolean

	    isAutomaticForward?: boolean

	    isAutomaticReply?: boolean

	    isEncrypted?: boolean

	    isMeetingRequest?: boolean

	    isMeetingResponse?: boolean

	    isNonDeliveryReport?: boolean

	    isPermissionControlled?: boolean

	    isReadReceipt?: boolean

	    isSigned?: boolean

	    isVoicemail?: boolean

	    withinSizeRange?: SizeRange

}
export interface SizeRange {

	    minimumSize?: number

	    maximumSize?: number

}
export interface MessageRuleActions {

	    moveToFolder?: string

	    copyToFolder?: string

	    delete?: boolean

	    permanentDelete?: boolean

	    markAsRead?: boolean

	    markImportance?: Importance

	    forwardTo?: Recipient[]

	    forwardAsAttachmentTo?: Recipient[]

	    redirectTo?: Recipient[]

	    assignCategories?: string[]

	    stopProcessingRules?: boolean

}
export interface RankedEmailAddress {

	    address?: string

	    rank?: number

}
export interface PersonDataSource {

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

	    /** How to display the information about the person or group chosen. See below. */
	    displayAs?: string

	    /** Whether to allow selection of people only, or people and groups. Must be one of peopleAndGroups or peopleOnly. */
	    chooseFromType?: string

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

	    comment?: CommentAction

	    create?: CreateAction

	    delete?: DeleteAction

	    edit?: EditAction

	    mention?: MentionAction

	    move?: MoveAction

	    rename?: RenameAction

	    restore?: RestoreAction

	    share?: ShareAction

	    version?: VersionAction

}
export interface CommentAction {

	    isReply?: boolean

	    parentAuthor?: IdentitySet

	    participants?: IdentitySet[]

}
export interface CreateAction {

}
export interface DeleteAction {

	    name?: string

}
export interface EditAction {

}
export interface MentionAction {

	    mentionees?: IdentitySet[]

}
export interface MoveAction {

	    From?: string

	    to?: string

}
export interface RenameAction {

	    oldName?: string

}
export interface RestoreAction {

}
export interface ShareAction {

	    recipients?: IdentitySet[]

}
export interface VersionAction {

	    newVersion?: string

}
export interface ItemActivityTimeSet {

	    observedDateTime?: string

	    recordedDateTime?: string

}
export interface ContentTypeInfo {

	    /** The id of the content type. */
	    id?: string

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

	    orderHint?: string

	    planTitle?: string

}
export interface PlannerRecentPlanReference {

	    lastAccessedDateTime?: string

	    planTitle?: string

}
export interface PlannerPlanContext {

	    associationType?: string

	    createdDateTime?: string

	    displayNameSegments?: string[]

	    ownerAppId?: string

}
export interface PlannerPlanContextDetails {

	    url?: string

}
export interface PlannerPlanContextDetailsCollection {

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

	    message?: string

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

	    /** Opens the notebook in the OneNote native client if it's installed. */
	    oneNoteClientUrl?: ExternalLink

	    /** Opens the notebook in OneNote Online. */
	    oneNoteWebUrl?: ExternalLink

}
export interface SignInLocation {

	    city?: string

	    state?: string

	    countryOrRegion?: string

	    geoCoordinates?: GeoCoordinates

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
export interface AdminConsent {

	    shareAPNSData?: AdminConsentState

}
export interface DeviceProtectionOverview {

	    totalReportedDeviceCount?: number

	    inactiveThreatAgentDeviceCount?: number

	    unknownStateThreatAgentDeviceCount?: number

	    pendingSignatureUpdateDeviceCount?: number

	    cleanDeviceCount?: number

	    pendingFullScanDeviceCount?: number

	    pendingRestartDeviceCount?: number

	    pendingManualStepsDeviceCount?: number

	    pendingOfflineScanDeviceCount?: number

	    criticalFailuresDeviceCount?: number

}
export interface DeviceManagementSettings {

	    /** The number of days a device is allowed to go without checking in to remain compliant. Valid values 0 to 120 */
	    deviceComplianceCheckinThresholdDays?: number

	    /** Is feature enabled or not for scheduled action for rule. */
	    isScheduledActionEnabled?: boolean

	    /** Device should be noncompliant when there is no compliance policy targeted when this is true */
	    secureByDefault?: boolean

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

	    /** The type of value this item describes Possible values are: bool, integer, string, choice, multiselect, bundle, bundleArray, hidden. */
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
export interface MicrosoftStoreForBusinessAppAssignmentSettings extends MobileAppAssignmentSettings {

	    /** Whether or not to use device execution context for Microsoft Store for Business mobile app. */
	    useDeviceContext?: boolean

}
export interface ExcludedApps {

	    access?: boolean

	    excel?: boolean

	    groove?: boolean

	    infoPath?: boolean

	    lync?: boolean

	    oneDrive?: boolean

	    oneNote?: boolean

	    outlook?: boolean

	    powerPoint?: boolean

	    publisher?: boolean

	    sharePointDesigner?: boolean

	    visio?: boolean

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
export interface IosDeviceType {

	    /** Whether the app should run on iPads. */
	    iPad?: boolean

	    /** Whether the app should run on iPhones and iPods. */
	    iPhoneAndIPod?: boolean

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
export interface WindowsPackageInformation {

	    applicableArchitecture?: WindowsArchitecture

	    displayName?: string

	    identityName?: string

	    identityPublisher?: string

	    identityResourceIdentifier?: string

	    identityVersion?: string

	    minimumSupportedOperatingSystem?: WindowsMinimumOperatingSystem

}
export interface VppLicensingType {

	    supportUserLicensing?: boolean

	    supportDeviceLicensing?: boolean

	    /** Whether the program supports the user licensing type. */
	    supportsUserLicensing?: boolean

	    /** Whether the program supports the device licensing type. */
	    supportsDeviceLicensing?: boolean

}
export interface AndroidPermissionAction {

	    permission?: string

	    action?: AndroidPermissionActionType

}
export interface AppConfigurationSettingItem {

	    appConfigKey?: string

	    appConfigKeyType?: MdmAppConfigKeyType

	    appConfigKeyValue?: string

}
export interface ManagementCertificateWithThumbprint {

	    thumbprint?: string

	    certificate?: string

}
export interface RunSchedule {

}
export interface HardwareInformation {

	    serialNumber?: string

	    totalStorageSpace?: number

	    freeStorageSpace?: number

	    imei?: string

	    meid?: string

	    manufacturer?: string

	    model?: string

	    phoneNumber?: string

	    subscriberCarrier?: string

	    cellularTechnology?: string

	    wifiMac?: string

	    operatingSystemLanguage?: string

	    isSupervised?: boolean

	    isEncrypted?: boolean

	    isSharedDevice?: boolean

	    sharedDeviceCachedUsers?: SharedAppleDeviceUser[]

	    tpmSpecificationVersion?: string

	    operatingSystemEdition?: string

	    deviceFullQualifiedDomainName?: string

	    deviceGuardVirtualizationBasedSecurityHardwareRequirementState?: DeviceGuardVirtualizationBasedSecurityHardwareRequirementState

	    deviceGuardVirtualizationBasedSecurityState?: DeviceGuardVirtualizationBasedSecurityState

	    deviceGuardLocalSystemAuthorityCredentialGuardState?: DeviceGuardLocalSystemAuthorityCredentialGuardState

}
export interface SharedAppleDeviceUser {

	    userPrincipalName?: string

	    dataToSync?: boolean

	    dataQuota?: number

	    dataUsed?: number

}
export interface DeviceActionResult {

	    /** Action name */
	    actionName?: string

	    /** State of the action Possible values are: none, pending, canceled, active, done, failed, notSupported. */
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
export interface BulkManagedDeviceActionResult {

	    successfulDeviceIds?: string[]

	    failedDeviceIds?: string[]

	    notFoundDeviceIds?: string[]

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

	    interval?: number

}
export interface HourlySchedule extends RunSchedule {

	    interval?: number

}
export interface RevokeAppleVppLicensesActionResult extends DeviceActionResult {

	    totalLicensesCount?: number

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

	    /** Not yet documented */
	    content?: any

}
export interface ExtendedKeyUsage {

	    name?: string

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

	    description?: string

	    ipAddressOrFqdn?: string

	    address?: string

	    isDefaultServer?: boolean

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
export interface IosEduCertificateSettings {

	    trustedRootCertificate?: number

	    certFileName?: string

	    certificationAuthority?: string

	    certificationAuthorityName?: string

	    certificateTemplateName?: string

	    renewalThresholdPercentage?: number

	    certificateValidityPeriodValue?: number

	    certificateValidityPeriodScale?: CertificateValidityPeriodScale

}
export interface MediaContentRatingAustralia {

	    /** Movies rating selected for Australia Possible values are: allAllowed, allBlocked, general, parentalGuidance, mature, agesAbove15, agesAbove18. */
	    movieRating?: RatingAustraliaMoviesType

	    /** TV rating selected for Australia Possible values are: allAllowed, allBlocked, preschoolers, children, general, parentalGuidance, mature, agesAbove15, agesAbove15AdultViolence. */
	    tvRating?: RatingAustraliaTelevisionType

}
export interface MediaContentRatingCanada {

	    /** Movies rating selected for Canada Possible values are: allAllowed, allBlocked, general, parentalGuidance, agesAbove14, agesAbove18, restricted. */
	    movieRating?: RatingCanadaMoviesType

	    /** TV rating selected for Canada Possible values are: allAllowed, allBlocked, children, childrenAbove8, general, parentalGuidance, agesAbove14, agesAbove18. */
	    tvRating?: RatingCanadaTelevisionType

}
export interface MediaContentRatingFrance {

	    /** Movies rating selected for France Possible values are: allAllowed, allBlocked, agesAbove10, agesAbove12, agesAbove16, agesAbove18. */
	    movieRating?: RatingFranceMoviesType

	    /** TV rating selected for France Possible values are: allAllowed, allBlocked, agesAbove10, agesAbove12, agesAbove16, agesAbove18. */
	    tvRating?: RatingFranceTelevisionType

}
export interface MediaContentRatingGermany {

	    /** Movies rating selected for Germany Possible values are: allAllowed, allBlocked, general, agesAbove6, agesAbove12, agesAbove16, adults. */
	    movieRating?: RatingGermanyMoviesType

	    /** TV rating selected for Germany Possible values are: allAllowed, allBlocked, general, agesAbove6, agesAbove12, agesAbove16, adults. */
	    tvRating?: RatingGermanyTelevisionType

}
export interface MediaContentRatingIreland {

	    /** Movies rating selected for Ireland Possible values are: allAllowed, allBlocked, general, parentalGuidance, agesAbove12, agesAbove15, agesAbove16, adults. */
	    movieRating?: RatingIrelandMoviesType

	    /** TV rating selected for Ireland Possible values are: allAllowed, allBlocked, general, children, youngAdults, parentalSupervision, mature. */
	    tvRating?: RatingIrelandTelevisionType

}
export interface MediaContentRatingJapan {

	    /** Movies rating selected for Japan Possible values are: allAllowed, allBlocked, general, parentalGuidance, agesAbove15, agesAbove18. */
	    movieRating?: RatingJapanMoviesType

	    /** TV rating selected for Japan Possible values are: allAllowed, allBlocked, explicitAllowed. */
	    tvRating?: RatingJapanTelevisionType

}
export interface MediaContentRatingNewZealand {

	    /** Movies rating selected for New Zealand Possible values are: allAllowed, allBlocked, general, parentalGuidance, mature, agesAbove13, agesAbove15, agesAbove16, agesAbove18, restricted, agesAbove16Restricted. */
	    movieRating?: RatingNewZealandMoviesType

	    /** TV rating selected for New Zealand Possible values are: allAllowed, allBlocked, general, parentalGuidance, adults. */
	    tvRating?: RatingNewZealandTelevisionType

}
export interface MediaContentRatingUnitedKingdom {

	    /** Movies rating selected for United Kingdom Possible values are: allAllowed, allBlocked, general, universalChildren, parentalGuidance, agesAbove12Video, agesAbove12Cinema, agesAbove15, adults. */
	    movieRating?: RatingUnitedKingdomMoviesType

	    /** TV rating selected for United Kingdom Possible values are: allAllowed, allBlocked, caution. */
	    tvRating?: RatingUnitedKingdomTelevisionType

}
export interface MediaContentRatingUnitedStates {

	    /** Movies rating selected for United States Possible values are: allAllowed, allBlocked, general, parentalGuidance, parentalGuidance13, restricted, adults. */
	    movieRating?: RatingUnitedStatesMoviesType

	    /** TV rating selected for United States Possible values are: allAllowed, allBlocked, childrenAll, childrenAbove7, general, parentalGuidance, childrenAbove14, adults. */
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
export interface AirPrintDestination {

	    ipAddress?: string

	    /** The Resource Path associated with the printer. This corresponds to the rp parameter of the _ipps.tcp Bonjour record. For example: printers/Canon_MG5300_series, printers/Xerox_Phaser_7600, ipp/print, Epson_IPP_Printer. */
	    resourcePath?: string

	    port?: number

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

	    allowedAppsList?: AppListItem[]

	    allowedUrls?: string[]

	    displayName?: string

	    kerberosPrincipalName?: string

	    kerberosRealm?: string

}
export interface IosWebContentFilterSpecificWebsitesAccess extends IosWebContentFilterBase {

	    specificWebsitesOnly?: IosBookmark[]

}
export interface IosBookmark {

	    url?: string

	    bookmarkFolder?: string

	    displayName?: string

}
export interface IosWebContentFilterAutoFilter extends IosWebContentFilterBase {

	    allowedUrls?: string[]

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

	    ssids?: string[]

	    dnsSearchDomains?: string[]

	    probeUrl?: string

	    action?: VpnOnDemandRuleConnectionAction

	    domainAction?: VpnOnDemandRuleConnectionDomainAction

	    domains?: string[]

	    probeRequiredUrl?: string

}
export interface VpnProxyServer {

	    automaticConfigurationScriptUrl?: string

	    address?: string

	    port?: number

}
export interface Windows81VpnProxyServer extends VpnProxyServer {

	    automaticallyDetectProxySettings?: boolean

	    bypassProxyServerForLocalAddress?: boolean

}
export interface Windows10VpnProxyServer extends VpnProxyServer {

	    bypassProxyServerForLocalAddress?: boolean

}
export interface WindowsFirewallNetworkProfile {

	    /** Turn on the firewall and advanced security enforcement Possible values are: notConfigured, blocked, allowed. */
	    firewallEnabled?: StateManagementSetting

	    /** Prevent the server from operating in stealth mode */
	    stealthModeBlocked?: boolean

	    /** Configures the firewall to block all incoming traffic regardless of other policy settings */
	    incomingTrafficBlocked?: boolean

	    /** Configures the firewall to block unicast responses to multicast broadcast traffic */
	    unicastResponsesToMulticastBroadcastsBlocked?: boolean

	    /** Prevents the firewall from displaying notifications when an application is blocked from listening on a port */
	    inboundNotificationsBlocked?: boolean

	    /** Configures the firewall to merge authorized application rules from group policy with those from local store instead of ignoring the local store rules */
	    authorizedApplicationRulesFromGroupPolicyMerged?: boolean

	    /** Configures the firewall to merge global port rules from group policy with those from local store instead of ignoring the local store rules */
	    globalPortRulesFromGroupPolicyMerged?: boolean

	    /** Configures the firewall to merge connection security rules from group policy with those from local store instead of ignoring the local store rules */
	    connectionSecurityRulesFromGroupPolicyMerged?: boolean

	    /** Configures the firewall to block all outgoing connections by default */
	    outboundConnectionsBlocked?: boolean

	    /** Configures the firewall to block all incoming connections by default */
	    inboundConnectionsBlocked?: boolean

	    /** Configures the firewall to allow the host computer to respond to unsolicited network traffic of that traffic is secured by IPSec even when stealthModeBlocked is set to true */
	    securedPacketExemptionAllowed?: boolean

	    /** Configures the firewall to merge Firewall Rule policies from group policy with those from local store instead of ignoring the local store rules */
	    policyRulesFromGroupPolicyMerged?: boolean

}
export interface BitLockerSystemDrivePolicy {

	    encryptionMethod?: BitLockerEncryptionMethod

	    startupAuthenticationRequired?: boolean

	    startupAuthenticationBlockWithoutTpmChip?: boolean

	    startupAuthenticationTpmUsage?: ConfigurationUsage

	    startupAuthenticationTpmPinUsage?: ConfigurationUsage

	    startupAuthenticationTpmKeyUsage?: ConfigurationUsage

	    startupAuthenticationTpmPinAndKeyUsage?: ConfigurationUsage

	    minimumPinLength?: number

	    recoveryOptions?: BitLockerRecoveryOptions

	    prebootRecoveryEnableMessageAndUrl?: boolean

	    prebootRecoveryMessage?: string

	    prebootRecoveryUrl?: string

}
export interface BitLockerRecoveryOptions {

	    blockDataRecoveryAgent?: boolean

	    recoveryPasswordUsage?: ConfigurationUsage

	    recoveryKeyUsage?: ConfigurationUsage

	    hideRecoveryOptions?: boolean

	    enableRecoveryInformationSaveToStore?: boolean

	    recoveryInformationToStore?: BitLockerRecoveryinformationType

	    enableBitLockerAfterRecoveryInformationToStore?: boolean

}
export interface BitLockerFixedDrivePolicy {

	    encryptionMethod?: BitLockerEncryptionMethod

	    requireEncryptionForWriteAccess?: boolean

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

	    enterpriseNetworkDomainNames?: string[]

	    enterpriseCloudResources?: ProxiedDomain[]

	    enterpriseIPRanges?: IpRange[]

	    enterpriseInternalProxyServers?: string[]

	    enterpriseIPRangesAreAuthoritative?: boolean

	    enterpriseProxyServers?: string[]

	    enterpriseProxyServersAreAuthoritative?: boolean

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

	    /** Scheduled Install Day in week Possible values are: userDefined, everyday, sunday, monday, tuesday, wednesday, thursday, friday, saturday. */
	    scheduledInstallDay?: WeeklySchedule

	    /** Scheduled Install Time during day */
	    scheduledInstallTime?: string

	    restartMode?: WindowsUpdateRestartMode

}
export interface WindowsUpdateActiveHoursInstall extends WindowsUpdateInstallScheduleType {

	    /** Active Hours Start */
	    activeHoursStart?: string

	    /** Active Hours End */
	    activeHoursEnd?: string

}
export interface Windows10AssociatedApps {

	    appType?: Windows10AppType

	    identifier?: string

}
export interface VpnTrafficRule {

	    name?: string

	    protocols?: number

	    localPortRanges?: NumberRange[]

	    remotePortRanges?: NumberRange[]

	    localAddressRanges?: IPv4Range[]

	    remoteAddressRanges?: IPv4Range[]

	    appId?: string

	    appType?: VpnTrafficRuleAppType

	    routingPolicyType?: VpnTrafficRuleRoutingPolicyType

	    claims?: string

}
export interface NumberRange {

	    lowerNumber?: number

	    upperNumber?: number

}
export interface VpnRoute {

	    destinationPrefix?: string

	    prefixSize?: number

}
export interface VpnDnsRule {

	    name?: string

	    servers?: string[]

	    proxyServerUri?: string

}
export interface OperatingSystemVersionRange {

	    description?: string

	    lowestVersion?: string

	    highestVersion?: string

}
export interface DeviceConfigurationSettingState {

	    /** The setting that is being reported */
	    setting?: string

	    /** Localized/user friendly setting name that is being reported */
	    settingName?: string

	    /** Name of setting instance that is being reported. */
	    instanceDisplayName?: string

	    /** The compliance state of the setting Possible values are: unknown, notApplicable, compliant, remediated, nonCompliant, error, conflict. */
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

	    /** The compliance state of the setting Possible values are: unknown, notApplicable, compliant, remediated, nonCompliant, error, conflict. */
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
export interface VppTokenActionResult {

	    actionName?: string

	    actionState?: ActionState

	    startDateTime?: string

	    lastUpdatedDateTime?: string

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

	    totalLicensesCount?: number

	    failedLicensesCount?: number

	    actionFailureReason?: VppTokenActionFailureReason

}
export interface DeviceManagementExchangeAccessRule {

	    deviceClass?: DeviceManagementExchangeDeviceClass

	    accessLevel?: DeviceManagementExchangeAccessLevel

}
export interface DeviceManagementExchangeDeviceClass {

	    name?: string

	    type?: DeviceManagementExchangeAccessRuleType

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
export interface OutOfBoxExperienceSettings {

	    hidePrivacySettings?: boolean

	    hideEULA?: boolean

	    userType?: WindowsUserType

}
export interface ImportedWindowsAutopilotDeviceIdentityState {

	    deviceImportStatus?: ImportedWindowsAutopilotDeviceIdentityImportStatus

	    deviceRegistrationId?: string

	    deviceErrorCode?: number

	    deviceErrorName?: string

}
export interface UserActivationCounts {

	    productType?: string

	    lastActivatedDate?: string

	    windows?: number

	    mac?: number

	    windows10Mobile?: number

	    ios?: number

	    android?: number

	    activatedOnSharedComputer?: boolean

}
export interface PayloadRequest {

}
export interface TeamMemberSettings {

	    allowCreateUpdateChannels?: boolean

	    allowDeleteChannels?: boolean

	    allowAddRemoveApps?: boolean

	    allowCreateUpdateRemoveTabs?: boolean

	    allowCreateUpdateRemoveConnectors?: boolean

}
export interface TeamMessagingSettings {

	    allowUserEditMessages?: boolean

	    allowUserDeleteMessages?: boolean

	    allowOwnerDeleteMessages?: boolean

	    allowTeamMentions?: boolean

	    allowChannelMentions?: boolean

}
export interface TeamFunSettings {

	    allowGiphy?: boolean

	    giphyContentRating?: GiphyRatingType

	    allowStickersAndMemes?: boolean

	    allowCustomMemes?: boolean

}
export interface TeamGuestSettings {

	    allowCreateUpdateChannels?: boolean

	    allowDeleteChannels?: boolean

}
export interface SynchronizationSecretKeyStringValuePair {

	    key?: SynchronizationSecret

	    value?: string

}
export interface MetadataEntry {

	    key?: string

	    value?: string

}
export interface SynchronizationSchedule {

	    expiration?: string

	    interval?: string

	    state?: SynchronizationScheduleState

}
export interface SynchronizationStatus {

	    countSuccessiveCompleteFailures?: number

	    escrowsPruned?: boolean

	    synchronizedEntryCountByType?: StringKeyLongValuePair[]

	    code?: SynchronizationStatusCode

	    lastExecution?: SynchronizationTaskExecution

	    lastSuccessfulExecution?: SynchronizationTaskExecution

	    lastSuccessfulExecutionWithExports?: SynchronizationTaskExecution

	    steadyStateFirstAchievedTime?: string

	    steadyStateLastAchievedTime?: string

	    quarantine?: SynchronizationQuarantine

	    troubleshootingUrl?: string

}
export interface StringKeyLongValuePair {

	    key?: string

	    value?: number

}
export interface SynchronizationTaskExecution {

	    activityIdentifier?: string

	    countEntitled?: number

	    countEntitledForProvisioning?: number

	    countEscrowed?: number

	    countEscrowedRaw?: number

	    countExported?: number

	    countExports?: number

	    countImported?: number

	    countImportedDeltas?: number

	    countImportedReferenceDeltas?: number

	    state?: SynchronizationTaskExecutionResult

	    error?: SynchronizationError

	    timeBegan?: string

	    timeEnded?: string

}
export interface SynchronizationError {

	    code?: string

	    message?: string

	    tenantActionable?: boolean

}
export interface SynchronizationQuarantine {

	    currentBegan?: string

	    nextAttempt?: string

	    reason?: QuarantineReason

	    seriesBegan?: string

	    seriesCount?: number

}
export interface SynchronizationJobRestartCriteria {

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

	    anchor?: boolean

	    apiExpressions?: StringKeyStringValuePair[]

	    caseExact?: boolean

	    defaultValue?: string

	    metadata?: MetadataEntry[]

	    multivalued?: boolean

	    mutability?: Mutability

	    name?: string

	    required?: boolean

	    referencedObjects?: ReferencedObject[]

	    type?: AttributeType

}
export interface StringKeyStringValuePair {

	    key?: string

	    value?: string

}
export interface ReferencedObject {

	    referencedObjectName?: string

	    referencedProperty?: string

}
export interface SynchronizationRule {

	    editable?: boolean

	    id?: string

	    metadata?: StringKeyStringValuePair[]

	    name?: string

	    objectMappings?: ObjectMapping[]

	    priority?: number

	    sourceDirectoryName?: string

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

	    defaultValue?: string

	    exportMissingReferences?: boolean

	    flowBehavior?: AttributeFlowBehavior

	    flowType?: AttributeFlowType

	    matchingPriority?: number

	    source?: AttributeMappingSource

	    targetAttributeName?: string

}
export interface AttributeMappingSource {

	    expression?: string

	    name?: string

	    parameters?: StringKeyAttributeMappingSourceValuePair[]

	    type?: AttributeMappingSourceType

}
export interface StringKeyAttributeMappingSourceValuePair {

	    key?: string

	    value?: AttributeMappingSource

}
export interface Filter {

	    groups?: FilterGroup[]

	    inputFilterGroups?: FilterGroup[]

	    categoryFilterGroups?: FilterGroup[]

}
export interface FilterGroup {

	    clauses?: FilterClause[]

	    name?: string

}
export interface FilterClause {

	    operatorName?: string

	    sourceOperandName?: string

	    targetOperand?: FilterOperand

}
export interface FilterOperand {

	    values?: string[]

}
export interface AttributeMappingParameterSchema {

	    allowMultipleOccurrences?: boolean

	    name?: string

	    required?: boolean

	    type?: AttributeType

}
export interface ExpressionInputObject {

	    definition?: ObjectDefinition

	    properties?: StringKeyObjectValuePair[]

}
export interface StringKeyObjectValuePair {

	    key?: string

}
export interface ParseExpressionResponse {

	    error?: PublicError

	    evaluationSucceeded?: boolean

	    evaluationResult?: string[]

	    parsedExpression?: AttributeMappingSource

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

	    type?: string

	    fileName?: string

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

	    maxPoints?: number

}
export interface EducationAssignmentGrade {

	    gradedBy?: IdentitySet

	    gradedDateTime?: string

}
export interface EducationAssignmentPointsGrade extends EducationAssignmentGrade {

	    points?: number

}
export interface EducationAssignmentRecipient {

}
export interface EducationAssignmentClassRecipient extends EducationAssignmentRecipient {

}
export interface EducationAssignmentGroupRecipient extends EducationAssignmentRecipient {

}
export interface EducationResource {

	    displayName?: string

	    createdDateTime?: string

	    createdBy?: IdentitySet

	    lastModifiedDateTime?: string

	    lastModifiedBy?: IdentitySet

}
export interface EducationWordResource extends EducationResource {

	    fileUrl?: string

}
export interface EducationPowerPointResource extends EducationResource {

	    fileUrl?: string

}
export interface EducationExcelResource extends EducationResource {

	    fileUrl?: string

}
export interface EducationOneNoteResource extends EducationResource {

	    sectionName?: string

	    pageUrl?: string

}
export interface EducationFileResource extends EducationResource {

	    fileUrl?: string

}
export interface EducationLinkResource extends EducationResource {

	    link?: string

}
export interface EducationSubmissionRecipient {

}
export interface EducationSubmissionIndividualRecipient extends EducationSubmissionRecipient {

	    userId?: string

}
export interface EducationFeedback {

	    text?: EducationItemBody

	    feedbackDateTime?: string

	    feedbackBy?: IdentitySet

}
export interface AuditActor {

	    /** Actor Type. */
	    type?: string

	    /** List of user permissions when the audit was performed. */
	    permissions?: string[]

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
