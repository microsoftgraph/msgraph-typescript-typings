// Type definitions for the Microsoft Graph API
// Project: https://github.com/microsoftgraph/msgraph-typescript-typings
// Definitions by: Microsoft Graph Team <https://github.com/microsoftgraph>

//
// Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
//


export as namespace microsoftgraph;

export type DayOfWeek = "sunday" | "monday" | "tuesday" | "wednesday" | "thursday" | "friday" | "saturday"
export type AutomaticRepliesStatus = "disabled" | "alwaysEnabled" | "scheduled"
export type ExternalAudienceScope = "none" | "contactsOnly" | "all"
export type AttendeeType = "required" | "optional" | "resource"
export type FreeBusyStatus = "free" | "tentative" | "busy" | "oof" | "workingElsewhere" | "unknown"
export type LocationType = "default" | "conferenceRoom" | "homeAddress" | "businessAddress" | "geoCoordinates" | "streetAddress" | "hotel" | "restaurant" | "localBusiness" | "postalAddress"
export type LocationUniqueIdType = "unknown" | "locationStore" | "directory" | "private" | "bing"
export type ActivityDomain = "unknown" | "work" | "personal" | "unrestricted"
export type MailTipsType = "automaticReplies" | "mailboxFullStatus" | "customMailTip" | "externalMemberCount" | "totalMemberCount" | "maxMessageSize" | "deliveryRestriction" | "moderationStatus" | "recipientScope" | "recipientSuggestions"
export type RecipientScopeType = "none" | "internal" | "external" | "externalPartner" | "externalNonPartner"
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
export type MeetingMessageType = "none" | "meetingRequest" | "meetingCancelled" | "meetingAccepted" | "meetingTenativelyAccepted" | "meetingDeclined"
export type MessageActionFlag = "any" | "call" | "doNotForward" | "followUp" | "fyi" | "forward" | "noResponseNecessary" | "read" | "reply" | "replyToAll" | "review"
export type CategoryColor = "preset0" | "preset1" | "preset2" | "preset3" | "preset4" | "preset5" | "preset6" | "preset7" | "preset8" | "preset9" | "preset10" | "preset11" | "preset12" | "preset13" | "preset14" | "preset15" | "preset16" | "preset17" | "preset18" | "preset19" | "preset20" | "preset21" | "preset22" | "preset23" | "preset24" | "none"
export type SelectionLikelihoodInfo = "notSpecified" | "high"
export type PhoneType = "home" | "business" | "mobile" | "other" | "assistant" | "homeFax" | "businessFax" | "otherFax" | "pager" | "radio"
export type WebsiteType = "other" | "home" | "work" | "blog" | "profile"
export type PlannerPreviewType = "automatic" | "noPreview" | "checklist" | "description" | "reference"
export type OperationStatus = "NotStarted" | "Running" | "Completed" | "Failed"
export type OnenotePatchInsertPosition = "After" | "Before"
export type OnenotePatchActionType = "Replace" | "Append" | "Delete" | "Insert" | "Prepend"
export type OnenoteSourceService = "Unknown" | "OneDrive" | "OneDriveForBusiness" | "OnPremOneDriveForBusiness"
export type OnenoteUserRole = "Owner" | "Contributor" | "Reader" | "None"
export type EducationUserRole = "student" | "teacher" | "none" | "unknownFutureValue"
export type EducationExternalSource = "sis" | "manual" | "unknownFutureValue"
export type EducationGender = "female" | "male" | "other" | "unknownFutureValue"
export type EducationContactRelationship = "parent" | "relative" | "aide" | "doctor" | "guardian" | "child" | "other" | "unknownFutureValue"
export type InstallIntent = "available" | "required" | "uninstall" | "availableWithoutEnrollment"
export type MobileAppPublishingState = "notPublished" | "processing" | "published"
export type WindowsArchitecture = "none" | "x86" | "x64" | "arm" | "neutral"
export type ManagedAppAvailability = "global" | "lineOfBusiness"
export type MobileAppContentFileUploadState = "success" | "transientError" | "error" | "unknown" | "azureStorageUriRequestSuccess" | "azureStorageUriRequestPending" | "azureStorageUriRequestFailed" | "azureStorageUriRequestTimedOut" | "azureStorageUriRenewalSuccess" | "azureStorageUriRenewalPending" | "azureStorageUriRenewalFailed" | "azureStorageUriRenewalTimedOut" | "commitFileSuccess" | "commitFilePending" | "commitFileFailed" | "commitFileTimedOut"
export type WindowsDeviceType = "none" | "desktop" | "mobile" | "holographic" | "team"
export type MicrosoftStoreForBusinessLicenseType = "offline" | "online"
export type VppTokenAccountType = "business" | "education"
export type ComplianceStatus = "unknown" | "notApplicable" | "compliant" | "remediated" | "nonCompliant" | "error" | "conflict" | "notAssigned"
export type MdmAppConfigKeyType = "stringType" | "integerType" | "realType" | "booleanType" | "tokenType"
export type ActionState = "none" | "pending" | "canceled" | "active" | "done" | "failed" | "notSupported"
export type ManagedDeviceOwnerType = "unknown" | "company" | "personal"
export type ComplianceState = "unknown" | "compliant" | "noncompliant" | "conflict" | "error" | "inGracePeriod" | "configManager"
export type ManagementAgentType = "eas" | "mdm" | "easMdm" | "intuneClient" | "easIntuneClient" | "configurationManagerClient" | "configurationManagerClientMdm" | "configurationManagerClientMdmEas" | "unknown" | "jamf" | "googleCloudDevicePolicyController"
export type DeviceEnrollmentType = "unknown" | "userEnrollment" | "deviceEnrollmentManager" | "appleBulkWithUser" | "appleBulkWithoutUser" | "windowsAzureADJoin" | "windowsBulkUserless" | "windowsAutoEnrollment" | "windowsBulkAzureDomainJoin" | "windowsCoManagement"
export type DeviceRegistrationState = "notRegistered" | "registered" | "revoked" | "keyConflict" | "approvalPending" | "certificateReset" | "notRegisteredPendingEnrollment" | "unknown"
export type DeviceManagementExchangeAccessState = "none" | "unknown" | "allowed" | "blocked" | "quarantined"
export type DeviceManagementExchangeAccessStateReason = "none" | "unknown" | "exchangeGlobalRule" | "exchangeIndividualRule" | "exchangeDeviceRule" | "exchangeUpgrade" | "exchangeMailboxPolicy" | "other" | "compliant" | "notCompliant" | "notEnrolled" | "unknownLocation" | "mfaRequired" | "azureADBlockDueToAccessPolicy" | "compromisedPassword" | "deviceNotKnownWithManagedApp"
export type ManagedDevicePartnerReportedHealthState = "unknown" | "activated" | "deactivated" | "secured" | "lowSeverity" | "mediumSeverity" | "highSeverity" | "unresponsive" | "compromised" | "misconfigured"
export type DeviceManagementSubscriptionState = "pending" | "active" | "warning" | "disabled" | "deleted" | "blocked" | "lockedOut"
export type Windows10EditionType = "windows10Enterprise" | "windows10EnterpriseN" | "windows10Education" | "windows10EducationN" | "windows10MobileEnterprise" | "windows10HolographicEnterprise" | "windows10Professional" | "windows10ProfessionalN" | "windows10ProfessionalEducation" | "windows10ProfessionalEducationN" | "windows10ProfessionalWorkstation" | "windows10ProfessionalWorkstationN"
export type AppListType = "none" | "appsInListCompliant" | "appsNotInListCompliant"
export type AndroidRequiredPasswordType = "deviceDefault" | "alphabetic" | "alphanumeric" | "alphanumericWithSymbols" | "lowSecurityBiometric" | "numeric" | "numericComplex" | "any"
export type WebBrowserCookieSettings = "browserDefault" | "blockAlways" | "allowCurrentWebSite" | "allowFromWebsitesVisited" | "allowAlways"
export type AndroidWorkProfileRequiredPasswordType = "deviceDefault" | "lowSecurityBiometric" | "required" | "atLeastNumeric" | "numericComplex" | "atLeastAlphabetic" | "atLeastAlphanumeric" | "alphanumericWithSymbols"
export type AndroidWorkProfileCrossProfileDataSharingType = "deviceDefault" | "preventAny" | "allowPersonalToWork" | "noRestrictions"
export type AndroidWorkProfileDefaultAppPermissionPolicyType = "deviceDefault" | "prompt" | "autoGrant" | "autoDeny"
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
export type IosNotificationAlertType = "deviceDefault" | "banner" | "modal" | "none"
export type EditionUpgradeLicenseType = "productKey" | "licenseFile"
export type StateManagementSetting = "notConfigured" | "blocked" | "allowed"
export type FirewallPreSharedKeyEncodingMethodType = "deviceDefault" | "none" | "utF8"
export type FirewallCertificateRevocationListCheckMethodType = "deviceDefault" | "none" | "attempt" | "require"
export type FirewallPacketQueueingMethodType = "deviceDefault" | "disabled" | "queueInbound" | "queueOutbound" | "queueBoth"
export type AppLockerApplicationControlType = "notConfigured" | "enforceComponentsAndStoreApps" | "auditComponentsAndStoreApps" | "enforceComponentsStoreAppsAndSmartlocker" | "auditComponentsStoreAppsAndSmartlocker"
export type ApplicationGuardBlockFileTransferType = "notConfigured" | "blockImageAndTextFile" | "blockImageFile" | "blockNone" | "blockTextFile"
export type ApplicationGuardBlockClipboardSharingType = "notConfigured" | "blockBoth" | "blockHostToContainer" | "blockContainerToHost" | "blockNone"
export type BitLockerEncryptionMethod = "aesCbc128" | "aesCbc256" | "xtsAes128" | "xtsAes256"
export type DiagnosticDataSubmissionMode = "userDefined" | "none" | "basic" | "enhanced" | "full"
export type EdgeCookiePolicy = "userDefined" | "allow" | "blockThirdParty" | "blockAll"
export type VisibilitySetting = "notConfigured" | "hide" | "show"
export type DefenderThreatAction = "deviceDefault" | "clean" | "quarantine" | "remove" | "allow" | "userDefined" | "block"
export type WeeklySchedule = "userDefined" | "everyday" | "sunday" | "monday" | "tuesday" | "wednesday" | "thursday" | "friday" | "saturday"
export type DefenderMonitorFileActivity = "userDefined" | "disable" | "monitorAllFiles" | "monitorIncomingFilesOnly" | "monitorOutgoingFilesOnly"
export type DefenderPromptForSampleSubmission = "userDefined" | "alwaysPrompt" | "promptBeforeSendingPersonalData" | "neverSendData" | "sendAllDataWithoutPrompting"
export type DefenderScanType = "userDefined" | "disabled" | "quick" | "full"
export type DefenderCloudBlockLevelType = "notConfigured" | "high" | "highPlus" | "zeroTolerance"
export type WindowsStartMenuAppListVisibilityType = "userDefined" | "collapse" | "remove" | "disableSettingsApp"
export type WindowsStartMenuModeType = "userDefined" | "fullScreen" | "nonFullScreen"
export type WindowsSpotlightEnablementSettings = "notConfigured" | "disabled" | "enabled"
export type AutomaticUpdateMode = "userDefined" | "notifyDownload" | "autoInstallAtMaintenanceTime" | "autoInstallAndRebootAtMaintenanceTime" | "autoInstallAndRebootAtScheduledTime" | "autoInstallAndRebootWithoutEndUserControl"
export type SafeSearchFilterType = "userDefined" | "strict" | "moderate"
export type EdgeSearchEngineType = "default" | "bing"
export type PrereleaseFeatures = "userDefined" | "settingsOnly" | "settingsAndExperimentations" | "notAllowed"
export type WindowsDeliveryOptimizationMode = "userDefined" | "httpOnly" | "httpWithPeeringNat" | "httpWithPeeringPrivateGroup" | "httpWithInternetPeering" | "simpleDownload" | "bypassMode"
export type SharedPCAccountDeletionPolicyType = "immediate" | "diskSpaceThreshold" | "diskSpaceThresholdOrInactiveThreshold"
export type SharedPCAllowedAccountType = "guest" | "domain"
export type WindowsUpdateType = "userDefined" | "all" | "businessReadyOnly" | "windowsInsiderBuildFast" | "windowsInsiderBuildSlow" | "windowsInsiderBuildRelease"
export type InternetSiteSecurityLevel = "userDefined" | "medium" | "mediumHigh" | "high"
export type SiteSecurityLevel = "userDefined" | "low" | "mediumLow" | "medium" | "mediumHigh" | "high"
export type WindowsUserAccountControlSettings = "userDefined" | "alwaysNotify" | "notifyOnAppChanges" | "notifyOnAppChangesWithoutDimming" | "neverNotify"
export type MiracastChannel = "userDefined" | "one" | "two" | "three" | "four" | "five" | "six" | "seven" | "eight" | "nine" | "ten" | "eleven" | "thirtySix" | "forty" | "fortyFour" | "fortyEight" | "oneHundredFortyNine" | "oneHundredFiftyThree" | "oneHundredFiftySeven" | "oneHundredSixtyOne" | "oneHundredSixtyFive"
export type WelcomeScreenMeetingInformation = "userDefined" | "showOrganizerAndTimeOnly" | "showOrganizerAndTimeAndSubject"
export type DeviceComplianceActionType = "noAction" | "notification" | "block" | "retire" | "wipe" | "removeResourceAccessProfiles" | "pushNotification"
export type DeviceThreatProtectionLevel = "unavailable" | "secured" | "low" | "medium" | "high" | "notSet"
export type PolicyPlatformType = "android" | "iOS" | "macOS" | "windowsPhone81" | "windows81AndLater" | "windows10AndLater" | "androidWorkProfile" | "all"
export type IosUpdatesInstallStatus = "success" | "available" | "idle" | "unknown" | "downloading" | "downloadFailed" | "downloadRequiresComputer" | "downloadInsufficientSpace" | "downloadInsufficientPower" | "downloadInsufficientNetwork" | "installing" | "installInsufficientSpace" | "installInsufficientPower" | "installPhoneCallInProgress" | "installFailed" | "notSupportedOperation" | "sharedDeviceUserLoggedInError"
export type DeviceManagementExchangeConnectorSyncType = "fullSync" | "deltaSync"
export type MdmAuthority = "unknown" | "intune" | "sccm" | "office365"
export type WindowsHelloForBusinessPinUsage = "allowed" | "required" | "disallowed"
export type Enablement = "notConfigured" | "enabled" | "disabled"
export type VppTokenState = "unknown" | "valid" | "expired" | "invalid" | "assignedToExternalMDM"
export type VppTokenSyncStatus = "none" | "inProgress" | "completed" | "failed"
export type DeviceManagementExchangeConnectorStatus = "none" | "connectionPending" | "connected" | "disconnected"
export type DeviceManagementExchangeConnectorType = "onPremises" | "hosted" | "serviceToService" | "dedicated"
export type MobileThreatPartnerTenantState = "unavailable" | "available" | "enabled" | "unresponsive"
export type DeviceManagementPartnerTenantState = "unknown" | "unavailable" | "enabled" | "terminated" | "rejected" | "unresponsive"
export type DeviceManagementPartnerAppType = "unknown" | "singleTenantApp" | "multiTenantApp"
export type ManagedAppDataTransferLevel = "allApps" | "managedApps" | "none"
export type ManagedAppClipboardSharingLevel = "allApps" | "managedAppsWithPasteIn" | "managedApps" | "blocked"
export type ManagedAppPinCharacterSet = "numeric" | "alphanumericAndSymbol"
export type ManagedAppDataStorageLocation = "oneDriveForBusiness" | "sharePoint" | "localStorage"
export type ManagedAppDataEncryptionType = "useDeviceSettings" | "afterDeviceRestart" | "whenDeviceLockedExceptOpenFiles" | "whenDeviceLocked"
export type WindowsInformationProtectionEnforcementLevel = "noProtection" | "encryptAndAuditOnly" | "encryptAuditAndPrompt" | "encryptAuditAndBlock"
export type WindowsInformationProtectionPinCharacterRequirements = "notAllow" | "requireAtLeastOne" | "allow"
export type ManagedAppFlaggedReason = "none" | "rootedDevice"
export type NotificationTemplateBrandingOptions = "none" | "includeCompanyLogo" | "includeCompanyName" | "includeContactInformation"
export type InstallState = "notApplicable" | "installed" | "failed" | "notInstalled" | "uninstallFailed" | "unknown"
export type RemoteAssistanceOnboardingStatus = "notOnboarded" | "onboarding" | "onboarded"
export type ApplicationType = "universal" | "desktop"
export type DeviceEnrollmentFailureReason = "unknown" | "authentication" | "authorization" | "accountValidation" | "userValidation" | "deviceNotSupported" | "inMaintenance" | "badRequest" | "featureNotSupported" | "enrollmentRestrictionsEnforced" | "clientDisconnected" | "userAbandonment"
export type Status = "active" | "updated" | "deleted" | "ignored" | "unknownFutureValue"
export type AlertFeedback = "unknown" | "truePositive" | "falsePositive" | "benignPositive" | "unknownFutureValue"
export type AlertSeverity = "unknown" | "informational" | "low" | "medium" | "high" | "unknownFutureValue"
export type AlertStatus = "unknown" | "newAlert" | "inProgress" | "resolved" | "dismissed" | "unknownFutureValue"
export type ConnectionDirection = "unknown" | "inbound" | "outbound" | "unknownFutureValue"
export type ConnectionStatus = "unknown" | "attempted" | "succeeded" | "blocked" | "failed" | "unknownFutureValue"
export type EmailRole = "unknown" | "sender" | "recipient" | "unknownFutureValue"
export type FileHashType = "unknown" | "sha1" | "sha256" | "md5" | "authenticodeHash256" | "lsHash" | "ctph" | "unknownFutureValue"
export type LogonType = "unknown" | "interactive" | "remoteInteractive" | "network" | "batch" | "service" | "unknownFutureValue"
export type ProcessIntegrityLevel = "unknown" | "untrusted" | "low" | "medium" | "high" | "system" | "unknownFutureValue"
export type RegistryHive = "unknown" | "currentConfig" | "currentUser" | "localMachineSam" | "localMachineSecurity" | "localMachineSoftware" | "localMachineSystem" | "usersDefault" | "unknownFutureValue"
export type RegistryOperation = "unknown" | "create" | "modify" | "delete" | "unknownFutureValue"
export type RegistryValueType = "unknown" | "binary" | "dword" | "dwordLittleEndian" | "dwordBigEndian" | "expandSz" | "link" | "multiSz" | "none" | "qword" | "qwordlittleEndian" | "sz" | "unknownFutureValue"
export type SecurityNetworkProtocol = "ip" | "icmp" | "igmp" | "ggp" | "ipv4" | "tcp" | "pup" | "udp" | "idp" | "ipv6" | "ipv6RoutingHeader" | "ipv6FragmentHeader" | "ipSecEncapsulatingSecurityPayload" | "ipSecAuthenticationHeader" | "icmpV6" | "ipv6NoNextHeader" | "ipv6DestinationOptions" | "nd" | "raw" | "ipx" | "spx" | "spxII" | "unknownFutureValue" | "unknown"
export type UserAccountSecurityType = "unknown" | "standard" | "power" | "administrator" | "unknownFutureValue"
export type TeamVisibilityType = "private" | "public" | "hiddenMembership" | "unknownFutureValue"
export type ClonableTeamParts = "apps" | "tabs" | "settings" | "channels" | "members"
export type GiphyRatingType = "moderate" | "strict" | "unknownFutureValue"
export type TeamsAsyncOperationType = "invalid" | "cloneTeam" | "archiveTeam" | "unarchiveTeam" | "createTeam" | "unknownFutureValue"
export type TeamsAsyncOperationStatus = "invalid" | "notStarted" | "inProgress" | "succeeded" | "failed" | "unknownFutureValue"
export type TeamsAppDistributionMethod = "store" | "organization" | "sideloaded" | "unknownFutureValue"
export type DataPolicyOperationStatus = "notStarted" | "running" | "complete" | "failed" | "unknownFutureValue"

export interface Entity {

		id?: string

}

export interface Directory extends Entity {

		deletedItems?: DirectoryObject[]

}

export interface DirectoryObject extends Entity {

		deletedDateTime?: string

}

export interface Device extends DirectoryObject {

		accountEnabled?: boolean

		alternativeSecurityIds?: AlternativeSecurityId[]

		approximateLastSignInDateTime?: string

		deviceId?: string

		deviceMetadata?: string

		deviceVersion?: number

		displayName?: string

		isCompliant?: boolean

		isManaged?: boolean

		onPremisesLastSyncDateTime?: string

		onPremisesSyncEnabled?: boolean

		operatingSystem?: string

		operatingSystemVersion?: string

		physicalIds?: string[]

		trustType?: string

		registeredOwners?: DirectoryObject[]

		registeredUsers?: DirectoryObject[]

		extensions?: Extension[]

}

export interface Extension extends Entity {

}

export interface DirectoryRole extends DirectoryObject {

		description?: string

		displayName?: string

		roleTemplateId?: string

		members?: DirectoryObject[]

}

export interface DirectoryRoleTemplate extends DirectoryObject {

		description?: string

		displayName?: string

}

export interface Domain extends Entity {

		authenticationType?: string

		availabilityStatus?: string

		isAdminManaged?: boolean

		isDefault?: boolean

		isInitial?: boolean

		isRoot?: boolean

		isVerified?: boolean

		supportedServices?: string[]

		state?: DomainState

		serviceConfigurationRecords?: DomainDnsRecord[]

		verificationDnsRecords?: DomainDnsRecord[]

		domainNameReferences?: DirectoryObject[]

}

export interface DomainDnsRecord extends Entity {

		isOptional?: boolean

		label?: string

		recordType?: string

		supportedService?: string

		ttl?: number

}

export interface DomainDnsCnameRecord extends DomainDnsRecord {

		canonicalName?: string

}

export interface DomainDnsMxRecord extends DomainDnsRecord {

		mailExchange?: string

		preference?: number

}

export interface DomainDnsSrvRecord extends DomainDnsRecord {

		nameTarget?: string

		port?: number

		priority?: number

		protocol?: string

		service?: string

		weight?: number

}

export interface DomainDnsTxtRecord extends DomainDnsRecord {

		text?: string

}

export interface DomainDnsUnavailableRecord extends DomainDnsRecord {

		description?: string

}

export interface LicenseDetails extends Entity {

		servicePlans?: ServicePlanInfo[]

		skuId?: string

		skuPartNumber?: string

}

export interface Group extends DirectoryObject {

		classification?: string

		createdDateTime?: string

		description?: string

		displayName?: string

		groupTypes?: string[]

		mail?: string

		mailEnabled?: boolean

		mailNickname?: string

		onPremisesLastSyncDateTime?: string

		onPremisesProvisioningErrors?: OnPremisesProvisioningError[]

		onPremisesSecurityIdentifier?: string

		onPremisesSyncEnabled?: boolean

		proxyAddresses?: string[]

		renewedDateTime?: string

		securityEnabled?: boolean

		visibility?: string

		allowExternalSenders?: boolean

		autoSubscribeNewMembers?: boolean

		isSubscribedByMail?: boolean

		unseenCount?: number

		isArchived?: boolean

		members?: DirectoryObject[]

		memberOf?: DirectoryObject[]

		createdOnBehalfOf?: DirectoryObject

		owners?: DirectoryObject[]

		settings?: GroupSetting[]

		extensions?: Extension[]

		threads?: ConversationThread[]

		calendar?: Calendar

		calendarView?: Event[]

		events?: Event[]

		conversations?: Conversation[]

		photo?: ProfilePhoto

		photos?: ProfilePhoto[]

		acceptedSenders?: DirectoryObject[]

		rejectedSenders?: DirectoryObject[]

		drive?: Drive

		drives?: Drive[]

		sites?: Site[]

		planner?: PlannerGroup

		onenote?: Onenote

		groupLifecyclePolicies?: GroupLifecyclePolicy[]

		team?: Team

}

export interface GroupSetting extends Entity {

		displayName?: string

		templateId?: string

		values?: SettingValue[]

}

export interface ConversationThread extends Entity {

		toRecipients?: Recipient[]

		topic?: string

		hasAttachments?: boolean

		lastDeliveredDateTime?: string

		uniqueSenders?: string[]

		ccRecipients?: Recipient[]

		preview?: string

		isLocked?: boolean

		posts?: Post[]

}

export interface Calendar extends Entity {

		name?: string

		color?: CalendarColor

		changeKey?: string

		canShare?: boolean

		canViewPrivateItems?: boolean

		canEdit?: boolean

		owner?: EmailAddress

		events?: Event[]

		calendarView?: Event[]

		singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

		multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

}

export interface OutlookItem extends Entity {

		createdDateTime?: string

		lastModifiedDateTime?: string

		changeKey?: string

		categories?: string[]

}

export interface Event extends OutlookItem {

		originalStartTimeZone?: string

		originalEndTimeZone?: string

		responseStatus?: ResponseStatus

		iCalUId?: string

		reminderMinutesBeforeStart?: number

		isReminderOn?: boolean

		hasAttachments?: boolean

		subject?: string

		body?: ItemBody

		bodyPreview?: string

		importance?: Importance

		sensitivity?: Sensitivity

		start?: DateTimeTimeZone

		originalStart?: string

		end?: DateTimeTimeZone

		location?: Location

		locations?: Location[]

		isAllDay?: boolean

		isCancelled?: boolean

		isOrganizer?: boolean

		recurrence?: PatternedRecurrence

		responseRequested?: boolean

		seriesMasterId?: string

		showAs?: FreeBusyStatus

		type?: EventType

		attendees?: Attendee[]

		organizer?: Recipient

		webLink?: string

		onlineMeetingUrl?: string

		calendar?: Calendar

		instances?: Event[]

		extensions?: Extension[]

		attachments?: Attachment[]

		singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

		multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

}

export interface Conversation extends Entity {

		topic?: string

		hasAttachments?: boolean

		lastDeliveredDateTime?: string

		uniqueSenders?: string[]

		preview?: string

		threads?: ConversationThread[]

}

export interface ProfilePhoto extends Entity {

		height?: number

		width?: number

}

export interface BaseItem extends Entity {

		createdBy?: IdentitySet

		createdDateTime?: string

		description?: string

		eTag?: string

		lastModifiedBy?: IdentitySet

		lastModifiedDateTime?: string

		name?: string

		parentReference?: ItemReference

		webUrl?: string

		createdByUser?: User

		lastModifiedByUser?: User

}

export interface Drive extends BaseItem {

		driveType?: string

		owner?: IdentitySet

		quota?: Quota

		sharePointIds?: SharepointIds

		system?: SystemFacet

		items?: DriveItem[]

		list?: List

		root?: DriveItem

		special?: DriveItem[]

}

export interface Site extends BaseItem {

		displayName?: string

		root?: Root

		sharepointIds?: SharepointIds

		siteCollection?: SiteCollection

		columns?: ColumnDefinition[]

		contentTypes?: ContentType[]

		drive?: Drive

		drives?: Drive[]

		items?: BaseItem[]

		lists?: List[]

		sites?: Site[]

		onenote?: Onenote

}

export interface PlannerGroup extends Entity {

		plans?: PlannerPlan[]

}

export interface Onenote extends Entity {

		notebooks?: Notebook[]

		sections?: OnenoteSection[]

		sectionGroups?: SectionGroup[]

		pages?: OnenotePage[]

		resources?: OnenoteResource[]

		operations?: OnenoteOperation[]

}

export interface GroupLifecyclePolicy extends Entity {

		groupLifetimeInDays?: number

		managedGroupTypes?: string

		alternateNotificationEmails?: string

}

export interface Team extends Entity {

		webUrl?: string

		memberSettings?: TeamMemberSettings

		guestSettings?: TeamGuestSettings

		messagingSettings?: TeamMessagingSettings

		funSettings?: TeamFunSettings

		isArchived?: boolean

		channels?: Channel[]

		installedApps?: TeamsAppInstallation[]

		operations?: TeamsAsyncOperation[]

}

export interface Contract extends DirectoryObject {

		contractType?: string

		customerId?: string

		defaultDomainName?: string

		displayName?: string

}

export interface SubscribedSku extends Entity {

		capabilityStatus?: string

		consumedUnits?: number

		prepaidUnits?: LicenseUnitsDetail

		servicePlans?: ServicePlanInfo[]

		skuId?: string

		skuPartNumber?: string

		appliesTo?: string

}

export interface Organization extends DirectoryObject {

		assignedPlans?: AssignedPlan[]

		businessPhones?: string[]

		city?: string

		country?: string

		countryLetterCode?: string

		displayName?: string

		marketingNotificationEmails?: string[]

		onPremisesLastSyncDateTime?: string

		onPremisesSyncEnabled?: boolean

		postalCode?: string

		preferredLanguage?: string

		privacyProfile?: PrivacyProfile

		provisionedPlans?: ProvisionedPlan[]

		securityComplianceNotificationMails?: string[]

		securityComplianceNotificationPhones?: string[]

		state?: string

		street?: string

		technicalNotificationMails?: string[]

		verifiedDomains?: VerifiedDomain[]

		mobileDeviceManagementAuthority?: MdmAuthority

		extensions?: Extension[]

}

export interface User extends DirectoryObject {

		accountEnabled?: boolean

		ageGroup?: string

		assignedLicenses?: AssignedLicense[]

		assignedPlans?: AssignedPlan[]

		businessPhones?: string[]

		city?: string

		companyName?: string

		consentProvidedForMinor?: string

		country?: string

		department?: string

		displayName?: string

		givenName?: string

		imAddresses?: string[]

		jobTitle?: string

		legalAgeGroupClassification?: string

		mail?: string

		mailNickname?: string

		mobilePhone?: string

		onPremisesExtensionAttributes?: OnPremisesExtensionAttributes

		onPremisesImmutableId?: string

		onPremisesLastSyncDateTime?: string

		onPremisesProvisioningErrors?: OnPremisesProvisioningError[]

		onPremisesSecurityIdentifier?: string

		onPremisesSyncEnabled?: boolean

		onPremisesDomainName?: string

		onPremisesSamAccountName?: string

		onPremisesUserPrincipalName?: string

		passwordPolicies?: string

		passwordProfile?: PasswordProfile

		officeLocation?: string

		postalCode?: string

		preferredLanguage?: string

		provisionedPlans?: ProvisionedPlan[]

		proxyAddresses?: string[]

		state?: string

		streetAddress?: string

		surname?: string

		usageLocation?: string

		userPrincipalName?: string

		userType?: string

		mailboxSettings?: MailboxSettings

		aboutMe?: string

		birthday?: string

		hireDate?: string

		interests?: string[]

		mySite?: string

		pastProjects?: string[]

		preferredName?: string

		responsibilities?: string[]

		schools?: string[]

		skills?: string[]

		deviceEnrollmentLimit?: number

		ownedDevices?: DirectoryObject[]

		registeredDevices?: DirectoryObject[]

		manager?: DirectoryObject

		directReports?: DirectoryObject[]

		memberOf?: DirectoryObject[]

		createdObjects?: DirectoryObject[]

		ownedObjects?: DirectoryObject[]

		licenseDetails?: LicenseDetails[]

		extensions?: Extension[]

		outlook?: OutlookUser

		messages?: Message[]

		mailFolders?: MailFolder[]

		calendar?: Calendar

		calendars?: Calendar[]

		calendarGroups?: CalendarGroup[]

		calendarView?: Event[]

		events?: Event[]

		people?: Person[]

		contacts?: Contact[]

		contactFolders?: ContactFolder[]

		inferenceClassification?: InferenceClassification

		photo?: ProfilePhoto

		photos?: ProfilePhoto[]

		drive?: Drive

		drives?: Drive[]

		planner?: PlannerUser

		onenote?: Onenote

		managedDevices?: ManagedDevice[]

		managedAppRegistrations?: ManagedAppRegistration[]

		deviceManagementTroubleshootingEvents?: DeviceManagementTroubleshootingEvent[]

		activities?: UserActivity[]

		insights?: OfficeGraphInsights

		settings?: UserSettings

		joinedTeams?: Group[]

}

export interface OutlookUser extends Entity {

		masterCategories?: OutlookCategory[]

}

export interface Message extends OutlookItem {

		receivedDateTime?: string

		sentDateTime?: string

		hasAttachments?: boolean

		internetMessageId?: string

		internetMessageHeaders?: InternetMessageHeader[]

		subject?: string

		body?: ItemBody

		bodyPreview?: string

		importance?: Importance

		parentFolderId?: string

		sender?: Recipient

		from?: Recipient

		toRecipients?: Recipient[]

		ccRecipients?: Recipient[]

		bccRecipients?: Recipient[]

		replyTo?: Recipient[]

		conversationId?: string

		uniqueBody?: ItemBody

		isDeliveryReceiptRequested?: boolean

		isReadReceiptRequested?: boolean

		isRead?: boolean

		isDraft?: boolean

		webLink?: string

		inferenceClassification?: InferenceClassificationType

		flag?: FollowupFlag

		attachments?: Attachment[]

		extensions?: Extension[]

		singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

		multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

}

export interface MailFolder extends Entity {

		displayName?: string

		parentFolderId?: string

		childFolderCount?: number

		unreadItemCount?: number

		totalItemCount?: number

		messages?: Message[]

		messageRules?: MessageRule[]

		childFolders?: MailFolder[]

		singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

		multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

}

export interface CalendarGroup extends Entity {

		name?: string

		classId?: string

		changeKey?: string

		calendars?: Calendar[]

}

export interface Person extends Entity {

		displayName?: string

		givenName?: string

		surname?: string

		birthday?: string

		personNotes?: string

		isFavorite?: boolean

		scoredEmailAddresses?: ScoredEmailAddress[]

		phones?: Phone[]

		postalAddresses?: Location[]

		websites?: Website[]

		jobTitle?: string

		companyName?: string

		yomiCompany?: string

		department?: string

		officeLocation?: string

		profession?: string

		personType?: PersonType

		userPrincipalName?: string

		imAddress?: string

}

export interface Contact extends OutlookItem {

		parentFolderId?: string

		birthday?: string

		fileAs?: string

		displayName?: string

		givenName?: string

		initials?: string

		middleName?: string

		nickName?: string

		surname?: string

		title?: string

		yomiGivenName?: string

		yomiSurname?: string

		yomiCompanyName?: string

		generation?: string

		emailAddresses?: EmailAddress[]

		imAddresses?: string[]

		jobTitle?: string

		companyName?: string

		department?: string

		officeLocation?: string

		profession?: string

		businessHomePage?: string

		assistantName?: string

		manager?: string

		homePhones?: string[]

		mobilePhone?: string

		businessPhones?: string[]

		homeAddress?: PhysicalAddress

		businessAddress?: PhysicalAddress

		otherAddress?: PhysicalAddress

		spouseName?: string

		personalNotes?: string

		children?: string[]

		extensions?: Extension[]

		singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

		multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

		photo?: ProfilePhoto

}

export interface ContactFolder extends Entity {

		parentFolderId?: string

		displayName?: string

		contacts?: Contact[]

		childFolders?: ContactFolder[]

		singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

		multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

}

export interface InferenceClassification extends Entity {

		overrides?: InferenceClassificationOverride[]

}

export interface PlannerUser extends Entity {

		tasks?: PlannerTask[]

		plans?: PlannerPlan[]

}

export interface ManagedDevice extends Entity {

		userId?: string

		deviceName?: string

		managedDeviceOwnerType?: ManagedDeviceOwnerType

		deviceActionResults?: DeviceActionResult[]

		enrolledDateTime?: string

		lastSyncDateTime?: string

		operatingSystem?: string

		complianceState?: ComplianceState

		jailBroken?: string

		managementAgent?: ManagementAgentType

		osVersion?: string

		easActivated?: boolean

		easDeviceId?: string

		easActivationDateTime?: string

		azureADRegistered?: boolean

		deviceEnrollmentType?: DeviceEnrollmentType

		activationLockBypassCode?: string

		emailAddress?: string

		azureADDeviceId?: string

		deviceRegistrationState?: DeviceRegistrationState

		deviceCategoryDisplayName?: string

		isSupervised?: boolean

		exchangeLastSuccessfulSyncDateTime?: string

		exchangeAccessState?: DeviceManagementExchangeAccessState

		exchangeAccessStateReason?: DeviceManagementExchangeAccessStateReason

		remoteAssistanceSessionUrl?: string

		remoteAssistanceSessionErrorDetails?: string

		isEncrypted?: boolean

		userPrincipalName?: string

		model?: string

		manufacturer?: string

		imei?: string

		complianceGracePeriodExpirationDateTime?: string

		serialNumber?: string

		phoneNumber?: string

		androidSecurityPatchLevel?: string

		userDisplayName?: string

		configurationManagerClientEnabledFeatures?: ConfigurationManagerClientEnabledFeatures

		wiFiMacAddress?: string

		deviceHealthAttestationState?: DeviceHealthAttestationState

		subscriberCarrier?: string

		meid?: string

		totalStorageSpaceInBytes?: number

		freeStorageSpaceInBytes?: number

		managedDeviceName?: string

		partnerReportedThreatState?: ManagedDevicePartnerReportedHealthState

		deviceConfigurationStates?: DeviceConfigurationState[]

		deviceCategory?: DeviceCategory

		deviceCompliancePolicyStates?: DeviceCompliancePolicyState[]

}

export interface ManagedAppRegistration extends Entity {

		createdDateTime?: string

		lastSyncDateTime?: string

		applicationVersion?: string

		managementSdkVersion?: string

		platformVersion?: string

		deviceType?: string

		deviceTag?: string

		deviceName?: string

		flaggedReasons?: ManagedAppFlaggedReason[]

		userId?: string

		appIdentifier?: MobileAppIdentifier

		version?: string

		appliedPolicies?: ManagedAppPolicy[]

		intendedPolicies?: ManagedAppPolicy[]

		operations?: ManagedAppOperation[]

}

export interface DeviceManagementTroubleshootingEvent extends Entity {

		eventDateTime?: string

		correlationId?: string

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

export interface OfficeGraphInsights extends Entity {

		trending?: Trending[]

		shared?: SharedInsight[]

		used?: UsedInsight[]

}

export interface UserSettings extends Entity {

		contributionToContentDiscoveryDisabled?: boolean

		contributionToContentDiscoveryAsOrganizationDisabled?: boolean

}

export interface GroupSettingTemplate extends DirectoryObject {

		displayName?: string

		description?: string

		values?: SettingTemplateValue[]

}

export interface SchemaExtension extends Entity {

		description?: string

		targetTypes?: string[]

		properties?: ExtensionSchemaProperty[]

		status?: string

		owner?: string

}

export interface Attachment extends Entity {

		lastModifiedDateTime?: string

		name?: string

		contentType?: string

		size?: number

		isInline?: boolean

}

export interface OutlookCategory extends Entity {

		displayName?: string

		color?: CategoryColor

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

export interface SingleValueLegacyExtendedProperty extends Entity {

		value?: string

}

export interface MultiValueLegacyExtendedProperty extends Entity {

		value?: string[]

}

export interface FileAttachment extends Attachment {

		contentId?: string

		contentLocation?: string

		contentBytes?: number

}

export interface ItemAttachment extends Attachment {

		item?: OutlookItem

}

export interface EventMessage extends Message {

		meetingMessageType?: MeetingMessageType

		event?: Event

}

export interface ReferenceAttachment extends Attachment {

}

export interface OpenTypeExtension extends Extension {

		extensionName?: string

}

export interface Post extends OutlookItem {

		body?: ItemBody

		receivedDateTime?: string

		hasAttachments?: boolean

		from?: Recipient

		sender?: Recipient

		conversationThreadId?: string

		newParticipants?: Recipient[]

		conversationId?: string

		extensions?: Extension[]

		inReplyTo?: Post

		attachments?: Attachment[]

		singleValueExtendedProperties?: SingleValueLegacyExtendedProperty[]

		multiValueExtendedProperties?: MultiValueLegacyExtendedProperty[]

}

export interface InferenceClassificationOverride extends Entity {

		classifyAs?: InferenceClassificationType

		senderEmailAddress?: EmailAddress

}

export interface BaseItemVersion extends Entity {

		lastModifiedBy?: IdentitySet

		lastModifiedDateTime?: string

		publication?: PublicationFacet

}

export interface ColumnDefinition extends Entity {

		boolean?: BooleanColumn

		calculated?: CalculatedColumn

		choice?: ChoiceColumn

		columnGroup?: string

		currency?: CurrencyColumn

		dateTime?: DateTimeColumn

		defaultValue?: DefaultColumnValue

		description?: string

		displayName?: string

		enforceUniqueValues?: boolean

		hidden?: boolean

		indexed?: boolean

		lookup?: LookupColumn

		name?: string

		number?: NumberColumn

		personOrGroup?: PersonOrGroupColumn

		readOnly?: boolean

		required?: boolean

		text?: TextColumn

}

export interface ColumnLink extends Entity {

		name?: string

}

export interface ContentType extends Entity {

		description?: string

		group?: string

		hidden?: boolean

		inheritedFrom?: ItemReference

		name?: string

		order?: ContentTypeOrder

		parentId?: string

		readOnly?: boolean

		sealed?: boolean

		columnLinks?: ColumnLink[]

}

export interface DriveItem extends BaseItem {

		audio?: Audio

		content?: any

		cTag?: string

		deleted?: Deleted

		file?: File

		fileSystemInfo?: FileSystemInfo

		folder?: Folder

		image?: Image

		location?: GeoCoordinates

		package?: Package

		photo?: Photo

		publication?: PublicationFacet

		remoteItem?: RemoteItem

		root?: Root

		searchResult?: SearchResult

		shared?: Shared

		sharepointIds?: SharepointIds

		size?: number

		specialFolder?: SpecialFolder

		video?: Video

		webDavUrl?: string

		children?: DriveItem[]

		listItem?: ListItem

		permissions?: Permission[]

		thumbnails?: ThumbnailSet[]

		versions?: DriveItemVersion[]

		workbook?: Workbook

}

export interface List extends BaseItem {

		displayName?: string

		list?: ListInfo

		sharepointIds?: SharepointIds

		system?: SystemFacet

		columns?: ColumnDefinition[]

		contentTypes?: ContentType[]

		drive?: Drive

		items?: ListItem[]

}

export interface ListItem extends BaseItem {

		contentType?: ContentTypeInfo

		sharepointIds?: SharepointIds

		driveItem?: DriveItem

		fields?: FieldValueSet

		versions?: ListItemVersion[]

}

export interface Permission extends Entity {

		grantedTo?: IdentitySet

		inheritedFrom?: ItemReference

		invitation?: SharingInvitation

		link?: SharingLink

		roles?: string[]

		shareId?: string

}

export interface ThumbnailSet extends Entity {

		large?: Thumbnail

		medium?: Thumbnail

		small?: Thumbnail

		source?: Thumbnail

}

export interface DriveItemVersion extends BaseItemVersion {

		content?: any

		size?: number

}

export interface Workbook extends Entity {

		application?: WorkbookApplication

		names?: WorkbookNamedItem[]

		tables?: WorkbookTable[]

		worksheets?: WorkbookWorksheet[]

		functions?: WorkbookFunctions

}

export interface FieldValueSet extends Entity {

}

export interface ListItemVersion extends BaseItemVersion {

		fields?: FieldValueSet

}

export interface SharedDriveItem extends BaseItem {

		owner?: IdentitySet

		driveItem?: DriveItem

		items?: DriveItem[]

		list?: List

		listItem?: ListItem

		root?: DriveItem

		site?: Site

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

		name?: string

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

		columnCount?: number

		formulas?: any

		formulasLocal?: any

		formulasR1C1?: any

		index?: number

		numberFormat?: any

		rowCount?: number

		text?: any

		valueTypes?: any

		values?: any

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

export interface Subscription extends Entity {

		resource?: string

		changeType?: string

		clientState?: string

		notificationUrl?: string

		expirationDateTime?: string

		applicationId?: string

		creatorId?: string

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

export interface PlannerTask extends Entity {

		createdBy?: IdentitySet

		planId?: string

		bucketId?: string

		title?: string

		orderHint?: string

		assigneePriority?: string

		percentComplete?: number

		startDateTime?: string

		createdDateTime?: string

		dueDateTime?: string

		hasDescription?: boolean

		previewType?: PlannerPreviewType

		completedDateTime?: string

		completedBy?: IdentitySet

		referenceCount?: number

		checklistItemCount?: number

		activeChecklistItemCount?: number

		appliedCategories?: PlannerAppliedCategories

		assignments?: PlannerAssignments

		conversationThreadId?: string

		details?: PlannerTaskDetails

		assignedToTaskBoardFormat?: PlannerAssignedToTaskBoardTaskFormat

		progressTaskBoardFormat?: PlannerProgressTaskBoardTaskFormat

		bucketTaskBoardFormat?: PlannerBucketTaskBoardTaskFormat

}

export interface PlannerPlan extends Entity {

		createdBy?: IdentitySet

		createdDateTime?: string

		owner?: string

		title?: string

		tasks?: PlannerTask[]

		buckets?: PlannerBucket[]

		details?: PlannerPlanDetails

}

export interface Planner extends Entity {

		tasks?: PlannerTask[]

		plans?: PlannerPlan[]

		buckets?: PlannerBucket[]

}

export interface PlannerBucket extends Entity {

		name?: string

		planId?: string

		orderHint?: string

		tasks?: PlannerTask[]

}

export interface PlannerTaskDetails extends Entity {

		description?: string

		previewType?: PlannerPreviewType

		references?: PlannerExternalReferences

		checklist?: PlannerChecklistItems

}

export interface PlannerAssignedToTaskBoardTaskFormat extends Entity {

		unassignedOrderHint?: string

		orderHintsByAssignee?: PlannerOrderHintsByAssignee

}

export interface PlannerProgressTaskBoardTaskFormat extends Entity {

		orderHint?: string

}

export interface PlannerBucketTaskBoardTaskFormat extends Entity {

		orderHint?: string

}

export interface PlannerPlanDetails extends Entity {

		sharedWith?: PlannerUserIds

		categoryDescriptions?: PlannerCategoryDescriptions

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

		isDefault?: boolean

		userRole?: OnenoteUserRole

		isShared?: boolean

		sectionsUrl?: string

		sectionGroupsUrl?: string

		links?: NotebookLinks

		sections?: OnenoteSection[]

		sectionGroups?: SectionGroup[]

}

export interface OnenoteSection extends OnenoteEntityHierarchyModel {

		isDefault?: boolean

		links?: SectionLinks

		pagesUrl?: string

		parentNotebook?: Notebook

		parentSectionGroup?: SectionGroup

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

		title?: string

		createdByAppId?: string

		links?: PageLinks

		contentUrl?: string

		content?: any

		lastModifiedDateTime?: string

		level?: number

		order?: number

		userTags?: string[]

		parentSection?: OnenoteSection

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

		resourceLocation?: string

		resourceId?: string

		error?: OnenoteOperationError

		percentComplete?: string

}

export interface ReportRoot extends Entity {

}

export interface AdministrativeUnit extends DirectoryObject {

}

export interface EducationRoot extends Entity {

		classes?: EducationClass[]

		schools?: EducationSchool[]

		users?: EducationUser[]

		me?: EducationUser

}

export interface EducationClass extends Entity {

		displayName?: string

		mailNickname?: string

		description?: string

		createdBy?: IdentitySet

		classCode?: string

		externalName?: string

		externalId?: string

		externalSource?: EducationExternalSource

		term?: EducationTerm

		schools?: EducationSchool[]

		members?: EducationUser[]

		teachers?: EducationUser[]

		group?: Group

}

export interface EducationOrganization extends Entity {

		displayName?: string

		description?: string

		externalSource?: EducationExternalSource

}

export interface EducationSchool extends EducationOrganization {

		principalEmail?: string

		principalName?: string

		externalPrincipalId?: string

		lowestGrade?: string

		highestGrade?: string

		schoolNumber?: string

		externalId?: string

		phone?: string

		fax?: string

		createdBy?: IdentitySet

		address?: PhysicalAddress

		classes?: EducationClass[]

		users?: EducationUser[]

}

export interface EducationUser extends Entity {

		primaryRole?: EducationUserRole

		middleName?: string

		externalSource?: EducationExternalSource

		residenceAddress?: PhysicalAddress

		mailingAddress?: PhysicalAddress

		student?: EducationStudent

		teacher?: EducationTeacher

		createdBy?: IdentitySet

		relatedContacts?: EducationRelatedContact[]

		accountEnabled?: boolean

		assignedLicenses?: AssignedLicense[]

		assignedPlans?: AssignedPlan[]

		businessPhones?: string[]

		department?: string

		displayName?: string

		givenName?: string

		mail?: string

		mailNickname?: string

		mobilePhone?: string

		passwordPolicies?: string

		passwordProfile?: PasswordProfile

		officeLocation?: string

		preferredLanguage?: string

		provisionedPlans?: ProvisionedPlan[]

		refreshTokensValidFromDateTime?: string

		showInAddressList?: boolean

		surname?: string

		usageLocation?: string

		userPrincipalName?: string

		userType?: string

		schools?: EducationSchool[]

		classes?: EducationClass[]

		user?: User

}

export interface DeviceAppManagement extends Entity {

		microsoftStoreForBusinessLastSuccessfulSyncDateTime?: string

		isEnabledForMicrosoftStoreForBusiness?: boolean

		microsoftStoreForBusinessLanguage?: string

		microsoftStoreForBusinessLastCompletedApplicationSyncTime?: string

		mobileApps?: MobileApp[]

		mobileAppCategories?: MobileAppCategory[]

		mobileAppConfigurations?: ManagedDeviceMobileAppConfiguration[]

		vppTokens?: VppToken[]

		managedAppPolicies?: ManagedAppPolicy[]

		iosManagedAppProtections?: IosManagedAppProtection[]

		androidManagedAppProtections?: AndroidManagedAppProtection[]

		defaultManagedAppProtections?: DefaultManagedAppProtection[]

		targetedManagedAppConfigurations?: TargetedManagedAppConfiguration[]

		mdmWindowsInformationProtectionPolicies?: MdmWindowsInformationProtectionPolicy[]

		windowsInformationProtectionPolicies?: WindowsInformationProtectionPolicy[]

		managedAppRegistrations?: ManagedAppRegistration[]

		managedAppStatuses?: ManagedAppStatus[]

		managedEBooks?: ManagedEBook[]

}

export interface MobileApp extends Entity {

		displayName?: string

		description?: string

		publisher?: string

		largeIcon?: MimeContent

		createdDateTime?: string

		lastModifiedDateTime?: string

		isFeatured?: boolean

		privacyInformationUrl?: string

		informationUrl?: string

		owner?: string

		developer?: string

		notes?: string

		publishingState?: MobileAppPublishingState

		categories?: MobileAppCategory[]

		assignments?: MobileAppAssignment[]

}

export interface MobileAppCategory extends Entity {

		displayName?: string

		lastModifiedDateTime?: string

}

export interface ManagedDeviceMobileAppConfiguration extends Entity {

		targetedMobileApps?: string[]

		createdDateTime?: string

		description?: string

		lastModifiedDateTime?: string

		displayName?: string

		version?: number

		assignments?: ManagedDeviceMobileAppConfigurationAssignment[]

		deviceStatuses?: ManagedDeviceMobileAppConfigurationDeviceStatus[]

		userStatuses?: ManagedDeviceMobileAppConfigurationUserStatus[]

		deviceStatusSummary?: ManagedDeviceMobileAppConfigurationDeviceSummary

		userStatusSummary?: ManagedDeviceMobileAppConfigurationUserSummary

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

		lastSyncStatus?: VppTokenSyncStatus

		automaticallyUpdateApps?: boolean

		countryOrRegion?: string

}

export interface ManagedAppPolicy extends Entity {

		displayName?: string

		description?: string

		createdDateTime?: string

		lastModifiedDateTime?: string

		version?: string

}

export interface ManagedAppProtection extends ManagedAppPolicy {

		periodOfflineBeforeAccessCheck?: string

		periodOnlineBeforeAccessCheck?: string

		allowedInboundDataTransferSources?: ManagedAppDataTransferLevel

		allowedOutboundDataTransferDestinations?: ManagedAppDataTransferLevel

		organizationalCredentialsRequired?: boolean

		allowedOutboundClipboardSharingLevel?: ManagedAppClipboardSharingLevel

		dataBackupBlocked?: boolean

		deviceComplianceRequired?: boolean

		managedBrowserToOpenLinksRequired?: boolean

		saveAsBlocked?: boolean

		periodOfflineBeforeWipeIsEnforced?: string

		pinRequired?: boolean

		maximumPinRetries?: number

		simplePinBlocked?: boolean

		minimumPinLength?: number

		pinCharacterSet?: ManagedAppPinCharacterSet

		periodBeforePinReset?: string

		allowedDataStorageLocations?: ManagedAppDataStorageLocation[]

		contactSyncBlocked?: boolean

		printBlocked?: boolean

		fingerprintBlocked?: boolean

		disableAppPinIfDevicePinIsSet?: boolean

		minimumRequiredOsVersion?: string

		minimumWarningOsVersion?: string

		minimumRequiredAppVersion?: string

		minimumWarningAppVersion?: string

}

export interface TargetedManagedAppProtection extends ManagedAppProtection {

		isAssigned?: boolean

		assignments?: TargetedManagedAppPolicyAssignment[]

}

export interface IosManagedAppProtection extends TargetedManagedAppProtection {

		appDataEncryptionType?: ManagedAppDataEncryptionType

		minimumRequiredSdkVersion?: string

		deployedAppCount?: number

		faceIdBlocked?: boolean

		apps?: ManagedMobileApp[]

		deploymentSummary?: ManagedAppPolicyDeploymentSummary

}

export interface AndroidManagedAppProtection extends TargetedManagedAppProtection {

		screenCaptureBlocked?: boolean

		disableAppEncryptionIfDeviceEncryptionIsEnabled?: boolean

		encryptAppData?: boolean

		deployedAppCount?: number

		minimumRequiredPatchVersion?: string

		minimumWarningPatchVersion?: string

		apps?: ManagedMobileApp[]

		deploymentSummary?: ManagedAppPolicyDeploymentSummary

}

export interface DefaultManagedAppProtection extends ManagedAppProtection {

		appDataEncryptionType?: ManagedAppDataEncryptionType

		screenCaptureBlocked?: boolean

		encryptAppData?: boolean

		disableAppEncryptionIfDeviceEncryptionIsEnabled?: boolean

		minimumRequiredSdkVersion?: string

		customSettings?: KeyValuePair[]

		deployedAppCount?: number

		minimumRequiredPatchVersion?: string

		minimumWarningPatchVersion?: string

		faceIdBlocked?: boolean

		apps?: ManagedMobileApp[]

		deploymentSummary?: ManagedAppPolicyDeploymentSummary

}

export interface ManagedAppConfiguration extends ManagedAppPolicy {

		customSettings?: KeyValuePair[]

}

export interface TargetedManagedAppConfiguration extends ManagedAppConfiguration {

		deployedAppCount?: number

		isAssigned?: boolean

		apps?: ManagedMobileApp[]

		deploymentSummary?: ManagedAppPolicyDeploymentSummary

		assignments?: TargetedManagedAppPolicyAssignment[]

}

export interface WindowsInformationProtection extends ManagedAppPolicy {

		enforcementLevel?: WindowsInformationProtectionEnforcementLevel

		enterpriseDomain?: string

		enterpriseProtectedDomainNames?: WindowsInformationProtectionResourceCollection[]

		protectionUnderLockConfigRequired?: boolean

		dataRecoveryCertificate?: WindowsInformationProtectionDataRecoveryCertificate

		revokeOnUnenrollDisabled?: boolean

		rightsManagementServicesTemplateId?: string

		azureRightsManagementServicesAllowed?: boolean

		iconsVisible?: boolean

		protectedApps?: WindowsInformationProtectionApp[]

		exemptApps?: WindowsInformationProtectionApp[]

		enterpriseNetworkDomainNames?: WindowsInformationProtectionResourceCollection[]

		enterpriseProxiedDomains?: WindowsInformationProtectionProxiedDomainCollection[]

		enterpriseIPRanges?: WindowsInformationProtectionIPRangeCollection[]

		enterpriseIPRangesAreAuthoritative?: boolean

		enterpriseProxyServers?: WindowsInformationProtectionResourceCollection[]

		enterpriseInternalProxyServers?: WindowsInformationProtectionResourceCollection[]

		enterpriseProxyServersAreAuthoritative?: boolean

		neutralDomainResources?: WindowsInformationProtectionResourceCollection[]

		indexingEncryptedStoresOrItemsBlocked?: boolean

		smbAutoEncryptedFileExtensions?: WindowsInformationProtectionResourceCollection[]

		isAssigned?: boolean

		protectedAppLockerFiles?: WindowsInformationProtectionAppLockerFile[]

		exemptAppLockerFiles?: WindowsInformationProtectionAppLockerFile[]

		assignments?: TargetedManagedAppPolicyAssignment[]

}

export interface MdmWindowsInformationProtectionPolicy extends WindowsInformationProtection {

}

export interface WindowsInformationProtectionPolicy extends WindowsInformationProtection {

		revokeOnMdmHandoffDisabled?: boolean

		mdmEnrollmentUrl?: string

		windowsHelloForBusinessBlocked?: boolean

		pinMinimumLength?: number

		pinUppercaseLetters?: WindowsInformationProtectionPinCharacterRequirements

		pinLowercaseLetters?: WindowsInformationProtectionPinCharacterRequirements

		pinSpecialCharacters?: WindowsInformationProtectionPinCharacterRequirements

		pinExpirationDays?: number

		numberOfPastPinsRemembered?: number

		passwordMaximumAttemptCount?: number

		minutesOfInactivityBeforeDeviceLock?: number

		daysWithoutContactBeforeUnenroll?: number

}

export interface ManagedAppStatus extends Entity {

		displayName?: string

		version?: string

}

export interface ManagedEBook extends Entity {

		displayName?: string

		description?: string

		publisher?: string

		publishedDateTime?: string

		largeCover?: MimeContent

		createdDateTime?: string

		lastModifiedDateTime?: string

		informationUrl?: string

		privacyInformationUrl?: string

		assignments?: ManagedEBookAssignment[]

		installSummary?: EBookInstallSummary

		deviceStates?: DeviceInstallState[]

		userStateSummary?: UserInstallStateSummary[]

}

export interface MobileAppAssignment extends Entity {

		intent?: InstallIntent

		target?: DeviceAndAppManagementAssignmentTarget

		settings?: MobileAppAssignmentSettings

}

export interface MobileAppContentFile extends Entity {

		azureStorageUri?: string

		isCommitted?: boolean

		createdDateTime?: string

		name?: string

		size?: number

		sizeEncrypted?: number

		azureStorageUriExpirationDateTime?: string

		manifest?: number

		uploadState?: MobileAppContentFileUploadState

}

export interface ManagedDeviceMobileAppConfigurationAssignment extends Entity {

		target?: DeviceAndAppManagementAssignmentTarget

}

export interface ManagedDeviceMobileAppConfigurationDeviceStatus extends Entity {

		deviceDisplayName?: string

		userName?: string

		deviceModel?: string

		complianceGracePeriodExpirationDateTime?: string

		status?: ComplianceStatus

		lastReportedDateTime?: string

		userPrincipalName?: string

}

export interface ManagedDeviceMobileAppConfigurationUserStatus extends Entity {

		userDisplayName?: string

		devicesCount?: number

		status?: ComplianceStatus

		lastReportedDateTime?: string

		userPrincipalName?: string

}

export interface ManagedDeviceMobileAppConfigurationDeviceSummary extends Entity {

		pendingCount?: number

		notApplicableCount?: number

		successCount?: number

		errorCount?: number

		failedCount?: number

		lastUpdateDateTime?: string

		configurationVersion?: number

}

export interface ManagedDeviceMobileAppConfigurationUserSummary extends Entity {

		pendingCount?: number

		notApplicableCount?: number

		successCount?: number

		errorCount?: number

		failedCount?: number

		lastUpdateDateTime?: string

		configurationVersion?: number

}

export interface MacOSOfficeSuiteApp extends MobileApp {

}

export interface ManagedApp extends MobileApp {

		appAvailability?: ManagedAppAvailability

		version?: string

}

export interface ManagedAndroidStoreApp extends ManagedApp {

		packageId?: string

		appStoreUrl?: string

		minimumSupportedOperatingSystem?: AndroidMinimumOperatingSystem

}

export interface ManagedIOSStoreApp extends ManagedApp {

		bundleId?: string

		appStoreUrl?: string

		applicableDeviceType?: IosDeviceType

		minimumSupportedOperatingSystem?: IosMinimumOperatingSystem

}

export interface ManagedMobileLobApp extends ManagedApp {

		committedContentVersion?: string

		fileName?: string

		size?: number

		contentVersions?: MobileAppContent[]

}

export interface MobileAppContent extends Entity {

		files?: MobileAppContentFile[]

}

export interface ManagedAndroidLobApp extends ManagedMobileLobApp {

		packageId?: string

		minimumSupportedOperatingSystem?: AndroidMinimumOperatingSystem

		versionName?: string

		versionCode?: string

}

export interface ManagedIOSLobApp extends ManagedMobileLobApp {

		bundleId?: string

		applicableDeviceType?: IosDeviceType

		minimumSupportedOperatingSystem?: IosMinimumOperatingSystem

		expirationDateTime?: string

		versionNumber?: string

		buildNumber?: string

}

export interface MobileLobApp extends MobileApp {

		committedContentVersion?: string

		fileName?: string

		size?: number

		contentVersions?: MobileAppContent[]

}

export interface WindowsMobileMSI extends MobileLobApp {

		commandLine?: string

		productCode?: string

		productVersion?: string

		ignoreVersionDetection?: boolean

}

export interface WindowsUniversalAppX extends MobileLobApp {

		applicableArchitectures?: WindowsArchitecture

		applicableDeviceTypes?: WindowsDeviceType

		identityName?: string

		identityPublisherHash?: string

		identityResourceIdentifier?: string

		isBundle?: boolean

		minimumSupportedOperatingSystem?: WindowsMinimumOperatingSystem

		identityVersion?: string

}

export interface AndroidLobApp extends MobileLobApp {

		packageId?: string

		minimumSupportedOperatingSystem?: AndroidMinimumOperatingSystem

		versionName?: string

		versionCode?: string

}

export interface IosLobApp extends MobileLobApp {

		bundleId?: string

		applicableDeviceType?: IosDeviceType

		minimumSupportedOperatingSystem?: IosMinimumOperatingSystem

		expirationDateTime?: string

		versionNumber?: string

		buildNumber?: string

}

export interface MicrosoftStoreForBusinessApp extends MobileApp {

		usedLicenseCount?: number

		totalLicenseCount?: number

		productKey?: string

		licenseType?: MicrosoftStoreForBusinessLicenseType

		packageIdentityName?: string

}

export interface WebApp extends MobileApp {

		appUrl?: string

		useManagedBrowser?: boolean

}

export interface AndroidStoreApp extends MobileApp {

		packageId?: string

		appStoreUrl?: string

		minimumSupportedOperatingSystem?: AndroidMinimumOperatingSystem

}

export interface IosVppApp extends MobileApp {

		usedLicenseCount?: number

		totalLicenseCount?: number

		releaseDateTime?: string

		appStoreUrl?: string

		licensingType?: VppLicensingType

		applicableDeviceType?: IosDeviceType

		vppTokenOrganizationName?: string

		vppTokenAccountType?: VppTokenAccountType

		vppTokenAppleId?: string

		bundleId?: string

}

export interface IosStoreApp extends MobileApp {

		bundleId?: string

		appStoreUrl?: string

		applicableDeviceType?: IosDeviceType

		minimumSupportedOperatingSystem?: IosMinimumOperatingSystem

}

export interface IosMobileAppConfiguration extends ManagedDeviceMobileAppConfiguration {

		encodedSettingXml?: number

		settings?: AppConfigurationSettingItem[]

}

export interface DeviceManagement extends Entity {

		subscriptionState?: DeviceManagementSubscriptionState

		settings?: DeviceManagementSettings

		intuneBrand?: IntuneBrand

		termsAndConditions?: TermsAndConditions[]

		applePushNotificationCertificate?: ApplePushNotificationCertificate

		managedDeviceOverview?: ManagedDeviceOverview

		detectedApps?: DetectedApp[]

		managedDevices?: ManagedDevice[]

		deviceConfigurations?: DeviceConfiguration[]

		deviceCompliancePolicies?: DeviceCompliancePolicy[]

		softwareUpdateStatusSummary?: SoftwareUpdateStatusSummary

		deviceCompliancePolicyDeviceStateSummary?: DeviceCompliancePolicyDeviceStateSummary

		deviceCompliancePolicySettingStateSummaries?: DeviceCompliancePolicySettingStateSummary[]

		deviceConfigurationDeviceStateSummaries?: DeviceConfigurationDeviceStateSummary

		iosUpdateStatuses?: IosUpdateDeviceStatus[]

		deviceCategories?: DeviceCategory[]

		exchangeConnectors?: DeviceManagementExchangeConnector[]

		deviceEnrollmentConfigurations?: DeviceEnrollmentConfiguration[]

		conditionalAccessSettings?: OnPremisesConditionalAccessSettings

		mobileThreatDefenseConnectors?: MobileThreatDefenseConnector[]

		deviceManagementPartners?: DeviceManagementPartner[]

		notificationMessageTemplates?: NotificationMessageTemplate[]

		roleDefinitions?: RoleDefinition[]

		roleAssignments?: DeviceAndAppManagementRoleAssignment[]

		resourceOperations?: ResourceOperation[]

		telecomExpenseManagementPartners?: TelecomExpenseManagementPartner[]

		remoteAssistancePartners?: RemoteAssistancePartner[]

		windowsInformationProtectionAppLearningSummaries?: WindowsInformationProtectionAppLearningSummary[]

		windowsInformationProtectionNetworkLearningSummaries?: WindowsInformationProtectionNetworkLearningSummary[]

		troubleshootingEvents?: DeviceManagementTroubleshootingEvent[]

}

export interface TermsAndConditions extends Entity {

		createdDateTime?: string

		lastModifiedDateTime?: string

		displayName?: string

		description?: string

		title?: string

		bodyText?: string

		acceptanceStatement?: string

		version?: number

		assignments?: TermsAndConditionsAssignment[]

		acceptanceStatuses?: TermsAndConditionsAcceptanceStatus[]

}

export interface ApplePushNotificationCertificate extends Entity {

		appleIdentifier?: string

		topicIdentifier?: string

		lastModifiedDateTime?: string

		expirationDateTime?: string

		certificate?: string

}

export interface ManagedDeviceOverview extends Entity {

		enrolledDeviceCount?: number

		mdmEnrolledCount?: number

		dualEnrolledDeviceCount?: number

		deviceOperatingSystemSummary?: DeviceOperatingSystemSummary

		deviceExchangeAccessStateSummary?: DeviceExchangeAccessStateSummary

}

export interface DetectedApp extends Entity {

		displayName?: string

		version?: string

		sizeInByte?: number

		deviceCount?: number

		managedDevices?: ManagedDevice[]

}

export interface DeviceConfiguration extends Entity {

		lastModifiedDateTime?: string

		createdDateTime?: string

		description?: string

		displayName?: string

		version?: number

		assignments?: DeviceConfigurationAssignment[]

		deviceStatuses?: DeviceConfigurationDeviceStatus[]

		userStatuses?: DeviceConfigurationUserStatus[]

		deviceStatusOverview?: DeviceConfigurationDeviceOverview

		userStatusOverview?: DeviceConfigurationUserOverview

		deviceSettingStateSummaries?: SettingStateDeviceSummary[]

}

export interface DeviceCompliancePolicy extends Entity {

		createdDateTime?: string

		description?: string

		lastModifiedDateTime?: string

		displayName?: string

		version?: number

		scheduledActionsForRule?: DeviceComplianceScheduledActionForRule[]

		deviceStatuses?: DeviceComplianceDeviceStatus[]

		userStatuses?: DeviceComplianceUserStatus[]

		deviceStatusOverview?: DeviceComplianceDeviceOverview

		userStatusOverview?: DeviceComplianceUserOverview

		deviceSettingStateSummaries?: SettingStateDeviceSummary[]

		assignments?: DeviceCompliancePolicyAssignment[]

}

export interface SoftwareUpdateStatusSummary extends Entity {

		displayName?: string

		compliantDeviceCount?: number

		nonCompliantDeviceCount?: number

		remediatedDeviceCount?: number

		errorDeviceCount?: number

		unknownDeviceCount?: number

		conflictDeviceCount?: number

		notApplicableDeviceCount?: number

		compliantUserCount?: number

		nonCompliantUserCount?: number

		remediatedUserCount?: number

		errorUserCount?: number

		unknownUserCount?: number

		conflictUserCount?: number

		notApplicableUserCount?: number

}

export interface DeviceCompliancePolicyDeviceStateSummary extends Entity {

		inGracePeriodCount?: number

		configManagerCount?: number

		unknownDeviceCount?: number

		notApplicableDeviceCount?: number

		compliantDeviceCount?: number

		remediatedDeviceCount?: number

		nonCompliantDeviceCount?: number

		errorDeviceCount?: number

		conflictDeviceCount?: number

}

export interface DeviceCompliancePolicySettingStateSummary extends Entity {

		setting?: string

		settingName?: string

		platformType?: PolicyPlatformType

		unknownDeviceCount?: number

		notApplicableDeviceCount?: number

		compliantDeviceCount?: number

		remediatedDeviceCount?: number

		nonCompliantDeviceCount?: number

		errorDeviceCount?: number

		conflictDeviceCount?: number

		deviceComplianceSettingStates?: DeviceComplianceSettingState[]

}

export interface DeviceConfigurationDeviceStateSummary extends Entity {

		unknownDeviceCount?: number

		notApplicableDeviceCount?: number

		compliantDeviceCount?: number

		remediatedDeviceCount?: number

		nonCompliantDeviceCount?: number

		errorDeviceCount?: number

		conflictDeviceCount?: number

}

export interface IosUpdateDeviceStatus extends Entity {

		installStatus?: IosUpdatesInstallStatus

		osVersion?: string

		deviceId?: string

		userId?: string

		deviceDisplayName?: string

		userName?: string

		deviceModel?: string

		complianceGracePeriodExpirationDateTime?: string

		status?: ComplianceStatus

		lastReportedDateTime?: string

		userPrincipalName?: string

}

export interface DeviceCategory extends Entity {

		displayName?: string

		description?: string

}

export interface DeviceManagementExchangeConnector extends Entity {

		lastSyncDateTime?: string

		status?: DeviceManagementExchangeConnectorStatus

		primarySmtpAddress?: string

		serverName?: string

		connectorServerName?: string

		exchangeConnectorType?: DeviceManagementExchangeConnectorType

		version?: string

		exchangeAlias?: string

		exchangeOrganization?: string

}

export interface DeviceEnrollmentConfiguration extends Entity {

		displayName?: string

		description?: string

		priority?: number

		createdDateTime?: string

		lastModifiedDateTime?: string

		version?: number

		assignments?: EnrollmentConfigurationAssignment[]

}

export interface OnPremisesConditionalAccessSettings extends Entity {

		enabled?: boolean

		includedGroups?: string[]

		excludedGroups?: string[]

		overrideDefaultRule?: boolean

}

export interface MobileThreatDefenseConnector extends Entity {

		lastHeartbeatDateTime?: string

		partnerState?: MobileThreatPartnerTenantState

		androidEnabled?: boolean

		iosEnabled?: boolean

		androidDeviceBlockedOnMissingPartnerData?: boolean

		iosDeviceBlockedOnMissingPartnerData?: boolean

		partnerUnsupportedOsVersionBlocked?: boolean

		partnerUnresponsivenessThresholdInDays?: number

}

export interface DeviceManagementPartner extends Entity {

		lastHeartbeatDateTime?: string

		partnerState?: DeviceManagementPartnerTenantState

		partnerAppType?: DeviceManagementPartnerAppType

		singleTenantAppId?: string

		displayName?: string

		isConfigured?: boolean

		whenPartnerDevicesWillBeRemovedDateTime?: string

		whenPartnerDevicesWillBeMarkedAsNonCompliantDateTime?: string

}

export interface NotificationMessageTemplate extends Entity {

		lastModifiedDateTime?: string

		displayName?: string

		defaultLocale?: string

		brandingOptions?: NotificationTemplateBrandingOptions

		localizedNotificationMessages?: LocalizedNotificationMessage[]

}

export interface RoleDefinition extends Entity {

		displayName?: string

		description?: string

		rolePermissions?: RolePermission[]

		isBuiltIn?: boolean

		roleAssignments?: RoleAssignment[]

}

export interface RoleAssignment extends Entity {

		displayName?: string

		description?: string

		resourceScopes?: string[]

		roleDefinition?: RoleDefinition

}

export interface DeviceAndAppManagementRoleAssignment extends RoleAssignment {

		members?: string[]

}

export interface ResourceOperation extends Entity {

		resourceName?: string

		actionName?: string

		description?: string

}

export interface TelecomExpenseManagementPartner extends Entity {

		displayName?: string

		url?: string

		appAuthorized?: boolean

		enabled?: boolean

		lastConnectionDateTime?: string

}

export interface RemoteAssistancePartner extends Entity {

		displayName?: string

		onboardingUrl?: string

		onboardingStatus?: RemoteAssistanceOnboardingStatus

		lastConnectionDateTime?: string

}

export interface WindowsInformationProtectionAppLearningSummary extends Entity {

		applicationName?: string

		applicationType?: ApplicationType

		deviceCount?: number

}

export interface WindowsInformationProtectionNetworkLearningSummary extends Entity {

		url?: string

		deviceCount?: number

}

export interface TermsAndConditionsAssignment extends Entity {

		target?: DeviceAndAppManagementAssignmentTarget

}

export interface TermsAndConditionsAcceptanceStatus extends Entity {

		userDisplayName?: string

		acceptedVersion?: number

		acceptedDateTime?: string

		termsAndConditions?: TermsAndConditions

}

export interface DeviceConfigurationState extends Entity {

		settingStates?: DeviceConfigurationSettingState[]

		displayName?: string

		version?: number

		platformType?: PolicyPlatformType

		state?: ComplianceStatus

		settingCount?: number

}

export interface DeviceCompliancePolicyState extends Entity {

		settingStates?: DeviceCompliancePolicySettingState[]

		displayName?: string

		version?: number

		platformType?: PolicyPlatformType

		state?: ComplianceStatus

		settingCount?: number

}

export interface DeviceConfigurationAssignment extends Entity {

		target?: DeviceAndAppManagementAssignmentTarget

}

export interface DeviceConfigurationDeviceStatus extends Entity {

		deviceDisplayName?: string

		userName?: string

		deviceModel?: string

		complianceGracePeriodExpirationDateTime?: string

		status?: ComplianceStatus

		lastReportedDateTime?: string

		userPrincipalName?: string

}

export interface DeviceConfigurationUserStatus extends Entity {

		userDisplayName?: string

		devicesCount?: number

		status?: ComplianceStatus

		lastReportedDateTime?: string

		userPrincipalName?: string

}

export interface DeviceConfigurationDeviceOverview extends Entity {

		pendingCount?: number

		notApplicableCount?: number

		successCount?: number

		errorCount?: number

		failedCount?: number

		lastUpdateDateTime?: string

		configurationVersion?: number

}

export interface DeviceConfigurationUserOverview extends Entity {

		pendingCount?: number

		notApplicableCount?: number

		successCount?: number

		errorCount?: number

		failedCount?: number

		lastUpdateDateTime?: string

		configurationVersion?: number

}

export interface SettingStateDeviceSummary extends Entity {

		settingName?: string

		instancePath?: string

		unknownDeviceCount?: number

		notApplicableDeviceCount?: number

		compliantDeviceCount?: number

		remediatedDeviceCount?: number

		nonCompliantDeviceCount?: number

		errorDeviceCount?: number

		conflictDeviceCount?: number

}

export interface DeviceCompliancePolicyAssignment extends Entity {

		target?: DeviceAndAppManagementAssignmentTarget

}

export interface DeviceComplianceScheduledActionForRule extends Entity {

		ruleName?: string

		scheduledActionConfigurations?: DeviceComplianceActionItem[]

}

export interface DeviceComplianceDeviceStatus extends Entity {

		deviceDisplayName?: string

		userName?: string

		deviceModel?: string

		complianceGracePeriodExpirationDateTime?: string

		status?: ComplianceStatus

		lastReportedDateTime?: string

		userPrincipalName?: string

}

export interface DeviceComplianceUserStatus extends Entity {

		userDisplayName?: string

		devicesCount?: number

		status?: ComplianceStatus

		lastReportedDateTime?: string

		userPrincipalName?: string

}

export interface DeviceComplianceDeviceOverview extends Entity {

		pendingCount?: number

		notApplicableCount?: number

		successCount?: number

		errorCount?: number

		failedCount?: number

		lastUpdateDateTime?: string

		configurationVersion?: number

}

export interface DeviceComplianceUserOverview extends Entity {

		pendingCount?: number

		notApplicableCount?: number

		successCount?: number

		errorCount?: number

		failedCount?: number

		lastUpdateDateTime?: string

		configurationVersion?: number

}

export interface DeviceComplianceActionItem extends Entity {

		gracePeriodHours?: number

		actionType?: DeviceComplianceActionType

		notificationTemplateId?: string

		notificationMessageCCList?: string[]

}

export interface AndroidCustomConfiguration extends DeviceConfiguration {

		omaSettings?: OmaSetting[]

}

export interface AndroidGeneralDeviceConfiguration extends DeviceConfiguration {

		appsBlockClipboardSharing?: boolean

		appsBlockCopyPaste?: boolean

		appsBlockYouTube?: boolean

		bluetoothBlocked?: boolean

		cameraBlocked?: boolean

		cellularBlockDataRoaming?: boolean

		cellularBlockMessaging?: boolean

		cellularBlockVoiceRoaming?: boolean

		cellularBlockWiFiTethering?: boolean

		compliantAppsList?: AppListItem[]

		compliantAppListType?: AppListType

		diagnosticDataBlockSubmission?: boolean

		locationServicesBlocked?: boolean

		googleAccountBlockAutoSync?: boolean

		googlePlayStoreBlocked?: boolean

		kioskModeBlockSleepButton?: boolean

		kioskModeBlockVolumeButtons?: boolean

		kioskModeApps?: AppListItem[]

		nfcBlocked?: boolean

		passwordBlockFingerprintUnlock?: boolean

		passwordBlockTrustAgents?: boolean

		passwordExpirationDays?: number

		passwordMinimumLength?: number

		passwordMinutesOfInactivityBeforeScreenTimeout?: number

		passwordPreviousPasswordBlockCount?: number

		passwordSignInFailureCountBeforeFactoryReset?: number

		passwordRequiredType?: AndroidRequiredPasswordType

		passwordRequired?: boolean

		powerOffBlocked?: boolean

		factoryResetBlocked?: boolean

		screenCaptureBlocked?: boolean

		deviceSharingAllowed?: boolean

		storageBlockGoogleBackup?: boolean

		storageBlockRemovableStorage?: boolean

		storageRequireDeviceEncryption?: boolean

		storageRequireRemovableStorageEncryption?: boolean

		voiceAssistantBlocked?: boolean

		voiceDialingBlocked?: boolean

		webBrowserBlockPopups?: boolean

		webBrowserBlockAutofill?: boolean

		webBrowserBlockJavaScript?: boolean

		webBrowserBlocked?: boolean

		webBrowserCookieSettings?: WebBrowserCookieSettings

		wiFiBlocked?: boolean

		appsInstallAllowList?: AppListItem[]

		appsLaunchBlockList?: AppListItem[]

		appsHideList?: AppListItem[]

		securityRequireVerifyApps?: boolean

}

export interface AndroidWorkProfileCustomConfiguration extends DeviceConfiguration {

		omaSettings?: OmaSetting[]

}

export interface AndroidWorkProfileGeneralDeviceConfiguration extends DeviceConfiguration {

		passwordBlockFingerprintUnlock?: boolean

		passwordBlockTrustAgents?: boolean

		passwordExpirationDays?: number

		passwordMinimumLength?: number

		passwordMinutesOfInactivityBeforeScreenTimeout?: number

		passwordPreviousPasswordBlockCount?: number

		passwordSignInFailureCountBeforeFactoryReset?: number

		passwordRequiredType?: AndroidWorkProfileRequiredPasswordType

		workProfileDataSharingType?: AndroidWorkProfileCrossProfileDataSharingType

		workProfileBlockNotificationsWhileDeviceLocked?: boolean

		workProfileBlockAddingAccounts?: boolean

		workProfileBluetoothEnableContactSharing?: boolean

		workProfileBlockScreenCapture?: boolean

		workProfileBlockCrossProfileCallerId?: boolean

		workProfileBlockCamera?: boolean

		workProfileBlockCrossProfileContactsSearch?: boolean

		workProfileBlockCrossProfileCopyPaste?: boolean

		workProfileDefaultAppPermissionPolicy?: AndroidWorkProfileDefaultAppPermissionPolicyType

		workProfilePasswordBlockFingerprintUnlock?: boolean

		workProfilePasswordBlockTrustAgents?: boolean

		workProfilePasswordExpirationDays?: number

		workProfilePasswordMinimumLength?: number

		workProfilePasswordMinNumericCharacters?: number

		workProfilePasswordMinNonLetterCharacters?: number

		workProfilePasswordMinLetterCharacters?: number

		workProfilePasswordMinLowerCaseCharacters?: number

		workProfilePasswordMinUpperCaseCharacters?: number

		workProfilePasswordMinSymbolCharacters?: number

		workProfilePasswordMinutesOfInactivityBeforeScreenTimeout?: number

		workProfilePasswordPreviousPasswordBlockCount?: number

		workProfilePasswordSignInFailureCountBeforeFactoryReset?: number

		workProfilePasswordRequiredType?: AndroidWorkProfileRequiredPasswordType

		workProfileRequirePassword?: boolean

		securityRequireVerifyApps?: boolean

}

export interface IosCertificateProfile extends DeviceConfiguration {

}

export interface IosCustomConfiguration extends DeviceConfiguration {

		payloadName?: string

		payloadFileName?: string

		payload?: number

}

export interface IosGeneralDeviceConfiguration extends DeviceConfiguration {

		accountBlockModification?: boolean

		activationLockAllowWhenSupervised?: boolean

		airDropBlocked?: boolean

		airDropForceUnmanagedDropTarget?: boolean

		airPlayForcePairingPasswordForOutgoingRequests?: boolean

		appleWatchBlockPairing?: boolean

		appleWatchForceWristDetection?: boolean

		appleNewsBlocked?: boolean

		appsSingleAppModeList?: AppListItem[]

		appsVisibilityList?: AppListItem[]

		appsVisibilityListType?: AppListType

		appStoreBlockAutomaticDownloads?: boolean

		appStoreBlocked?: boolean

		appStoreBlockInAppPurchases?: boolean

		appStoreBlockUIAppInstallation?: boolean

		appStoreRequirePassword?: boolean

		bluetoothBlockModification?: boolean

		cameraBlocked?: boolean

		cellularBlockDataRoaming?: boolean

		cellularBlockGlobalBackgroundFetchWhileRoaming?: boolean

		cellularBlockPerAppDataModification?: boolean

		cellularBlockPersonalHotspot?: boolean

		cellularBlockVoiceRoaming?: boolean

		certificatesBlockUntrustedTlsCertificates?: boolean

		classroomAppBlockRemoteScreenObservation?: boolean

		classroomAppForceUnpromptedScreenObservation?: boolean

		compliantAppsList?: AppListItem[]

		compliantAppListType?: AppListType

		configurationProfileBlockChanges?: boolean

		definitionLookupBlocked?: boolean

		deviceBlockEnableRestrictions?: boolean

		deviceBlockEraseContentAndSettings?: boolean

		deviceBlockNameModification?: boolean

		diagnosticDataBlockSubmission?: boolean

		diagnosticDataBlockSubmissionModification?: boolean

		documentsBlockManagedDocumentsInUnmanagedApps?: boolean

		documentsBlockUnmanagedDocumentsInManagedApps?: boolean

		emailInDomainSuffixes?: string[]

		enterpriseAppBlockTrust?: boolean

		enterpriseAppBlockTrustModification?: boolean

		faceTimeBlocked?: boolean

		findMyFriendsBlocked?: boolean

		gamingBlockGameCenterFriends?: boolean

		gamingBlockMultiplayer?: boolean

		gameCenterBlocked?: boolean

		hostPairingBlocked?: boolean

		iBooksStoreBlocked?: boolean

		iBooksStoreBlockErotica?: boolean

		iCloudBlockActivityContinuation?: boolean

		iCloudBlockBackup?: boolean

		iCloudBlockDocumentSync?: boolean

		iCloudBlockManagedAppsSync?: boolean

		iCloudBlockPhotoLibrary?: boolean

		iCloudBlockPhotoStreamSync?: boolean

		iCloudBlockSharedPhotoStream?: boolean

		iCloudRequireEncryptedBackup?: boolean

		iTunesBlockExplicitContent?: boolean

		iTunesBlockMusicService?: boolean

		iTunesBlockRadio?: boolean

		keyboardBlockAutoCorrect?: boolean

		keyboardBlockDictation?: boolean

		keyboardBlockPredictive?: boolean

		keyboardBlockShortcuts?: boolean

		keyboardBlockSpellCheck?: boolean

		kioskModeAllowAssistiveSpeak?: boolean

		kioskModeAllowAssistiveTouchSettings?: boolean

		kioskModeAllowAutoLock?: boolean

		kioskModeAllowColorInversionSettings?: boolean

		kioskModeAllowRingerSwitch?: boolean

		kioskModeAllowScreenRotation?: boolean

		kioskModeAllowSleepButton?: boolean

		kioskModeAllowTouchscreen?: boolean

		kioskModeAllowVoiceOverSettings?: boolean

		kioskModeAllowVolumeButtons?: boolean

		kioskModeAllowZoomSettings?: boolean

		kioskModeAppStoreUrl?: string

		kioskModeBuiltInAppId?: string

		kioskModeRequireAssistiveTouch?: boolean

		kioskModeRequireColorInversion?: boolean

		kioskModeRequireMonoAudio?: boolean

		kioskModeRequireVoiceOver?: boolean

		kioskModeRequireZoom?: boolean

		kioskModeManagedAppId?: string

		lockScreenBlockControlCenter?: boolean

		lockScreenBlockNotificationView?: boolean

		lockScreenBlockPassbook?: boolean

		lockScreenBlockTodayView?: boolean

		mediaContentRatingAustralia?: MediaContentRatingAustralia

		mediaContentRatingCanada?: MediaContentRatingCanada

		mediaContentRatingFrance?: MediaContentRatingFrance

		mediaContentRatingGermany?: MediaContentRatingGermany

		mediaContentRatingIreland?: MediaContentRatingIreland

		mediaContentRatingJapan?: MediaContentRatingJapan

		mediaContentRatingNewZealand?: MediaContentRatingNewZealand

		mediaContentRatingUnitedKingdom?: MediaContentRatingUnitedKingdom

		mediaContentRatingUnitedStates?: MediaContentRatingUnitedStates

		networkUsageRules?: IosNetworkUsageRule[]

		mediaContentRatingApps?: RatingAppsType

		messagesBlocked?: boolean

		notificationsBlockSettingsModification?: boolean

		passcodeBlockFingerprintUnlock?: boolean

		passcodeBlockFingerprintModification?: boolean

		passcodeBlockModification?: boolean

		passcodeBlockSimple?: boolean

		passcodeExpirationDays?: number

		passcodeMinimumLength?: number

		passcodeMinutesOfInactivityBeforeLock?: number

		passcodeMinutesOfInactivityBeforeScreenTimeout?: number

		passcodeMinimumCharacterSetCount?: number

		passcodePreviousPasscodeBlockCount?: number

		passcodeSignInFailureCountBeforeWipe?: number

		passcodeRequiredType?: RequiredPasswordType

		passcodeRequired?: boolean

		podcastsBlocked?: boolean

		safariBlockAutofill?: boolean

		safariBlockJavaScript?: boolean

		safariBlockPopups?: boolean

		safariBlocked?: boolean

		safariCookieSettings?: WebBrowserCookieSettings

		safariManagedDomains?: string[]

		safariPasswordAutoFillDomains?: string[]

		safariRequireFraudWarning?: boolean

		screenCaptureBlocked?: boolean

		siriBlocked?: boolean

		siriBlockedWhenLocked?: boolean

		siriBlockUserGeneratedContent?: boolean

		siriRequireProfanityFilter?: boolean

		spotlightBlockInternetResults?: boolean

		voiceDialingBlocked?: boolean

		wallpaperBlockModification?: boolean

		wiFiConnectOnlyToConfiguredNetworks?: boolean

}

export interface IosUpdateConfiguration extends DeviceConfiguration {

		activeHoursStart?: string

		activeHoursEnd?: string

		scheduledInstallDays?: DayOfWeek[]

		utcTimeOffsetInMinutes?: number

}

export interface MacOSCustomConfiguration extends DeviceConfiguration {

		payloadName?: string

		payloadFileName?: string

		payload?: number

}

export interface MacOSGeneralDeviceConfiguration extends DeviceConfiguration {

		compliantAppsList?: AppListItem[]

		compliantAppListType?: AppListType

		emailInDomainSuffixes?: string[]

		passwordBlockSimple?: boolean

		passwordExpirationDays?: number

		passwordMinimumCharacterSetCount?: number

		passwordMinimumLength?: number

		passwordMinutesOfInactivityBeforeLock?: number

		passwordMinutesOfInactivityBeforeScreenTimeout?: number

		passwordPreviousPasswordBlockCount?: number

		passwordRequiredType?: RequiredPasswordType

		passwordRequired?: boolean

}

export interface AppleDeviceFeaturesConfigurationBase extends DeviceConfiguration {

}

export interface IosDeviceFeaturesConfiguration extends AppleDeviceFeaturesConfigurationBase {

		assetTagTemplate?: string

		lockScreenFootnote?: string

		homeScreenDockIcons?: IosHomeScreenItem[]

		homeScreenPages?: IosHomeScreenPage[]

		notificationSettings?: IosNotificationSettings[]

}

export interface MacOSDeviceFeaturesConfiguration extends AppleDeviceFeaturesConfigurationBase {

}

export interface WindowsDefenderAdvancedThreatProtectionConfiguration extends DeviceConfiguration {

		allowSampleSharing?: boolean

		enableExpeditedTelemetryReporting?: boolean

}

export interface EditionUpgradeConfiguration extends DeviceConfiguration {

		licenseType?: EditionUpgradeLicenseType

		targetEdition?: Windows10EditionType

		license?: string

		productKey?: string

}

export interface Windows10EndpointProtectionConfiguration extends DeviceConfiguration {

		firewallBlockStatefulFTP?: boolean

		firewallIdleTimeoutForSecurityAssociationInSeconds?: number

		firewallPreSharedKeyEncodingMethod?: FirewallPreSharedKeyEncodingMethodType

		firewallIPSecExemptionsAllowNeighborDiscovery?: boolean

		firewallIPSecExemptionsAllowICMP?: boolean

		firewallIPSecExemptionsAllowRouterDiscovery?: boolean

		firewallIPSecExemptionsAllowDHCP?: boolean

		firewallCertificateRevocationListCheckMethod?: FirewallCertificateRevocationListCheckMethodType

		firewallMergeKeyingModuleSettings?: boolean

		firewallPacketQueueingMethod?: FirewallPacketQueueingMethodType

		firewallProfileDomain?: WindowsFirewallNetworkProfile

		firewallProfilePublic?: WindowsFirewallNetworkProfile

		firewallProfilePrivate?: WindowsFirewallNetworkProfile

		defenderAttackSurfaceReductionExcludedPaths?: string[]

		defenderGuardedFoldersAllowedAppPaths?: string[]

		defenderAdditionalGuardedFolders?: string[]

		defenderExploitProtectionXml?: number

		defenderExploitProtectionXmlFileName?: string

		defenderSecurityCenterBlockExploitProtectionOverride?: boolean

		appLockerApplicationControl?: AppLockerApplicationControlType

		smartScreenEnableInShell?: boolean

		smartScreenBlockOverrideForFiles?: boolean

		applicationGuardEnabled?: boolean

		applicationGuardBlockFileTransfer?: ApplicationGuardBlockFileTransferType

		applicationGuardBlockNonEnterpriseContent?: boolean

		applicationGuardAllowPersistence?: boolean

		applicationGuardForceAuditing?: boolean

		applicationGuardBlockClipboardSharing?: ApplicationGuardBlockClipboardSharingType

		applicationGuardAllowPrintToPDF?: boolean

		applicationGuardAllowPrintToXPS?: boolean

		applicationGuardAllowPrintToLocalPrinters?: boolean

		applicationGuardAllowPrintToNetworkPrinters?: boolean

		bitLockerDisableWarningForOtherDiskEncryption?: boolean

		bitLockerEnableStorageCardEncryptionOnMobile?: boolean

		bitLockerEncryptDevice?: boolean

		bitLockerRemovableDrivePolicy?: BitLockerRemovableDrivePolicy

}

export interface Windows10GeneralConfiguration extends DeviceConfiguration {

		enterpriseCloudPrintDiscoveryEndPoint?: string

		enterpriseCloudPrintOAuthAuthority?: string

		enterpriseCloudPrintOAuthClientIdentifier?: string

		enterpriseCloudPrintResourceIdentifier?: string

		enterpriseCloudPrintDiscoveryMaxLimit?: number

		enterpriseCloudPrintMopriaDiscoveryResourceIdentifier?: string

		searchBlockDiacritics?: boolean

		searchDisableAutoLanguageDetection?: boolean

		searchDisableIndexingEncryptedItems?: boolean

		searchEnableRemoteQueries?: boolean

		searchDisableIndexerBackoff?: boolean

		searchDisableIndexingRemovableDrive?: boolean

		searchEnableAutomaticIndexSizeManangement?: boolean

		diagnosticsDataSubmissionMode?: DiagnosticDataSubmissionMode

		oneDriveDisableFileSync?: boolean

		smartScreenEnableAppInstallControl?: boolean

		personalizationDesktopImageUrl?: string

		personalizationLockScreenImageUrl?: string

		bluetoothAllowedServices?: string[]

		bluetoothBlockAdvertising?: boolean

		bluetoothBlockDiscoverableMode?: boolean

		bluetoothBlockPrePairing?: boolean

		edgeBlockAutofill?: boolean

		edgeBlocked?: boolean

		edgeCookiePolicy?: EdgeCookiePolicy

		edgeBlockDeveloperTools?: boolean

		edgeBlockSendingDoNotTrackHeader?: boolean

		edgeBlockExtensions?: boolean

		edgeBlockInPrivateBrowsing?: boolean

		edgeBlockJavaScript?: boolean

		edgeBlockPasswordManager?: boolean

		edgeBlockAddressBarDropdown?: boolean

		edgeBlockCompatibilityList?: boolean

		edgeClearBrowsingDataOnExit?: boolean

		edgeAllowStartPagesModification?: boolean

		edgeDisableFirstRunPage?: boolean

		edgeBlockLiveTileDataCollection?: boolean

		edgeSyncFavoritesWithInternetExplorer?: boolean

		cellularBlockDataWhenRoaming?: boolean

		cellularBlockVpn?: boolean

		cellularBlockVpnWhenRoaming?: boolean

		defenderBlockEndUserAccess?: boolean

		defenderDaysBeforeDeletingQuarantinedMalware?: number

		defenderDetectedMalwareActions?: DefenderDetectedMalwareActions

		defenderSystemScanSchedule?: WeeklySchedule

		defenderFilesAndFoldersToExclude?: string[]

		defenderFileExtensionsToExclude?: string[]

		defenderScanMaxCpu?: number

		defenderMonitorFileActivity?: DefenderMonitorFileActivity

		defenderProcessesToExclude?: string[]

		defenderPromptForSampleSubmission?: DefenderPromptForSampleSubmission

		defenderRequireBehaviorMonitoring?: boolean

		defenderRequireCloudProtection?: boolean

		defenderRequireNetworkInspectionSystem?: boolean

		defenderRequireRealTimeMonitoring?: boolean

		defenderScanArchiveFiles?: boolean

		defenderScanDownloads?: boolean

		defenderScanNetworkFiles?: boolean

		defenderScanIncomingMail?: boolean

		defenderScanMappedNetworkDrivesDuringFullScan?: boolean

		defenderScanRemovableDrivesDuringFullScan?: boolean

		defenderScanScriptsLoadedInInternetExplorer?: boolean

		defenderSignatureUpdateIntervalInHours?: number

		defenderScanType?: DefenderScanType

		defenderScheduledScanTime?: string

		defenderScheduledQuickScanTime?: string

		defenderCloudBlockLevel?: DefenderCloudBlockLevelType

		lockScreenAllowTimeoutConfiguration?: boolean

		lockScreenBlockActionCenterNotifications?: boolean

		lockScreenBlockCortana?: boolean

		lockScreenBlockToastNotifications?: boolean

		lockScreenTimeoutInSeconds?: number

		passwordBlockSimple?: boolean

		passwordExpirationDays?: number

		passwordMinimumLength?: number

		passwordMinutesOfInactivityBeforeScreenTimeout?: number

		passwordMinimumCharacterSetCount?: number

		passwordPreviousPasswordBlockCount?: number

		passwordRequired?: boolean

		passwordRequireWhenResumeFromIdleState?: boolean

		passwordRequiredType?: RequiredPasswordType

		passwordSignInFailureCountBeforeFactoryReset?: number

		privacyAdvertisingId?: StateManagementSetting

		privacyAutoAcceptPairingAndConsentPrompts?: boolean

		privacyBlockInputPersonalization?: boolean

		startBlockUnpinningAppsFromTaskbar?: boolean

		startMenuAppListVisibility?: WindowsStartMenuAppListVisibilityType

		startMenuHideChangeAccountSettings?: boolean

		startMenuHideFrequentlyUsedApps?: boolean

		startMenuHideHibernate?: boolean

		startMenuHideLock?: boolean

		startMenuHidePowerButton?: boolean

		startMenuHideRecentJumpLists?: boolean

		startMenuHideRecentlyAddedApps?: boolean

		startMenuHideRestartOptions?: boolean

		startMenuHideShutDown?: boolean

		startMenuHideSignOut?: boolean

		startMenuHideSleep?: boolean

		startMenuHideSwitchAccount?: boolean

		startMenuHideUserTile?: boolean

		startMenuLayoutEdgeAssetsXml?: number

		startMenuLayoutXml?: number

		startMenuMode?: WindowsStartMenuModeType

		startMenuPinnedFolderDocuments?: VisibilitySetting

		startMenuPinnedFolderDownloads?: VisibilitySetting

		startMenuPinnedFolderFileExplorer?: VisibilitySetting

		startMenuPinnedFolderHomeGroup?: VisibilitySetting

		startMenuPinnedFolderMusic?: VisibilitySetting

		startMenuPinnedFolderNetwork?: VisibilitySetting

		startMenuPinnedFolderPersonalFolder?: VisibilitySetting

		startMenuPinnedFolderPictures?: VisibilitySetting

		startMenuPinnedFolderSettings?: VisibilitySetting

		startMenuPinnedFolderVideos?: VisibilitySetting

		settingsBlockSettingsApp?: boolean

		settingsBlockSystemPage?: boolean

		settingsBlockDevicesPage?: boolean

		settingsBlockNetworkInternetPage?: boolean

		settingsBlockPersonalizationPage?: boolean

		settingsBlockAccountsPage?: boolean

		settingsBlockTimeLanguagePage?: boolean

		settingsBlockEaseOfAccessPage?: boolean

		settingsBlockPrivacyPage?: boolean

		settingsBlockUpdateSecurityPage?: boolean

		settingsBlockAppsPage?: boolean

		settingsBlockGamingPage?: boolean

		windowsSpotlightBlockConsumerSpecificFeatures?: boolean

		windowsSpotlightBlocked?: boolean

		windowsSpotlightBlockOnActionCenter?: boolean

		windowsSpotlightBlockTailoredExperiences?: boolean

		windowsSpotlightBlockThirdPartyNotifications?: boolean

		windowsSpotlightBlockWelcomeExperience?: boolean

		windowsSpotlightBlockWindowsTips?: boolean

		windowsSpotlightConfigureOnLockScreen?: WindowsSpotlightEnablementSettings

		networkProxyApplySettingsDeviceWide?: boolean

		networkProxyDisableAutoDetect?: boolean

		networkProxyAutomaticConfigurationUrl?: string

		networkProxyServer?: Windows10NetworkProxyServer

		accountsBlockAddingNonMicrosoftAccountEmail?: boolean

		antiTheftModeBlocked?: boolean

		bluetoothBlocked?: boolean

		cameraBlocked?: boolean

		connectedDevicesServiceBlocked?: boolean

		certificatesBlockManualRootCertificateInstallation?: boolean

		copyPasteBlocked?: boolean

		cortanaBlocked?: boolean

		deviceManagementBlockFactoryResetOnMobile?: boolean

		deviceManagementBlockManualUnenroll?: boolean

		safeSearchFilter?: SafeSearchFilterType

		edgeBlockPopups?: boolean

		edgeBlockSearchSuggestions?: boolean

		edgeBlockSendingIntranetTrafficToInternetExplorer?: boolean

		edgeRequireSmartScreen?: boolean

		edgeEnterpriseModeSiteListLocation?: string

		edgeFirstRunUrl?: string

		edgeSearchEngine?: EdgeSearchEngineBase

		edgeHomepageUrls?: string[]

		edgeBlockAccessToAboutFlags?: boolean

		smartScreenBlockPromptOverride?: boolean

		smartScreenBlockPromptOverrideForFiles?: boolean

		webRtcBlockLocalhostIpAddress?: boolean

		internetSharingBlocked?: boolean

		settingsBlockAddProvisioningPackage?: boolean

		settingsBlockRemoveProvisioningPackage?: boolean

		settingsBlockChangeSystemTime?: boolean

		settingsBlockEditDeviceName?: boolean

		settingsBlockChangeRegion?: boolean

		settingsBlockChangeLanguage?: boolean

		settingsBlockChangePowerSleep?: boolean

		locationServicesBlocked?: boolean

		microsoftAccountBlocked?: boolean

		microsoftAccountBlockSettingsSync?: boolean

		nfcBlocked?: boolean

		resetProtectionModeBlocked?: boolean

		screenCaptureBlocked?: boolean

		storageBlockRemovableStorage?: boolean

		storageRequireMobileDeviceEncryption?: boolean

		usbBlocked?: boolean

		voiceRecordingBlocked?: boolean

		wiFiBlockAutomaticConnectHotspots?: boolean

		wiFiBlocked?: boolean

		wiFiBlockManualConfiguration?: boolean

		wiFiScanInterval?: number

		wirelessDisplayBlockProjectionToThisDevice?: boolean

		wirelessDisplayBlockUserInputFromReceiver?: boolean

		wirelessDisplayRequirePinForPairing?: boolean

		windowsStoreBlocked?: boolean

		appsAllowTrustedAppsSideloading?: StateManagementSetting

		windowsStoreBlockAutoUpdate?: boolean

		developerUnlockSetting?: StateManagementSetting

		sharedUserAppDataAllowed?: boolean

		appsBlockWindowsStoreOriginatedApps?: boolean

		windowsStoreEnablePrivateStoreOnly?: boolean

		storageRestrictAppDataToSystemVolume?: boolean

		storageRestrictAppInstallToSystemVolume?: boolean

		gameDvrBlocked?: boolean

		experienceBlockDeviceDiscovery?: boolean

		experienceBlockErrorDialogWhenNoSIM?: boolean

		experienceBlockTaskSwitcher?: boolean

		logonBlockFastUserSwitching?: boolean

		tenantLockdownRequireNetworkDuringOutOfBoxExperience?: boolean

}

export interface Windows10CustomConfiguration extends DeviceConfiguration {

		omaSettings?: OmaSetting[]

}

export interface Windows10EnterpriseModernAppManagementConfiguration extends DeviceConfiguration {

		uninstallBuiltInApps?: boolean

}

export interface SharedPCConfiguration extends DeviceConfiguration {

		accountManagerPolicy?: SharedPCAccountManagerPolicy

		allowedAccounts?: SharedPCAllowedAccountType

		allowLocalStorage?: boolean

		disableAccountManager?: boolean

		disableEduPolicies?: boolean

		disablePowerPolicies?: boolean

		disableSignInOnResume?: boolean

		enabled?: boolean

		idleTimeBeforeSleepInSeconds?: number

		kioskAppDisplayName?: string

		kioskAppUserModelId?: string

		maintenanceStartTime?: string

}

export interface Windows10SecureAssessmentConfiguration extends DeviceConfiguration {

		launchUri?: string

		configurationAccount?: string

		allowPrinting?: boolean

		allowScreenCapture?: boolean

		allowTextSuggestion?: boolean

}

export interface WindowsPhone81CustomConfiguration extends DeviceConfiguration {

		omaSettings?: OmaSetting[]

}

export interface WindowsUpdateForBusinessConfiguration extends DeviceConfiguration {

		deliveryOptimizationMode?: WindowsDeliveryOptimizationMode

		prereleaseFeatures?: PrereleaseFeatures

		automaticUpdateMode?: AutomaticUpdateMode

		microsoftUpdateServiceAllowed?: boolean

		driversExcluded?: boolean

		installationSchedule?: WindowsUpdateInstallScheduleType

		qualityUpdatesDeferralPeriodInDays?: number

		featureUpdatesDeferralPeriodInDays?: number

		qualityUpdatesPaused?: boolean

		featureUpdatesPaused?: boolean

		qualityUpdatesPauseExpiryDateTime?: string

		featureUpdatesPauseExpiryDateTime?: string

		businessReadyUpdatesOnly?: WindowsUpdateType

}

export interface Windows81GeneralConfiguration extends DeviceConfiguration {

		accountsBlockAddingNonMicrosoftAccountEmail?: boolean

		applyOnlyToWindows81?: boolean

		browserBlockAutofill?: boolean

		browserBlockAutomaticDetectionOfIntranetSites?: boolean

		browserBlockEnterpriseModeAccess?: boolean

		browserBlockJavaScript?: boolean

		browserBlockPlugins?: boolean

		browserBlockPopups?: boolean

		browserBlockSendingDoNotTrackHeader?: boolean

		browserBlockSingleWordEntryOnIntranetSites?: boolean

		browserRequireSmartScreen?: boolean

		browserEnterpriseModeSiteListLocation?: string

		browserInternetSecurityLevel?: InternetSiteSecurityLevel

		browserIntranetSecurityLevel?: SiteSecurityLevel

		browserLoggingReportLocation?: string

		browserRequireHighSecurityForRestrictedSites?: boolean

		browserRequireFirewall?: boolean

		browserRequireFraudWarning?: boolean

		browserTrustedSitesSecurityLevel?: SiteSecurityLevel

		cellularBlockDataRoaming?: boolean

		diagnosticsBlockDataSubmission?: boolean

		passwordBlockPicturePasswordAndPin?: boolean

		passwordExpirationDays?: number

		passwordMinimumLength?: number

		passwordMinutesOfInactivityBeforeScreenTimeout?: number

		passwordMinimumCharacterSetCount?: number

		passwordPreviousPasswordBlockCount?: number

		passwordRequiredType?: RequiredPasswordType

		passwordSignInFailureCountBeforeFactoryReset?: number

		storageRequireDeviceEncryption?: boolean

		updatesRequireAutomaticUpdates?: boolean

		userAccountControlSettings?: WindowsUserAccountControlSettings

		workFoldersUrl?: string

}

export interface WindowsPhone81GeneralConfiguration extends DeviceConfiguration {

		applyOnlyToWindowsPhone81?: boolean

		appsBlockCopyPaste?: boolean

		bluetoothBlocked?: boolean

		cameraBlocked?: boolean

		cellularBlockWifiTethering?: boolean

		compliantAppsList?: AppListItem[]

		compliantAppListType?: AppListType

		diagnosticDataBlockSubmission?: boolean

		emailBlockAddingAccounts?: boolean

		locationServicesBlocked?: boolean

		microsoftAccountBlocked?: boolean

		nfcBlocked?: boolean

		passwordBlockSimple?: boolean

		passwordExpirationDays?: number

		passwordMinimumLength?: number

		passwordMinutesOfInactivityBeforeScreenTimeout?: number

		passwordMinimumCharacterSetCount?: number

		passwordPreviousPasswordBlockCount?: number

		passwordSignInFailureCountBeforeFactoryReset?: number

		passwordRequiredType?: RequiredPasswordType

		passwordRequired?: boolean

		screenCaptureBlocked?: boolean

		storageBlockRemovableStorage?: boolean

		storageRequireEncryption?: boolean

		webBrowserBlocked?: boolean

		wifiBlocked?: boolean

		wifiBlockAutomaticConnectHotspots?: boolean

		wifiBlockHotspotReporting?: boolean

		windowsStoreBlocked?: boolean

}

export interface Windows10TeamGeneralConfiguration extends DeviceConfiguration {

		azureOperationalInsightsBlockTelemetry?: boolean

		azureOperationalInsightsWorkspaceId?: string

		azureOperationalInsightsWorkspaceKey?: string

		connectAppBlockAutoLaunch?: boolean

		maintenanceWindowBlocked?: boolean

		maintenanceWindowDurationInHours?: number

		maintenanceWindowStartTime?: string

		miracastChannel?: MiracastChannel

		miracastBlocked?: boolean

		miracastRequirePin?: boolean

		settingsBlockMyMeetingsAndFiles?: boolean

		settingsBlockSessionResume?: boolean

		settingsBlockSigninSuggestions?: boolean

		settingsDefaultVolume?: number

		settingsScreenTimeoutInMinutes?: number

		settingsSessionTimeoutInMinutes?: number

		settingsSleepTimeoutInMinutes?: number

		welcomeScreenBlockAutomaticWakeUp?: boolean

		welcomeScreenBackgroundImageUrl?: string

		welcomeScreenMeetingInformation?: WelcomeScreenMeetingInformation

}

export interface AndroidCompliancePolicy extends DeviceCompliancePolicy {

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

export interface AndroidWorkProfileCompliancePolicy extends DeviceCompliancePolicy {

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

export interface IosCompliancePolicy extends DeviceCompliancePolicy {

		passcodeBlockSimple?: boolean

		passcodeExpirationDays?: number

		passcodeMinimumLength?: number

		passcodeMinutesOfInactivityBeforeLock?: number

		passcodePreviousPasscodeBlockCount?: number

		passcodeMinimumCharacterSetCount?: number

		passcodeRequiredType?: RequiredPasswordType

		passcodeRequired?: boolean

		osMinimumVersion?: string

		osMaximumVersion?: string

		securityBlockJailbrokenDevices?: boolean

		deviceThreatProtectionEnabled?: boolean

		deviceThreatProtectionRequiredSecurityLevel?: DeviceThreatProtectionLevel

		managedEmailProfileRequired?: boolean

}

export interface MacOSCompliancePolicy extends DeviceCompliancePolicy {

		passwordRequired?: boolean

		passwordBlockSimple?: boolean

		passwordExpirationDays?: number

		passwordMinimumLength?: number

		passwordMinutesOfInactivityBeforeLock?: number

		passwordPreviousPasswordBlockCount?: number

		passwordMinimumCharacterSetCount?: number

		passwordRequiredType?: RequiredPasswordType

		osMinimumVersion?: string

		osMaximumVersion?: string

		systemIntegrityProtectionEnabled?: boolean

		deviceThreatProtectionEnabled?: boolean

		deviceThreatProtectionRequiredSecurityLevel?: DeviceThreatProtectionLevel

		storageRequireEncryption?: boolean

		firewallEnabled?: boolean

		firewallBlockAllIncoming?: boolean

		firewallEnableStealthMode?: boolean

}

export interface Windows10CompliancePolicy extends DeviceCompliancePolicy {

		passwordRequired?: boolean

		passwordBlockSimple?: boolean

		passwordRequiredToUnlockFromIdle?: boolean

		passwordMinutesOfInactivityBeforeLock?: number

		passwordExpirationDays?: number

		passwordMinimumLength?: number

		passwordMinimumCharacterSetCount?: number

		passwordRequiredType?: RequiredPasswordType

		passwordPreviousPasswordBlockCount?: number

		requireHealthyDeviceReport?: boolean

		osMinimumVersion?: string

		osMaximumVersion?: string

		mobileOsMinimumVersion?: string

		mobileOsMaximumVersion?: string

		earlyLaunchAntiMalwareDriverEnabled?: boolean

		bitLockerEnabled?: boolean

		secureBootEnabled?: boolean

		codeIntegrityEnabled?: boolean

		storageRequireEncryption?: boolean

}

export interface Windows10MobileCompliancePolicy extends DeviceCompliancePolicy {

		passwordRequired?: boolean

		passwordBlockSimple?: boolean

		passwordMinimumLength?: number

		passwordMinimumCharacterSetCount?: number

		passwordRequiredType?: RequiredPasswordType

		passwordPreviousPasswordBlockCount?: number

		passwordExpirationDays?: number

		passwordMinutesOfInactivityBeforeLock?: number

		passwordRequireToUnlockFromIdle?: boolean

		osMinimumVersion?: string

		osMaximumVersion?: string

		earlyLaunchAntiMalwareDriverEnabled?: boolean

		bitLockerEnabled?: boolean

		secureBootEnabled?: boolean

		codeIntegrityEnabled?: boolean

		storageRequireEncryption?: boolean

}

export interface Windows81CompliancePolicy extends DeviceCompliancePolicy {

		passwordRequired?: boolean

		passwordBlockSimple?: boolean

		passwordExpirationDays?: number

		passwordMinimumLength?: number

		passwordMinutesOfInactivityBeforeLock?: number

		passwordMinimumCharacterSetCount?: number

		passwordRequiredType?: RequiredPasswordType

		passwordPreviousPasswordBlockCount?: number

		osMinimumVersion?: string

		osMaximumVersion?: string

		storageRequireEncryption?: boolean

}

export interface WindowsPhone81CompliancePolicy extends DeviceCompliancePolicy {

		passwordBlockSimple?: boolean

		passwordExpirationDays?: number

		passwordMinimumLength?: number

		passwordMinutesOfInactivityBeforeLock?: number

		passwordMinimumCharacterSetCount?: number

		passwordRequiredType?: RequiredPasswordType

		passwordPreviousPasswordBlockCount?: number

		passwordRequired?: boolean

		osMinimumVersion?: string

		osMaximumVersion?: string

		storageRequireEncryption?: boolean

}

export interface DeviceComplianceSettingState extends Entity {

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

		target?: DeviceAndAppManagementAssignmentTarget

}

export interface DeviceEnrollmentLimitConfiguration extends DeviceEnrollmentConfiguration {

		limit?: number

}

export interface DeviceEnrollmentPlatformRestrictionsConfiguration extends DeviceEnrollmentConfiguration {

		iosRestriction?: DeviceEnrollmentPlatformRestriction

		windowsRestriction?: DeviceEnrollmentPlatformRestriction

		windowsMobileRestriction?: DeviceEnrollmentPlatformRestriction

		androidRestriction?: DeviceEnrollmentPlatformRestriction

		macOSRestriction?: DeviceEnrollmentPlatformRestriction

}

export interface DeviceEnrollmentWindowsHelloForBusinessConfiguration extends DeviceEnrollmentConfiguration {

		pinMinimumLength?: number

		pinMaximumLength?: number

		pinUppercaseCharactersUsage?: WindowsHelloForBusinessPinUsage

		pinLowercaseCharactersUsage?: WindowsHelloForBusinessPinUsage

		pinSpecialCharactersUsage?: WindowsHelloForBusinessPinUsage

		state?: Enablement

		securityDeviceRequired?: boolean

		unlockWithBiometricsEnabled?: boolean

		remotePassportEnabled?: boolean

		pinPreviousBlockCount?: number

		pinExpirationInDays?: number

		enhancedBiometricsState?: Enablement

}

export interface ManagedMobileApp extends Entity {

		mobileAppIdentifier?: MobileAppIdentifier

		version?: string

}

export interface TargetedManagedAppPolicyAssignment extends Entity {

		target?: DeviceAndAppManagementAssignmentTarget

}

export interface ManagedAppOperation extends Entity {

		displayName?: string

		lastModifiedDateTime?: string

		state?: string

		version?: string

}

export interface ManagedAppPolicyDeploymentSummary extends Entity {

		displayName?: string

		configurationDeployedUserCount?: number

		lastRefreshTime?: string

		configurationDeploymentSummaryPerApp?: ManagedAppPolicyDeploymentSummaryPerApp[]

		version?: string

}

export interface WindowsInformationProtectionAppLockerFile extends Entity {

		displayName?: string

		fileHash?: string

		file?: number

		version?: string

}

export interface IosManagedAppRegistration extends ManagedAppRegistration {

}

export interface AndroidManagedAppRegistration extends ManagedAppRegistration {

}

export interface ManagedAppStatusRaw extends ManagedAppStatus {

		content?: any

}

export interface LocalizedNotificationMessage extends Entity {

		lastModifiedDateTime?: string

		locale?: string

		subject?: string

		messageTemplate?: string

		isDefault?: boolean

}

export interface DeviceAndAppManagementRoleDefinition extends RoleDefinition {

}

export interface ManagedEBookAssignment extends Entity {

		target?: DeviceAndAppManagementAssignmentTarget

		installIntent?: InstallIntent

}

export interface EBookInstallSummary extends Entity {

		installedDeviceCount?: number

		failedDeviceCount?: number

		notInstalledDeviceCount?: number

		installedUserCount?: number

		failedUserCount?: number

		notInstalledUserCount?: number

}

export interface DeviceInstallState extends Entity {

		deviceName?: string

		deviceId?: string

		lastSyncDateTime?: string

		installState?: InstallState

		errorCode?: string

		osVersion?: string

		osDescription?: string

		userName?: string

}

export interface UserInstallStateSummary extends Entity {

		userName?: string

		installedDeviceCount?: number

		failedDeviceCount?: number

		notInstalledDeviceCount?: number

		deviceStates?: DeviceInstallState[]

}

export interface IosVppEBookAssignment extends ManagedEBookAssignment {

}

export interface IosVppEBook extends ManagedEBook {

		vppTokenId?: string

		appleId?: string

		vppOrganizationName?: string

		genres?: string[]

		language?: string

		seller?: string

		totalLicenseCount?: number

		usedLicenseCount?: number

}

export interface EnrollmentTroubleshootingEvent extends DeviceManagementTroubleshootingEvent {

		managedDeviceIdentifier?: string

		operatingSystem?: string

		osVersion?: string

		userId?: string

		deviceId?: string

		enrollmentType?: DeviceEnrollmentType

		failureCategory?: DeviceEnrollmentFailureReason

		failureReason?: string

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

export interface Security extends Entity {

		alerts?: Alert[]

}

export interface Alert extends Entity {

		activityGroupName?: string

		assignedTo?: string

		azureSubscriptionId?: string

		azureTenantId?: string

		category?: string

		closedDateTime?: string

		cloudAppStates?: CloudAppSecurityState[]

		comments?: string[]

		confidence?: number

		createdDateTime?: string

		description?: string

		detectionIds?: string[]

		eventDateTime?: string

		feedback?: AlertFeedback

		fileStates?: FileSecurityState[]

		hostStates?: HostSecurityState[]

		lastModifiedDateTime?: string

		malwareStates?: MalwareState[]

		networkConnections?: NetworkConnection[]

		processes?: Process[]

		recommendedActions?: string[]

		registryKeyStates?: RegistryKeyState[]

		severity?: AlertSeverity

		sourceMaterials?: string[]

		status?: AlertStatus

		tags?: string[]

		title?: string

		triggers?: AlertTrigger[]

		userStates?: UserSecurityState[]

		vendorInformation?: SecurityVendorInformation

		vulnerabilityStates?: VulnerabilityState[]

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

export interface AppCatalogs extends Entity {

		teamsApps?: TeamsApp[]

}

export interface TeamsApp extends Entity {

		externalId?: string

		displayName?: string

		distributionMethod?: TeamsAppDistributionMethod

		appDefinitions?: TeamsAppDefinition[]

}

export interface Channel extends Entity {

		displayName?: string

		description?: string

		tabs?: TeamsTab[]

}

export interface TeamsAppInstallation extends Entity {

		teamsApp?: TeamsApp

		teamsAppDefinition?: TeamsAppDefinition

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

export interface TeamsAppDefinition extends Entity {

		teamsAppId?: string

		displayName?: string

		version?: string

}

export interface TeamsTab extends Entity {

		displayName?: string

		webUrl?: string

		configuration?: TeamsTabConfiguration

		teamsApp?: TeamsApp

}

export interface DataPolicyOperation extends Entity {

		completedDateTime?: string

		status?: DataPolicyOperationStatus

		storageLocation?: string

		userId?: string

		submittedDateTime?: string

		progress?: number

}
export interface AlternativeSecurityId {

		type?: number

		identityProvider?: string

		key?: number

}
export interface DomainState {

		status?: string

		operation?: string

		lastActionDateTime?: string

}
export interface ServicePlanInfo {

		servicePlanId?: string

		servicePlanName?: string

		provisioningStatus?: string

		appliesTo?: string

}
export interface OnPremisesProvisioningError {

		value?: string

		category?: string

		propertyCausingError?: string

		occurredDateTime?: string

}
export interface LicenseUnitsDetail {

		enabled?: number

		suspended?: number

		warning?: number

}
export interface AssignedPlan {

		assignedDateTime?: string

		capabilityStatus?: string

		service?: string

		servicePlanId?: string

}
export interface PrivacyProfile {

		contactEmail?: string

		statementUrl?: string

}
export interface ProvisionedPlan {

		capabilityStatus?: string

		provisioningStatus?: string

		service?: string

}
export interface VerifiedDomain {

		capabilities?: string

		isDefault?: boolean

		isInitial?: boolean

		name?: string

		type?: string

}
export interface AssignedLicense {

		disabledPlans?: string[]

		skuId?: string

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
export interface PasswordProfile {

		password?: string

		forceChangePasswordNextSignIn?: boolean

}
export interface MailboxSettings {

		automaticRepliesSetting?: AutomaticRepliesSetting

		archiveFolder?: string

		timeZone?: string

		language?: LocaleInfo

		workingHours?: WorkingHours

}
export interface AutomaticRepliesSetting {

		status?: AutomaticRepliesStatus

		externalAudience?: ExternalAudienceScope

		scheduledStartDateTime?: DateTimeTimeZone

		scheduledEndDateTime?: DateTimeTimeZone

		internalReplyMessage?: string

		externalReplyMessage?: string

}
export interface DateTimeTimeZone {

		dateTime?: string

		timeZone?: string

}
export interface LocaleInfo {

		locale?: string

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
export interface SettingValue {

		name?: string

		value?: string

}
export interface SettingTemplateValue {

		name?: string

		type?: string

		defaultValue?: string

		description?: string

}
export interface ComplexExtensionValue {

}
export interface ExtensionSchemaProperty {

		name?: string

		type?: string

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

		emailAddress?: EmailAddress

}
export interface EmailAddress {

		name?: string

		address?: string

}
export interface AttendeeBase extends Recipient {

		type?: AttendeeType

}
export interface MeetingTimeSuggestionsResult {

		meetingTimeSuggestions?: MeetingTimeSuggestion[]

		emptySuggestionsReason?: string

}
export interface MeetingTimeSuggestion {

		meetingTimeSlot?: TimeSlot

		confidence?: number

		organizerAvailability?: FreeBusyStatus

		attendeeAvailability?: AttendeeAvailability[]

		locations?: Location[]

		suggestionReason?: string

}
export interface TimeSlot {

		start?: DateTimeTimeZone

		end?: DateTimeTimeZone

}
export interface AttendeeAvailability {

		attendee?: AttendeeBase

		availability?: FreeBusyStatus

}
export interface Location {

		displayName?: string

		locationEmailAddress?: string

		address?: PhysicalAddress

		coordinates?: OutlookGeoCoordinates

		locationUri?: string

		locationType?: LocationType

		uniqueId?: string

		uniqueIdType?: LocationUniqueIdType

}
export interface PhysicalAddress {

		street?: string

		city?: string

		state?: string

		countryOrRegion?: string

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

		resolveAvailability?: boolean

}
export interface TimeConstraint {

		activityDomain?: ActivityDomain

		timeslots?: TimeSlot[]

}
export interface Reminder {

		eventId?: string

		eventStartTime?: DateTimeTimeZone

		eventEndTime?: DateTimeTimeZone

		changeKey?: string

		eventSubject?: string

		eventLocation?: Location

		eventWebLink?: string

		reminderFireTime?: DateTimeTimeZone

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
export interface TimeZoneInformation {

		alias?: string

		displayName?: string

}
export interface InternetMessageHeader {

		name?: string

		value?: string

}
export interface ItemBody {

		contentType?: BodyType

		content?: string

}
export interface FollowupFlag {

		completedDateTime?: DateTimeTimeZone

		dueDateTime?: DateTimeTimeZone

		startDateTime?: DateTimeTimeZone

		flagStatus?: FollowupFlagStatus

}
export interface ResponseStatus {

		response?: ResponseType

		time?: string

}
export interface PatternedRecurrence {

		pattern?: RecurrencePattern

		range?: RecurrenceRange

}
export interface RecurrencePattern {

		type?: RecurrencePatternType

		interval?: number

		month?: number

		dayOfMonth?: number

		daysOfWeek?: DayOfWeek[]

		firstDayOfWeek?: DayOfWeek

		index?: WeekIndex

}
export interface RecurrenceRange {

		type?: RecurrenceRangeType

		startDate?: string

		endDate?: string

		recurrenceTimeZone?: string

		numberOfOccurrences?: number

}
export interface Attendee extends AttendeeBase {

		status?: ResponseStatus

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
export interface ScoredEmailAddress {

		address?: string

		relevanceScore?: number

		selectionLikelihood?: SelectionLikelihoodInfo

		ItemId?: string

}
export interface Phone {

		type?: PhoneType

		number?: string

		region?: string

		language?: string

}
export interface Website {

		type?: WebsiteType

		address?: string

		displayName?: string

}
export interface PersonType {

		class?: string

		subclass?: string

}
export interface IdentitySet {

		application?: Identity

		device?: Identity

		user?: Identity

}
export interface Identity {

		displayName?: string

		id?: string

}
export interface ItemReference {

		driveId?: string

		driveType?: string

		id?: string

		name?: string

		path?: string

		shareId?: string

		sharepointIds?: SharepointIds

}
export interface SharepointIds {

		listId?: string

		listItemId?: string

		listItemUniqueId?: string

		siteId?: string

		siteUrl?: string

		webId?: string

}
export interface PublicationFacet {

		level?: string

		versionId?: string

}
export interface BooleanColumn {

}
export interface CalculatedColumn {

		format?: string

		formula?: string

		outputType?: string

}
export interface ChoiceColumn {

		allowTextEntry?: boolean

		choices?: string[]

		displayAs?: string

}
export interface CurrencyColumn {

		locale?: string

}
export interface DateTimeColumn {

		displayAs?: string

		format?: string

}
export interface DefaultColumnValue {

		formula?: string

		value?: string

}
export interface LookupColumn {

		allowMultipleValues?: boolean

		allowUnlimitedLength?: boolean

		columnName?: string

		listId?: string

		primaryLookupColumnId?: string

}
export interface NumberColumn {

		decimalPlaces?: string

		displayAs?: string

		maximum?: number

		minimum?: number

}
export interface PersonOrGroupColumn {

		allowMultipleSelection?: boolean

		chooseFromType?: string

		displayAs?: string

}
export interface TextColumn {

		allowMultipleLines?: boolean

		appendChangesToExistingText?: boolean

		linesForEditing?: number

		maxLength?: number

		textType?: string

}
export interface ContentTypeOrder {

		default?: boolean

		position?: number

}
export interface Quota {

		deleted?: number

		remaining?: number

		state?: string

		total?: number

		used?: number

}
export interface SystemFacet {

}
export interface Audio {

		album?: string

		albumArtist?: string

		artist?: string

		bitrate?: number

		composers?: string

		copyright?: string

		disc?: number

		discCount?: number

		duration?: number

		genre?: string

		hasDrm?: boolean

		isVariableBitrate?: boolean

		title?: string

		track?: number

		trackCount?: number

		year?: number

}
export interface Deleted {

		state?: string

}
export interface File {

		hashes?: Hashes

		mimeType?: string

		processingMetadata?: boolean

}
export interface Hashes {

		crc32Hash?: string

		quickXorHash?: string

		sha1Hash?: string

}
export interface FileSystemInfo {

		createdDateTime?: string

		lastAccessedDateTime?: string

		lastModifiedDateTime?: string

}
export interface Folder {

		childCount?: number

		view?: FolderView

}
export interface FolderView {

		sortBy?: string

		sortOrder?: string

		viewType?: string

}
export interface Image {

		height?: number

		width?: number

}
export interface GeoCoordinates {

		altitude?: number

		latitude?: number

		longitude?: number

}
export interface Package {

		type?: string

}
export interface Photo {

		cameraMake?: string

		cameraModel?: string

		exposureDenominator?: number

		exposureNumerator?: number

		fNumber?: number

		focalLength?: number

		iso?: number

		takenDateTime?: string

}
export interface RemoteItem {

		createdBy?: IdentitySet

		createdDateTime?: string

		file?: File

		fileSystemInfo?: FileSystemInfo

		folder?: Folder

		id?: string

		lastModifiedBy?: IdentitySet

		lastModifiedDateTime?: string

		name?: string

		package?: Package

		parentReference?: ItemReference

		shared?: Shared

		sharepointIds?: SharepointIds

		size?: number

		specialFolder?: SpecialFolder

		webDavUrl?: string

		webUrl?: string

}
export interface Shared {

		owner?: IdentitySet

		scope?: string

		sharedBy?: IdentitySet

		sharedDateTime?: string

}
export interface SpecialFolder {

		name?: string

}
export interface Root {

}
export interface SearchResult {

		onClickTelemetryUrl?: string

}
export interface Video {

		audioBitsPerSample?: number

		audioChannels?: number

		audioFormat?: string

		audioSamplesPerSecond?: number

		bitrate?: number

		duration?: number

		fourCC?: string

		frameRate?: number

		height?: number

		width?: number

}
export interface ListInfo {

		contentTypesEnabled?: boolean

		hidden?: boolean

		template?: string

}
export interface ContentTypeInfo {

		id?: string

}
export interface SharingInvitation {

		email?: string

		invitedBy?: IdentitySet

		redeemedBy?: string

		signInRequired?: boolean

}
export interface SharingLink {

		application?: Identity

		scope?: string

		type?: string

		webUrl?: string

}
export interface SiteCollection {

		hostname?: string

		root?: Root

}
export interface Thumbnail {

		content?: any

		height?: number

		sourceItemId?: string

		url?: string

		width?: number

}
export interface DriveItemUploadableProperties {

		description?: string

		fileSystemInfo?: FileSystemInfo

		name?: string

}
export interface DriveRecipient {

		alias?: string

		email?: string

		objectId?: string

}
export interface ItemPreviewInfo {

		getUrl?: string

		postParameters?: string

		postUrl?: string

}
export interface UploadSession {

		expirationDateTime?: string

		nextExpectedRanges?: string[]

		uploadUrl?: string

}
export interface WorkbookSessionInfo {

		id?: string

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
export interface InvitedUserMessageInfo {

		ccRecipients?: Recipient[]

		messageLanguage?: string

		customizedMessageBody?: string

}
export interface PlannerAppliedCategories {

}
export interface PlannerAssignments {

}
export interface PlannerExternalReference {

		alias?: string

		type?: string

		previewPriority?: string

		lastModifiedBy?: IdentitySet

		lastModifiedDateTime?: string

}
export interface PlannerChecklistItem {

		isChecked?: boolean

		title?: string

		orderHint?: string

		lastModifiedBy?: IdentitySet

		lastModifiedDateTime?: string

}
export interface PlannerAssignment {

		assignedBy?: IdentitySet

		assignedDateTime?: string

		orderHint?: string

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

		category1?: string

		category2?: string

		category3?: string

		category4?: string

		category5?: string

		category6?: string

}
export interface NotebookLinks {

		oneNoteClientUrl?: ExternalLink

		oneNoteWebUrl?: ExternalLink

}
export interface ExternalLink {

		href?: string

}
export interface SectionLinks {

		oneNoteClientUrl?: ExternalLink

		oneNoteWebUrl?: ExternalLink

}
export interface PageLinks {

		oneNoteClientUrl?: ExternalLink

		oneNoteWebUrl?: ExternalLink

}
export interface OnenoteOperationError {

		code?: string

		message?: string

}
export interface Diagnostic {

		message?: string

		url?: string

}
export interface OnenotePatchContentCommand {

		action?: OnenotePatchActionType

		target?: string

		content?: string

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

		lastAccessedTime?: string

		links?: RecentNotebookLinks

		sourceService?: OnenoteSourceService

}
export interface RecentNotebookLinks {

		oneNoteClientUrl?: ExternalLink

		oneNoteWebUrl?: ExternalLink

}
export interface Report {

		content?: any

}
export interface EducationStudent {

		graduationYear?: string

		grade?: string

		birthDate?: string

		gender?: EducationGender

		studentNumber?: string

		externalId?: string

}
export interface EducationRelatedContact {

		id?: string

		displayName?: string

		emailAddress?: string

		mobilePhone?: string

		relationship?: EducationContactRelationship

		accessConsent?: boolean

}
export interface EducationTeacher {

		teacherNumber?: string

		externalId?: string

}
export interface EducationTerm {

		externalId?: string

		startDate?: string

		endDate?: string

		displayName?: string

}
export interface DeviceAndAppManagementAssignmentTarget {

}
export interface MobileAppAssignmentSettings {

}
export interface MimeContent {

		type?: string

		value?: number

}
export interface FileEncryptionInfo {

		encryptionKey?: number

		initializationVector?: number

		mac?: number

		macKey?: number

		profileIdentifier?: string

		fileDigest?: number

		fileDigestAlgorithm?: string

}
export interface AllLicensedUsersAssignmentTarget extends DeviceAndAppManagementAssignmentTarget {

}
export interface GroupAssignmentTarget extends DeviceAndAppManagementAssignmentTarget {

		groupId?: string

}
export interface ExclusionGroupAssignmentTarget extends GroupAssignmentTarget {

}
export interface AllDevicesAssignmentTarget extends DeviceAndAppManagementAssignmentTarget {

}
export interface IosLobAppAssignmentSettings extends MobileAppAssignmentSettings {

		vpnConfigurationId?: string

}
export interface IosStoreAppAssignmentSettings extends MobileAppAssignmentSettings {

		vpnConfigurationId?: string

}
export interface IosVppAppAssignmentSettings extends MobileAppAssignmentSettings {

		useDeviceLicensing?: boolean

		vpnConfigurationId?: string

}
export interface MicrosoftStoreForBusinessAppAssignmentSettings extends MobileAppAssignmentSettings {

		useDeviceContext?: boolean

}
export interface AndroidMinimumOperatingSystem {

		v4_0?: boolean

		v4_0_3?: boolean

		v4_1?: boolean

		v4_2?: boolean

		v4_3?: boolean

		v4_4?: boolean

		v5_0?: boolean

		v5_1?: boolean

}
export interface IosDeviceType {

		iPad?: boolean

		iPhoneAndIPod?: boolean

}
export interface IosMinimumOperatingSystem {

		v8_0?: boolean

		v9_0?: boolean

		v10_0?: boolean

		v11_0?: boolean

		v12_0?: boolean

}
export interface WindowsMinimumOperatingSystem {

		v8_0?: boolean

		v8_1?: boolean

		v10_0?: boolean

}
export interface VppLicensingType {

		supportsUserLicensing?: boolean

		supportsDeviceLicensing?: boolean

}
export interface AppConfigurationSettingItem {

		appConfigKey?: string

		appConfigKeyType?: MdmAppConfigKeyType

		appConfigKeyValue?: string

}
export interface DeviceManagementSettings {

		deviceComplianceCheckinThresholdDays?: number

		isScheduledActionEnabled?: boolean

		secureByDefault?: boolean

}
export interface IntuneBrand {

		displayName?: string

		contactITName?: string

		contactITPhoneNumber?: string

		contactITEmailAddress?: string

		contactITNotes?: string

		privacyUrl?: string

		onlineSupportSiteUrl?: string

		onlineSupportSiteName?: string

		themeColor?: RgbColor

		showLogo?: boolean

		lightBackgroundLogo?: MimeContent

		darkBackgroundLogo?: MimeContent

		showNameNextToLogo?: boolean

		showDisplayNameNextToLogo?: boolean

}
export interface RgbColor {

		r?: number

		g?: number

		b?: number

}
export interface DeviceActionResult {

		actionName?: string

		actionState?: ActionState

		startDateTime?: string

		lastUpdatedDateTime?: string

}
export interface ConfigurationManagerClientEnabledFeatures {

		inventory?: boolean

		modernApps?: boolean

		resourceAccess?: boolean

		deviceConfiguration?: boolean

		compliancePolicy?: boolean

		windowsUpdateForBusiness?: boolean

}
export interface DeviceHealthAttestationState {

		lastUpdateDateTime?: string

		contentNamespaceUrl?: string

		deviceHealthAttestationStatus?: string

		contentVersion?: string

		issuedDateTime?: string

		attestationIdentityKey?: string

		resetCount?: number

		restartCount?: number

		dataExcutionPolicy?: string

		bitLockerStatus?: string

		bootManagerVersion?: string

		codeIntegrityCheckVersion?: string

		secureBoot?: string

		bootDebugging?: string

		operatingSystemKernelDebugging?: string

		codeIntegrity?: string

		testSigning?: string

		safeMode?: string

		windowsPE?: string

		earlyLaunchAntiMalwareDriverProtection?: string

		virtualSecureMode?: string

		pcrHashAlgorithm?: string

		bootAppSecurityVersion?: string

		bootManagerSecurityVersion?: string

		tpmVersion?: string

		pcr0?: string

		secureBootConfigurationPolicyFingerPrint?: string

		codeIntegrityPolicy?: string

		bootRevisionListInfo?: string

		operatingSystemRevListInfo?: string

		healthStatusMismatchInfo?: string

		healthAttestationSupportedStatus?: string

}
export interface UpdateWindowsDeviceAccountActionParameter {

		deviceAccount?: WindowsDeviceAccount

		passwordRotationEnabled?: boolean

		calendarSyncEnabled?: boolean

		deviceAccountEmail?: string

		exchangeServer?: string

		sessionInitiationProtocalAddress?: string

}
export interface WindowsDeviceAccount {

		password?: string

}
export interface WindowsDefenderScanActionResult extends DeviceActionResult {

		scanType?: string

}
export interface DeleteUserFromSharedAppleDeviceActionResult extends DeviceActionResult {

		userPrincipalName?: string

}
export interface DeviceGeoLocation {

		lastCollectedDateTime?: string

		longitude?: number

		latitude?: number

		altitude?: number

		horizontalAccuracy?: number

		verticalAccuracy?: number

		heading?: number

		speed?: number

}
export interface LocateDeviceActionResult extends DeviceActionResult {

		deviceLocation?: DeviceGeoLocation

}
export interface RemoteLockActionResult extends DeviceActionResult {

		unlockPin?: string

}
export interface ResetPasscodeActionResult extends DeviceActionResult {

		passcode?: string

}
export interface DeviceOperatingSystemSummary {

		androidCount?: number

		iosCount?: number

		macOSCount?: number

		windowsMobileCount?: number

		windowsCount?: number

		unknownCount?: number

}
export interface DeviceExchangeAccessStateSummary {

		allowedDeviceCount?: number

		blockedDeviceCount?: number

		quarantinedDeviceCount?: number

		unknownDeviceCount?: number

		unavailableDeviceCount?: number

}
export interface WindowsDeviceADAccount extends WindowsDeviceAccount {

		domainName?: string

		userName?: string

}
export interface WindowsDeviceAzureADAccount extends WindowsDeviceAccount {

		userPrincipalName?: string

}
export interface AppListItem {

		name?: string

		publisher?: string

		appStoreUrl?: string

		appId?: string

}
export interface OmaSetting {

		displayName?: string

		description?: string

		omaUri?: string

}
export interface OmaSettingInteger extends OmaSetting {

		value?: number

}
export interface OmaSettingFloatingPoint extends OmaSetting {

		value?: number

}
export interface OmaSettingString extends OmaSetting {

		value?: string

}
export interface OmaSettingDateTime extends OmaSetting {

		value?: string

}
export interface OmaSettingStringXml extends OmaSetting {

		fileName?: string

		value?: number

}
export interface OmaSettingBoolean extends OmaSetting {

		value?: boolean

}
export interface OmaSettingBase64 extends OmaSetting {

		fileName?: string

		value?: string

}
export interface MediaContentRatingAustralia {

		movieRating?: RatingAustraliaMoviesType

		tvRating?: RatingAustraliaTelevisionType

}
export interface MediaContentRatingCanada {

		movieRating?: RatingCanadaMoviesType

		tvRating?: RatingCanadaTelevisionType

}
export interface MediaContentRatingFrance {

		movieRating?: RatingFranceMoviesType

		tvRating?: RatingFranceTelevisionType

}
export interface MediaContentRatingGermany {

		movieRating?: RatingGermanyMoviesType

		tvRating?: RatingGermanyTelevisionType

}
export interface MediaContentRatingIreland {

		movieRating?: RatingIrelandMoviesType

		tvRating?: RatingIrelandTelevisionType

}
export interface MediaContentRatingJapan {

		movieRating?: RatingJapanMoviesType

		tvRating?: RatingJapanTelevisionType

}
export interface MediaContentRatingNewZealand {

		movieRating?: RatingNewZealandMoviesType

		tvRating?: RatingNewZealandTelevisionType

}
export interface MediaContentRatingUnitedKingdom {

		movieRating?: RatingUnitedKingdomMoviesType

		tvRating?: RatingUnitedKingdomTelevisionType

}
export interface MediaContentRatingUnitedStates {

		movieRating?: RatingUnitedStatesMoviesType

		tvRating?: RatingUnitedStatesTelevisionType

}
export interface IosNetworkUsageRule {

		managedApps?: AppListItem[]

		cellularDataBlockWhenRoaming?: boolean

		cellularDataBlocked?: boolean

}
export interface IosHomeScreenItem {

		displayName?: string

}
export interface IosHomeScreenPage {

		displayName?: string

		icons?: IosHomeScreenItem[]

}
export interface IosNotificationSettings {

		bundleID?: string

		appName?: string

		publisher?: string

		enabled?: boolean

		showInNotificationCenter?: boolean

		showOnLockScreen?: boolean

		alertType?: IosNotificationAlertType

		badgesEnabled?: boolean

		soundsEnabled?: boolean

}
export interface IosHomeScreenFolder extends IosHomeScreenItem {

		pages?: IosHomeScreenFolderPage[]

}
export interface IosHomeScreenFolderPage {

		displayName?: string

		apps?: IosHomeScreenApp[]

}
export interface IosHomeScreenApp extends IosHomeScreenItem {

		bundleID?: string

}
export interface WindowsFirewallNetworkProfile {

		firewallEnabled?: StateManagementSetting

		stealthModeBlocked?: boolean

		incomingTrafficBlocked?: boolean

		unicastResponsesToMulticastBroadcastsBlocked?: boolean

		inboundNotificationsBlocked?: boolean

		authorizedApplicationRulesFromGroupPolicyMerged?: boolean

		globalPortRulesFromGroupPolicyMerged?: boolean

		connectionSecurityRulesFromGroupPolicyMerged?: boolean

		outboundConnectionsBlocked?: boolean

		inboundConnectionsBlocked?: boolean

		securedPacketExemptionAllowed?: boolean

		policyRulesFromGroupPolicyMerged?: boolean

}
export interface BitLockerRemovableDrivePolicy {

		encryptionMethod?: BitLockerEncryptionMethod

		requireEncryptionForWriteAccess?: boolean

		blockCrossOrganizationWriteAccess?: boolean

}
export interface DefenderDetectedMalwareActions {

		lowSeverity?: DefenderThreatAction

		moderateSeverity?: DefenderThreatAction

		highSeverity?: DefenderThreatAction

		severeSeverity?: DefenderThreatAction

}
export interface Windows10NetworkProxyServer {

		address?: string

		exceptions?: string[]

		useForLocalAddresses?: boolean

}
export interface EdgeSearchEngineBase {

}
export interface EdgeSearchEngineCustom extends EdgeSearchEngineBase {

		edgeSearchEngineOpenSearchXmlUrl?: string

}
export interface EdgeSearchEngine extends EdgeSearchEngineBase {

		edgeSearchEngineType?: EdgeSearchEngineType

}
export interface SharedPCAccountManagerPolicy {

		accountDeletionPolicy?: SharedPCAccountDeletionPolicyType

		cacheAccountsAboveDiskFreePercentage?: number

		inactiveThresholdDays?: number

		removeAccountsBelowDiskFreePercentage?: number

}
export interface WindowsUpdateInstallScheduleType {

}
export interface WindowsUpdateScheduledInstall extends WindowsUpdateInstallScheduleType {

		scheduledInstallDay?: WeeklySchedule

		scheduledInstallTime?: string

}
export interface WindowsUpdateActiveHoursInstall extends WindowsUpdateInstallScheduleType {

		activeHoursStart?: string

		activeHoursEnd?: string

}
export interface DeviceConfigurationSettingState {

		setting?: string

		settingName?: string

		instanceDisplayName?: string

		state?: ComplianceStatus

		errorCode?: number

		errorDescription?: string

		userId?: string

		userName?: string

		userEmail?: string

		userPrincipalName?: string

		sources?: SettingSource[]

		currentValue?: string

}
export interface SettingSource {

		id?: string

		displayName?: string

}
export interface DeviceCompliancePolicySettingState {

		setting?: string

		settingName?: string

		instanceDisplayName?: string

		state?: ComplianceStatus

		errorCode?: number

		errorDescription?: string

		userId?: string

		userName?: string

		userEmail?: string

		userPrincipalName?: string

		sources?: SettingSource[]

		currentValue?: string

}
export interface DeviceEnrollmentPlatformRestriction {

		platformBlocked?: boolean

		personalDeviceEnrollmentBlocked?: boolean

		osMinimumVersion?: string

		osMaximumVersion?: string

}
export interface MobileAppIdentifier {

}
export interface ManagedAppDiagnosticStatus {

		validationName?: string

		state?: string

		mitigationInstruction?: string

}
export interface KeyValuePair {

		name?: string

		value?: string

}
export interface WindowsInformationProtectionResourceCollection {

		displayName?: string

		resources?: string[]

}
export interface WindowsInformationProtectionDataRecoveryCertificate {

		subjectName?: string

		description?: string

		expirationDateTime?: string

		certificate?: number

}
export interface WindowsInformationProtectionApp {

		displayName?: string

		description?: string

		publisherName?: string

		productName?: string

		denied?: boolean

}
export interface WindowsInformationProtectionProxiedDomainCollection {

		displayName?: string

		proxiedDomains?: ProxiedDomain[]

}
export interface ProxiedDomain {

		ipAddressOrFQDN?: string

		proxy?: string

}
export interface WindowsInformationProtectionIPRangeCollection {

		displayName?: string

		ranges?: IpRange[]

}
export interface IpRange {

}
export interface AndroidMobileAppIdentifier extends MobileAppIdentifier {

		packageId?: string

}
export interface IosMobileAppIdentifier extends MobileAppIdentifier {

		bundleId?: string

}
export interface ManagedAppPolicyDeploymentSummaryPerApp {

		mobileAppIdentifier?: MobileAppIdentifier

		configurationAppliedUserCount?: number

}
export interface WindowsInformationProtectionStoreApp extends WindowsInformationProtectionApp {

}
export interface WindowsInformationProtectionDesktopApp extends WindowsInformationProtectionApp {

		binaryName?: string

		binaryVersionLow?: string

		binaryVersionHigh?: string

}
export interface IPv6Range extends IpRange {

		lowerAddress?: string

		upperAddress?: string

}
export interface IPv4Range extends IpRange {

		lowerAddress?: string

		upperAddress?: string

}
export interface RolePermission {

		resourceActions?: ResourceAction[]

}
export interface ResourceAction {

		allowedResourceActions?: string[]

		notAllowedResourceActions?: string[]

}
export interface ImageInfo {

		iconUrl?: string

		alternativeText?: string

		alternateText?: string

		addImageQuery?: boolean

}
export interface VisualInfo {

		attribution?: ImageInfo

		backgroundColor?: string

		description?: string

		displayText?: string

		content?: any

}
export interface CloudAppSecurityState {

		destinationServiceIp?: string

		destinationServiceName?: string

		riskScore?: string

}
export interface FileSecurityState {

		fileHash?: FileHash

		name?: string

		path?: string

		riskScore?: string

}
export interface FileHash {

		hashType?: FileHashType

		hashValue?: string

}
export interface HostSecurityState {

		fqdn?: string

		isAzureAdJoined?: boolean

		isAzureAdRegistered?: boolean

		isHybridAzureDomainJoined?: boolean

		netBiosName?: string

		os?: string

		privateIpAddress?: string

		publicIpAddress?: string

		riskScore?: string

}
export interface MalwareState {

		category?: string

		family?: string

		name?: string

		severity?: string

		wasRunning?: boolean

}
export interface NetworkConnection {

		applicationName?: string

		destinationAddress?: string

		destinationDomain?: string

		destinationPort?: string

		destinationUrl?: string

		direction?: ConnectionDirection

		domainRegisteredDateTime?: string

		localDnsName?: string

		natDestinationAddress?: string

		natDestinationPort?: string

		natSourceAddress?: string

		natSourcePort?: string

		protocol?: SecurityNetworkProtocol

		riskScore?: string

		sourceAddress?: string

		sourcePort?: string

		status?: ConnectionStatus

		urlParameters?: string

}
export interface Process {

		accountName?: string

		commandLine?: string

		createdDateTime?: string

		fileHash?: FileHash

		integrityLevel?: ProcessIntegrityLevel

		isElevated?: boolean

		name?: string

		parentProcessCreatedDateTime?: string

		parentProcessId?: number

		parentProcessName?: string

		path?: string

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

		name?: string

		type?: string

		value?: string

}
export interface UserSecurityState {

		aadUserId?: string

		accountName?: string

		domainName?: string

		emailRole?: EmailRole

		isVpn?: boolean

		logonDateTime?: string

		logonId?: string

		logonIp?: string

		logonLocation?: string

		logonType?: LogonType

		onPremisesSecurityIdentifier?: string

		riskScore?: string

		userAccountType?: UserAccountSecurityType

		userPrincipalName?: string

}
export interface SecurityVendorInformation {

		provider?: string

		providerVersion?: string

		subProvider?: string

		vendor?: string

}
export interface VulnerabilityState {

		cve?: string

		severity?: string

		wasRunning?: boolean

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
export interface TeamMemberSettings {

		allowCreateUpdateChannels?: boolean

		allowDeleteChannels?: boolean

		allowAddRemoveApps?: boolean

		allowCreateUpdateRemoveTabs?: boolean

		allowCreateUpdateRemoveConnectors?: boolean

}
export interface TeamGuestSettings {

		allowCreateUpdateChannels?: boolean

		allowDeleteChannels?: boolean

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
export interface TeamClassSettings {

		notifyGuardiansAboutAssignments?: boolean

}
export interface TeamsTabConfiguration {

		entityId?: string

		contentUrl?: string

		removeUrl?: string

		websiteUrl?: string

}
export interface OperationError {

		code?: string

		message?: string

}
