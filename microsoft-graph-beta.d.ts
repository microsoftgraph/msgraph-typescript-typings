// Type definitions for the Microsoft Graph API
// Project: https://github.com/microsoftgraph/msgraph-typescript-typings
// Definitions by: Microsoft Graph Team <https://github.com/microsoftgraph>

//
// Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
//



export type AutomaticRepliesStatus = "disabled" | "alwaysEnabled" | "scheduled"
export type ExternalAudienceScope = "none" | "contactsOnly" | "all"
export type AttendeeType = "required" | "optional" | "resource"
export type FreeBusyStatus = "free" | "tentative" | "busy" | "oof" | "workingElsewhere" | "unknown"
export type PhysicalAddressType = "unknown" | "home" | "business" | "other"
export type ActivityDomain = "unknown" | "work" | "personal"
export type RecipientScopeType = "none" | "internal" | "external" | "externalPartner" | "externalNonPartner"
export type MailTipsType = "automaticReplies" | "mailboxFullStatus" | "customMailTip" | "externalMemberCount" | "totalMemberCount" | "maxMessageSize" | "deliveryRestriction" | "moderationStatus" | "recipientScope" | "recipientSuggestions"
export type BodyType = "text" | "html"
export type Importance = "low" | "normal" | "high"
export type InferenceClassificationType = "focused" | "other"
export type FollowupFlagStatus = "notFlagged" | "complete" | "flagged"
export type CalendarColor = "lightBlue" | "lightGreen" | "lightOrange" | "lightGray" | "lightYellow" | "lightTeal" | "lightPink" | "lightBrown" | "lightRed" | "maxColor" | "auto"
export type ResponseType = "none" | "organizer" | "tentativelyAccepted" | "accepted" | "declined" | "notResponded"
export type Sensitivity = "normal" | "personal" | "private" | "confidential"
export type RecurrencePatternType = "daily" | "weekly" | "absoluteMonthly" | "relativeMonthly" | "absoluteYearly" | "relativeYearly"
export type DayOfWeek = "sunday" | "monday" | "tuesday" | "wednesday" | "thursday" | "friday" | "saturday"
export type WeekIndex = "first" | "second" | "third" | "fourth" | "last"
export type RecurrenceRangeType = "endDate" | "noEnd" | "numbered"
export type EventType = "singleInstance" | "occurrence" | "exception" | "seriesMaster"
export type WebsiteType = "other" | "home" | "work" | "blog" | "profile"
export type PhoneType = "home" | "business" | "mobile" | "other" | "assistant" | "homeFax" | "businessFax" | "otherFax" | "pager" | "radio"
export type MeetingMessageType = "none" | "meetingRequest" | "meetingCancelled" | "meetingAccepted" | "meetingTentativelyAccepted" | "meetingDeclined"
export type ReferenceAttachmentProvider = "other" | "oneDriveBusiness" | "oneDriveConsumer" | "dropbox"
export type ReferenceAttachmentPermission = "other" | "view" | "edit" | "anonymousView" | "anonymousEdit" | "organizationView" | "organizationEdit"
export type GroupAccessType = "none" | "private" | "secret" | "public"
export type ContainerType = "none" | "oneDrive" | "group" | "site"
export type TaskBoardType = "progress" | "assignedTo" | "bucket"
export type PreviewType = "automatic" | "noPreview" | "checklist" | "description" | "reference"
export type PatchInsertPosition = "After" | "Before"
export type PatchActionType = "Replace" | "Append" | "Delete" | "Insert" | "Prepend"
export type UserRole = "Owner" | "Contributor" | "Reader" | "None"
export type RiskEventStatus = "active" | "remediated" | "dismissedAsFixed" | "dismissedAsFalsePositive" | "dismissedAsIgnore" | "loginBlocked" | "closedMfaAuto" | "closedMultipleReasons"
export type RiskLevel = "low" | "medium" | "high"
export type UserRiskLevel = "unknown" | "none" | "low" | "medium" | "high"
export type RoleSummaryStatus = "ok" | "bad"
export type SetupStatus = "unknown" | "notRegisteredYet" | "registeredSetupNotStarted" | "registeredSetupInProgress" | "registrationAndSetupCompleted" | "registrationFailed" | "registrationTimedOut" | "disabled"
export type ConnectorGroupType = "applicationProxy"
export type ExternalAuthenticationType = "passthru" | "aadPreAuthentication"
export type ConnectorStatus = "active" | "inactive"
export type AppInstallIntent = "available" | "notApplicable" | "required" | "uninstall" | "availableWithoutEnrollment"
export type ManagedAppAvailability = "global" | "lineOfBusiness"
export type MdmAppConfigKeyType = "stringType" | "integerType" | "realType" | "booleanType" | "tokenType"
export type AppConfigComplianceStatus = "unknown" | "notApplicable" | "compliant" | "remediated" | "nonCompliant" | "error" | "conflict"
export type ITunesPairingMode = "disallow" | "allow" | "requiresCertificate"
export type ImportedDeviceIdentityType = "unknown" | "imei" | "serialNumber"
export type EnrollmentState = "unknown" | "enrolled" | "pendingReset" | "failed" | "notContacted"
export type Platform = "unknown" | "ios" | "android" | "windows" | "windowsMobile" | "macOS"
export type DiscoverySource = "unknown" | "adminImport" | "deviceEnrollmentProgram"
export type ComplianceStatus = "unknown" | "notApplicable" | "compliant" | "remediated" | "nonCompliant" | "error" | "conflict"
export type SubjectNameFormat = "commonName" | "commonNameIncludingEmail" | "commonNameAsEmail"
export type SubjectAlternativeNameType = "emailAddress" | "userPrincipalName"
export type CertificateValidityPeriodScale = "days" | "months" | "years"
export type KeyUsages = "keyEncipherment" | "digitalSignature"
export type KeySize = "size1024" | "size2048"
export type HashAlgorithms = "sha1" | "sha2"
export type EasAuthenticationMethod = "usernameAndPassword" | "certificate"
export type EmailSyncDuration = "userDefined" | "oneDay" | "threeDays" | "oneWeek" | "twoWeeks" | "oneMonth" | "unlimited"
export type UserEmailSource = "userPrincipalName" | "primarySmtpAddress"
export type EmailSyncSchedule = "userDefined" | "asMessagesArrive" | "manual" | "fifteenMinutes" | "thirtyMinutes" | "sixtyMinutes" | "basedOnMyUsage"
export type AndroidUsernameSource = "username" | "userPrincipalName"
export type AndroidForWorkRequiredPasswordType = "deviceDefault" | "lowSecurityBiometric" | "required" | "atLeastNumeric" | "numericComplex" | "atLeastAlphabetic" | "atLeastAlphanumeric" | "alphanumericWithSymbols"
export type AndroidForWorkCrossProfileDataSharingType = "deviceDefault" | "preventAny" | "allowPersonalToWork" | "noRestrictions"
export type AndroidForWorkDefaultAppPermissionPolicyType = "deviceDefault" | "prompt" | "autoGrant" | "autoDeny"
export type AppsComplianceListType = "none" | "appsInListCompliant" | "appsNotInListCompliant"
export type AppListType = "none" | "appsInListCompliant" | "appsNotInListCompliant"
export type AndroidRequiredPasswordType = "deviceDefault" | "alphabetic" | "alphanumeric" | "alphanumericWithSymbols" | "lowSecurityBiometric" | "numeric"
export type WebBrowserCookieSettings = "browserDefault" | "blockAlways" | "allowCurrentWebSite" | "allowFromWebsitesVisited" | "allowAlways"
export type AndroidVpnConnectionType = "ciscoAnyConnect" | "pulseSecure" | "f5EdgeClient" | "dellSonicWallMobileConnect" | "checkPointCapsuleVpn" | "citrix"
export type VpnAuthenticationMethod = "certificate" | "usernameAndPassword"
export type AndroidWiFiSecurityType = "open" | "wpaEnterprise"
export type WiFiAuthenticationMethod = "certificate" | "usernameAndPassword"
export type AndroidEapType = "eapTls" | "eapTtls" | "peap"
export type NonEapAuthenticationMethodForEapTtlsType = "unencryptedPassword" | "challengeHandshakeAuthenticationProtocol" | "microsoftChap" | "microsoftChapVersionTwo"
export type NonEapAuthenticationMethodForPeap = "none" | "microsoftChapVersionTwo"
export type AppleSubjectNameFormat = "commonName" | "commonNameAsEmail" | "custom"
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
export type RatingRegionType = "noRegion" | "australia" | "canada" | "france" | "germany" | "ireland" | "japan" | "newZealand" | "unitedKingdom" | "unitedStates"
export type WiFiSecurityType = "open" | "wpaPersonal" | "wpaEnterprise" | "wep"
export type WiFiProxySetting = "none" | "manual" | "automatic"
export type EapType = "eapTls" | "leap" | "eapSim" | "eapTtls" | "peap" | "eapFast"
export type EapFastConfiguration = "noProtectedAccessCredential" | "useProtectedAccessCredential" | "useProtectedAccessCredentialAndProvision" | "useProtectedAccessCredentialAndProvisionAnonymously"
export type AppleVpnConnectionType = "ciscoAnyConnect" | "pulseSecure" | "f5EdgeClient" | "dellSonicWallMobileConnect" | "checkPointCapsuleVpn" | "customVpn" | "ciscoIPSec" | "citrix"
export type VpnOnDemandRuleConnectionAction = "connect" | "evaluateConnection" | "ignore" | "disconnect"
export type VpnOnDemandRuleConnectionDomainAction = "connectIfNeeded" | "neverConnect"
export type CertificateDestinationStore = "computerCertStoreRoot" | "computerCertStoreIntermediate" | "userCertStoreIntermediate"
export type WindowsDeliveryOptimizationMode = "userDefined" | "httpOnly" | "httpWithPeeringNat" | "httpWithPeeringPrivateGroup" | "httpWithInternetPeering" | "simpleDownload" | "bypassMode"
export type PrereleaseFeatures = "userDefined" | "settingsOnly" | "settingsAndExperimentations" | "notAllowed"
export type AutomaticUpdateMode = "userDefined" | "notifyDownload" | "autoInstallAtMaintenanceTime" | "autoInstallAndRebootAtMaintenanceTime" | "autoInstallAndRebootAtScheduledTime" | "autoInstallAndRebootWithoutEndUserControl"
export type WeeklySchedule = "userDefined" | "everyday" | "sunday" | "monday" | "tuesday" | "wednesday" | "thursday" | "friday" | "saturday"
export type WindowsUpdateType = "userDefined" | "all" | "businessReadyOnly"
export type Windows10VpnConnectionType = "pulseSecure" | "f5EdgeClient" | "dellSonicWallMobileConnect" | "checkPointCapsuleVpn" | "automatic" | "ikEv2" | "l2tp" | "pptp"
export type Windows10VpnAuthenticationMethod = "certificate" | "usernameAndPassword" | "customEapXml"
export type KeyStorageProviderOption = "useTpmKspOtherwiseUseSoftwareKsp" | "useTpmKspOtherwiseFail" | "usePassportForWorkKspOtherwiseFail" | "useSoftwareKsp"
export type Windows10AppType = "desktop" | "universal"
export type VpnTrafficRuleAppType = "none" | "desktop" | "universal"
export type VpnTrafficRuleRoutingPolicyType = "none" | "splitTunnel" | "forceTunnel"
export type WindowsVpnConnectionType = "pulseSecure" | "f5EdgeClient" | "dellSonicWallMobileConnect" | "checkPointCapsuleVpn"
export type InternetSiteSecurityLevel = "userDefined" | "medium" | "mediumHigh" | "high"
export type SiteSecurityLevel = "userDefined" | "low" | "mediumLow" | "medium" | "mediumHigh" | "high"
export type UpdateClassification = "userDefined" | "recommendedAndImportant" | "important" | "none"
export type WindowsUserAccountControlSettings = "userDefined" | "alwaysNotify" | "notifyOnAppChanges" | "notifyOnAppChangesWithoutDimming" | "neverNotify"
export type DefenderMonitorFileActivity = "userDefined" | "disable" | "monitorAllFiles" | "monitorIncomingFilesOnly" | "monitorOutgoingFilesOnly"
export type DefenderPromptForSampleSubmission = "userDefined" | "alwaysPrompt" | "promptBeforeSendingPersonalData" | "neverSendData" | "sendAllDataWithoutPrompting"
export type DefenderScanType = "userDefined" | "disabled" | "quick" | "full"
export type DiagnosticDataSubmissionMode = "userDefined" | "none" | "basic" | "enhanced" | "full"
export type EdgeCookiePolicy = "userDefined" | "allow" | "blockThirdParty" | "blockAll"
export type StateManagementSetting = "notConfigured" | "blocked" | "allowed"
export type MiracastChannel = "userDefined" | "one" | "two" | "three" | "four" | "five" | "six" | "seven" | "eight" | "nine" | "ten" | "eleven" | "thirtySix" | "forty" | "fortyFour" | "fortyEight" | "oneHundredFortyNine" | "oneHundredFiftyThree" | "oneHundredFiftySeven" | "oneHundredSixtyOne" | "oneHundredSixtyFive"
export type WelcomeScreenMeetingInformation = "userDefined" | "showOrganizerAndTimeOnly" | "showOrganizerAndTimeAndSubject"
export type EditionUpgradeLicenseType = "productKey" | "licenseFile"
export type Windows10EditionType = "windows10Enterprise" | "windows10EnterpriseN" | "windows10Education" | "windows10EducationN" | "windows10MobileEnterprise" | "windows10HolographicEnterprise"
export type DeviceComplianceActionType = "noAction" | "notification" | "block" | "retire" | "wipe" | "removeResourceAccessProfiles"
export type DeviceThreatProtectionLevel = "none" | "low" | "medium" | "high"
export type CloudPkiProvider = "unKnown" | "symantec"
export type SyncStatus = "unKnown" | "succeeded" | "failed"
export type DeviceManagementExchangeConnectorSyncType = "fullSync" | "deltaSync"
export type MdmAuthority = "unknown" | "intune" | "sccm" | "office365"
export type VolumePurchaseProgramTokenAccountType = "business" | "education"
export type VolumePurchaseProgramTokenState = "unknown" | "valid" | "expired" | "invalid"
export type VolumePurchaseProgramTokenSyncStatus = "none" | "inProgress" | "completed" | "failed"
export type WindowsHelloForBusinessPinUsage = "allowed" | "required" | "disallowed"
export type WindowsHelloForBusinessConfiguration = "disabled" | "enabled" | "notConfigured"
export type OwnerType = "unknown" | "company" | "personal"
export type DeviceActionState = "none" | "pending" | "cancel" | "active" | "done" | "failed" | "notSupported"
export type ManagementState = "managed" | "retirePending" | "retireFailed" | "wipePending" | "wipeFailed" | "unhealthy" | "deletePending" | "retireIssued" | "wipeIssued" | "wipeCanceled" | "retireCanceled" | "discovered"
export type ChassisType = "unknown" | "desktop" | "laptop" | "worksWorkstation" | "enterpriseServer" | "phone" | "tablet" | "mobileOther" | "mobileUnknown"
export type DeviceType = "desktop" | "windowsRT" | "winMO6" | "nokia" | "windowsPhone" | "mac" | "winCE" | "winEmbedded" | "iPhone" | "iPad" | "iPod" | "android" | "iSocConsumer" | "unix" | "macMDM" | "holoLens" | "surfaceHub" | "androidForWork" | "windowsBlue" | "windowsPhoneBlue" | "blackberry" | "palm" | "fakeDevice" | "unknown"
export type ComplianceState = "unknown" | "compliant" | "noncompliant" | "conflict" | "error"
export type EnrollmentType = "unknown" | "userEnrollment" | "deviceEnrollment" | "deviceEnrollmentWithUDA" | "azureDomainJoined" | "userEnrollmentWithServiceAccount" | "depDeviceEnrollment" | "depDeviceEnrollmentWithUDA" | "autoEnrollment"
export type LostModeState = "disabled" | "enabled"
export type RemoteAction = "unknown" | "factoryReset" | "removeCompanyData" | "resetPasscode" | "remoteLock" | "enableLostMode" | "disableLostMode" | "locateDevice" | "rebootNow"
export type DeviceManagementExchangeConnectorStatus = "connectionPending" | "connected" | "disconnected" | "none"
export type DeviceManagementExchangeConnectorType = "onPremises" | "hosted" | "serviceToService" | "dedicated"
export type DeviceManagementExchangeAccessLevel = "none" | "allow" | "block" | "quarantine"
export type ExchangeAccessRuleType = "family" | "model"
export type ManagedAppDataTransferLevel = "allApps" | "managedApps" | "none"
export type ManagedAppClipboardSharingLevel = "allApps" | "managedAppsWithPasteIn" | "managedApps" | "blocked"
export type ManagedAppPinCharacterSet = "any" | "numeric" | "alphanumeric" | "alphanumericAndSymbol"
export type ManagedAppDataStorageLocation = "oneDriveForBusiness" | "sharePoint" | "box" | "dropbox" | "googleDrive" | "localStorage"
export type ManagedAppDataEncryptionType = "useDeviceSettings" | "afterDeviceRestart" | "whenDeviceLockedExceptOpenFiles" | "whenDeviceLocked"
export type ManagedAppFlaggedReason = "none" | "rootedDevice"

export interface Entity {
    id?: string
}

export interface DirectoryObject extends Entity {
}

export interface ExtensionProperty extends DirectoryObject {
    appDisplayName?: string
    name?: string
    dataType?: string
    isSyncedFromOnPremises?: boolean
    targetObjects?: [string]
}

export interface Application extends DirectoryObject {
    addIns?: [AddIn]
    appId?: string
    appRoles?: [AppRole]
    availableToOtherOrganizations?: boolean
    displayName?: string
    errorUrl?: string
    groupMembershipClaims?: string
    homepage?: string
    identifierUris?: [string]
    keyCredentials?: [KeyCredential]
    knownClientApplications?: [string]
    mainLogo?: any
    logoutUrl?: string
    oauth2AllowImplicitFlow?: boolean
    oauth2AllowUrlPathMatching?: boolean
    oauth2Permissions?: [OAuth2Permission]
    oauth2RequirePostResponse?: boolean
    passwordCredentials?: [PasswordCredential]
    publicClient?: boolean
    recordConsentConditions?: string
    replyUrls?: [string]
    requiredResourceAccess?: [RequiredResourceAccess]
    samlMetadataUrl?: string
    onPremisesPublishing?: OnPremisesPublishing
    extensionProperties?: [ExtensionProperty]
    createdOnBehalfOf?: DirectoryObject
    owners?: [DirectoryObject]
    policies?: [DirectoryObject]
    connectorGroup?: ConnectorGroup
}

export interface ConnectorGroup extends Entity {
    name?: string
    connectorGroupType?: ConnectorGroupType
    isDefault?: boolean
    members?: [Connector]
    applications?: [Application]
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
    businessPhones?: [string]
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
    officeLocation?: string
    postalCode?: string
    proxyAddresses?: [string]
    state?: string
    streetAddress?: string
    surname?: string
    manager?: DirectoryObject
    directReports?: [DirectoryObject]
    memberOf?: [DirectoryObject]
}

export interface Device extends DirectoryObject {
    accountEnabled?: boolean
    alternativeSecurityIds?: [AlternativeSecurityId]
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
    physicalIds?: [string]
    trustType?: string
    registeredOwners?: [DirectoryObject]
    registeredUsers?: [DirectoryObject]
}

export interface DirectoryRole extends DirectoryObject {
    description?: string
    displayName?: string
    roleTemplateId?: string
    members?: [DirectoryObject]
    scopedAdministrators?: [ScopedRoleMembership]
}

export interface ScopedRoleMembership extends Entity {
    roleId?: string
    administrativeUnitId?: string
    roleMemberInfo?: IdentityInfo
}

export interface DirectoryRoleTemplate extends DirectoryObject {
    description?: string
    displayName?: string
}

export interface DirectorySetting extends Entity {
    displayName?: string
    templateId?: string
    values?: [SettingValue]
}

export interface DirectorySettingTemplate extends DirectoryObject {
    displayName?: string
    description?: string
    values?: [SettingTemplateValue]
}

export interface Group extends DirectoryObject {
    classification?: string
    createdDateTime?: string
    description?: string
    displayName?: string
    groupTypes?: [string]
    mail?: string
    mailEnabled?: boolean
    mailNickname?: string
    membershipRule?: string
    membershipRuleProcessingState?: string
    onPremisesLastSyncDateTime?: string
    onPremisesSecurityIdentifier?: string
    onPremisesSyncEnabled?: boolean
    preferredLanguage?: string
    proxyAddresses?: [string]
    renewedDateTime?: string
    securityEnabled?: boolean
    theme?: string
    visibility?: string
    accessType?: GroupAccessType
    allowExternalSenders?: boolean
    autoSubscribeNewMembers?: boolean
    isFavorite?: boolean
    isSubscribedByMail?: boolean
    unseenCount?: number
    members?: [DirectoryObject]
    memberOf?: [DirectoryObject]
    createdOnBehalfOf?: DirectoryObject
    owners?: [DirectoryObject]
    settings?: [DirectorySetting]
    threads?: [ConversationThread]
    calendar?: Calendar
    calendarView?: [Event]
    events?: [Event]
    conversations?: [Conversation]
    photo?: ProfilePhoto
    photos?: [ProfilePhoto]
    acceptedSenders?: [DirectoryObject]
    rejectedSenders?: [DirectoryObject]
    drive?: Drive
    sharepoint?: SharePoint
    plans?: [Plan]
    notes?: Notes
}

export interface ConversationThread extends Entity {
    toRecipients?: [Recipient]
    topic?: string
    hasAttachments?: boolean
    lastDeliveredDateTime?: string
    uniqueSenders?: [string]
    ccRecipients?: [Recipient]
    preview?: string
    isLocked?: boolean
    posts?: [Post]
}

export interface Calendar extends Entity {
    name?: string
    color?: CalendarColor
    isDefaultCalendar?: boolean
    changeKey?: string
    canShare?: boolean
    canViewPrivateItems?: boolean
    isShared?: boolean
    isSharedWithMe?: boolean
    canEdit?: boolean
    owner?: EmailAddress
    events?: [Event]
    calendarView?: [Event]
    singleValueExtendedProperties?: [SingleValueLegacyExtendedProperty]
    multiValueExtendedProperties?: [MultiValueLegacyExtendedProperty]
}

export interface OutlookItem extends Entity {
    createdDateTime?: string
    lastModifiedDateTime?: string
    changeKey?: string
    categories?: [string]
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
    isAllDay?: boolean
    isCancelled?: boolean
    isOrganizer?: boolean
    recurrence?: PatternedRecurrence
    responseRequested?: boolean
    seriesMasterId?: string
    showAs?: FreeBusyStatus
    type?: EventType
    attendees?: [Attendee]
    organizer?: Recipient
    webLink?: string
    onlineMeetingUrl?: string
    calendar?: Calendar
    instances?: [Event]
    extensions?: [Extension]
    attachments?: [Attachment]
    singleValueExtendedProperties?: [SingleValueLegacyExtendedProperty]
    multiValueExtendedProperties?: [MultiValueLegacyExtendedProperty]
}

export interface Conversation extends Entity {
    topic?: string
    hasAttachments?: boolean
    lastDeliveredDateTime?: string
    uniqueSenders?: [string]
    preview?: string
    threads?: [ConversationThread]
}

export interface ProfilePhoto extends Entity {
    height?: number
    width?: number
}

export interface Drive extends Entity {
    driveType?: string
    owner?: IdentitySet
    quota?: Quota
    items?: [DriveItem]
    special?: [DriveItem]
    root?: DriveItem
}

export interface SharePoint extends Entity {
    site?: Site
    sites?: [Site]
}

export interface Plan extends Entity {
    createdBy?: string
    createdDateTime?: string
    owner?: string
    title?: string
    isVisibleInPlannerWebClient?: boolean
    tasks?: [Task]
    buckets?: [Bucket]
    details?: PlanDetails
    assignedToTaskBoard?: PlanTaskBoard
    progressTaskBoard?: PlanTaskBoard
    bucketTaskBoard?: PlanTaskBoard
}

export interface Notes extends Entity {
    notebooks?: [Notebook]
    sections?: [Section]
    sectionGroups?: [SectionGroup]
    pages?: [Page]
    resources?: [Resource]
    operations?: [NotesOperation]
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
    definition?: [string]
    displayName?: string
    isOrganizationDefault?: boolean
    keyCredentials?: [KeyCredential]
    type?: string
    appliesTo?: [DirectoryObject]
}

export interface ServicePrincipal extends DirectoryObject {
    accountEnabled?: boolean
    addIns?: [AddIn]
    appDisplayName?: string
    appId?: string
    appOwnerOrganizationId?: string
    appRoleAssignmentRequired?: boolean
    appRoles?: [AppRole]
    displayName?: string
    errorUrl?: string
    homepage?: string
    keyCredentials?: [KeyCredential]
    logoutUrl?: string
    oauth2Permissions?: [OAuth2Permission]
    passwordCredentials?: [PasswordCredential]
    preferredTokenSigningKeyThumbprint?: string
    publisherName?: string
    replyUrls?: [string]
    samlMetadataUrl?: string
    servicePrincipalNames?: [string]
    tags?: [string]
    appRoleAssignedTo?: [AppRoleAssignment]
    appRoleAssignments?: [AppRoleAssignment]
    oauth2PermissionGrants?: [OAuth2PermissionGrant]
    memberOf?: [DirectoryObject]
    createdObjects?: [DirectoryObject]
    owners?: [DirectoryObject]
    ownedObjects?: [DirectoryObject]
    policies?: [DirectoryObject]
}

export interface SubscribedSku extends Entity {
    capabilityStatus?: string
    consumedUnits?: number
    prepaidUnits?: LicenseUnitsDetail
    servicePlans?: [ServicePlanInfo]
    skuId?: string
    skuPartNumber?: string
    appliesTo?: string
}

export interface Organization extends DirectoryObject {
    assignedPlans?: [AssignedPlan]
    businessPhones?: [string]
    city?: string
    country?: string
    countryLetterCode?: string
    displayName?: string
    marketingNotificationEmails?: [string]
    onPremisesLastSyncDateTime?: string
    onPremisesSyncEnabled?: boolean
    postalCode?: string
    preferredLanguage?: string
    provisionedPlans?: [ProvisionedPlan]
    securityComplianceNotificationMails?: [string]
    securityComplianceNotificationPhones?: [string]
    state?: string
    street?: string
    technicalNotificationMails?: [string]
    verifiedDomains?: [VerifiedDomain]
    applePushNotificationCertificateSetting?: ApplePushNotificationCertificateSetting
    mobileDeviceManagementAuthority?: MdmAuthority
    defaultDeviceEnrollmentRestrictions?: DefaultDeviceEnrollmentRestrictions
    defaultDeviceEnrollmentWindowsHelloForBusinessSettings?: DefaultDeviceEnrollmentWindowsHelloForBusinessSettings
    defaultDeviceEnrollmentLimit?: number
    intuneBrand?: IntuneBrand
    certificateConnectorSetting?: CertificateConnectorSetting
    depOnboardingSettings?: [DepOnboardingSetting]
    appleVolumePurchaseProgramTokens?: [AppleVolumePurchaseProgramToken]
    sideLoadingKeys?: [SideLoadingKey]
}

export interface DepOnboardingSetting extends Entity {
    appleIdentifier?: string
    tokenExpirationDateTime?: string
    lastModifiedDateTime?: string
    lastSuccessfulSyncDateTime?: string
    lastSyncTriggeredDateTime?: string
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
}

export interface SideLoadingKey extends Entity {
    value?: string
    displayName?: string
    description?: string
    totalActivation?: number
    lastUpdatedDateTime?: string
}

export interface User extends DirectoryObject {
    accountEnabled?: boolean
    assignedLicenses?: [AssignedLicense]
    assignedPlans?: [AssignedPlan]
    businessPhones?: [string]
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
    onPremisesImmutableId?: string
    onPremisesLastSyncDateTime?: string
    onPremisesSecurityIdentifier?: string
    onPremisesSyncEnabled?: boolean
    passwordPolicies?: string
    passwordProfile?: PasswordProfile
    officeLocation?: string
    postalCode?: string
    preferredLanguage?: string
    provisionedPlans?: [ProvisionedPlan]
    proxyAddresses?: [string]
    refreshTokensValidFromDateTime?: string
    showInAddressList?: boolean
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
    interests?: [string]
    mySite?: string
    pastProjects?: [string]
    preferredName?: string
    responsibilities?: [string]
    schools?: [string]
    skills?: [string]
    deviceEnrollmentLimit?: number
    ownedDevices?: [DirectoryObject]
    registeredDevices?: [DirectoryObject]
    manager?: DirectoryObject
    directReports?: [DirectoryObject]
    memberOf?: [DirectoryObject]
    createdObjects?: [DirectoryObject]
    ownedObjects?: [DirectoryObject]
    scopedAdministratorOf?: [ScopedRoleMembership]
    messages?: [Message]
    joinedGroups?: [Group]
    mailFolders?: [MailFolder]
    calendar?: Calendar
    calendars?: [Calendar]
    calendarGroups?: [CalendarGroup]
    calendarView?: [Event]
    events?: [Event]
    people?: [Person]
    contacts?: [Contact]
    contactFolders?: [ContactFolder]
    inferenceClassification?: InferenceClassification
    photo?: ProfilePhoto
    photos?: [ProfilePhoto]
    drive?: Drive
    drives?: [Drive]
    sharepoint?: SharePoint
    insights?: OfficeGraphInsights
    trendingAround?: [DriveItem]
    workingWith?: [User]
    tasks?: [Task]
    plans?: [Plan]
    notes?: Notes
    managedDevices?: [ManagedDevice]
    managedAppRegistrations?: [ManagedAppRegistration]
}

export interface Message extends OutlookItem {
    receivedDateTime?: string
    sentDateTime?: string
    hasAttachments?: boolean
    internetMessageId?: string
    subject?: string
    body?: ItemBody
    bodyPreview?: string
    importance?: Importance
    parentFolderId?: string
    sender?: Recipient
    from?: Recipient
    toRecipients?: [Recipient]
    ccRecipients?: [Recipient]
    bccRecipients?: [Recipient]
    replyTo?: [Recipient]
    conversationId?: string
    conversationIndex?: number
    uniqueBody?: ItemBody
    isDeliveryReceiptRequested?: boolean
    isReadReceiptRequested?: boolean
    isRead?: boolean
    isDraft?: boolean
    webLink?: string
    mentionsPreview?: MentionsPreview
    inferenceClassification?: InferenceClassificationType
    unsubscribeData?: [string]
    unsubscribeEnabled?: boolean
    flag?: FollowupFlag
    attachments?: [Attachment]
    extensions?: [Extension]
    singleValueExtendedProperties?: [SingleValueLegacyExtendedProperty]
    multiValueExtendedProperties?: [MultiValueLegacyExtendedProperty]
    mentions?: [Mention]
}

export interface MailFolder extends Entity {
    displayName?: string
    parentFolderId?: string
    childFolderCount?: number
    unreadItemCount?: number
    totalItemCount?: number
    wellKnownName?: string
    messages?: [Message]
    childFolders?: [MailFolder]
    userConfigurations?: [UserConfiguration]
    singleValueExtendedProperties?: [SingleValueLegacyExtendedProperty]
    multiValueExtendedProperties?: [MultiValueLegacyExtendedProperty]
}

export interface CalendarGroup extends Entity {
    name?: string
    classId?: string
    changeKey?: string
    calendars?: [Calendar]
}

export interface Person extends Entity {
    displayName?: string
    givenName?: string
    surname?: string
    birthday?: string
    personNotes?: string
    isFavorite?: boolean
    emailAddresses?: [RankedEmailAddress]
    phones?: [Phone]
    postalAddresses?: [Location]
    websites?: [Website]
    title?: string
    companyName?: string
    yomiCompany?: string
    department?: string
    officeLocation?: string
    profession?: string
    sources?: [PersonDataSource]
    mailboxType?: string
    personType?: string
    userPrincipalName?: string
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
    emailAddresses?: [EmailAddress]
    websites?: [Website]
    imAddresses?: [string]
    jobTitle?: string
    companyName?: string
    department?: string
    officeLocation?: string
    profession?: string
    assistantName?: string
    manager?: string
    phones?: [Phone]
    postalAddresses?: [PhysicalAddress]
    spouseName?: string
    personalNotes?: string
    children?: [string]
    weddingAnniversary?: string
    gender?: string
    isFavorite?: boolean
    flag?: FollowupFlag
    extensions?: [Extension]
    singleValueExtendedProperties?: [SingleValueLegacyExtendedProperty]
    multiValueExtendedProperties?: [MultiValueLegacyExtendedProperty]
    photo?: ProfilePhoto
}

export interface ContactFolder extends Entity {
    parentFolderId?: string
    displayName?: string
    wellKnownName?: string
    contacts?: [Contact]
    childFolders?: [ContactFolder]
    singleValueExtendedProperties?: [SingleValueLegacyExtendedProperty]
    multiValueExtendedProperties?: [MultiValueLegacyExtendedProperty]
}

export interface InferenceClassification extends Entity {
    overrides?: [InferenceClassificationOverride]
}

export interface OfficeGraphInsights extends Entity {
    trending?: [Trending]
}

export interface DriveItem extends Entity {
    createdBy?: IdentitySet
    createdDateTime?: string
    description?: string
    eTag?: string
    lastModifiedBy?: IdentitySet
    lastModifiedDateTime?: string
    name?: string
    webUrl?: string
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
    parentReference?: ItemReference
    photo?: Photo
    remoteItem?: RemoteItem
    root?: Root
    searchResult?: SearchResult
    shared?: Shared
    sharepointIds?: SharepointIds
    size?: number
    specialFolder?: SpecialFolder
    video?: Video
    webDavUrl?: string
    workbook?: Workbook
    createdByUser?: User
    lastModifiedByUser?: User
    children?: [DriveItem]
    permissions?: [Permission]
    thumbnails?: [ThumbnailSet]
}

export interface Task extends Entity {
    createdBy?: string
    assignedTo?: string
    planId?: string
    bucketId?: string
    title?: string
    orderHint?: string
    assigneePriority?: string
    percentComplete?: number
    startDateTime?: string
    assignedDateTime?: string
    createdDateTime?: string
    assignedBy?: string
    dueDateTime?: string
    hasDescription?: boolean
    previewType?: PreviewType
    completedDateTime?: string
    appliedCategories?: AppliedCategoriesCollection
    conversationThreadId?: string
    details?: TaskDetails
    assignedToTaskBoardFormat?: TaskBoardTaskFormat
    progressTaskBoardFormat?: TaskBoardTaskFormat
    bucketTaskBoardFormat?: TaskBoardTaskFormat
}

export interface ManagedDevice extends Entity {
    userId?: string
    deviceName?: string
    hardwareInformation?: HardwareInformation
    ownerType?: OwnerType
    deviceActionResults?: [DeviceActionResult]
    managementState?: ManagementState
    enrolledDateTime?: string
    lastSyncDateTime?: string
    chassisType?: ChassisType
    operatingSystem?: string
    deviceType?: DeviceType
    complianceState?: ComplianceState
    jailBroken?: string
    managementAgents?: number
    osVersion?: string
    easActivated?: boolean
    easDeviceId?: string
    easActivationDateTime?: string
    aadRegistered?: boolean
    enrollmentType?: EnrollmentType
    lostModeState?: LostModeState
    activationLockBypassCode?: string
    emailAddress?: string
    detectedApps?: [DetectedApp]
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
    flaggedReasons?: [ManagedAppFlaggedReason]
    userId?: string
    appIdentifier?: MobileAppIdentifier
    version?: string
    appliedPolicies?: [ManagedAppPolicy]
    intendedPolicies?: [ManagedAppPolicy]
    operations?: [ManagedAppOperation]
}

export interface AdministrativeUnit extends DirectoryObject {
    displayName?: string
    description?: string
    visibility?: string
    members?: [DirectoryObject]
    scopedAdministrators?: [ScopedRoleMembership]
}

export interface BaseItem extends Entity {
    createdBy?: IdentitySet
    createdDateTime?: string
    description?: string
    eTag?: string
    lastModifiedBy?: IdentitySet
    lastModifiedDateTime?: string
    name?: string
    webUrl?: string
    createdByUser?: User
    lastModifiedByUser?: User
}

export interface Site extends BaseItem {
    root?: Root
    siteCollection?: SiteCollection
    siteCollectionId?: string
    siteId?: string
    drive?: Drive
    drives?: [Drive]
    items?: [BaseItem]
    lists?: [List]
    sites?: [Site]
}

export interface List extends BaseItem {
    fields?: [FieldDefinition]
    list?: ListInfo
    drive?: Drive
    items?: [ListItem]
}

export interface ListItem extends BaseItem {
    listItemId?: number
    columnSet?: FieldValueSet
    driveItem?: DriveItem
}

export interface Workbook extends Entity {
    application?: WorkbookApplication
    names?: [WorkbookNamedItem]
    tables?: [WorkbookTable]
    worksheets?: [WorkbookWorksheet]
    functions?: WorkbookFunctions
}

export interface Permission extends Entity {
    grantedTo?: IdentitySet
    invitation?: SharingInvitation
    inheritedFrom?: ItemReference
    link?: SharingLink
    roles?: [string]
    shareId?: string
}

export interface ThumbnailSet extends Entity {
    large?: Thumbnail
    medium?: Thumbnail
    small?: Thumbnail
    source?: Thumbnail
}

export interface WorkbookApplication extends Entity {
    calculationMode?: string
}

export interface WorkbookNamedItem extends Entity {
    name?: string
    type?: string
    value?: any
    visible?: boolean
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
    columns?: [WorkbookTableColumn]
    rows?: [WorkbookTableRow]
    sort?: WorkbookTableSort
    worksheet?: WorkbookWorksheet
}

export interface WorkbookWorksheet extends Entity {
    name?: string
    position?: number
    visibility?: string
    charts?: [WorkbookChart]
    pivotTables?: [WorkbookPivotTable]
    protection?: WorkbookWorksheetProtection
    tables?: [WorkbookTable]
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
    series?: [WorkbookChartSeries]
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
    points?: [WorkbookChartPoint]
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
    borders?: [WorkbookRangeBorder]
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
    rows?: [WorkbookRangeView]
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
    fields?: [WorkbookSortField]
    matchCase?: boolean
    method?: string
}

export interface WorkbookWorksheetProtection extends Entity {
    options?: WorkbookWorksheetProtectionOptions
    protected?: boolean
}

export interface Attachment extends Entity {
    lastModifiedDateTime?: string
    name?: string
    contentType?: string
    size?: number
    isInline?: boolean
}

export interface UserConfiguration extends Entity {
    binaryData?: number
}

export interface SingleValueLegacyExtendedProperty extends Entity {
    value?: string
}

export interface MultiValueLegacyExtendedProperty extends Entity {
    value?: [string]
}

export interface Extension extends Entity {
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
    contentId?: string
    contentLocation?: string
    contentBytes?: number
}

export interface ItemAttachment extends Attachment {
    item?: OutlookItem
}

export interface EventMessage extends Message {
    meetingMessageType?: MeetingMessageType
    startDateTime?: DateTimeTimeZone
    endDateTime?: DateTimeTimeZone
    location?: Location
    type?: EventType
    recurrence?: PatternedRecurrence
    isOutOfDate?: boolean
    isAllDay?: boolean
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
    body?: ItemBody
    receivedDateTime?: string
    hasAttachments?: boolean
    from?: Recipient
    sender?: Recipient
    conversationThreadId?: string
    newParticipants?: [Recipient]
    conversationId?: string
    extensions?: [Extension]
    inReplyTo?: Post
    attachments?: [Attachment]
    singleValueExtendedProperties?: [SingleValueLegacyExtendedProperty]
    multiValueExtendedProperties?: [MultiValueLegacyExtendedProperty]
    mentions?: [Mention]
}

export interface InferenceClassificationOverride extends Entity {
    classifyAs?: InferenceClassificationType
    senderEmailAddress?: EmailAddress
}

export interface SharedDriveItem extends Entity {
    name?: string
    owner?: IdentitySet
    root?: DriveItem
    items?: [DriveItem]
}

export interface FieldValueSet extends Entity {
}

export interface Trending extends Entity {
    weight?: number
    resourceVisualization?: ResourceVisualization
    resourceReference?: ResourceReference
    lastModifiedDateTime?: string
    resource?: Entity
}

export interface TaskDetails extends Entity {
    description?: string
    previewType?: PreviewType
    completedBy?: string
    references?: ExternalReferenceCollection
    checklist?: ChecklistItemCollection
}

export interface TaskBoardTaskFormat extends Entity {
    type?: TaskBoardType
    orderHint?: string
}

export interface Bucket extends Entity {
    name?: string
    planId?: string
    orderHint?: string
    tasks?: [Task]
}

export interface PlanDetails extends Entity {
    sharedWith?: UserIdCollection
    category0Description?: string
    category1Description?: string
    category2Description?: string
    category3Description?: string
    category4Description?: string
    category5Description?: string
}

export interface PlanTaskBoard extends Entity {
    type?: TaskBoardType
}

export interface Notebook extends Entity {
    isDefault?: boolean
    userRole?: UserRole
    isShared?: boolean
    sectionsUrl?: string
    sectionGroupsUrl?: string
    links?: NotebookLinks
    name?: string
    createdBy?: string
    createdByIdentity?: OneNoteIdentitySet
    lastModifiedBy?: string
    lastModifiedByIdentity?: OneNoteIdentitySet
    lastModifiedTime?: string
    self?: string
    createdTime?: string
    sections?: [Section]
    sectionGroups?: [SectionGroup]
}

export interface Section extends Entity {
    isDefault?: boolean
    pagesUrl?: string
    name?: string
    createdBy?: string
    createdByIdentity?: OneNoteIdentitySet
    lastModifiedBy?: string
    lastModifiedByIdentity?: OneNoteIdentitySet
    lastModifiedTime?: string
    self?: string
    createdTime?: string
    parentNotebook?: Notebook
    parentSectionGroup?: SectionGroup
    pages?: [Page]
}

export interface SectionGroup extends Entity {
    sectionsUrl?: string
    sectionGroupsUrl?: string
    name?: string
    createdBy?: string
    createdByIdentity?: OneNoteIdentitySet
    lastModifiedBy?: string
    lastModifiedByIdentity?: OneNoteIdentitySet
    lastModifiedTime?: string
    self?: string
    createdTime?: string
    parentNotebook?: Notebook
    parentSectionGroup?: SectionGroup
    sections?: [Section]
    sectionGroups?: [SectionGroup]
}

export interface Page extends Entity {
    title?: string
    createdByAppId?: string
    links?: PageLinks
    contentUrl?: string
    content?: any
    lastModifiedTime?: string
    level?: number
    order?: number
    self?: string
    createdTime?: string
    parentSection?: Section
    parentNotebook?: Notebook
}

export interface Resource extends Entity {
    self?: string
    content?: any
    contentUrl?: string
}

export interface NotesOperation extends Entity {
    status?: string
    createdDateTime?: string
    lastActionDateTime?: string
    resourceLocation?: string
    resourceId?: string
    error?: NotesOperationError
}

export interface Subscription extends Entity {
    resource?: string
    changeType?: string
    clientState?: string
    notificationUrl?: string
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
    assignments?: [PrivilegedRoleAssignment]
    summary?: PrivilegedRoleSummary
}

export interface PrivilegedRoleSettings extends Entity {
    minElevationDuration?: number
    maxElavationDuration?: number
    elevationDuration?: number
    notificationToUserOnElevation?: boolean
    ticketingInfoOnElevation?: boolean
    mfaOnElevation?: boolean
    lastGlobalAdmin?: boolean
    isMfaOnElevationConfigurable?: boolean
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

export interface TenantSetupInfo extends Entity {
    userRolesActions?: string
    firstTimeSetup?: boolean
    relevantRolesSettings?: [string]
    skipSetup?: boolean
    setupStatus?: SetupStatus
    defaultRolesSettings?: PrivilegedRoleSettings
}

export interface Connector extends Entity {
    machineName?: string
    externalIp?: string
    status?: ConnectorStatus
    memberOf?: [ConnectorGroup]
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

export interface DeviceAppManagement extends Entity {
    windowsStoreForBusinessLastSuccessfulSyncDateTime?: string
    isEnabledForWindowsStoreForBusiness?: boolean
    windowsStoreForBusinessLanguage?: string
    windowsStoreForBusinessLastCompletedApplicationSyncTime?: string
    mobileApps?: [MobileApp]
    mobileAppCategories?: [MobileAppCategory]
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
    uploadState?: number
    installSummary?: MobileAppInstallSummary
    categories?: [MobileAppCategory]
    groupAssignments?: [MobileAppGroupAssignment]
    deviceStatuses?: [MobileAppInstallStatus]
    userStatuses?: [UserAppInstallStatus]
}

export interface MobileAppCategory extends Entity {
    displayName?: string
}

export interface ManagedDeviceMobileAppConfiguration extends Entity {
    settingXml?: string
    settings?: [AppConfigurationSettingItem]
    targetedMobileApps?: [string]
    createdDateTime?: string
    description?: string
    lastModifiedDateTime?: string
    displayName?: string
    version?: number
    groupAssignments?: [MdmAppConfigGroupAssignment]
    deviceStatuses?: [ManagedDeviceMobileAppConfigurationDeviceStatus]
    userStatuses?: [ManagedDeviceMobileAppConfigurationUserStatus]
}

export interface MdmAppConfigGroupAssignment extends Entity {
    appConfiguration?: string
    targetGroupId?: string
}

export interface ManagedDeviceMobileAppConfigurationDeviceStatus extends Entity {
    status?: AppConfigComplianceStatus
    lastReportedDateTime?: string
}

export interface ManagedDeviceMobileAppConfigurationUserStatus extends Entity {
    status?: AppConfigComplianceStatus
    lastReportedDateTime?: string
}

export interface MobileAppGroupAssignment extends Entity {
    targetGroupId?: string
    installIntent?: AppInstallIntent
    app?: MobileApp
}

export interface MobileAppInstallStatus extends Entity {
    deviceName?: string
    deviceId?: string
    lastSyncDateTime?: string
    mobileAppInstallStatusValue?: number
    errorCode?: number
    deviceType?: number
    osVersion?: string
    app?: MobileApp
}

export interface UserAppInstallStatus extends Entity {
    userName?: string
    installedDeviceCount?: number
    failedDeviceCount?: number
    notInstalledDeviceCount?: number
    app?: MobileApp
    deviceStatuses?: [MobileAppInstallStatus]
}

export interface MobileAppContentFile extends Entity {
    azureStorageUri?: string
    isCommitted?: boolean
    createdDateTime?: string
    name?: string
    size?: number
    sizeEncrypted?: number
    azureStorageUriExpirationDateTime?: string
}

export interface MobileAppVppGroupAssignment extends MobileAppGroupAssignment {
    useDeviceLicensing?: boolean
}

export interface ManagedApp extends MobileApp {
    appAvailability?: ManagedAppAvailability
    version?: string
}

export interface ManagedAndroidStoreApp extends ManagedApp {
    packageId?: string
}

export interface ManagedIOSStoreApp extends ManagedApp {
    bundleId?: string
}

export interface MobileLobApp extends MobileApp {
    committedContentVersion?: string
    fileName?: string
    size?: number
    identityVersion?: string
    contentVersions?: [MobileAppContent]
}

export interface MobileAppContent extends Entity {
    files?: [MobileAppContentFile]
}

export interface AndroidLobApp extends MobileLobApp {
    identityName?: string
    minimumSupportedOperatingSystem?: AndroidMinimumOperatingSystem
    manifest?: number
}

export interface IosLobApp extends MobileLobApp {
    bundleId?: string
    applicableDeviceType?: IosDeviceType
    minimumSupportedOperatingSystem?: IosMinimumOperatingSystem
    expirationDateTime?: string
    manifest?: number
}

export interface WebApp extends MobileApp {
    appUrl?: string
    useManagedBrowser?: boolean
}

export interface WindowsPhone81StoreApp extends MobileApp {
    appStoreUrl?: string
}

export interface WindowsStoreApp extends MobileApp {
    appStoreUrl?: string
}

export interface AndroidStoreApp extends MobileApp {
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
    vppToken?: AppleVolumePurchaseProgramToken
}

export interface IosStoreApp extends MobileApp {
    bundleId?: string
    appStoreUrl?: string
    applicableDeviceType?: IosDeviceType
    minimumSupportedOperatingSystem?: IosMinimumOperatingSystem
}

export interface WindowsStoreForBusinessApp extends MobileApp {
    usedLicenseCount?: number
    totalLicenseCount?: number
}

export interface IosMobileAppConfiguration extends ManagedDeviceMobileAppConfiguration {
}

export interface TermsAndConditions extends Entity {
    createdDateTime?: string
    modifiedDateTime?: string
    displayName?: string
    description?: string
    title?: string
    bodyText?: string
    acceptanceStatement?: string
    version?: number
    groupAssignments?: [TermsAndConditionsGroupAssignment]
    acceptanceStatuses?: [TermsAndConditionsAcceptanceStatus]
}

export interface TermsAndConditionsGroupAssignment extends Entity {
    targetGroupId?: string
    termsAndConditions?: TermsAndConditions
}

export interface TermsAndConditionsAcceptanceStatus extends Entity {
    userDisplayName?: string
    acceptedVersion?: number
    acceptedDateTime?: string
    termsAndConditions?: TermsAndConditions
}

export interface DeviceManagement extends Entity {
    settings?: DeviceManagementSettings
    enrollmentProfiles?: [EnrollmentProfile]
    importedDeviceIdentities?: [ImportedDeviceIdentity]
    importedAppleDeviceIdentities?: [ImportedAppleDeviceIdentity]
    deviceConfigurations?: [DeviceConfiguration]
    deviceCompliancePolicies?: [DeviceCompliancePolicy]
    remoteActionAudits?: [RemoteActionAudit]
    deviceCategories?: [DeviceCategory]
    exchangeConnectors?: [DeviceManagementExchangeConnector]
    exchangeOnPremisesPolicy?: DeviceManagementExchangeOnPremisesPolicy
    roleDefinitions?: [RoleDefinition]
    roleAssignments?: [RoleAssignment]
    resourceOperations?: [ResourceOperation]
    telecomExpenseManagementPartners?: [TelecomExpenseManagementPartner]
}

export interface EnrollmentProfile extends Entity {
    displayName?: string
    description?: string
    requiresUserAuthentication?: boolean
    configurationEndpointUrl?: string
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

export interface DeviceConfiguration extends Entity {
    lastModifiedDateTime?: string
    createdDateTime?: string
    description?: string
    displayName?: string
    version?: number
    groupAssignments?: [DeviceConfigurationGroupAssignment]
    deviceStatuses?: [DeviceConfigurationDeviceStatus]
    userStatuses?: [DeviceConfigurationUserStatus]
}

export interface DeviceCompliancePolicy extends Entity {
    createdDateTime?: string
    description?: string
    lastModifiedDateTime?: string
    displayName?: string
    version?: number
    groupAssignments?: [DeviceCompliancePolicyGroupAssignment]
    scheduledActionsForRule?: [DeviceComplianceScheduledActionForRule]
    deviceStatuses?: [DeviceComplianceDeviceStatus]
    userStatuses?: [DeviceComplianceUserStatus]
}

export interface RemoteActionAudit extends Entity {
    deviceDisplayName?: string
    userName?: string
    action?: RemoteAction
    requestDateTime?: string
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
    exchangeConnectorType?: DeviceManagementExchangeConnectorType
}

export interface DeviceManagementExchangeOnPremisesPolicy extends Entity {
    notificationContent?: number
    defaultAccessLevel?: DeviceManagementExchangeAccessLevel
    accessRules?: [DeviceManagementExchangeAccessRule]
    knownDeviceClasses?: [DeviceManagementExchangeDeviceClass]
    conditionalAccessSettings?: OnPremisesConditionalAccessSettings
}

export interface RoleDefinition extends Entity {
    displayName?: string
    description?: string
    permissions?: [RolePermission]
    isBuiltInRoleDefinition?: boolean
    roleAssignments?: [RoleAssignment]
}

export interface RoleAssignment extends Entity {
    displayName?: string
    description?: string
    members?: [string]
    scopeMembers?: [string]
    roleDefinition?: RoleDefinition
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
    managementCertificates?: [ManagementCertificateWithThumbprint]
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
}

export interface CloudPkiSubscription extends Entity {
    cloudPkiProvider?: CloudPkiProvider
    createdDateTime?: string
    description?: string
    lastModifiedDateTime?: string
    displayName?: string
    syncStatus?: SyncStatus
    lastSyncError?: string
    lastSyncDateTime?: string
    credentials?: CloudPkiAdministratorCredentials
    trustedRootCertificate?: number
    version?: number
}

export interface DeviceConfigurationAssignment extends Entity {
    deviceConfiguration?: DeviceConfiguration
}

export interface DeviceConfigurationGroupAssignment extends DeviceConfigurationAssignment {
    targetGroupId?: string
}

export interface DeviceConfigurationDeviceStatus extends Entity {
    status?: ComplianceStatus
    lastReportedDateTime?: string
}

export interface DeviceConfigurationUserStatus extends Entity {
    status?: ComplianceStatus
    lastReportedDateTime?: string
}

export interface DeviceCompliancePolicyAssignment extends Entity {
    deviceCompliancePolicy?: DeviceCompliancePolicy
}

export interface DeviceCompliancePolicyGroupAssignment extends DeviceCompliancePolicyAssignment {
    targetGroupId?: string
}

export interface DeviceComplianceScheduledActionForRule extends Entity {
    scheduledActionConfigurations?: [DeviceComplianceActionItem]
}

export interface DeviceComplianceDeviceStatus extends Entity {
    status?: ComplianceStatus
    lastReportedDateTime?: string
}

export interface DeviceComplianceUserStatus extends Entity {
    status?: ComplianceStatus
    lastReportedDateTime?: string
}

export interface AndroidCertificateProfileBase extends DeviceConfiguration {
    renewalThresholdPercentage?: number
    subjectNameFormat?: SubjectNameFormat
    subjectAlternativeNameType?: SubjectAlternativeNameType
    certificateValidityPeriodValue?: number
    certificateValidityPeriodScale?: CertificateValidityPeriodScale
    extendedKeyUsages?: [ExtendedKeyUsage]
    rootCertificate?: AndroidTrustedRootCertificate
}

export interface AndroidTrustedRootCertificate extends DeviceConfiguration {
    trustedRootCertificate?: number
    certFileName?: string
}

export interface AndroidPkcsCertificateProfile extends AndroidCertificateProfileBase {
    certificationAuthority?: string
    certificationAuthorityName?: string
    certificateTemplateName?: string
}

export interface AndroidScepCertificateProfile extends AndroidCertificateProfileBase {
    scepServerUrls?: [string]
    keyUsage?: KeyUsages
    keySize?: KeySize
    hashAlgorithm?: HashAlgorithms
}

export interface AndroidCustomConfiguration extends DeviceConfiguration {
    omaSettings?: [OmaSetting]
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
    omaSettings?: [OmaSetting]
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
    workProfileDefaultAppPermissionPolicy?: AndroidForWorkDefaultAppPermissionPolicyType
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
    compliantAppsList?: [AppListItem]
    compliantAppListType?: AppListType
    diagnosticDataBlockSubmission?: boolean
    locationServicesBlocked?: boolean
    googleAccountBlockAutoSync?: boolean
    googlePlayStoreBlocked?: boolean
    kioskModeBlockSleepButton?: boolean
    kioskModeBlockVolumeButtons?: boolean
    kioskModeManagedAppId?: string
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
    deviceSharingBlocked?: boolean
    storageBlockGoogleBackup?: boolean
    storageBlockRemovableStorage?: boolean
    storageRequireDeviceEncryption?: boolean
    storageRequireRemovableStorageEncryption?: boolean
    voiceAssistantBlocked?: boolean
    voiceDialingBlocked?: boolean
    webBrowserAllowPopups?: boolean
    webBrowserBlockAutofill?: boolean
    webBrowserBlockJavaScript?: boolean
    webBrowserBlocked?: boolean
    webBrowserCookieSettings?: WebBrowserCookieSettings
    wiFiBlocked?: boolean
}

export interface AndroidVpnConfiguration extends DeviceConfiguration {
    connectionName?: string
    connectionType?: AndroidVpnConnectionType
    role?: string
    realm?: string
    servers?: [VpnServer]
    fingerprint?: string
    customData?: [KeyValue]
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
    nonEapAuthenticationMethodForEapTtls?: NonEapAuthenticationMethodForEapTtlsType
    nonEapAuthenticationMethodForPeap?: NonEapAuthenticationMethodForPeap
    enableOuterIdentityPrivacy?: string
    rootCertificateForServerValidation?: AndroidTrustedRootCertificate
    identityCertificateForClientAuthentication?: AndroidCertificateProfileBase
}

export interface IosCertificateProfileBase extends DeviceConfiguration {
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
}

export interface IosScepCertificateProfile extends IosCertificateProfileBase {
    scepServerUrls?: [string]
    subjectNameFormatString?: string
    keyUsage?: KeyUsages
    keySize?: KeySize
    extendedKeyUsages?: [ExtendedKeyUsage]
    rootCertificate?: IosTrustedRootCertificate
}

export interface IosTrustedRootCertificate extends DeviceConfiguration {
    trustedRootCertificate?: number
    certFileName?: string
}

export interface IosCustomConfiguration extends DeviceConfiguration {
    payloadName?: string
    payloadFileName?: string
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
    requireSsl?: boolean
    usernameSource?: UserEmailSource
    identityCertificate?: IosCertificateProfileBase
    smimeSigningCertificate?: IosCertificateProfileBase
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
    appsVisibilityList?: [AppListItem]
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
    cellularBlockVoiceRoaming?: boolean
    certificatesBlockUntrustedTlsCertificates?: boolean
    classroomAppBlockRemoteScreenObservation?: boolean
    compliantAppsList?: [AppListItem]
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
    emailInDomainSuffixes?: [string]
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
    mediaContentRatingApps?: RatingAppsType
    messagesBlocked?: boolean
    notificationsBlockSettingsModification?: boolean
    passcodeBlockFingerprintUnlock?: boolean
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
    safariManagedDomains?: [string]
    safariPasswordAutoFillDomains?: [string]
    safariRequireFraudWarning?: boolean
    screenCaptureBlocked?: boolean
    siriBlocked?: boolean
    siriBlockedWhenLocked?: boolean
    siriBlockUserGeneratedContent?: boolean
    siriRequireProfanityFilter?: boolean
    spotlightBlockInternetResults?: boolean
    voiceDialingBlocked?: boolean
    wallpaperBlockModification?: boolean
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
}

export interface IosEnterpriseWiFiConfiguration extends IosWiFiConfiguration {
    eapType?: EapType
    eapFastConfiguration?: EapFastConfiguration
    trustedServerCertificateNames?: [string]
    authenticationMethod?: WiFiAuthenticationMethod
    nonEapAuthenticationMethodForEapTtls?: NonEapAuthenticationMethodForEapTtlsType
    enableOuterIdentityPrivacy?: string
    rootCertificatesForServerValidation?: [IosTrustedRootCertificate]
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
    scepServerUrls?: [string]
    subjectNameFormatString?: string
    keyUsage?: KeyUsages
    keySize?: KeySize
    hashAlgorithm?: HashAlgorithms
    extendedKeyUsages?: [ExtendedKeyUsage]
    rootCertificate?: MacOSTrustedRootCertificate
}

export interface MacOSTrustedRootCertificate extends DeviceConfiguration {
    trustedRootCertificate?: number
    certFileName?: string
}

export interface MacOSCustomConfiguration extends DeviceConfiguration {
    payloadName?: string
    payloadFileName?: string
    payload?: number
}

export interface MacOSGeneralDeviceConfiguration extends DeviceConfiguration {
    compliantAppsList?: [AppListItem]
    compliantAppListType?: AppListType
    emailInDomainSuffixes?: [string]
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
}

export interface MacOSEnterpriseWiFiConfiguration extends MacOSWiFiConfiguration {
    eapType?: EapType
    eapFastConfiguration?: EapFastConfiguration
    trustedServerCertificateNames?: [string]
    authenticationMethod?: WiFiAuthenticationMethod
    nonEapAuthenticationMethodForEapTtls?: NonEapAuthenticationMethodForEapTtlsType
    enableOuterIdentityPrivacy?: string
    rootCertificateForServerValidation?: MacOSTrustedRootCertificate
    identityCertificateForClientAuthentication?: MacOSCertificateProfileBase
}

export interface AppleVpnConfiguration extends DeviceConfiguration {
    connectionName?: string
    connectionType?: AppleVpnConnectionType
    loginGroupOrDomain?: string
    role?: string
    realm?: string
    server?: VpnServer
    identifier?: string
    customData?: [KeyValue]
    enableSplitTunneling?: boolean
    authenticationMethod?: VpnAuthenticationMethod
    enablePerApp?: boolean
    safariDomains?: [string]
    onDemandRules?: [VpnOnDemandRule]
    proxyServer?: VpnProxyServer
}

export interface IosVpnConfiguration extends AppleVpnConfiguration {
    identityCertificate?: IosCertificateProfileBase
}

export interface MacOSVpnConfiguration extends AppleVpnConfiguration {
    identityCertificate?: MacOSCertificateProfileBase
}

export interface Windows10CustomConfiguration extends DeviceConfiguration {
    omaSettings?: [OmaSetting]
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

export interface Windows81WifiImportConfiguration extends DeviceConfiguration {
    payloadFileName?: string
    profileName?: string
    payload?: number
}

export interface Windows81TrustedRootCertificate extends DeviceConfiguration {
    trustedRootCertificate?: number
    certFileName?: string
    destinationStore?: CertificateDestinationStore
}

export interface WindowsPhone81CustomConfiguration extends DeviceConfiguration {
    omaSettings?: [OmaSetting]
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

export interface WindowsVpnConfiguration extends DeviceConfiguration {
    connectionName?: string
    servers?: [VpnServer]
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
    associatedApps?: [Windows10AssociatedApps]
    onlyAssociatedAppsCanUseConnection?: boolean
    windowsInformationProtectionDomain?: string
    trafficRules?: [VpnTrafficRule]
    routes?: [VpnRoute]
    dnsRules?: [VpnDnsRule]
    identityCertificate?: Windows10CertificateProfileBase
}

export interface Windows10CertificateProfileBase extends DeviceConfiguration {
    renewalThresholdPercentage?: number
    keyStorageProvider?: KeyStorageProviderOption
    subjectNameFormat?: SubjectNameFormat
    subjectAlternativeNameType?: SubjectAlternativeNameType
    certificateValidityPeriodValue?: number
    certificateValidityPeriodScale?: CertificateValidityPeriodScale
}

export interface Windows10PkcsCertificateProfile extends Windows10CertificateProfileBase {
    certificationAuthority?: string
    certificationAuthorityName?: string
    certificateTemplateName?: string
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
    dnsSuffixSearchList?: [string]
    identityCertificate?: WindowsPhone81CertificateProfileBase
}

export interface WindowsPhone81CertificateProfileBase extends DeviceConfiguration {
    renewalThresholdPercentage?: number
    keyStorageProvider?: KeyStorageProviderOption
    subjectNameFormat?: SubjectNameFormat
    subjectAlternativeNameType?: SubjectAlternativeNameType
    certificateValidityPeriodValue?: number
    certificateValidityPeriodScale?: CertificateValidityPeriodScale
    extendedKeyUsages?: [ExtendedKeyUsage]
}

export interface WindowsPhone81SCEPCertificateProfile extends WindowsPhone81CertificateProfileBase {
    scepServerUrls?: [string]
    keyUsage?: KeyUsages
    keySize?: KeySize
    hashAlgorithm?: HashAlgorithms
    rootCertificate?: WindowsPhone81TrustedRootCertificate
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
    minimumAutoInstallClassification?: UpdateClassification
    updatesRequireAutomaticUpdates?: boolean
    userAccountControlSettings?: WindowsUserAccountControlSettings
    workFoldersUrl?: string
}

export interface Windows81CertificateProfileBase extends DeviceConfiguration {
    renewalThresholdPercentage?: number
    keyStorageProvider?: KeyStorageProviderOption
    subjectNameFormat?: SubjectNameFormat
    subjectAlternativeNameType?: SubjectAlternativeNameType
    certificateValidityPeriodValue?: number
    certificateValidityPeriodScale?: CertificateValidityPeriodScale
    extendedKeyUsages?: [ExtendedKeyUsage]
}

export interface Windows81SCEPCertificateProfile extends Windows81CertificateProfileBase {
    scepServerUrls?: [string]
    keyUsage?: KeyUsages
    keySize?: KeySize
    hashAlgorithm?: HashAlgorithms
    rootCertificate?: Windows81TrustedRootCertificate
}

export interface WindowsPhone81GeneralConfiguration extends DeviceConfiguration {
    applyToWindows10Mobile?: boolean
    applyOnlyToWindowsPhone81?: boolean
    appsBlockCopyPaste?: boolean
    bluetoothBlocked?: boolean
    cameraBlocked?: boolean
    cellularBlockWifiTethering?: boolean
    compliantAppsList?: [AppListItem]
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

export interface Windows10GeneralConfiguration extends DeviceConfiguration {
    accountsBlockAddingNonMicrosoftAccountEmail?: boolean
    antiTheftModeBlocked?: boolean
    automaticUpdateMode?: AutomaticUpdateMode
    automaticUpdateSchedule?: WeeklySchedule
    automaticUpdateTime?: string
    bluetoothBlocked?: boolean
    bluetoothBlockAdvertising?: boolean
    bluetoothBlockDiscoverableMode?: boolean
    cameraBlocked?: boolean
    cellularBlockDataWhenRoaming?: boolean
    cellularBlockVpn?: boolean
    cellularBlockVpnWhenRoaming?: boolean
    certificatesBlockManualRootCertificateInstallation?: boolean
    copyPasteBlocked?: boolean
    cortanaBlocked?: boolean
    defenderBlockEndUserAccess?: boolean
    defenderDaysBeforeDeletingQuarantinedMalware?: number
    defenderSystemScanSchedule?: WeeklySchedule
    defenderFilesAndFoldersToExclude?: [string]
    defenderFileExtensionsToExclude?: [string]
    defenderScanMaxCpu?: number
    defenderMonitorFileActivity?: DefenderMonitorFileActivity
    defenderProcessesToExclude?: [string]
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
    deviceManagementBlockFactoryResetOnMobile?: boolean
    deviceManagementBlockManualUnenroll?: boolean
    diagnosticsDataSubmissionMode?: DiagnosticDataSubmissionMode
    edgeBlockAutofill?: boolean
    edgeBlocked?: boolean
    edgeCookiePolicy?: EdgeCookiePolicy
    edgeBlockSendingDoNotTrackHeader?: boolean
    edgeBlockJavaScript?: boolean
    edgeBlockPasswordManager?: boolean
    edgeBlockPopups?: boolean
    edgeBlockSearchSuggestions?: boolean
    edgeBlockSendingIntranetTrafficToInternetExplorer?: boolean
    edgeRequireSmartScreen?: boolean
    edgeEnterpriseModeSiteListLocation?: string
    internetSharingBlocked?: boolean
    locationServicesBlocked?: boolean
    lockScreenBlockActionCenterNotifications?: boolean
    microsoftAccountBlocked?: boolean
    microsoftAccountBlockSettingsSync?: boolean
    nfcBlocked?: boolean
    passwordExpirationDays?: number
    passwordMinimumLength?: number
    passwordMinutesOfInactivityBeforeScreenTimeout?: number
    passwordMinimumCharacterSetCount?: number
    passwordPreviousPasswordBlockCount?: number
    passwordRequired?: boolean
    passwordRequireWhenResumeFromIdleState?: boolean
    passwordRequiredType?: RequiredPasswordType
    passwordSignInFailureCountBeforeFactoryReset?: number
    prereleaseFeatures?: PrereleaseFeatures
    resetProtectionModeBlocked?: boolean
    screenCaptureBlocked?: boolean
    storageBlockRemovableStorage?: boolean
    storageRequireMobileDeviceEncryption?: boolean
    usbBlocked?: boolean
    voiceRecordingBlocked?: boolean
    wiFiBlockAutomaticConnectHotspots?: boolean
    wiFiBlocked?: boolean
    wiFiBlockManualConfiguration?: boolean
    windowsStoreBlocked?: boolean
}

export interface Windows10TeamGeneralConfiguration extends DeviceConfiguration {
    azureOperationalInsightsBlockTelemetry?: boolean
    azureOperationalInsightsWorkspaceId?: string
    azureOperationalInsightsWorkspaceKey?: string
    maintenanceWindowBlocked?: boolean
    maintenanceWindowDurationInHours?: number
    maintenanceWindowStartTime?: string
    miracastChannel?: MiracastChannel
    miracastBlocked?: boolean
    miracastRequirePin?: boolean
    welcomeScreenBlockAutomaticWakeUp?: boolean
    welcomeScreenBackgroundImageUrl?: string
    welcomeScreenMeetingInformation?: WelcomeScreenMeetingInformation
}

export interface EditionUpgradeConfiguration extends DeviceConfiguration {
    licenseType?: EditionUpgradeLicenseType
    targetEdition?: Windows10EditionType
    license?: string
    productKey?: string
}

export interface DeviceComplianceActionItem extends Entity {
    gracePeriodHours?: number
    actionType?: DeviceComplianceActionType
    notificationMessageTemplate?: NotificationMessageTemplate
}

export interface NotificationMessageTemplate extends Entity {
}

export interface LocalizedNotificationMessage extends Entity {
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
    requireAppVerify?: boolean
    deviceThreatProtectionEnabled?: boolean
    deviceThreatProtectionRequiredSecurityLevel?: DeviceThreatProtectionLevel
    securityBlockJailbrokenDevices?: boolean
    osMinimumVersion?: string
    osMaximumVersion?: string
    minAndroidSecurityPatchLevel?: string
    storageRequireEncryption?: boolean
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
}

export interface MacOSCompliancePolicy extends DeviceCompliancePolicy {
    passwordRequired?: boolean
    passwordBlockSimple?: boolean
    passwordExpirationDays?: number
    passwordMinimumLength?: number
    passwordMinutesOfInactivityBeforeLock?: number
    passwordPreviousPasswordBlockCount?: number
    passwordRequiredType?: RequiredPasswordType
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

export interface DetectedApp extends Entity {
    displayName?: string
    version?: string
    sizeInByte?: number
    deviceCount?: number
    managedDevices?: [ManagedDevice]
}

export interface ManagedDeviceOverview extends Entity {
    enrolledDeviceCount?: number
    mdmEnrolledCount?: number
    dualEnrolledDeviceCount?: number
    deviceOperatingSystemSummary?: DeviceOperatingSystemSummary
}

export interface OnPremisesConditionalAccessSettings extends Entity {
    enabled?: boolean
    includedGroups?: [string]
    excludedGroups?: [string]
}

export interface ManagedAppPolicy extends Entity {
    displayName?: string
    description?: string
    lastModifiedTime?: string
    deployedAppCount?: number
    version?: string
    mobileAppIdentifierDeployments?: [MobileAppIdentifierDeployment]
    deploymentSummary?: ManagedAppPolicyDeploymentSummary
}

export interface MobileAppIdentifierDeployment extends Entity {
    mobileAppIdentifier?: MobileAppIdentifier
    version?: string
}

export interface ManagedAppPolicyDeploymentSummary extends Entity {
    displayName?: string
    configurationDeployedUserCount?: number
    lastRefreshTime?: string
    configurationDeploymentSummaryPerApp?: [ManagedAppPolicyDeploymentSummaryPerApp]
    version?: string
}

export interface ManagedAppOperation extends Entity {
    displayName?: string
    lastModifiedDateTime?: string
    state?: string
    version?: string
}

export interface ManagedAppStatus extends Entity {
    displayName?: string
    version?: string
}

export interface ManagedAppProtection extends ManagedAppPolicy {
    periodOfflineBeforeAccessCheck?: number
    periodOnlineBeforeAccessCheck?: number
    allowedInboundDataTransferSources?: ManagedAppDataTransferLevel
    allowedOutboundDataTransferDestinations?: ManagedAppDataTransferLevel
    organizationalCredentialsRequired?: boolean
    allowedOutboundClipboardSharingLevel?: ManagedAppClipboardSharingLevel
    dataBackupBlocked?: boolean
    deviceComplianceRequired?: boolean
    managedBrowserToOpenLinksRequired?: boolean
    saveAsBlocked?: boolean
    periodOfflineBeforeWipeIsEnforced?: number
    pinRequired?: boolean
    maximumPinRetries?: number
    simplePinBlocked?: boolean
    minimumPinLength?: number
    pinCharacterSet?: ManagedAppPinCharacterSet
    allowedDataStorageLocations?: [ManagedAppDataStorageLocation]
    contactSyncBlocked?: boolean
    printBlocked?: boolean
    fingerprintBlocked?: boolean
}

export interface TargetedManagedAppProtection extends ManagedAppProtection {
    targetedSecurityGroupsCount?: number
    targetedSecurityGroupIds?: [string]
    targetedSecurityGroups?: [DirectoryObject]
}

export interface ManagedAppConfiguration extends ManagedAppPolicy {
    customSettings?: [KeyValuePair]
}

export interface TargetedManagedAppConfiguration extends ManagedAppConfiguration {
    numberOfTargetedSecurityGroups?: number
    targetedSecurityGroups?: [DirectoryObject]
}

export interface DefaultManagedAppConfiguration extends ManagedAppConfiguration {
}

export interface DefaultManagedAppProtection extends ManagedAppProtection {
    appDataEncryptionType?: ManagedAppDataEncryptionType
    screenCaptureBlocked?: boolean
    encryptAppData?: boolean
    customSettings?: [KeyValuePair]
}

export interface AndroidManagedAppProtection extends TargetedManagedAppProtection {
    screenCaptureBlocked?: boolean
    encryptAppData?: boolean
}

export interface IosManagedAppProtection extends TargetedManagedAppProtection {
    appDataEncryptionType?: ManagedAppDataEncryptionType
}

export interface IosManagedAppRegistration extends ManagedAppRegistration {
}

export interface AndroidManagedAppRegistration extends ManagedAppRegistration {
}

export interface ManagedAppStatusRaw extends ManagedAppStatus {
    content?: ManagedAppSummary
}

export interface AddIn {
      id?: string
      type?: string
      properties?: [KeyValue]
}

export interface KeyValue {
      key?: string
      value?: string
}

export interface AppRole {
      allowedMemberTypes?: [string]
      description?: string
      displayName?: string
      id?: string
      isEnabled?: boolean
      origin?: string
      value?: string
}

export interface KeyCredential {
      customKeyIdentifier?: number
      endDate?: string
      keyId?: string
      startDate?: string
      type?: string
      usage?: string
      value?: number
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

export interface PasswordCredential {
      customKeyIdentifier?: number
      endDate?: string
      keyId?: string
      startDate?: string
      value?: string
}

export interface RequiredResourceAccess {
      resourceAppId?: string
      resourceAccess?: [ResourceAccess]
}

export interface ResourceAccess {
      id?: string
      type?: string
}

export interface OnPremisesPublishing {
      externalUrl?: string
      internalUrl?: string
      externalAuthenticationType?: ExternalAuthenticationType
      isTranslateHostHeaderEnabled?: boolean
      isOnPremPublishingEnabled?: boolean
      verifiedCustomDomainKeyCredential?: KeyCredential
      verifiedCustomDomainPasswordCredential?: PasswordCredential
      verifiedCustomDomainCertificatesMetadata?: VerifiedCustomDomainCertificatesMetadata
}

export interface VerifiedCustomDomainCertificatesMetadata {
      thumbprint?: string
      subjectName?: string
      issuerName?: string
      issueDate?: string
      expiryDate?: string
}

export interface AlternativeSecurityId {
      type?: number
      identityProvider?: string
      key?: number
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

export interface LicenseUnitsDetail {
      enabled?: number
      suspended?: number
      warning?: number
}

export interface ServicePlanInfo {
      servicePlanId?: string
      servicePlanName?: string
      provisioningStatus?: string
      appliesTo?: string
}

export interface AssignedPlan {
      assignedDateTime?: string
      capabilityStatus?: string
      service?: string
      servicePlanId?: string
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

export interface ApplePushNotificationCertificateSetting {
      appleIdentifier?: string
      topicIdentifier?: string
      lastModifiedDateTime?: string
      expirationDateTime?: string
      certificateUploadStatus?: string
      certificateUploadFailureReason?: string
}

export interface DefaultDeviceEnrollmentRestrictions {
      iosRestrictions?: DeviceEnrollmentPlatformRestrictions
      windowsRestrictions?: DeviceEnrollmentPlatformRestrictions
      windowsMobileRestrictions?: DeviceEnrollmentPlatformRestrictions
      androidRestrictions?: DeviceEnrollmentPlatformRestrictions
      macRestrictions?: DeviceEnrollmentPlatformRestrictions
}

export interface DeviceEnrollmentPlatformRestrictions {
      platformBlocked?: boolean
      personalDeviceEnrollmentBlocked?: boolean
}

export interface DefaultDeviceEnrollmentWindowsHelloForBusinessSettings {
      pinMinimumLength?: number
      pinMaximumLength?: number
      pinUppercaseLettersUsage?: WindowsHelloForBusinessPinUsage
      pinLowercaseLettersUsage?: WindowsHelloForBusinessPinUsage
      pinSpecialCharactersUsage?: WindowsHelloForBusinessPinUsage
      windowsHelloForBusiness?: WindowsHelloForBusinessConfiguration
      securityDeviceRequired?: boolean
      unlockWithBiometricsEnabled?: boolean
      mobilePinSignInEnabled?: boolean
      pinPreviousBlockCount?: number
      pinExpirationInDays?: number
      enhancedBiometrics?: WindowsHelloForBusinessConfiguration
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
}

export interface RgbColor {
      r?: number
      g?: number
      b?: number
}

export interface MimeContent {
      type?: string
      value?: number
}

export interface CertificateConnectorSetting {
      status?: number
      certExpiryTime?: string
      enrollmentError?: string
      lastConnectorConnectionTime?: string
      connectorVersion?: string
      lastUploadVersion?: number
}

export interface AssignedLicense {
      disabledPlans?: [string]
      skuId?: string
}

export interface PasswordProfile {
      password?: string
      forceChangePasswordNextSignIn?: boolean
}

export interface MailboxSettings {
      automaticRepliesSetting?: AutomaticRepliesSetting
      timeZone?: string
      language?: LocaleInfo
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

export interface IdentityInfo {
      id?: string
      displayName?: string
      userPrincipalName?: string
}

export interface Root {
}

export interface SiteCollection {
      hostname?: string
}

export interface FieldDefinition {
      defaultValue?: string
      description?: string
      formulas?: Formulas
      hidden?: boolean
      id?: string
      indexed?: boolean
      name?: string
      required?: boolean
      title?: string
      type?: string
}

export interface Formulas {
      default?: string
      validation?: string
}

export interface ListInfo {
      hidden?: boolean
      template?: string
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

export interface Quota {
      deleted?: number
      remaining?: number
      state?: string
      total?: number
      used?: number
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
      sha1Hash?: string
      quickXorHash?: string
}

export interface FileSystemInfo {
      createdDateTime?: string
      lastModifiedDateTime?: string
}

export interface Folder {
      childCount?: number
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

export interface ItemReference {
      driveId?: string
      id?: string
      name?: string
      path?: string
      shareId?: string
}

export interface Photo {
      cameraMake?: string
      cameraModel?: string
      exposureDenominator?: number
      exposureNumerator?: number
      focalLength?: number
      fNumber?: number
      takenDateTime?: string
      iso?: number
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
      sharepointIds?: SharepointIds
      size?: number
      specialFolder?: SpecialFolder
      webDavUrl?: string
      webUrl?: string
}

export interface SharepointIds {
      listId?: string
      listItemId?: string
      listItemUniqueId?: string
      siteId?: string
      webId?: string
}

export interface SpecialFolder {
      name?: string
}

export interface SearchResult {
      onClickTelemetryUrl?: string
}

export interface Shared {
      owner?: IdentitySet
      scope?: string
}

export interface Video {
      bitrate?: number
      duration?: number
      height?: number
      width?: number
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

export interface Recipient {
      emailAddress?: EmailAddress
}

export interface EmailAddress {
      name?: string
      address?: string
}

export interface AttendeeBase {
      type?: AttendeeType
}

export interface MeetingTimeSuggestionsResult {
      meetingTimeSuggestions?: [MeetingTimeSuggestion]
      emptySuggestionsReason?: string
}

export interface MeetingTimeSuggestion {
      meetingTimeSlot?: TimeSlot
      confidence?: number
      organizerAvailability?: FreeBusyStatus
      attendeeAvailability?: [AttendeeAvailability]
      locations?: [Location]
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
}

export interface PhysicalAddress {
      type?: PhysicalAddressType
      postOfficeBox?: string
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
      locations?: [LocationConstraintItem]
}

export interface LocationConstraintItem {
      resolveAvailability?: boolean
}

export interface TimeConstraint {
      activityDomain?: ActivityDomain
      timeslots?: [TimeSlot]
}

export interface MeetingTimeCandidatesResult {
      meetingTimeSlots?: [MeetingTimeCandidate]
      emptySuggestionsHint?: string
}

export interface MeetingTimeCandidate {
      meetingTimeSlot?: TimeSlotOLD
      confidence?: number
      organizerAvailability?: FreeBusyStatus
      attendeeAvailability?: [AttendeeAvailability]
      locations?: [Location]
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
      recipientSuggestions?: [Recipient]
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
      eventId?: string
      eventStartTime?: DateTimeTimeZone
      eventEndTime?: DateTimeTimeZone
      changeKey?: string
      eventSubject?: string
      eventLocation?: Location
      eventWebLink?: string
      reminderFireTime?: DateTimeTimeZone
}

export interface ItemBody {
      contentType?: BodyType
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
      daysOfWeek?: [DayOfWeek]
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

export interface Attendee {
      status?: ResponseStatus
}

export interface Website {
      type?: WebsiteType
      address?: string
      displayName?: string
}

export interface Phone {
      type?: PhoneType
      number?: string
}

export interface RankedEmailAddress {
      address?: string
      rank?: number
}

export interface PersonDataSource {
      type?: string
}

export interface SharingInvitation {
      email?: string
      invitedBy?: IdentitySet
      redeemedBy?: string
      signInRequired?: boolean
}

export interface SharingLink {
      application?: Identity
      type?: string
      scope?: string
      webUrl?: string
}

export interface Thumbnail {
      content?: any
      height?: number
      url?: string
      width?: number
}

export interface DriveRecipient {
      email?: string
      alias?: string
      objectId?: string
}

export interface DriveItemUploadableProperties {
      name?: string
      description?: string
      fileSystemInfo?: FileSystemInfo
}

export interface UploadSession {
      uploadUrl?: string
      expirationDateTime?: string
      nextExpectedRanges?: [string]
}

export interface ResourceVisualization {
      title?: string
      mediaType?: string
      previewImageUrl?: string
      previewText?: string
      containerWebUrl?: string
      containerDisplayName?: string
      containerType?: ContainerType
}

export interface ResourceReference {
      webUrl?: string
      id?: string
      type?: string
}

export interface AppliedCategoriesCollection {
}

export interface ExternalReferenceCollection {
}

export interface ChecklistItemCollection {
}

export interface UserIdCollection {
}

export interface ExternalReference {
      alias?: string
      type?: string
      previewPriority?: string
      lastModifiedBy?: string
      lastModifiedDateTime?: string
}

export interface ChecklistItem {
      isChecked?: boolean
      title?: string
      orderHint?: string
      lastModifiedBy?: string
      lastModifiedDateTime?: string
}

export interface NotebookLinks {
      oneNoteClientUrl?: ExternalLink
      oneNoteWebUrl?: ExternalLink
}

export interface ExternalLink {
      href?: string
}

export interface OneNoteIdentitySet {
      user?: OneNoteIdentity
}

export interface OneNoteIdentity {
      id?: string
      displayName?: string
}

export interface PageLinks {
      oneNoteClientUrl?: ExternalLink
      oneNoteWebUrl?: ExternalLink
}

export interface NotesOperationError {
      code?: string
      message?: string
}

export interface Diagnostic {
      message?: string
      url?: string
}

export interface PatchContentCommand {
      action?: PatchActionType
      target?: string
      content?: string
      position?: PatchInsertPosition
}

export interface CopyStatusModel {
      id?: string
      status?: string
      createdDateTime?: string
}

export interface ImportStatusModel {
      id?: string
      status?: string
      createdDateTime?: string
}

export interface IdentityUserRisk {
      level?: UserRiskLevel
      lastChangedDateTime?: string
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
      ccRecipients?: [Recipient]
      messageLanguage?: string
      customizedMessageBody?: string
}

export interface AppConfigurationSettingItem {
      appConfigKey?: string
      appConfigKeyType?: MdmAppConfigKeyType
      appConfigKeyValue?: string
}

export interface MobileAppInstallSummary {
      installedDeviceCount?: number
      failedDeviceCount?: number
      notInstalledDeviceCount?: number
      installedUserCount?: number
      failedUserCount?: number
      notInstalledUserCount?: number
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
}

export interface VppLicensingType {
      supportUserLicensing?: boolean
      supportDeviceLicensing?: boolean
}

export interface DeviceManagementSettings {
      windowsCommercialId?: string
      windowsCommercialIdLastModifiedTime?: string
}

export interface ManagementCertificateWithThumbprint {
      thumbprint?: string
      certificate?: string
}

export interface CloudPkiAdministratorCredentials {
      adminUserName?: string
      adminPassword?: string
      authenticationCertificate?: number
      authenticationCertificatePassword?: string
}

export interface ExtendedKeyUsage {
      name?: string
      objectIdentifier?: string
}

export interface OmaSetting {
      displayName?: string
      description?: string
      omaUri?: string
}

export interface OmaSettingInteger {
      value?: number
}

export interface OmaSettingFloatingPoint {
      value?: any
}

export interface OmaSettingString {
      value?: string
}

export interface OmaSettingDateTime {
      value?: string
}

export interface OmaSettingStringXml {
      fileName?: string
      value?: number
}

export interface OmaSettingBoolean {
      value?: boolean
}

export interface OmaSettingBase64 {
      fileName?: string
      value?: string
}

export interface AppListItem {
      name?: string
      publisher?: string
      appStoreUrl?: string
      appId?: string
}

export interface AppsComplianceListItem {
      name?: string
      publisher?: string
      appStoreUrl?: string
      appId?: string
}

export interface VpnServer {
      description?: string
      ipAddressOrFqdn?: string
      isDefaultServer?: boolean
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

export interface VpnOnDemandRule {
      ssids?: [string]
      dnsSearchDomains?: [string]
      probeUrl?: string
      action?: VpnOnDemandRuleConnectionAction
      domainAction?: VpnOnDemandRuleConnectionDomainAction
      domains?: [string]
      probeRequiredUrl?: string
}

export interface VpnProxyServer {
      automaticConfigurationScriptUrl?: string
      address?: string
      port?: number
}

export interface Windows81VpnProxyServer {
      automaticallyDetectProxySettings?: boolean
      bypassProxyServerForLocalAddress?: boolean
}

export interface Windows10VpnProxyServer {
      bypassProxyServerForLocalAddress?: boolean
}

export interface WindowsUpdateInstallScheduleType {
}

export interface WindowsUpdateScheduledInstall {
      scheduledInstallDay?: WeeklySchedule
      scheduledInstallTime?: string
}

export interface WindowsUpdateActiveHoursInstall {
      activeHoursStart?: string
      activeHoursEnd?: string
}

export interface Windows10AssociatedApps {
      appType?: Windows10AppType
      identifier?: string
}

export interface VpnTrafficRule {
      name?: string
      protocols?: number
      localPortRanges?: [NumberRange]
      remotePortRanges?: [NumberRange]
      localAddressRanges?: [IPv4Range]
      remoteAddressRanges?: [IPv4Range]
      appId?: string
      appType?: VpnTrafficRuleAppType
      routingPolicyType?: VpnTrafficRuleRoutingPolicyType
      claims?: string
}

export interface NumberRange {
      lowerNumber?: number
      upperNumber?: number
}

export interface IPv4Range {
      lowerAddress?: string
      upperAddress?: string
}

export interface VpnRoute {
      destinationPrefix?: string
      prefixSize?: number
}

export interface VpnDnsRule {
      name?: string
      servers?: [string]
      proxyServerUri?: string
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
}

export interface DeviceActionResult {
      actionName?: string
      actionState?: DeviceActionState
      startDateTime?: string
      lastUpdatedDateTime?: string
}

export interface DeviceOperatingSystemSummary {
      androidCount?: number
      iosCount?: number
      macOSCount?: number
      windowsMobileCount?: number
      windowsCount?: number
}

export interface LocateDeviceActionResult {
      deviceLocation?: DeviceGeoLocation
}

export interface DeviceGeoLocation {
      lastCollectedDateTimeUtc?: string
      longitude?: number
      latitude?: number
      altitude?: number
      horizontalAccuracy?: number
      verticalAccuracy?: number
      heading?: number
      speed?: number
}

export interface ResetPasscodeActionResult {
      passcode?: string
}

export interface DeviceManagementExchangeAccessRule {
      deviceClass?: DeviceManagementExchangeDeviceClass
      accessLevel?: DeviceManagementExchangeAccessLevel
}

export interface DeviceManagementExchangeDeviceClass {
      name?: string
      type?: ExchangeAccessRuleType
}

export interface MobileAppIdentifier {
}

export interface ManagedAppDiagnosticStatus {
      validationName?: string
      state?: string
      mitigationInstruction?: string
}

export interface AndroidMobileAppIdentifier {
      packageId?: string
}

export interface IosMobileAppIdentifier {
      bundleId?: string
}

export interface ManagedAppPolicyDeploymentSummaryPerApp {
      mobileAppIdentifier?: MobileAppIdentifier
      configurationAppliedUserCount?: number
}

export interface KeyValuePair {
      name?: string
      value?: string
}

export interface ManagedAppSummary {
}

export interface ManagedAppDeploymentSummary {
      numberOfDeployedPolicies?: number
      numberOfFlaggedUsers?: number
      numberOfSyncedUsersWithPolicies?: number
      numberOfSyncedUsersWithoutPolicy?: number
      numberOfPendingAppWipes?: number
      numberOfFailedAppWipes?: number
      numberOfSucceededAppWipes?: number
      lastModifiedDateTime?: string
      numberOfIosSyncedUsersWithoutPolicies?: number
      numberOfIosSyncedUsersWithPolicies?: number
      numberOfAndroidSyncedUsersWithoutPolicies?: number
      numberOfAndroidSyncedUsersWithPolicies?: number
}

export interface RolePermission {
      actions?: [string]
}
