// Type definitions for the Microsoft Graph API
// Project: https://github.com/microsoftgraph/msgraph-typescript-typings
// Definitions by: Microsoft Graph Team <https://github.com/microsoftgraph>
// Definitions: https://github.com/DefinitelyTyped/DefinitelyTyped

//
// Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
//


declare module MicrosoftGraph {
  type BodyType = "text" | "html"
  type Importance = "low" | "normal" | "high"
  type InferenceClassificationType = "focused" | "other"
  type CalendarColor = "lightBlue" | "lightGreen" | "lightOrange" | "lightGray" | "lightYellow" | "lightTeal" | "lightPink" | "lightBrown" | "lightRed" | "maxColor" | "auto"
  type ResponseType = "none" | "organizer" | "tentativelyAccepted" | "accepted" | "declined" | "notResponded"
  type Sensitivity = "normal" | "personal" | "private" | "confidential"
  type RecurrencePatternType = "daily" | "weekly" | "absoluteMonthly" | "relativeMonthly" | "absoluteYearly" | "relativeYearly"
  type DayOfWeek = "sunday" | "monday" | "tuesday" | "wednesday" | "thursday" | "friday" | "saturday"
  type WeekIndex = "first" | "second" | "third" | "fourth" | "last"
  type RecurrenceRangeType = "endDate" | "noEnd" | "numbered"
  type FreeBusyStatus = "free" | "tentative" | "busy" | "oof" | "workingElsewhere" | "unknown"
  type EventType = "singleInstance" | "occurrence" | "exception" | "seriesMaster"
  type AttendeeType = "required" | "optional" | "resource"
  type MeetingMessageType = "none" | "meetingRequest" | "meetingCancelled" | "meetingAccepted" | "meetingTenativelyAccepted" | "meetingDeclined"

  interface Entity {
    id?: string
  }
    
  interface DirectoryObject extends Entity {
  }
    
  interface Device extends DirectoryObject {
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
    
  interface DirectoryRole extends DirectoryObject {
    description?: string
    displayName?: string
    roleTemplateId?: string
    members?: [DirectoryObject]
  }
    
  interface DirectoryRoleTemplate extends DirectoryObject {
    description?: string
    displayName?: string
  }
    
  interface Group extends DirectoryObject {
    description?: string
    displayName?: string
    groupTypes?: [string]
    mail?: string
    mailEnabled?: boolean
    mailNickname?: string
    onPremisesLastSyncDateTime?: string
    onPremisesSecurityIdentifier?: string
    onPremisesSyncEnabled?: boolean
    proxyAddresses?: [string]
    securityEnabled?: boolean
    visibility?: string
    allowExternalSenders?: boolean
    autoSubscribeNewMembers?: boolean
    isSubscribedByMail?: boolean
    unseenCount?: number
    members?: [DirectoryObject]
    memberOf?: [DirectoryObject]
    createdOnBehalfOf?: DirectoryObject
    owners?: [DirectoryObject]
    threads?: [ConversationThread]
    calendar?: Calendar
    calendarView?: [Event]
    events?: [Event]
    conversations?: [Conversation]
    photo?: ProfilePhoto
    acceptedSenders?: [DirectoryObject]
    rejectedSenders?: [DirectoryObject]
    drive?: Drive
  }
    
  interface ConversationThread extends Entity {
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
    
  interface Calendar extends Entity {
    name?: string
    color?: CalendarColor
    changeKey?: string
    events?: [Event]
    calendarView?: [Event]
  }
    
  interface OutlookItem extends Entity {
    createdDateTime?: string
    lastModifiedDateTime?: string
    changeKey?: string
    categories?: [string]
  }
    
  interface Event extends OutlookItem {
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
    calendar?: Calendar
    instances?: [Event]
    extensions?: [Extension]
    attachments?: [Attachment]
  }
    
  interface Conversation extends Entity {
    topic?: string
    hasAttachments?: boolean
    lastDeliveredDateTime?: string
    uniqueSenders?: [string]
    preview?: string
    threads?: [ConversationThread]
  }
    
  interface ProfilePhoto extends Entity {
    height?: number
    width?: number
  }
    
  interface Drive extends Entity {
    driveType?: string
    owner?: IdentitySet
    quota?: Quota
    items?: [DriveItem]
    special?: [DriveItem]
    root?: DriveItem
  }
    
  interface SubscribedSku extends Entity {
    capabilityStatus?: string
    consumedUnits?: number
    prepaidUnits?: LicenseUnitsDetail
    servicePlans?: [ServicePlanInfo]
    skuId?: string
    skuPartNumber?: string
    appliesTo?: string
  }
    
  interface Organization extends DirectoryObject {
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
  }
    
  interface User extends DirectoryObject {
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
    state?: string
    streetAddress?: string
    surname?: string
    usageLocation?: string
    userPrincipalName?: string
    userType?: string
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
    ownedDevices?: [DirectoryObject]
    registeredDevices?: [DirectoryObject]
    manager?: DirectoryObject
    directReports?: [DirectoryObject]
    memberOf?: [DirectoryObject]
    createdObjects?: [DirectoryObject]
    ownedObjects?: [DirectoryObject]
    messages?: [Message]
    mailFolders?: [MailFolder]
    calendar?: Calendar
    calendars?: [Calendar]
    calendarGroups?: [CalendarGroup]
    calendarView?: [Event]
    events?: [Event]
    contacts?: [Contact]
    contactFolders?: [ContactFolder]
    inferenceClassification?: InferenceClassification
    photo?: ProfilePhoto
    drive?: Drive
  }
    
  interface Message extends OutlookItem {
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
    uniqueBody?: ItemBody
    isDeliveryReceiptRequested?: boolean
    isReadReceiptRequested?: boolean
    isRead?: boolean
    isDraft?: boolean
    webLink?: string
    inferenceClassification?: InferenceClassificationType
    extensions?: [Extension]
    attachments?: [Attachment]
  }
    
  interface MailFolder extends Entity {
    displayName?: string
    parentFolderId?: string
    childFolderCount?: number
    unreadItemCount?: number
    totalItemCount?: number
    messages?: [Message]
    childFolders?: [MailFolder]
  }
    
  interface CalendarGroup extends Entity {
    name?: string
    classId?: string
    changeKey?: string
    calendars?: [Calendar]
  }
    
  interface Contact extends OutlookItem {
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
    imAddresses?: [string]
    jobTitle?: string
    companyName?: string
    department?: string
    officeLocation?: string
    profession?: string
    businessHomePage?: string
    assistantName?: string
    manager?: string
    homePhones?: [string]
    mobilePhone?: string
    businessPhones?: [string]
    homeAddress?: PhysicalAddress
    businessAddress?: PhysicalAddress
    otherAddress?: PhysicalAddress
    spouseName?: string
    personalNotes?: string
    children?: [string]
    extensions?: [Extension]
    photo?: ProfilePhoto
  }
    
  interface ContactFolder extends Entity {
    parentFolderId?: string
    displayName?: string
    contacts?: [Contact]
    childFolders?: [ContactFolder]
  }
    
  interface InferenceClassification extends Entity {
    overrides?: [InferenceClassificationOverride]
  }
    
  interface Attachment extends Entity {
    lastModifiedDateTime?: string
    name?: string
    contentType?: string
    size?: number
    isInline?: boolean
  }
    
  interface Extension extends Entity {
  }
    
  interface FileAttachment extends Attachment {
    contentId?: string
    contentLocation?: string
    contentBytes?: number
  }
    
  interface ItemAttachment extends Attachment {
    item?: OutlookItem
  }
    
  interface EventMessage extends Message {
    meetingMessageType?: MeetingMessageType
    event?: Event
  }
    
  interface ReferenceAttachment extends Attachment {
  }
    
  interface OpenTypeExtension extends Extension {
    extensionName?: string
  }
    
  interface Post extends OutlookItem {
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
  }
    
  interface InferenceClassificationOverride extends Entity {
    classifyAs?: InferenceClassificationType
    senderEmailAddress?: EmailAddress
  }
    
  interface DriveItem extends Entity {
    content?: any
    createdBy?: IdentitySet
    createdDateTime?: string
    cTag?: string
    description?: string
    eTag?: string
    lastModifiedBy?: IdentitySet
    lastModifiedDateTime?: string
    name?: string
    parentReference?: ItemReference
    size?: number
    webDavUrl?: string
    webUrl?: string
    audio?: Audio
    deleted?: Deleted
    file?: File
    fileSystemInfo?: FileSystemInfo
    folder?: Folder
    image?: Image
    location?: GeoCoordinates
    photo?: Photo
    remoteItem?: RemoteItem
    searchResult?: SearchResult
    shared?: Shared
    specialFolder?: SpecialFolder
    video?: Video
    package?: Package
    createdByUser?: User
    lastModifiedByUser?: User
    permissions?: [Permission]
    children?: [DriveItem]
    thumbnails?: [ThumbnailSet]
  }
    
  interface Permission extends Entity {
    grantedTo?: IdentitySet
    invitation?: SharingInvitation
    inheritedFrom?: ItemReference
    link?: SharingLink
    roles?: [string]
    shareId?: string
  }
    
  interface ThumbnailSet extends Entity {
    large?: Thumbnail
    medium?: Thumbnail
    small?: Thumbnail
    source?: Thumbnail
  }
    
  interface Subscription extends Entity {
    resource?: string
    changeType?: string
    clientState?: string
    notificationUrl?: string
    expirationDateTime?: string
  }
    
  interface AlternativeSecurityId {
      type?: number
      identityProvider?: string
      key?: number
  }

  interface LicenseUnitsDetail {
      enabled?: number
      suspended?: number
      warning?: number
  }

  interface ServicePlanInfo {
      servicePlanId?: string
      servicePlanName?: string
      provisioningStatus?: string
      appliesTo?: string
  }

  interface AssignedPlan {
      assignedDateTime?: string
      capabilityStatus?: string
      service?: string
      servicePlanId?: string
  }

  interface ProvisionedPlan {
      capabilityStatus?: string
      provisioningStatus?: string
      service?: string
  }

  interface VerifiedDomain {
      capabilities?: string
      isDefault?: boolean
      isInitial?: boolean
      name?: string
      type?: string
  }

  interface AssignedLicense {
      disabledPlans?: [string]
      skuId?: string
  }

  interface PasswordProfile {
      password?: string
      forceChangePasswordNextSignIn?: boolean
  }

  interface Reminder {
      eventId?: string
      eventStartTime?: DateTimeTimeZone
      eventEndTime?: DateTimeTimeZone
      changeKey?: string
      eventSubject?: string
      eventLocation?: Location
      eventWebLink?: string
      reminderFireTime?: DateTimeTimeZone
  }

  interface DateTimeTimeZone {
      dateTime?: string
      timeZone?: string
  }

  interface Location {
      displayName?: string
      address?: PhysicalAddress
  }

  interface PhysicalAddress {
      street?: string
      city?: string
      state?: string
      countryOrRegion?: string
      postalCode?: string
  }

  interface ItemBody {
      contentType?: BodyType
      content?: string
  }

  interface Recipient {
      emailAddress?: EmailAddress
  }

  interface EmailAddress {
      name?: string
      address?: string
  }

  interface ResponseStatus {
      response?: ResponseType
      time?: string
  }

  interface PatternedRecurrence {
      pattern?: RecurrencePattern
      range?: RecurrenceRange
  }

  interface RecurrencePattern {
      type?: RecurrencePatternType
      interval?: number
      month?: number
      dayOfMonth?: number
      daysOfWeek?: [DayOfWeek]
      firstDayOfWeek?: DayOfWeek
      index?: WeekIndex
  }

  interface RecurrenceRange {
      type?: RecurrenceRangeType
      startDate?: string
      endDate?: string
      recurrenceTimeZone?: string
      numberOfOccurrences?: number
  }

  interface Attendee {
      status?: ResponseStatus
      type?: AttendeeType
  }

  interface IdentitySet {
      application?: Identity
      device?: Identity
      user?: Identity
  }

  interface Identity {
      displayName?: string
      id?: string
  }

  interface Quota {
      deleted?: number
      remaining?: number
      state?: string
      total?: number
      used?: number
  }

  interface ItemReference {
      driveId?: string
      id?: string
      path?: string
  }

  interface Audio {
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

  interface Deleted {
      state?: string
  }

  interface File {
      hashes?: Hashes
      mimeType?: string
  }

  interface Hashes {
      crc32Hash?: string
      sha1Hash?: string
  }

  interface FileSystemInfo {
      createdDateTime?: string
      lastModifiedDateTime?: string
  }

  interface Folder {
      childCount?: number
  }

  interface Image {
      height?: number
      width?: number
  }

  interface GeoCoordinates {
      altitude?: number
      latitude?: number
      longitude?: number
  }

  interface Photo {
      cameraMake?: string
      cameraModel?: string
      exposureDenominator?: number
      exposureNumerator?: number
      focalLength?: number
      fNumber?: number
      takenDateTime?: string
      iso?: number
  }

  interface RemoteItem {
      file?: File
      fileSystemInfo?: FileSystemInfo
      folder?: Folder
      id?: string
      name?: string
      parentReference?: ItemReference
      size?: number
  }

  interface SearchResult {
      onClickTelemetryUrl?: string
  }

  interface Shared {
      owner?: IdentitySet
      scope?: string
  }

  interface SpecialFolder {
      name?: string
  }

  interface Video {
      bitrate?: number
      duration?: number
      height?: number
      width?: number
  }

  interface Package {
      type?: string
  }

  interface SharingInvitation {
      email?: string
      invitedBy?: IdentitySet
      redeemedBy?: string
      signInRequired?: boolean
  }

  interface SharingLink {
      application?: Identity
      type?: string
      webUrl?: string
  }

  interface Thumbnail {
      content?: any
      height?: number
      url?: string
      width?: number
  }
}

declare module "MicrosoftGraph" {
    export = MicrosoftGraph;
}