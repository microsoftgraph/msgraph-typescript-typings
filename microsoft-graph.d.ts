// Type definitions for the Microsoft Graph API
// Project: https://github.com/microsoftgraph/msgraph-typescript-typings
// Definitions by: Microsoft Graph Team <https://github.com/microsoftgraph>

//
// Copyright (c) Microsoft Corporation.  All Rights Reserved.  Licensed under the MIT License.  See License in the project root for license information.
//


export as namespace microsoftgraph;

export type AutomaticRepliesStatus = "disabled" | "alwaysEnabled" | "scheduled"
export type ExternalAudienceScope = "none" | "contactsOnly" | "all"
export type AttendeeType = "required" | "optional" | "resource"
export type FreeBusyStatus = "free" | "tentative" | "busy" | "oof" | "workingElsewhere" | "unknown"
export type ActivityDomain = "unknown" | "work" | "personal"
export type BodyType = "text" | "html"
export type Importance = "low" | "normal" | "high"
export type InferenceClassificationType = "focused" | "other"
export type CalendarColor = "lightBlue" | "lightGreen" | "lightOrange" | "lightGray" | "lightYellow" | "lightTeal" | "lightPink" | "lightBrown" | "lightRed" | "maxColor" | "auto"
export type ResponseType = "none" | "organizer" | "tentativelyAccepted" | "accepted" | "declined" | "notResponded"
export type Sensitivity = "normal" | "personal" | "private" | "confidential"
export type RecurrencePatternType = "daily" | "weekly" | "absoluteMonthly" | "relativeMonthly" | "absoluteYearly" | "relativeYearly"
export type DayOfWeek = "sunday" | "monday" | "tuesday" | "wednesday" | "thursday" | "friday" | "saturday"
export type WeekIndex = "first" | "second" | "third" | "fourth" | "last"
export type RecurrenceRangeType = "endDate" | "noEnd" | "numbered"
export type EventType = "singleInstance" | "occurrence" | "exception" | "seriesMaster"
export type MeetingMessageType = "none" | "meetingRequest" | "meetingCancelled" | "meetingAccepted" | "meetingTenativelyAccepted" | "meetingDeclined"

export interface Entity {
    id?: string
}

export interface DirectoryObject extends Entity {
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
}

export interface DirectoryRoleTemplate extends DirectoryObject {
    description?: string
    displayName?: string
}

export interface Group extends DirectoryObject {
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
    changeKey?: string
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
    drives?: [Drive]
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
    uniqueBody?: ItemBody
    isDeliveryReceiptRequested?: boolean
    isReadReceiptRequested?: boolean
    isRead?: boolean
    isDraft?: boolean
    webLink?: string
    inferenceClassification?: InferenceClassificationType
    attachments?: [Attachment]
    extensions?: [Extension]
    singleValueExtendedProperties?: [SingleValueLegacyExtendedProperty]
    multiValueExtendedProperties?: [MultiValueLegacyExtendedProperty]
}

export interface MailFolder extends Entity {
    displayName?: string
    parentFolderId?: string
    childFolderCount?: number
    unreadItemCount?: number
    totalItemCount?: number
    messages?: [Message]
    childFolders?: [MailFolder]
    singleValueExtendedProperties?: [SingleValueLegacyExtendedProperty]
    multiValueExtendedProperties?: [MultiValueLegacyExtendedProperty]
}

export interface CalendarGroup extends Entity {
    name?: string
    classId?: string
    changeKey?: string
    calendars?: [Calendar]
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
    singleValueExtendedProperties?: [SingleValueLegacyExtendedProperty]
    multiValueExtendedProperties?: [MultiValueLegacyExtendedProperty]
    photo?: ProfilePhoto
}

export interface ContactFolder extends Entity {
    parentFolderId?: string
    displayName?: string
    contacts?: [Contact]
    childFolders?: [ContactFolder]
    singleValueExtendedProperties?: [SingleValueLegacyExtendedProperty]
    multiValueExtendedProperties?: [MultiValueLegacyExtendedProperty]
}

export interface InferenceClassification extends Entity {
    overrides?: [InferenceClassificationOverride]
}

export interface Attachment extends Entity {
    lastModifiedDateTime?: string
    name?: string
    contentType?: string
    size?: number
    isInline?: boolean
}

export interface SingleValueLegacyExtendedProperty extends Entity {
    value?: string
}

export interface MultiValueLegacyExtendedProperty extends Entity {
    value?: [string]
}

export interface Extension extends Entity {
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
    newParticipants?: [Recipient]
    conversationId?: string
    extensions?: [Extension]
    inReplyTo?: Post
    attachments?: [Attachment]
    singleValueExtendedProperties?: [SingleValueLegacyExtendedProperty]
    multiValueExtendedProperties?: [MultiValueLegacyExtendedProperty]
}

export interface InferenceClassificationOverride extends Entity {
    classifyAs?: InferenceClassificationType
    senderEmailAddress?: EmailAddress
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
    createdByUser?: User
    workbook?: Workbook
    lastModifiedByUser?: User
    children?: [DriveItem]
    permissions?: [Permission]
    thumbnails?: [ThumbnailSet]
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

export interface SharedDriveItem extends Entity {
    name?: string
    owner?: IdentitySet
    root?: DriveItem
    items?: [DriveItem]
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

export interface Subscription extends Entity {
    resource?: string
    changeType?: string
    clientState?: string
    notificationUrl?: string
    expirationDateTime?: string
}

export interface AlternativeSecurityId {
      type?: number
      identityProvider?: string
      key?: number
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
}

export interface PhysicalAddress {
      street?: string
      city?: string
      state?: string
      countryOrRegion?: string
      postalCode?: string
}

export interface LocationConstraint {
      isRequired?: boolean
      suggestLocation?: boolean
      locations?: [LocationConstraintItem]
}

export interface LocationConstraintItem extends Location {
      resolveAvailability?: boolean
}

export interface TimeConstraint {
      activityDomain?: ActivityDomain
      timeslots?: [TimeSlot]
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

export interface Attendee extends AttendeeBase {
      status?: ResponseStatus
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

export interface Root {
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
