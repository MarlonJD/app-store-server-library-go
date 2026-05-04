package appstore

type Environment string

const (
	EnvironmentProduction Environment = "Production"
	EnvironmentSandbox    Environment = "Sandbox"
)

type JWSDecodedHeader struct {
	Alg string   `json:"alg"`
	KID string   `json:"kid,omitempty"`
	Typ string   `json:"typ,omitempty"`
	X5C []string `json:"x5c"`
}

type JWSTransactionDecodedPayload struct {
	TransactionID               string      `json:"transactionId,omitempty"`
	OriginalTransactionID       string      `json:"originalTransactionId,omitempty"`
	WebOrderLineItemID          string      `json:"webOrderLineItemId,omitempty"`
	BundleID                    string      `json:"bundleId,omitempty"`
	ProductID                   string      `json:"productId,omitempty"`
	SubscriptionGroupIdentifier string      `json:"subscriptionGroupIdentifier,omitempty"`
	PurchaseDate                int64       `json:"purchaseDate,omitempty"`
	OriginalPurchaseDate        int64       `json:"originalPurchaseDate,omitempty"`
	ExpiresDate                 int64       `json:"expiresDate,omitempty"`
	Quantity                    int64       `json:"quantity,omitempty"`
	Type                        string      `json:"type,omitempty"`
	InAppOwnershipType          string      `json:"inAppOwnershipType,omitempty"`
	SignedDate                  int64       `json:"signedDate,omitempty"`
	RevocationReason            *int64      `json:"revocationReason,omitempty"`
	RevocationDate              int64       `json:"revocationDate,omitempty"`
	IsUpgraded                  bool        `json:"isUpgraded,omitempty"`
	OfferType                   *int64      `json:"offerType,omitempty"`
	OfferIdentifier             string      `json:"offerIdentifier,omitempty"`
	Environment                 Environment `json:"environment,omitempty"`
	Storefront                  string      `json:"storefront,omitempty"`
	StorefrontID                string      `json:"storefrontId,omitempty"`
	TransactionReason           string      `json:"transactionReason,omitempty"`
	AppAccountToken             string      `json:"appAccountToken,omitempty"`
}

type JWSRenewalInfoDecodedPayload struct {
	ExpirationIntent            *int64      `json:"expirationIntent,omitempty"`
	OriginalTransactionID       string      `json:"originalTransactionId,omitempty"`
	AutoRenewProductID          string      `json:"autoRenewProductId,omitempty"`
	ProductID                   string      `json:"productId,omitempty"`
	AutoRenewStatus             *int64      `json:"autoRenewStatus,omitempty"`
	IsInBillingRetryPeriod      bool        `json:"isInBillingRetryPeriod,omitempty"`
	PriceIncreaseStatus         *int64      `json:"priceIncreaseStatus,omitempty"`
	GracePeriodExpiresDate      int64       `json:"gracePeriodExpiresDate,omitempty"`
	OfferType                   *int64      `json:"offerType,omitempty"`
	OfferIdentifier             string      `json:"offerIdentifier,omitempty"`
	SignedDate                  int64       `json:"signedDate,omitempty"`
	Environment                 Environment `json:"environment,omitempty"`
	RecentSubscriptionStartDate int64       `json:"recentSubscriptionStartDate,omitempty"`
	RenewalDate                 int64       `json:"renewalDate,omitempty"`
}

type JWSAppTransactionDecodedPayload struct {
	ReceiptType                Environment `json:"receiptType,omitempty"`
	AppAppleID                 int64       `json:"appAppleId,omitempty"`
	BundleID                   string      `json:"bundleId,omitempty"`
	ApplicationVersion         string      `json:"applicationVersion,omitempty"`
	VersionExternalIdentifier  int64       `json:"versionExternalIdentifier,omitempty"`
	ReceiptCreationDate        int64       `json:"receiptCreationDate,omitempty"`
	OriginalPurchaseDate       int64       `json:"originalPurchaseDate,omitempty"`
	OriginalApplicationVersion string      `json:"originalApplicationVersion,omitempty"`
	DeviceVerification         string      `json:"deviceVerification,omitempty"`
	DeviceVerificationNonce    string      `json:"deviceVerificationNonce,omitempty"`
	PreorderDate               int64       `json:"preorderDate,omitempty"`
	AppTransactionID           string      `json:"appTransactionId,omitempty"`
	OriginalPlatform           string      `json:"originalPlatform,omitempty"`
}

type ResponseBodyV2DecodedPayload struct {
	NotificationType      string                 `json:"notificationType,omitempty"`
	Subtype               string                 `json:"subtype,omitempty"`
	NotificationUUID      string                 `json:"notificationUUID,omitempty"`
	Version               string                 `json:"version,omitempty"`
	SignedDate            int64                  `json:"signedDate,omitempty"`
	Data                  *NotificationData      `json:"data,omitempty"`
	Summary               *NotificationSummary   `json:"summary,omitempty"`
	ExternalPurchaseToken *ExternalPurchaseToken `json:"externalPurchaseToken,omitempty"`
}

type NotificationData struct {
	AppAppleID               int64       `json:"appAppleId,omitempty"`
	BundleID                 string      `json:"bundleId,omitempty"`
	BundleVersion            string      `json:"bundleVersion,omitempty"`
	Environment              Environment `json:"environment,omitempty"`
	SignedTransactionInfo    string      `json:"signedTransactionInfo,omitempty"`
	SignedRenewalInfo        string      `json:"signedRenewalInfo,omitempty"`
	Status                   *int64      `json:"status,omitempty"`
	ConsumptionRequestReason string      `json:"consumptionRequestReason,omitempty"`
}

type NotificationSummary struct {
	AppAppleID  int64       `json:"appAppleId,omitempty"`
	BundleID    string      `json:"bundleId,omitempty"`
	Environment Environment `json:"environment,omitempty"`
}

type ExternalPurchaseToken struct {
	AppAppleID         int64  `json:"appAppleId,omitempty"`
	BundleID           string `json:"bundleId,omitempty"`
	ExternalPurchaseID string `json:"externalPurchaseId,omitempty"`
	TokenCreationDate  int64  `json:"tokenCreationDate,omitempty"`
}

type TransactionInfoResponse struct {
	SignedTransactionInfo string `json:"signedTransactionInfo"`
}

type AppTransactionInfoResponse struct {
	SignedAppTransaction string `json:"signedAppTransaction"`
}

type HistoryResponse struct {
	Revision           string      `json:"revision,omitempty"`
	HasMore            bool        `json:"hasMore"`
	BundleID           string      `json:"bundleId,omitempty"`
	AppAppleID         int64       `json:"appAppleId,omitempty"`
	Environment        Environment `json:"environment,omitempty"`
	SignedTransactions []string    `json:"signedTransactions,omitempty"`
}

type StatusResponse struct {
	Environment Environment                       `json:"environment,omitempty"`
	AppAppleID  int64                             `json:"appAppleId,omitempty"`
	BundleID    string                            `json:"bundleId,omitempty"`
	Data        []SubscriptionGroupIdentifierItem `json:"data,omitempty"`
}

type SubscriptionGroupIdentifierItem struct {
	SubscriptionGroupIdentifier string                 `json:"subscriptionGroupIdentifier,omitempty"`
	LastTransactions            []LastTransactionsItem `json:"lastTransactions,omitempty"`
}

type LastTransactionsItem struct {
	OriginalTransactionID string `json:"originalTransactionId,omitempty"`
	Status                int64  `json:"status,omitempty"`
	SignedTransactionInfo string `json:"signedTransactionInfo,omitempty"`
	SignedRenewalInfo     string `json:"signedRenewalInfo,omitempty"`
}

type RefundHistoryResponse struct {
	Revision           string   `json:"revision,omitempty"`
	HasMore            bool     `json:"hasMore"`
	SignedTransactions []string `json:"signedTransactions,omitempty"`
}

type OrderLookupResponse struct {
	Status             int64    `json:"status"`
	SignedTransactions []string `json:"signedTransactions,omitempty"`
}

type SendTestNotificationResponse struct {
	TestNotificationToken string `json:"testNotificationToken"`
}

type CheckTestNotificationResponse struct {
	SignedPayload string            `json:"signedPayload,omitempty"`
	SendAttempts  []SendAttemptItem `json:"sendAttempts,omitempty"`
}

type SendAttemptItem struct {
	AttemptDate       int64  `json:"attemptDate,omitempty"`
	SendAttemptResult string `json:"sendAttemptResult,omitempty"`
}

type NotificationHistoryRequest struct {
	StartDate           int64  `json:"startDate"`
	EndDate             int64  `json:"endDate"`
	NotificationType    string `json:"notificationType,omitempty"`
	NotificationSubtype string `json:"notificationSubtype,omitempty"`
	TransactionID       string `json:"transactionId,omitempty"`
	OnlyFailures        bool   `json:"onlyFailures,omitempty"`
}

type NotificationHistoryResponse struct {
	PaginationToken     string                            `json:"paginationToken,omitempty"`
	HasMore             bool                              `json:"hasMore"`
	NotificationHistory []NotificationHistoryResponseItem `json:"notificationHistory,omitempty"`
}

type NotificationHistoryResponseItem struct {
	SignedPayload string            `json:"signedPayload,omitempty"`
	SendAttempts  []SendAttemptItem `json:"sendAttempts,omitempty"`
}

type ConsumptionRequest struct {
	AccountTenure            *int64 `json:"accountTenure,omitempty"`
	AppAccountToken          string `json:"appAccountToken,omitempty"`
	ConsumptionStatus        *int64 `json:"consumptionStatus,omitempty"`
	CustomerConsented        *bool  `json:"customerConsented,omitempty"`
	DeliveryStatus           *int64 `json:"deliveryStatus,omitempty"`
	LifetimeDollarsPurchased *int64 `json:"lifetimeDollarsPurchased,omitempty"`
	LifetimeDollarsRefunded  *int64 `json:"lifetimeDollarsRefunded,omitempty"`
	Platform                 *int64 `json:"platform,omitempty"`
	PlayTime                 *int64 `json:"playTime,omitempty"`
	SampleContentProvided    *bool  `json:"sampleContentProvided,omitempty"`
	UserStatus               *int64 `json:"userStatus,omitempty"`
	RefundPreference         *int64 `json:"refundPreference,omitempty"`
}

type ExtendRenewalDateRequest struct {
	ExtendByDays      int64  `json:"extendByDays"`
	ExtendReasonCode  int64  `json:"extendReasonCode"`
	RequestIdentifier string `json:"requestIdentifier"`
}

type ExtendRenewalDateResponse struct {
	OriginalTransactionID string `json:"originalTransactionId,omitempty"`
	WebOrderLineItemID    string `json:"webOrderLineItemId,omitempty"`
	Success               bool   `json:"success"`
	EffectiveDate         int64  `json:"effectiveDate,omitempty"`
}

type MassExtendRenewalDateRequest struct {
	ProductID              string   `json:"productId"`
	ExtendByDays           int64    `json:"extendByDays"`
	ExtendReasonCode       int64    `json:"extendReasonCode"`
	RequestIdentifier      string   `json:"requestIdentifier"`
	StorefrontCountryCodes []string `json:"storefrontCountryCodes,omitempty"`
}

type MassExtendRenewalDateResponse struct {
	RequestIdentifier string `json:"requestIdentifier,omitempty"`
}

type MassExtendRenewalDateStatusResponse struct {
	RequestIdentifier string `json:"requestIdentifier,omitempty"`
	Complete          bool   `json:"complete"`
	CompleteDate      int64  `json:"completeDate,omitempty"`
	SucceededCount    int64  `json:"succeededCount,omitempty"`
	FailedCount       int64  `json:"failedCount,omitempty"`
}
