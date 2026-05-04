# SDK API Documentation

This document describes the public API surface of
`github.com/marlonjd/app-store-server-library-go`. The package name is
`appstore`, and the SDK covers two main areas:

- A JWT-signing `Client` for App Store Server API requests
- A `SignedDataVerifier` for validating Apple-signed JWS payloads

## Installation

```bash
go get github.com/marlonjd/app-store-server-library-go
```

```go
import appstore "github.com/marlonjd/app-store-server-library-go"
```

## Core Concepts

### Environments

The SDK supports the two App Store Server environments:

```go
appstore.EnvironmentProduction // "Production"
appstore.EnvironmentSandbox    // "Sandbox"
```

When `ClientOptions.Environment` is `EnvironmentSandbox`, the client uses the
sandbox base URL. In all other cases, it defaults to production.

```go
fmt.Println(appstore.ProductionBaseURL)
fmt.Println(appstore.SandboxBaseURL)
```

### Timestamps

Apple payload and request date fields are represented as `int64` Unix
timestamps. App Store Server payload fields such as `signedDate`,
`purchaseDate`, and `expiresDate` are commonly represented in milliseconds.

```go
start := time.Now().Add(-30 * 24 * time.Hour).UnixMilli()
end := time.Now().UnixMilli()
```

### Import Alias

The module path contains hyphens, while the package name is `appstore`. The
examples use an import alias for readability:

```go
import appstore "github.com/marlonjd/app-store-server-library-go"
```

## Client

`Client` sends requests to App Store Server API endpoints. It creates an ES256
JWT for each request and adds it as an `Authorization: Bearer <token>` header.

### Creating a Client

```go
package billing

import (
	"context"
	"os"
	"time"

	appstore "github.com/marlonjd/app-store-server-library-go"
)

func newAppStoreClient() (*appstore.Client, error) {
	privateKey, err := os.ReadFile("AuthKey_ABCDEFGHIJ.p8")
	if err != nil {
		return nil, err
	}

	return appstore.NewClient(appstore.ClientOptions{
		PrivateKeyPEM: string(privateKey),
		KeyID:         os.Getenv("APPSTORE_KEY_ID"),
		IssuerID:      os.Getenv("APPSTORE_ISSUER_ID"),
		BundleID:      "com.example.app",
		Environment:   appstore.EnvironmentSandbox,
		TokenTTL:      20 * time.Minute,
	})
}

func example(ctx context.Context) error {
	client, err := newAppStoreClient()
	if err != nil {
		return err
	}

	_, err = client.GetTransactionInfo(ctx, "2000000123456789")
	return err
}
```

### ClientOptions

| Field | Required | Description |
| --- | --- | --- |
| `PrivateKeyPEM` | Yes | App Store Connect API key `.p8` private key contents. PKCS#8 and EC private key PEM formats are supported. |
| `KeyID` | Yes | App Store Connect API key ID. Used as the JWT header `kid`. |
| `IssuerID` | Yes | App Store Connect issuer ID. Used as the JWT payload `iss`. |
| `BundleID` | Yes | App bundle ID. Used as the JWT payload `bid`. |
| `Environment` | No | Uses sandbox when set to `EnvironmentSandbox`; otherwise production is used. |
| `BaseURL` | No | Overrides the base URL for tests or proxies. Empty means the URL is selected from `Environment`. |
| `HTTPClient` | No | Custom `*http.Client`. Defaults to `http.DefaultClient`. |
| `TokenTTL` | No | JWT lifetime. Defaults to `20 * time.Minute`; must not exceed `1 * time.Hour`. |
| `Now` | No | Clock hook for deterministic tests. Defaults to `time.Now`. |

### Creating a JWT

Tokens are created automatically for normal API calls. If you need a token
manually:

```go
token, err := client.CreateToken(time.Now())
if err != nil {
	return err
}

_ = token
```

JWT header fields:

- `alg`: `ES256`
- `kid`: `ClientOptions.KeyID`
- `typ`: `JWT`

JWT payload fields:

- `iss`: `ClientOptions.IssuerID`
- `iat`: token issue time
- `exp`: `iat + TokenTTL`
- `aud`: `appstoreconnect-v1`
- `bid`: `ClientOptions.BundleID`

## API Methods

### Get Transaction Info

```go
info, err := client.GetTransactionInfo(ctx, transactionID)
if err != nil {
	return err
}

signedTransaction := info.SignedTransactionInfo
_ = signedTransaction
```

Method:

```go
GetTransactionInfo(ctx context.Context, transactionID string) (TransactionInfoResponse, error)
```

Endpoint:

```text
GET /inApps/v1/transactions/{transactionID}
```

Response:

```go
type TransactionInfoResponse struct {
	SignedTransactionInfo string `json:"signedTransactionInfo"`
}
```

The returned `SignedTransactionInfo` should usually be passed directly to
`SignedDataVerifier.VerifyAndDecodeTransaction`.

### Get Transaction History

Transaction history is paginated. When the response has `HasMore == true`, pass
the returned `Revision` into the next request.

```go
func fetchTransactionHistory(ctx context.Context, client *appstore.Client, transactionID string) ([]appstore.JWSTransactionDecodedPayload, error) {
	verifier, err := appstore.NewSignedDataVerifier(appstore.SignedDataVerifierOptions{
		BundleID:    "com.example.app",
		Environment: appstore.EnvironmentSandbox,
	})
	if err != nil {
		return nil, err
	}

	var revision string
	var transactions []appstore.JWSTransactionDecodedPayload

	for {
		response, err := client.GetTransactionHistory(ctx, transactionID, revision, &appstore.TransactionHistoryRequest{
			StartDate: time.Now().Add(-90 * 24 * time.Hour).UnixMilli(),
			EndDate:   time.Now().UnixMilli(),
			ProductIDs: []string{
				"com.example.premium.monthly",
				"com.example.premium.yearly",
			},
			Sort: "ASCENDING",
		})
		if err != nil {
			return nil, err
		}

		for _, signed := range response.SignedTransactions {
			tx, err := verifier.VerifyAndDecodeTransaction(signed)
			if err != nil {
				return nil, err
			}
			transactions = append(transactions, tx)
		}

		if !response.HasMore {
			break
		}
		revision = response.Revision
	}

	return transactions, nil
}
```

Method:

```go
GetTransactionHistory(ctx context.Context, transactionID string, revision string, request *TransactionHistoryRequest) (HistoryResponse, error)
```

Endpoint:

```text
GET /inApps/v2/history/{transactionID}
```

Query parameters are generated from `revision` and `TransactionHistoryRequest`.
`request` may be `nil`.

`TransactionHistoryRequest`:

| Field | Query parameter | Description |
| --- | --- | --- |
| `StartDate` | `startDate` | Start timestamp. Omitted when `0`. |
| `EndDate` | `endDate` | End timestamp. Omitted when `0`. |
| `ProductIDs` | `productId` | Each value is added as a separate query parameter. |
| `ProductTypes` | `productType` | Each value is added as a separate query parameter. |
| `Revoked` | `revoked` | Omitted when `nil`; otherwise sent as `true` or `false`. |
| `SubscriptionGroupIdentifiers` | `subscriptionGroupIdentifier` | Each value is added as a separate query parameter. |
| `InAppOwnershipType` | `inAppOwnershipType` | Omitted when empty. |
| `Sort` | `sort` | Omitted when empty. |

Response:

```go
type HistoryResponse struct {
	Revision           string
	HasMore            bool
	BundleID           string
	AppAppleID         int64
	Environment        appstore.Environment
	SignedTransactions []string
}
```

### Get All Subscription Statuses

```go
statusResponse, err := client.GetAllSubscriptionStatuses(ctx, anyTransactionID, 1, 4)
if err != nil {
	return err
}

for _, group := range statusResponse.Data {
	for _, item := range group.LastTransactions {
		tx, err := verifier.VerifyAndDecodeTransaction(item.SignedTransactionInfo)
		if err != nil {
			return err
		}

		renewal, err := verifier.VerifyAndDecodeRenewalInfo(item.SignedRenewalInfo)
		if err != nil {
			return err
		}

		_ = tx.ProductID
		_ = renewal.AutoRenewStatus
	}
}
```

Method:

```go
GetAllSubscriptionStatuses(ctx context.Context, anyTransactionID string, statuses ...int64) (StatusResponse, error)
```

Endpoint:

```text
GET /inApps/v1/subscriptions/{anyTransactionID}
```

`statuses` is variadic. Each value is added as a `status=<value>` query
parameter. If no statuses are provided, no status filter is sent.

### Get Refund History

```go
var revision string

for {
	response, err := client.GetRefundHistory(ctx, transactionID, revision)
	if err != nil {
		return err
	}

	for _, signed := range response.SignedTransactions {
		tx, err := verifier.VerifyAndDecodeTransaction(signed)
		if err != nil {
			return err
		}
		_ = tx.RevocationDate
	}

	if !response.HasMore {
		break
	}
	revision = response.Revision
}
```

Method:

```go
GetRefundHistory(ctx context.Context, transactionID string, revision string) (RefundHistoryResponse, error)
```

Endpoint:

```text
GET /inApps/v2/refund/lookup/{transactionID}
```

### Get Notification History

```go
func fetchNotificationHistory(ctx context.Context, client *appstore.Client, verifier *appstore.SignedDataVerifier) error {
	request := appstore.NotificationHistoryRequest{
		StartDate:        time.Now().Add(-24 * time.Hour).UnixMilli(),
		EndDate:          time.Now().UnixMilli(),
		NotificationType: "DID_RENEW",
		OnlyFailures:     false,
	}

	var token string
	for {
		response, err := client.GetNotificationHistory(ctx, request, token)
		if err != nil {
			return err
		}

		for _, item := range response.NotificationHistory {
			notification, err := verifier.VerifyAndDecodeNotification(item.SignedPayload)
			if err != nil {
				return err
			}
			_ = notification.NotificationUUID
		}

		if !response.HasMore {
			break
		}
		token = response.PaginationToken
	}

	return nil
}
```

Method:

```go
GetNotificationHistory(ctx context.Context, request NotificationHistoryRequest, paginationToken string) (NotificationHistoryResponse, error)
```

Endpoint:

```text
POST /inApps/v1/notifications/history
```

When `paginationToken` is not empty, it is added as a query parameter. Filters
are sent as a JSON request body.

`NotificationHistoryRequest`:

| Field | Description |
| --- | --- |
| `StartDate` | Query start timestamp. |
| `EndDate` | Query end timestamp. |
| `NotificationType` | Optional notification type filter. |
| `NotificationSubtype` | Optional subtype filter. |
| `TransactionID` | Optional transaction filter. |
| `OnlyFailures` | When `true`, only failed send attempts are queried. |

### Request and Check Test Notifications

```go
sent, err := client.RequestTestNotification(ctx)
if err != nil {
	return err
}

status, err := client.GetTestNotificationStatus(ctx, sent.TestNotificationToken)
if err != nil {
	return err
}

if status.SignedPayload != "" {
	notification, err := verifier.VerifyAndDecodeNotification(status.SignedPayload)
	if err != nil {
		return err
	}
	_ = notification.NotificationType
}
```

Methods:

```go
RequestTestNotification(ctx context.Context) (SendTestNotificationResponse, error)
GetTestNotificationStatus(ctx context.Context, testNotificationToken string) (CheckTestNotificationResponse, error)
```

Endpoints:

```text
POST /inApps/v1/notifications/test
GET  /inApps/v1/notifications/test/{testNotificationToken}
```

### Send Consumption Information

Use this method to send consumption information to Apple for refund or
consumption request flows.

```go
customerConsented := true
consumptionStatus := int64(1)
deliveryStatus := int64(1)
platform := int64(1)

err := client.SendConsumptionInformation(ctx, transactionID, appstore.ConsumptionRequest{
	AppAccountToken:   "018f8c8a-0001-7000-9000-000000000001",
	CustomerConsented: &customerConsented,
	ConsumptionStatus: &consumptionStatus,
	DeliveryStatus:    &deliveryStatus,
	Platform:          &platform,
})
if err != nil {
	return err
}
```

Method:

```go
SendConsumptionInformation(ctx context.Context, transactionID string, request ConsumptionRequest) error
```

Endpoint:

```text
PUT /inApps/v1/transactions/consumption/{transactionID}
```

Pointer fields in `ConsumptionRequest` are omitted from the JSON body when they
are `nil`. This lets you send only the values you actually know.

### Extend a Renewal Date for One Subscriber

```go
response, err := client.ExtendRenewalDate(ctx, originalTransactionID, appstore.ExtendRenewalDateRequest{
	ExtendByDays:      7,
	ExtendReasonCode:  1,
	RequestIdentifier: "support-case-12345",
})
if err != nil {
	return err
}

if response.Success {
	_ = response.EffectiveDate
}
```

Method:

```go
ExtendRenewalDate(ctx context.Context, originalTransactionID string, request ExtendRenewalDateRequest) (ExtendRenewalDateResponse, error)
```

Endpoint:

```text
PUT /inApps/v1/subscriptions/extend/{originalTransactionID}
```

### Extend Renewal Dates for All Active Subscribers

```go
requestID := "campaign-2026-05"

started, err := client.ExtendRenewalDateForAllActiveSubscribers(ctx, appstore.MassExtendRenewalDateRequest{
	ProductID:              "com.example.premium.monthly",
	ExtendByDays:           7,
	ExtendReasonCode:       1,
	RequestIdentifier:      requestID,
	StorefrontCountryCodes: []string{"US", "TR"},
})
if err != nil {
	return err
}

status, err := client.GetStatusOfSubscriptionRenewalDateExtensions(ctx, "com.example.premium.monthly", started.RequestIdentifier)
if err != nil {
	return err
}

_ = status.Complete
```

Methods:

```go
ExtendRenewalDateForAllActiveSubscribers(ctx context.Context, request MassExtendRenewalDateRequest) (MassExtendRenewalDateResponse, error)
GetStatusOfSubscriptionRenewalDateExtensions(ctx context.Context, productID, requestIdentifier string) (MassExtendRenewalDateStatusResponse, error)
```

Endpoints:

```text
POST /inApps/v1/subscriptions/extend/mass
GET  /inApps/v1/subscriptions/extend/mass/{productID}/{requestIdentifier}
```

### Look Up an Order ID

```go
lookup, err := client.LookUpOrderID(ctx, orderID)
if err != nil {
	return err
}

for _, signed := range lookup.SignedTransactions {
	tx, err := verifier.VerifyAndDecodeTransaction(signed)
	if err != nil {
		return err
	}
	_ = tx.OriginalTransactionID
}
```

Method:

```go
LookUpOrderID(ctx context.Context, orderID string) (OrderLookupResponse, error)
```

Endpoint:

```text
GET /inApps/v1/lookup/{orderID}
```

## SignedDataVerifier

`SignedDataVerifier` verifies and decodes Apple-signed JWS payloads. Successful
processing must validate the signature, certificate chain, app identity, and
environment; plain JSON decoding is not enough.

### Creating a Verifier

```go
verifier, err := appstore.NewSignedDataVerifier(appstore.SignedDataVerifierOptions{
	BundleID:    "com.example.app",
	AppAppleID:  1234567890,
	Environment: appstore.EnvironmentProduction,
})
if err != nil {
	return err
}
```

For sandbox:

```go
verifier, err := appstore.NewSignedDataVerifier(appstore.SignedDataVerifierOptions{
	BundleID:    "com.example.app",
	Environment: appstore.EnvironmentSandbox,
})
```

### SignedDataVerifierOptions

| Field | Description |
| --- | --- |
| `RootCertificates` | Apple root certificates in DER form. When empty, the SDK uses its bundled Apple root certificates. |
| `BundleID` | When set, the payload bundle ID must match this value. |
| `AppAppleID` | Used for App Apple ID validation in production verification. |
| `Environment` | When set, the payload environment must match this value. |
| `Now` | Clock used for certificate validation when a payload has no signing date. Defaults to `time.Now`. |

### Verification Rules

The verifier checks:

- The JWS compact serialization has exactly three parts
- The JWS header `alg` is `ES256`
- The header `x5c` certificate chain has exactly three certificates
- Certificates can be parsed
- The root certificate matches one of the trusted Apple root certificates
- The leaf certificate has the Apple receipt signing extension
- The intermediate certificate has the Apple WWDR extension
- The certificate chain is valid at the payload signing date
- The ES256 signature is valid for the leaf public key
- Bundle ID, App Apple ID, and environment match the verifier options

### Decode a Transaction JWS

```go
tx, err := verifier.VerifyAndDecodeTransaction(signedTransactionInfo)
if err != nil {
	return err
}

if tx.ExpiresDate > time.Now().UnixMilli() {
	// The subscription appears to be active.
}
```

Method:

```go
VerifyAndDecodeTransaction(signedTransactionInfo string) (JWSTransactionDecodedPayload, error)
```

Important decoded fields:

| Field | Description |
| --- | --- |
| `TransactionID` | Transaction ID. |
| `OriginalTransactionID` | Original transaction ID for the subscription chain. |
| `BundleID` | App bundle ID. |
| `ProductID` | Purchased product ID. |
| `SubscriptionGroupIdentifier` | Subscription group ID. |
| `PurchaseDate` | Purchase timestamp. |
| `OriginalPurchaseDate` | Original purchase timestamp. |
| `ExpiresDate` | Subscription expiration timestamp. |
| `RevocationReason` | Revocation reason, or `nil`. |
| `RevocationDate` | Revocation timestamp. |
| `Environment` | `Production` or `Sandbox`. |
| `AppAccountToken` | App-side account token associated with the transaction. |

### Decode Renewal Info JWS

```go
renewal, err := verifier.VerifyAndDecodeRenewalInfo(signedRenewalInfo)
if err != nil {
	return err
}

if renewal.AutoRenewStatus != nil && *renewal.AutoRenewStatus == 1 {
	// Auto-renew is enabled.
}
```

Method:

```go
VerifyAndDecodeRenewalInfo(signedRenewalInfo string) (JWSRenewalInfoDecodedPayload, error)
```

Renewal info payloads do not include a bundle ID, so this method validates the
environment but does not perform transaction-style bundle ID validation.

Important fields:

| Field | Description |
| --- | --- |
| `OriginalTransactionID` | Subscription chain ID. |
| `AutoRenewProductID` | Product ID that will renew. |
| `ProductID` | Current product ID. |
| `AutoRenewStatus` | Auto-renew status, or `nil`. |
| `ExpirationIntent` | Expiration reason, or `nil`. |
| `IsInBillingRetryPeriod` | Whether the subscription is in billing retry. |
| `GracePeriodExpiresDate` | Grace period expiration timestamp. |
| `RenewalDate` | Next renewal timestamp. |
| `Environment` | Payload environment. |

### Decode an App Transaction JWS

```go
appTx, err := verifier.VerifyAndDecodeAppTransaction(signedAppTransaction)
if err != nil {
	return err
}

_ = appTx.OriginalApplicationVersion
```

Method:

```go
VerifyAndDecodeAppTransaction(signedAppTransaction string) (JWSAppTransactionDecodedPayload, error)
```

This method verifies the app transaction payload and compares its `BundleID`,
`AppAppleID`, and `ReceiptType` with the verifier options.

### Decode a Notification JWS

App Store Server Notifications V2 request bodies contain a `signedPayload`.
Webhook handlers should verify this payload before trusting any fields.

```go
func handleAppStoreNotification(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SignedPayload string `json:"signedPayload"`
	}

	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	notification, err := verifier.VerifyAndDecodeNotification(body.SignedPayload)
	if err != nil {
		http.Error(w, "invalid signed payload", http.StatusBadRequest)
		return
	}

	switch notification.NotificationType {
	case "DID_RENEW":
		if notification.Data != nil {
			tx, err := verifier.VerifyAndDecodeTransaction(notification.Data.SignedTransactionInfo)
			if err != nil {
				http.Error(w, "invalid transaction", http.StatusBadRequest)
				return
			}
			_ = tx.ProductID
		}
	case "EXPIRED":
		// Run expiration handling.
	}

	w.WriteHeader(http.StatusNoContent)
}
```

Method:

```go
VerifyAndDecodeNotification(signedPayload string) (ResponseBodyV2DecodedPayload, error)
```

The verifier finds notification app identity from one of these fields:

- `Data`
- `Summary`
- `ExternalPurchaseToken`

For `ExternalPurchaseToken`, environment is inferred from the token ID:
`ExternalPurchaseID` values starting with `SANDBOX` are treated as sandbox;
all others are treated as production.

## Error Handling

### APIError

When the App Store Server API returns a non-2xx response, the SDK returns
`*appstore.APIError`.

```go
info, err := client.GetTransactionInfo(ctx, transactionID)
if err != nil {
	var apiErr *appstore.APIError
	if errors.As(err, &apiErr) {
		log.Printf("appstore api failed: status=%d code=%d message=%q body=%s",
			apiErr.StatusCode,
			apiErr.ErrorCode,
			apiErr.Message,
			string(apiErr.Body),
		)
		return err
	}

	return err
}

_ = info
```

`APIError` fields:

| Field | Description |
| --- | --- |
| `StatusCode` | HTTP status code. |
| `ErrorCode` | Numeric `errorCode` from Apple's error body. |
| `Message` | Apple error message. |
| `Body` | Copy of the raw response body. |

### VerificationError

JWS verification failures are returned as `*appstore.VerificationError`.

```go
tx, err := verifier.VerifyAndDecodeTransaction(signedTransactionInfo)
if err != nil {
	var verificationErr *appstore.VerificationError
	if errors.As(err, &verificationErr) {
		switch verificationErr.Status {
		case appstore.InvalidAppIdentifier:
			return fmt.Errorf("wrong app payload: %w", err)
		case appstore.InvalidEnvironment:
			return fmt.Errorf("wrong app store environment: %w", err)
		case appstore.InvalidSignedData:
			return fmt.Errorf("malformed signed payload: %w", err)
		default:
			return fmt.Errorf("untrusted app store payload: %w", err)
		}
	}

	return err
}

_ = tx
```

Verification statuses:

| Status | Meaning |
| --- | --- |
| `VerificationOK` | Reserved for successful verification. It is not returned as an error. |
| `VerificationFailure` | Signature or general verification failure. |
| `RetryableVerificationFailure` | Reserved for retryable verification failures. |
| `InvalidAppIdentifier` | Bundle ID or App Apple ID did not match the expected app. |
| `InvalidEnvironment` | Payload environment did not match the expected environment. |
| `InvalidChainLength` | JWS `x5c` did not contain exactly three certificates. |
| `InvalidCertificate` | Certificate parse, trust, or validity failure. |
| `InvalidSignedData` | JWS format or payload decode failure. |

## End-to-End Example: Entitlement Check by Transaction ID

```go
package billing

import (
	"context"
	"errors"
	"os"
	"time"

	appstore "github.com/marlonjd/app-store-server-library-go"
)

type Entitlement struct {
	ProductID string
	Active   bool
	Expires  time.Time
}

func LoadEntitlement(ctx context.Context, transactionID string) (Entitlement, error) {
	privateKey, err := os.ReadFile(os.Getenv("APPSTORE_PRIVATE_KEY_PATH"))
	if err != nil {
		return Entitlement{}, err
	}

	client, err := appstore.NewClient(appstore.ClientOptions{
		PrivateKeyPEM: string(privateKey),
		KeyID:         os.Getenv("APPSTORE_KEY_ID"),
		IssuerID:      os.Getenv("APPSTORE_ISSUER_ID"),
		BundleID:      "com.example.app",
		Environment:   appstore.EnvironmentProduction,
	})
	if err != nil {
		return Entitlement{}, err
	}

	verifier, err := appstore.NewSignedDataVerifier(appstore.SignedDataVerifierOptions{
		BundleID:    "com.example.app",
		AppAppleID:  1234567890,
		Environment: appstore.EnvironmentProduction,
	})
	if err != nil {
		return Entitlement{}, err
	}

	info, err := client.GetTransactionInfo(ctx, transactionID)
	if err != nil {
		var apiErr *appstore.APIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == 404 {
			return Entitlement{}, nil
		}
		return Entitlement{}, err
	}

	tx, err := verifier.VerifyAndDecodeTransaction(info.SignedTransactionInfo)
	if err != nil {
		return Entitlement{}, err
	}

	expires := time.UnixMilli(tx.ExpiresDate)
	return Entitlement{
		ProductID: tx.ProductID,
		Active:   tx.RevocationDate == 0 && expires.After(time.Now()),
		Expires:  expires,
	}, nil
}
```

## End-to-End Example: Webhook Handler

```go
package billing

import (
	"encoding/json"
	"net/http"

	appstore "github.com/marlonjd/app-store-server-library-go"
)

type AppStoreWebhook struct {
	Verifier *appstore.SignedDataVerifier
}

func (h AppStoreWebhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		SignedPayload string `json:"signedPayload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	notification, err := h.Verifier.VerifyAndDecodeNotification(body.SignedPayload)
	if err != nil {
		http.Error(w, "invalid notification", http.StatusBadRequest)
		return
	}

	if notification.Data != nil && notification.Data.SignedTransactionInfo != "" {
		tx, err := h.Verifier.VerifyAndDecodeTransaction(notification.Data.SignedTransactionInfo)
		if err != nil {
			http.Error(w, "invalid transaction", http.StatusBadRequest)
			return
		}

		// Update entitlement or subscription state in your own system.
		_ = tx.OriginalTransactionID
	}

	if notification.Data != nil && notification.Data.SignedRenewalInfo != "" {
		renewal, err := h.Verifier.VerifyAndDecodeRenewalInfo(notification.Data.SignedRenewalInfo)
		if err != nil {
			http.Error(w, "invalid renewal info", http.StatusBadRequest)
			return
		}

		// Update renewal policy or billing state.
		_ = renewal.RenewalDate
	}

	w.WriteHeader(http.StatusNoContent)
}
```

## Testing and Mocking

`ClientOptions.BaseURL`, `HTTPClient`, and `Now` make client behavior easy to
control in tests.

```go
server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		t.Fatal("missing authorization header")
	}

	switch r.URL.Path {
	case "/inApps/v1/transactions/tx-1":
		_, _ = w.Write([]byte(`{"signedTransactionInfo":"signed"}`))
	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errorCode":4040010,"errorMessage":"not found"}`))
	}
}))
defer server.Close()

client, err := appstore.NewClient(appstore.ClientOptions{
	PrivateKeyPEM: testPrivateKeyPEM,
	KeyID:         "KEY123",
	IssuerID:      "issuer-1",
	BundleID:      "com.example.app",
	Environment:   appstore.EnvironmentSandbox,
	BaseURL:       server.URL,
	Now: func() time.Time {
		return time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	},
})
if err != nil {
	t.Fatal(err)
}
```

`SignedDataVerifierOptions.RootCertificates` can be set to a test root
certificate. When it is empty, the SDK uses its bundled Apple root certificates.

## Security Notes

- Do not log `.p8` private key contents or commit them to source control.
- Verify signed JWS values before using data from API responses.
- Do not trust webhook request bodies after plain JSON decoding; use
  `VerifyAndDecodeNotification`.
- For production, set `BundleID`, `AppAppleID`, and `Environment` together for
  stricter validation.
- Keep sandbox and production client/verifier instances separate to reduce
  operational mistakes.
- `APIError.Body` may contain user or purchase data. Mask it according to your
  logging policy before writing it to logs.

## Public Type Summary

Client and request/response types:

| Type | Usage |
| --- | --- |
| `Environment` | Production and Sandbox environment values. |
| `ClientOptions` | Configuration for `NewClient`. |
| `Client` | App Store Server API methods. |
| `TransactionHistoryRequest` | Transaction history filters. |
| `NotificationHistoryRequest` | Notification history filters. |
| `ConsumptionRequest` | Consumption information request body. |
| `ExtendRenewalDateRequest` | Single-subscription renewal date extension body. |
| `MassExtendRenewalDateRequest` | Mass renewal date extension body. |
| `TransactionInfoResponse` | Transaction lookup response. |
| `AppTransactionInfoResponse` | Signed app transaction response model. |
| `HistoryResponse` | Transaction history response. |
| `StatusResponse` | Subscription status response. |
| `SubscriptionGroupIdentifierItem` | Group item in subscription status responses. |
| `LastTransactionsItem` | Last transaction item in subscription status responses. |
| `RefundHistoryResponse` | Refund history response. |
| `OrderLookupResponse` | Order ID lookup response. |
| `SendTestNotificationResponse` | Test notification create response. |
| `CheckTestNotificationResponse` | Test notification status response. |
| `SendAttemptItem` | Notification send attempt model. |
| `NotificationHistoryResponse` | Notification history response. |
| `NotificationHistoryResponseItem` | Signed payload and send attempt item in notification history. |
| `ExtendRenewalDateResponse` | Single-subscription extension response. |
| `MassExtendRenewalDateResponse` | Mass extension start response. |
| `MassExtendRenewalDateStatusResponse` | Mass extension status response. |
| `APIError` | Non-2xx API response error. |

Verifier and payload types:

| Type | Usage |
| --- | --- |
| `SignedDataVerifierOptions` | Configuration for `NewSignedDataVerifier`. |
| `SignedDataVerifier` | JWS verification and decode methods. |
| `JWSTransactionDecodedPayload` | Transaction JWS payload. |
| `JWSRenewalInfoDecodedPayload` | Renewal info JWS payload. |
| `JWSAppTransactionDecodedPayload` | App transaction JWS payload. |
| `ResponseBodyV2DecodedPayload` | Notification V2 signed payload. |
| `NotificationData` | Notification data section. |
| `NotificationSummary` | Notification summary section. |
| `ExternalPurchaseToken` | External purchase token section. |
| `JWSDecodedHeader` | JWS header model. |
| `VerificationError` | JWS verification error. |
| `VerificationStatus` | Verification error category. |

Root certificate helper:

```go
roots := appstore.DefaultAppleRootCertificates()
verifier, err := appstore.NewSignedDataVerifier(appstore.SignedDataVerifierOptions{
	RootCertificates: roots,
	BundleID:         "com.example.app",
	Environment:      appstore.EnvironmentSandbox,
})
```
