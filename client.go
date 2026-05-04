package appstore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	ProductionBaseURL = "https://api.storekit.itunes.apple.com"
	SandboxBaseURL    = "https://api.storekit-sandbox.itunes.apple.com"
)

type ClientOptions struct {
	PrivateKeyPEM string
	KeyID         string
	IssuerID      string
	BundleID      string
	Environment   Environment
	BaseURL       string
	HTTPClient    *http.Client
	TokenTTL      time.Duration
	Now           func() time.Time
}

type Client struct {
	key        *ecdsa.PrivateKey
	keyID      string
	issuerID   string
	bundleID   string
	baseURL    *url.URL
	httpClient *http.Client
	tokenTTL   time.Duration
	now        func() time.Time
}

func NewClient(opts ClientOptions) (*Client, error) {
	if opts.KeyID == "" || opts.IssuerID == "" || opts.BundleID == "" {
		return nil, errors.New("key id, issuer id, and bundle id are required")
	}
	key, err := parseECDSAPrivateKey([]byte(opts.PrivateKeyPEM))
	if err != nil {
		return nil, err
	}
	tokenTTL := opts.TokenTTL
	if tokenTTL == 0 {
		tokenTTL = 20 * time.Minute
	}
	if tokenTTL > time.Hour {
		return nil, errors.New("token ttl must not exceed one hour")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	base := opts.BaseURL
	if base == "" {
		base = baseURLForEnvironment(opts.Environment)
	}
	parsed, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	return &Client{
		key:        key,
		keyID:      opts.KeyID,
		issuerID:   opts.IssuerID,
		bundleID:   opts.BundleID,
		baseURL:    parsed,
		httpClient: httpClient,
		tokenTTL:   tokenTTL,
		now:        now,
	}, nil
}

func baseURLForEnvironment(environment Environment) string {
	if environment == EnvironmentSandbox {
		return SandboxBaseURL
	}
	return ProductionBaseURL
}

func parseECDSAPrivateKey(raw []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("private key PEM is invalid")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		ecdsaKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key must be ECDSA")
		}
		return ecdsaKey, nil
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (c *Client) CreateToken(now time.Time) (string, error) {
	if now.IsZero() {
		now = c.now()
	}
	header := map[string]string{
		"alg": "ES256",
		"kid": c.keyID,
		"typ": "JWT",
	}
	payload := map[string]any{
		"iss": c.issuerID,
		"iat": now.Unix(),
		"exp": now.Add(c.tokenTTL).Unix(),
		"aud": "appstoreconnect-v1",
		"bid": c.bundleID,
	}
	return signJWT(c.key, header, payload)
}

func signJWT(key *ecdsa.PrivateKey, header map[string]string, payload map[string]any) (string, error) {
	headerRaw, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	payloadRaw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signingInput := base64.RawURLEncoding.EncodeToString(headerRaw) + "." + base64.RawURLEncoding.EncodeToString(payloadRaw)
	sum := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", err
	}
	size := (key.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, size*2)
	r.FillBytes(sig[:size])
	s.FillBytes(sig[size:])
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (c *Client) GetTransactionInfo(ctx context.Context, transactionID string) (TransactionInfoResponse, error) {
	var out TransactionInfoResponse
	err := c.do(ctx, http.MethodGet, "/inApps/v1/transactions/"+url.PathEscape(transactionID), nil, nil, &out)
	return out, err
}

func (c *Client) GetTransactionHistory(ctx context.Context, transactionID string, revision string, request *TransactionHistoryRequest) (HistoryResponse, error) {
	query := url.Values{}
	if revision != "" {
		query.Set("revision", revision)
	}
	if request != nil {
		request.apply(query)
	}
	var out HistoryResponse
	err := c.do(ctx, http.MethodGet, "/inApps/v2/history/"+url.PathEscape(transactionID), query, nil, &out)
	return out, err
}

type TransactionHistoryRequest struct {
	StartDate                    int64
	EndDate                      int64
	ProductIDs                   []string
	ProductTypes                 []string
	Revoked                      *bool
	SubscriptionGroupIdentifiers []string
	InAppOwnershipType           string
	Sort                         string
}

func (r TransactionHistoryRequest) apply(query url.Values) {
	if r.StartDate != 0 {
		query.Set("startDate", strconv.FormatInt(r.StartDate, 10))
	}
	if r.EndDate != 0 {
		query.Set("endDate", strconv.FormatInt(r.EndDate, 10))
	}
	for _, value := range r.ProductIDs {
		query.Add("productId", value)
	}
	for _, value := range r.ProductTypes {
		query.Add("productType", value)
	}
	for _, value := range r.SubscriptionGroupIdentifiers {
		query.Add("subscriptionGroupIdentifier", value)
	}
	if r.Revoked != nil {
		query.Set("revoked", strconv.FormatBool(*r.Revoked))
	}
	if r.InAppOwnershipType != "" {
		query.Set("inAppOwnershipType", r.InAppOwnershipType)
	}
	if r.Sort != "" {
		query.Set("sort", r.Sort)
	}
}

func (c *Client) GetAllSubscriptionStatuses(ctx context.Context, anyTransactionID string, statuses ...int64) (StatusResponse, error) {
	query := url.Values{}
	for _, status := range statuses {
		query.Add("status", strconv.FormatInt(status, 10))
	}
	var out StatusResponse
	err := c.do(ctx, http.MethodGet, "/inApps/v1/subscriptions/"+url.PathEscape(anyTransactionID), query, nil, &out)
	return out, err
}

func (c *Client) GetRefundHistory(ctx context.Context, transactionID string, revision string) (RefundHistoryResponse, error) {
	query := url.Values{}
	if revision != "" {
		query.Set("revision", revision)
	}
	var out RefundHistoryResponse
	err := c.do(ctx, http.MethodGet, "/inApps/v2/refund/lookup/"+url.PathEscape(transactionID), query, nil, &out)
	return out, err
}

func (c *Client) GetNotificationHistory(ctx context.Context, request NotificationHistoryRequest, paginationToken string) (NotificationHistoryResponse, error) {
	query := url.Values{}
	if paginationToken != "" {
		query.Set("paginationToken", paginationToken)
	}
	var out NotificationHistoryResponse
	err := c.do(ctx, http.MethodPost, "/inApps/v1/notifications/history", query, request, &out)
	return out, err
}

func (c *Client) RequestTestNotification(ctx context.Context) (SendTestNotificationResponse, error) {
	var out SendTestNotificationResponse
	err := c.do(ctx, http.MethodPost, "/inApps/v1/notifications/test", nil, nil, &out)
	return out, err
}

func (c *Client) GetTestNotificationStatus(ctx context.Context, testNotificationToken string) (CheckTestNotificationResponse, error) {
	var out CheckTestNotificationResponse
	err := c.do(ctx, http.MethodGet, "/inApps/v1/notifications/test/"+url.PathEscape(testNotificationToken), nil, nil, &out)
	return out, err
}

func (c *Client) SendConsumptionInformation(ctx context.Context, transactionID string, request ConsumptionRequest) error {
	return c.do(ctx, http.MethodPut, "/inApps/v1/transactions/consumption/"+url.PathEscape(transactionID), nil, request, nil)
}

func (c *Client) ExtendRenewalDate(ctx context.Context, originalTransactionID string, request ExtendRenewalDateRequest) (ExtendRenewalDateResponse, error) {
	var out ExtendRenewalDateResponse
	err := c.do(ctx, http.MethodPut, "/inApps/v1/subscriptions/extend/"+url.PathEscape(originalTransactionID), nil, request, &out)
	return out, err
}

func (c *Client) ExtendRenewalDateForAllActiveSubscribers(ctx context.Context, request MassExtendRenewalDateRequest) (MassExtendRenewalDateResponse, error) {
	var out MassExtendRenewalDateResponse
	err := c.do(ctx, http.MethodPost, "/inApps/v1/subscriptions/extend/mass", nil, request, &out)
	return out, err
}

func (c *Client) GetStatusOfSubscriptionRenewalDateExtensions(ctx context.Context, productID, requestIdentifier string) (MassExtendRenewalDateStatusResponse, error) {
	var out MassExtendRenewalDateStatusResponse
	path := "/inApps/v1/subscriptions/extend/mass/" + url.PathEscape(productID) + "/" + url.PathEscape(requestIdentifier)
	err := c.do(ctx, http.MethodGet, path, nil, nil, &out)
	return out, err
}

func (c *Client) LookUpOrderID(ctx context.Context, orderID string) (OrderLookupResponse, error) {
	var out OrderLookupResponse
	err := c.do(ctx, http.MethodGet, "/inApps/v1/lookup/"+url.PathEscape(orderID), nil, nil, &out)
	return out, err
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body any, out any) error {
	endpoint := *c.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + path
	if len(query) > 0 {
		endpoint.RawQuery = query.Encode()
	}
	var bodyReader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	token, err := c.CreateToken(c.now())
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	res, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	if err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return parseAPIError(res.StatusCode, raw)
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("decode appstore response: %w", err)
	}
	return nil
}

func parseAPIError(status int, raw []byte) error {
	var body struct {
		ErrorCode    int64  `json:"errorCode"`
		ErrorMessage string `json:"errorMessage"`
		Error        struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	_ = json.Unmarshal(raw, &body)
	message := body.ErrorMessage
	if message == "" {
		message = body.Error.Message
	}
	return &APIError{
		StatusCode: status,
		ErrorCode:  body.ErrorCode,
		Message:    message,
		Body:       append([]byte(nil), raw...),
	}
}
