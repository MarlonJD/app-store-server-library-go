package appstore

import "fmt"

type VerificationStatus string

const (
	VerificationOK               VerificationStatus = "OK"
	VerificationFailure          VerificationStatus = "VERIFICATION_FAILURE"
	RetryableVerificationFailure VerificationStatus = "RETRYABLE_VERIFICATION_FAILURE"
	InvalidAppIdentifier         VerificationStatus = "INVALID_APP_IDENTIFIER"
	InvalidEnvironment           VerificationStatus = "INVALID_ENVIRONMENT"
	InvalidChainLength           VerificationStatus = "INVALID_CHAIN_LENGTH"
	InvalidCertificate           VerificationStatus = "INVALID_CERTIFICATE"
	InvalidSignedData            VerificationStatus = "INVALID_SIGNED_DATA"
)

type VerificationError struct {
	Status VerificationStatus
	Err    error
}

func (e *VerificationError) Error() string {
	if e.Err == nil {
		return string(e.Status)
	}
	return fmt.Sprintf("%s: %v", e.Status, e.Err)
}

func (e *VerificationError) Unwrap() error {
	return e.Err
}

func verificationError(status VerificationStatus, err error) error {
	return &VerificationError{Status: status, Err: err}
}

type APIError struct {
	StatusCode int
	ErrorCode  int64
	Message    string
	Body       []byte
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("appstore api status %d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("appstore api status %d", e.StatusCode)
}
