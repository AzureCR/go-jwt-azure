package azure

import "errors"

var (
	ErrInvalidServerResponse = errors.New("azure: invalid server response")
	ErrMismatchResponseKeyID = errors.New("azure: response key id mismatch")
	ErrUnsupportedAlgorithm  = errors.New("azure: unsupported algorithm")
	ErrVerification          = errors.New("azure: verification error")
)
