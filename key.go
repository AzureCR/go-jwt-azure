package azure

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault/keyvaultapi"
	"github.com/golang-jwt/jwt"
)

// Key represents a remote key in the Azure Key Vault.
type Key struct {
	Client  keyvaultapi.BaseClientAPI
	Context context.Context

	id           string
	vaultBaseURL string
	name         string
	version      string
}

// NewKey create a remote key referenced by a key identifier.
func NewKey(client keyvaultapi.BaseClientAPI, keyID string) (*Key, error) {
	return NewKeyWithContext(context.Background(), client, keyID)
}

// NewKeyWithContext create a remote key referenced by a key identifier with context.
func NewKeyWithContext(ctx context.Context, client keyvaultapi.BaseClientAPI, keyID string) (*Key, error) {
	keyURL, err := url.Parse(keyID)
	if err != nil {
		return nil, jwt.ErrInvalidKey
	}

	parts := strings.Split(strings.TrimPrefix(keyURL.Path, "/"), "/")
	if len(parts) != 3 {
		return nil, jwt.ErrInvalidKey
	}
	if parts[0] != "keys" {
		return nil, jwt.ErrInvalidKey
	}

	return &Key{
		Client:       client,
		Context:      ctx,
		id:           keyID,
		vaultBaseURL: keyURL.Scheme + "://" + keyURL.Host,
		name:         parts[1],
		version:      parts[2],
	}, nil
}

// Sign signs the message with the algorithm provided.
func (k *Key) Sign(algorithm keyvault.JSONWebKeySignatureAlgorithm, message []byte) ([]byte, error) {
	sig, err := k.signToBase64RawURL(algorithm, message)
	if err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.DecodeString(sig)
}

// signToBase64RawURL signs the message and returns the signature in base64 raw URL form.
func (k *Key) signToBase64RawURL(algorithm keyvault.JSONWebKeySignatureAlgorithm, message []byte) (string, error) {
	digest, err := ComputeHash(algorithm, message)
	if err != nil {
		return "", err
	}
	return k.signDigestToBase64RawURL(algorithm, digest)
}

// SignDigest signs the message digest with the algorithm provided.
func (k *Key) SignDigest(algorithm keyvault.JSONWebKeySignatureAlgorithm, digest []byte) ([]byte, error) {
	sig, err := k.signDigestToBase64RawURL(algorithm, digest)
	if err != nil {
		return nil, err
	}
	return base64.RawURLEncoding.DecodeString(sig)
}

// signDigestToBase64RawURL signs the message digest and returns the signature in base64 raw URL form.
func (k *Key) signDigestToBase64RawURL(algorithm keyvault.JSONWebKeySignatureAlgorithm, digest []byte) (string, error) {
	// Prepare the message
	value := base64.RawURLEncoding.EncodeToString(digest)

	// Sign the message
	res, err := k.Client.Sign(
		k.Context,
		k.vaultBaseURL,
		k.name,
		k.version,
		keyvault.KeySignParameters{
			Algorithm: algorithm,
			Value:     &value,
		},
	)
	if err != nil {
		return "", err
	}

	// Verify the result
	if res.Kid == nil || *res.Kid != k.id {
		return "", ErrMismatchResponseKeyID
	}
	if res.Result == nil {
		return "", ErrInvalidServerResponse
	}
	return *res.Result, nil
}

// Verify verifies the message  with the algorithm provided against the signature.
func (k *Key) Verify(algorithm keyvault.JSONWebKeySignatureAlgorithm, message, signature []byte) error {
	digest, err := ComputeHash(algorithm, message)
	if err != nil {
		return err
	}
	return k.VerifyDigest(algorithm, digest, signature)
}

// VerifyDigest verifies the message digest with the algorithm provided against the signature.
func (k *Key) VerifyDigest(algorithm keyvault.JSONWebKeySignatureAlgorithm, digest, signature []byte) error {
	// Prepare for verification
	encodedDigest := base64.RawURLEncoding.EncodeToString(digest)
	encodedSignature := base64.RawURLEncoding.EncodeToString(signature)

	// Verify the message digest
	res, err := k.Client.Verify(
		k.Context,
		k.vaultBaseURL,
		k.name,
		k.version,
		keyvault.KeyVerifyParameters{
			Algorithm: algorithm,
			Digest:    &encodedDigest,
			Signature: &encodedSignature,
		},
	)
	if err != nil {
		return err
	}
	if res.Value == nil {
		return ErrInvalidServerResponse
	}
	if valid := *res.Value; !valid {
		return ErrVerification
	}
	return nil
}
