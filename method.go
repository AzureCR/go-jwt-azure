package azure

import (
	"encoding/base64"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/golang-jwt/jwt"
)

// SigningMethod for Azure Key Vault.
type SigningMethod struct {
	algorithm keyvault.JSONWebKeySignatureAlgorithm
}

// Alg identifies the signing / verification algorithm.
// For more information on possible algorithm types,
// see https://docs.microsoft.com/en-us/rest/api/keyvault/sign/sign#jsonwebkeysignaturealgorithm
func (m *SigningMethod) Alg() string {
	return string(m.algorithm)
}

// Sign signs the signing string remotely.
func (m *SigningMethod) Sign(signingString string, key interface{}) (string, error) {
	// Check the key
	k, ok := key.(*Key)
	if !ok {
		return "", jwt.ErrInvalidKeyType
	}

	// Sign the string
	sig, err := k.Sign(m.algorithm, []byte(signingString))
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}

// Verify verifies the singing string against the signature remotely.
func (m *SigningMethod) Verify(signingString, signature string, key interface{}) error {
	// Check the key
	k, ok := key.(*Key)
	if !ok {
		return jwt.ErrInvalidKeyType
	}

	// Verify the string
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return err
	}
	return k.Verify(m.algorithm, []byte(signingString), sig)
}
