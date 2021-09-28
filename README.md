# go-jwt-azure
jwt-go signing methods backed by Azure Key Vault

## Example

```go
package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault"
	"github.com/Azure/azure-sdk-for-go/services/keyvault/v7.1/keyvault/keyvaultapi"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/adal"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/golang-jwt/jwt/v4"
	jwtazure "github.com/shizhMSFT/go-jwt-azure"
)

func main() {
	// Extract parameters
	if len(os.Args) != 5 {
		fmt.Println("usage:", os.Args[0], "<tenant_id> <client_id> <secret> <key_id>")
		os.Exit(1)
	}
	tid := os.Args[1]
	cid := os.Args[2]
	secret := os.Args[3]
	kid := os.Args[4] // example: https://<keyvault_name>.vault.azure.net/keys/<name>/<version>

	// Get remote key
	client, err := getClient(tid, cid, secret)
	fail(err)
	key, err := jwtazure.NewKey(client, kid)
	fail(err)

	// Generate a JWT token
	token := jwt.NewWithClaims(jwtazure.SigningMethodPS512, jwt.MapClaims{
		"sub": "demo",
	})
	serialized, err := token.SignedString(key)
	fail(err)

	// Print the serialized token
	fmt.Println(serialized)

	// Parse and verify the token locally
	cert, err := key.Certificate()
	fail(err)
	_, err = jwt.Parse(serialized, func(token *jwt.Token) (interface{}, error) {
		if alg := token.Method.Alg(); alg != jwt.SigningMethodPS512.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", alg)
		}
		return cert.PublicKey, nil
	})
	fail(err)

	// Parse and verify the token remotely
	jwt.RegisterSigningMethod(jwtazure.SigningMethodPS512.Alg(), func() jwt.SigningMethod {
		return jwtazure.SigningMethodPS512
	})
	_, err = jwt.Parse(serialized, func(token *jwt.Token) (interface{}, error) {
		if alg := token.Method.Alg(); alg != jwtazure.SigningMethodPS512.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", alg)
		}
		return key, nil
	})
	fail(err)
}

func getClient(tenantID, clientID, secret string) (keyvaultapi.BaseClientAPI, error) {
	azureEnv := azure.PublicCloud
	oauthConfig, err := adal.NewOAuthConfig(azureEnv.ActiveDirectoryEndpoint, tenantID)
	if err != nil {
		return nil, err
	}
	spToken, err := adal.NewServicePrincipalToken(*oauthConfig, clientID, secret, strings.TrimSuffix(azureEnv.KeyVaultEndpoint, "/"))
	if err != nil {
		return nil, err
	}

	client := keyvault.New()
	client.Authorizer = autorest.NewBearerAuthorizer(spToken)
	return client, nil
}

func fail(err error) {
	if err != nil {
		panic(err)
	}
}
```

The above code outputs:

```
eyJhbGciOiJQUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkZW1vIn0.iXopV96iaVk4i2_FefAr6v99LCdlSvjeiPGVUlwxX-9-Oo5MJIzqAtITbF30biuNrFeQs-nT_LD3yW85wuZXtAvtq1GQLEEUgbB7_RKgb04UGFne5keCaKuKeIzXVubF4-R9qrVnuyb9Igvu7eg_RdXm-Cr1V3OHEy49AlvKV3iDjam1_iChTZe2FywWcemjDK-0UBMRRxQDgdJuullkBwmtmPriaspF3Y3DSA7nZNGnHdkshrNPaImYo_uIRvuElToRCldD6XBUI5Czu1ax9rUR5VPw7kinF_RL-ETKu0H2mMaUnlKr6iI4yP4xjXdXBIuNpKs-VVOJkwkjRrhn4Q
```

The JWS compact object in the output can be pretty printed as

```json
{
  "alg": "PS512",
  "typ": "JWT"
}.{
  "sub": "demo"
}.[Signature]
```
