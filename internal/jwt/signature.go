package jwt

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
)

var (
	ErrSignatureNoKey   = errors.New("unable to find a key for this signature: either it was not provided or it was recovered from the information in the JWT")
	ErrSignatureNetwork = errors.New("request error when fetching discovery document of jwk set")
	ErrUnsupportedAlg   = errors.New("the given signature algorithm is not supported")
)

type requiredHead struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

// requiredClaims is the minimum claims set required to obtain a signature
type requiredClaims struct {
	Iss string `json:"iss"`
}

type discoveryDocument struct {
	JWKSUri string `json:"jwks_uri"`
}

type RSASet struct {
	Kty string `json:"kty"`
	E   string `json:"e"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
}

func (s *RSASet) toKey() (*rsa.PublicKey, error) {
	dataE, err := base64.RawURLEncoding.DecodeString(s.E)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public exponent e: %w", err)
	}
	e := new(big.Int)
	e.SetBytes(dataE) // big endian
	if e.Int64() >= (1 << 30) {
		return nil, fmt.Errorf("failed to read public exponent e: public exponent is too big")
	}

	dataN, err := base64.RawURLEncoding.DecodeString(s.N)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public modulus N: %w", err)
	}
	n := new(big.Int)
	n.SetBytes(dataN) // big endian

	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

type issKeys struct {
	// Non RSA Keys are currently not supported
	Keys []RSASet `json:"keys"`
}

func isAlgSupported(alg string) bool {
	if alg == "RS256" {
		return true
	}
	return false
}

// requestPublicJWKS obtained public jwks key sets using information
// available in the jwt. This requires a two-round network call, in particular
//  1. Obtain the iss claims from jwt
//  2. Make an HTTP request to obtain oidc discovery document, usually
//     formatted as iss + /.well-known/oidc-configuration
//  3. Obtain jwks_uri from discovery document
//  4. Make an HTTP request to obtain the key set
//  5. Parse the JKWS
//
// Note that we are not technically guaranteed to obtain the required jwks.
// For example, authorization server that originally issued the jwt might since
// then rotated or changed its jwks. In this case, the signature should be
// considered invalid, as this implies that signing key is not to be
// trusted.
func requestPublicJWKS(j *Jwt) (*issKeys, error) {
	// 1. Extract iss
	var claims requiredClaims
	if err := json.Unmarshal([]byte(j.ClaimsSet), &claims); err != nil {
		return nil, fmt.Errorf("%w : %w", ErrSignatureNoKey, err)
	}
	// 2. obtain discovery document
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, claims.Iss+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, fmt.Errorf("%w : %w", ErrSignatureNetwork, err)
	}
	res, err := new(http.Client).Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w : %w", ErrSignatureNetwork, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: not a 200 response in discovery document", ErrSignatureNetwork)
	}
	docBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("%w : %w", ErrSignatureNetwork, err)
	}
	// 3 parse discovery document
	var doc discoveryDocument
	if err = json.Unmarshal(docBody, &doc); err != nil {
		return nil, fmt.Errorf("%w: error in parsing discovery document", ErrSignatureNoKey)
	}
	// 4 obtain jwks
	reqKey, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, doc.JWKSUri, nil)
	if err != nil {
		return nil, fmt.Errorf("%w : %w", ErrSignatureNetwork, err)
	}
	resKey, err := new(http.Client).Do(reqKey)
	if err != nil {
		return nil, fmt.Errorf("%w : %w", ErrSignatureNetwork, err)
	}
	defer resKey.Body.Close()
	if resKey.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: not a 200 response in discovery document", ErrSignatureNetwork)
	}
	keyBody, err := io.ReadAll(resKey.Body)
	if err != nil {
		return nil, fmt.Errorf("%w : %w", ErrSignatureNetwork, err)
	}
	// 5 parse jwks
	var keys issKeys
	if err = json.Unmarshal(keyBody, &keys); err != nil {
		return nil, fmt.Errorf("%w: failed to parse issuer keys", ErrSignatureNoKey)
	}
	return &keys, nil
}

// VerifySignature checks if signature is valid.
// The function currently assumed that the token is an OIDC id token and
// only RS256 signature is supported.
// This information is used to fetch the public key that validates the
// signature.
func VerifySignature(jws string) (bool, error) {
	j, err := ParseJwt(jws)
	if err != nil {
		return false, errors.New("not a jwt")
	}
	var head requiredHead
	if err := json.Unmarshal([]byte(j.Head), &head); err != nil {
		return false, fmt.Errorf("unsupported head information")
	}
	if !isAlgSupported(head.Alg) {
		return false, ErrUnsupportedAlg
	}

	keys, err := requestPublicJWKS(j)
	if err != nil {
		return false, err
	}
	var pk *rsa.PublicKey
	for _, key := range keys.Keys {
		if key.Kid == head.Kid {
			pk, err = key.toKey()
			if err != nil {
				return false, fmt.Errorf("failed to parse public key: %w", err)
			}
		}
	}

	// validate signature
	sig, err := base64.RawURLEncoding.DecodeString(j.Signature)
	if err != nil {
		return false, errors.New("failed to parse jwt signature")
	}

	// recover that is signed
	var message []byte
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return false, errors.New("not a jws")
	}
	message = []byte(parts[0] + "." + parts[1])
	digest := sha256.Sum256(message)
	err = rsa.VerifyPKCS1v15(pk, crypto.SHA256, digest[:], sig)
	if err != nil {
		return false, err // NOTE: this is of type ErrVerification
	}
	return true, nil
}
