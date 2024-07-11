package jwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"slices"
	"strings"
)

var (
	ErrSignatureNoKey   = errors.New("unable to find a key for this signature: either it was not provided or it was not recovered from the information in the JWT")
	ErrSignatureNetwork = errors.New("request error when fetching discovery document of jwk set")
	ErrUnsupportedAlg   = errors.New("the given signature algorithm is not supported")
)

var suppAlg = []string{
	"RS256", "none",
}

type headModel struct {
	Kid string `json:"kid"`
	Alg string `json:"alg"`
}

// claimsModel is the minimum claims set required to obtain a signature
type claimsModel struct {
	Iss string `json:"iss"`
}

type discoveryDocumentModel struct {
	JWKSUri string `json:"jwks_uri"`
}

type PublicRSAModel struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	E   string `json:"e"`
	N   string `json:"n"`
}

type PublicESModel struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	// EC: public
	Crv string `json:"crv"` // either: P-256, P-384, P-521
	X   string `json:"x"`
	Y   string `json:"y"`
}

type jwksModel struct {
	// Non RSA Keys are currently not supported
	Keys []JwkSignatureKeysModel `json:"keys"`
}

// JwkSignatureKeysModel is a polymorphic model whose full interpretation depends on the "use" and "alg".
// Moreover, the same "use" and "alg" might have multiple interpretations if, say, the key
// includes both private and public information or just public information.
type JwkSignatureKeysModel struct {
	Kty    string `json:"kty"` // either: EC, RSA, oth
	Use    string `json:"use"` // must be "sign"
	KeyOps string `json:"key_ops"`
	Alg    string `json:"alg"`
	Kid    string `json:"kid"`
	X5u    string `json:"x5u"` // x509 url: where to download a public key certificate or certificate chain
	X5c    string `json:"x5c"` // contains a chain of one or more PKIX certificates
	X5t    string `json:"x5t"` // certificate SHA-1 thumbprint
	// RSA: public
	E string `json:"e"`
	N string `json:"n"`
	// RSA: private ("oth" not supported)
	D  string `json:"d"`
	P  string `json:"p"`
	DP string `json:"dp"`
	DQ string `json:"dq"`
	QI string `json:"qi"`
	// EC: public
	Crv string `json:"crv"` // either: P-256, P-384, P-521
	X   string `json:"x"`
	Y   string `json:"y"`
	// Oth
	OthK string `json:"k"` // base64url encoding of the octet sequence
}

func keyToRSAPublicKey(k JwkSignatureKeysModel) PublicRSAModel {
	return PublicRSAModel{
		Kty: k.Kty,
		Use: k.Use,
		Alg: k.Alg,
		Kid: k.Kid,
		E:   k.E,
		N:   k.N,
	}
}

func keyToESPublicKey(k JwkSignatureKeysModel) PublicESModel {
	return PublicESModel{
		Kty: k.Kty,
		Use: k.Use,
		Alg: k.Alg,
		Kid: k.Kid,
		Crv: k.Crv,
		X:   k.X,
		Y:   k.Y,
	}
}

func (s *PublicRSAModel) toKey() (*rsa.PublicKey, error) {
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

func (s *PublicESModel) toKey() (*ecdsa.PublicKey, error) {
	dataX, err := base64.RawURLEncoding.DecodeString(s.X)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base point coordinate X: %w", err)
	}
	x := new(big.Int)
	x.SetBytes(dataX)
	dataY, err := base64.RawURLEncoding.DecodeString(s.Y)
	if err != nil {
		return nil, fmt.Errorf("failed to parse base point coordinate Y: %w", err)
	}
	y := new(big.Int)
	y.SetBytes(dataY)

	switch s.Crv {
	case "P-256":
		return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
	case "P-384":
		return &ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}, nil
	case "P-521":
		return &ecdsa.PublicKey{Curve: elliptic.P384(), X: x, Y: y}, nil
	default:
		return nil, errors.New("invalid curve type")
	}
}

func isAlgSupported(alg string) bool {
	return slices.Contains(suppAlg, alg)
}

func wellKnownEndpoint(iss string) string {
	return strings.ReplaceAll(iss, `\/`, `/`) + "/.well-known/openid-configuration"
}

// requestPublicJWKS obtained public jwksModel key sets using information
// available in the jwt. This requires a two-round network call, in particular
//  1. Obtain the iss claims from jwt
//  2. Make an HTTP request to obtain oidc discovery document, usually
//     formatted as iss + /.well-known/oidc-configuration
//  3. Obtain jwks_uri from discovery document
//  4. Make an HTTP request to obtain the key set
//  5. Parse the JKWS
//
// Note that we are not technically guaranteed to obtain the required jwksModel.
// For example, authorization server that originally issued the jwt might since
// then rotated or changed its jwksModel. In this case, the signature should be
// considered invalid, as this implies that signing key is not to be
// trusted.
func requestPublicJWKS(j *Jwt) (*jwksModel, error) {
	// 1. Extract iss
	var claims claimsModel
	if err := json.Unmarshal([]byte(j.ClaimsSet), &claims); err != nil {
		return nil, fmt.Errorf("%w : %w", ErrSignatureNoKey, err)
	}
	// 2. obtain discovery document
	req, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, wellKnownEndpoint(claims.Iss), nil)
	if err != nil {
		return nil, fmt.Errorf("%w : %w", ErrSignatureNetwork, err)
	}
	res, err := new(http.Client).Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w : %w", ErrSignatureNetwork, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: not a 200 response in discovery document %s, instead %d", ErrSignatureNetwork, wellKnownEndpoint(claims.Iss), res.StatusCode)
	}
	docBody, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("%w : %w", ErrSignatureNetwork, err)
	}
	// 3. parse discovery document
	var doc discoveryDocumentModel
	if err = json.Unmarshal(docBody, &doc); err != nil {
		return nil, fmt.Errorf("%w: error in parsing discovery document", ErrSignatureNoKey)
	}
	// 4. obtain jwksModel
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
	// 5. parse jwksModel
	var keys jwksModel
	if err = json.Unmarshal(keyBody, &keys); err != nil {
		return nil, fmt.Errorf("%w: failed to parse issuer keys", ErrSignatureNoKey)
	}
	return &keys, nil
}

func matchKey(keys []JwkSignatureKeysModel, kid string) (JwkSignatureKeysModel, error) {
	if keys == nil {
		return JwkSignatureKeysModel{}, ErrSignatureNoKey
	}
	for _, key := range keys {
		if key.Kid == kid {
			return key, nil
		}
	}
	return JwkSignatureKeysModel{}, ErrSignatureNoKey
}

func PKCStore(j *Jwt) ([]JwkSignatureKeysModel, error) {
	keys, err := requestPublicJWKS(j)
	if err != nil {
		return nil, err
	}
	return keys.Keys, nil
}

// VerifySignature checks if signature is valid.
// The function currently assumed that the token is an OIDC id token and
// only RS256 signature is supported.
// This information is used to fetch the public key that validates the
// signature.
func VerifySignature(jws string, keyStore []JwkSignatureKeysModel) (bool, error) {
	j, err := ParseJwt(jws)
	if err != nil {
		return false, errors.New("not a jwt")
	}
	var head headModel
	if err := json.Unmarshal([]byte(j.Head), &head); err != nil {
		return false, fmt.Errorf("unsupported head information")
	}
	if !isAlgSupported(head.Alg) {
		return false, ErrUnsupportedAlg
	}

	// special case: no signature to verify
	if head.Alg == "none" {
		return true, nil
	}
	key, err := matchKey(keyStore, head.Kid)
	if err != nil {
		return false, err
	}
	var message []byte
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return false, errors.New("not a jws")
	}
	message = []byte(parts[0] + "." + parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(j.Signature)
	if err != nil {
		return false, errors.New("failed to parse jwt signature")
	}
	return verifyWithKey(message, sig, key)
}

func verifyWithKey(message []byte, sig []byte, key JwkSignatureKeysModel) (bool, error) {
	switch key.Alg {
	case "RS256":
		pk := keyToRSAPublicKey(key)
		return verifyRS256(message, sig, pk)
	case "RS384":
		pk := keyToRSAPublicKey(key)
		return verifyRS384(message, sig, pk)
	case "RS512":
		pk := keyToRSAPublicKey(key)
		return verifyRS512(message, sig, pk)
	case "ES256":
		pk := keyToESPublicKey(key)
		return verifyES256(message, sig, pk)
	case "ES384":
		pk := keyToESPublicKey(key)
		return verifyES384(message, sig, pk)
	case "ES512":
		pk := keyToESPublicKey(key)
		return verifyES512(message, sig, pk)
	default:
		return false, ErrSignatureNoKey
	}
}

func verifyRS256(message []byte, sig []byte, pkm PublicRSAModel) (bool, error) {
	pk, err := pkm.toKey()
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256(message)
	err = rsa.VerifyPKCS1v15(pk, crypto.SHA256, digest[:], sig)
	if err != nil {
		return false, err // NOTE: this is of type ErrVerification
	}
	return true, nil
}

func verifyRS384(message []byte, sig []byte, pkm PublicRSAModel) (bool, error) {
	pk, err := pkm.toKey()
	if err != nil {
		return false, err
	}
	digest := sha512.Sum384(message)
	err = rsa.VerifyPKCS1v15(pk, crypto.SHA256, digest[:], sig)
	if err != nil {
		return false, err // NOTE: this is of type ErrVerification
	}
	return true, nil
}

func verifyRS512(message []byte, sig []byte, pkm PublicRSAModel) (bool, error) {
	pk, err := pkm.toKey()
	if err != nil {
		return false, err
	}
	digest := sha512.Sum512(message)
	err = rsa.VerifyPKCS1v15(pk, crypto.SHA256, digest[:], sig)
	if err != nil {
		return false, err // NOTE: this is of type ErrVerification
	}
	return true, nil
}

func parseESSignature(sig []byte) (r *big.Int, s *big.Int, err error) {
	if len(sig) != 64 {
		err = errors.New("invalid ES signature format")
		return
	}
	r = new(big.Int)
	r.SetBytes(sig[:32])
	s = new(big.Int)
	s.SetBytes(sig[32:])
	return
}

func verifyES256(message []byte, sig []byte, pkm PublicESModel) (bool, error) {
	pk, err := pkm.toKey()
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256(message)
	r, s, err := parseESSignature(sig)
	if err != nil {
		return false, err
	}
	if ok := ecdsa.Verify(pk, digest[:], r, s); !ok {
		return false, errors.New("verification error of ECDSA signature")
	}
	return true, nil
}

func verifyES384(message []byte, sig []byte, pkm PublicESModel) (bool, error) {
	pk, err := pkm.toKey()
	if err != nil {
		return false, err
	}
	digest := sha512.Sum384(message)
	r, s, err := parseESSignature(sig)
	if err != nil {
		return false, err
	}
	if ok := ecdsa.Verify(pk, digest[:], r, s); !ok {
		return false, errors.New("verification error of ECDSA signature")
	}
	return true, nil
}

func verifyES512(message []byte, sig []byte, pkm PublicESModel) (bool, error) {
	pk, err := pkm.toKey()
	if err != nil {
		return false, err
	}
	digest := sha512.Sum512(message)
	r, s, err := parseESSignature(sig)
	if err != nil {
		return false, err
	}
	if ok := ecdsa.Verify(pk, digest[:], r, s); !ok {
		return false, errors.New("verification error of ECDSA signature")
	}
	return true, nil
}
