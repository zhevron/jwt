// Package jwt provides an implementation JSON Web Tokens.
package jwt

import (
	"errors"

	"github.com/zhevron/jwt/ecdsa"
	"github.com/zhevron/jwt/hmac"
	"github.com/zhevron/jwt/rsa"
)

// Signer is used by the signing packages to sign tokens.
// You can use this type to implement your own signing and verification.
type Signer func(string, interface{}) (string, error)

// Verifier is used by the signing packages to verify signatures.
// You can use this type to implement your own signing and verification.
type Verifier func(string, string, interface{}) error

// signingPair is used for internal mapping of signing/verifying functions.
type signingPair struct {
	Signer   Signer
	Verifier Verifier
}

// Type is used to define the type of token.
type Type string

const (
	// JWT represents the JSON Web Token type.
	JWT Type = "JWT"
)

// Algorithm is used to define the encryption algorithm used for the token.
type Algorithm string

const (
	// None represents an unsecured JWT.
	None Algorithm = "none"

	// HS256 represents the HMAC SHA-256 algorithm.
	HS256 Algorithm = "HS256"

	// HS384 represents the HMAC SHA-384 algorithm.
	HS384 Algorithm = "HS384"

	// HS512 represents the HMAC SHA-512 algorithm.
	HS512 Algorithm = "HS512"

	// RS256 represents the RSA SHA-256 algorithm.
	RS256 Algorithm = "RS256"

	// RS384 represents the RSA SHA-384 algorithm.
	RS384 Algorithm = "RS384"

	// RS512 represents the RSA SHA-512 algorithm.
	RS512 Algorithm = "RS512"

	// ES256 represents the ECDSA SHA-256 algorithm.
	ES256 Algorithm = "ES256"

	// ES384 represents the ECDSA SHA-384 algorithm.
	ES384 Algorithm = "ES384"

	// ES512 represents the ECDSA SHA-512 algorithm.
	ES512 Algorithm = "ES512"
)

var (
	// ErrInvalidAlgorithm is returned when the algorithm is not set.
	ErrInvalidAlgorithm = errors.New("jwt: invalid algorithm")

	// ErrInvalidAudience is returned when the audience cannot be verified.
	ErrInvalidAudience = errors.New("jwt: invalid audience")

	// ErrInvalidIssuer is returned when the issuer cannot be verified.
	ErrInvalidIssuer = errors.New("jwt: invalid issuer")

	// ErrInvalidSubject is returned when the subject cannot be verified.
	ErrInvalidSubject = errors.New("jwt: invalid subject")

	// ErrInvalidToken is returned when the token structure is invalid.
	ErrInvalidToken = errors.New("jwt: invalid token")

	// ErrReservedClaim is returned when the user data contains a reserved claim.
	ErrReservedClaim = errors.New("jwt: reserved claim used")

	// ErrTokenExpired is returned when the token has expired.
	ErrTokenExpired = errors.New("jwt: token expired")

	// ErrTokenNotValidYet is returned when the token is not valid yet.
	ErrTokenNotValidYet = errors.New("jwt: token not valid yet")

	// ErrUnsupportedAlgorithm is returned when the algorithm isn't implemented.
	ErrUnsupportedAlgorithm = errors.New("jwt: unsupported algorithm")

	// ErrUnsupportedTokenType is returned when an unsupported token type is used.
	ErrUnsupportedTokenType = errors.New("jwt: unsupported token type")

	// ErrNoneAlgorithmWithSecret is returned when the "none" algorithm is used with a secret.
	ErrNoneAlgorithmWithSecret = errors.New("jwt: none algorithm with secret")

	// ErrNoKeyProvided is returned when the key lookup callback is set, but no key is in the token.
	ErrNoKeyProvided = errors.New("jwt: no key provided")

	// ErrNonExistantKey is returned when the provided key ID does not exist.
	ErrNonExistantKey = errors.New("jwt: non-existant key")
)

// keyLookupCallback is used by DecodeToken to look up the algorithm to decode with
// if the "kid" header is specified in the token.
var keyLookupCallback func(string) (Algorithm, interface{})

// supportedTypes is used to determine if a token type is supported.
var supportedTypes = map[Type]bool{
	JWT: true,
}

// supportedAlgorithms is used to determine if an algorithm is supported.
var supportedAlgorithms = map[Algorithm]signingPair{
	None:  {nil, nil},
	HS256: {hmac.SignHS256, hmac.VerifyHS256},
	HS384: {hmac.SignHS384, hmac.VerifyHS384},
	HS512: {hmac.SignHS512, hmac.VerifyHS512},
	RS256: {rsa.SignRS256, rsa.VerifyRS256},
	RS384: {rsa.SignRS384, rsa.VerifyRS384},
	RS512: {rsa.SignRS512, rsa.VerifyRS512},
	ES256: {ecdsa.SignES256, ecdsa.VerifyES256},
	ES384: {ecdsa.SignES384, ecdsa.VerifyES384},
	ES512: {ecdsa.SignES512, ecdsa.VerifyES512},
}

// reservedClaims is used to make sure no reserved claims are used in user data.
var reservedClaims = map[string]bool{
	"iss": true,
	"sub": true,
	"aud": true,
	"exp": true,
	"nbf": true,
	"iat": true,
	"jti": true,
}

// KeyLookupCallback sets the callback function to look up the algorithm and
// secret to use for a given "kid" header (located in the token header).
//
// The function is expected to return the algorithm and secret, but the secret
// can be omitted (by setting it to "" or nil). The callback will then use the
// provided algorithm with the secret provided to the DecodeToken function.
//
// If the callback returns "" for the Algorithm, the subsequent token validation
// will fail with ErrNonExistantKey.
func KeyLookupCallback(callback func(string) (Algorithm, interface{})) {
	keyLookupCallback = callback
}
