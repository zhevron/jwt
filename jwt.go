// Package jwt provides an implementation JSON Web Tokens.
package jwt

import (
	"errors"

	"github.com/zhevron/jwt/hmac"
)

// Signer is used by the signing packages to sign tokens.
type Signer func(string, []byte) []byte

// Type is used to define the type of token.
type Type string

const (
	// JWT represents the JSON Web Token type.
	JWT Type = "JWT"
)

// Algorithm is used to define the hashing algorithm used for the token.
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

	// ES256 represents the ECDSA P-256 SHA-256 algorithm.
	ES256 Algorithm = "ES256"

	// ES384 represents the ECDSA P-384 SHA-384 algorithm.
	ES384 Algorithm = "ES384"

	// ES512 represents the ECDSA P-512 SHA-512 algorithm.
	ES512 Algorithm = "ES512"
)

var (
	// ErrInvalidAlgorithm is returned when the algorithm is not set.
	ErrInvalidAlgorithm = errors.New("jwt: invalid algorithm")

	// ErrInvalidAudience is returned when the audience cannot be verified.
	ErrInvalidAudience = errors.New("jwt: invalid audience")

	// ErrInvalidIssuer is returned when the issuer cannot be verified.
	ErrInvalidIssuer = errors.New("jwt: invalid issuer")

	// ErrInvalidSignature is returned when the signature cannot be verified.
	ErrInvalidSignature = errors.New("jwt: invalid signature")

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
)

// supportedTypes is used to determine if a token type is supported.
var supportedTypes = map[Type]bool{
	JWT: true,
}

// supportedAlgorithms is used to determine if an algorithm is supported.
var supportedAlgorithms = map[Algorithm]Signer{
	None:  nil,
	HS256: hmac.HS256,
	HS384: hmac.HS384,
	HS512: hmac.HS512,
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
