// Package hmac provides HMAC signing methods for JWT.
package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"hash"
)

// SignHS256 signs the given token with the given secret using HMAC SHA-256.
func SignHS256(token string, secret []byte) string {
	return base64.URLEncoding.EncodeToString(
		computeHash(token, hmac.New(sha256.New, secret)),
	)
}

// SignHS384 signs the given token with the given secret using HMAC SHA-384.
func SignHS384(token string, secret []byte) string {
	return base64.URLEncoding.EncodeToString(
		computeHash(token, hmac.New(sha512.New384, secret)),
	)
}

// SignHS512 signs the given token with the given secret using HMAC SHA-512.
func SignHS512(token string, secret []byte) string {
	return base64.URLEncoding.EncodeToString(
		computeHash(token, hmac.New(sha512.New, secret)),
	)
}

// VerifyHS256 verifies the given signature using the given secret.
func VerifyHS256(token, signature string, secret []byte) bool {
	if signature == SignHS256(token, secret) {
		return true
	}
	return false
}

// VerifyHS384 verifies the given signature using the given secret.
func VerifyHS384(token, signature string, secret []byte) bool {
	if signature == SignHS384(token, secret) {
		return true
	}
	return false
}

// VerifyHS512 verifies the given signature using the given secret.
func VerifyHS512(token, signature string, secret []byte) bool {
	if signature == SignHS512(token, secret) {
		return true
	}
	return false
}

// computeHash calculates the hash for the token with the given algorithm.
func computeHash(token string, h hash.Hash) []byte {
	h.Write([]byte(token))
	return h.Sum(nil)
}
