// Package hmac provides HMAC signing methods for JWT.
package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
)

// HS256 signs the given token with the given secret using HMAC SHA-256.
func HS256(token string, secret []byte) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(token))
	return h.Sum(nil)
}

// HS384 signs the given token with the given secret using HMAC SHA-384.
func HS384(token string, secret []byte) []byte {
	h := hmac.New(sha512.New384, secret)
	h.Write([]byte(token))
	return h.Sum(nil)
}

// HS512 signs the given token with the given secret using HMAC SHA-512.
func HS512(token string, secret []byte) []byte {
	h := hmac.New(sha512.New, secret)
	h.Write([]byte(token))
	return h.Sum(nil)
}
