// Package hmac provides HMAC signing methods for JWT.
package hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
)

// HS256 signs the given token with the given secret using HMAC SHA-256.
func HS256(token string, secret []byte) []byte {
	return compute(token, hmac.New(sha256.New, secret))
}

// HS384 signs the given token with the given secret using HMAC SHA-384.
func HS384(token string, secret []byte) []byte {
	return compute(token, hmac.New(sha512.New384, secret))
}

// HS512 signs the given token with the given secret using HMAC SHA-512.
func HS512(token string, secret []byte) []byte {
	return compute(token, hmac.New(sha512.New, secret))
}

// compute calculates the hash for the token with the given algorithm.
func compute(token string, h hash.Hash) []byte {
	h.Write([]byte(token))
	return h.Sum(nil)
}
