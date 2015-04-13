// Package ecdsa provides ECDSA signing methods for JWT.
package ecdsa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
)

var (
	// ErrVerifyFailed is returned when signature verification fails.
	ErrVerifyFailed = errors.New("jwt/ecdsa: verification failed")

	// ErrInvalidKey is returned when the given key is not a valid ECDSA key.
	ErrInvalidKey = errors.New("jwt/ecdsa: invalid key")

	//ErrInvalidSignature is returned when the signature provided cannot be decoded.
	ErrInvalidSignature = errors.New("jwt/ecdsa: invalid signature")
)

// SignES256 signs the given token with the given secret using ECDSA SHA-256.
func SignES256(token string, secret []byte) (string, error) {
	k, err := privateKey(secret)
	if err != nil {
		return "", err
	}

	return computeHash(token, crypto.SHA256, k)
}

// SignES384 signs the given token with the given secret using ECDSA SHA-384.
func SignES384(token string, secret []byte) (string, error) {
	k, err := privateKey(secret)
	if err != nil {
		return "", err
	}

	return computeHash(token, crypto.SHA384, k)
}

// SignES512 signs the given token with the given secret using ECDSA SHA-512.
func SignES512(token string, secret []byte) (string, error) {
	k, err := privateKey(secret)
	if err != nil {
		return "", err
	}

	return computeHash(token, crypto.SHA512, k)
}

// VerifyES256 verifies the given signature using the given secret.
func VerifyES256(token, signature string, secret []byte) error {
	k, err := publicKey(secret)
	if err != nil {
		return err
	}

	return verifySignature(token, signature, crypto.SHA256, k)
}

// VerifyES384 verifies the given signature using the given secret.
func VerifyES384(token, signature string, secret []byte) error {
	k, err := publicKey(secret)
	if err != nil {
		return err
	}

	return verifySignature(token, signature, crypto.SHA384, k)
}

// VerifyES512 verifies the given signature using the given secret.
func VerifyES512(token, signature string, secret []byte) error {
	k, err := publicKey(secret)
	if err != nil {
		return err
	}

	return verifySignature(token, signature, crypto.SHA512, k)
}

// computeHash calculates the hash for the token with the given algorithm.
func computeHash(tkn string, h crypto.Hash, k *ecdsa.PrivateKey) (string, error) {
	hash := h.New()
	hash.Write([]byte(tkn))

	r, s, err := ecdsa.Sign(rand.Reader, k, hash.Sum(nil))
	if err != nil {
		return "", err
	}

	var b []byte
	b = append(b, r.Bytes()...)
	b = append(b, s.Bytes()...)

	return base64.URLEncoding.EncodeToString(b), nil
}

// verifySignature verifies the signature using the given algorithm.
func verifySignature(tkn, sig string, h crypto.Hash, k *ecdsa.PublicKey) error {
	hash := h.New()
	hash.Write([]byte(tkn))

	b, err := base64.URLEncoding.DecodeString(sig)
	if err != nil {
		return err
	}

	if len(b) != 64 {
		return ErrInvalidSignature
	}

	r := new(big.Int)
	r.SetBytes(b[:32])
	s := new(big.Int)
	s.SetBytes(b[32:])

	if !ecdsa.Verify(k, hash.Sum(nil), r, s) {
		return ErrVerifyFailed
	}

	return nil
}

// privateKey returns the ECDSA private key from the secret.
func privateKey(key []byte) (*ecdsa.PrivateKey, error) {
	b, _ := pem.Decode(key)
	if b == nil {
		return nil, ErrInvalidKey
	}

	var k interface{}
	k, err := x509.ParseECPrivateKey(b.Bytes)
	if err != nil {
		if k, err = x509.ParsePKCS8PrivateKey(b.Bytes); err != nil {
			return nil, err
		}
	}

	if k, ok := k.(*ecdsa.PrivateKey); ok {
		return k, nil
	}

	return nil, ErrInvalidKey
}

// publicKey returns the ECDSA public key from the secret.
func publicKey(key []byte) (*ecdsa.PublicKey, error) {
	b, _ := pem.Decode(key)
	if b == nil {
		return nil, ErrInvalidKey
	}

	var k interface{}
	k, err := x509.ParsePKIXPublicKey(b.Bytes)
	if err != nil {
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			k = c.PublicKey
		} else {
			return nil, ErrInvalidKey
		}
	}

	if k, ok := k.(*ecdsa.PublicKey); ok {
		return k, nil
	}

	return nil, ErrInvalidKey
}
