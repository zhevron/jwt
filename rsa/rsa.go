// Package rsa provides RSA signing methods for JWT.
package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

var (
	// ErrInvalidKey is returned when the given key is not a valid RSA key.
	ErrInvalidKey = errors.New("jwt/rsa: invalid key")

	// ErrUnsupportedKeyType is returned when the secret is not a supported type.
	ErrUnsupportedKeyType = errors.New("jwt/rsa: unsupported key type")
)

// SignRS256 signs a token with the provided secret using RSA SHA-256.
func SignRS256(token string, secret interface{}) (string, error) {
	k, err := privateKey(secret)
	if err != nil {
		return "", err
	}

	return computeHash(token, crypto.SHA256, k)
}

// SignRS384 signs a token with the provided secret using RSA SHA-384.
func SignRS384(token string, secret interface{}) (string, error) {
	k, err := privateKey(secret)
	if err != nil {
		return "", err
	}

	return computeHash(token, crypto.SHA384, k)
}

// SignRS512 signs a token with the provided secret using RSA SHA-512.
func SignRS512(token string, secret interface{}) (string, error) {
	k, err := privateKey(secret)
	if err != nil {
		return "", err
	}

	return computeHash(token, crypto.SHA512, k)
}

// VerifyRS256 verifies the given signature using the given secret.
func VerifyRS256(token, signature string, secret interface{}) error {
	k, err := publicKey(secret)
	if err != nil {
		return err
	}

	return verifySignature(token, signature, crypto.SHA256, k)
}

// VerifyRS384 verifies the given signature using the given secret.
func VerifyRS384(token, signature string, secret interface{}) error {
	k, err := publicKey(secret)
	if err != nil {
		return err
	}

	return verifySignature(token, signature, crypto.SHA384, k)
}

// VerifyRS512 verifies the given signature using the given secret.
func VerifyRS512(token, signature string, secret interface{}) error {
	k, err := publicKey(secret)
	if err != nil {
		return err
	}

	return verifySignature(token, signature, crypto.SHA512, k)
}

// computeHash calculates the hash for a token using the provided algorithm..
func computeHash(tkn string, h crypto.Hash, k *rsa.PrivateKey) (string, error) {
	hash := h.New()
	hash.Write([]byte(tkn))

	b, err := rsa.SignPKCS1v15(rand.Reader, k, h, hash.Sum(nil))
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(b), nil
}

// verifySignature verifies the signature using the given algorithm.
func verifySignature(tkn, sig string, h crypto.Hash, k *rsa.PublicKey) error {
	hash := h.New()
	hash.Write([]byte(tkn))

	b, err := base64.URLEncoding.DecodeString(sig)
	if err != nil {
		return err
	}

	return rsa.VerifyPKCS1v15(k, h, hash.Sum(nil), b)
}

// privateKey returns the RSA private key from the secret.
func privateKey(key interface{}) (*rsa.PrivateKey, error) {
	switch key.(type) {
	case *rsa.PrivateKey:
		return key.(*rsa.PrivateKey), nil

	case string:
		return privateKey([]byte(key.(string)))

	case []byte:
		b, _ := pem.Decode(key.([]byte))
		if b == nil {
			return nil, ErrInvalidKey
		}

		var k interface{}
		k, err := x509.ParsePKCS1PrivateKey(b.Bytes)
		if err != nil {
			if k, err = x509.ParsePKCS8PrivateKey(b.Bytes); err != nil {
				return nil, err
			}
		}

		if k, ok := k.(*rsa.PrivateKey); ok {
			return k, nil
		}

		return nil, ErrInvalidKey
	}

	return nil, ErrUnsupportedKeyType
}

// publicKey returns the RSA public key from the secret.
func publicKey(key interface{}) (*rsa.PublicKey, error) {
	switch key.(type) {
	case *rsa.PublicKey:
		return key.(*rsa.PublicKey), nil

	case string:
		return publicKey([]byte(key.(string)))

	case []byte:
		b, _ := pem.Decode(key.([]byte))
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

		if k, ok := k.(*rsa.PublicKey); ok {
			return k, nil
		}

		return nil, ErrInvalidKey
	}

	return nil, ErrUnsupportedKeyType
}
