package ecdsa

import "testing"

var PublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELPzoodhKFk3MqbmBsKxRHS+SV9CE
g6SkYvRV1w+fMqyy8+byfiBawUmI9PBZ7BJinUkTpXf8t7rsThmiIjb+7w==
-----END PUBLIC KEY-----`
var PrivateKeyPKCS1 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIE3VFlZu/rlnApxRQtKDxHEkTibgpxvKIaliNjqNjAqFoAoGCCqGSM49
AwEHoUQDQgAELPzoodhKFk3MqbmBsKxRHS+SV9CEg6SkYvRV1w+fMqyy8+byfiBa
wUmI9PBZ7BJinUkTpXf8t7rsThmiIjb+7w==
-----END EC PRIVATE KEY-----`
var PrivateKeyPKCS8 = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTdUWVm7+uWcCnFFC
0oPEcSROJuCnG8ohqWI2Oo2MCoWhRANCAAQs/Oih2EoWTcypuYGwrFEdL5JX0ISD
pKRi9FXXD58yrLLz5vJ+IFrBSYj08FnsEmKdSROld/y3uuxOGaIiNv7v
-----END PRIVATE KEY-----`
var Token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19"

var SignatureES256 = "G3Ha2td55IQOdAkSyimCQaPsqSZQQA9coaN5IbullfB59t9F1RMwxOOm2x8_j3gRK1VA6qCrf5idR32-QbhuWA=="
var SignatureES384 = "XK-GAN8HWGbtYXFoAy_eOsqkX59piaU3qfn1YXPHwVS2quFFuyoVuGKptTq9WIkdB2BW-glg7cuq50XU8AwhYg=="
var SignatureES512 = "6kmoVmIc_qkHdhw1MZNDlOxTf8mWiEotPNwty3z1GoX_kfHC_266gj-xhIoHYi2cMM9EDoqNROgpOGyDVJ9CzA=="

func TestSignES256(t *testing.T) {
	if _, err := SignES256(Token, PrivateKeyPKCS1); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestSignES256_PKCS8(t *testing.T) {
	if _, err := SignES256(Token, PrivateKeyPKCS8); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestSignES256_ByteSlice(t *testing.T) {
	if _, err := SignES256(Token, []byte(PrivateKeyPKCS1)); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestSignES256_UnsupportedKeyType(t *testing.T) {
	if _, err := SignES256(Token, 0); err != ErrUnsupportedKeyType {
		t.Fatalf("expected %#q, got %#q", ErrUnsupportedKeyType, err)
	}
}

func TestSignES384(t *testing.T) {
	if _, err := SignES384(Token, PrivateKeyPKCS1); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestSignES512(t *testing.T) {
	if _, err := SignES512(Token, PrivateKeyPKCS1); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestSignES256_Fail(t *testing.T) {
	if _, err := SignES256(Token, []byte("INVALID")); err == nil {
		t.Fatal("expected non-nil, got nil")
	}
}

func TestSignES384_Fail(t *testing.T) {
	if _, err := SignES384(Token, []byte("INVALID")); err == nil {
		t.Fatal("expected non-nil, got nil")
	}
}

func TestSignES512_Fail(t *testing.T) {
	if _, err := SignES512(Token, []byte("INVALID")); err == nil {
		t.Fatal("expected non-nil, got nil")
	}
}

func TestVerifyES256(t *testing.T) {
	if err := VerifyES256(Token, SignatureES256, PublicKey); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestVerifyES384(t *testing.T) {
	if err := VerifyES384(Token, SignatureES384, PublicKey); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestVerifyES512(t *testing.T) {
	if err := VerifyES512(Token, SignatureES512, PublicKey); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestVerifyES256_Fail(t *testing.T) {
	if VerifyES256(Token, SignatureES256, "INVALID") == nil {
		t.Fatal("expected non-nil, got nil")
	}
}

func TestVerifyES384_Fail(t *testing.T) {
	if VerifyES384(Token, SignatureES384, "INVALID") == nil {
		t.Fatal("expected non-nil, got nil")
	}
}

func TestVerifyES512_Fail(t *testing.T) {
	if VerifyES512(Token, SignatureES512, "INVALID") == nil {
		t.Fatal("expected non-nil, got nil")
	}
}
