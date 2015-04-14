package hmac

import "testing"

var Secret = "secret"
var Token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19"

var SignatureHS256 = "cMrSIdfeoGxOtgoZcNufWR2DGFP-qncUOdfrGCPJLZY="
var SignatureHS384 = "1iCCiZmnb_BxpDevfB1Af10qVNEEoKzhC-K-HrdZEauAKBWCeyT-syWZYv6Pp9zT"
var SignatureHS512 = "nbv50JDKuBqZ1vmIvCOg4YoZUiiecuZAWCm8Q61PvtyajjuUHTrOGCUtWI6XwYKPN2n-8S_AZRqW2AoREOgLXg=="

func TestSignHS256(t *testing.T) {
	str, err := SignHS256(Token, Secret)
	if err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
	if str != SignatureHS256 {
		t.Fatalf("expected %#q, got %#q", SignatureHS256, str)
	}
}

func TestSignHS256_ByteSlice(t *testing.T) {
	if _, err := SignHS256(Token, []byte(Secret)); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestSignHS256_UnsupportedKeyType(t *testing.T) {
	if _, err := SignHS256(Token, 0); err != ErrUnsupportedKeyType {
		t.Fatalf("expected %#q, got %#q", ErrUnsupportedKeyType, err)
	}
}

func TestSignHS384(t *testing.T) {
	str, err := SignHS384(Token, Secret)
	if err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
	if str != SignatureHS384 {
		t.Fatalf("expected %#q, got %#q", SignatureHS384, str)
	}
}

func TestSignHS512(t *testing.T) {
	str, err := SignHS512(Token, Secret)
	if err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
	if str != SignatureHS512 {
		t.Fatalf("expected %#q, got %#q", SignatureHS512, str)
	}
}

func TestSignHS256_Fail(t *testing.T) {
	str, _ := SignHS256(Token, []byte("INVALID"))
	if str == SignatureHS256 {
		t.Fatalf("expected non-%#q, got %#q", SignatureHS256, str)
	}
}

func TestSignHS384_Fail(t *testing.T) {
	str, _ := SignHS384(Token, []byte("INVALID"))
	if str == SignatureHS384 {
		t.Fatalf("expected non-%#q, got %#q", SignatureHS384, str)
	}
}

func TestSignHS512_Fail(t *testing.T) {
	str, _ := SignHS512(Token, []byte("INVALID"))
	if str == SignatureHS512 {
		t.Fatalf("expected non-%#q, got %#q", SignatureHS512, str)
	}
}

func TestVerifyHS256(t *testing.T) {
	if err := VerifyHS256(Token, SignatureHS256, Secret); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestVerifyHS384(t *testing.T) {
	if err := VerifyHS384(Token, SignatureHS384, Secret); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestVerifyHS512(t *testing.T) {
	if err := VerifyHS512(Token, SignatureHS512, Secret); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestVerifyHS256_Fail(t *testing.T) {
	err := VerifyHS256(Token, SignatureHS256, []byte("Key"))
	if err != ErrVerifyFailed {
		t.Fatalf("expected %#q, got %#q", ErrVerifyFailed, err)
	}
}

func TestVerifyHS384_Fail(t *testing.T) {
	err := VerifyHS384(Token, SignatureHS384, []byte("Key"))
	if err != ErrVerifyFailed {
		t.Fatalf("expected %#q, got %#q", ErrVerifyFailed, err)
	}
}

func TestVerifyHS512_Fail(t *testing.T) {
	err := VerifyHS512(Token, SignatureHS512, []byte("Key"))
	if err != ErrVerifyFailed {
		t.Fatalf("expected %#q, got %#q", ErrVerifyFailed, err)
	}
}
