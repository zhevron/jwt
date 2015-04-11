package hmac

import "testing"

var Secret = []byte("secret")
var Token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19"

var SignatureHS256 = "cMrSIdfeoGxOtgoZcNufWR2DGFP-qncUOdfrGCPJLZY="
var SignatureHS384 = "1iCCiZmnb_BxpDevfB1Af10qVNEEoKzhC-K-HrdZEauAKBWCeyT-syWZYv6Pp9zT"
var SignatureHS512 = "nbv50JDKuBqZ1vmIvCOg4YoZUiiecuZAWCm8Q61PvtyajjuUHTrOGCUtWI6XwYKPN2n-8S_AZRqW2AoREOgLXg=="

func TestSignHS256(t *testing.T) {
	if str := SignHS256(Token, Secret); str != SignatureHS256 {
		t.Fatalf("expected %#q, got %#q", SignatureHS256, str)
	}
}

func TestSignHS384(t *testing.T) {
	if str := SignHS384(Token, Secret); str != SignatureHS384 {
		t.Fatalf("expected %#q, got %#q", SignatureHS384, str)
	}
}

func TestSignHS512(t *testing.T) {
	if str := SignHS512(Token, Secret); str != SignatureHS512 {
		t.Fatalf("expected %#q, got %#q", SignatureHS512, str)
	}
}

func TestSignHS256_Fail(t *testing.T) {
	if str := SignHS256(Token, []byte("INVALID")); str == SignatureHS256 {
		t.Fatalf("expected != %#q", SignatureHS256)
	}
}

func TestSignHS384_Fail(t *testing.T) {
	if str := SignHS384(Token, []byte("INVALID")); str == SignatureHS384 {
		t.Fatalf("expected != %#q", SignatureHS384)
	}
}

func TestSignHS512_Fail(t *testing.T) {
	if str := SignHS512(Token, []byte("INVALID")); str == SignatureHS512 {
		t.Fatalf("expected != %#q", SignatureHS512)
	}
}

func TestVerifyHS256(t *testing.T) {
	if !VerifyHS256(Token, SignatureHS256, Secret) {
		t.Fatal("expected true, got false")
	}
}

func TestVerifyHS384(t *testing.T) {
	if !VerifyHS384(Token, SignatureHS384, Secret) {
		t.Fatal("expected true, got false")
	}
}

func TestVerifyHS512(t *testing.T) {
	if !VerifyHS512(Token, SignatureHS512, Secret) {
		t.Fatal("expected true, got false")
	}
}

func TestVerifyHS256_Fail(t *testing.T) {
	if VerifyHS256(Token, SignatureHS256, []byte("INVALID")) {
		t.Fatal("expected false, got true")
	}
}

func TestVerifyHS384_Fail(t *testing.T) {
	if VerifyHS384(Token, SignatureHS384, []byte("INVALID")) {
		t.Fatal("expected false, got true")
	}
}

func TestVerifyHS512_Fail(t *testing.T) {
	if VerifyHS512(Token, SignatureHS512, []byte("INVALID")) {
		t.Fatal("expected false, got true")
	}
}
