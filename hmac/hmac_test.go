package hmac

import "testing"

func TestSignHS256(t *testing.T) {
	tkn := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19"
	sig := "cMrSIdfeoGxOtgoZcNufWR2DGFP-qncUOdfrGCPJLZY="
	if str := SignHS256(tkn, []byte("secret")); str != sig {
		t.Fatalf("expected %#q, got %#q", sig, str)
	}
}

func TestSignHS384(t *testing.T) {
	tkn := "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19"
	sig := "BpHZzG_ocKno1rT21T1FHlJH_hK3r4luraPhRfDp2F0ynB2rApS5IYsoVAWFy75J"
	if str := SignHS384(tkn, []byte("secret")); str != sig {
		t.Fatalf("expected %#q, got %#q", sig, str)
	}
}

func TestSignHS512(t *testing.T) {
	tkn := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19"
	sig := "vqhUi4XHe121nCmlvwIpMGCpV4qPk37slr6JuRNrcRiU9Fm9bx82cq7W2AIndudGVcV9Tlk38tD10sPcKeb7Lg=="
	if str := SignHS512(tkn, []byte("secret")); str != sig {
		t.Fatalf("expected %#q, got %#q", sig, str)
	}
}

func TestVerifyHS256(t *testing.T) {
	tkn := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19"
	sig := "cMrSIdfeoGxOtgoZcNufWR2DGFP-qncUOdfrGCPJLZY="
	if !VerifyHS256(tkn, sig, []byte("secret")) {
		t.Fatal("expected true, got false")
	}
}

func TestVerifyHS384(t *testing.T) {
	tkn := "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19"
	sig := "BpHZzG_ocKno1rT21T1FHlJH_hK3r4luraPhRfDp2F0ynB2rApS5IYsoVAWFy75J"
	if !VerifyHS384(tkn, sig, []byte("secret")) {
		t.Fatal("expected true, got false")
	}
}

func TestVerifyHS512(t *testing.T) {
	tkn := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19"
	sig := "vqhUi4XHe121nCmlvwIpMGCpV4qPk37slr6JuRNrcRiU9Fm9bx82cq7W2AIndudGVcV9Tlk38tD10sPcKeb7Lg=="
	if !VerifyHS512(tkn, sig, []byte("secret")) {
		t.Fatal("expected true, got false")
	}
}
