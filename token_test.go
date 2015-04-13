package jwt

import (
	"testing"
	"time"

	"github.com/zhevron/jwt/hmac"
)

func TestNewToken(t *testing.T) {
	tkn := NewToken()
	if tkn == nil {
		t.Fatal("token was nil")
	}
}

func TestDecodeToken(t *testing.T) {
	str := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19.cMrSIdfeoGxOtgoZcNufWR2DGFP-qncUOdfrGCPJLZY="
	tkn, err := DecodeToken(str, "", []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if tkn.Issuer != "MyIssuer" {
		t.Fatalf("expected %#q, got %#q", "MyIssuer", tkn.Issuer)
	}
}

func TestDecodeToken_NoneAlgorithm(t *testing.T) {
	str := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=.eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19."
	tkn, err := DecodeToken(str, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if tkn.Issuer != "MyIssuer" {
		t.Fatalf("expected %#q, got %#q", "MyIssuer", tkn.Issuer)
	}
}

func TestDecodeToken_InvalidToken(t *testing.T) {
	str := "abc123def456"
	_, err := DecodeToken(str, "", []byte("secret"))
	if err != ErrInvalidToken {
		t.Fatalf("expected %#q, got %#q", ErrInvalidToken, err)
	}
}

func TestDecodeToken_InvalidHeader(t *testing.T) {
	str := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJX.eyJpYXQiOjE0MjQ3NzYzMDcsIm5iZiI6MTQyNDc3NjMwNiwiZXhwIjoxNDI0Nzc2MzA4LCJpc3MiOiJNeUlzc3VlciIsInN1YiI6Ik15U3ViamVjdCIsImF1ZCI6Ik15QXVkaWVuY2UiLCJzY29wZXMiOlsibXlfc2NvcGUiXX0=."
	_, err := DecodeToken(str, "", []byte("secret"))
	if err == nil {
		t.Fatal("expected non nil, got nil")
	}
}

func TestDecodeToken_InvalidPayload(t *testing.T) {
	str := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjQ3NzYzMDcsIm5iZiI6MTQyNDc3NjMwNiwiZXhwIjoxNDI0Nzc2MzA4LCJpc3MiOiJNeUlzc3VlciIsInN1YiI6Ik15U3ViamVjdCIsImF1ZCI6Ik15QXVkaWVuY2UiLCJzY29wZXMiOlsibXlfc2NvcGUiXX0X."
	_, err := DecodeToken(str, "", []byte("secret"))
	if err == nil {
		t.Fatal("expected non nil, got nil")
	}
}

func TestDecodeToken_InvalidSignature(t *testing.T) {
	str := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0MjQ3NzY0NzAsImlhdCI6MTQyNDc3NjMwNywiaXNzIjoiTXlJc3N1ZXIiLCJzY29wZXMiOlsibXlfc2NvcGUiXX0=.zs_EW5i5gSmI660LlklPhtm8oH8ltf-vZMI3TDaOFH4="
	_, err := DecodeToken(str, "", []byte("_secret"))
	if err != hmac.ErrVerifyFailed {
		t.Fatalf("expected %#q, got %#q", hmac.ErrVerifyFailed, err)
	}
}

func TestDecodeToken_UnsupportedTokenType(t *testing.T) {
	str := "eyJhbGciOiJIUzI1NiIsInR5cCI6IklOViJ9.eyJleHAiOjE0MjQ3NzY0NzAsImlhdCI6MTQyNDc3NjMwNywiaXNzIjoiTXlJc3N1ZXIiLCJzY29wZXMiOlsibXlfc2NvcGUiXX0.ml5wzmgIkPQEhfBse923MA4zEVAmlB1IZ6N6rKLSX7k"
	_, err := DecodeToken(str, "", []byte("_secret"))
	if err != ErrUnsupportedTokenType {
		t.Fatalf("expected %#q, got %#q", ErrUnsupportedTokenType, err)
	}
}

func TestDecodeToken_UnsupportedAlgorithm(t *testing.T) {
	str := "eyJhbGciOiJJTlZBTElEIiwidHlwIjoiSldUIn0=.eyJleHAiOjE0MjQ3NzY0NzAsImlhdCI6MTQyNDc3NjMwNywiaXNzIjoiTXlJc3N1ZXIiLCJzY29wZXMiOlsibXlfc2NvcGUiXX0=.zs_EW5i5gSmI660LlklPhtm8oH8ltf-vZMI3TDaOFH4="
	_, err := DecodeToken(str, "", []byte("secret"))
	if err != ErrUnsupportedAlgorithm {
		t.Fatalf("expected %#q, got %#q", ErrUnsupportedAlgorithm, err)
	}
}

func TestDecodeToken_FailNoneWithSecret(t *testing.T) {
	str := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=.eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19."
	_, err := DecodeToken(str, "", []byte("secret"))
	if err != ErrNoneAlgorithmWithSecret {
		t.Fatalf("expected %#q, got %#q", ErrNoneAlgorithmWithSecret, err)
	}
}

func TestDecodeToken_ManualAlgorithm(t *testing.T) {
	str := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19.cMrSIdfeoGxOtgoZcNufWR2DGFP-qncUOdfrGCPJLZY="
	_, err := DecodeToken(str, HS256, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestDecodeToken_FailManualAlgorithm(t *testing.T) {
	str := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19.cMrSIdfeoGxOtgoZcNufWR2DGFP-qncUOdfrGCPJLZY="
	_, err := DecodeToken(str, HS512, []byte("secret"))
	if err != hmac.ErrVerifyFailed {
		t.Fatalf("expected %#q, got %#q", hmac.ErrVerifyFailed, err)
	}
}

func TestDecodeHeader(t *testing.T) {
	tkn := NewToken()
	str := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

	if err := decodeHeader(tkn, str); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestDecodeHeader_InvalidBase64(t *testing.T) {
	tkn := NewToken()
	str := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ"

	if err := decodeHeader(tkn, str); err == nil {
		t.Fatal("expected non nil, got nil")
	}
}

func TestDecodeHeader_InvalidJSON(t *testing.T) {
	tkn := NewToken()
	str := "eyJpbnZhbGlkIjoianNvbn0="

	if err := decodeHeader(tkn, str); err == nil {
		t.Fatal("expected non nil, got nil")
	}
}

func TestDecodeHeader_InvalidType(t *testing.T) {
	tkn := NewToken()
	str := "eyJhbGciOiJIUzI1NiIsInR5cCI6MX0="

	if err := decodeHeader(tkn, str); err != ErrInvalidToken {
		t.Fatalf("expected %#q, got %#q", ErrInvalidToken, err)
	}
}

func TestDecodeHeader_InvalidAlgorithm(t *testing.T) {
	tkn := NewToken()
	str := "eyJhbGciOjEsInR5cCI6IkpXVCJ9"

	if err := decodeHeader(tkn, str); err != ErrInvalidToken {
		t.Fatalf("expected %#q, got %#q", ErrInvalidToken, err)
	}
}

func TestDecodeHeader_UnsupportedType(t *testing.T) {
	tkn := NewToken()
	str := "eyJhbGciOiJIUzI1NiIsInR5cCI6IklOViJ9"

	if err := decodeHeader(tkn, str); err != ErrUnsupportedTokenType {
		t.Fatalf("expected %#q, got %#q", ErrUnsupportedTokenType, err)
	}
}

func TestDecodePayload(t *testing.T) {
	tkn := NewToken()
	str := "eyJpYXQiOjE0MjQ3NzYzMDcsIm5iZiI6MTQyNDc3NjMwNiwiZXhwIjoxNDI0Nzc2MzA4LCJpc3MiOiJNeUlzc3VlciIsInN1YiI6Ik15U3ViamVjdCIsImF1ZCI6Ik15QXVkaWVuY2UiLCJzY29wZXMiOlsibXlfc2NvcGUiXX0="

	if err := decodePayload(tkn, str); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestDecodePayload_InvalidBase64(t *testing.T) {
	tkn := NewToken()
	str := "eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl1"

	if err := decodePayload(tkn, str); err == nil {
		t.Fatal("expected non nil, got nil")
	}
}

func TestDecodePayload_InvalidJSON(t *testing.T) {
	tkn := NewToken()
	str := "eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIn0="

	if err := decodePayload(tkn, str); err == nil {
		t.Fatal("expected non nil, got nil")
	}
}

func TestDecodePayload_InvalidIssuer(t *testing.T) {
	tkn := NewToken()
	str := "eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6MSwic2NvcGVzIjpbIm15X3Njb3BlIl19"

	if err := decodePayload(tkn, str); err != ErrInvalidToken {
		t.Fatalf("expected %#q, got %#q", ErrInvalidToken, err)
	}
}

func TestDecodePayload_InvalidSubject(t *testing.T) {
	tkn := NewToken()
	str := "eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic3ViIjoxLCJzY29wZXMiOlsibXlfc2NvcGUiXX0="

	if err := decodePayload(tkn, str); err != ErrInvalidToken {
		t.Fatalf("expected %#q, got %#q", ErrInvalidToken, err)
	}
}

func TestDecodePayload_InvalidAudience(t *testing.T) {
	tkn := NewToken()
	str := "eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwiYXVkIjoxLCJzY29wZXMiOlsibXlfc2NvcGUiXX0="

	if err := decodePayload(tkn, str); err != ErrInvalidToken {
		t.Fatalf("expected %#q, got %#q", ErrInvalidToken, err)
	}
}

func TestDecodePayload_InvalidIssuedAt(t *testing.T) {
	tkn := NewToken()
	str := "eyJpYXQiOiIxNDI0Nzc2MzA3IiwiaXNzIjoiTXlJc3N1ZXIiLCJzY29wZXMiOlsibXlfc2NvcGUiXX0="

	if err := decodePayload(tkn, str); err != ErrInvalidToken {
		t.Fatalf("expected %#q, got %#q", ErrInvalidToken, err)
	}
}

func TestDecodePayload_InvalidNotBefore(t *testing.T) {
	tkn := NewToken()
	str := "eyJpYXQiOjE0MjQ3NzYzMDcsIm5iZiI6IklOViIsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19"

	if err := decodePayload(tkn, str); err != ErrInvalidToken {
		t.Fatalf("expected %#q, got %#q", ErrInvalidToken, err)
	}
}

func TestDecodePayload_InvalidExpires(t *testing.T) {
	tkn := NewToken()
	str := "eyJpYXQiOjE0MjQ3NzYzMDcsImV4cCI6IklOViIsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19"

	if err := decodePayload(tkn, str); err != ErrInvalidToken {
		t.Fatalf("expected %#q, got %#q", ErrInvalidToken, err)
	}
}

func TestTokenSign(t *testing.T) {
	str := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19.cMrSIdfeoGxOtgoZcNufWR2DGFP-qncUOdfrGCPJLZY="
	tkn := NewToken()
	tkn.Issuer = "MyIssuer"
	tkn.IssuedAt = time.Unix(1424776307, 0)
	tkn.NotBefore = time.Unix(1424776307, 0)
	tkn.Expires = time.Unix(1424776307, 0)
	tkn.Claims["scopes"] = []string{"my_scope"}
	s, err := tkn.Sign([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if str != s {
		t.Fatalf("expected %#q, got %#q", str, s)
	}
}

func TestTokenSign_NoneAlgorithm(t *testing.T) {
	str := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=.eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19."
	tkn := NewToken()
	tkn.Algorithm = None
	tkn.Issuer = "MyIssuer"
	tkn.IssuedAt = time.Unix(1424776307, 0)
	tkn.NotBefore = time.Unix(1424776307, 0)
	tkn.Expires = time.Unix(1424776307, 0)
	tkn.Claims["scopes"] = []string{"my_scope"}
	s, err := tkn.Sign([]byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if str != s {
		t.Fatalf("expected %#q, got %#q", str, s)
	}
}

func TestTokenSign_InvalidClaims(t *testing.T) {
	tkn := NewToken()
	tkn.Claims["iss"] = 1
	_, err := tkn.Sign([]byte("secret"))
	if err == nil {
		t.Fatalf("expected non nil, got nil")
	}
}

func TestTokenSign_InvalidPayload(t *testing.T) {
	tkn := NewToken()
	tkn.Claims["scopes"] = map[int]string{
		0: "test",
	}
	_, err := tkn.Sign([]byte("secret"))
	if err == nil {
		t.Fatalf("expected non nil, got nil")
	}
}

func TestTokenSign_UnsupportedAlgorithm(t *testing.T) {
	tkn := NewToken()
	tkn.Algorithm = Algorithm("INVALID")
	_, err := tkn.Sign([]byte("secret"))
	if err != ErrUnsupportedAlgorithm {
		t.Fatalf("expected %#q, got %#q", ErrUnsupportedAlgorithm, err)
	}
}

func TestTokenVerify(t *testing.T) {
	tkn := NewToken()
	if err := tkn.Verify("", "", ""); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestTokenVerify_InvalidIssuer(t *testing.T) {
	tkn := NewToken()
	tkn.Issuer = "MyIssuer"
	if err := tkn.Verify("TestIssuer", "", ""); err != ErrInvalidIssuer {
		t.Fatalf("expected %#q, got %#q", ErrInvalidIssuer, err)
	}
}

func TestTokenVerify_InvalidSubject(t *testing.T) {
	tkn := NewToken()
	tkn.Subject = "MySubject"
	if err := tkn.Verify("", "TestSubject", ""); err != ErrInvalidSubject {
		t.Fatalf("expected %#q, got %#q", ErrInvalidSubject, err)
	}
}

func TestTokenVerify_InvalidAudience(t *testing.T) {
	tkn := NewToken()
	tkn.Audience = "MyAudience"
	if err := tkn.Verify("", "", "TestAudience"); err != ErrInvalidAudience {
		t.Fatalf("expected %#q, got %#q", ErrInvalidAudience, err)
	}
}

func TestTokenVerify_NotValidYet(t *testing.T) {
	tkn := NewToken()
	tkn.NotBefore = tkn.IssuedAt.Add(1 * time.Hour)
	if err := tkn.Verify("", "", ""); err != ErrTokenNotValidYet {
		t.Fatalf("expected %#q, got %#q", ErrTokenNotValidYet, err)
	}
}

func TestTokenVerify_Expired(t *testing.T) {
	tkn := NewToken()
	tkn.Expires = tkn.IssuedAt.Add(-1 * time.Hour)
	if err := tkn.Verify("", "", ""); err != ErrTokenExpired {
		t.Fatalf("expected %#q, got %#q", ErrTokenExpired, err)
	}
}

func TestTokenValid_True(t *testing.T) {
	tkn := NewToken()
	tkn.NotBefore = tkn.IssuedAt.Add(-1 * time.Hour)
	if !tkn.Valid() {
		t.Fatal("expected true, got false")
	}
}

func TestTokenValid_False(t *testing.T) {
	tkn := NewToken()
	tkn.NotBefore = tkn.IssuedAt.Add(1 * time.Hour)
	if tkn.Valid() {
		t.Fatal("expected false, got true")
	}
}

func TestTokenExpired_True(t *testing.T) {
	tkn := NewToken()
	tkn.Expires = tkn.IssuedAt.Add(-1 * time.Hour)
	if !tkn.Expired() {
		t.Fatal("expected true, got false")
	}
}

func TestTokenExpired_False(t *testing.T) {
	tkn := NewToken()
	tkn.Expires = tkn.IssuedAt.Add(1 * time.Hour)
	if tkn.Expired() {
		t.Fatal("expected false, got true")
	}
}

func TestTokenBuildHeader(t *testing.T) {
	tkn := NewToken()
	header := tkn.buildHeader()
	if _, ok := header["alg"]; !ok {
		t.Fatalf("expected true, got false")
	}
	if _, ok := header["typ"]; !ok {
		t.Fatalf("expected true, got false")
	}
}

func TestTokenBuildClaims(t *testing.T) {
	tkn := NewToken()
	tkn.Issuer = "Test"
	tkn.Subject = "Test"
	tkn.Audience = "Test"
	tkn.NotBefore = tkn.IssuedAt.Add(-1 * time.Hour)
	tkn.Expires = tkn.IssuedAt.Add(1 * time.Hour)
	tkn.Claims["var"] = "test"
	claims, err := tkn.buildClaims()
	if err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
	if _, ok := claims["iss"]; !ok {
		t.Fatalf("expected true, got false")
	}
	if _, ok := claims["sub"]; !ok {
		t.Fatalf("expected true, got false")
	}
	if _, ok := claims["aud"]; !ok {
		t.Fatalf("expected true, got false")
	}
	if _, ok := claims["iat"]; !ok {
		t.Fatalf("expected true, got false")
	}
	if _, ok := claims["nbf"]; !ok {
		t.Fatalf("expected true, got false")
	}
	if _, ok := claims["exp"]; !ok {
		t.Fatalf("expected true, got false")
	}
	if _, ok := claims["var"]; !ok {
		t.Fatalf("expected true, got false")
	}
}

func TestTokenBuildClaims_ReservedClaim(t *testing.T) {
	tkn := NewToken()
	tkn.Claims["iss"] = "NewIssuer"
	if _, err := tkn.buildClaims(); err != ErrReservedClaim {
		t.Fatalf("expected %#q, got %#q", ErrReservedClaim, err)
	}
}
