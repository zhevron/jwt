package jwt

import "fmt"

func ExampleToken_decode() {
	str := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJNeUlzc3VlciIsInNjb3BlcyI6WyJteV9zY29wZSJdfQ._rCzwTmDAHuUq8XNsBjLMfxHJM8Jj_H3l8-ZoPKL4TQ"

	secret := []byte("secret")
	token, err := DecodeToken(str, HS256, secret)
	if err != nil {
		panic(err)
	}

	if err := token.Verify("MyIssuer", "", ""); err != nil {
		panic(err)
	}

	for k, v := range token.Claims {
		fmt.Printf("%s = %v", k, v)
	}
}

func ExampleToken_kid() {
	str := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ik15S2V5In0.eyJpc3MiOiJNeUlzc3VlciIsInNjb3BlcyI6WyJteV9zY29wZSJdfQ.blumu_NqfxUpTLAM48lAusGjJx5Mfyv_bRiRDWfPM9A"

	KeyLookupCallback(func(kid string) (Algorithm, interface{}) {
		if kid == "MyKey" {
			return HS256, nil
		}

		return "", nil
	})

	secret := []byte("secret")
	token, err := DecodeToken(str, None, secret)
	if err != nil {
		panic(err)
	}

	if err := token.Verify("MyIssuer", "", ""); err != nil {
		panic(err)
	}

	for k, v := range token.Claims {
		fmt.Printf("%s = %v", k, v)
	}
}

func ExampleToken_sign() {
	token := NewToken()

	token.Issuer = "MyIssuer"
	token.Claims["scopes"] = []string{
		"my_scope",
	}

	secret := []byte("secret")
	str, err := token.Sign(secret)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Your token is: %s", str)
}
