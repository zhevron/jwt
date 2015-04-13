package rsa

import "testing"

var PublicKey = []byte(`-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzshs12YDUivJD8MUdBTZ
8wnzrWrLWxz0gAn03l72diG0yEzAsBH+s+mw293NJYGggWe2ueAE+5r252HNsKF7
nACCm2FAk3kg+FOAQ0Fj7kxORRS8MSVK1eYBm1mIadpZs++ChgTbey/YJXaVPigD
eWcuxX1yLGxOeR44Sp0yIA50Qbko2i33Ruxjcl/HDi8uYFj1Vj1SmXKH+HPJ0qyS
4YSJHyLP9545BMGUyhTNxYVam1rbKVlQH4S4A0rI9Yuqf/9O29UQ9DwWDUV0QXfC
gjRSKGVHaA7XH6L/67292RzcCqtPg7ELac9W9YKwipVoNgbIi0Ny5HIkO1YMj5X+
fQIDAQAB
-----END PUBLIC KEY-----`)
var PrivateKeyPKCS1 = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAzshs12YDUivJD8MUdBTZ8wnzrWrLWxz0gAn03l72diG0yEzA
sBH+s+mw293NJYGggWe2ueAE+5r252HNsKF7nACCm2FAk3kg+FOAQ0Fj7kxORRS8
MSVK1eYBm1mIadpZs++ChgTbey/YJXaVPigDeWcuxX1yLGxOeR44Sp0yIA50Qbko
2i33Ruxjcl/HDi8uYFj1Vj1SmXKH+HPJ0qyS4YSJHyLP9545BMGUyhTNxYVam1rb
KVlQH4S4A0rI9Yuqf/9O29UQ9DwWDUV0QXfCgjRSKGVHaA7XH6L/67292RzcCqtP
g7ELac9W9YKwipVoNgbIi0Ny5HIkO1YMj5X+fQIDAQABAoIBAQCDDgPtgHoaWiXU
F4+fApgfsO7/ue+oj3FmtOi9BvKtbC9nwz1cWgtTe4jb0Hd0jfNsEI9+vrxpuo1B
mHsEt1PgS3J7h+elj9+Vg1aHSapMHZB9t+aOP1RuvJfIHbaXYAv6PpI63lk8edZD
6CQugK2zA/JguGDkRsB1gvGqWHasWViJJ7mSvYa2zNfPNd21B+Sg1nmamPOPvnZE
NrQuX6FhDruQjvmqb37yXgmCRoxlJMQ7y3iObwYqpYc6Lrw2MOW0AhiFK8QsWd5b
JbljT+8ZO7iZ1XxVzgnYVcnPuUVvY6jZsi8sqrqlrFeW+g45SO5GdvQpVdqKWZI5
F8XMlnABAoGBAPYDkvhVGPjb/egxxCB2Z67q5CTuM+Nlkljj6vp/LwirHY78CWcB
4J6IstXprv91S80nRC43M1qffMBJZMfx3rfHJ/K61g9VCoh5Zu5bWFwbqMXihrXc
Yj5pI/2HPeMVOLZfzO8OvQ9vHkUvEtToshBjBLEom0AHpayvzFSCxXTRAoGBANct
L6O790DB/DKAB9k2gxlwW8zyxRtT6Z0duV/co09vTSlHUu/nSWEUiEM2rxVwqVJ6
so5p0WtIidRspcRveklGNF+iWaxFd7MeTA3t9EqI/jlOEOwAw0edDmE5fCyPkfOW
lb4lgiO3ye/U7EabbyFLezi3AhwuIRkn4IFkNYntAoGAFwS2l62+rGpJE5S0eSUb
Bm7L8finujsiulZ5Af8sc28vUNWcO5sdXTgFI6a9zQE4mnV2F6zqjSwnDAbR+zNS
V3e28SsyJDUcyzAwxVSeq9+apwlO+W0pdBV6XJpu2/R8XfQQxL1oSy1mc6q35Fvx
bT8WjUzzWcZdZg7821txBkECgYAEDFyWFwY62Kt3A8OiCY2D4AJKI9MjhXuishl3
vT3xU6W+/hGIY/CUe/9oTFIU9C6rV5Weak0/WHkHXxfrTzGcyU5Y8kP/orryysIh
jPWIpXUq/NYCqq0B3umTWLKGYBkd3RpqHmiJZX7OHVJoran0lWf3FDJc9102DPMD
XDBJrQKBgFUuBFCVtpcCcxHj+K0Y6kPHJ2o2dT4MaxXceYf+11da3zSAEGEoTLQB
SiO0CgJt2xqBflgqBkXvRJxxIsfkWVzj7iapCE/zJqRCN1ToajmPDVJ0t5avMGNo
x+O0Outi+RobtHziZuyx3pPwVhnEZ2CGEV3EMv9HG75aWDLqRXoH
-----END RSA PRIVATE KEY-----`)
var PrivateKeyPKCS8 = []byte(`-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDOyGzXZgNSK8kP
wxR0FNnzCfOtastbHPSACfTeXvZ2IbTITMCwEf6z6bDb3c0lgaCBZ7a54AT7mvbn
Yc2woXucAIKbYUCTeSD4U4BDQWPuTE5FFLwxJUrV5gGbWYhp2lmz74KGBNt7L9gl
dpU+KAN5Zy7FfXIsbE55HjhKnTIgDnRBuSjaLfdG7GNyX8cOLy5gWPVWPVKZcof4
c8nSrJLhhIkfIs/3njkEwZTKFM3FhVqbWtspWVAfhLgDSsj1i6p//07b1RD0PBYN
RXRBd8KCNFIoZUdoDtcfov/rvb3ZHNwKq0+DsQtpz1b1grCKlWg2BsiLQ3LkciQ7
VgyPlf59AgMBAAECggEBAIMOA+2AehpaJdQXj58CmB+w7v+576iPcWa06L0G8q1s
L2fDPVxaC1N7iNvQd3SN82wQj36+vGm6jUGYewS3U+BLcnuH56WP35WDVodJqkwd
kH235o4/VG68l8gdtpdgC/o+kjreWTx51kPoJC6ArbMD8mC4YORGwHWC8apYdqxZ
WIknuZK9hrbM18813bUH5KDWeZqY84++dkQ2tC5foWEOu5CO+apvfvJeCYJGjGUk
xDvLeI5vBiqlhzouvDYw5bQCGIUrxCxZ3lsluWNP7xk7uJnVfFXOCdhVyc+5RW9j
qNmyLyyquqWsV5b6DjlI7kZ29ClV2opZkjkXxcyWcAECgYEA9gOS+FUY+Nv96DHE
IHZnrurkJO4z42WSWOPq+n8vCKsdjvwJZwHgnoiy1emu/3VLzSdELjczWp98wElk
x/Het8cn8rrWD1UKiHlm7ltYXBuoxeKGtdxiPmkj/Yc94xU4tl/M7w69D28eRS8S
1OiyEGMEsSibQAelrK/MVILFdNECgYEA1y0vo7v3QMH8MoAH2TaDGXBbzPLFG1Pp
nR25X9yjT29NKUdS7+dJYRSIQzavFXCpUnqyjmnRa0iJ1GylxG96SUY0X6JZrEV3
sx5MDe30Soj+OU4Q7ADDR50OYTl8LI+R85aVviWCI7fJ79TsRptvIUt7OLcCHC4h
GSfggWQ1ie0CgYAXBLaXrb6sakkTlLR5JRsGbsvx+Ke6OyK6VnkB/yxzby9Q1Zw7
mx1dOAUjpr3NATiadXYXrOqNLCcMBtH7M1JXd7bxKzIkNRzLMDDFVJ6r35qnCU75
bSl0FXpcmm7b9Hxd9BDEvWhLLWZzqrfkW/FtPxaNTPNZxl1mDvzbW3EGQQKBgAQM
XJYXBjrYq3cDw6IJjYPgAkoj0yOFe6KyGXe9PfFTpb7+EYhj8JR7/2hMUhT0LqtX
lZ5qTT9YeQdfF+tPMZzJTljyQ/+iuvLKwiGM9YildSr81gKqrQHe6ZNYsoZgGR3d
GmoeaIllfs4dUmitqfSVZ/cUMlz3XTYM8wNcMEmtAoGAVS4EUJW2lwJzEeP4rRjq
Q8cnajZ1PgxrFdx5h/7XV1rfNIAQYShMtAFKI7QKAm3bGoF+WCoGRe9EnHEix+RZ
XOPuJqkIT/MmpEI3VOhqOY8NUnS3lq8wY2jH47Q662L5Ghu0fOJm7LHek/BWGcRn
YIYRXcQy/0cbvlpYMupFegc=
-----END PRIVATE KEY-----`)
var Token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE0MjQ3NzYzMDcsImlzcyI6Ik15SXNzdWVyIiwic2NvcGVzIjpbIm15X3Njb3BlIl19"

var SignatureRS256 = "YnK9-Nz5q-b7cKoVVpA6UPIieLj5XgU4cbyLYGNkYS0_60_9g-s8V0hbeqLXbfDiUBB5JD15zrU--fNbIlYzb_WKgluF6UEza6-dB51_mdFjdXrUmtNyzntidl1Q7GRzuXc6aKu4sbJJd7RA_pMLjDdiMZl2Gkmf2WrX-qoDPQ0y-cRlrvU9G8UhSOFJe_OX07h7dPG9UU7xHbJ9ZY4HfC0zCVEnqSTldZplY31OpM_sg4S45tJKOIGSSPULMRc0WFli_SycqWJA44fakZvLQzcxpcuhMj3qYoSKaNvtILfH2vhG63qreo-9loR7vKQ96S1tQfEq6SrD2kBYkF-E8g=="
var SignatureRS384 = "tk5fiP9SNd1dptLDkm2GZA6jifb8HQKH2CrX_Pkd_Fds9F7DBpMXbpH4NpbjXMqCxuX7scFk-et8sF0ugmh7oJy54W2trHRfk318E_iUJvoE9NtSItye-eglU5Ux7BH1uRUal5fYzSRF9jnscEKhWXBntzaYONb4lQrWC9fUbvPxGnS3_vRfJl9uKOD7Pz3VcbXCos6TFmL3WMNydm5QIabh2BAdJpguOj_mEzjDl9vMew1WsDsS7LPUYDWvFr573yAmk67YJZPqMZ0lbidKNAlbrPLl6sCL94pQQeq_oJZNlEcS0ZwJlsxrx3hcN5QDLEkfaONAcZKzRIzjBsBUtg=="
var SignatureRS512 = "BLOePcjJWLKWjCxFrvsiuL7l_To8Xwn_w6uMeRtR91VEBRuXxPeqix8T8Q8k9azou3TBV_kAx1uFvdPQXJjYlqndcSZ2M76QYIOPamfWsi-sqgIU7q4jNUkQKIY2yRwYUle49vZ53Um1WWkaZ7LpToi2Cz8dEi0GyAsfRJwzZZ015jVQ0d5InxEo8rNeEGtkRfPKLtSwwmRxJDlNvB3TaQ4AcFGeeC9-kUa8NyHYmvxZ9HEanIAaM4lcRf2naq7Rznh_vqq3twFEjrm8TMyoZmajGIpWCCmQRvRCJLfU1zQC1eFjPXyIPf05cJFnGP0L3N8GUqnBJkva4E8zkRFJTw=="

func TestSignRS256(t *testing.T) {
	if _, err := SignRS256(Token, PrivateKeyPKCS1); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestSignRS256_PKCS8(t *testing.T) {
	if _, err := SignRS256(Token, PrivateKeyPKCS8); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestSignRS384(t *testing.T) {
	if _, err := SignRS384(Token, PrivateKeyPKCS1); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestSignRS512(t *testing.T) {
	if _, err := SignRS512(Token, PrivateKeyPKCS1); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestSignRS256_Fail(t *testing.T) {
	if _, err := SignRS256(Token, []byte("INVALID")); err == nil {
		t.Fatal("expected non-nil, got nil")
	}
}

func TestSignRS384_Fail(t *testing.T) {
	if _, err := SignRS384(Token, []byte("INVALID")); err == nil {
		t.Fatal("expected non-nil, got nil")
	}
}

func TestSignRS512_Fail(t *testing.T) {
	if _, err := SignRS512(Token, []byte("INVALID")); err == nil {
		t.Fatal("expected non-nil, got nil")
	}
}

func TestVerifyRS256(t *testing.T) {
	if err := VerifyRS256(Token, SignatureRS256, PublicKey); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestVerifyRS384(t *testing.T) {
	if err := VerifyRS384(Token, SignatureRS384, PublicKey); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestVerifyRS512(t *testing.T) {
	if err := VerifyRS512(Token, SignatureRS512, PublicKey); err != nil {
		t.Fatalf("expected nil, got %#q", err)
	}
}

func TestVerifyRS256_Fail(t *testing.T) {
	if VerifyRS256(Token, SignatureRS256, []byte("INVALID")) == nil {
		t.Fatal("expected non-nil, got nil")
	}
}

func TestVerifyRS384_Fail(t *testing.T) {
	if VerifyRS384(Token, SignatureRS384, []byte("INVALID")) == nil {
		t.Fatal("expected non-nil, got nil")
	}
}

func TestVerifyRS512_Fail(t *testing.T) {
	if VerifyRS512(Token, SignatureRS512, []byte("INVALID")) == nil {
		t.Fatal("expected non-nil, got nil")
	}
}
