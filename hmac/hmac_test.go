package hmac

import "testing"

func TestHS256(t *testing.T) {
	b := []byte{
		168, 34, 156, 105, 112, 73, 149, 54, 222, 0, 162, 101, 180, 173, 67, 41, 11,
		83, 236, 246, 150, 81, 19, 212, 119, 38, 99, 200, 193, 239, 26, 112,
	}
	h := HS256("abd.def", []byte("secret"))
	if len(h) != len(b) {
		t.Fatalf("expected %d, got %d", len(b), len(h))
	}
	for i := range h {
		if h[i] != b[i] {
			t.Fatalf("expected %#q, got %#q", b[i], h[i])
		}
	}
}

func TestHS384(t *testing.T) {
	b := []byte{
		237, 120, 125, 181, 21, 100, 230, 79, 119, 90, 238, 58, 137, 179, 39, 119,
		66, 34, 224, 245, 209, 184, 15, 134, 58, 174, 202, 5, 39, 88, 218, 52, 81,
		113, 86, 207, 128, 46, 208, 15, 172, 115, 93, 55, 81, 150, 253, 156,
	}
	h := HS384("abd.def", []byte("secret"))
	if len(h) != len(b) {
		t.Fatalf("expected %d, got %d", len(b), len(h))
	}
	for i := range h {
		if h[i] != b[i] {
			t.Fatalf("expected %#q, got %#q", b[i], h[i])
		}
	}
}

func TestHS512(t *testing.T) {
	b := []byte{
		73, 49, 243, 111, 169, 79, 210, 159, 83, 139, 155, 212, 221, 210, 181, 115,
		101, 33, 92, 100, 6, 255, 193, 129, 108, 31, 79, 192, 66, 128, 49, 92, 66,
		169, 29, 184, 199, 243, 186, 158, 9, 16, 102, 3, 30, 181, 86, 80, 8, 31, 97,
		27, 103, 217, 128, 47, 172, 34, 137, 146, 132, 19, 112, 62,
	}
	h := HS512("abd.def", []byte("secret"))
	if len(h) != len(b) {
		t.Fatalf("expected %d, got %d", len(b), len(h))
	}
	for i := range h {
		if h[i] != b[i] {
			t.Fatalf("expected %#q, got %#q", b[i], h[i])
		}
	}
}
