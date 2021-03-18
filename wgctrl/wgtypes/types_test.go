package wgtypes_test

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestPreparedKeys(t *testing.T) {
	// Keys generated via "wg key" and "wg pubkey" for comparison
	// with this Go implementation.
	const (
		private = "AWbv2os59B+t0WEd6Q0bMFjBxstWuRKAUPS4aa7Lvs0Rkbm7bryiisF/7SJGa8guGUzloAUKzrFWnguM3cDlN5M3"
		public  = "AgCk516rZpYP6+/WIc3VEoqUJHoE95xecn/Q0Btm3Q6aoWbNHwbcbbFfLDX8XT5eLQ30buo4LNwwY5p9Y7snXXQWPA=="
	)

	priv, err := wgtypes.ParseKey(private)
	if err != nil {
		t.Fatalf("failed to parse private key: %v", err)
	}

	if diff := cmp.Diff(private, priv.String()); diff != "" {
		t.Fatalf("unexpected private key (-want +got):\n%s", diff)
	}

	pub := priv.PublicKey()
	if diff := cmp.Diff(public, pub.String()); diff != "" {
		t.Fatalf("unexpected public key (-want +got):\n%s", diff)
	}
}

func TestKeyExchange(t *testing.T) {
	privA, pubA := mustKeyPair()
	privB, pubB := mustKeyPair()

	// Perform ECDH key exhange
	sharedA := sharedSecret(privA, pubB)
	sharedB := sharedSecret(privB, pubA)

	if diff := cmp.Diff(sharedA, sharedB); diff != "" {
		t.Fatalf("unexpected shared secret (-want +got):\n%s", diff)
	}
}

func TestBadKeys(t *testing.T) {
	// Adapt to fit the signature used in the test table.
	parseKey := func(b []byte) (wgtypes.Key, error) {
		return wgtypes.ParseKey(string(b))
	}

	tests := []struct {
		name string
		b    []byte
		fn   func(b []byte) (wgtypes.Key, error)
	}{
		{
			name: "bad base64",
			b:    []byte("xxx"),
			fn:   parseKey,
		},
		{
			name: "short base64",
			b:    []byte("aGVsbG8="),
			fn:   parseKey,
		},
		{
			name: "short key",
			b:    []byte("xxx"),
			fn:   wgtypes.NewKey,
		},
		{
			name: "long base64",
			b:    []byte("aEYETYwTBo4R9pPfAkVtMx2sDhZRshDkuQ6OuMROaREzmygO32FDBRrmGl9KGVj9/07yPh2KrwUJddNxc/h22J1HfQtdDg=="),
			fn:   parseKey,
		},
		{
			name: "long bytes",
			b:    bytes.Repeat([]byte{0xff}, 70),
			fn:   wgtypes.NewKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.fn(tt.b)
			if err == nil {
				t.Fatal("expected an error, but none occurred")
			}

			t.Logf("OK error: %v", err)
		})
	}
}

func mustKeyPair() (private wgtypes.Key, public wgtypes.Key) {
	var err error

	private, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		panicf("failed to generate private key: %v", err)
	}

	public = private.PublicKey()

	return private, public
}

func sharedSecret(private wgtypes.Key, public wgtypes.Key) wgtypes.Key {
	x, y := elliptic.UnmarshalCompressed(wgtypes.Curve, public)
	x, y = wgtypes.Curve.ScalarMult(x, y, private)
	return elliptic.MarshalCompressed(wgtypes.Curve, x, y)
}

func panicf(format string, a ...interface{}) {
	panic(fmt.Sprintf(format, a...))
}
