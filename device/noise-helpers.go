/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
)

var curve = elliptic.P521()

/* KDF related functions.
 * HMAC-based Key Derivation Function (HKDF)
 * https://tools.ietf.org/html/rfc5869
 */

func HMAC1(sum *[sha256.Size]byte, key, in0 []byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write(in0)
	mac.Sum(sum[:0])
}

func HMAC2(sum *[sha256.Size]byte, key, in0, in1 []byte) {
	mac := hmac.New(sha256.New, key)
	mac.Write(in0)
	mac.Write(in1)
	mac.Sum(sum[:0])
}

func KDF1(t0 *[sha256.Size]byte, key, input []byte) {
	HMAC1(t0, key, input)
	HMAC1(t0, t0[:], []byte{0x1})
}

func KDF2(t0, t1 *[sha256.Size]byte, key, input []byte) {
	var prk [sha256.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	setZero(prk[:])
}

func KDF3(t0, t1, t2 *[sha256.Size]byte, key, input []byte) {
	var prk [sha256.Size]byte
	HMAC1(&prk, key, input)
	HMAC1(t0, prk[:], []byte{0x1})
	HMAC2(t1, prk[:], t0[:], []byte{0x2})
	HMAC2(t2, prk[:], t1[:], []byte{0x3})
	setZero(prk[:])
}

func isZero(val []byte) bool {
	acc := 1
	for _, b := range val {
		acc &= subtle.ConstantTimeByteEq(b, 0)
	}
	return acc == 1
}

/* This function is not used as pervasively as it should because this is mostly impossible in Go at the moment */
func setZero(arr []byte) {
	for i := range arr {
		arr[i] = 0
	}
}

func newPrivateKey() (sk NoisePrivateKey, err error) {
	private, _, _, err := elliptic.GenerateKey(curve, rand.Reader)
	copy(sk[:], private[:])
	return
}

func (sk *NoisePrivateKey) publicKey() (pk NoisePublicKey) {
	x, y := curve.ScalarBaseMult(sk[:])
	public := elliptic.MarshalCompressed(curve, x, y)
	copy(pk[:], public[:])
	return
}

func (sk *NoisePrivateKey) sharedSecret(pk NoisePublicKey) (ss [NoisePublicKeySize]byte) {
	x, y := elliptic.UnmarshalCompressed(curve, pk[:])
	x, y = curve.ScalarMult(x, y, sk[:])
	copy(ss[:], elliptic.MarshalCompressed(curve, x, y))
	return
}
