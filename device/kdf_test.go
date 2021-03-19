/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package device

import (
	"crypto/sha512"
	"encoding/hex"
	"testing"
)

type KDFTest struct {
	key   string
	input string
	t0    string
	t1    string
	t2    string
}

func assertEquals(t *testing.T, a string, b string) {
	if a != b {
		t.Log("expected", a, "=", b)
	}
}

func TestKDF(t *testing.T) {
	tests := []KDFTest{
		{
			key:   "746573742d6b6579",
			input: "746573742d696e707574",
			t0:    "8a5a9f34897d575c46b121d859203aaaddbea2b13081f65f8930d9dfb9b121c0acb7f9af2fd0783d28d6574d5a5d16b6",
			t1:    "2bb61a2c1b3591bb9eb2b35af526e0040e8ce8c3456251218c8fde6a995f30deab61224e723571556011e863a3376aa5",
			t2:    "22aaf09f06d056172202d92876c06c4d412c22f472237746a9354a19dd4f9791246d616cfe051b7ea41b21fc0a8592af",
		},
		{
			key:   "776972656775617264",
			input: "776972656775617264",
			t0:    "8d420e431f88f238e2f4649c478b34c56faca1d5c71873bf25d91035aa7aad7a887c968ea0be0003f7cdfa3794dcd0bf",
			t1:    "199c819a2803ff82b370b2a7309e9685b8bb215d53c9345f220a0c53da36afba2f4c5d32862a48eec00f42be2f5a977b",
			t2:    "c3e007b2a936fa61ba1cb7097d36f1f696f4e409d8287e220267c6567b0784e703f579282ae1a92e9cca6195fc39b9fc",
		},
		{
			key:   "",
			input: "",
			t0:    "470cc65387ca4a10c7a68a3b5148c8e513daa63101000739c4c6659b8611888413b4617b1e75cf30370c2865d6d5eb49",
			t1:    "9931fffca53cb44bc9bf8dfd7c2e9f12fe8c3aed4eee08b5cb076a526973f166c5a153fcb6df17d31d95928f0ddfbb9d",
			t2:    "10fcbf538fcc49d4bacbd0da01ab59001802c236faa0670e6760c4be657a578409ccc9077779d6fface3ef65d8c73aa7",
		},
	}

	var t0, t1, t2 [sha512.Size384]byte

	for _, test := range tests {
		key, _ := hex.DecodeString(test.key)
		input, _ := hex.DecodeString(test.input)
		KDF3(&t0, &t1, &t2, key, input)
		t0s := hex.EncodeToString(t0[:])
		t1s := hex.EncodeToString(t1[:])
		t2s := hex.EncodeToString(t2[:])
		assertEquals(t, t0s, test.t0)
		assertEquals(t, t1s, test.t1)
		assertEquals(t, t2s, test.t2)
	}

	for _, test := range tests {
		key, _ := hex.DecodeString(test.key)
		input, _ := hex.DecodeString(test.input)
		KDF2(&t0, &t1, key, input)
		t0s := hex.EncodeToString(t0[:])
		t1s := hex.EncodeToString(t1[:])
		assertEquals(t, t0s, test.t0)
		assertEquals(t, t1s, test.t1)
	}

	for _, test := range tests {
		key, _ := hex.DecodeString(test.key)
		input, _ := hex.DecodeString(test.input)
		KDF1(&t0, key, input)
		t0s := hex.EncodeToString(t0[:])
		assertEquals(t, t0s, test.t0)
	}
}
