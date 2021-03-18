/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package set

import (
	"bytes"
	"net"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestParseInt(t *testing.T) {
	testVectors := []struct {
		input  string
		result int
		err    bool
	}{
		{"1234", 1234, false},
		{" 1234 ", 1234, false},
		{"", 0, true},
		{"123456789123456789123456789", 0, true},
	}

	for _, v := range testVectors {
		res, err := parseInt(v.input)
		if (res != v.result) && (!v.err) {
			t.Fail()
		}
		if (err == nil) && v.err {
			t.Fail()
		}
	}
}

func TestParseFwmark(t *testing.T) {
	testVectors := []struct {
		input  string
		result *int
		err    bool
	}{
		{"0", nil, false},
		{" 0 ", nil, false},
		{"off", nil, false},
		{" off ", nil, false},
		{"", nil, true},
		{"10", new(int), false},
		{"0x10", new(int), false},
		{"123456789123456789123456789", nil, true},
	}

	*testVectors[5].result = 10
	*testVectors[6].result = 16

	for _, v := range testVectors {
		res, err := parseFwmark(v.input)
		if (res != nil) && (*res != *v.result) && (!v.err) {
			t.Fail()
		}
		if (err == nil) && v.err {
			t.Fail()
		}
	}
}

func TestParsePrivateKey(t *testing.T) {
	testVectors := []struct {
		input    string
		result   wgtypes.Key
		errorMsg string
	}{
		{"", nil, "invalid private key length"},
		{"dGVzdA==", nil, "invalid private key length"},
		{
			"AWFbKb2ve13XM2LslP/4zJWHwzRhahkaSe57MIc6036ZyyaKPdKihXQe5FyWRYKRcb2FUxq+9R+7eQkmorsvVpNY",
			wgtypes.Key{
				0x01, 0x61, 0x5b, 0x29, 0xbd, 0xaf, 0x7b, 0x5d,
				0xd7, 0x33, 0x62, 0xec, 0x94, 0xff, 0xf8, 0xcc,
				0x95, 0x87, 0xc3, 0x34, 0x61, 0x6a, 0x19, 0x1a,
				0x49, 0xee, 0x7b, 0x30, 0x87, 0x3a, 0xd3, 0x7e,
				0x99, 0xcb, 0x26, 0x8a, 0x3d, 0xd2, 0xa2, 0x85,
				0x74, 0x1e, 0xe4, 0x5c, 0x96, 0x45, 0x82, 0x91,
				0x71, 0xbd, 0x85, 0x53, 0x1a, 0xbe, 0xf5, 0x1f,
				0xbb, 0x79, 0x09, 0x26, 0xa2, 0xbb, 0x2f, 0x56,
				0x93, 0x58,
			},
			"",
		},
		{"aEYETYwTBo4R9pPfAkVtMx2sDhZRshDkuQ6OuMROaREzmygO32FDBRrmGl9KGVj9/07yPh2KrwUJddNxc/h22J1HfQtdDg==", nil, "invalid private key length"},
	}

	for _, v := range testVectors {
		res, err := parsePrivateKey(v.input)
		if err != nil && err.Error() != v.errorMsg {
			t.Fail()
		}
		if err == nil && res != nil && !bytes.Equal(*res, v.result) {
			t.Fail()
		}
	}
}

func TestParsePublicKey(t *testing.T) {
	testVectors := []struct {
		input    string
		result   wgtypes.Key
		errorMsg string
	}{
		{"", nil, "invalid public key length"},
		{"dGVzdA==", nil, "invalid public key length"},
		{
			"AgBE0OJFcIlJUWHRRMJFGMmmz7fEe3VbACK8ik9IrRxyNvawV8l+tzfilNojFyCylQwvBR80ORpPDtJYEHMF9A8Pwg==",
			wgtypes.Key{
				0x02, 0x00, 0x44, 0xd0, 0xe2, 0x45, 0x70, 0x89,
				0x49, 0x51, 0x61, 0xd1, 0x44, 0xc2, 0x45, 0x18,
				0xc9, 0xa6, 0xcf, 0xb7, 0xc4, 0x7b, 0x75, 0x5b,
				0x00, 0x22, 0xbc, 0x8a, 0x4f, 0x48, 0xad, 0x1c,
				0x72, 0x36, 0xf6, 0xb0, 0x57, 0xc9, 0x7e, 0xb7,
				0x37, 0xe2, 0x94, 0xda, 0x23, 0x17, 0x20, 0xb2,
				0x95, 0x0c, 0x2f, 0x05, 0x1f, 0x34, 0x39, 0x1a,
				0x4f, 0x0e, 0xd2, 0x58, 0x10, 0x73, 0x05, 0xf4,
				0x0f, 0x0f, 0xc2,
			},
			"",
		},
	}

	for _, v := range testVectors {
		res, err := parsePublicKey(v.input)
		if err != nil && err.Error() != v.errorMsg {
			t.Fail()
		}
		if err == nil && res != nil && !bytes.Equal(res, v.result) {
			t.Fail()
		}
	}
}

func TestSplitHostZone(t *testing.T) {
	testVectors := []struct {
		input string
		host  string
		zone  string
	}{
		{"fe80::1ff:fe23:4567:890a", "fe80::1ff:fe23:4567:890a", ""},
		{"fe80::1ff:fe23:4567:890a%eth0", "fe80::1ff:fe23:4567:890a", "eth0"},
	}

	for _, v := range testVectors {
		host, zone := splitHostZone(v.input)
		if host != v.host && zone != v.zone {
			t.Fail()
		}
	}
}

func TestParseEndpoint(t *testing.T) {
	testVectors := []struct {
		input string
		host  net.IP
		port  int
		zone  string
	}{
		{"192.168.1.1:1337", net.IPv4(192, 168, 1, 1), 1337, ""},
		{"[192.168.1.1]:1337", net.IPv4(192, 168, 1, 1), 1337, ""},
		{"[fe80::1ff:fe23:4567:890a]:1337", net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0xfe, 0x23, 0x45, 0x67, 0x89, 0x0a}, 1337, ""},
		{"[fe80::1ff:fe23:4567:890a%eth0]:1337", net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0xfe, 0x23, 0x45, 0x67, 0x89, 0x0a}, 1337, "eth0"},
	}

	for _, v := range testVectors {
		ip, err := parseEndpoint(v.input)

		if err != nil {
			t.Fail()
		}

		if ip != nil && (!net.IP.Equal(ip.IP, v.host) || ip.Port != v.port || ip.Zone != v.zone) {
			t.Fail()
		}
	}
}

func TestParseAllowedIPs(t *testing.T) {
	testVectors := []struct {
		input  string
		result []net.IPNet
	}{
		{
			"192.168.1.1/24",
			[]net.IPNet{
				{IP: net.IPv4(192, 168, 1, 0).Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)},
			},
		},
		{
			"192.168.1.1/24,10.10.1.1/32",
			[]net.IPNet{
				{IP: net.IPv4(192, 168, 1, 0).Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)},
				{IP: net.IPv4(10, 10, 1, 1).Mask(net.CIDRMask(32, 32)), Mask: net.CIDRMask(32, 32)},
			},
		},
		{
			"fe80::1ff:fe23:4567:890a/64",
			[]net.IPNet{
				{IP: net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, Mask: net.CIDRMask(64, 128)},
			},
		},
		{
			"10.10.1.1/32,fe80::1ff:fe23:4567:890a/64",
			[]net.IPNet{
				{IP: net.IPv4(10, 10, 1, 1).Mask(net.CIDRMask(32, 32)), Mask: net.CIDRMask(32, 32)},
				{IP: net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, Mask: net.CIDRMask(64, 128)},
			},
		},
	}

	for _, v := range testVectors {
		ipNet, err := parseAllowedIPs(v.input)

		if err != nil {
			t.Fail()
		}

		if ipNet != nil && !reflect.DeepEqual(ipNet, v.result) {
			t.Fail()
		}
	}
}

func TestParsePersistentKeepalive(t *testing.T) {
	testVectors := []struct {
		input  string
		result *time.Duration
		errMsg string
	}{
		{"0", nil, ""},
		{" 0 ", nil, ""},
		{"off", nil, ""},
		{" off ", nil, ""},
		{"", nil, "string is empty"},
		{"100", new(time.Duration), ""},
		{"10000000", nil, "persistent keepalive interval is neither 0/off nor 1-65535: 10000000"},
	}

	*testVectors[5].result = time.Duration(100) * time.Second

	for _, v := range testVectors {
		td, err := parsePersistentKeepalive(v.input)

		if err != nil && err.Error() != v.errMsg {
			t.Fail()
		}

		if err != nil && v.errMsg == "" {
			t.Fail()
		}

		if td != nil && v.result != nil && (*td != *v.result) {
			t.Fail()
		}
	}
}

func TestParseCmd(t *testing.T) {
	tempDir := t.TempDir()
	keyFile := path.Join(tempDir, "wg-test-private-key")
	pskFile := path.Join(tempDir, "wg-test-preshared-key")

	wgTestPrivateKey, err := os.Create(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	wgTestPreSharedKey, err := os.Create(pskFile)
	if err != nil {
		t.Fatal(err)
	}

	_, err = wgTestPrivateKey.WriteString("Af9+Jj7jOZ/MuGJ0Cd3boH/PsUBqtIpfdmjYmfFOnU0ilGvpU+kP8JiuDQw6PuZtXUqAGRFXSK19FLyx4YD89T+q")
	if err != nil {
		t.Fatal(err)
	}
	_, err = wgTestPreSharedKey.WriteString("3jB5o5+qR3Mc5iDMGhaSrO1GGvyWhSAK0/6fT1QR9XI=")
	if err != nil {
		t.Fatal(err)
	}

	cmdArgs := []string{
		"listen-port", "1337",
		"fwmark", "0x10",
		"private-key", keyFile,
		"peer", "AgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==",
		"remove",
		"peer", "AwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==",
		"endpoint", "192.168.0.1:1337",
		"allowed-ips", "10.10.10.1/32",
		"persistent-keepalive", "3",
		"preshared-key", pskFile,
	}

	expectedConfig := &wgtypes.Config{
		PrivateKey: &wgtypes.Key{
			0x01, 0xff, 0x7e, 0x26, 0x3e, 0xe3, 0x39, 0x9f,
			0xcc, 0xb8, 0x62, 0x74, 0x09, 0xdd, 0xdb, 0xa0,
			0x7f, 0xcf, 0xb1, 0x40, 0x6a, 0xb4, 0x8a, 0x5f,
			0x76, 0x68, 0xd8, 0x99, 0xf1, 0x4e, 0x9d, 0x4d,
			0x22, 0x94, 0x6b, 0xe9, 0x53, 0xe9, 0x0f, 0xf0,
			0x98, 0xae, 0x0d, 0x0c, 0x3a, 0x3e, 0xe6, 0x6d,
			0x5d, 0x4a, 0x80, 0x19, 0x11, 0x57, 0x48, 0xad,
			0x7d, 0x14, 0xbc, 0xb1, 0xe1, 0x80, 0xfc, 0xf5,
			0x3f, 0xaa,
		},
		ListenPort:   new(int), // need to complete
		FirewallMark: new(int), // need to complete
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: wgtypes.Key{
					0x02, 0x01, 0x46, 0xdd, 0xed, 0x7d, 0x53, 0xd9,
					0xe3, 0xa1, 0xed, 0x84, 0xda, 0xa3, 0x15, 0x26,
					0x5a, 0x71, 0x08, 0x43, 0xe9, 0xd7, 0x94, 0x80,
					0x98, 0xd1, 0x80, 0x36, 0x9f, 0x12, 0xcc, 0x9a,
					0xe4, 0xef, 0x09, 0x5b, 0x0c, 0x9d, 0x0b, 0x5a,
					0x71, 0x0a, 0x32, 0xae, 0x37, 0x89, 0x5e, 0xcc,
					0x55, 0x60, 0xb2, 0x18, 0xbd, 0x50, 0x63, 0x55,
					0x57, 0x96, 0x24, 0x70, 0xa7, 0xae, 0x1e, 0xa3,
					0xd7, 0x39, 0x79,
				},
				Remove: true,
			},
			{
				PublicKey: wgtypes.Key{
					0x03, 0x00, 0x9c, 0xaf, 0x64, 0xc7, 0x82, 0x5a,
					0x69, 0x93, 0xc4, 0x21, 0x7c, 0x46, 0xdc, 0x73,
					0xc6, 0xd0, 0xfe, 0xd4, 0x24, 0xcf, 0x5e, 0x57,
					0x38, 0x0e, 0xe0, 0xfd, 0x20, 0x5e, 0xbc, 0x2d,
					0x23, 0x05, 0xdc, 0x87, 0x7b, 0x90, 0xf6, 0x77,
					0x26, 0x2c, 0x96, 0x6f, 0xb2, 0x74, 0x78, 0xf8,
					0xc8, 0xa1, 0x0d, 0x1e, 0x1e, 0x69, 0xcf, 0xfc,
					0x16, 0x3d, 0x17, 0x80, 0xc9, 0x0c, 0x9a, 0xd0,
					0xf7, 0x02, 0xc0,
				},
				PresharedKey: &wgtypes.Key{
					0xde, 0x30, 0x79, 0xa3, 0x9f, 0xaa, 0x47, 0x73,
					0x1c, 0xe6, 0x20, 0xcc, 0x1a, 0x16, 0x92, 0xac,
					0xed, 0x46, 0x1a, 0xfc, 0x96, 0x85, 0x20, 0x0a,
					0xd3, 0xfe, 0x9f, 0x4f, 0x54, 0x11, 0xf5, 0x72,
				},
				Endpoint: &net.UDPAddr{
					IP:   net.IPv4(192, 168, 0, 1),
					Port: 1337,
				},
				PersistentKeepaliveInterval: new(time.Duration), // need to complete
				ReplaceAllowedIPs:           true,
				AllowedIPs:                  []net.IPNet{{IP: net.IPv4(10, 10, 10, 1).Mask(net.CIDRMask(32, 32)), Mask: net.CIDRMask(32, 32)}},
			},
		},
	}

	*expectedConfig.ListenPort = 1337
	*expectedConfig.FirewallMark = 16
	*expectedConfig.Peers[1].PersistentKeepaliveInterval = time.Duration(3) * time.Second

	result, err := parseCmd(cmdArgs)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(expectedConfig, result); diff != "" {
		t.Errorf("parseCmd() mismatch (-want +got):\n%s", diff)
		t.Fail()
	}
}

func TestParseConfigFile(t *testing.T) {
	config := `
[Interface]
PrivateKey = Af9+Jj7jOZ/MuGJ0Cd3boH/PsUBqtIpfdmjYmfFOnU0ilGvpU+kP8JiuDQw6PuZtXUqAGRFXSK19FLyx4YD89T+q
ListenPort = 1337
FwMark = 0x10

[Peer]
PublicKey = AgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==
Endpoint = 192.168.0.1:1337
AllowedIPs = 10.10.10.1/32, 192.168.1.1/24
PersistentKeepalive = 3
PresharedKey = 3jB5o5+qR3Mc5iDMGhaSrO1GGvyWhSAK0/6fT1QR9XI=

[Peer]
PublicKey = AwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==
Endpoint = [fe80::1ff:fe23:4567:890a%eth0]:1337
AllowedIPs = 10.10.10.2/32
`

	expectedConfig := &wgtypes.Config{
		PrivateKey: &wgtypes.Key{
			0x01, 0xff, 0x7e, 0x26, 0x3e, 0xe3, 0x39, 0x9f,
			0xcc, 0xb8, 0x62, 0x74, 0x09, 0xdd, 0xdb, 0xa0,
			0x7f, 0xcf, 0xb1, 0x40, 0x6a, 0xb4, 0x8a, 0x5f,
			0x76, 0x68, 0xd8, 0x99, 0xf1, 0x4e, 0x9d, 0x4d,
			0x22, 0x94, 0x6b, 0xe9, 0x53, 0xe9, 0x0f, 0xf0,
			0x98, 0xae, 0x0d, 0x0c, 0x3a, 0x3e, 0xe6, 0x6d,
			0x5d, 0x4a, 0x80, 0x19, 0x11, 0x57, 0x48, 0xad,
			0x7d, 0x14, 0xbc, 0xb1, 0xe1, 0x80, 0xfc, 0xf5,
			0x3f, 0xaa,
		},
		ListenPort:   new(int), // need to complete
		FirewallMark: new(int), // need to complete
		Peers: []wgtypes.PeerConfig{
			{
				PublicKey: wgtypes.Key{
					0x02, 0x01, 0x46, 0xdd, 0xed, 0x7d, 0x53, 0xd9,
					0xe3, 0xa1, 0xed, 0x84, 0xda, 0xa3, 0x15, 0x26,
					0x5a, 0x71, 0x08, 0x43, 0xe9, 0xd7, 0x94, 0x80,
					0x98, 0xd1, 0x80, 0x36, 0x9f, 0x12, 0xcc, 0x9a,
					0xe4, 0xef, 0x09, 0x5b, 0x0c, 0x9d, 0x0b, 0x5a,
					0x71, 0x0a, 0x32, 0xae, 0x37, 0x89, 0x5e, 0xcc,
					0x55, 0x60, 0xb2, 0x18, 0xbd, 0x50, 0x63, 0x55,
					0x57, 0x96, 0x24, 0x70, 0xa7, 0xae, 0x1e, 0xa3,
					0xd7, 0x39, 0x79,
				},
				PresharedKey: &wgtypes.Key{
					0xde, 0x30, 0x79, 0xa3, 0x9f, 0xaa, 0x47, 0x73,
					0x1c, 0xe6, 0x20, 0xcc, 0x1a, 0x16, 0x92, 0xac,
					0xed, 0x46, 0x1a, 0xfc, 0x96, 0x85, 0x20, 0x0a,
					0xd3, 0xfe, 0x9f, 0x4f, 0x54, 0x11, 0xf5, 0x72,
				},
				Endpoint: &net.UDPAddr{
					IP:   net.IPv4(192, 168, 0, 1),
					Port: 1337,
				},
				PersistentKeepaliveInterval: new(time.Duration), // need to complete
				AllowedIPs: []net.IPNet{
					{IP: net.IPv4(10, 10, 10, 1).Mask(net.CIDRMask(32, 32)), Mask: net.CIDRMask(32, 32)},
					{IP: net.IPv4(192, 168, 1, 0).Mask(net.CIDRMask(24, 32)), Mask: net.CIDRMask(24, 32)},
				},
			},
			{
				PublicKey: wgtypes.Key{
					0x03, 0x00, 0x9c, 0xaf, 0x64, 0xc7, 0x82, 0x5a,
					0x69, 0x93, 0xc4, 0x21, 0x7c, 0x46, 0xdc, 0x73,
					0xc6, 0xd0, 0xfe, 0xd4, 0x24, 0xcf, 0x5e, 0x57,
					0x38, 0x0e, 0xe0, 0xfd, 0x20, 0x5e, 0xbc, 0x2d,
					0x23, 0x05, 0xdc, 0x87, 0x7b, 0x90, 0xf6, 0x77,
					0x26, 0x2c, 0x96, 0x6f, 0xb2, 0x74, 0x78, 0xf8,
					0xc8, 0xa1, 0x0d, 0x1e, 0x1e, 0x69, 0xcf, 0xfc,
					0x16, 0x3d, 0x17, 0x80, 0xc9, 0x0c, 0x9a, 0xd0,
					0xf7, 0x02, 0xc0,
				},
				Endpoint: &net.UDPAddr{
					IP:   net.IP{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0xfe, 0x23, 0x45, 0x67, 0x89, 0x0a},
					Port: 1337,
					Zone: "eth0",
				},
				AllowedIPs: []net.IPNet{
					{IP: net.IPv4(10, 10, 10, 2).Mask(net.CIDRMask(32, 32)), Mask: net.CIDRMask(32, 32)},
				},
			},
		},
	}

	*expectedConfig.ListenPort = 1337
	*expectedConfig.FirewallMark = 16
	*expectedConfig.Peers[0].PersistentKeepaliveInterval = time.Duration(3) * time.Second

	configReader := strings.NewReader(config)

	result, err := parseConfigFile(configReader)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(expectedConfig, result); diff != "" {
		t.Errorf("parseConfigFile() mismatch (-want +got):\n%s", diff)
		t.Fail()
	}
}
