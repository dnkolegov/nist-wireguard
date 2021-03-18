/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package show

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestPrettyTime(t *testing.T) {
	testVectors := []struct {
		time   int64
		result string
	}{
		{0, ""},
		{1, "1 second"},
		{10, "10 seconds"},
		{60, "1 minute"},
		{150, "2 minutes, 30 seconds"},
		{3600, "1 hour"},
		{7220, "2 hours, 20 seconds"},
		{86400, "1 day"},
		{249201, "2 days, 21 hours, 13 minutes, 21 seconds"},
		{31536000, "1 year"},
		{347436473, "11 years, 6 days, 6 hours, 7 minutes, 53 seconds"},
	}

	for _, v := range testVectors {
		if prettyTime(v.time) != v.result {
			t.Fail()
		}
	}
}

func TestPrettyBytes(t *testing.T) {
	testVectors := []struct {
		size   int64
		result string
	}{
		{0, "0 B"},
		{10, "10 B"},
		{1024, "1.00 KiB"},
		{123456, "120.56 KiB"},
		{1048576, "1.00 MiB"},
		{123456789, "117.74 MiB"},
		{1073741824, "1.00 GiB"},
		{12345678912, "11.50 GiB"},
		{1099511627776, "1.00 TiB"},
		{12345678912345, "11.23 TiB"},
	}

	for _, v := range testVectors {
		if prettyBytes(v.size) != v.result {
			t.Fail()
		}
	}
}

var testDevice = &wgtypes.Device{
	Name: "wg0",
	Type: wgtypes.Userspace,
	PrivateKey: wgtypes.Key{
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
	PublicKey: wgtypes.Key{
		0x03, 0x00, 0x09, 0x99, 0x56, 0x4c, 0xbb, 0xf7,
		0x26, 0xe0, 0x90, 0xd8, 0x4f, 0x6a, 0xc9, 0x26,
		0xf2, 0x33, 0xc9, 0x8a, 0x4f, 0x65, 0x5a, 0xc4,
		0xae, 0x05, 0xb2, 0x90, 0xb3, 0x53, 0x6f, 0x11,
		0x39, 0x7a, 0x5e, 0x94, 0xa6, 0xb2, 0x47, 0x89,
		0x47, 0x0e, 0x21, 0xfe, 0xdf, 0x79, 0x1f, 0x4e,
		0xf5, 0xe4, 0x4d, 0xa0, 0x80, 0x9d, 0x56, 0xfe,
		0xb5, 0xfa, 0xf5, 0x86, 0xbd, 0xf1, 0xb5, 0x9d,
		0x71, 0x50, 0x4a,
	},
	ListenPort:   1337,
	FirewallMark: 16,
	Peers: []wgtypes.Peer{
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
			PresharedKey: wgtypes.Key{
				0xde, 0x30, 0x79, 0xa3, 0x9f, 0xaa, 0x47, 0x73,
				0x1c, 0xe6, 0x20, 0xcc, 0x1a, 0x16, 0x92, 0xac,
				0xed, 0x46, 0x1a, 0xfc, 0x96, 0x85, 0x20, 0x0a,
				0xd3, 0xfe, 0x9f, 0x4f, 0x54, 0x11, 0xf5, 0x72,
			},
			Endpoint: &net.UDPAddr{
				IP:   net.IPv4(192, 168, 0, 1),
				Port: 1337,
			},
			PersistentKeepaliveInterval: 3,
			LastHandshakeTime:           time.Unix(time.Now().Unix()-10, 0),
			ReceiveBytes:                5000000,
			TransmitBytes:               10000000,
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
			PresharedKey: wgtypes.Key{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
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

func TestPrettyPrint(t *testing.T) {
	expectedOutput := `interface: wg0
  public key: AwAJmVZMu/cm4JDYT2rJJvIzyYpPZVrErgWykLNTbxE5el6UprJHiUcOIf7feR9O9eRNoICdVv61+vWGvfG1nXFQSg==
  private key: Af9+Jj7jOZ/MuGJ0Cd3boH/PsUBqtIpfdmjYmfFOnU0ilGvpU+kP8JiuDQw6PuZtXUqAGRFXSK19FLyx4YD89T+q
  listening port: 1337
  fwmark: 0x10

peer: AgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==
  preshared key: 3jB5o5+qR3Mc5iDMGhaSrO1GGvyWhSAK0/6fT1QR9XI=
  endpoint: 192.168.0.1:1337
  allowed-ips: 10.10.10.1/32, 192.168.1.0/24
  latest handshake: 10 seconds
  transfer: 4.77 MiB received, 9.54 MiB sent

peer: AwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==
  endpoint: [fe80::1ff:fe23:4567:890a%eth0]:1337
  allowed-ips: 10.10.10.2/32
`

	result := bytes.NewBufferString("")
	prettyPrint(result, testDevice)

	if diff := cmp.Diff(expectedOutput, result.String()); diff != "" {
		t.Errorf("prettyPrint() mismatch (-want +got):\n%s", diff)
		t.Fail()
	}
}

func TestDumpPrint(t *testing.T) {
	expectedOutput1 := `Af9+Jj7jOZ/MuGJ0Cd3boH/PsUBqtIpfdmjYmfFOnU0ilGvpU+kP8JiuDQw6PuZtXUqAGRFXSK19FLyx4YD89T+q	AwAJmVZMu/cm4JDYT2rJJvIzyYpPZVrErgWykLNTbxE5el6UprJHiUcOIf7feR9O9eRNoICdVv61+vWGvfG1nXFQSg==	1337	0x10
AgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==	3jB5o5+qR3Mc5iDMGhaSrO1GGvyWhSAK0/6fT1QR9XI=	192.168.0.1:1337	10.10.10.1/32,192.168.1.0/24	10	5000000	10000000	0
AwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==	(none)	[fe80::1ff:fe23:4567:890a%eth0]:1337	10.10.10.2/32	0	0	0	off
`
	expectedOutput2 := `wg0	Af9+Jj7jOZ/MuGJ0Cd3boH/PsUBqtIpfdmjYmfFOnU0ilGvpU+kP8JiuDQw6PuZtXUqAGRFXSK19FLyx4YD89T+q	AwAJmVZMu/cm4JDYT2rJJvIzyYpPZVrErgWykLNTbxE5el6UprJHiUcOIf7feR9O9eRNoICdVv61+vWGvfG1nXFQSg==	1337	0x10
wg0	AgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==	3jB5o5+qR3Mc5iDMGhaSrO1GGvyWhSAK0/6fT1QR9XI=	192.168.0.1:1337	10.10.10.1/32,192.168.1.0/24	10	5000000	10000000	0
wg0	AwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==	(none)	[fe80::1ff:fe23:4567:890a%eth0]:1337	10.10.10.2/32	0	0	0	off
`

	testDevice.Peers[0].LastHandshakeTime = time.Unix(time.Now().Unix()-10, 0)

	result := bytes.NewBufferString("")
	dumpPrint(result, testDevice, false)

	if diff := cmp.Diff(expectedOutput1, result.String()); diff != "" {
		t.Errorf("dumpPrint() mismatch (-want +got):\n%s", diff)
		t.Fail()
	}

	result = bytes.NewBufferString("")
	dumpPrint(result, testDevice, true)

	if diff := cmp.Diff(expectedOutput2, result.String()); diff != "" {
		t.Errorf("dumpPrint() mismatch (-want +got):\n%s", diff)
		t.Fail()
	}
}

func TestUglyPrint(t *testing.T) {
	testVectors := []struct {
		param          string
		showDeviceName bool
		result         string
	}{
		{"public-key", false, "AwAJmVZMu/cm4JDYT2rJJvIzyYpPZVrErgWykLNTbxE5el6UprJHiUcOIf7feR9O9eRNoICdVv61+vWGvfG1nXFQSg==\n"},
		{"public-key", true, "wg0\tAwAJmVZMu/cm4JDYT2rJJvIzyYpPZVrErgWykLNTbxE5el6UprJHiUcOIf7feR9O9eRNoICdVv61+vWGvfG1nXFQSg==\n"},

		{"private-key", false, "Af9+Jj7jOZ/MuGJ0Cd3boH/PsUBqtIpfdmjYmfFOnU0ilGvpU+kP8JiuDQw6PuZtXUqAGRFXSK19FLyx4YD89T+q\n"},
		{"private-key", true, "wg0\tAf9+Jj7jOZ/MuGJ0Cd3boH/PsUBqtIpfdmjYmfFOnU0ilGvpU+kP8JiuDQw6PuZtXUqAGRFXSK19FLyx4YD89T+q\n"},

		{"listen-port", false, "1337\n"},
		{"listen-port", true, "wg0\t1337\n"},

		{"fwmark", false, "0x10\n"},
		{"fwmark", true, "wg0\t0x10\n"},

		{"endpoints", false, "AgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==\t192.168.0.1:1337\nAwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==\t[fe80::1ff:fe23:4567:890a%eth0]:1337\n"},
		{"endpoints", true, "wg0\tAgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==\t192.168.0.1:1337\nwg0\tAwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==\t[fe80::1ff:fe23:4567:890a%eth0]:1337\n"},

		{"allowed-ips", false, "AgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==\t10.10.10.1/32 192.168.1.0/24\nAwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==\t10.10.10.2/32\n"},
		{"allowed-ips", true, "wg0\tAgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==\t10.10.10.1/32 192.168.1.0/24\nwg0\tAwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==\t10.10.10.2/32\n"},

		{"latest-handshakes", false, "AgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==\t10\nAwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==\t0\n"},
		{"latest-handshakes", true, "wg0\tAgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==\t10\nwg0\tAwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==\t0\n"},

		{"transfer", false, "AgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==\t5000000\t10000000\nAwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==\t0\t0\n"},
		{"transfer", true, "wg0\tAgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==\t5000000\t10000000\nwg0\tAwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==\t0\t0\n"},

		{"persistent-keepalive", false, "AgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==\t0\nAwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==\toff\n"},
		{"persistent-keepalive", true, "wg0\tAgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==\t0\nwg0\tAwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==\toff\n"},

		{"preshared-keys", false, "AgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==\t3jB5o5+qR3Mc5iDMGhaSrO1GGvyWhSAK0/6fT1QR9XI=\nAwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==\t(none)\n"},
		{"preshared-keys", true, "wg0\tAgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==\t3jB5o5+qR3Mc5iDMGhaSrO1GGvyWhSAK0/6fT1QR9XI=\nwg0\tAwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==\t(none)\n"},

		{"peers", false, "AgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==\nAwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==\n"},
		{"peers", true, "wg0\tAgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==\nwg0\tAwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==\n"},
	}

	testDevice.Peers[0].LastHandshakeTime = time.Unix(time.Now().Unix()-10, 0)

	for _, v := range testVectors {
		result := bytes.NewBufferString("")
		_ = uglyPrint(result, testDevice, v.param, v.showDeviceName)

		if diff := cmp.Diff(v.result, result.String()); diff != "" {
			t.Errorf("uglyPrint() mismatch (-want +got):\n%s", diff)
			t.Fail()
		}
	}
}

func TestPrintConf(t *testing.T) {
	expextedOutput := `[Interface]
ListenPort = 1337
FwMark = 0x10
PrivateKey = Af9+Jj7jOZ/MuGJ0Cd3boH/PsUBqtIpfdmjYmfFOnU0ilGvpU+kP8JiuDQw6PuZtXUqAGRFXSK19FLyx4YD89T+q

[Peer]
PublicKey = AgFG3e19U9njoe2E2qMVJlpxCEPp15SAmNGANp8SzJrk7wlbDJ0LWnEKMq43iV7MVWCyGL1QY1VXliRwp64eo9c5eQ==
PresharedKey = 3jB5o5+qR3Mc5iDMGhaSrO1GGvyWhSAK0/6fT1QR9XI=
AllowedIPs = 10.10.10.1/32, 192.168.1.0/24
Endpoint = 192.168.0.1:1337
PersistentKeepalive = 0

[Peer]
PublicKey = AwCcr2THglppk8QhfEbcc8bQ/tQkz15XOA7g/SBevC0jBdyHe5D2dyYslm+ydHj4yKENHh5pz/wWPReAyQya0PcCwA==
AllowedIPs = 10.10.10.2/32
Endpoint = [fe80::1ff:fe23:4567:890a%eth0]:1337
`

	result := bytes.NewBufferString("")
	printConf(result, testDevice)

	if diff := cmp.Diff(expextedOutput, result.String()); diff != "" {
		t.Errorf("printConf() mismatch (-want +got):\n%s", diff)
		t.Fail()
	}
}
