package wguser

import (
	"net"
	"os"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/internal/wgtest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Example string source (with some slight modifications to use all fields):
// https://www.wireguard.com/xplatform/#cross-platform-userspace-implementation.
const okSet = `set=1
private_key=01240cd97377d287d75c258204714e8b5d27c4453b40052877ac71923bf8d206e92a6853919d294b739131340e9e476879d711cd7bfea062d2f702997e41a12a382d
listen_port=12912
fwmark=0
replace_peers=true
public_key=0301fc42b519241594214d4902d170f218704a90838b9255c6da9dcd6e2a552a5a4e2879b58c7db2694a987fd95030d081bbb5c784a77edda442b54d649dc97408e878
preshared_key=188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52
endpoint=[abcd:23::33%2]:51820
replace_allowed_ips=true
allowed_ip=192.168.4.4/32
public_key=030053cb7aa78110dbdf3c947c4b03c508735b96e71afe0a29a9826904dfaec86ff4776601b84e01695702f0319fc5b74699544d3c7dcf02b329011d9d3b55a952e2f0
update_only=true
endpoint=182.122.22.19:3233
persistent_keepalive_interval=111
replace_allowed_ips=true
allowed_ip=192.168.4.6/32
public_key=02006c771a294a8b4e587022bf95a5644f0fd97327d77843a74bf7536c802fe0831cce473456930e63c72f05e88f6a175a02b7d1932a77bf6e112b6d9adf63a49cf631
endpoint=5.152.198.39:51820
replace_allowed_ips=true
allowed_ip=192.168.4.10/32
allowed_ip=192.168.4.11/32
public_key=030128d24cf79a49dacb5d071dbbf1578c8a7781504ffd64380dab36fa0649885350a2b957a0e48a31704ed7b158cfc8f7e3760ef807ae50401cb7587ef0d7689d0571
remove=true

`

func TestClientConfigureDeviceError(t *testing.T) {
	tests := []struct {
		name     string
		device   string
		cfg      wgtypes.Config
		res      []byte
		notExist bool
	}{
		{
			name:     "not found",
			device:   "wg1",
			notExist: true,
		},
		{
			name:   "bad errno",
			device: testDevice,
			res:    []byte("errno=1\n\n"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, done := testClient(t, tt.res)
			defer done()

			err := c.ConfigureDevice(tt.device, tt.cfg)
			if err == nil {
				t.Fatal("expected an error, but none occurred")
			}

			if !tt.notExist && os.IsNotExist(err) {
				t.Fatalf("expected other error, but got not exist: %v", err)
			}
			if tt.notExist && !os.IsNotExist(err) {
				t.Fatalf("expected not exist error, but got: %v", err)
			}
		})
	}
}

func TestClientConfigureDeviceOK(t *testing.T) {
	tests := []struct {
		name string
		cfg  wgtypes.Config
		req  string
	}{
		{
			name: "ok, none",
			req:  "set=1\n\n",
		},
		{
			name: "ok, clear key",
			cfg: wgtypes.Config{
				PrivateKey: &wgtypes.Key{
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00,
				},
			},
			req: "set=1\nprivate_key=000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\n\n",
		},
		{
			name: "ok, all",
			cfg: wgtypes.Config{
				PrivateKey:   keyPtr(wgtest.MustHexKey("01240cd97377d287d75c258204714e8b5d27c4453b40052877ac71923bf8d206e92a6853919d294b739131340e9e476879d711cd7bfea062d2f702997e41a12a382d")),
				ListenPort:   intPtr(12912),
				FirewallMark: intPtr(0),
				ReplacePeers: true,
				Peers: []wgtypes.PeerConfig{
					{
						PublicKey:         wgtest.MustHexKey("0301fc42b519241594214d4902d170f218704a90838b9255c6da9dcd6e2a552a5a4e2879b58c7db2694a987fd95030d081bbb5c784a77edda442b54d649dc97408e878"),
						PresharedKey:      keyPtr(wgtest.MustHexKey("188515093e952f5f22e865cef3012e72f8b5f0b598ac0309d5dacce3b70fcf52")),
						Endpoint:          wgtest.MustUDPAddr("[abcd:23::33%2]:51820"),
						ReplaceAllowedIPs: true,
						AllowedIPs: []net.IPNet{
							wgtest.MustCIDR("192.168.4.4/32"),
						},
					},
					{
						PublicKey:                   wgtest.MustHexKey("030053cb7aa78110dbdf3c947c4b03c508735b96e71afe0a29a9826904dfaec86ff4776601b84e01695702f0319fc5b74699544d3c7dcf02b329011d9d3b55a952e2f0"),
						UpdateOnly:                  true,
						Endpoint:                    wgtest.MustUDPAddr("182.122.22.19:3233"),
						PersistentKeepaliveInterval: durPtr(111 * time.Second),
						ReplaceAllowedIPs:           true,
						AllowedIPs: []net.IPNet{
							wgtest.MustCIDR("192.168.4.6/32"),
						},
					},
					{
						PublicKey:         wgtest.MustHexKey("02006c771a294a8b4e587022bf95a5644f0fd97327d77843a74bf7536c802fe0831cce473456930e63c72f05e88f6a175a02b7d1932a77bf6e112b6d9adf63a49cf631"),
						Endpoint:          wgtest.MustUDPAddr("5.152.198.39:51820"),
						ReplaceAllowedIPs: true,
						AllowedIPs: []net.IPNet{
							wgtest.MustCIDR("192.168.4.10/32"),
							wgtest.MustCIDR("192.168.4.11/32"),
						},
					},
					{
						PublicKey: wgtest.MustHexKey("030128d24cf79a49dacb5d071dbbf1578c8a7781504ffd64380dab36fa0649885350a2b957a0e48a31704ed7b158cfc8f7e3760ef807ae50401cb7587ef0d7689d0571"),
						Remove:    true,
					},
				},
			},
			req: okSet,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, done := testClient(t, nil)

			if err := c.ConfigureDevice(testDevice, tt.cfg); err != nil {
				t.Fatalf("failed to configure device: %v", err)
			}

			req := done()

			if want, got := tt.req, string(req); want != got {
				t.Fatalf("unexpected configure request:\nwant:\n%s\ngot:\n%s", want, got)
			}
		})
	}
}
