/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2020 BI.ZONE LLC. All Rights Reserved.
 */

package key

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func showUsage(file io.Writer, cmd string) {
	fmt.Fprintf(file, "Usage: %s %s\n", os.Args[0], cmd)
}

func GenKey(args []string) int {
	if len(args) == 2 && (args[1] == "-h" || args[1] == "--help" || args[1] == "help") {
		showUsage(os.Stdout, args[0])
		return 0
	}

	if len(args) != 1 {
		showUsage(os.Stderr, args[0])
		return 1
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate private key: %s\n", err)
		return 1
	}

	fmt.Println(base64.StdEncoding.EncodeToString(key))

	return 0
}

func PubKey(args []string) int {
	if len(args) == 2 && (args[1] == "-h" || args[1] == "--help" || args[1] == "help") {
		showUsage(os.Stdout, args[0])
		return 0
	}

	if len(args) != 1 {
		showUsage(os.Stderr, args[0])
		return 1
	}

	var input string

	fmt.Scan(&input)

	rawKey, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to decode base64: %s\n", err)
		return 1
	}

	privateKey, err := wgtypes.NewKey(rawKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse private key: %s\n", err)
		return 1
	}

	pubKey := privateKey.PublicKey()

	b64PubKey := base64.StdEncoding.EncodeToString(pubKey)
	fmt.Println(b64PubKey)

	return 0
}

func GenPsk(args []string) int {
	if len(args) == 2 && (args[1] == "-h" || args[1] == "--help" || args[1] == "help") {
		showUsage(os.Stdout, args[0])
		return 0
	}

	if len(args) != 1 {
		showUsage(os.Stderr, args[0])
		return 1
	}

	psk, err := wgtypes.GenerateKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate pre-shared key: %s\n", err)
		return 1
	}

	fmt.Println(psk.String())

	return 0
}
