// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

func sessionHandler(s ssh.Session) {
	// Generate a cert that allows the user to login as the user
	// they used here.
	cert, err := genCert(s.PublicKey(), s.User(), s.User())
	if err != nil {
		log.Printf("cert: couldn't generate cert: %v", err)
		cert = []byte("server error")
	}

	if _, err := s.Write(cert); err != nil {
		log.Printf("couldn't send: %v", err)
	}
}

func authHandler(userPubKeys map[string]UserPubKey, insecure bool) ssh.PublicKeyHandler {
	return ssh.PublicKeyHandler(func(ctx ssh.Context, key ssh.PublicKey) bool {
		if insecure {
			return true
		}

		mKey := string(gossh.MarshalAuthorizedKey(key))
		// Drop the newline
		mKey = mKey[:len(mKey)-1]

		// If the presented pubkey is allowed to get a cert,
		// let them continue with a challenge/response. If
		// not, just stop here.
		if _, ok := userPubKeys[mKey]; ok {
			return true
		}

		return false
	})
}

type UserPubKey struct {
	PubKey string
	KeyID  string
}

type Config struct {
	HostKey     []byte
	UserPubKeys map[string]UserPubKey
}

// loadAuthorized loads and parses list of authorized keys
func loadAuthorized(authFileName string, userPubKeys map[string]UserPubKey) error {
	file, err := os.Open(authFileName)
	defer file.Close()
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	sc := bufio.NewScanner(file)

	for sc.Scan() {
		words := strings.Fields(sc.Text())
		// Check length, should be 3.
		if len(words) != 3 {
			return fmt.Errorf("parse error")
		}

		k := words[0] + " " + words[1]
		uPubKey := UserPubKey{
			PubKey: k,
			KeyID:  words[2],
		}

		userPubKeys[k] = uPubKey
	}

	if err := sc.Err(); err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}

func loadConfig(authFileName string, insecure bool) (Config, error) {
	var err error

	conf := Config{
		UserPubKeys: map[string]UserPubKey{},
	}

	// Host private key
	conf.HostKey, err = os.ReadFile("host_ed25519")
	if err != nil {
		return conf, fmt.Errorf("private key file: %w", err)
	}

	if !insecure {
		if err := loadAuthorized(authFileName, conf.UserPubKeys); err != nil {
			return conf, fmt.Errorf("%w")
		}
	}

	return conf, nil
}

func main() {
	var confFileFlag = flag.String("c", "./authorized_keys", "")
	var listenFlag = flag.String("l", "127.0.0.1:2222", "")
	var insecureFlag = flag.Bool("insecure", false, "Disable user authentication")

	flag.Parse()

	conf, err := loadConfig(*confFileFlag, *insecureFlag)
	if err != nil {
		log.Fatalf("couldn't load config file: %v", err)
	}

	hostKeySigner, err := gossh.ParsePrivateKey(conf.HostKey)
	if err != nil {
		log.Fatalf("unable to parse private key: %v", err)
	}

	s := &ssh.Server{
		Addr:             *listenFlag,
		Handler:          sessionHandler,
		PublicKeyHandler: authHandler(conf.UserPubKeys, *insecureFlag),
		PasswordHandler:  nil,
	}
	s.AddHostKey(hostKeySigner)

	log.Printf("starting ssh server on %v", *listenFlag)
	log.Fatal(s.ListenAndServe())
}
