// SPDX-FileCopyrightText: 2024 Tillitis AB <tillitis.se>
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

func run(cmdLine []string) (string, string, int) {
	var outBuf bytes.Buffer
	var errBuf bytes.Buffer

	cmd := exec.Command(cmdLine[0], cmdLine[1:]...) // #nosec G204
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	stdout := string(outBuf.Bytes())
	stderr := string(errBuf.Bytes())
	code := 0
	if err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			log.Printf("Failed to run %v: %s.\nSTDOUT:\n%s\nSTDERR:\n%s\n", cmdLine, err, stdout, stderr)
			os.Exit(1)
		}
		code = exitError.ExitCode()
	}

	return stdout, stderr, code
}

func rolePermissions(user string) ([]string, error) {
	var options []string

	switch user {
	case "webuser":
		options = append(options, "-V", "+8h")

	case "admin":
		options = append(options, "-V", "+30m",
			"-O", "force-command=internal-sftp",
			"-O", "no-port-forwarding")
	case "loguser":
		options = append(options, "-V", "+52w",
			"-O", "force-command=/home/admin/dumplog",
			"-O", "no-port-forwarding")
	default:
		return []string{}, fmt.Errorf("unknown user role")
	}

	return options, nil

}

func genCert(pubkey ssh.PublicKey, keyid string, user string) ([]byte, error) {
	mKey := gossh.MarshalAuthorizedKey(pubkey)
	log.Printf("Generating cert of pubkey %s\n", mKey)

	f, err := os.CreateTemp("", "ssh-ca")
	if err != nil {
		return nil, fmt.Errorf("couldn't create temp file: %w", err)
	}
	defer os.Remove(f.Name())

	_, err = f.Write(mKey)
	if err != nil {
		return nil, fmt.Errorf("couldn't write to temp file: %w", err)
	}

	permissions, err := rolePermissions(user)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	cmdLine := []string{
		"ssh-keygen",
		"-Us", "./ca_key.pub",
		"-I", keyid,
		"-n", user,
	}

	cmdLine = append(cmdLine, permissions...)
	cmdLine = append(cmdLine, f.Name())

	if stdout, stderr, code := run(cmdLine); code != 0 {
		log.Printf("stdout: %v\nstderr: %v", stdout, stderr)
		return nil, fmt.Errorf("couldn't run ssh-keygen")
	}
	defer os.Remove(f.Name() + "-cert.pub")

	cert, err := os.ReadFile(f.Name() + "-cert.pub")
	if err != nil {
		return nil, fmt.Errorf("unable to read cert: %w", err)
	}

	return cert, nil
}
