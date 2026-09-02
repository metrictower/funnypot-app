// FP-0291 §2.7 row 5 — Go golang.org/x/crypto/ssh client: password auth + `exec id`.
//
// x/crypto >= 0.17 negotiates strict kex (kex-strict-c), leads with aes128-gcm@openssh.com and
// hmac-sha2-256-etm — a distinct point in the matrix. Host key preference (ecdsa vs ed25519) is
// recorded, not asserted (verify at code). Prints the command output so run.sh asserts uid=0(root).
package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	host := os.Getenv("HOST")
	port := os.Getenv("PORT")
	if host == "" {
		host = "127.0.0.1"
	}
	if port == "" {
		port = "2222"
	}

	config := &ssh.ClientConfig{
		User:            "root",
		Auth:            []ssh.AuthMethod{ssh.Password("hunter2")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         15 * time.Second,
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(host, port), config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		fmt.Fprintln(os.Stderr, "session:", err)
		os.Exit(1)
	}
	defer session.Close()

	out, err := session.Output("id")
	if err != nil {
		fmt.Fprintln(os.Stderr, "exec:", err)
		os.Exit(1)
	}
	os.Stdout.Write(out)
}
