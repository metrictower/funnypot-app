module funnypot/interop/gossh

go 1.22

// Pinned (plan-review adjudication 8): golang.org/x/crypto >= 0.17 negotiates kex-strict-c,
// aes128-gcm@openssh.com first and hmac-sha2-256-etm — a distinct matrix point from OpenSSH.
require golang.org/x/crypto v0.21.0

require golang.org/x/sys v0.18.0 // indirect
