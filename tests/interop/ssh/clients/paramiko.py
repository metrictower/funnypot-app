#!/usr/bin/env python3
"""FP-0291 §2.7 row 4 — paramiko client: password auth + `exec id`, print stdout.

paramiko negotiates curve25519-sha256@libssh.org / aes128-ctr + hmac-sha2-256 (E&M, non-etm) /
ssh-ed25519 by default — a distinct point in the matrix from OpenSSH. Prints the command output so
run.sh can assert uid=0(root). Pinned via `pip install paramiko==3.4.0` in run.sh.
"""
import sys

import paramiko


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=host,
        port=port,
        username="root",
        password="hunter2",
        allow_agent=False,
        look_for_keys=False,
        timeout=15,
    )
    stdin, stdout, stderr = client.exec_command("id")
    out = stdout.read().decode("utf-8", "replace")
    sys.stdout.write(out)
    transport = client.get_transport()
    if transport is not None:
        # Recorded, not asserted (verify at code): the negotiated algorithms paramiko chose.
        sys.stderr.write("negotiated: %s\n" % transport.get_security_options().kex[:1])
    client.close()
    return 0 if "uid=0(root)" in out else 1


if __name__ == "__main__":
    sys.exit(main())
