#!/usr/bin/env python3
"""FP-0291 §2.7 row 6 — ssh2-python (bundles libssh2 1.11): password auth + `exec id`.

libssh2 brings its own kex/cipher/MAC preferences (recorded, not asserted). Prints the command output
so run.sh can assert uid=0(root). Pinned via `pip install ssh2-python==1.1.1` in run.sh.
"""
import socket
import sys

from ssh2.session import Session


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    session = Session()
    session.handshake(sock)
    session.userauth_password("root", "hunter2")

    channel = session.open_session()
    channel.execute("id")

    out = b""
    while True:
        size, data = channel.read()
        if size <= 0:
            break
        out += data
    channel.close()

    text = out.decode("utf-8", "replace")
    sys.stdout.write(text)
    return 0 if "uid=0(root)" in text else 1


if __name__ == "__main__":
    sys.exit(main())
