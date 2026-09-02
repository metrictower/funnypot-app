#!/usr/bin/env python3
"""FP-0291 §4.6 row 7 — compare ssh-audit -j output to the expected served KEXINIT, order-exact.

Usage: compare_audit.py <audit.json> <expected-kexinit.txt>
Exit 0 if every section (kex/key/enc/mac/comp) matches byte-for-byte AND in order, else 1.
"""
import json
import sys


def load_expected(path):
    sections, current = {}, None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("[") and line.endswith("]"):
                current = line[1:-1]
                sections[current] = []
            elif current is not None:
                sections[current].append(line)
    return sections


def algos(node):
    """ssh-audit lists each algorithm as a dict {'algorithm': name, ...} or a bare string."""
    out = []
    for item in node or []:
        if isinstance(item, dict):
            out.append(item.get("algorithm", ""))
        else:
            out.append(str(item))
    return out


def main():
    if len(sys.argv) != 3:
        print("usage: compare_audit.py <audit.json> <expected-kexinit.txt>", file=sys.stderr)
        return 1
    with open(sys.argv[1], encoding="utf-8") as fh:
        data = json.load(fh)
    expected = load_expected(sys.argv[2])

    # ssh-audit JSON keys per section, with fallbacks across versions.
    keymap = {
        "kex": ["kex"],
        "key": ["key"],
        "enc": ["enc"],
        "mac": ["mac"],
        "comp": ["compression", "comp"],
    }
    ok = True
    for section, want in expected.items():
        node = None
        for candidate in keymap.get(section, [section]):
            if candidate in data:
                node = data[candidate]
                break
        got = algos(node)
        if got != want:
            ok = False
            print(f"[{section}] mismatch:\n  expected: {want}\n  got:      {got}", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
