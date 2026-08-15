"""Generate salt and SHA-256(salt + password) for authserver's users.conf.

Usage: python gen_hash.py <password>
"""

import hashlib
import secrets
import sys


def make_hash(password):
    """Return (salt, digest) where digest is the hex sha256 of salt+password."""
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode()).hexdigest()
    return salt, digest


def main(argv=None):
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1:
        print("Usage: gen_hash.py <password>", file=sys.stderr)
        return 1
    salt, digest = make_hash(args[0])
    print(f"salt={salt}")
    print(f"hash={digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
