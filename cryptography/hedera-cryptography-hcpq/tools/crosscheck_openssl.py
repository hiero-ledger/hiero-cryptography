#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Cross-checks the HCPQ v1 signature vectors with an implementation independent of the Java module.

SHA3-256 framing is recomputed with Python's hashlib and every ML-DSA-44 operation (seeded key generation,
deterministic signing, context strings, raw M' signing and verification) uses the OpenSSL 3.5+ command line.

Usage: crosscheck_openssl.py src/test/resources/hcpq-v1/signature-vectors.json
"""
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

CONTEXT = b"HCPQ-SIG-TX-v1"
PUBLIC_KEY_LENGTH = 1312
SIGNATURE_LENGTH = 2420
KEY_ID_LENGTH = 32
SPKI_HEADER_LENGTH = 22  # DER SubjectPublicKeyInfo prefix in front of a raw ML-DSA-44 public key


def key_id(public_key: bytes) -> bytes:
    return hashlib.sha3_256(
        b"HCPQ-SIG-KEY-ID\0" + b"\x01" + b"\x02" + len(public_key).to_bytes(8, "big") + public_key
    ).digest()


def transaction_digest(ledger_id: bytes, body: bytes) -> bytes:
    return hashlib.sha3_256(
        b"HCPQ-SIG-HEDERA-TX\0"
        + b"\x01"
        + len(ledger_id).to_bytes(2, "big")
        + ledger_id
        + len(body).to_bytes(8, "big")
        + body
    ).digest()


def fips204_message(context: bytes, message: bytes) -> bytes:
    return b"\x00" + bytes([len(context)]) + context + message


class OpenSsl:
    def __init__(self, workdir: str):
        self.workdir = workdir

    def _file(self, name: str, data: bytes) -> str:
        path = os.path.join(self.workdir, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    @staticmethod
    def _run(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(["openssl", *args], capture_output=True)

    def keygen(self, name: str, seed_hex: str) -> tuple[str, str, bytes]:
        private_pem = os.path.join(self.workdir, name + ".pem")
        public_pem = os.path.join(self.workdir, name + ".pub.pem")
        self._run("genpkey", "-algorithm", "ML-DSA-44", "-pkeyopt", "hexseed:" + seed_hex, "-out", private_pem)
        self._run("pkey", "-in", private_pem, "-pubout", "-out", public_pem)
        spki = self._run("pkey", "-in", private_pem, "-pubout", "-outform", "DER").stdout
        return private_pem, public_pem, spki[SPKI_HEADER_LENGTH:]

    def sign(self, private_pem: str, message: bytes, context: bytes | None = None, raw: bool = False) -> bytes:
        args = ["pkeyutl", "-sign", "-inkey", private_pem, "-rawin", "-in", self._file("message.bin", message)]
        args += ["-pkeyopt", "deterministic:1"]
        if raw:
            args += ["-pkeyopt", "message-encoding:0"]
        if context:
            args += ["-pkeyopt", "hexcontext-string:" + context.hex()]
        return self._run(*args).stdout

    def verify(self, public_pem: str, message: bytes, signature: bytes, context: bytes) -> bool:
        return self._run(
            "pkeyutl", "-verify", "-pubin", "-inkey", public_pem, "-rawin",
            "-in", self._file("message.bin", message),
            "-sigfile", self._file("signature.bin", signature),
            "-pkeyopt", "hexcontext-string:" + context.hex(),
        ).returncode == 0


def require_openssl_3_5() -> None:
    version = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout
    match = re.match(r"OpenSSL (\d+)\.(\d+)", version)
    if not match or (int(match.group(1)), int(match.group(2))) < (3, 5):
        sys.exit(f"OpenSSL 3.5 or later is required for ML-DSA, found: {version.strip() or 'none'}")


def main(path: str) -> int:
    require_openssl_3_5()
    with open(path, encoding="utf-8") as f:
        vectors = json.load(f)
    failures = 0

    def check(ok: bool, what: str) -> None:
        nonlocal failures
        print(("ok   " if ok else "FAIL ") + what)
        failures += 0 if ok else 1

    with tempfile.TemporaryDirectory() as workdir:
        openssl = OpenSsl(workdir)
        keys = {}
        for k in vectors["key_id"]:
            public_key = bytes.fromhex(k["public_key"])
            check(key_id(public_key).hex() == k["key_id"], f"key_id {k['id']}")
            if "seed" in k:
                private_pem, public_pem, derived = openssl.keygen(k["id"], k["seed"])
                check(derived == public_key, f"public key from seed {k['id']}")
                keys[k["id"]] = (private_pem, public_pem, public_key, bytes.fromhex(k["key_id"]))

        for d in vectors["transaction_digest"]:
            digest = transaction_digest(bytes.fromhex(d["ledger_id"]), bytes.fromhex(d["body"]))
            check(digest.hex() == d["transaction_digest"], f"transaction_digest {d['id']}")

        for t in vectors["signature"]:
            private_pem, public_pem, public_key, identifier = keys[t["key"]]
            public_key = bytes.fromhex(t["public_key"]) if "public_key" in t else public_key
            identifier = bytes.fromhex(t["key_id"]) if "key_id" in t else identifier
            signature = bytes.fromhex(t["signature"])
            digest = transaction_digest(bytes.fromhex(t["ledger_id"]), bytes.fromhex(t["body"]))

            # HCPQ verification: exact lengths, exact key-ID match, then ML-DSA-44 with the HCPQ context.
            well_formed = (
                len(public_key) == PUBLIC_KEY_LENGTH
                and len(identifier) == KEY_ID_LENGTH
                and len(signature) == SIGNATURE_LENGTH
                and key_id(public_key) == identifier
            )
            verified = well_formed and openssl.verify(public_pem, digest, signature, CONTEXT)
            check(verified == (t["result"] == "valid"), f"verify {t['id']} is {t['result']}")

            if t["result"] == "valid":
                check(digest.hex() == t["transaction_digest"], f"transaction_digest of {t['id']}")
                m_prime = fips204_message(CONTEXT, digest)
                check(m_prime.hex() == t["fips204_message"], f"fips204_message of {t['id']}")
                check(openssl.sign(private_pem, digest, CONTEXT) == signature, f"deterministic signature {t['id']}")
                check(openssl.sign(private_pem, m_prime, raw=True) == signature, f"signature of M' {t['id']}")

            provenance = t.get("signed_as")
            if provenance and provenance["mode"] == "ml_dsa":
                signer_pem = keys[provenance["key"]][0]
                regenerated = openssl.sign(
                    signer_pem, bytes.fromhex(provenance["message"]), bytes.fromhex(provenance["context"])
                )
                check(regenerated == signature, f"signed_as reproduces {t['id']}")
            elif provenance:
                print(f"skip signed_as {t['id']}: {provenance['mode']} is not available in the OpenSSL CLI")

    print(f"\n{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
