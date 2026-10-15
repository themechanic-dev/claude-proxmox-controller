"""The API token secrets, locked with a password the user types when the app starts.

    {"locked": {"v": 1, "kdf": "scrypt", "n": 131072, "r": 8, "p": 1, "salt": …, "nonce": …, "data": …}}

The key comes from the password through scrypt (128 MiB, about 0.4 s: costly to guess offline); the secrets are
sealed with AES-256-GCM, which also notices any change to the file. The password itself is never stored; the key
lives only in the running app, so it can save again without asking."""

from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KDF = {"n": 1 << 17, "r": 8, "p": 1}  # OWASP's minimum for scrypt
AAD = b"proxmox-controller/secrets/v1"


class WrongPassword(Exception):
    pass


@dataclass(frozen=True)
class Key:
    salt: bytes
    key: bytes
    n: int
    r: int
    p: int


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def derive(password: str, salt: bytes | None = None, n: int | None = None, r: int | None = None,
           p: int | None = None) -> Key:
    """A new key (new salt) with today's cost, or the key of a saved file from its salt and cost."""
    n, r, p = n or KDF["n"], r or KDF["r"], p or KDF["p"]
    salt = salt if salt is not None else os.urandom(16)
    key = Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(password.encode("utf-8"))
    return Key(salt, key, n, r, p)


def is_locked(blob: dict) -> bool:
    return isinstance(blob, dict) and isinstance(blob.get("locked"), dict)


def seal(payload: dict, key: Key) -> dict:
    nonce = os.urandom(12)  # new for every save: GCM must never reuse one with the same key
    data = AESGCM(key.key).encrypt(nonce, json.dumps(payload).encode("utf-8"), AAD)
    return {"locked": {"v": 1, "kdf": "scrypt", "n": key.n, "r": key.r, "p": key.p, "salt": _b64(key.salt),
                       "nonce": _b64(nonce), "data": _b64(data)}}


def open_with_key(blob: dict, key: Key) -> dict:
    """The secrets, opened with a key already derived. WrongPassword if the key does not fit (or the file changed)."""
    try:
        box = blob["locked"]
        plain = AESGCM(key.key).decrypt(base64.b64decode(box["nonce"]), base64.b64decode(box["data"]), AAD)
        payload = json.loads(plain)
    except (InvalidTag, KeyError, ValueError, TypeError) as e:
        raise WrongPassword("Wrong password.") from e
    return payload if isinstance(payload, dict) else {}


def open_with(blob: dict, password: str) -> tuple[dict, Key]:
    """The secrets and the key that opened them. WrongPassword for a wrong password or a changed file."""
    try:
        box = blob["locked"]
        key = derive(password, base64.b64decode(box["salt"]), int(box["n"]), int(box["r"]), int(box["p"]))
    except (KeyError, ValueError, TypeError) as e:
        raise WrongPassword("Wrong password.") from e
    return open_with_key(blob, key), key
