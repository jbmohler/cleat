import os
import json
import base64
import getpass
import contextlib
import functools
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

salt = b"lkajsdfl;ajs;lfj2oi32oi2t233"  # os.urandom(16)


@functools.lru_cache()
def pw2key(filename):
    print(f"Unlocking {filename}")
    password = getpass.getpass("password: ")
    bpw = password.encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )

    key = base64.urlsafe_b64encode(kdf.derive(bpw))
    return key


@contextlib.contextmanager
def pw_fernet(filename):
    yield Fernet(pw2key(filename))


def write_encrypted_content(fernet, filename, obj):
    data = json.dumps(obj).encode("utf-8")
    disk = fernet.encrypt(data)
    with open(filename, "wb") as ff:
        ff.write(disk)


def read_encrypted_content(fernet, filename):
    with open(filename, "rb") as ff:
        disk = ff.read()
    data = fernet.decrypt(disk)
    return json.loads(data.decode("utf-8"))


class Vault:
    def __init__(self, filename):
        self._content = None
        self._filename = filename

    @property
    def content(self):
        if self._content is None:
            with pw_fernet(self._filename) as ff:
                self._content = read_encrypted_content(ff, self._filename)
        return self._content

    def get(self, keyname):
        segs = keyname.split(".")
        obj = self.content
        for seg in segs:
            obj = obj[seg]
        return obj


class VaultManager:
    def __init__(self):
        self._vaultdict = {}

    def add(self, vname, vcfg):
        self._vaultdict[vname] = Vault(vcfg, filename)

    def __contains__(self, key):
        return key in self._vaultdict

    def __getitem__(self, key):
        return self._vaultdict[key]
