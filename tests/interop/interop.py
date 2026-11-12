#!/usr/bin/env python3
"""Interop helper using the independent `cryptography` library (not Go).

  python3 tests/interop/interop.py verify <bundle.json> <public.pem>
      Verify a bundle produced by osiris with `cryptography`.
  python3 tests/interop/interop.py extract <bundle.json> <outdir>
      Write manifest.bin and sig.bin (for the openssl script).
  python3 tests/interop/interop.py make-fixtures
      Sign a manifest per profile with `cryptography` and write
      tests/interop/fixtures/<profile>.json, which `go test ./internal/crypto`
      verifies with osiris (the reverse direction).

Requires: pip install cryptography
"""
import base64, hashlib, json, os, sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils

HERE = os.path.dirname(os.path.abspath(__file__))
KEYS = os.path.join(HERE, "..", "keys")
FIX = os.path.join(HERE, "fixtures")
PROFILES = {"rsa-pss-sha256": "test-rsa", "ecdsa-p256-sha256": "test-ecdsa", "ed25519": "test-ed25519"}


def load_bundle(path):
    with open(path, "rb") as f:
        b = json.load(f)
    assert b["schema"] == "minisign-bundle/v1"
    return base64.b64decode(b["manifest_b64"], validate=True), base64.b64decode(b["signature_b64"], validate=True)


def verify(profile, pub, M, sig):
    """Returns True/False. ECDSA signature is r||s (64 bytes) -> DER first."""
    try:
        if profile == "rsa-pss-sha256":
            assert isinstance(pub, rsa.RSAPublicKey) and pub.key_size == 3072 and len(sig) == 384
            pub.verify(sig, M, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        elif profile == "ecdsa-p256-sha256":
            assert isinstance(pub, ec.EllipticCurvePublicKey) and pub.curve.name == "secp256r1" and len(sig) == 64
            r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
            pub.verify(utils.encode_dss_signature(r, s), M, ec.ECDSA(hashes.SHA256()))
        elif profile == "ed25519":
            assert isinstance(pub, ed25519.Ed25519PublicKey) and len(sig) == 64
            pub.verify(sig, M)
        else:
            return False
        return True
    except Exception:
        return False


def cmd_verify(bundle, pubpath):
    M, sig = load_bundle(bundle)
    profile = json.loads(M)["algorithm"]
    with open(pubpath, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    ok = verify(profile, pub, M, sig)
    print(f"{profile}: {'VALID' if ok else 'INVALID'} (verified by python-cryptography)")
    return 0 if ok else 1


def cmd_extract(bundle, outdir):
    M, sig = load_bundle(bundle)
    os.makedirs(outdir, exist_ok=True)
    open(os.path.join(outdir, "manifest.bin"), "wb").write(M)
    open(os.path.join(outdir, "sig.bin"), "wb").write(sig)
    return 0


def manifest_bytes(profile, keyid):
    sha = hashlib.sha256(b"interop artifact").hexdigest()
    return (
        '{"schema":"minisign-manifest/v1","package":"interop-app","version":"1.0.0",'
        f'"algorithm":"{profile}","keyid":"{keyid}","artifact":{{"name":"interop.bin","size":16,"sha256":"{sha}"}}}}'
    ).encode()


def cmd_make_fixtures():
    os.makedirs(FIX, exist_ok=True)
    for profile, prefix in PROFILES.items():
        with open(os.path.join(KEYS, prefix + ".key.pem"), "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        spki = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        M = manifest_bytes(profile, hashlib.sha256(spki).hexdigest())
        if profile == "rsa-pss-sha256":
            sig = priv.sign(M, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
        elif profile == "ecdsa-p256-sha256":
            r, s = utils.decode_dss_signature(priv.sign(M, ec.ECDSA(hashes.SHA256())))
            sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        else:
            sig = priv.sign(M)
        out = {
            "schema": "minisign-bundle/v1",
            "manifest_b64": base64.b64encode(M).decode(),
            "signature_b64": base64.b64encode(sig).decode(),
        }
        with open(os.path.join(FIX, profile + ".json"), "w") as f:
            json.dump(out, f, indent=2)
            f.write("\n")
        print("wrote", profile)
    return 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) == 3 and a[0] == "verify":
        sys.exit(cmd_verify(a[1], a[2]))
    if len(a) == 3 and a[0] == "extract":
        sys.exit(cmd_extract(a[1], a[2]))
    if a == ["make-fixtures"]:
        sys.exit(cmd_make_fixtures())
    print(__doc__)
    sys.exit(2)
