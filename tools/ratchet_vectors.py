"""Writes ratchet_vectors.json: RNS 1.5.2's ratchets as the web client must
reproduce them, made with the Python reference (RNS 1.5.2, LXMF 1.1.1) so
that Retichat-js asserts its ratchet code against an implementation that is
not its own.

Run from Retichat-js with the workspace venv:

    /Users/james/Offline/Reticulum/.venv/bin/python -I tools/ratchet_vectors.py          # (re)write the JSON
    /Users/james/Offline/Reticulum/.venv/bin/python -I tools/ratchet_vectors.py --check  # exit 1 if the JSON drifted

Every value comes out of RNS's own code: Destination.enable_ratchets,
rotate_ratchets and _persist_ratchets write the ratchet file,
Destination.announce builds the announce, LXMRouter.get_announce_app_data
builds its app_data, and Identity.encrypt / Identity.decrypt make and read
the ciphertexts. Only RNS's sources of randomness and time are replaced, and
only for the step that needs them (fixed_inputs below):

- RNS.Cryptography.X25519PrivateKey.generate returns the next fixed key
  (ratchet rotation and the ephemeral key of Identity.encrypt);
- os.urandom returns the next fixed bytes, of the length asked for (the IV
  of Token.encrypt);
- RNS.Identity.get_random_hash returns a fixed 16 bytes (the announce takes
  the first 5);
- time.time returns a fixed second (ratchet rotation, the announce's
  emitted time).

Each step must use exactly the values it was given, so a change in how RNS
draws randomness stops the generator instead of changing the file.
"""

import contextlib
import hashlib
import json
import os
import sys
import tempfile
import threading
import time
import types

try:
    import RNS
    import RNS.vendor.umsgpack as umsgpack
    from RNS.Cryptography import X25519PrivateKey, X25519PublicKey, Token
    import LXMF
    from LXMF.LXMRouter import LXMRouter
except ImportError:  # pragma: no cover - environment guard
    sys.stderr.write("RNS/LXMF are not importable: run with the workspace .venv (RNS 1.5.2, LXMF 1.1.1)\n")
    sys.exit(2)

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_PATH = os.path.normpath(os.path.join(HERE, "..", "ratchet_vectors.json"))

LABEL_ROOT = b"retichat-js ratchet vectors v1"

# The three ratchets are rotated in an hour apart, more than
# Destination.RATCHET_INTERVAL, so each rotate_ratchets call makes one.
ROTATED_AT = [1790000000, 1790003600, 1790007200]
# Within RATCHET_INTERVAL of the last rotation, so the announce rotates none.
ANNOUNCED_AT = 1790007800

DISPLAY_NAME = "Ratchet Vectors"
STAMP_COST = 8

PLAINTEXTS = {
    "newest_ratchet": b"ratchet vector: to the newest ratchet",
    "oldest_ratchet": b"ratchet vector: to the oldest of the three ratchets",
    "identity_key": b"ratchet vector: to the identity key, no ratchet",
    "unlisted_ratchet": b"ratchet vector: to a ratchet that is not in the list",
}
ENCRYPT_PLAINTEXT = b"ratchet vector: deterministic encrypt to the newest ratchet"


def fixed(label, length=32):
    return hashlib.sha256(LABEL_ROOT + b"/" + label.encode()).digest()[:length]


def fixed_x25519(label):
    """A fixed X25519 private key, clamped as every key RNS generates is:
    OpenSSL clamps on generation and RNS's internal X25519 clamps in
    private_bytes, so the file is the same under either provider."""
    k = bytearray(fixed(label))
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return bytes(k)


@contextlib.contextmanager
def fixed_inputs(x25519_keys=(), urandom=(), now=None, random_hash=None):
    """Replaces RNS's randomness and clock for one step. Every value given
    must be used, in order, and nothing else may be drawn."""
    keys = list(x25519_keys)
    rand = list(urandom)
    orig_generate = X25519PrivateKey.__dict__["generate"]
    orig_urandom = os.urandom
    orig_time = time.time
    orig_random_hash = RNS.Identity.__dict__["get_random_hash"]

    def generate(cls):
        if not keys:
            raise AssertionError("RNS generated an X25519 key this step did not fix")
        return cls.from_private_bytes(keys.pop(0))

    def fixed_urandom(n):
        if not rand:
            raise AssertionError(f"RNS asked os.urandom for {n} bytes this step did not fix")
        b = rand.pop(0)
        if len(b) != n:
            raise AssertionError(f"RNS asked os.urandom for {n} bytes, the fixed value has {len(b)}")
        return b

    X25519PrivateKey.generate = classmethod(generate)
    os.urandom = fixed_urandom
    if now is not None:
        time.time = lambda: float(now)
    if random_hash is not None:
        RNS.Identity.get_random_hash = staticmethod(lambda: random_hash)
    try:
        yield
    finally:
        X25519PrivateKey.generate = orig_generate
        os.urandom = orig_urandom
        time.time = orig_time
        RNS.Identity.get_random_hash = orig_random_hash
    assert not keys, f"{len(keys)} fixed X25519 keys were not used"
    assert not rand, f"{len(rand)} fixed os.urandom values were not used"


def ratchet_entry(prv):
    pub = RNS.Identity._ratchet_public_bytes(prv)
    return {
        "private_key_hex": prv.hex(),
        "public_key_hex": pub.hex(),
        "ratchet_id_hex": RNS.Identity._get_ratchet_id(pub).hex(),
    }


def encrypt_to(public_identity, plaintext, ratchet_pub, label):
    """RNS Identity.encrypt with the ephemeral key and IV fixed by label."""
    ephemeral = fixed_x25519(label + "/ephemeral")
    iv = fixed(label + "/iv", 16)
    with fixed_inputs(x25519_keys=[ephemeral], urandom=[iv]):
        ciphertext = public_identity.encrypt(plaintext, ratchet=ratchet_pub)
    return ephemeral, iv, ciphertext


def decrypt_result(identity, ciphertext, ratchets, enforce):
    receiver = types.SimpleNamespace(latest_ratchet_id="untouched")
    plaintext = identity.decrypt(ciphertext, ratchets=ratchets, enforce_ratchets=enforce, ratchet_id_receiver=receiver)
    assert receiver.latest_ratchet_id != "untouched", "RNS decrypt did not report a ratchet id"
    rid = receiver.latest_ratchet_id
    return {
        "enforce_ratchets": enforce,
        "plaintext_hex": plaintext.hex() if plaintext is not None else None,
        "ratchet_id_hex": rid.hex() if rid is not None else None,
    }


def build(workdir):
    # Destination registration and Identity._remember_ratchet ask
    # Transport.owner whether a shared instance is connected; there is no
    # Reticulum instance here. _remember_ratchet's background write of the
    # announced ratchet goes to this throwaway storage path.
    RNS.Transport.owner = types.SimpleNamespace(is_connected_to_shared_instance=False)
    RNS.Reticulum.storagepath = os.path.join(workdir, "storage")

    private_key = fixed("identity/x25519") + fixed("identity/ed25519")
    identity = RNS.Identity.from_bytes(private_key)
    public_key = identity.get_public_key()
    dest = RNS.Destination(identity, RNS.Destination.IN, RNS.Destination.SINGLE, LXMF.APP_NAME, "delivery")
    assert dest.hash == RNS.Destination.hash(identity, "lxmf", "delivery")

    # The ratchet file, as LXMRouter.register_delivery_identity names it.
    ratchets_dir = os.path.join(workdir, "ratchets")
    os.makedirs(ratchets_dir)
    ratchets_path = os.path.join(ratchets_dir, f"{RNS.hexrep(dest.hash, delimit=False)}.ratchets")
    with fixed_inputs():
        dest.enable_ratchets(ratchets_path)
    assert dest.ratchets == []
    with open(ratchets_path, "rb") as f:
        empty_file = f.read()

    rotation_keys = [fixed_x25519(f"ratchet/{i}") for i in (1, 2, 3)]
    for at, key in zip(ROTATED_AT, rotation_keys):
        with fixed_inputs(x25519_keys=[key], now=at):
            dest.rotate_ratchets()
        assert dest.ratchets[0] == key and dest.latest_ratchet_time == at
    ratchets = list(dest.ratchets)
    assert ratchets == rotation_keys[::-1], "RNS did not keep the ratchets newest first"

    with open(ratchets_path, "rb") as f:
        ratchet_file = f.read()
    persisted = umsgpack.unpackb(ratchet_file)
    assert list(persisted.keys()) == ["signature", "ratchets"]
    assert identity.validate(persisted["signature"], persisted["ratchets"])
    assert umsgpack.unpackb(persisted["ratchets"]) == ratchets
    # Python reads its own file back.
    dest.ratchets = None
    dest._reload_ratchets(ratchets_path)
    assert dest.ratchets == ratchets

    newest_pub = RNS.Identity._ratchet_public_bytes(ratchets[0])
    unlisted = fixed_x25519("ratchet/unlisted")
    unlisted_pub = RNS.Identity._ratchet_public_bytes(unlisted)

    # The announce, as LXMRouter.announce sends it: LXMF's app_data from
    # register_delivery_identity's display name and set_inbound_stamp_cost.
    router = types.SimpleNamespace(delivery_destinations={dest.hash: dest})
    dest.display_name = DISPLAY_NAME
    assert LXMRouter.set_inbound_stamp_cost(router, dest.hash, STAMP_COST)
    app_data = LXMRouter.get_announce_app_data(router, dest.hash)
    assert LXMF.display_name_from_app_data(app_data) == DISPLAY_NAME
    assert LXMF.stamp_cost_from_app_data(app_data) == STAMP_COST

    random_hash_source = fixed("announce/random_hash", 16)
    threads_before = set(threading.enumerate())
    with fixed_inputs(now=ANNOUNCED_AT, random_hash=random_hash_source):
        packet = dest.announce(app_data=app_data, send=False)
    for t in set(threading.enumerate()) - threads_before:
        t.join()
    assert dest.ratchets == ratchets, "the announce rotated a ratchet"
    packet.pack()
    raw = packet.raw

    keysize = RNS.Identity.KEYSIZE // 8
    name_hash_len = RNS.Identity.NAME_HASH_LENGTH // 8
    ratchetsize = RNS.Identity.RATCHETSIZE // 8
    sig_len = RNS.Identity.SIGLENGTH // 8
    data = packet.data
    o = 0
    a_public_key = data[o:o + keysize]; o += keysize
    a_name_hash = data[o:o + name_hash_len]; o += name_hash_len
    a_random_hash = data[o:o + 10]; o += 10
    a_ratchet = data[o:o + ratchetsize]; o += ratchetsize
    a_signature = data[o:o + sig_len]; o += sig_len
    a_app_data = data[o:]
    assert a_public_key == public_key and a_name_hash == dest.name_hash
    assert a_random_hash == random_hash_source[:5] + ANNOUNCED_AT.to_bytes(5, "big")
    assert a_ratchet == newest_pub and a_app_data == app_data
    signed_data = dest.hash + a_public_key + a_name_hash + a_random_hash + a_ratchet + a_app_data
    assert identity.validate(a_signature, signed_data)
    received = RNS.Packet(None, raw)
    assert received.unpack()
    assert received.context_flag == RNS.Packet.FLAG_SET and received.destination_hash == dest.hash
    assert RNS.Identity.validate_announce(received, only_validate_signature=True) is True

    # The sender's side: only the public key, as recalled from an announce.
    sender_view = RNS.Identity(create_keys=False)
    sender_view.load_public_key(public_key)
    assert sender_view.hash == identity.hash

    cases = [
        ("newest_ratchet", "the newest ratchet, ratchets[0]: the one the announce carries", newest_pub),
        ("oldest_ratchet", "the oldest of the three ratchets, ratchets[2]", RNS.Identity._ratchet_public_bytes(ratchets[2])),
        ("identity_key", "no ratchet: the identity's own X25519 key", None),
        ("unlisted_ratchet", "a fourth ratchet that is not in the list (unlisted_ratchet)", unlisted_pub),
    ]
    decrypt_cases = []
    for name, encrypted_to, ratchet_pub in cases:
        plaintext = PLAINTEXTS[name]
        _, _, ciphertext = encrypt_to(sender_view, plaintext, ratchet_pub, f"decrypt/{name}")
        results = [decrypt_result(identity, ciphertext, ratchets, enforce) for enforce in (False, True)]
        decrypt_cases.append({
            "name": name,
            "encrypted_to": encrypted_to,
            "ratchet_public_hex": ratchet_pub.hex() if ratchet_pub is not None else None,
            "plaintext_hex": plaintext.hex(),
            "ciphertext_hex": ciphertext.hex(),
            "results": results,
        })
    by_name = {c["name"]: c["results"] for c in decrypt_cases}
    newest_id = RNS.Identity._get_ratchet_id(newest_pub).hex()
    oldest_id = RNS.Identity._get_ratchet_id(RNS.Identity._ratchet_public_bytes(ratchets[2])).hex()
    assert [r["ratchet_id_hex"] for r in by_name["newest_ratchet"]] == [newest_id, newest_id]
    assert [r["ratchet_id_hex"] for r in by_name["oldest_ratchet"]] == [oldest_id, oldest_id]
    assert by_name["identity_key"][0]["plaintext_hex"] == PLAINTEXTS["identity_key"].hex()
    assert by_name["identity_key"][1]["plaintext_hex"] is None
    assert all(r["plaintext_hex"] is None for r in by_name["unlisted_ratchet"])

    ephemeral, iv, ciphertext = encrypt_to(sender_view, ENCRYPT_PLAINTEXT, newest_pub, "encrypt")
    ephemeral_pub = X25519PrivateKey.from_private_bytes(ephemeral).public_key().public_bytes()
    assert ciphertext[:32] == ephemeral_pub and ciphertext[32:48] == iv
    # Intermediates for debugging, checked against RNS's ciphertext.
    shared_key = X25519PrivateKey.from_private_bytes(ratchets[0]).exchange(X25519PublicKey.from_public_bytes(ephemeral_pub))
    assert shared_key == X25519PrivateKey.from_private_bytes(ephemeral).exchange(X25519PublicKey.from_public_bytes(newest_pub))
    derived_key = RNS.Cryptography.hkdf(length=RNS.Identity.DERIVED_KEY_LENGTH, derive_from=shared_key, salt=identity.hash, context=None)
    assert Token(derived_key).decrypt(ciphertext[32:]) == ENCRYPT_PLAINTEXT
    receiver = types.SimpleNamespace(latest_ratchet_id=None)
    assert identity.decrypt(ciphertext, ratchets=ratchets, enforce_ratchets=True, ratchet_id_receiver=receiver) == ENCRYPT_PLAINTEXT
    assert receiver.latest_ratchet_id.hex() == newest_id

    return {
        "spec": "RNS 1.5.2 ratchets: Identity.py (RATCHETSIZE, RATCHET_EXPIRY, _get_ratchet_id, encrypt, decrypt), Destination.py (RATCHET_COUNT, RATCHET_INTERVAL, enable_ratchets, rotate_ratchets, _persist_ratchets, announce); LXMF 1.1.1 LXMRouter.get_announce_app_data",
        "format_version": 1,
        "generator": "Retichat-js tools/ratchet_vectors.py (RNS 1.5.2, LXMF 1.1.1)",
        "notes": [
            "Generated with the Python reference (RNS 1.5.2, LXMF 1.1.1, RNS.vendor.umsgpack) by running RNS's own code; do not edit by hand. Regenerate with the generator; --check fails if this file drifted.",
            "Only RNS's randomness and clock were replaced, each for the one step that needs it: RNS.Cryptography.X25519PrivateKey.generate returns a fixed key (ratchet rotation; the ephemeral key of Identity.encrypt), os.urandom returns fixed bytes (the 16-byte IV of Token.encrypt), RNS.Identity.get_random_hash returns a fixed 16 bytes (the announce uses the first 5), time.time returns a fixed second (ratchet rotation; the announce's emitted time). Each step must use exactly the values it was given. Transport.owner is a stand-in reporting no shared instance (there is no Reticulum instance), and LXMRouter's methods ran against a stand-in router holding only the delivery destination.",
            "All *_hex values are lowercase hex. Fixed inputs are SHA-256 of 'retichat-js ratchet vectors v1/<label>'; X25519 private keys are clamped, as every key RNS generates is, so the ratchet file is the same under RNS's OpenSSL and internal providers.",
            "identity.private_key_hex is the X25519 private key (32) | Ed25519 seed (32). lxmf_delivery_hash_hex = Destination.hash(identity, 'lxmf', 'delivery'); name_hash_hex = SHA-256('lxmf.delivery')[0:10].",
            "ratchets are the destination's ratchets newest first, as Destination.ratchets holds them and the file stores them: rotate_ratchets inserts each new ratchet at index 0. ratchet_id = SHA-256(ratchet public key)[0:10] (Identity._get_ratchet_id). unlisted_ratchet is a fourth key that is not among them.",
            "ratchet_file.file_hex is the exact file Destination._persist_ratchets wrote after the three rotations: msgpack map {'signature': bin64, 'ratchets': bin(packed_ratchets)} with the keys in that order, where packed_ratchets = msgpack array of the 32-byte private keys newest first and signature = the identity's Ed25519 signature over packed_ratchets. empty_file_hex is what enable_ratchets wrote first, with no ratchets. Python persists no rotation time; latest_ratchet_time starts at 0 on every load, so the first announce after a load rotates. LXMF names the file <lxmf_delivery_hash hex>.ratchets in its ratchets directory.",
            "announce is Destination.announce(app_data, send=False) for lxmf.delivery, packed: announce data = public_key(64) | name_hash(10) | random_hash(10) | ratchet(32) | signature(64) | app_data, random_hash = 5 random bytes | emitted time (5 bytes big-endian, whole seconds). signed_data = destination_hash | public_key | name_hash | random_hash | ratchet | app_data. The packet's context flag is set because it carries a ratchet: flags = header_type 0 << 6 | context_flag 1 << 5 | transport_type 0 << 4 | SINGLE 0 << 2 | ANNOUNCE 1. app_data is LXMF 1.1.1's msgpack [display_name bin, stamp_cost, [SF_COMPRESSION]].",
            "decrypt_cases: ciphertexts from RNS Identity.encrypt (the sender holding only the public key) to the named key, each read with RNS Identity.decrypt(ciphertext, ratchets=the three ratchets newest first, enforce_ratchets=False and True). Each result is what decrypt returned (null = None) and the ratchet id it reported through ratchet_id_receiver.latest_ratchet_id (null = None, the identity key or a failure).",
            "encrypt_case: Identity.encrypt(plaintext, ratchet=the newest ratchet's public key) with the ephemeral key and IV fixed, so an implementation given them must produce ciphertext_hex exactly: ephemeral_public(32) | iv(16) | AES-256-CBC(PKCS7(plaintext)) | HMAC-SHA256(32) over iv | AES output. shared_key_hex and derived_key_hex are intermediates, checked against the ciphertext: derived_key = HKDF-SHA256(64, shared_key, salt = identity hash, info empty); its first 32 bytes are the HMAC key, the last 32 the AES key.",
        ],
        "constants": {
            "RATCHETSIZE": RNS.Identity.RATCHETSIZE,
            "RATCHET_EXPIRY": RNS.Identity.RATCHET_EXPIRY,
            "RATCHET_COUNT": RNS.Destination.RATCHET_COUNT,
            "RATCHET_INTERVAL": RNS.Destination.RATCHET_INTERVAL,
            "ratchet_id_length": RNS.Identity.NAME_HASH_LENGTH // 8,
            "units": "RATCHETSIZE in bits; RATCHET_EXPIRY and RATCHET_INTERVAL in seconds; RATCHET_COUNT is the number of ratchets a destination retains",
        },
        "identity": {
            "private_key_hex": private_key.hex(),
            "public_key_hex": public_key.hex(),
            "identity_hash_hex": identity.hash.hex(),
            "lxmf_delivery_hash_hex": dest.hash.hex(),
            "name_hash_hex": dest.name_hash.hex(),
        },
        "ratchets": [ratchet_entry(r) for r in ratchets],
        "unlisted_ratchet": ratchet_entry(unlisted),
        "ratchet_file": {
            "rotated_at": ROTATED_AT,
            "packed_ratchets_hex": persisted["ratchets"].hex(),
            "signature_hex": persisted["signature"].hex(),
            "file_hex": ratchet_file.hex(),
            "empty_file_hex": empty_file.hex(),
        },
        "announce": {
            "display_name": DISPLAY_NAME,
            "stamp_cost": STAMP_COST,
            "app_data_hex": app_data.hex(),
            "emitted_at": ANNOUNCED_AT,
            "random_hash_hex": a_random_hash.hex(),
            "ratchet_public_hex": a_ratchet.hex(),
            "ratchet_id_hex": RNS.Identity._get_ratchet_id(a_ratchet).hex(),
            "signature_hex": a_signature.hex(),
            "announce_data_hex": data.hex(),
            "signed_data_hex": signed_data.hex(),
            "flags_hex": bytes([packet.flags]).hex(),
            "context_flag": packet.context_flag,
            "hops": raw[1],
            "context_hex": bytes([packet.context]).hex(),
            "packet_hex": raw.hex(),
            "packet_hash_hex": packet.get_hash().hex(),
        },
        "decrypt_cases": decrypt_cases,
        "encrypt_case": {
            "ratchet_public_hex": newest_pub.hex(),
            "ephemeral_private_hex": ephemeral.hex(),
            "ephemeral_public_hex": ephemeral_pub.hex(),
            "iv_hex": iv.hex(),
            "plaintext_hex": ENCRYPT_PLAINTEXT.hex(),
            "ciphertext_hex": ciphertext.hex(),
            "shared_key_hex": shared_key.hex(),
            "derived_key_hex": derived_key.hex(),
        },
    }


def render():
    with tempfile.TemporaryDirectory() as workdir:
        doc = build(workdir)
    return json.dumps(doc, indent=2, ensure_ascii=True) + "\n"


def main():
    assert RNS.__version__ == "1.5.2", f"RNS {RNS.__version__}, the reference is 1.5.2"
    assert LXMF.__version__ == "1.1.1", f"LXMF {LXMF.__version__}, the reference is 1.1.1"
    text = render()
    if "--check" in sys.argv:
        with open(OUT_PATH, encoding="utf-8") as f:
            committed = f.read()
        if committed != text:
            sys.stderr.write(f"{OUT_PATH} is not this generator's output\n")
            sys.exit(1)
        print(f"{OUT_PATH} matches")
        return
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {OUT_PATH}")


if __name__ == "__main__":
    main()
