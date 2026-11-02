#!/usr/bin/env python3

"""
QKMS Real-Time Media AES-256-GCM Test

Purpose:
    Test the existing QKMS BB84 key with AES-256-GCM
    before integrating encryption into video/audio.

Security:
    - 256-bit BB84 key
    - AES-256-GCM
    - 12-byte random nonce
    - Authenticated metadata (AAD)
    - Raw key is never transmitted
"""

import base64
import hashlib
import os
import sys

import requests

from crypto.file_crypto import (
    key_from_binary,
    encrypt_chunk,
    decrypt_chunk,
)


# ============================================================
# CONFIGURATION
# ============================================================

QKMS_URL = "http://127.0.0.1:8000"

KEY_ID = 28

TEST_SESSION_ID = "VIDEO-CONFERENCE-TEST-001"

QKMS_TIMEOUT = 15


# ============================================================
# QKMS KEY RETRIEVAL
# ============================================================

def get_qkms_key(key_id):

    url = f"{QKMS_URL}/etsi/v1/keys/{key_id}"

    print()
    print("=" * 70)
    print("QKMS KEY RETRIEVAL")
    print("=" * 70)

    print(f"QKMS URL : {url}")
    print(f"Key ID   : {key_id}")

    response = requests.get(
        url,
        timeout=QKMS_TIMEOUT
    )

    response.raise_for_status()

    data = response.json()

    if "key" not in data:
        raise RuntimeError(
            "QKMS response does not contain key"
        )

    record = data["key"]

    fields = record.strip().split("\t")

    if len(fields) < 9:
        raise RuntimeError(
            "Unexpected QKMS key record"
        )

    record_key_id = fields[0]
    protocol = fields[1]
    key_length = int(fields[2])
    status = fields[3]
    key_binary = fields[-1]

    if str(record_key_id) != str(key_id):
        raise RuntimeError(
            "Key ID mismatch"
        )

    if protocol.upper() != "BB84":
        raise RuntimeError(
            f"Expected BB84, got {protocol}"
        )

    if status.upper() != "ACTIVE":
        raise RuntimeError(
            f"Key {key_id} is not ACTIVE"
        )

    if key_length != 256:
        raise RuntimeError(
            f"Expected 256-bit key, got {key_length}"
        )

    if len(key_binary) != 256:
        raise RuntimeError(
            "Retrieved binary key is not 256 bits"
        )

    key = key_from_binary(key_binary)

    print()
    print("Protocol       : BB84")
    print("Key ID         :", key_id)
    print("Key Length     : 256 bits")
    print("Key Bytes      :", len(key))
    print("Status         : ACTIVE")

    # Do NOT print the raw key.

    digest = hashlib.sha256(key).hexdigest()

    print("Local Key SHA256:", digest)

    print()
    print("QKMS KEY RETRIEVAL: SUCCESS")

    return key


# ============================================================
# AAD
# ============================================================

def make_aad(
    session_id,
    key_id,
    media_type,
    sequence
):

    return (
        "QKMS-VIDEO-CONFERENCE-V1"
        f"|session={session_id}"
        f"|key={key_id}"
        f"|media={media_type}"
        f"|sequence={sequence}"
    ).encode("utf-8")


# ============================================================
# TEST
# ============================================================

def run_test():

    print()
    print("=" * 70)
    print("QKMS SECURE MEDIA CRYPTOGRAPHY TEST")
    print("=" * 70)

    # --------------------------------------------------------
    # 1. Get BB84 key
    # --------------------------------------------------------

    key = get_qkms_key(KEY_ID)

    # --------------------------------------------------------
    # 2. Simulated video packet
    # --------------------------------------------------------

    plaintext = (
        b"SIMULATED VIDEO FRAME DATA - "
        b"QKMS AES-256-GCM TEST"
    )

    sequence = 1

    aad = make_aad(
        TEST_SESSION_ID,
        KEY_ID,
        "video",
        sequence
    )

    print()
    print("=" * 70)
    print("MEDIA PACKET")
    print("=" * 70)

    print("Media Type      : video")
    print("Sequence        :", sequence)
    print("Plaintext Bytes :", len(plaintext))
    print("AAD Bytes       :", len(aad))

    # --------------------------------------------------------
    # 3. Generate unique nonce
    # --------------------------------------------------------

    nonce = os.urandom(12)

    print("Nonce Size      :", len(nonce), "bytes")
    print(
        "Nonce           :",
        base64.b64encode(nonce).decode()
    )

    # --------------------------------------------------------
    # 4. Encrypt
    # --------------------------------------------------------

    ciphertext = encrypt_chunk(
        key,
        plaintext,
        nonce,
        aad
    )

    print()
    print("Encryption      : SUCCESS")
    print(
        "Ciphertext Size :",
        len(ciphertext),
        "bytes"
    )

    # --------------------------------------------------------
    # 5. Simulate transmission
    #
    # Only these values would travel:
    #
    #     Key ID
    #     Nonce
    #     AAD/metadata
    #     Ciphertext
    #
    # Raw key is NOT transmitted.
    # --------------------------------------------------------

    transmitted = {
        "key_id": KEY_ID,
        "nonce": nonce,
        "aad": aad,
        "ciphertext": ciphertext,
    }

    print()
    print("=" * 70)
    print("SIMULATED NETWORK PACKET")
    print("=" * 70)

    print("Key ID          :", transmitted["key_id"])
    print("Nonce           :", len(transmitted["nonce"]), "bytes")
    print("AAD             :", len(transmitted["aad"]), "bytes")
    print(
        "Ciphertext      :",
        len(transmitted["ciphertext"]),
        "bytes"
    )
    print("Raw Key Sent    : NO")

    # --------------------------------------------------------
    # 6. Decrypt
    # --------------------------------------------------------

    recovered = decrypt_chunk(
        key,
        transmitted["ciphertext"],
        transmitted["nonce"],
        transmitted["aad"]
    )

    print()
    print("=" * 70)
    print("DECRYPTION")
    print("=" * 70)

    print("Decryption      : SUCCESS")
    print("Recovered Bytes :", len(recovered))

    # --------------------------------------------------------
    # 7. Verify
    # --------------------------------------------------------

    if recovered != plaintext:

        print()
        print("RESULT           : FAILED")
        print("Data mismatch.")

        return False

    print()
    print("Original Data   :", plaintext.decode())
    print("Recovered Data  :", recovered.decode())

    print()
    print("=" * 70)
    print("SECURE MEDIA CRYPTO TEST: PASS")
    print("=" * 70)

    print()
    print("Verified:")
    print("  [OK] QKMS BB84 key retrieved")
    print("  [OK] 256-bit AES key")
    print("  [OK] AES-256-GCM encryption")
    print("  [OK] Random 12-byte nonce")
    print("  [OK] Authenticated AAD")
    print("  [OK] AES-GCM decryption")
    print("  [OK] Plaintext integrity")
    print("  [OK] Raw key not transmitted")

    return True


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    try:

        success = run_test()

        if success:
            sys.exit(0)

        sys.exit(1)

    except KeyboardInterrupt:

        print()
        print("Test cancelled.")

        sys.exit(130)

    except Exception as exc:

        print()
        print("=" * 70)
        print("SECURE MEDIA CRYPTO TEST: FAILED")
        print("=" * 70)

        print("Error:", exc)

        sys.exit(1)
