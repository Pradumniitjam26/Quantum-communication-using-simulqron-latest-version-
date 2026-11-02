#!/usr/bin/env python3

"""
QKMS Secure File Transfer - Cryptographic Module

Phase 1

Encryption:
    AES-256-GCM

Key:
    256-bit BB84 key obtained from QKMS

Nonce:
    12 bytes / 96 bits

Authentication:
    AES-GCM authentication tag

IMPORTANT:
    The raw QKMS key is never transmitted.
"""


import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# CONSTANTS
# ============================================================

KEY_SIZE = 32          # 256 bits
NONCE_SIZE = 12        # 96 bits


# ============================================================
# KEY CONVERSION
# ============================================================

def key_from_binary(binary_key):
    """
    Convert a 256-bit binary string into a 32-byte AES key.

    Example:

        010101...256 bits...

    becomes:

        32 bytes
    """

    if not isinstance(binary_key, str):
        raise TypeError(
            "Binary key must be a string"
        )

    binary_key = binary_key.strip()

    if len(binary_key) != 256:
        raise ValueError(
            f"Expected 256-bit key, "
            f"got {len(binary_key)} bits"
        )

    if any(
        bit not in "01"
        for bit in binary_key
    ):
        raise ValueError(
            "Binary key contains "
            "characters other than 0 and 1"
        )

    key = int(
        binary_key,
        2
    ).to_bytes(
        KEY_SIZE,
        byteorder="big"
    )

    return key


# ============================================================
# KEY VALIDATION
# ============================================================

def validate_key(key):
    """
    Verify that the AES key is exactly 32 bytes.
    """

    if not isinstance(
        key,
        bytes
    ):
        raise TypeError(
            "AES key must be bytes"
        )

    if len(key) != KEY_SIZE:
        raise ValueError(
            "AES-256 requires exactly "
            "32 bytes"
        )

    return True


# ============================================================
# NONCE GENERATION
# ============================================================

def new_nonce():
    """
    Generate a fresh 96-bit random nonce.

    AES-GCM requires nonce uniqueness
    for a given key.
    """

    return os.urandom(
        NONCE_SIZE
    )


# ============================================================
# CHUNK ENCRYPTION
# ============================================================

def encrypt_chunk(
    key,
    plaintext,
    nonce,
    aad=None
):
    """
    Encrypt one file chunk using AES-256-GCM.

    Parameters:
        key       : 32-byte AES key
        plaintext : bytes
        nonce     : 12-byte nonce
        aad       : authenticated metadata

    Returns:
        ciphertext including GCM tag
    """

    validate_key(key)

    if not isinstance(
        plaintext,
        bytes
    ):
        raise TypeError(
            "Plaintext must be bytes"
        )

    if not isinstance(
        nonce,
        bytes
    ):
        raise TypeError(
            "Nonce must be bytes"
        )

    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            "AES-GCM nonce must be "
            "12 bytes"
        )

    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(
        nonce,
        plaintext,
        aad
    )

    return ciphertext


# ============================================================
# CHUNK DECRYPTION
# ============================================================

def decrypt_chunk(
    key,
    ciphertext,
    nonce,
    aad=None
):
    """
    Decrypt one AES-256-GCM encrypted chunk.

    If the ciphertext, nonce, key, or AAD
    has been modified, AES-GCM authentication
    will fail.
    """

    validate_key(key)

    if not isinstance(
        ciphertext,
        bytes
    ):
        raise TypeError(
            "Ciphertext must be bytes"
        )

    if not isinstance(
        nonce,
        bytes
    ):
        raise TypeError(
            "Nonce must be bytes"
        )

    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            "AES-GCM nonce must be "
            "12 bytes"
        )

    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(
        nonce,
        ciphertext,
        aad
    )

    return plaintext


# ============================================================
# BASE64 ENCODING
# ============================================================

def nonce_to_base64(nonce):
    """
    Convert nonce bytes to Base64 text.

    Used when nonce is placed inside
    the JSON protocol header.
    """

    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            "Nonce must be 12 bytes"
        )

    return base64.b64encode(
        nonce
    ).decode("ascii")


def nonce_from_base64(value):
    """
    Convert Base64 nonce text back to bytes.
    """

    nonce = base64.b64decode(
        value,
        validate=True
    )

    if len(nonce) != NONCE_SIZE:
        raise ValueError(
            "Decoded nonce must be "
            "12 bytes"
        )

    return nonce


# ============================================================
# CIPHERTEXT BASE64 HELPERS
# ============================================================

def ciphertext_to_base64(ciphertext):
    """
    Convert ciphertext to Base64.
    """

    return base64.b64encode(
        ciphertext
    ).decode("ascii")


def ciphertext_from_base64(value):
    """
    Convert Base64 ciphertext back to bytes.
    """

    return base64.b64decode(
        value,
        validate=True
    )


# ============================================================
# SIMPLE SELF TEST
# ============================================================

def self_test():
    """
    Verify AES-256-GCM encryption and decryption.
    """

    # 256-bit test key
    binary_key = (
        "01010101010101010101010101010101"
        "01010101010101010101010101010101"
        "01010101010101010101010101010101"
        "01010101010101010101010101010101"
        "01010101010101010101010101010101"
        "01010101010101010101010101010101"
        "01010101010101010101010101010101"
        "01010101010101010101010101010101"
    )

    key = key_from_binary(
        binary_key
    )

    plaintext = (
        b"QKMS secure file transfer test"
    )

    aad = (
        b"QKMS-PHASE1-TEST"
    )

    nonce = new_nonce()

    ciphertext = encrypt_chunk(
        key,
        plaintext,
        nonce,
        aad
    )

    recovered = decrypt_chunk(
        key,
        ciphertext,
        nonce,
        aad
    )

    if recovered != plaintext:
        raise RuntimeError(
            "AES-GCM self-test failed"
        )

    print(
        "AES-256-GCM self-test: PASS"
    )

    print(
        f"Key size     : {len(key)} bytes"
    )

    print(
        f"Nonce size   : {len(nonce)} bytes"
    )

    print(
        f"Plaintext    : {len(plaintext)} bytes"
    )

    print(
        f"Ciphertext   : {len(ciphertext)} bytes"
    )

    print(
        "Decryption   : SUCCESS"
    )


# ============================================================
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":
    self_test()
