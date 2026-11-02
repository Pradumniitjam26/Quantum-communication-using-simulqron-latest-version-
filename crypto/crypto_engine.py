#!/usr/bin/env python3

"""
Application-Level AES-256 Encryption Engine

Design:
    AES-256-CBC
    PKCS7 padding
    Random 16-byte IV

The QKMS supplies the 256-bit key.
The IV is generated randomly and is safe to transmit
along with the ciphertext.
"""

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import (
    Cipher,
    algorithms,
    modes,
)
from cryptography.hazmat.primitives.padding import PKCS7


AES_KEY_SIZE = 32      # 256 bits
AES_BLOCK_SIZE = 128   # bits = 16 bytes


def validate_key(key: bytes):
    """
    Validate that the supplied AES key is exactly 256 bits.
    """

    if not isinstance(key, bytes):
        raise TypeError("AES key must be bytes.")

    if len(key) != AES_KEY_SIZE:
        raise ValueError(
            f"AES-256 requires a 32-byte key, got {len(key)} bytes."
        )


def encrypt(plaintext: str, key: bytes):
    """
    Encrypt plaintext using AES-256-CBC.

    Returns:
        iv, ciphertext
    """

    if not isinstance(plaintext, str):
        raise TypeError(
            "Plaintext must be a string."
        )

    validate_key(key)

    # Random 16-byte IV
    iv = os.urandom(16)

    # Convert plaintext to bytes
    plaintext_bytes = plaintext.encode("utf-8")

    # PKCS7 padding
    padder = PKCS7(
        AES_BLOCK_SIZE
    ).padder()

    padded_data = (
        padder.update(plaintext_bytes)
        + padder.finalize()
    )

    # AES-256-CBC
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
    )

    encryptor = cipher.encryptor()

    ciphertext = (
        encryptor.update(padded_data)
        + encryptor.finalize()
    )

    return iv, ciphertext


def decrypt(iv: bytes, ciphertext: bytes, key: bytes):
    """
    Decrypt AES-256-CBC ciphertext and remove PKCS7 padding.

    Returns:
        Original plaintext string.
    """

    if not isinstance(iv, bytes):
        raise TypeError(
            "IV must be bytes."
        )

    if len(iv) != 16:
        raise ValueError(
            "AES-CBC IV must be exactly 16 bytes."
        )

    if not isinstance(ciphertext, bytes):
        raise TypeError(
            "Ciphertext must be bytes."
        )

    validate_key(key)

    # AES-256-CBC
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
    )

    decryptor = cipher.decryptor()

    padded_plaintext = (
        decryptor.update(ciphertext)
        + decryptor.finalize()
    )

    # Remove PKCS7 padding
    unpadder = PKCS7(
        AES_BLOCK_SIZE
    ).unpadder()

    plaintext_bytes = (
        unpadder.update(padded_plaintext)
        + unpadder.finalize()
    )

    return plaintext_bytes.decode("utf-8")


def key_from_binary(binary_key: str):
    """
    Convert a 256-character binary QKMS key into
    a 32-byte AES-256 key.
    """

    if not isinstance(binary_key, str):
        raise TypeError(
            "Binary key must be a string."
        )

    if len(binary_key) != 256:
        raise ValueError(
            "QKMS key must contain exactly 256 bits."
        )

    if set(binary_key) - {"0", "1"}:
        raise ValueError(
            "QKMS key must contain only 0 and 1."
        )

    return int(
        binary_key,
        2
    ).to_bytes(
        AES_KEY_SIZE,
        byteorder="big"
    )
