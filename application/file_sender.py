#!/usr/bin/env python3

"""
QKMS Secure File Sender - Phase 1

Features:
- Uses existing QKMS FastAPI key API
- Retrieves BB84 key locally through QKMS API
- AES-256-GCM encryption
- Supports multiple files in one TCP session
- Supports chunked transfer for large files
- SHA-256 integrity verification
- Raw QKMS key is NEVER transmitted
- Uses existing file-transfer port 6001
"""

import argparse
import base64
import hashlib
import json
import math
import os
import socket
import struct
import sys
import time
import uuid
from pathlib import Path

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# CONFIGURATION
# ============================================================

QKMS_URL = os.getenv(
    "QKMS_URL",
    "http://127.0.0.1:8000"
)

BOB_HOST = os.getenv(
    "BOB_HOST",
    "10.11.80.93"
)

FILE_TRANSFER_PORT = int(
    os.getenv(
        "FILE_TRANSFER_PORT",
        "6001"
    )
)

DEFAULT_CHUNK_SIZE = 4 * 1024 * 1024       # 4 MiB
MAX_CHUNK_SIZE = 16 * 1024 * 1024          # 16 MiB
MAX_FILES = 100
MAX_FILE_SIZE = 100 * 1024 * 1024 * 1024   # 100 GiB

MAX_FRAME_SIZE = MAX_CHUNK_SIZE + (256 * 1024)

CONNECT_TIMEOUT = 10
QKMS_TIMEOUT = 15


# ============================================================
# SIZE PARSER
# ============================================================

def parse_size(value):
    """
    Convert values such as:

        4M
        8M
        1G
        512K

    into bytes.
    """

    value = str(value).strip().upper()

    units = {
        "K": 1024,
        "KB": 1024,
        "M": 1024 ** 2,
        "MB": 1024 ** 2,
        "G": 1024 ** 3,
        "GB": 1024 ** 3,
    }

    for suffix, multiplier in units.items():

        if value.endswith(suffix):

            number = value[:-len(suffix)]

            try:
                return int(float(number) * multiplier)
            except ValueError:
                raise ValueError(
                    f"Invalid size: {value}"
                )

    return int(value)


# ============================================================
# KEY CONVERSION
# ============================================================

def key_from_binary(binary_key):
    """
    Convert 256-bit binary string into 32-byte AES key.
    """

    binary_key = binary_key.strip()

    if len(binary_key) != 256:
        raise ValueError(
            f"Expected 256-bit key, got {len(binary_key)} bits"
        )

    if any(bit not in "01" for bit in binary_key):
        raise ValueError(
            "QKMS key contains invalid binary characters"
        )

    return int(binary_key, 2).to_bytes(32, "big")


# ============================================================
# SHA-256
# ============================================================

def sha256_file(path):
    """
    Calculate SHA-256 without loading the complete file
    into RAM.
    """

    digest = hashlib.sha256()
    size = 0

    with open(path, "rb") as file:

        while True:

            data = file.read(1024 * 1024)

            if not data:
                break

            digest.update(data)
            size += len(data)

    return size, digest.hexdigest()


# ============================================================
# TCP FRAMING
# ============================================================

def send_frame(sock, header, payload=b""):
    """
    Frame format:

        4 bytes  -> total frame length
        4 bytes  -> JSON header length
        N bytes  -> JSON header
        M bytes  -> binary payload
    """

    header_bytes = json.dumps(
        header,
        separators=(",", ":")
    ).encode("utf-8")

    frame_body = (
        struct.pack(
            "!I",
            len(header_bytes)
        )
        + header_bytes
        + payload
    )

    if len(frame_body) > MAX_FRAME_SIZE:
        raise ValueError(
            f"Frame too large: {len(frame_body)} bytes"
        )

    sock.sendall(
        struct.pack(
            "!I",
            len(frame_body)
        )
        + frame_body
    )


def recv_exact(sock, length):
    """
    Receive exactly 'length' bytes.
    """

    data = bytearray()

    while len(data) < length:

        chunk = sock.recv(
            length - len(data)
        )

        if not chunk:
            raise ConnectionError(
                "Connection closed while receiving data"
            )

        data.extend(chunk)

    return bytes(data)


def recv_frame(sock):
    """
    Receive one framed message.
    """

    raw_length = recv_exact(
        sock,
        4
    )

    frame_length = struct.unpack(
        "!I",
        raw_length
    )[0]

    if frame_length <= 4:
        raise ValueError(
            "Invalid frame length"
        )

    if frame_length > MAX_FRAME_SIZE:
        raise ValueError(
            f"Frame exceeds limit: {frame_length}"
        )

    body = recv_exact(
        sock,
        frame_length
    )

    header_length = struct.unpack(
        "!I",
        body[:4]
    )[0]

    if header_length > frame_length - 4:
        raise ValueError(
            "Invalid header length"
        )

    header_bytes = body[
        4:4 + header_length
    ]

    payload = body[
        4 + header_length:
    ]

    header = json.loads(
        header_bytes.decode("utf-8")
    )

    return header, payload


def recv_json(sock):
    """
    Receive a frame and return only JSON header.
    """

    header, payload = recv_frame(sock)

    if payload:
        raise ValueError(
            "Unexpected payload in ACK"
        )

    return header


# ============================================================
# QKMS KEY RETRIEVAL
# ============================================================

def get_key(key_id):
    """
    Retrieve BB84 key metadata from Alice's QKMS API.

    IMPORTANT:
    The key is used locally by Alice.
    It is NOT transmitted to Bob.
    """

    url = (
        f"{QKMS_URL}/etsi/v1/keys/{key_id}"
    )

    print()
    print("QKMS KEY REQUEST")
    print("----------------")
    print(f"URL    : {url}")
    print(f"Key ID : {key_id}")

    response = requests.get(
        url,
        timeout=QKMS_TIMEOUT
    )

    response.raise_for_status()

    data = response.json()

    if "key" not in data:
        raise ValueError(
            "QKMS response does not contain 'key'"
        )

    record = data["key"]

    fields = record.strip().split("\t")

    if len(fields) < 7:
        raise ValueError(
            "Unexpected QKMS key record format"
        )

    record_key_id = fields[0]
    protocol = fields[1]
    key_length = int(fields[2])
    status = fields[3]
    key_binary = fields[-1]

    if str(record_key_id) != str(key_id):
        raise ValueError(
            "Returned key ID does not match requested key ID"
        )

    if protocol.upper() != "BB84":
        raise ValueError(
            f"Expected BB84 key, got {protocol}"
        )

    if status.upper() != "ACTIVE":
        raise ValueError(
            f"Key {key_id} is not ACTIVE"
        )

    if key_length != 256:
        raise ValueError(
            f"Expected 256-bit key, got {key_length}"
        )

    key_bytes = key_from_binary(
        key_binary
    )

    print("Protocol : BB84")
    print("Length   : 256 bits")
    print("Status   : ACTIVE")
    print("Result   : QKMS key retrieved")

    return key_bytes


# ============================================================
# FILE INPUT EXPANSION
# ============================================================

def expand_inputs(inputs):
    """
    Accept:

        file1.txt
        file2.pdf

    or directories:

        folder/

    Directories are searched recursively.
    """

    files = []

    for item in inputs:

        path = Path(item).expanduser()

        if not path.exists():
            raise FileNotFoundError(
                f"File/directory not found: {path}"
            )

        if path.is_file():

            files.append(
                path.resolve()
            )

        elif path.is_dir():

            for child in sorted(
                path.rglob("*")
            ):

                if child.is_file():
                    files.append(
                        child.resolve()
                    )

    if not files:
        raise ValueError(
            "No files found"
        )

    if len(files) > MAX_FILES:
        raise ValueError(
            f"Maximum {MAX_FILES} files allowed"
        )

    return files


# ============================================================
# AAD
# ============================================================

def make_aad(
    session_id,
    file_id,
    key_id,
    filename,
    file_size,
    chunk_index
):
    """
    Additional authenticated data.

    This metadata is authenticated by AES-GCM.
    """

    return (
        "QKMS-PHASE1-V2"
        f"|session={session_id}"
        f"|file={file_id}"
        f"|key={key_id}"
        f"|name={filename}"
        f"|size={file_size}"
        f"|chunk={chunk_index}"
    ).encode("utf-8")


# ============================================================
# SEND ONE FILE
# ============================================================

def send_one_file(
    sock,
    path,
    key_bytes,
    key_id,
    session_id,
    chunk_size,
    file_number,
    total_files
):

    filename = path.name

    file_size, file_sha256 = sha256_file(
        path
    )

    if file_size > MAX_FILE_SIZE:
        raise ValueError(
            f"File too large: {filename}"
        )

    file_id = str(
        uuid.uuid4()
    )

    if file_size == 0:
        total_chunks = 0
    else:
        total_chunks = math.ceil(
            file_size / chunk_size
        )

    print()
    print("=" * 70)
    print(
        f"FILE {file_number}/{total_files}"
    )
    print("=" * 70)

    print(f"Name       : {filename}")
    print(f"Size       : {file_size:,} bytes")
    print(f"SHA-256    : {file_sha256}")
    print(f"Chunks     : {total_chunks}")
    print(
        f"Chunk size : {chunk_size:,} bytes"
    )

    # --------------------------------------------------------
    # FILE_BEGIN
    # --------------------------------------------------------

    send_frame(
        sock,
        {
            "type": "FILE_BEGIN",
            "session_id": session_id,
            "file_id": file_id,
            "filename": filename,
            "size": file_size,
            "sha256": file_sha256,
            "total_chunks": total_chunks,
        }
    )

    ack = recv_json(sock)

    if ack.get("type") != "FILE_READY":
        raise RuntimeError(
            f"Bob did not accept file: {ack}"
        )

    start_time = time.perf_counter()

    sent = 0
    chunk_index = 0

    # --------------------------------------------------------
    # SEND CHUNKS
    # --------------------------------------------------------

    with open(path, "rb") as file:

        while True:

            plaintext = file.read(
                chunk_size
            )

            if not plaintext:
                break

            nonce = os.urandom(12)

            aad = make_aad(
                session_id,
                file_id,
                key_id,
                filename,
                file_size,
                chunk_index
            )

            aesgcm = AESGCM(
                key_bytes
            )

            ciphertext = aesgcm.encrypt(
                nonce,
                plaintext,
                aad
            )

            send_frame(
                sock,
                {
                    "type": "FILE_CHUNK",
                    "session_id": session_id,
                    "file_id": file_id,
                    "chunk_index": chunk_index,
                    "plaintext_size": len(plaintext),
                    "nonce": base64.b64encode(
                        nonce
                    ).decode("ascii"),
                    "aad": base64.b64encode(
                        aad
                    ).decode("ascii"),
                },
                ciphertext
            )

            ack = recv_json(sock)

            if ack.get("type") != "CHUNK_OK":
                raise RuntimeError(
                    f"Chunk {chunk_index} failed: {ack}"
                )

            sent += len(plaintext)

            percent = (
                sent / file_size * 100
                if file_size
                else 100
            )

            print(
                f"\r  Progress: "
                f"{sent:,}/{file_size:,} bytes "
                f"({percent:.1f}%)",
                end="",
                flush=True
            )

            chunk_index += 1

    print()

    # --------------------------------------------------------
    # FILE_END
    # --------------------------------------------------------

    send_frame(
        sock,
        {
            "type": "FILE_END",
            "session_id": session_id,
            "file_id": file_id,
            "total_chunks": total_chunks,
            "size": file_size,
            "sha256": file_sha256,
        }
    )

    ack = recv_json(sock)

    if ack.get("type") != "FILE_OK":
        raise RuntimeError(
            f"Bob did not verify file: {ack}"
        )

    elapsed = (
        time.perf_counter()
        - start_time
    )

    mb = file_size / (
        1024 * 1024
    )

    throughput = (
        mb / elapsed
        if elapsed > 0
        else 0
    )

    print()
    print("FILE RESULT")
    print("-----------")
    print("Status     : SUCCESS")
    print(f"File       : {filename}")
    print(f"Chunks     : {total_chunks}")
    print(f"Time       : {elapsed:.3f} seconds")
    print(
        f"Throughput : {throughput:.2f} MiB/s"
    )
    print(
        "SHA-256    : VERIFIED BY BOB"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description=(
            "QKMS Secure File Sender - "
            "Phase 1"
        )
    )

    parser.add_argument(
        "key_id",
        type=int,
        help="QKMS BB84 key ID"
    )

    parser.add_argument(
        "files",
        nargs="+",
        help=(
            "Files or directories "
            "to transfer"
        )
    )

    parser.add_argument(
        "--chunk-size",
        default="4M",
        help=(
            "Chunk size, e.g. "
            "1M, 4M, 8M, 16M"
        )
    )

    parser.add_argument(
        "--host",
        default=BOB_HOST,
        help="Bob IP address"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=FILE_TRANSFER_PORT,
        help="Bob file-transfer port"
    )

    args = parser.parse_args()

    # --------------------------------------------------------
    # CHUNK SIZE
    # --------------------------------------------------------

    chunk_size = parse_size(
        args.chunk_size
    )

    if chunk_size <= 0:
        raise ValueError(
            "Chunk size must be positive"
        )

    if chunk_size > MAX_CHUNK_SIZE:
        raise ValueError(
            f"Chunk size cannot exceed "
            f"{MAX_CHUNK_SIZE // 1024 // 1024} MiB"
        )

    # --------------------------------------------------------
    # FILES
    # --------------------------------------------------------

    files = expand_inputs(
        args.files
    )

    print()
    print("=" * 70)
    print("QKMS SECURE FILE TRANSFER")
    print("PHASE 1")
    print("=" * 70)

    print(
        f"Files      : {len(files)}"
    )

    print(
        f"Bob        : "
        f"{args.host}:{args.port}"
    )

    print(
        f"Chunk size : "
        f"{chunk_size / 1024 / 1024:.1f} MiB"
    )

    print(
        "Encryption : AES-256-GCM"
    )

    print(
        "Integrity  : SHA-256"
    )

    print(
        "Key source : QKMS / BB84"
    )

    print(
        "Raw key    : NOT TRANSMITTED"
    )

    # --------------------------------------------------------
    # GET QKMS KEY
    # --------------------------------------------------------

    key_bytes = get_key(
        args.key_id
    )

    # --------------------------------------------------------
    # SESSION
    # --------------------------------------------------------

    session_id = str(
        uuid.uuid4()
    )

    print()
    print(
        f"Session ID : {session_id}"
    )

    # --------------------------------------------------------
    # TCP CONNECTION
    # --------------------------------------------------------

    print()
    print(
        f"Connecting to Bob "
        f"{args.host}:{args.port}..."
    )

    session_start = time.perf_counter()

    with socket.create_connection(
        (
            args.host,
            args.port
        ),
        timeout=CONNECT_TIMEOUT
    ) as sock:

        # ----------------------------------------------------
        # SESSION_BEGIN
        # ----------------------------------------------------

        send_frame(
            sock,
            {
                "type": "SESSION_BEGIN",
                "session_id": session_id,
                "key_id": args.key_id,
                "file_count": len(files),
                "chunk_size": chunk_size,
            }
        )

        ack = recv_json(sock)

        if ack.get("type") != "SESSION_READY":
            raise RuntimeError(
                f"Bob rejected session: {ack}"
            )

        print(
            "Bob status : SESSION READY"
        )

        # ----------------------------------------------------
        # SEND ALL FILES
        # ----------------------------------------------------

        for number, path in enumerate(
            files,
            start=1
        ):

            send_one_file(
                sock=sock,
                path=path,
                key_bytes=key_bytes,
                key_id=args.key_id,
                session_id=session_id,
                chunk_size=chunk_size,
                file_number=number,
                total_files=len(files),
            )

        # ----------------------------------------------------
        # SESSION_END
        # ----------------------------------------------------

        send_frame(
            sock,
            {
                "type": "SESSION_END",
                "session_id": session_id,
                "file_count": len(files),
            }
        )

        ack = recv_json(sock)

        if ack.get("type") != "SESSION_OK":
            raise RuntimeError(
                f"Bob did not confirm session: {ack}"
            )

    elapsed = (
        time.perf_counter()
        - session_start
    )

    total_bytes = sum(
        path.stat().st_size
        for path in files
    )

    total_mib = (
        total_bytes /
        (1024 * 1024)
    )

    throughput = (
        total_mib / elapsed
        if elapsed > 0
        else 0
    )

    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("TRANSFER COMPLETE")
    print("=" * 70)

    print(
        f"Files       : {len(files)}"
    )

    print(
        f"Total data  : {total_bytes:,} bytes"
    )

    print(
        f"Time        : {elapsed:.3f} seconds"
    )

    print(
        f"Throughput  : "
        f"{throughput:.2f} MiB/s"
    )

    print(
        "Encryption  : AES-256-GCM"
    )

    print(
        "Integrity   : SHA-256"
    )

    print(
        "Key sent    : NO"
    )

    print(
        "Result      : SUCCESS"
    )


# ============================================================
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":

    try:
        main()

    except KeyboardInterrupt:

        print(
            "\nTransfer cancelled by user."
        )

        sys.exit(130)

    except Exception as exc:

        print()
        print(
            "TRANSFER FAILED"
        )
        print(
            f"Error: {exc}"
        )

        sys.exit(1)
