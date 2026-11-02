#!/usr/bin/env python3

"""
QKMS Application-Level Secure SMS Sender

Alice-side application.

Workflow:

1. Request a BB84-generated 256-bit key from the
   Alice QKMS REST API using a Key ID.
2. Validate the returned QKMS record.
3. Convert the 256-bit binary key into a 32-byte AES-256 key.
4. Encrypt the SMS using AES-256-CBC + PKCS7.
5. Generate a random IV.
6. Build the secure application packet:
       - key_id
       - iv
       - ciphertext
7. Send the packet directly to Bob using TCP.

IMPORTANT SECURITY RULE:
The raw QKMS secret key is NEVER sent to Bob.

Bob already owns the same key locally in his QKMS database.
Only the Key ID, IV and ciphertext are transmitted.
"""

import json
import socket
import sys

import requests

from crypto.crypto_engine import (
    encrypt,
    key_from_binary,
)


# ============================================================
# QKMS CONFIGURATION
# ============================================================

# Alice's local FastAPI QKMS server.
QKMS_API_URL = "http://127.0.0.1:8000"

# REST endpoint for retrieving one key.
KEY_ENDPOINT = "/etsi/v1/keys/{key_id}"


# ============================================================
# BOB APPLICATION TCP CONFIGURATION
# ============================================================

# Bob's machine IP address.
BOB_IP = "10.11.80.93"

# Application-level secure-message TCP port.
# This is separate from the QKMS Agent port 5000.
BOB_SMS_PORT = 6000

# Receive buffer for Bob's acknowledgement.
BUFFER_SIZE = 65536

# Network encoding.
ENCODING = "utf-8"


# ============================================================
# GET KEY FROM ALICE QKMS
# ============================================================

def get_qkms_key(key_id: int) -> str:
    """
    Retrieve a specific key from the Alice QKMS REST API.

    Expected response format:

        {
            "key": "3\\tBB84\\t256\\tACTIVE\\tAlice-Bob\\t..."
        }

    Returns:
        256-bit binary key as a string.

    Raises:
        RuntimeError if retrieval or validation fails.
    """

    url = (
        QKMS_API_URL
        + KEY_ENDPOINT.format(key_id=key_id)
    )

    print()
    print("=" * 70)
    print("Requesting Key from QKMS")
    print("=" * 70)

    print("Key ID :", key_id)
    print("URL    :", url)

    try:

        response = requests.get(
            url,
            timeout=5
        )

    except requests.RequestException as error:

        raise RuntimeError(
            f"Unable to connect to QKMS: {error}"
        )

    if response.status_code != 200:

        raise RuntimeError(
            f"QKMS returned HTTP {response.status_code}: "
            f"{response.text}"
        )

    try:

        data = response.json()

    except ValueError:

        raise RuntimeError(
            "QKMS returned invalid JSON."
        )

    if "key" not in data:

        raise RuntimeError(
            "QKMS response does not contain 'key'."
        )

    record = data["key"]

    if not isinstance(record, str):

        raise RuntimeError(
            "QKMS key record is not a string."
        )

    # --------------------------------------------------------
    # QKMS database record format:
    #
    # 0  ID
    # 1  Protocol
    # 2  Length
    # 3  Status
    # 4  Owner
    # 5  Created
    # 6  Expiry
    # 7  Used
    # 8  Secret Key
    # --------------------------------------------------------

    fields = record.strip().split("\t")

    if len(fields) < 9:

        raise RuntimeError(
            "Invalid QKMS key record format."
        )

    returned_key_id = fields[0]
    protocol = fields[1]
    length = fields[2]
    status = fields[3]
    secret_key = fields[8]

    print()
    print("QKMS Response")
    print("Key ID   :", returned_key_id)
    print("Protocol :", protocol)
    print("Length   :", length)
    print("Status   :", status)

    # --------------------------------------------------------
    # Validate Key ID
    # --------------------------------------------------------

    if returned_key_id != str(key_id):

        raise RuntimeError(
            f"Key ID mismatch. "
            f"Requested {key_id}, "
            f"received {returned_key_id}."
        )

    # --------------------------------------------------------
    # Validate protocol
    # --------------------------------------------------------

    if protocol != "BB84":

        raise RuntimeError(
            f"Unsupported protocol: {protocol}"
        )

    # --------------------------------------------------------
    # Key must be ACTIVE
    # --------------------------------------------------------

    if status != "ACTIVE":

        raise RuntimeError(
            f"Key is not ACTIVE. "
            f"Current status: {status}"
        )

    # --------------------------------------------------------
    # Validate key length
    # --------------------------------------------------------

    if len(secret_key) != 256:

        raise RuntimeError(
            f"Expected 256-bit key, "
            f"got {len(secret_key)} bits."
        )

    # --------------------------------------------------------
    # Validate binary format
    # --------------------------------------------------------

    if set(secret_key) - {"0", "1"}:

        raise RuntimeError(
            "Secret key contains characters "
            "other than 0 and 1."
        )

    return secret_key


# ============================================================
# CREATE ENCRYPTED MESSAGE
# ============================================================

def create_secure_message(
    key_id: int,
    message: str
):
    """
    Encrypt an SMS using the QKMS key.

    Returns a packet containing ONLY:

        key_id
        iv
        ciphertext

    The raw secret key is never included.
    """

    # --------------------------------------------------------
    # Retrieve key from QKMS
    # --------------------------------------------------------

    binary_key = get_qkms_key(
        key_id
    )

    # --------------------------------------------------------
    # Convert 256-bit binary key into
    # 32-byte AES-256 key.
    # --------------------------------------------------------

    aes_key = key_from_binary(
        binary_key
    )

    print()
    print("=" * 70)
    print("AES-256 Encryption")
    print("=" * 70)

    print("Message :", message)

    # --------------------------------------------------------
    # Encrypt the plaintext.
    #
    # crypto_engine.py performs:
    #     AES-256-CBC
    #     PKCS7 padding
    #     random IV generation
    # --------------------------------------------------------

    iv, ciphertext = encrypt(
        message,
        aes_key
    )

    # --------------------------------------------------------
    # Build application packet.
    #
    # IMPORTANT:
    # Raw secret key is NOT included.
    # --------------------------------------------------------

    packet = {
        "key_id": key_id,
        "iv": iv.hex(),
        "ciphertext": ciphertext.hex(),
    }

    print()
    print("Encrypted Message Packet")
    print(json.dumps(
        packet,
        indent=4
    ))

    print()
    print(
        "Raw QKMS key was NOT included "
        "in packet."
    )

    return packet


# ============================================================
# SEND PACKET DIRECTLY TO BOB
# ============================================================

def send_to_bob(packet: dict):
    """
    Send the encrypted message directly to Bob
    over a classical TCP connection.

    Transmitted data:

        key_id
        iv
        ciphertext

    The raw QKMS key is never transmitted.
    """

    message = json.dumps(
        packet
    ).encode(ENCODING)

    print()
    print("=" * 70)
    print("Sending Encrypted Message to Bob")
    print("=" * 70)

    print(
        f"Bob address : {BOB_IP}:{BOB_SMS_PORT}"
    )

    print(
        "Packet size :",
        len(message),
        "bytes"
    )

    client = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    # Prevent the client from waiting forever.
    client.settimeout(10)

    try:

        print(
            "Connecting to Bob..."
        )

        client.connect(
            (
                BOB_IP,
                BOB_SMS_PORT
            )
        )

        print(
            "Connected to Bob."
        )

        # ----------------------------------------------------
        # Send complete JSON packet.
        # ----------------------------------------------------

        client.sendall(
            message
        )

        print(
            "Encrypted packet transmitted."
        )

        # ----------------------------------------------------
        # Wait for Bob's acknowledgement.
        # ----------------------------------------------------

        response_data = client.recv(
            BUFFER_SIZE
        )

        if not response_data:

            raise RuntimeError(
                "Bob closed the connection "
                "without sending a response."
            )

        response_text = response_data.decode(
            ENCODING
        )

        print()
        print("Bob Response:")
        print(response_text)

        try:

            return json.loads(
                response_text
            )

        except json.JSONDecodeError:

            return {
                "status": "UNKNOWN",
                "raw_response": response_text,
            }

    except socket.timeout:

        return {
            "status": "FAILED",
            "error": "Connection timed out."
        }

    except ConnectionRefusedError:

        return {
            "status": "FAILED",
            "error": (
                f"Bob refused connection on "
                f"{BOB_IP}:{BOB_SMS_PORT}"
            )
        }

    except OSError as error:

        return {
            "status": "FAILED",
            "error": str(error)
        }

    finally:

        client.close()


# ============================================================
# MAIN APPLICATION
# ============================================================

def main():

    print("=" * 70)
    print("QKMS Automatic Secure SMS Sender")
    print("=" * 70)

    # --------------------------------------------------------
    # Key ID
    #
    # Example:
    #
    # python3 -m application.sms_sender 3
    # --------------------------------------------------------

    if len(sys.argv) >= 2:

        try:

            key_id = int(
                sys.argv[1]
            )

        except ValueError:

            print(
                "ERROR: Key ID must be an integer."
            )

            return

    else:

        key_id = 3

    print(
        "Using Key ID :",
        key_id
    )

    # --------------------------------------------------------
    # Read user message.
    # --------------------------------------------------------

    message = input(
        "\nEnter message to encrypt: "
    ).strip()

    if not message:

        print(
            "ERROR: Message cannot be empty."
        )

        return

    try:

        # ----------------------------------------------------
        # Generate encrypted packet.
        # ----------------------------------------------------

        packet = create_secure_message(
            key_id,
            message
        )

        # ----------------------------------------------------
        # Send directly to Bob over TCP.
        # ----------------------------------------------------

        response = send_to_bob(
            packet
        )

        # ----------------------------------------------------
        # Display final delivery status.
        # ----------------------------------------------------

        print()
        print("=" * 70)
        print("Final Message Delivery Status")
        print("=" * 70)

        print(
            json.dumps(
                response,
                indent=4
            )
        )

        if response.get(
            "status"
        ) == "SUCCESS":

            print()
            print("=" * 70)
            print("SECURE SMS DELIVERY SUCCESS")
            print("=" * 70)

            print(
                "Key ID :",
                key_id
            )

        else:

            print()
            print("=" * 70)
            print("SECURE SMS DELIVERY FAILED")
            print("=" * 70)

            print(
                "Check that Bob's TCP receiver "
                "is running on port 6000."
            )

    except Exception as error:

        print()
        print("=" * 70)
        print("ENCRYPTION / DELIVERY FAILED")
        print("=" * 70)

        print(
            "Reason :",
            error
        )


if __name__ == "__main__":
    main()
