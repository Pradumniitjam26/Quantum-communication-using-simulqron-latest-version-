#!/usr/bin/env python3

"""
Quantum Key Management System (QKMS)

BB84 Protocol Manager

Workflow:

1. Generate common Key ID
2. Contact Bob Agent
3. Start Bob BB84 receiver
4. Start Alice BB84 sender
5. Validate Alice BB84 result
6. Get Bob final-key digest
7. Compare Alice/Bob digests
8. Commit Bob key only after digest match
9. Store Alice key using the same Key ID
"""

import hashlib
import os
import subprocess
import time

from communication.client import send_command

from protocols.bb84.result_parser import get_result

from database.key_manager import save_key

from utils.logger import logger


def next_key_id():
    """
    Get the next available Key ID from Alice's database.
    """

    try:

        from config.config import DATABASE_FILE

        with open(DATABASE_FILE, "r") as f:

            lines = [
                line.strip()
                for line in f
                if line.strip()
            ]

        if not lines:
            return 0

        ids = []

        for line in lines:

            fields = line.split("\t")

            try:
                ids.append(int(fields[0]))
            except (ValueError, IndexError):
                continue

        return max(ids) + 1 if ids else 0

    except Exception as error:

        logger.error(
            f"Could not determine next Key ID: {error}"
        )

        return 0


def launch_alice():

    project = os.path.expanduser(
        "~/SimulaQron/examples/native-mode/bb84_native"
    )

    script = os.path.join(
        project,
        "alice_bb84_100.py"
    )

    logger.info(
        "Launching Alice BB84 Sender"
    )

    process = subprocess.Popen(
        ["python3", script],
        cwd=project
    )

    logger.info(
        f"Alice PID : {process.pid}"
    )

    return process


def calculate_digest(key):
    """
    Calculate SHA-256 digest of the reconciled
    Alice BB84 key.
    """

    return hashlib.sha256(
        key.encode()
    ).hexdigest()


def get_bob_digest(key_id, retries=20, delay=0.5):
    """
    Ask Bob for the current session digest.

    Bob may still be finishing its result processing,
    so retry for a short period.
    """

    command = (
        f"GET_BB84_DIGEST:{key_id}"
    )

    for attempt in range(retries):

        response = send_command(command)

        logger.info(
            f"Bob digest response : {response}"
        )

        if response.startswith("READY:"):

            return response.split(
                ":",
                1
            )[1]

        if response.startswith("STATUS:"):

            logger.info(
                f"Bob session status : {response}"
            )

        time.sleep(delay)

    return None


def execute_bb84():

    # ========================================================
    # Generate common Key ID
    # ========================================================

    key_id = next_key_id()

    logger.info(
        f"Common BB84 Key ID : {key_id}"
    )

    # ========================================================
    # Start Bob
    # ========================================================

    logger.info(
        "Contacting Bob Agent"
    )

    response = send_command(
        f"START_BB84:{key_id}"
    )

    if response != "READY":

        logger.error(
            "Bob Agent did not report READY."
        )

        return False

    logger.info(
        "Bob Agent Ready"
    )

    time.sleep(2)

    # ========================================================
    # Start Alice
    # ========================================================

    alice = launch_alice()

    return_code = alice.wait()

    logger.info(
        f"Alice BB84 process return code : {return_code}"
    )

    if return_code != 0:

        logger.error(
            "Alice BB84 process failed."
        )

        # Tell Bob to discard pending session
        send_command(
            f"ABORT_BB84:{key_id}"
        )

        return False

    # ========================================================
    # Validate Alice result
    # ========================================================

    logger.info(
        "Validating Alice BB84 result"
    )

    result = get_result()

    if result is None:

        logger.error(
            "Alice BB84 result file not found."
        )

        send_command(
            f"ABORT_BB84:{key_id}"
        )

        return False

    logger.info(
        f"Alice result file : {result['result_file']}"
    )

    if not result["success"]:

        logger.error(
            "Alice BB84 validation FAILED."
        )

        send_command(
            f"ABORT_BB84:{key_id}"
        )

        return False

    alice_key = result["secret_key"]

    if alice_key is None:

        logger.error(
            "Alice secret key not found."
        )

        send_command(
            f"ABORT_BB84:{key_id}"
        )

        return False

    if len(alice_key) != 256:

        logger.error(
            f"Invalid Alice key length : {len(alice_key)}"
        )

        send_command(
            f"ABORT_BB84:{key_id}"
        )

        return False

    # ========================================================
    # Calculate Alice digest
    # ========================================================

    alice_digest = calculate_digest(
        alice_key
    )

    logger.info(
        f"Alice reconciled-key digest : {alice_digest}"
    )

    # ========================================================
    # Get Bob digest
    # ========================================================

    logger.info(
        "Requesting Bob reconciled-key digest"
    )

    bob_digest = get_bob_digest(
        key_id
    )

    if bob_digest is None:

        logger.error(
            "Bob digest was not available."
        )

        send_command(
            f"ABORT_BB84:{key_id}"
        )

        return False

    # ========================================================
    # Compare digests
    # ========================================================

    logger.info(
        f"Bob reconciled-key digest : {bob_digest}"
    )

    if alice_digest != bob_digest:

        logger.error(
            "FINAL KEY DIGEST MISMATCH."
        )

        logger.error(
            "Alice and Bob keys are NOT identical."
        )

        logger.error(
            "No QKMS key will be committed."
        )

        send_command(
            f"ABORT_BB84:{key_id}"
        )

        return False

    logger.info(
        "FINAL KEY DIGEST MATCH."
    )

    # ========================================================
    # Commit Bob key
    # ========================================================

    commit_response = send_command(
        f"COMMIT_BB84:{key_id}"
    )

    logger.info(
        f"Bob commit response : {commit_response}"
    )

    if commit_response != "COMMITTED":

        logger.error(
            "Bob key commit failed."
        )

        send_command(
            f"ABORT_BB84:{key_id}"
        )

        return False

    # ========================================================
    # Store Alice key using SAME Key ID
    # ========================================================

    saved_key_id = save_key(
        "BB84",
        alice_key,
        owner="Alice-Bob"
    )

    if saved_key_id != key_id:

        logger.error(
            f"Key ID mismatch. Expected {key_id}, "
            f"stored {saved_key_id}."
        )

        return False

    # ========================================================
    # Final success
    # ========================================================

    logger.info(
        "=" * 60
    )

    logger.info(
        "DISTRIBUTED BB84 KEY COMMIT SUCCESS"
    )

    logger.info(
        f"Common Key ID : {key_id}"
    )

    logger.info(
        "Alice/Bob digest : MATCH"
    )

    logger.info(
        "Alice key stored successfully"
    )

    logger.info(
        "Bob key committed successfully"
    )

    logger.info(
        "=" * 60
    )

    return True
