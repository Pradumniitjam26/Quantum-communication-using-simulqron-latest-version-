#!/usr/bin/env python3

import json
import time
import hashlib
import socket
from pathlib import Path

import requests


# ============================================================
# CONFIGURATION
# ============================================================

# ------------------------------------------------------------
# ALICE QKMS
# ------------------------------------------------------------
# This API is running on the Alice machine.
# The script is executed on Alice, therefore localhost is used.
API_URL = "http://127.0.0.1:8000/etsi/v1/keys/generate"


# ------------------------------------------------------------
# ALICE MACHINE
# ------------------------------------------------------------
ALICE_HOST = "10.11.80.94"


# ------------------------------------------------------------
# BOB MACHINE
# ------------------------------------------------------------
BOB_AGENT_HOST = "10.11.80.93"
BOB_AGENT_PORT = 5000


# ------------------------------------------------------------
# KEY RANGE
# ------------------------------------------------------------
# Keys 0-10 already exist.
# Therefore start from 11.
START_KEY_ID = 11
END_KEY_ID = 99


# ------------------------------------------------------------
# TIMING
# ------------------------------------------------------------
WAIT_BETWEEN_KEYS = 1
REQUEST_TIMEOUT = 120
BOB_TIMEOUT = 15


# ------------------------------------------------------------
# ALICE DATABASE
# ------------------------------------------------------------
DATABASE_FILE = Path("database/key_database.txt")


# ============================================================
# BOB AGENT CONNECTION
# ============================================================

def send_bob_command(command):

    try:

        with socket.create_connection(
            (BOB_AGENT_HOST, BOB_AGENT_PORT),
            timeout=BOB_TIMEOUT
        ) as sock:

            sock.sendall(command.encode())

            response = sock.recv(8192).decode().strip()

            return response

    except Exception as e:

        print(
            f"[ERROR] Cannot connect to Bob Agent "
            f"{BOB_AGENT_HOST}:{BOB_AGENT_PORT}: {e}"
        )

        return None


# ============================================================
# ALICE DATABASE
# ============================================================

def get_database_ids():

    ids = set()

    if not DATABASE_FILE.exists():
        return ids

    try:

        with open(DATABASE_FILE, "r") as f:

            for line in f:

                line = line.strip()

                if not line:
                    continue

                fields = line.split("\t")

                try:

                    key_id = int(fields[0])

                    ids.add(key_id)

                except (ValueError, IndexError):

                    continue

    except OSError as e:

        print(f"[ERROR] Cannot read Alice database: {e}")

        raise

    return ids


# ============================================================
# GET ALICE DATABASE RECORD
# ============================================================

def get_database_record(key_id):

    if not DATABASE_FILE.exists():
        return None

    try:

        with open(DATABASE_FILE, "r") as f:

            for line in f:

                fields = line.strip().split("\t")

                if fields and fields[0] == str(key_id):

                    return fields

    except OSError:

        return None

    return None


# ============================================================
# GET ALICE KEY DIGEST
# ============================================================

def get_alice_key_digest(key_id):

    record = get_database_record(key_id)

    if record is None:
        return None

    if len(record) < 9:
        return None

    key_value = record[8]

    if len(key_value) != 256:
        return None

    return hashlib.sha256(
        key_value.encode()
    ).hexdigest()


# ============================================================
# ASK BOB FOR KEY DIGEST
# ============================================================

def get_bob_digest(key_id):

    response = send_bob_command(
        f"GET_BB84_DIGEST:{key_id}"
    )

    if response is None:

        return None

    print(
        f"[Bob] Response : {response}"
    )

    if not response.startswith("READY:"):

        return None

    digest = response[
        len("READY:"):
    ].strip()

    return digest


# ============================================================
# CHECK WHETHER KEY IS ALREADY COMPLETE
# ============================================================

def is_key_already_complete(key_id):

    print()
    print(
        f"[CHECK] Checking whether Key {key_id} "
        f"already exists on Alice and Bob..."
    )

    alice_digest = get_alice_key_digest(key_id)

    if alice_digest is None:

        print(
            f"[CHECK] Key {key_id} is not available "
            f"as a valid 256-bit key on Alice."
        )

        return False

    print(
        f"[CHECK] Alice digest : {alice_digest}"
    )

    bob_digest = get_bob_digest(key_id)

    if bob_digest is None:

        print(
            f"[CHECK] Key {key_id} is not available "
            f"on Bob."
        )

        return False

    print(
        f"[CHECK] Bob digest   : {bob_digest}"
    )

    if alice_digest != bob_digest:

        print(
            f"[WARNING] Key {key_id} exists on both sides "
            f"but digest does not match."
        )

        return False

    print(
        f"[OK] Key {key_id} already exists "
        f"and Alice/Bob digests MATCH."
    )

    return True


# ============================================================
# GENERATE ONE DISTRIBUTED BB84 KEY
# ============================================================

def generate_one_key(expected_key_id):

    print()
    print("=" * 70)

    print(
        f"REQUESTING DISTRIBUTED BB84 KEY {expected_key_id}"
    )

    print("=" * 70)


    # --------------------------------------------------------
    # STEP 1
    # REQUEST BB84 FROM ALICE
    # --------------------------------------------------------

    print(
        "[1] Requesting BB84 key from Alice QKMS"
    )

    try:

        response = requests.post(
            API_URL,
            timeout=REQUEST_TIMEOUT
        )

    except requests.exceptions.Timeout:

        print(
            "[ERROR] QKMS API timeout."
        )

        return False

    except requests.exceptions.ConnectionError as e:

        print(
            f"[ERROR] Cannot connect to QKMS API: {e}"
        )

        return False

    except requests.exceptions.RequestException as e:

        print(
            f"[ERROR] HTTP error: {e}"
        )

        return False


    print(
        f"[INFO] HTTP status: {response.status_code}"
    )


    if response.status_code != 200:

        print(
            "[ERROR] QKMS returned unsuccessful HTTP status."
        )

        print(response.text)

        return False


    # --------------------------------------------------------
    # STEP 2
    # PARSE JSON
    # --------------------------------------------------------

    try:

        result = response.json()

    except json.JSONDecodeError:

        print(
            "[ERROR] Invalid JSON from QKMS."
        )

        print(response.text)

        return False


    # --------------------------------------------------------
    # STEP 3
    # CHECK BB84 SUCCESS
    # --------------------------------------------------------

    if result.get("status") != "SUCCESS":

        print(
            "[ERROR] BB84 generation failed."
        )

        print(
            json.dumps(
                result,
                indent=2
            )
        )

        return False


    if result.get("protocol") != "BB84":

        print(
            f"[ERROR] Unexpected protocol: "
            f"{result.get('protocol')}"
        )

        return False


    # --------------------------------------------------------
    # STEP 4
    # READ KEY RECORD
    # --------------------------------------------------------

    key_record = result.get("key")

    if not key_record:

        print(
            "[ERROR] No key record returned."
        )

        return False


    fields = str(key_record).split("\t")


    if len(fields) < 9:

        print(
            "[ERROR] Invalid key database record."
        )

        print(key_record)

        return False


    try:

        returned_key_id = int(fields[0])

    except ValueError:

        print(
            "[ERROR] Invalid Key ID."
        )

        return False


    key_length = fields[2]

    key_status = fields[3]

    key_value = fields[8]


    print()
    print("[Alice QKMS RESULT]")

    print(
        f"Key ID       : {returned_key_id}"
    )

    print(
        f"Key Length   : {key_length}"
    )

    print(
        f"Status       : {key_status}"
    )


    # --------------------------------------------------------
    # STEP 5
    # VERIFY KEY ID
    # --------------------------------------------------------

    if returned_key_id != expected_key_id:

        print()
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("KEY ID MISMATCH")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        print(
            f"Expected : {expected_key_id}"
        )

        print(
            f"Received : {returned_key_id}"
        )

        return False


    # --------------------------------------------------------
    # STEP 6
    # VERIFY KEY LENGTH
    # --------------------------------------------------------

    if key_length != "256":

        print(
            "[ERROR] Key is not 256 bits."
        )

        return False


    # --------------------------------------------------------
    # STEP 7
    # VERIFY STATUS
    # --------------------------------------------------------

    if key_status != "ACTIVE":

        print(
            "[ERROR] Key is not ACTIVE."
        )

        return False


    # --------------------------------------------------------
    # STEP 8
    # VERIFY ALICE DATABASE
    # --------------------------------------------------------

    alice_record = get_database_record(
        expected_key_id
    )


    if alice_record is None:

        print(
            "[ERROR] Key is not present "
            "in Alice database."
        )

        return False


    print(
        "[OK] Key exists in Alice database."
    )


    # --------------------------------------------------------
    # STEP 9
    # VERIFY ALICE KEY
    # --------------------------------------------------------

    alice_key = alice_record[8]


    if len(alice_key) != 256:

        print(
            "[ERROR] Alice database key "
            "is not 256 bits."
        )

        return False


    # --------------------------------------------------------
    # STEP 10
    # CALCULATE ALICE DIGEST
    # --------------------------------------------------------

    alice_digest = hashlib.sha256(
        alice_key.encode()
    ).hexdigest()


    print()
    print("[Alice Key Verification]")

    print(
        f"Alice Key Digest : {alice_digest}"
    )


    # --------------------------------------------------------
    # STEP 11
    # ASK BOB FOR DIGEST
    # --------------------------------------------------------

    print()
    print(
        "[2] Asking Bob Agent for BB84 digest"
    )


    bob_response = send_bob_command(
        f"GET_BB84_DIGEST:{expected_key_id}"
    )


    if bob_response is None:

        print(
            "[ERROR] No response from Bob."
        )

        return False


    print(
        f"[Bob] Response : {bob_response}"
    )


    # --------------------------------------------------------
    # STEP 12
    # CHECK BOB RESPONSE
    # --------------------------------------------------------

    if not bob_response.startswith("READY:"):

        print(
            "[ERROR] Bob did not return READY:digest."
        )

        return False


    bob_digest = bob_response[
        len("READY:"):
    ].strip()


    print(
        f"[Bob Key Digest] : {bob_digest}"
    )


    # --------------------------------------------------------
    # STEP 13
    # COMPARE DIGESTS
    # --------------------------------------------------------

    if alice_digest != bob_digest:

        print()
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("DIGEST MISMATCH")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

        print(
            f"Alice : {alice_digest}"
        )

        print(
            f"Bob   : {bob_digest}"
        )

        print()
        print(
            "KEY WILL NOT BE COMMITTED."
        )

        return False


    print()
    print("========================================")
    print("ALICE / BOB DIGEST MATCH")
    print("========================================")


    # --------------------------------------------------------
    # STEP 14
    # COMMIT KEY ON BOB
    # --------------------------------------------------------

    print(
        f"[3] Committing Key {expected_key_id} on Bob"
    )


    commit_response = send_bob_command(
        f"COMMIT_BB84:{expected_key_id}"
    )


    if commit_response is None:

        print(
            "[ERROR] No response from Bob commit."
        )

        return False


    print(
        f"[Bob] Commit response : "
        f"{commit_response}"
    )


    if commit_response != "COMMITTED":

        print(
            "[ERROR] Bob did not commit the key."
        )

        return False


    # --------------------------------------------------------
    # STEP 15
    # VERIFY AFTER COMMIT
    # --------------------------------------------------------

    print()
    print(
        f"[4] Verifying Key {expected_key_id} "
        f"after Bob commit..."
    )


    verify_digest = get_bob_digest(
        expected_key_id
    )


    if verify_digest != alice_digest:

        print(
            "[ERROR] Post-commit digest verification failed."
        )

        print(
            f"Alice : {alice_digest}"
        )

        print(
            f"Bob   : {verify_digest}"
        )

        return False


    # --------------------------------------------------------
    # SUCCESS
    # --------------------------------------------------------

    print()
    print("=" * 70)

    print(
        f"DISTRIBUTED BB84 KEY {expected_key_id} SUCCESS"
    )

    print("=" * 70)

    print(
        f"Key ID        : {expected_key_id}"
    )

    print(
        "Alice DB      : STORED"
    )

    print(
        "Bob DB        : COMMITTED"
    )

    print(
        "Alice Digest  : MATCH"
    )

    print(
        "Bob Digest    : MATCH"
    )

    print(
        "Key Length    : 256 bits"
    )

    print(
        "Status        : ACTIVE"
    )

    print(
        "Protocol      : BB84"
    )

    print("=" * 70)


    return True


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("=" * 70)

    print(
        " DISTRIBUTED BB84 KEY POOL GENERATOR"
    )

    print("=" * 70)


    print()

    print(
        f"Key range       : "
        f"{START_KEY_ID}-{END_KEY_ID}"
    )

    print(
        f"Alice machine   : "
        f"{ALICE_HOST}"
    )

    print(
        f"Alice API       : "
        f"{API_URL}"
    )

    print(
        f"Bob Agent       : "
        f"{BOB_AGENT_HOST}:{BOB_AGENT_PORT}"
    )

    print(
        f"Alice database  : "
        f"{DATABASE_FILE}"
    )


    # --------------------------------------------------------
    # CHECK BOB CONNECTION
    # --------------------------------------------------------

    print()
    print(
        "[INFO] Testing connection to Bob Agent..."
    )


    test_response = send_bob_command(
        "GET_BB84_DIGEST:999999"
    )


    if test_response is None:

        print()
        print(
            "[ERROR] Cannot reach Bob Agent."
        )

        print(
            f"Check Bob Agent at "
            f"{BOB_AGENT_HOST}:{BOB_AGENT_PORT}"
        )

        return


    print(
        f"[OK] Bob Agent reachable."
    )


    # --------------------------------------------------------
    # EXISTING ALICE IDs
    # --------------------------------------------------------

    existing_ids = get_database_ids()


    print()
    print(
        "[INFO] Existing Alice Key IDs:"
    )

    print(
        sorted(existing_ids)
    )


    # --------------------------------------------------------
    # DETERMINE STARTING POINT
    # --------------------------------------------------------

    print()
    print(
        "[INFO] Checking existing distributed keys..."
    )


    completed_ids = set()


    for key_id in range(
        0,
        END_KEY_ID + 1
    ):

        if key_id not in existing_ids:
            continue


        if is_key_already_complete(key_id):

            completed_ids.add(key_id)


    print()
    print(
        "[INFO] Already completed distributed keys:"
    )

    print(
        sorted(completed_ids)
    )


    # --------------------------------------------------------
    # GENERATE MISSING KEYS
    # --------------------------------------------------------

    successful = 0

    skipped = 0


    for key_id in range(
        START_KEY_ID,
        END_KEY_ID + 1
    ):


        # ----------------------------------------------------
        # SKIP COMPLETED KEY
        # ----------------------------------------------------

        if key_id in completed_ids:

            print()
            print(
                f"[SKIP] Key {key_id} already exists "
                f"on Alice and Bob with matching digest."
            )

            skipped += 1

            continue


        # ----------------------------------------------------
        # GENERATE KEY
        # ----------------------------------------------------

        success = generate_one_key(
            key_id
        )


        if not success:

            print()
            print("=" * 70)

            print(
                "GENERATION STOPPED"
            )

            print("=" * 70)

            print(
                f"Failed Key ID : {key_id}"
            )

            print(
                f"Successful    : {successful}"
            )

            print(
                f"Skipped       : {skipped}"
            )

            print()

            print(
                "Fix the problem and run again."
            )

            return


        successful += 1


        # ----------------------------------------------------
        # WAIT
        # ----------------------------------------------------

        if key_id < END_KEY_ID:

            print()

            print(
                f"Waiting "
                f"{WAIT_BETWEEN_KEYS} second..."
            )

            time.sleep(
                WAIT_BETWEEN_KEYS
            )


    # --------------------------------------------------------
    # FINAL CHECK - ALICE DATABASE
    # --------------------------------------------------------

    final_ids = get_database_ids()


    missing_alice = [

        i

        for i in range(
            START_KEY_ID,
            END_KEY_ID + 1
        )

        if i not in final_ids

    ]


    # --------------------------------------------------------
    # FINAL CHECK - DISTRIBUTED
    # --------------------------------------------------------

    missing_distributed = []


    print()
    print(
        "[INFO] Performing final Alice/Bob verification..."
    )


    for key_id in range(
        START_KEY_ID,
        END_KEY_ID + 1
    ):

        if key_id not in final_ids:

            missing_distributed.append(
                key_id
            )

            continue


        if not is_key_already_complete(
            key_id
        ):

            missing_distributed.append(
                key_id
            )


    # --------------------------------------------------------
    # FINAL REPORT
    # --------------------------------------------------------

    print()
    print("=" * 70)

    print(
        "FINAL DISTRIBUTED BB84 KEY POOL REPORT"
    )

    print("=" * 70)


    print(
        f"Requested range       : "
        f"{START_KEY_ID}-{END_KEY_ID}"
    )

    print(
        f"Newly generated       : "
        f"{successful}"
    )

    print(
        f"Already completed     : "
        f"{skipped}"
    )


    if missing_alice:

        print()
        print(
            "[WARNING] Missing Alice keys:"
        )

        print(
            missing_alice
        )


    if missing_distributed:

        print()
        print(
            "[WARNING] Keys not verified "
            "on both Alice and Bob:"
        )

        print(
            missing_distributed
        )


    if (
        not missing_alice
        and not missing_distributed
    ):

        print()
        print(
            "[SUCCESS] Distributed key pool complete."
        )

        print(
            "[SUCCESS] Alice contains keys 0-99 "
            "(assuming 0-10 already existed)."
        )

        print(
            "[SUCCESS] Keys 11-99 verified "
            "against Bob."
        )

        print(
            "[SUCCESS] Alice/Bob digests match."
        )


    print()
    print("=" * 70)


# ============================================================
# PROGRAM ENTRY
# ============================================================

if __name__ == "__main__":

    main()
