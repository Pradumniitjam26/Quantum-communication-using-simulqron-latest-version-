#!/usr/bin/env python3

# =============================================================================
#
# Quantum Key Management System (QKMS)
#
# File        : key_manager.py
#
# Author      : Pradum
#
# Description :
# -----------------------------------------------------------------------------
# This module manages the Quantum Key Database.
#
# Functions:
#   • Save new keys
#   • Read all keys
#   • Retrieve the latest key
#
# =============================================================================

#!/usr/bin/env python3

"""
Quantum Key Management System
Key Manager
"""

from datetime import datetime

from config.config import DATABASE_FILE
from utils.logger import logger


def _next_key_id():

    try:
        with open(DATABASE_FILE, "r") as f:
            lines = [line.strip() for line in f if line.strip()]

        if not lines:
            return 0

        return int(lines[-1].split("\t")[0]) + 1

    except Exception:
        return 0


def save_key(protocol, secret_key, owner="Alice-Bob"):

    key_id = _next_key_id()

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    length = len(secret_key)

    status = "ACTIVE"

    expiry = "NEVER"

    usage = 0

    record = "\t".join([
        str(key_id),
        protocol,
        str(length),
        status,
        owner,
        timestamp,
        expiry,
        str(usage),
        secret_key
    ])

    with open(DATABASE_FILE, "a") as f:
        f.write(record + "\n")

    logger.info(f"Key {key_id} stored successfully.")

    return key_id


def latest_key():

    try:

        with open(DATABASE_FILE, "r") as f:

            lines = [line.strip() for line in f if line.strip()]

        if not lines:

            return None

        return lines[-1]

    except Exception:

        return None


def get_key(key_id):

    try:

        with open(DATABASE_FILE, "r") as f:

            for line in f:

                fields = line.strip().split("\t")

                if int(fields[0]) == key_id:

                    return line.strip()

    except Exception:

        pass

    return None
def mark_key_used(key_id):

    try:

        with open(DATABASE_FILE, "r") as f:
            lines = [line.strip().split("\t") for line in f if line.strip()]

        updated = False

        for fields in lines:

            if int(fields[0]) == key_id:

                fields[3] = "USED"

                fields[7] = str(int(fields[7]) + 1)

                updated = True

                logger.info(f"Key {key_id} marked as USED.")

        if updated:

            with open(DATABASE_FILE, "w") as f:

                for fields in lines:

                    f.write("\t".join(fields) + "\n")

            return True

    except Exception as error:

        logger.error(error)

    return False


def expire_key(key_id):

    try:

        with open(DATABASE_FILE, "r") as f:
            lines = [line.strip().split("\t") for line in f if line.strip()]

        updated = False

        for fields in lines:

            if int(fields[0]) == key_id:

                fields[3] = "EXPIRED"

                updated = True

                logger.info(f"Key {key_id} expired.")

        if updated:

            with open(DATABASE_FILE, "w") as f:

                for fields in lines:

                    f.write("\t".join(fields) + "\n")

            return True

    except Exception as error:

        logger.error(error)

    return False


def list_active_keys():

    active = []

    try:

        with open(DATABASE_FILE, "r") as f:

            for line in f:

                fields = line.strip().split("\t")

                if len(fields) >= 9 and fields[3] == "ACTIVE":

                    active.append(line.strip())

    except Exception:

        pass

    return active
def keys_by_status(status):
    """Return key records matching the requested status."""
    matching = []
    wanted_status = status.strip().upper()

    try:
        with open(DATABASE_FILE, "r") as f:
            for line in f:
                fields = line.strip().split("\t")

                if len(fields) >= 9 and fields[3].upper() == wanted_status:
                    matching.append(line.strip())

    except (OSError, IndexError) as error:
        logger.error(f"Unable to read keys by status: {error}")

    return matching


def key_stats():
    """Return counts of keys grouped by status."""
    stats = {
        "total": 0,
        "ACTIVE": 0,
        "USED": 0,
        "EXPIRED": 0,
    }

    try:
        with open(DATABASE_FILE, "r") as f:
            for line in f:
                fields = line.strip().split("\t")

                if len(fields) < 9:
                    continue

                status = fields[3].upper()
                stats["total"] += 1

                if status not in stats:
                    stats[status] = 0

                stats[status] += 1

    except OSError as error:
        logger.error(f"Unable to calculate key statistics: {error}")

    return stats
