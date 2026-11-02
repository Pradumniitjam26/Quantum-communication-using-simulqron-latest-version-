#!/usr/bin/env python3

"""
Quantum Key Management System (QKMS)

Alice BB84 Result Parser

Reads the latest Alice BB84 experiment report and provides:
    - Latest result file
    - Protocol success/failure
    - Final SHA-256 secret key
"""

import glob
import os
import re

from config.config import RESULT_DIRECTORY


def latest_result_file():
    """
    Return the newest Alice BB84 experiment report.
    """

    files = glob.glob(
        os.path.join(
            RESULT_DIRECTORY,
            "alice_result_*.txt"
        )
    )

    if not files:
        return None

    return max(
        files,
        key=os.path.getmtime
    )


def read_latest_result():
    """
    Read the newest Alice BB84 report.
    """

    report = latest_result_file()

    if report is None:
        return None, None

    with open(report, "r") as file:
        text = file.read()

    return report, text


def protocol_success():
    """
    Return True only when the latest Alice report
    explicitly contains Protocol Status : SUCCESS.
    """

    report, text = read_latest_result()

    if report is None:
        return False

    match = re.search(
        r"Protocol Status\s*:\s*SUCCESS",
        text,
        re.MULTILINE
    )

    return match is not None


def extract_secret_key():
    """
    Extract the 256-bit SHA-256 secret key from
    the newest successful Alice report.
    """

    report, text = read_latest_result()

    if report is None:
        return None

    # Do not return a key from a failed experiment.
    if not protocol_success():
        return None

    match = re.search(
        r"SHA-256 Privacy Amplified Key \(Binary\)\s*:\s*([01]{256})",
        text,
        re.MULTILINE
    )

    if match:
        return match.group(1)

    # Fallback for report variants containing SHA-256 Secret Key
    match = re.search(
        r"SHA-256 Secret Key\s*([01]{256})",
        text,
        re.MULTILINE
    )

    if match:
        return match.group(1)

    return None


def get_result():
    """
    Return structured information about the latest
    Alice BB84 experiment.
    """

    report, text = read_latest_result()

    if report is None:
        return None

    success = bool(
        re.search(
            r"Protocol Status\s*:\s*SUCCESS",
            text,
            re.MULTILINE
        )
    )

    key = None

    if success:

        match = re.search(
            r"SHA-256 Privacy Amplified Key \(Binary\)\s*:\s*([01]{256})",
            text,
            re.MULTILINE
        )

        if match:
            key = match.group(1)

        else:

            match = re.search(
                r"SHA-256 Secret Key\s*([01]{256})",
                text,
                re.MULTILINE
            )

            if match:
                key = match.group(1)

    return {
        "result_file": report,
        "success": success,
        "secret_key": key
    }


if __name__ == "__main__":

    result = get_result()

    if result is None:

        print("=" * 70)
        print("No Alice BB84 result found.")
        print("=" * 70)

    else:

        print("=" * 70)
        print("Alice BB84 Result Validation")
        print("=" * 70)

        print("Result File :", result["result_file"])

        print(
            "Status      :",
            "SUCCESS" if result["success"] else "FAILED"
        )

        print(
            "Key Length  :",
            len(result["secret_key"])
            if result["secret_key"]
            else 0
        )

        if result["secret_key"]:
            print("[RESULT] Secret key generated successfully.")
            print("[RESULT] Raw secret key is hidden for security.")
        print("=" * 70)
