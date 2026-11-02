
#!/usr/bin/env python3

"""
QKMS Background BB84 Key Generation Worker.

Uses the existing Alice QKMS FastAPI endpoint.
Does not directly modify Alice/Bob databases.
Does not transmit raw BB84 key material.
Does not perform live video/audio key rotation.
"""

import argparse
import json
import signal
import time
import urllib.request
import urllib.error


STOP_WORKER = False


def stop_worker(signum, frame):

    global STOP_WORKER

    STOP_WORKER = True

    print(
        "\n[WORKER] Stop requested. "
        "Waiting before next generation.",
        flush=True
    )


def generate_bb84(api_url, timeout):

    endpoint = (
        api_url.rstrip("/")
        + "/etsi/v1/keys/generate"
    )

    request = urllib.request.Request(
        endpoint,
        data=b"{}",
        headers={
            "Content-Type": "application/json"
        },
        method="POST"
    )

    try:

        with urllib.request.urlopen(
            request,
            timeout=timeout
        ) as response:

            result = json.loads(
                response.read().decode("utf-8")
            )

            return response.status, result

    except urllib.error.HTTPError as error:

        body = error.read().decode(
            "utf-8",
            errors="replace"
        )

        return error.code, {
            "status": "HTTP_ERROR",
            "detail": body[:500]
        }

    except Exception as error:

        return 0, {
            "status": "CONNECTION_ERROR",
            "detail": str(error)
        }


def main():

    parser = argparse.ArgumentParser(
        description="QKMS Background BB84 Worker"
    )

    mode = parser.add_mutually_exclusive_group(
        required=True
    )

    mode.add_argument(
        "--once",
        action="store_true",
        help="Generate one BB84 key"
    )

    mode.add_argument(
        "--continuous",
        action="store_true",
        help="Generate BB84 keys continuously"
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=300,
        help="Interval in seconds (default 300)"
    )

    parser.add_argument(
        "--api-url",
        default="http://127.0.0.1:8000",
        help="Alice QKMS API URL"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="API timeout in seconds"
    )

    args = parser.parse_args()

    if args.interval < 30:
        parser.error("Interval must be at least 30 seconds")

    if args.timeout < 30:
        parser.error("Timeout must be at least 30 seconds")

    signal.signal(
        signal.SIGINT,
        stop_worker
    )

    signal.signal(
        signal.SIGTERM,
        stop_worker
    )

    print("=" * 55)
    print(" QKMS BACKGROUND BB84 GENERATION")
    print("=" * 55)

    print("API URL:", args.api_url)
    print("Interval:", args.interval, "seconds")
    print("Mode:", "CONTINUOUS" if args.continuous else "ONCE")

    while not STOP_WORKER:

        start_time = time.time()

        print("\n[WORKER] Starting BB84 generation request...")

        status_code, result = generate_bb84(
            args.api_url,
            args.timeout
        )


        print("[WORKER] HTTP status:", status_code)

        # Never print the complete API response because it may
        # contain raw BB84 key material.
        response_status = (
            result.get("status", "UNKNOWN")
            if isinstance(result, dict)
            else "INVALID_RESPONSE"
        )

        print("[WORKER] Response status:", response_status)

        if status_code == 200 and response_status == "SUCCESS":

            key_info = result.get("key")

            # API currently returns a tab-separated database record.
            if isinstance(key_info, str):
                fields = key_info.strip().split("\t")

                if len(fields) < 9:
                    raise RuntimeError("Invalid QKMS key record")

                key_info = {
                    "key_id": fields[0],
                    "protocol": fields[1],
                    "key_length": fields[2],
                    "status": fields[3],
                }

            elif not isinstance(key_info, dict):
                raise RuntimeError("Unexpected QKMS key response")

            key_id = key_info.get("key_id", key_info.get("id"))
            protocol = key_info.get("protocol")
            key_length = key_info.get(
                "key_length", key_info.get("length")
            )
            key_status = key_info.get("status")

            if (
                key_id is None
                or str(protocol).upper() != "BB84"
                or int(key_length) != 256
                or str(key_status).upper() != "ACTIVE"
            ):
                raise RuntimeError("Generated key failed validation")

            print("\n[WORKER] BB84 GENERATION SUCCESS")
            print("[WORKER] Key ID:", key_id)
            print("[WORKER] Protocol:", protocol)
            print("[WORKER] Key length:", key_length)
            print("[WORKER] Status:", key_status)
            print("[WORKER] Raw key is not displayed.")

        elif response_status == "BUSY":

            print(
                "[WORKER] QKMS is busy. "
                "No second generation was started."
            )

        else:

            detail = (
                result.get("detail", "No additional details")
                if isinstance(result, dict)
                else "Invalid API response"
            )

            print("[WORKER] Generation failed:", detail)
            print("[WORKER] Will retry at the next interval.")


        if not args.continuous:
            break

        if STOP_WORKER:
            break

        elapsed = time.time() - start_time

        wait_time = max(
            0,
            args.interval - elapsed
        )

        print(
            "\n[WORKER] Next generation in",
            round(wait_time, 1),
            "seconds."
        )

        end_time = time.time() + wait_time

        while (
            not STOP_WORKER
            and time.time() < end_time
        ):

            time.sleep(
                min(1, end_time - time.time())
            )

    print("\n[WORKER] Background worker stopped.")


if __name__ == "__main__":

    main()
