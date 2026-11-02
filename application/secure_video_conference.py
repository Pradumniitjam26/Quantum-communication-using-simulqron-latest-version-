#!/usr/bin/env python3

import base64
import hashlib
import json
import os
import queue
import secrets
import socket
import struct
import sys
import threading
import cv2
import numpy as np
import sounddevice as sd

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# QKMS SECURE VIDEO CONFERENCE
# STAGE 4F FINAL
# ALICE
#
# Alice selects QKMS Key ID from command line.
#
# Example:
# python3 -m application.secure_video_conference 20
#
# Bob receives the Key ID through SESSION_HELLO and loads
# the corresponding key from his LOCAL QKMS database.
#
# RAW QKMS KEY IS NEVER TRANSMITTED.
# ============================================================


# ============================================================
# NETWORK
# ============================================================

ROLE = "ALICE"

LOCAL_IP = "10.11.80.94"
PEER_IP = "10.11.80.93"

# Alice -> Bob
SEND_VIDEO_PORT = 7100

# Bob -> Alice
RECEIVE_VIDEO_PORT = 7101

# Alice -> Bob
SEND_AUDIO_PORT = 7200

# Bob -> Alice
RECEIVE_AUDIO_PORT = 7201


# ============================================================
# QKMS KEY
# ============================================================

if len(sys.argv) != 2:

    print()
    print("=" * 70)
    print("QKMS SECURE VIDEO CONFERENCE")
    print("=" * 70)
    print()
    print("ERROR: QKMS Key ID is required.")
    print()
    print("Usage:")
    print("python3 -m application.secure_video_conference <KEY_ID>")
    print()
    print("Example:")
    print("python3 -m application.secure_video_conference 20")
    print()

    sys.exit(1)


try:

    KEY_ID = int(sys.argv[1])

except ValueError:

    print("[ERROR] KEY_ID must be an integer.")
    sys.exit(1)


if KEY_ID <= 0:

    print("[ERROR] KEY_ID must be greater than 0.")
    sys.exit(1)


# ============================================================
# CAMERA
# ============================================================

CAMERA_DEVICE = "/dev/video0"

FRAME_WIDTH = 640
FRAME_HEIGHT = 480
FRAME_FPS = 30

JPEG_QUALITY = 70


# ============================================================
# AUDIO
# ============================================================

AUDIO_RATE = 48000
AUDIO_CHANNELS = 1
AUDIO_DTYPE = "int16"
AUDIO_BLOCKSIZE = 960

AUDIO_OUTPUT_DEVICE = None

NOISE_GATE_THRESHOLD = 500
NOISE_GATE_ATTENUATION = 0.12
MIC_GAIN = 1.0


# ============================================================
# SECURITY
# ============================================================

VIDEO_AAD_PREFIX = "QKMS-SECURE-VIDEO-V2"
AUDIO_AAD_PREFIX = "QKMS-SECURE-AUDIO-V2"

NONCE_SIZE = 12

MAX_HEADER_SIZE = 65535
MAX_PACKET_SIZE = 2 * 1024 * 1024


# ============================================================
# GLOBAL STATE
# ============================================================

running = True

stop_event = threading.Event()

SESSION_READY = threading.Event()

SESSION_ID = secrets.token_hex(16)

local_frame = None
remote_frame = None

local_frame_lock = threading.Lock()
remote_frame_lock = threading.Lock()


# ============================================================
# AUDIO QUEUES
# ============================================================

audio_send_queue = queue.Queue(
    maxsize=20
)

audio_play_queue = queue.Queue(
    maxsize=100
)


# ============================================================
# MICROPHONE
# ============================================================

mic_muted = False

mic_lock = threading.Lock()


def is_microphone_muted():

    with mic_lock:

        return mic_muted


def clear_audio_queue():

    while True:

        try:

            audio_send_queue.get_nowait()

        except queue.Empty:

            break


def toggle_microphone():

    global mic_muted

    with mic_lock:

        mic_muted = not mic_muted

        state = mic_muted

    if state:

        clear_audio_queue()

        print("[MIC] Microphone MUTED")

    else:

        print("[MIC] Microphone UNMUTED")


# ============================================================
# QKMS KEY LOADER
# ============================================================

def get_qkms_key(key_id):

    print()
    print("[QKMS] Loading local Key ID:", key_id)

    from database.key_manager import get_key

    record = get_key(key_id)

    if record is None:

        raise RuntimeError(
            f"QKMS Key {key_id} not found"
        )


    # --------------------------------------------------------
    # Dictionary record
    # --------------------------------------------------------

    if isinstance(record, dict):

        record_key_id = record.get(
            "key_id",
            record.get(
                "id",
                key_id
            )
        )

        protocol = record.get(
            "protocol",
            "BB84"
        )

        key_length = int(
            record.get(
                "key_length",
                record.get(
                    "length",
                    256
                )
            )
        )

        status = record.get(
            "status",
            "ACTIVE"
        )

        binary_key = record.get(
            "key",
            record.get(
                "binary_key",
                record.get(
                    "value"
                )
            )
        )


    # --------------------------------------------------------
    # Existing QKMS database record
    # --------------------------------------------------------

    else:

        fields = str(
            record
        ).strip().split("\t")

        if len(fields) < 4:

            raise RuntimeError(
                "Invalid local QKMS record"
            )

        record_key_id = fields[0]

        protocol = fields[1]

        key_length = int(
            fields[2]
        )

        status = fields[3]

        binary_key = fields[-1]


    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    if str(record_key_id) != str(key_id):

        raise RuntimeError(
            "QKMS key ID mismatch"
        )


    if str(protocol).upper() != "BB84":

        raise RuntimeError(
            f"Expected BB84, got {protocol}"
        )


    if key_length != 256:

        raise RuntimeError(
            f"Expected 256-bit key, got {key_length}"
        )


    if str(status).upper() != "ACTIVE":

        raise RuntimeError(
            f"Key {key_id} is not ACTIVE"
        )


    # --------------------------------------------------------
    # Convert binary key to 32 bytes
    # --------------------------------------------------------

    if isinstance(binary_key, bytes):

        key = binary_key

    else:

        binary_key = str(
            binary_key
        ).strip()


        if (
            len(binary_key) == 256
            and set(binary_key) <= {"0", "1"}
        ):

            key = int(
                binary_key,
                2
            ).to_bytes(
                32,
                "big"
            )

        elif len(binary_key) == 64:

            key = bytes.fromhex(
                binary_key
            )

        else:

            raise RuntimeError(
                "Invalid 256-bit BB84 key"
            )


    if len(key) != 32:

        raise RuntimeError(
            "QKMS key is not 32 bytes"
        )


    digest = hashlib.sha256(
        key
    ).hexdigest()


    print("[QKMS] Key ID      :", key_id)
    print("[QKMS] Protocol    :", protocol)
    print("[QKMS] Length      : 256 bits")
    print("[QKMS] Status      :", status)
    print("[QKMS] Key SHA-256 :", digest)
    print("[QKMS] Raw key     : LOCAL ONLY")

    return key


# ============================================================
# TCP FRAMING
#
# 4 bytes = JSON header length
# 4 bytes = payload length
# N bytes = JSON header
# M bytes = ciphertext
# ============================================================

def send_packet(
    sock,
    header,
    payload=b""
):

    header_bytes = json.dumps(
        header,
        separators=(",", ":")
    ).encode("utf-8")

    header_length = len(
        header_bytes
    )

    payload_length = len(
        payload
    )

    if header_length > MAX_HEADER_SIZE:

        raise ValueError(
            "Header too large"
        )

    if payload_length > MAX_PACKET_SIZE:

        raise ValueError(
            "Payload too large"
        )


    sock.sendall(
        struct.pack(
            "!II",
            header_length,
            payload_length
        )
    )

    sock.sendall(
        header_bytes
    )

    if payload_length > 0:

        sock.sendall(
            payload
        )


def recv_exact(
    sock,
    size
):

    data = bytearray()

    while len(data) < size:

        chunk = sock.recv(
            size - len(data)
        )

        if not chunk:

            raise ConnectionError(
                "Connection closed by peer"
            )

        data.extend(
            chunk
        )

    return bytes(data)


def recv_packet(sock):

    prefix = recv_exact(
        sock,
        8
    )

    header_length, payload_length = struct.unpack(
        "!II",
        prefix
    )

    if (
        header_length == 0
        or header_length > MAX_HEADER_SIZE
    ):

        raise ValueError(
            f"Invalid header length: {header_length}"
        )


    if payload_length > MAX_PACKET_SIZE:

        raise ValueError(
            f"Invalid payload length: {payload_length}"
        )


    header_bytes = recv_exact(
        sock,
        header_length
    )

    payload = recv_exact(
        sock,
        payload_length
    )

    header = json.loads(
        header_bytes.decode("utf-8")
    )

    return header, payload


# ============================================================
# AAD
# ============================================================

def make_aad(
    prefix,
    media,
    sequence
):

    text = (
        f"{prefix}"
        f"|session={SESSION_ID}"
        f"|key={KEY_ID}"
        f"|media={media}"
        f"|sequence={sequence}"
    )

    return text.encode("utf-8")


# ============================================================
# CONNECTION
# ============================================================

def connect_retry(
    host,
    port,
    label
):

    while (
        running
        and not stop_event.is_set()
    ):

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        try:

            print(
                f"[{label}] Connecting to "
                f"{host}:{port}"
            )

            sock.settimeout(5)

            sock.connect(
                (
                    host,
                    port
                )
            )

            sock.settimeout(None)

            print(
                f"[{label}] Connected"
            )

            return sock

        except OSError as exc:

            sock.close()

            print(
                f"[{label}] Peer not ready "
                f"({exc}). Retrying in 2 seconds..."
            )

            stop_event.wait(2)

    return None


def create_server(
    port,
    label
):

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    server.bind(
        (
            LOCAL_IP,
            port
        )
    )

    server.listen(5)

    server.settimeout(1)

    print(
        f"[{label}] Listening on "
        f"{LOCAL_IP}:{port}"
    )

    return server


# ============================================================
# CAMERA
# ============================================================

def open_camera():

    camera = cv2.VideoCapture(
        CAMERA_DEVICE,
        cv2.CAP_V4L2
    )

    if not camera.isOpened():

        raise RuntimeError(
            f"Cannot open camera {CAMERA_DEVICE}"
        )


    camera.set(
        cv2.CAP_PROP_FOURCC,
        cv2.VideoWriter_fourcc(*"MJPG")
    )

    camera.set(
        cv2.CAP_PROP_FRAME_WIDTH,
        FRAME_WIDTH
    )

    camera.set(
        cv2.CAP_PROP_FRAME_HEIGHT,
        FRAME_HEIGHT
    )

    camera.set(
        cv2.CAP_PROP_FPS,
        FRAME_FPS
    )


    print(
        "[VIDEO] Camera active:",
        CAMERA_DEVICE
    )

    return camera


# ============================================================
# VIDEO SENDER
# ============================================================

def video_sender(key):

    global local_frame

    aes = AESGCM(key)

    camera = None
    sock = None

    sequence = 0


    try:

        camera = open_camera()


        # ----------------------------------------------------
        # SESSION HANDSHAKE
        # ----------------------------------------------------

        sock = connect_retry(
            PEER_IP,
            SEND_VIDEO_PORT,
            "SECURE VIDEO SEND"
        )

        if sock is None:

            return


        hello = {

            "type": "SESSION_HELLO",

            "version": 2,

            "key_id": KEY_ID,

            "session_id": SESSION_ID,

            "protocol": "BB84",

            "key_length": 256
        }


        print()
        print(
            "[SESSION] Sending SESSION_HELLO"
        )

        print(
            "[SESSION] Key ID:",
            KEY_ID
        )

        print(
            "[SESSION] Session ID:",
            SESSION_ID
        )


        send_packet(
            sock,
            hello,
            b""
        )


        ack, _ = recv_packet(
            sock
        )


        if ack.get("type") != "SESSION_ACK":

            raise RuntimeError(
                "Invalid SESSION_ACK type"
            )


        if ack.get("status") != "READY":

            raise RuntimeError(
                "Bob did not accept session"
            )


        if int(
            ack.get(
                "key_id",
                -1
            )
        ) != KEY_ID:

            raise RuntimeError(
                "SESSION_ACK Key ID mismatch"
            )


        if (
            ack.get(
                "session_id"
            )
            != SESSION_ID
        ):

            raise RuntimeError(
                "SESSION_ACK session mismatch"
            )


        print()
        print(
            "[SESSION] Bob accepted Key ID:",
            KEY_ID
        )

        print(
            "[SESSION] Session established"
        )

        print(
            "[SESSION] RAW KEY SENT: NO"
        )

        print()


        SESSION_READY.set()


        # ----------------------------------------------------
        # VIDEO LOOP
        # ----------------------------------------------------

        while (
            running
            and not stop_event.is_set()
        ):

            ret, frame = camera.read()

            if not ret:

                continue


            with local_frame_lock:

                local_frame = frame.copy()


            ok, encoded = cv2.imencode(
                ".jpg",
                frame,
                [
                    cv2.IMWRITE_JPEG_QUALITY,
                    JPEG_QUALITY
                ]
            )


            if not ok:

                continue


            plaintext = encoded.tobytes()


            nonce = os.urandom(
                NONCE_SIZE
            )


            aad = make_aad(
                VIDEO_AAD_PREFIX,
                "video",
                sequence
            )


            ciphertext = aes.encrypt(
                nonce,
                plaintext,
                aad
            )


            header = {

                "type": "SECURE_VIDEO",

                "version": 2,

                "key_id": KEY_ID,

                "session_id": SESSION_ID,

                "sequence": sequence,

                "nonce":
                    base64.b64encode(
                        nonce
                    ).decode("ascii"),

                "aad":
                    base64.b64encode(
                        aad
                    ).decode("ascii"),

                "plaintext_size":
                    len(plaintext),

                "ciphertext_size":
                    len(ciphertext)
            }


            try:

                send_packet(
                    sock,
                    header,
                    ciphertext
                )

                sequence += 1


            except OSError as exc:

                print(
                    "[SECURE VIDEO SEND] "
                    f"Connection lost: {exc}"
                )

                break


    except Exception as exc:

        print(
            "[SECURE VIDEO SEND] Error:",
            exc
        )


    finally:

        if camera:

            camera.release()

        if sock:

            sock.close()

        print(
            "[SECURE VIDEO SEND] Stopped"
        )


# ============================================================
# VIDEO RECEIVER
# ============================================================

def video_receiver(key):

    global remote_frame

    aes = AESGCM(key)

    server = create_server(
        RECEIVE_VIDEO_PORT,
        "SECURE VIDEO RECV"
    )


    try:

        while (
            running
            and not stop_event.is_set()
        ):

            try:

                conn, address = server.accept()

            except socket.timeout:

                continue


            print(
                "[SECURE VIDEO RECV] "
                f"Connection from {address}"
            )


            with conn:

                last_sequence = -1


                while (
                    running
                    and not stop_event.is_set()
                ):

                    try:

                        header, ciphertext = (
                            recv_packet(conn)
                        )


                        if header.get(
                            "type"
                        ) != "SECURE_VIDEO":

                            raise ValueError(
                                "Invalid video packet"
                            )


                        if int(
                            header.get(
                                "key_id",
                                -1
                            )
                        ) != KEY_ID:

                            raise ValueError(
                                "Unexpected video key ID"
                            )


                        if (
                            header.get(
                                "session_id"
                            )
                            != SESSION_ID
                        ):

                            raise ValueError(
                                "Unexpected video session ID"
                            )


                        sequence = int(
                            header[
                                "sequence"
                            ]
                        )


                        if sequence <= last_sequence:

                            raise ValueError(
                                "Replay/out-of-order "
                                "video packet"
                            )


                        nonce = base64.b64decode(
                            header[
                                "nonce"
                            ],
                            validate=True
                        )


                        aad = base64.b64decode(
                            header[
                                "aad"
                            ],
                            validate=True
                        )


                        if len(nonce) != NONCE_SIZE:

                            raise ValueError(
                                "Invalid video nonce"
                            )


                        expected_ciphertext = int(
                            header[
                                "ciphertext_size"
                            ]
                        )


                        if (
                            len(ciphertext)
                            != expected_ciphertext
                        ):

                            raise ValueError(
                                "Video ciphertext "
                                "size mismatch"
                            )


                        plaintext = aes.decrypt(
                            nonce,
                            ciphertext,
                            aad
                        )


                        expected_plaintext = int(
                            header[
                                "plaintext_size"
                            ]
                        )


                        if (
                            len(plaintext)
                            != expected_plaintext
                        ):

                            raise ValueError(
                                "Video plaintext "
                                "size mismatch"
                            )


                        frame = cv2.imdecode(
                            np.frombuffer(
                                plaintext,
                                dtype=np.uint8
                            ),
                            cv2.IMREAD_COLOR
                        )


                        if frame is None:

                            raise ValueError(
                                "JPEG decode failed"
                            )


                        with remote_frame_lock:

                            remote_frame = frame


                        last_sequence = sequence


                    except Exception as exc:

                        print(
                            "[SECURE VIDEO RECV] "
                            f"Packet error: {exc}"
                        )

                        break


    finally:

        server.close()

        print(
            "[SECURE VIDEO RECV] Stopped"
        )


# ============================================================
# MICROPHONE
# ============================================================

def process_microphone(
    indata
):

    audio = (
        indata[:, 0]
        .astype(
            np.float32,
            copy=True
        )
    )


    if MIC_GAIN != 1.0:

        audio *= float(
            MIC_GAIN
        )


    magnitude = np.abs(
        audio
    )


    quiet = (
        magnitude
        < float(
            NOISE_GATE_THRESHOLD
        )
    )


    audio[quiet] *= float(
        NOISE_GATE_ATTENUATION
    )


    audio = np.clip(
        audio,
        -32768,
        32767
    )


    return audio.astype(
        np.int16
    ).tobytes()


# ============================================================
# FIND C270
# ============================================================

def find_microphone():

    devices = sd.query_devices()

    candidates = []


    for index, device in enumerate(
        devices
    ):

        if device.get(
            "max_input_channels",
            0
        ) <= 0:

            continue


        name = str(
            device.get(
                "name",
                ""
            )
        )


        if "C270" in name.upper():

            candidates.append(
                (
                    index,
                    name
                )
            )


    if candidates:

        index, name = candidates[0]

        print(
            "[AUDIO] Microphone:",
            f"[{index}] {name}"
        )

        return index


    raise RuntimeError(
        "C270 microphone not found"
    )


# ============================================================
# AUDIO SENDER
# ============================================================

def audio_sender(key):

    aes = AESGCM(key)

    sock = None

    sequence = 0

    microphone = find_microphone()


    def callback(
        indata,
        frames,
        time_info,
        status
    ):

        if status:

            print(
                "[AUDIO MIC]",
                status
            )


        if is_microphone_muted():

            return


        try:

            data = process_microphone(
                indata
            )


            if audio_send_queue.full():

                try:

                    audio_send_queue.get_nowait()

                except queue.Empty:

                    pass


            audio_send_queue.put_nowait(
                data
            )


        except Exception as exc:

            print(
                "[AUDIO MIC] Error:",
                exc
            )


    try:

        with sd.InputStream(

            device=microphone,

            samplerate=AUDIO_RATE,

            channels=AUDIO_CHANNELS,

            dtype=AUDIO_DTYPE,

            blocksize=AUDIO_BLOCKSIZE,

            callback=callback

        ):

            print(
                "[AUDIO SEND] "
                "Microphone active"
            )


            SESSION_READY.wait()


            while (
                running
                and not stop_event.is_set()
            ):


                if sock is None:

                    sock = connect_retry(
                        PEER_IP,
                        SEND_AUDIO_PORT,
                        "SECURE AUDIO SEND"
                    )


                    if sock is None:

                        break


                try:

                    pcm = audio_send_queue.get(
                        timeout=0.5
                    )

                except queue.Empty:

                    continue


                nonce = os.urandom(
                    NONCE_SIZE
                )


                aad = make_aad(
                    AUDIO_AAD_PREFIX,
                    "audio",
                    sequence
                )


                ciphertext = aes.encrypt(
                    nonce,
                    pcm,
                    aad
                )


                header = {

                    "type": "SECURE_AUDIO",

                    "version": 2,

                    "key_id": KEY_ID,

                    "session_id": SESSION_ID,

                    "sequence": sequence,

                    "nonce":
                        base64.b64encode(
                            nonce
                        ).decode("ascii"),

                    "aad":
                        base64.b64encode(
                            aad
                        ).decode("ascii"),

                    "plaintext_size":
                        len(pcm),

                    "ciphertext_size":
                        len(ciphertext)
                }


                try:

                    send_packet(
                        sock,
                        header,
                        ciphertext
                    )

                    sequence += 1


                except OSError as exc:

                    print(
                        "[SECURE AUDIO SEND] "
                        f"Connection lost: {exc}"
                    )

                    sock.close()

                    sock = None


    except Exception as exc:

        print(
            "[AUDIO SEND] Error:",
            exc
        )


    finally:

        if sock:

            sock.close()

        print(
            "[SECURE AUDIO SEND] Stopped"
        )


# ============================================================
# AUDIO RECEIVER
# ============================================================

def audio_receiver(key):

    aes = AESGCM(key)

    server = create_server(
        RECEIVE_AUDIO_PORT,
        "SECURE AUDIO RECV"
    )


    try:

        while (
            running
            and not stop_event.is_set()
        ):

            try:

                conn, address = server.accept()

            except socket.timeout:

                continue


            print(
                "[SECURE AUDIO RECV] "
                f"Connection from {address}"
            )


            with conn:

                last_sequence = -1


                while (
                    running
                    and not stop_event.is_set()
                ):

                    try:

                        header, ciphertext = (
                            recv_packet(conn)
                        )


                        if header.get(
                            "type"
                        ) != "SECURE_AUDIO":

                            raise ValueError(
                                "Invalid audio packet"
                            )


                        if int(
                            header.get(
                                "key_id",
                                -1
                            )
                        ) != KEY_ID:

                            raise ValueError(
                                "Unexpected audio key ID"
                            )


                        if (
                            header.get(
                                "session_id"
                            )
                            != SESSION_ID
                        ):

                            raise ValueError(
                                "Unexpected audio session ID"
                            )


                        sequence = int(
                            header[
                                "sequence"
                            ]
                        )


                        if sequence <= last_sequence:

                            raise ValueError(
                                "Replay/out-of-order "
                                "audio packet"
                            )


                        nonce = base64.b64decode(
                            header[
                                "nonce"
                            ],
                            validate=True
                        )


                        aad = base64.b64decode(
                            header[
                                "aad"
                            ],
                            validate=True
                        )


                        if len(nonce) != NONCE_SIZE:

                            raise ValueError(
                                "Invalid audio nonce"
                            )


                        expected_ciphertext = int(
                            header[
                                "ciphertext_size"
                            ]
                        )


                        if (
                            len(ciphertext)
                            != expected_ciphertext
                        ):

                            raise ValueError(
                                "Audio ciphertext "
                                "size mismatch"
                            )


                        plaintext = aes.decrypt(
                            nonce,
                            ciphertext,
                            aad
                        )


                        expected_plaintext = int(
                            header[
                                "plaintext_size"
                            ]
                        )


                        if (
                            len(plaintext)
                            != expected_plaintext
                        ):

                            raise ValueError(
                                "Audio plaintext "
                                "size mismatch"
                            )


                        if audio_play_queue.full():

                            try:

                                audio_play_queue.get_nowait()

                            except queue.Empty:

                                pass


                        audio_play_queue.put_nowait(
                            plaintext
                        )


                        last_sequence = sequence


                    except Exception as exc:

                        print(
                            "[SECURE AUDIO RECV] "
                            f"Packet error: {exc}"
                        )

                        break


    finally:

        server.close()

        print(
            "[SECURE AUDIO RECV] Stopped"
        )


# ============================================================
# AUDIO PLAYBACK
# ============================================================

def audio_playback():

    def callback(
        outdata,
        frames,
        time_info,
        status
    ):

        if status:

            print(
                "[AUDIO PLAY]",
                status
            )


        outdata.fill(0)


        try:

            data = (
                audio_play_queue.get_nowait()
            )

        except queue.Empty:

            return


        samples = np.frombuffer(
            data,
            dtype=np.int16
        )


        count = min(
            len(samples),
            frames
        )


        if count > 0:

            outdata[
                :count,
                0
            ] = samples[
                :count
            ]


    try:

        with sd.OutputStream(

            device=AUDIO_OUTPUT_DEVICE,

            samplerate=AUDIO_RATE,

            channels=1,

            dtype="int16",

            blocksize=AUDIO_BLOCKSIZE,

            callback=callback

        ):

            print(
                "[AUDIO PLAY] "
                "Speaker active"
            )


            while (
                running
                and not stop_event.is_set()
            ):

                stop_event.wait(
                    0.2
                )


    except Exception as exc:

        print(
            "[AUDIO PLAY] Error:",
            exc
        )


    print(
        "[AUDIO PLAY] Stopped"
    )


# ============================================================
# GUI
# ============================================================

def mouse_callback(
    event,
    x,
    y,
    flags,
    param
):

    if (
        event
        == cv2.EVENT_LBUTTONDOWN
        and 20 <= x <= 190
        and 410 <= y <= 470
    ):

        toggle_microphone()


def gui():

    global running

    window = (
        "ALICE - QKMS SECURE "
        "VIDEO CONFERENCE"
    )


    cv2.namedWindow(
        window,
        cv2.WINDOW_NORMAL
    )


    cv2.setMouseCallback(
        window,
        mouse_callback
    )


    print(
        "[GUI] Press Q or ESC to quit."
    )

    print(
        "[GUI] Click MIC button "
        "to mute/unmute."
    )


    while (
        running
        and not stop_event.is_set()
    ):

        with local_frame_lock:

            left = (
                None
                if local_frame is None
                else local_frame.copy()
            )


        with remote_frame_lock:

            right = (
                None
                if remote_frame is None
                else remote_frame.copy()
            )


        if left is None:

            left = np.zeros(
                (
                    FRAME_HEIGHT,
                    FRAME_WIDTH,
                    3
                ),
                dtype=np.uint8
            )

            cv2.putText(
                left,
                "Waiting for local camera...",
                (70, 240),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.7,
                (255, 255, 255),
                2
            )


        if right is None:

            right = np.zeros(
                (
                    FRAME_HEIGHT,
                    FRAME_WIDTH,
                    3
                ),
                dtype=np.uint8
            )

            cv2.putText(
                right,
                "Waiting for Bob...",
                (170, 240),
                cv2.FONT_HERSHEY_SIMPLEX,
                0.8,
                (255, 255, 255),
                2
            )


        cv2.putText(
            left,
            "ALICE - LOCAL",
            (15, 30),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.75,
            (255, 255, 255),
            2
        )


        cv2.putText(
            right,
            "BOB - AES-256-GCM",
            (15, 30),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.7,
            (255, 255, 255),
            2
        )


        cv2.rectangle(
            left,
            (20, 410),
            (190, 470),
            (40, 40, 40),
            -1
        )


        cv2.rectangle(
            left,
            (20, 410),
            (190, 470),
            (255, 255, 255),
            1
        )


        label = (
            "MIC: MUTED"
            if is_microphone_muted()
            else
            "MIC: ON"
        )


        cv2.putText(
            left,
            label,
            (32, 448),
            cv2.FONT_HERSHEY_SIMPLEX,
            0.65,
            (255, 255, 255),
            2
        )


        combined = np.hstack(
            (
                left,
                right
            )
        )


        cv2.imshow(
            window,
            combined
        )


        key = (
            cv2.waitKey(1)
            & 0xFF
        )


        if key in (
            ord("q"),
            ord("Q"),
            27
        ):

            break


    stop_event.set()

    running = False

    cv2.destroyAllWindows()


# ============================================================
# MAIN
# ============================================================

def main():

    global running


    print()
    print("=" * 70)
    print("QKMS SECURE VIDEO CONFERENCE")
    print("STAGE 4F FINAL - ALICE")
    print("SESSION HANDSHAKE + AES-256-GCM")
    print("SECURE VIDEO + SECURE AUDIO")
    print("=" * 70)

    print(
        f"Peer             : {PEER_IP}"
    )

    print(
        f"QKMS Key ID      : {KEY_ID}"
    )

    print(
        "Encryption       : AES-256-GCM"
    )

    print(
        "Raw key sent     : NO"
    )

    print(
        f"Video TX/RX      : "
        f"{SEND_VIDEO_PORT}/"
        f"{RECEIVE_VIDEO_PORT}"
    )

    print(
        f"Audio TX/RX      : "
        f"{SEND_AUDIO_PORT}/"
        f"{RECEIVE_AUDIO_PORT}"
    )

    print(
        f"Session ID       : {SESSION_ID}"
    )

    print("=" * 70)


    try:

        key = get_qkms_key(
            KEY_ID
        )


        threads = [

            threading.Thread(
                target=video_receiver,
                args=(key,),
                daemon=True
            ),

            threading.Thread(
                target=video_sender,
                args=(key,),
                daemon=True
            ),

            threading.Thread(
                target=audio_receiver,
                args=(key,),
                daemon=True
            ),

            threading.Thread(
                target=audio_sender,
                args=(key,),
                daemon=True
            ),

            threading.Thread(
                target=audio_playback,
                daemon=True
            )
        ]


        for thread in threads:

            thread.start()


        gui()


    except KeyboardInterrupt:

        print(
            "\n[SYSTEM] Keyboard interrupt"
        )


    except Exception as exc:

        print(
            "[SYSTEM] Error:",
            exc
        )


    finally:

        running = False

        stop_event.set()

        cv2.destroyAllWindows()

        print(
            "[SYSTEM] Alice stopped"
        )


if __name__ == "__main__":

    main()
