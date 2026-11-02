#!/usr/bin/env python3

import base64
import collections
import hashlib
import json
import math
import os
import queue
import secrets
import socket
import struct
import sys
import threading
import time

# Ensure project root is in sys.path for database/config imports
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import requests
import cv2
import numpy as np
import sounddevice as sd

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# QKMS SECURE VIDEO CONFERENCE
# STAGE 4G
# ALICE
#
# Alice selects the QKMS Key ID from the command line:
#
#     python3 -m application.secure_video_conference 20
#
# Bob receives the Key ID through SESSION_HELLO and loads the
# same key from his LOCAL QKMS database.
#
# RAW QKMS KEY IS NEVER TRANSMITTED.
# ============================================================


# ============================================================
# NETWORK
# (QKMS_LOCAL_IP / QKMS_PEER_IP override the defaults)
# ============================================================

ROLE = "ALICE"

LOCAL_NAME = "Alice"
PEER_NAME = "Bob"

LOCAL_IP = os.getenv("QKMS_LOCAL_IP", "10.11.80.94")
PEER_IP = os.getenv("QKMS_PEER_IP", "10.11.80.93")

QKMS_API_URL = os.getenv("QKMS_API_URL", "http://127.0.0.1:8000").rstrip("/")
QKMS_API_TIMEOUT = float(os.getenv("QKMS_API_TIMEOUT", "10"))

SEND_VIDEO_PORT = 7100       # Alice -> Bob
RECEIVE_VIDEO_PORT = 7101    # Bob -> Alice
SEND_AUDIO_PORT = 7200       # Alice -> Bob
RECEIVE_AUDIO_PORT = 7201    # Bob -> Alice


# ============================================================
# QKMS KEY ID (command line)
# ============================================================

if len(sys.argv) != 2:

    print()
    print("=" * 70)
    print("QKMS SECURE VIDEO CONFERENCE - ALICE")
    print("=" * 70)
    print()
    print("ERROR: QKMS Key ID is required.")
    print()
    print("Usage:   python3 -m application.secure_video_conference <KEY_ID>")
    print("Example: python3 -m application.secure_video_conference 20")
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

SESSION_ID = secrets.token_hex(16)

# ============================================================
# CAMERA
# ============================================================

def _camera_source(value):
    """'/dev/video0' stays a path, '0' / '1' become device indexes."""
    value = str(value).strip()
    return int(value) if value.isdigit() else value


CAMERA_DEVICE = _camera_source(os.getenv("QKMS_CAMERA", "/dev/video0"))

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
AUDIO_BLOCKSIZE = 960                 # 20 ms per block

AUDIO_OUTPUT_DEVICE = None            # None = system default speaker

# Preferred microphone. If it is not found, the default input is used
# instead (the old code stopped sending audio completely).
PREFERRED_MIC_NAME = os.getenv("QKMS_MIC_NAME", "C270")

# Block-level noise gate (RMS of each 20 ms block, smoothed + hold).
NOISE_GATE_THRESHOLD = 300
NOISE_GATE_ATTENUATION = 0.12
NOISE_GATE_HOLD_BLOCKS = 12
MIC_GAIN = 1.0

# Playback jitter buffer (in 20 ms blocks)
PLAYBACK_PREBUFFER_BLOCKS = 3
PLAYBACK_MAX_BLOCKS = 10


# ============================================================
# SECURITY
# ============================================================

VIDEO_AAD_PREFIX = "QKMS-SECURE-VIDEO-V2"
AUDIO_AAD_PREFIX = "QKMS-SECURE-AUDIO-V2"

PROTOCOL_VERSION = 2

NONCE_SIZE = 12

MAX_HEADER_SIZE = 65535
MAX_PACKET_SIZE = 2 * 1024 * 1024

HANDSHAKE_TIMEOUT = 15.0


# ============================================================
# GLOBAL STATE
# ============================================================

running = True

stop_event = threading.Event()

SESSION_READY = threading.Event()

local_frame = None
local_frame_id = 0
remote_frame = None

local_frame_lock = threading.Lock()
local_frame_cond = threading.Condition(local_frame_lock)
remote_frame_lock = threading.Lock()


def is_running():
    return running and not stop_event.is_set()


def key_label():
    return "–" if KEY_ID is None else str(KEY_ID)


def session_label(n=16):
    return (SESSION_ID or "–")[:n].upper()


# ============================================================
# CALL UI STATE (shared between media threads and the GUI)
# ============================================================

class RateMeter:
    """Sliding 2-second window: events/sec and bytes/sec."""

    def __init__(self, window=2.0):
        self.window = window
        self.events = collections.deque()
        self.total_events = 0
        self.total_bytes = 0
        self.lock = threading.Lock()

    def tick(self, nbytes=0):
        now = time.time()
        with self.lock:
            self.events.append((now, nbytes))
            self.total_events += 1
            self.total_bytes += nbytes
            self._trim(now)

    def _trim(self, now):
        while self.events and now - self.events[0][0] > self.window:
            self.events.popleft()

    def rate(self):
        now = time.time()
        with self.lock:
            self._trim(now)
            if len(self.events) < 2:
                return 0.0
            return len(self.events) / max(now - self.events[0][0], 0.001)

    def kbps(self):
        now = time.time()
        with self.lock:
            self._trim(now)
            if not self.events:
                return 0.0
            span = max(now - self.events[0][0], 0.001)
            return sum(b for _, b in self.events) * 8 / 1000.0 / span


class CallSettings:
    """Values the user changes live from the menu."""

    FILTERS = [
        "NONE", "GRAYSCALE", "SEPIA", "COOL", "WARM",
        "CARTOON", "SKETCH", "BLUR", "NEGATIVE", "VIGNETTE",
    ]

    QUALITY_PRESETS = [
        ("LOW", 40), ("MEDIUM", 60), ("HIGH", 80), ("ULTRA", 95)
    ]

    FPS_PRESETS = [10, 15, 24, 30]

    # (name, BGR)
    COLORS = [
        ("OFF", None),
        ("CYAN", (255, 220, 40)),
        ("GREEN", (110, 230, 90)),
        ("YELLOW", (60, 220, 250)),
        ("ORANGE", (40, 150, 255)),
        ("RED", (80, 80, 255)),
        ("PINK", (200, 90, 255)),
        ("PURPLE", (240, 90, 150)),
    ]

    def __init__(self):
        self.lock = threading.Lock()
        self.filter_index = 0
        self.color_index = 0
        self.jpeg_quality = JPEG_QUALITY
        self.target_fps = FRAME_FPS
        self.show_stats = True

    def snapshot(self):
        with self.lock:
            return (
                self.FILTERS[self.filter_index],
                self.COLORS[self.color_index][1] if self.color_index else None,
                self.jpeg_quality,
                self.target_fps,
            )


settings = CallSettings()

capture_meter = RateMeter()
send_meter = RateMeter()
recv_meter = RateMeter()
audio_tx_meter = RateMeter()
audio_rx_meter = RateMeter()

ui_info = {
    "key_fingerprint": "--------",
    "last_cipher_hex": "",
    "mic_level": 0.0,
    "mic_name": "",
    "mic_error": "",
    "camera_error": "",
    "local_res": (FRAME_WIDTH, FRAME_HEIGHT),
    "remote_res": None,
    "last_recv": 0.0,
    "last_audio": 0.0,
    "events": collections.deque(maxlen=8),
}


def ui_event(msg):
    """Short status message shown as a toast in the GUI and printed."""
    print(f"[STATUS] {msg}")
    ui_info["events"].append(msg)


# ============================================================
# OUTGOING VIDEO FILTERS
# The filter runs BEFORE encryption, so the peer sees the
# filtered picture and the stream stays end-to-end encrypted.
# ============================================================

_effect_cache = {}

_SEPIA = np.array(
    [[0.131, 0.534, 0.272],
     [0.168, 0.686, 0.349],
     [0.189, 0.769, 0.393]],
    dtype=np.float32
)


def _effect_cached(key, build):
    value = _effect_cache.get(key)
    if value is None:
        if len(_effect_cache) > 16:
            _effect_cache.clear()
        value = _effect_cache[key] = build()
    return value


def apply_video_effects(frame):

    name, tint, _, _ = settings.snapshot()
    out = frame

    if name == "GRAYSCALE":
        out = cv2.cvtColor(cv2.cvtColor(out, cv2.COLOR_BGR2GRAY),
                           cv2.COLOR_GRAY2BGR)

    elif name == "SEPIA":
        out = cv2.transform(out, _SEPIA)

    elif name == "COOL":
        out = cv2.add(out, (30, 0, -15, 0))

    elif name == "WARM":
        out = cv2.add(out, (-20, 0, 30, 0))

    elif name == "CARTOON":
        gray = cv2.medianBlur(cv2.cvtColor(out, cv2.COLOR_BGR2GRAY), 5)
        edges = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_MEAN_C,
                                      cv2.THRESH_BINARY, 9, 7)
        color = cv2.bilateralFilter(out, 7, 60, 60)
        out = cv2.bitwise_and(color, color, mask=edges)

    elif name == "SKETCH":
        gray = cv2.cvtColor(out, cv2.COLOR_BGR2GRAY)
        blur = cv2.GaussianBlur(255 - gray, (21, 21), 0)
        sketch = cv2.divide(gray, 255 - blur, scale=256)
        out = cv2.cvtColor(sketch, cv2.COLOR_GRAY2BGR)

    elif name == "BLUR":
        out = cv2.GaussianBlur(out, (21, 21), 0)

    elif name == "NEGATIVE":
        out = cv2.bitwise_not(out)

    elif name == "VIGNETTE":
        h, w = out.shape[:2]

        def build_vignette():
            kx = cv2.getGaussianKernel(w, w * 0.45)
            ky = cv2.getGaussianKernel(h, h * 0.45)
            mask = ky @ kx.T
            mask = (mask / mask.max()).astype(np.float32)
            return cv2.merge([mask, mask, mask])

        out = cv2.multiply(out, _effect_cached(("vignette", w, h), build_vignette),
                           dtype=cv2.CV_8U)

    if tint is not None:
        layer = _effect_cached(("tint", out.shape, tint),
                               lambda: np.full(out.shape, tint, np.uint8))
        out = cv2.addWeighted(out, 0.78, layer, 0.22, 0)

    return out


# ============================================================
# AUDIO QUEUES + MICROPHONE MUTE
# ============================================================

audio_send_queue = queue.Queue(maxsize=20)
audio_play_queue = queue.Queue(maxsize=100)

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
    print("[MIC] Microphone " + ("MUTED" if state else "UNMUTED"))


# ============================================================
# QKMS KEY LOADER
# ============================================================

def get_qkms_key(key_id):
    url = f"{QKMS_API_URL}/etsi/v1/keys/{int(key_id)}"
    print()
    print(f"[QKMS] Requesting Key ID {key_id} from QKMS API: {url}")

    record = None
    try:


        response = requests.get(url, timeout=QKMS_API_TIMEOUT)
        response.raise_for_status()

        data = response.json()

        if not isinstance(data, dict) or "key" not in data:
            raise RuntimeError("Invalid QKMS API response")

        record = data["key"]

        if record is None:
            raise RuntimeError(
                f"QKMS API returned no key for Key ID {key_id}"
            )

        print("[QKMS] API response received successfully")

    except requests.RequestException as exc:
        raise RuntimeError(
            f"QKMS API unavailable. Start the QKMS server first. "
            f"Details: {exc}"
        ) from exc

    if record is None:
        raise RuntimeError(f"QKMS Key {key_id} not found")

    # --------------------------------------------------------
    # Dictionary record
    # --------------------------------------------------------
    if isinstance(record, dict):

        record_key_id = record.get("key_id", record.get("id", key_id))
        protocol = record.get("protocol", "BB84")
        key_length = int(record.get("key_length", record.get("length", 256)))
        status = record.get("status", "ACTIVE")
        binary_key = record.get("key", record.get("binary_key", record.get("value")))

    # --------------------------------------------------------
    # Existing QKMS database record (tab separated)
    # --------------------------------------------------------
    else:

        fields = str(record).strip().split("\t")

        if len(fields) < 4:
            raise RuntimeError("Invalid local QKMS record")

        record_key_id = fields[0]
        protocol = fields[1]
        key_length = int(fields[2])
        status = fields[3]
        binary_key = fields[-1]

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------
    if str(record_key_id) != str(key_id):
        raise RuntimeError("QKMS key ID mismatch")

    if str(protocol).upper() != "BB84":
        raise RuntimeError(f"Expected BB84, got {protocol}")

    if key_length != 256:
        raise RuntimeError(f"Expected 256-bit key, got {key_length}")

    if str(status).upper() != "ACTIVE":
        raise RuntimeError(f"Key {key_id} is not ACTIVE")

    # --------------------------------------------------------
    # Convert to 32 bytes
    # --------------------------------------------------------
    if isinstance(binary_key, bytes):
        key = binary_key
    else:
        binary_key = str(binary_key).strip()

        if len(binary_key) == 256 and set(binary_key) <= {"0", "1"}:
            key = int(binary_key, 2).to_bytes(32, "big")
        elif len(binary_key) == 64:
            key = bytes.fromhex(binary_key)
        else:
            raise RuntimeError("Invalid 256-bit BB84 key")

    if len(key) != 32:
        raise RuntimeError("QKMS key is not 32 bytes")

    digest = hashlib.sha256(key).hexdigest()

    print("[QKMS] Key ID      :", key_id)
    print("[QKMS] Protocol    :", protocol)
    print("[QKMS] Length      : 256 bits")
    print("[QKMS] Status      :", status)
    print("[QKMS] Key SHA-256 :", digest)
    print("[QKMS] Raw key     : LOCAL ONLY")

    ui_info["key_fingerprint"] = digest[:16].upper()

    return key


# ============================================================
# TCP FRAMING
#
# 4 bytes = JSON header length
# 4 bytes = payload length
# N bytes = JSON header
# M bytes = ciphertext
# ============================================================

def send_packet(sock, header, payload=b""):

    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")

    if len(header_bytes) > MAX_HEADER_SIZE:
        raise ValueError("Header too large")

    if len(payload) > MAX_PACKET_SIZE:
        raise ValueError("Payload too large")

    # one syscall per packet
    sock.sendall(b"".join((
        struct.pack("!II", len(header_bytes), len(payload)),
        header_bytes,
        payload
    )))


def recv_exact(sock, size):

    data = bytearray(size)
    view = memoryview(data)
    got = 0

    while got < size:
        n = sock.recv_into(view[got:], size - got)
        if n == 0:
            raise ConnectionError("Connection closed by peer")
        got += n

    return bytes(data)


def recv_packet(sock):

    header_length, payload_length = struct.unpack("!II", recv_exact(sock, 8))

    if header_length == 0 or header_length > MAX_HEADER_SIZE:
        raise ValueError(f"Invalid header length: {header_length}")

    if payload_length > MAX_PACKET_SIZE:
        raise ValueError(f"Invalid payload length: {payload_length}")

    header = json.loads(recv_exact(sock, header_length).decode("utf-8"))
    payload = recv_exact(sock, payload_length)

    return header, payload


# ============================================================
# ENCRYPTED MEDIA PACKETS (same wire format as before)
# ============================================================

def make_aad(prefix, media, sequence, key_id, session_id):

    return (
        f"{prefix}"
        f"|session={session_id}"
        f"|key={key_id}"
        f"|media={media}"
        f"|sequence={sequence}"
    ).encode("utf-8")


def seal_media(aes, kind, prefix, media, sequence, plaintext, key_id, session_id):
    """Encrypt one media payload and build its header."""

    nonce = os.urandom(NONCE_SIZE)
    aad = make_aad(prefix, media, sequence, key_id, session_id)
    ciphertext = aes.encrypt(nonce, plaintext, aad)

    header = {
        "type": kind,
        "version": PROTOCOL_VERSION,
        "key_id": key_id,
        "session_id": session_id,
        "sequence": sequence,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "aad": base64.b64encode(aad).decode("ascii"),
        "plaintext_size": len(plaintext),
        "ciphertext_size": len(ciphertext),
    }

    return header, ciphertext


def open_media(aes, header, ciphertext, kind, prefix, media,
               key_id, session_id, last_sequence):
    """Validate + decrypt one media packet. Returns (plaintext, sequence).

    The AAD is rebuilt locally from OUR key id, session id and the packet
    sequence instead of trusting the AAD field sent by the peer. A replayed
    or re-numbered packet therefore fails authentication."""

    if header.get("type") != kind:
        raise ValueError(f"Invalid {media} packet")

    if int(header.get("version", 0)) != PROTOCOL_VERSION:
        raise ValueError(f"Unsupported {media} version")

    if int(header.get("key_id", -1)) != int(key_id):
        raise ValueError(f"Unexpected {media} key ID")

    if header.get("session_id") != session_id:
        raise ValueError(f"Unexpected {media} session ID")

    sequence = int(header["sequence"])

    if sequence <= last_sequence:
        raise ValueError(f"Replay/out-of-order {media} packet")

    nonce = base64.b64decode(header["nonce"], validate=True)

    if len(nonce) != NONCE_SIZE:
        raise ValueError(f"Invalid {media} nonce")

    if len(ciphertext) != int(header["ciphertext_size"]):
        raise ValueError(f"{media} ciphertext size mismatch")

    aad = make_aad(prefix, media, sequence, key_id, session_id)

    plaintext = aes.decrypt(nonce, ciphertext, aad)

    if len(plaintext) != int(header["plaintext_size"]):
        raise ValueError(f"{media} plaintext size mismatch")

    return plaintext, sequence


# ============================================================
# CONNECTION
# ============================================================

def tune_socket(sock):
    """Low-latency media socket: no Nagle delay, bigger buffers."""

    for level, opt, val in (
        (socket.IPPROTO_TCP, socket.TCP_NODELAY, 1),
        (socket.SOL_SOCKET, socket.SO_SNDBUF, 1 << 20),
        (socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20),
    ):
        try:
            sock.setsockopt(level, opt, val)
        except OSError:
            pass

    return sock


def connect_retry(host, port, label, should_continue=None):

    attempt = 0

    while is_running() and (should_continue is None or should_continue()):

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            tune_socket(sock)
            sock.settimeout(5)
            sock.connect((host, port))
            sock.settimeout(None)
            print(f"[{label}] Connected to {host}:{port}")
            return sock

        except OSError as exc:
            sock.close()
            if attempt % 5 == 0:
                print(f"[{label}] {PEER_NAME} not reachable at {host}:{port} "
                      f"({exc}). Retrying...")
            attempt += 1
            stop_event.wait(2)

    return None


def create_server(port, label):

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LOCAL_IP, port))
    server.listen(5)
    server.settimeout(1)

    print(f"[{label}] Listening on {LOCAL_IP}:{port}")

    return server


def accept_loop(server, label, handle):
    """Accept connections until stop; one handler call per connection."""

    try:
        while is_running():
            try:
                conn, address = server.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            conn.settimeout(None)
            tune_socket(conn)

            print(f"[{label}] Connection from {address[0]}:{address[1]}")

            with conn:
                try:
                    handle(conn)
                except Exception as exc:
                    if is_running():
                        print(f"[{label}] {exc}")
    finally:
        server.close()
        print(f"[{label}] Stopped")


# ============================================================
# CAMERA CAPTURE (own thread)
#
# Capture is decoupled from sending: the preview stays live while
# the network connects / reconnects, and a slow network never
# stalls the camera.
# ============================================================

def open_camera():

    if isinstance(CAMERA_DEVICE, str) and CAMERA_DEVICE.startswith("/dev/"):
        camera = cv2.VideoCapture(CAMERA_DEVICE, cv2.CAP_V4L2)
    else:
        camera = cv2.VideoCapture(CAMERA_DEVICE)

    if not camera.isOpened():
        raise RuntimeError(f"Cannot open camera {CAMERA_DEVICE}")

    camera.set(cv2.CAP_PROP_FOURCC, cv2.VideoWriter_fourcc(*"MJPG"))
    camera.set(cv2.CAP_PROP_FRAME_WIDTH, FRAME_WIDTH)
    camera.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)
    camera.set(cv2.CAP_PROP_FPS, FRAME_FPS)
    camera.set(cv2.CAP_PROP_BUFFERSIZE, 1)   # newest frame only

    print("[VIDEO] Camera active:", CAMERA_DEVICE)

    return camera


def camera_capture():

    global local_frame, local_frame_id

    camera = None

    try:
        while is_running():

            if camera is None:
                try:
                    camera = open_camera()
                    ui_info["camera_error"] = ""
                except Exception as exc:
                    ui_info["camera_error"] = str(exc)
                    print("[VIDEO]", exc, "- retrying in 3 s")
                    stop_event.wait(3)
                    continue

            ok, frame = camera.read()

            if not ok or frame is None:
                stop_event.wait(0.01)
                continue

            capture_meter.tick()

            frame = apply_video_effects(frame)

            with local_frame_cond:
                local_frame = frame
                local_frame_id += 1
                local_frame_cond.notify_all()

            ui_info["local_res"] = (frame.shape[1], frame.shape[0])

    finally:
        if camera is not None:
            camera.release()
        with local_frame_cond:
            local_frame_cond.notify_all()
        print("[VIDEO] Camera stopped")


def next_frame_to_send(last_id, last_sent_time):
    """Wait for a new camera frame, honouring the live FPS limit.
    Returns (frame, frame_id, send_time, jpeg_quality) or None on stop."""

    while is_running():

        _, _, quality, target_fps = settings.snapshot()

        wait = (1.0 / max(1, target_fps)) - (time.time() - last_sent_time)
        if wait > 0.002:
            stop_event.wait(wait)

        with local_frame_cond:
            if local_frame_id == last_id:
                local_frame_cond.wait(0.2)
            if local_frame_id == last_id or local_frame is None:
                continue
            return local_frame, local_frame_id, time.time(), quality

    return None


def stream_video(sock, aes, key_id, session_id, still_valid=None):
    """Encode + encrypt + send camera frames until the socket breaks,
    the call ends, or still_valid() returns False (new session)."""

    sequence = 0
    last_id = 0
    last_sent = 0.0

    while is_running():

        if still_valid is not None and not still_valid():
            return

        item = next_frame_to_send(last_id, last_sent)

        if item is None:
            return

        frame, last_id, last_sent, quality = item

        ok, encoded = cv2.imencode(".jpg", frame,
                                   [cv2.IMWRITE_JPEG_QUALITY, quality])
        if not ok:
            continue

        header, ciphertext = seal_media(
            aes, "SECURE_VIDEO", VIDEO_AAD_PREFIX, "video", sequence,
            encoded.tobytes(), key_id, session_id
        )

        send_packet(sock, header, ciphertext)

        sequence += 1
        send_meter.tick(len(ciphertext))
        ui_info["last_cipher_hex"] = ciphertext[:24].hex()


def clear_remote(reason):
    """Peer stopped sending: drop the frozen picture and say why."""

    global remote_frame

    with remote_frame_lock:
        remote_frame = None

    ui_info["remote_res"] = None
    ui_info["last_recv"] = 0.0

    if is_running():
        ui_event(reason)


def receive_video(conn, aes, key_id, session_id):
    """Decrypt + decode peer video from one connection."""

    global remote_frame

    last_sequence = -1
    first = True

    while is_running():

        header, ciphertext = recv_packet(conn)

        plaintext, last_sequence = open_media(
            aes, header, ciphertext, "SECURE_VIDEO", VIDEO_AAD_PREFIX,
            "video", key_id, session_id, last_sequence
        )

        frame = cv2.imdecode(np.frombuffer(plaintext, dtype=np.uint8),
                             cv2.IMREAD_COLOR)

        if frame is None:
            raise ValueError("JPEG decode failed")

        with remote_frame_lock:
            remote_frame = frame

        recv_meter.tick(len(ciphertext))
        ui_info["remote_res"] = (frame.shape[1], frame.shape[0])
        ui_info["last_recv"] = time.time()

        if first:
            first = False
            ui_event(f"Receiving {PEER_NAME}'s encrypted video")


# ============================================================
# MICROPHONE
# ============================================================

_gate_state = {"gain": 1.0, "hold": 0}


def process_microphone(indata):

    audio = indata[:, 0].astype(np.float32, copy=True)

    if MIC_GAIN != 1.0:
        audio *= float(MIC_GAIN)

    rms = float(np.sqrt(np.mean(audio * audio))) if audio.size else 0.0

    # open on speech, stay open for a short hold, then fade down
    if rms >= NOISE_GATE_THRESHOLD:
        _gate_state["hold"] = NOISE_GATE_HOLD_BLOCKS
        target = 1.0
    elif _gate_state["hold"] > 0:
        _gate_state["hold"] -= 1
        target = 1.0
    else:
        target = float(NOISE_GATE_ATTENUATION)

    g0 = _gate_state["gain"]

    # fast attack, gentle release; ramp across the block (no clicks)
    g1 = target if target > g0 else g0 + (target - g0) * 0.35

    audio *= np.linspace(g0, g1, audio.size, dtype=np.float32)
    _gate_state["gain"] = g1

    np.clip(audio, -32768, 32767, out=audio)

    ui_info["mic_level"] = float(min(1.0, rms / 4000.0))

    return audio.astype(np.int16).tobytes()


def find_microphone():
    """Preferred mic by name, otherwise the system default input."""

    devices = sd.query_devices()

    for index, device in enumerate(devices):
        if device.get("max_input_channels", 0) > 0 and \
                PREFERRED_MIC_NAME.upper() in str(device.get("name", "")).upper():
            print(f"[AUDIO] Microphone: [{index}] {device['name']}")
            ui_info["mic_name"] = str(device["name"])
            return index

    try:
        default_in = sd.default.device[0]
    except Exception:
        default_in = None

    if default_in is not None and default_in >= 0:
        name = str(devices[default_in].get("name", "default"))
        print(f"[AUDIO] {PREFERRED_MIC_NAME} not found - using default "
              f"input [{default_in}] {name}")
        ui_info["mic_name"] = name
        return default_in

    for index, device in enumerate(devices):
        if device.get("max_input_channels", 0) > 0:
            print(f"[AUDIO] Using first input [{index}] {device['name']}")
            ui_info["mic_name"] = str(device["name"])
            return index

    raise RuntimeError("No microphone found")


def mic_callback(indata, frames, time_info, status):

    if status:
        print("[AUDIO MIC]", status)

    if is_microphone_muted():
        ui_info["mic_level"] = 0.0
        return

    try:
        data = process_microphone(indata)

        if audio_send_queue.full():
            try:
                audio_send_queue.get_nowait()
            except queue.Empty:
                pass

        audio_send_queue.put_nowait(data)

    except Exception as exc:
        print("[AUDIO MIC] Error:", exc)


def stream_audio(sock, aes, key_id, session_id, still_valid=None):
    """Encrypt + send microphone blocks until the socket breaks."""

    sequence = 0

    while is_running():

        if still_valid is not None and not still_valid():
            return

        try:
            pcm = audio_send_queue.get(timeout=0.5)
        except queue.Empty:
            continue

        header, ciphertext = seal_media(
            aes, "SECURE_AUDIO", AUDIO_AAD_PREFIX, "audio", sequence,
            pcm, key_id, session_id
        )

        send_packet(sock, header, ciphertext)

        sequence += 1
        audio_tx_meter.tick(len(ciphertext))


def receive_audio(conn, aes, key_id, session_id):
    """Decrypt peer audio from one connection into the play queue."""

    last_sequence = -1
    first = True

    while is_running():

        header, ciphertext = recv_packet(conn)

        plaintext, last_sequence = open_media(
            aes, header, ciphertext, "SECURE_AUDIO", AUDIO_AAD_PREFIX,
            "audio", key_id, session_id, last_sequence
        )

        if audio_play_queue.full():
            try:
                audio_play_queue.get_nowait()
            except queue.Empty:
                pass

        audio_play_queue.put_nowait(plaintext)

        audio_rx_meter.tick(len(ciphertext))
        ui_info["last_audio"] = time.time()

        if first:
            first = False
            ui_event(f"Receiving {PEER_NAME}'s encrypted audio")


# ============================================================
# AUDIO PLAYBACK (jitter buffer)
# ============================================================

def audio_playback():

    buffer = bytearray()
    state = {"primed": False}

    block_bytes = AUDIO_BLOCKSIZE * 2
    prebuffer = PLAYBACK_PREBUFFER_BLOCKS * block_bytes
    max_buffer = PLAYBACK_MAX_BLOCKS * block_bytes

    def callback(outdata, frames, time_info, status):

        if status:
            print("[AUDIO PLAY]", status)

        outdata.fill(0)

        while True:
            try:
                buffer.extend(audio_play_queue.get_nowait())
            except queue.Empty:
                break

        # latency cap: if we fell behind, skip to near-live audio
        if len(buffer) > max_buffer:
            del buffer[:len(buffer) - prebuffer]

        # small jitter buffer so network hiccups do not crackle
        if not state["primed"]:
            if len(buffer) < prebuffer:
                return
            state["primed"] = True

        need = frames * 2
        count = min(need, len(buffer)) & ~1

        if count > 0:
            outdata[:count // 2, 0] = np.frombuffer(bytes(buffer[:count]),
                                                    dtype=np.int16)
            del buffer[:count]

        if count < need:
            state["primed"] = False

    try:
        with sd.OutputStream(device=AUDIO_OUTPUT_DEVICE, samplerate=AUDIO_RATE,
                             channels=1, dtype="int16",
                             blocksize=AUDIO_BLOCKSIZE, callback=callback):

            print("[AUDIO PLAY] Speaker active")

            while is_running():
                stop_event.wait(0.2)

    except Exception as exc:
        print("[AUDIO PLAY] Error:", exc)
        ui_event(f"Speaker error: {exc}")

    print("[AUDIO PLAY] Stopped")


def open_microphone_stream():
    """Open the mic stream (or return None if no mic is usable)."""

    try:
        microphone = find_microphone()
        stream = sd.InputStream(device=microphone, samplerate=AUDIO_RATE,
                                channels=AUDIO_CHANNELS, dtype=AUDIO_DTYPE,
                                blocksize=AUDIO_BLOCKSIZE, callback=mic_callback)
        stream.start()
        print("[AUDIO SEND] Microphone active")
        return stream

    except Exception as exc:
        ui_info["mic_error"] = str(exc)
        print("[AUDIO SEND] Microphone unavailable:", exc)
        ui_event(f"Microphone unavailable: {exc}")
        return None


# ============================================================
# SESSION HANDSHAKE (Alice -> Bob, on the video connection)
# ============================================================

def handshake(sock):

    hello = {
        "type": "SESSION_HELLO",
        "version": PROTOCOL_VERSION,
        "key_id": KEY_ID,
        "session_id": SESSION_ID,
        "protocol": "BB84",
        "key_length": 256,
    }

    print()
    print("[SESSION] Sending SESSION_HELLO")
    print("[SESSION] Key ID:", KEY_ID)
    print("[SESSION] Session ID:", SESSION_ID)

    sock.settimeout(HANDSHAKE_TIMEOUT)

    send_packet(sock, hello, b"")

    ack, _ = recv_packet(sock)

    sock.settimeout(None)

    if ack.get("type") != "SESSION_ACK":
        raise RuntimeError("Invalid SESSION_ACK type")

    if ack.get("status") != "READY":
        raise RuntimeError(
            f"{PEER_NAME} rejected the session: "
            f"{ack.get('reason', ack.get('status'))}"
        )

    if int(ack.get("key_id", -1)) != KEY_ID:
        raise RuntimeError("SESSION_ACK Key ID mismatch")

    if ack.get("session_id") != SESSION_ID:
        raise RuntimeError("SESSION_ACK session mismatch")

    print()
    print(f"[SESSION] {PEER_NAME} accepted Key ID:", KEY_ID)
    print("[SESSION] Session established")
    print("[SESSION] RAW KEY SENT: NO")
    print()

    SESSION_READY.set()
    ui_event(f"Secure session with {PEER_NAME} established · key #{KEY_ID}")


# ============================================================
# VIDEO SENDER (handshake, then frames; reconnects on loss)
# ============================================================

def video_sender(key):

    aes = AESGCM(key)

    while is_running():

        sock = connect_retry(PEER_IP, SEND_VIDEO_PORT, "SECURE VIDEO SEND")

        if sock is None:
            break

        try:
            with sock:
                handshake(sock)
                stream_video(sock, aes, KEY_ID, SESSION_ID)

        except Exception as exc:
            if is_running():
                print("[SECURE VIDEO SEND]", exc)
                ui_event(f"Video link to {PEER_NAME} lost · reconnecting")
                stop_event.wait(2)

    print("[SECURE VIDEO SEND] Stopped")


# ============================================================
# VIDEO RECEIVER
# ============================================================

def video_receiver(key):

    aes = AESGCM(key)

    server = create_server(RECEIVE_VIDEO_PORT, "SECURE VIDEO RECV")

    def handle(conn):
        try:
            receive_video(conn, aes, KEY_ID, SESSION_ID)
        finally:
            clear_remote(f"{PEER_NAME} left the call")

    accept_loop(server, "SECURE VIDEO RECV", handle)


# ============================================================
# AUDIO SENDER
# ============================================================

def audio_sender(key):

    aes = AESGCM(key)

    stream = open_microphone_stream()

    if stream is None:
        return

    try:
        while not SESSION_READY.wait(0.2):
            if not is_running():
                return

        clear_audio_queue()     # drop audio captured before the call

        while is_running():

            sock = connect_retry(PEER_IP, SEND_AUDIO_PORT, "SECURE AUDIO SEND")

            if sock is None:
                break

            try:
                with sock:
                    stream_audio(sock, aes, KEY_ID, SESSION_ID)

            except Exception as exc:
                if is_running():
                    print("[SECURE AUDIO SEND]", exc)
                    stop_event.wait(1)

    finally:
        stream.stop()
        stream.close()
        print("[SECURE AUDIO SEND] Stopped")


# ============================================================
# AUDIO RECEIVER
# ============================================================

def audio_receiver(key):

    aes = AESGCM(key)

    server = create_server(RECEIVE_AUDIO_PORT, "SECURE AUDIO RECV")

    accept_loop(
        server, "SECURE AUDIO RECV",
        lambda conn: receive_audio(conn, aes, KEY_ID, SESSION_ID)
    )
# ============================================================
# GUI
#
# Resolution-independent call screen.
#
# * Everything is drawn at the window's REAL pixel size, so nothing
#   is stretched or blurred when the window is resized / maximised.
# * Text uses a real TrueType font through Pillow (Inter, Noto,
#   Ubuntu, DejaVu ... whatever is installed), not Hershey fonts.
# * Shapes are anti-aliased analytically (rounded rects, circles) or
#   by 4x supersampling (icons, spinner), and cached, so a frame is
#   mostly cheap blits.
# * The UI loop is capped at UI_FPS so it no longer burns a full core.
#
#   Mouse : click any button, drag the quality slider
#   M mic | F filter | C colour | U quality | S stats
#   L security panel | P side panel | Q / ESC end call
# ============================================================

try:
    from PIL import Image, ImageDraw, ImageFont
    HAVE_PIL = True
except ImportError:
    HAVE_PIL = False
    print("[GUI] Pillow not installed - falling back to OpenCV fonts "
          "(pip install pillow for crisp text)")



BASE_W = 1280
BASE_H = 720
MAX_RENDER_W = 2560
UI_FPS = 60
SS = 4

AA = cv2.LINE_AA


def _hex(h):
    h = h.lstrip("#")
    return (int(h[4:6], 16), int(h[2:4], 16), int(h[0:2], 16))


BG_TOP = _hex("#161a22")
BG_BOT = _hex("#0b0d12")
SURFACE = _hex("#1a1f28")
SURFACE_2 = _hex("#232a35")
SURFACE_3 = _hex("#2e3644")
BORDER = _hex("#2b333f")
BORDER_2 = _hex("#3b4452")
C_TEXT = _hex("#eef1f6")
C_TEXT_2 = _hex("#a3acba")
C_TEXT_3 = _hex("#6d7685")
C_GOOD = _hex("#36c97d")
C_WARN = _hex("#f2b441")
C_BAD = _hex("#f0555b")
C_DANGER = _hex("#e5484d")
C_DANGER_HI = _hex("#f36a6e")
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)
DEFAULT_ACCENT = _hex("#4f8cff")


# ------------------------------------------------------------
# small helpers
# ------------------------------------------------------------

def _clamp(v, lo, hi):
    return max(lo, min(hi, v))


def _lerp(a, b, t):
    return a + (b - a) * t


def _ease(t):
    t = _clamp(t, 0.0, 1.0)
    return 1.0 - (1.0 - t) ** 3


def _mix(c1, c2, t):
    t = _clamp(t, 0.0, 1.0)
    return tuple(int(round(_lerp(a, b, t))) for a, b in zip(c1, c2))


def _fmt_time(sec):
    sec = max(0, int(sec))
    if sec >= 3600:
        return f"{sec // 3600}:{(sec % 3600) // 60:02d}:{sec % 60:02d}"
    return f"{sec // 60:02d}:{sec % 60:02d}"


def _fmt_kbps(v):
    if v >= 1000:
        return f"{v / 1000:.2f} Mbps"
    return f"{v:.0f} kbps"


def _fps_color(v, target):
    if target <= 0:
        return C_TEXT
    ratio = v / target
    if ratio >= 0.85:
        return C_GOOD
    if ratio >= 0.6:
        return C_WARN
    return C_BAD


class _LRU(collections.OrderedDict):

    def __init__(self, cap):
        super().__init__()
        self.cap = cap

    def hit(self, key):
        v = self.get(key)
        if v is not None:
            self.move_to_end(key)
        return v

    def put(self, key, value):
        self[key] = value
        if len(self) > self.cap:
            self.popitem(last=False)
        return value


_TEXT_CACHE = _LRU(4000)
_SHAPE_CACHE = _LRU(1200)


# ------------------------------------------------------------
# fonts
# ------------------------------------------------------------

_FONT_CANDIDATES = {
    "regular": [
        "Inter-Regular.ttf", "Inter-Regular.otf", "NotoSans-Regular.ttf",
        "Ubuntu-R.ttf", "Roboto-Regular.ttf", "OpenSans-Regular.ttf",
        "Cantarell-Regular.otf", "DejaVuSans.ttf",
        "LiberationSans-Regular.ttf", "FreeSans.ttf", "segoeui.ttf",
        "Arial.ttf", "arial.ttf",
    ],
    "medium": [
        "Inter-Medium.ttf", "Inter-Medium.otf", "NotoSans-Medium.ttf",
        "Ubuntu-M.ttf", "Roboto-Medium.ttf", "OpenSans-Medium.ttf",
        "seguisb.ttf",
    ],
    "semibold": [
        "Inter-SemiBold.ttf", "Inter-SemiBold.otf", "NotoSans-SemiBold.ttf",
        "Ubuntu-M.ttf", "Roboto-Medium.ttf", "OpenSans-SemiBold.ttf",
        "seguisb.ttf",
    ],
    "bold": [
        "Inter-Bold.ttf", "Inter-Bold.otf", "NotoSans-Bold.ttf",
        "Ubuntu-B.ttf", "Roboto-Bold.ttf", "OpenSans-Bold.ttf",
        "DejaVuSans-Bold.ttf", "LiberationSans-Bold.ttf",
        "FreeSansBold.ttf", "segoeuib.ttf", "arialbd.ttf",
    ],
    "mono": [
        "JetBrainsMono-Regular.ttf", "NotoSansMono-Regular.ttf",
        "UbuntuMono-R.ttf", "DejaVuSansMono.ttf",
        "LiberationMono-Regular.ttf", "FreeMono.ttf", "consola.ttf",
    ],
}

_FONT_CHAINS = {
    "regular": ["regular"],
    "medium": ["medium", "regular"],
    "semibold": ["semibold", "bold", "medium", "regular"],
    "bold": ["bold", "semibold", "regular"],
    "mono": ["mono", "regular"],
}

_FONT_DIRS = [
    "/usr/share/fonts", "/usr/local/share/fonts",
    "~/.local/share/fonts", "~/.fonts",
    "/Library/Fonts", "/System/Library/Fonts", "C:/Windows/Fonts",
]

_font_index = None
_font_paths = {}
_fonts = {}


def _font_path(weight):

    global _font_index

    if weight in _font_paths:
        return _font_paths[weight]

    if _font_index is None:

        _font_index = {}

        for d in _FONT_DIRS:

            d = os.path.expanduser(d)

            if not os.path.isdir(d):
                continue

            for root, _, files in os.walk(d):
                for f in files:
                    _font_index.setdefault(f.lower(), os.path.join(root, f))

    path = None

    for group in _FONT_CHAINS[weight]:
        for name in _FONT_CANDIDATES[group]:
            path = _font_index.get(name.lower())
            if path:
                break
        if path:
            break

    _font_paths[weight] = path

    return path


def _font(weight, px):

    key = (weight, px)
    f = _fonts.get(key)

    if f is None:

        path = _font_path(weight)

        try:
            f = (ImageFont.truetype(path, px) if path
                 else ImageFont.load_default(size=px))
        except Exception:
            f = ImageFont.load_default()

        _fonts[key] = f

    return f


# ------------------------------------------------------------
# low level blending
# ------------------------------------------------------------

def _blend_mask(cv, mask, x, y, color, alpha=1.0):
    """Paint `color` through a float coverage mask (0..1) at x, y."""

    if alpha <= 0.003:
        return

    mh, mw = mask.shape[:2]
    H, W = cv.shape[:2]

    x = int(round(x))
    y = int(round(y))

    x1, y1 = max(x, 0), max(y, 0)
    x2, y2 = min(x + mw, W), min(y + mh, H)

    if x2 <= x1 or y2 <= y1:
        return

    m = mask[y1 - y:y2 - y, x1 - x:x2 - x]

    if alpha < 0.999:
        m = m * alpha

    roi = cv[y1:y2, x1:x2]
    r = roi.astype(np.float32)
    d = np.asarray(color, np.float32) - r
    d *= m[:, :, None]
    r += d
    r += 0.5
    roi[:] = r


def _fill(cv, x1, y1, x2, y2, color, alpha=1.0):
    """Axis-aligned rectangle, integer edges, optional alpha."""

    if alpha <= 0.003:
        return

    H, W = cv.shape[:2]

    x1, y1 = max(int(round(x1)), 0), max(int(round(y1)), 0)
    x2, y2 = min(int(round(x2)), W), min(int(round(y2)), H)

    if x2 <= x1 or y2 <= y1:
        return

    roi = cv[y1:y2, x1:x2]

    if alpha >= 0.999:
        roi[:] = color
        return

    roi[:] = cv2.addWeighted(
        roi, 1.0 - alpha, np.full_like(roi, color), alpha, 0
    )


def _corner_mask(r, t=0):
    """Anti-aliased quarter disc (t=0) or quarter ring of width t.
    Top-left orientation; the arc centre sits at (r, r)."""

    key = ("corner", r, t)
    m = _SHAPE_CACHE.hit(key)

    if m is None:

        ys, xs = np.mgrid[0:r, 0:r].astype(np.float32) + 0.5
        d = np.hypot(xs - r, ys - r)
        m = np.clip(r - d + 0.5, 0.0, 1.0)

        if t > 0:
            m = m - np.clip((r - t) - d + 0.5, 0.0, 1.0)

        m = _SHAPE_CACHE.put(key, m.astype(np.float32))

    return m


def _rrect_mask(w, h, r):
    """Full anti-aliased rounded-rect mask (used for shadows)."""

    key = ("rrect", w, h, r)
    m = _SHAPE_CACHE.hit(key)

    if m is None:

        ys, xs = np.mgrid[0:h, 0:w].astype(np.float32) + 0.5
        qx = np.abs(xs - w / 2.0) - (w / 2.0 - r)
        qy = np.abs(ys - h / 2.0) - (h / 2.0 - r)
        d = (np.hypot(np.maximum(qx, 0), np.maximum(qy, 0))
             + np.minimum(np.maximum(qx, qy), 0) - r)
        m = _SHAPE_CACHE.put(key, np.clip(0.5 - d, 0, 1).astype(np.float32))

    return m


def rrect(cv, x1, y1, x2, y2, r, color, alpha=1.0, stroke=0):
    """Rounded rectangle. Filled when stroke == 0, else an outline."""

    x1, y1 = int(round(x1)), int(round(y1))
    x2, y2 = int(round(x2)), int(round(y2))

    w, h = x2 - x1, y2 - y1

    if w <= 0 or h <= 0 or alpha <= 0.003:
        return

    r = int(round(_clamp(r, 0, min(w, h) / 2.0)))

    if stroke <= 0:

        _fill(cv, x1, y1 + r, x2, y2 - r, color, alpha)

        if r > 0:

            _fill(cv, x1 + r, y1, x2 - r, y1 + r, color, alpha)
            _fill(cv, x1 + r, y2 - r, x2 - r, y2, color, alpha)

            m = _corner_mask(r)

            _blend_mask(cv, m, x1, y1, color, alpha)
            _blend_mask(cv, m[:, ::-1], x2 - r, y1, color, alpha)
            _blend_mask(cv, m[::-1, :], x1, y2 - r, color, alpha)
            _blend_mask(cv, m[::-1, ::-1], x2 - r, y2 - r, color, alpha)

        return

    t = max(1, int(round(stroke)))
    r = max(r, t)

    _fill(cv, x1 + r, y1, x2 - r, y1 + t, color, alpha)
    _fill(cv, x1 + r, y2 - t, x2 - r, y2, color, alpha)
    _fill(cv, x1, y1 + r, x1 + t, y2 - r, color, alpha)
    _fill(cv, x2 - t, y1 + r, x2, y2 - r, color, alpha)

    m = _corner_mask(r, t)

    _blend_mask(cv, m, x1, y1, color, alpha)
    _blend_mask(cv, m[:, ::-1], x2 - r, y1, color, alpha)
    _blend_mask(cv, m[::-1, :], x1, y2 - r, color, alpha)
    _blend_mask(cv, m[::-1, ::-1], x2 - r, y2 - r, color, alpha)


def disc(cv, cx, cy, r, color, alpha=1.0, stroke=0):
    """Anti-aliased filled circle or ring (sub-pixel radius)."""

    if r <= 0:
        return

    rq = round(r * 4) / 4.0
    sq = round(stroke * 4) / 4.0
    key = ("disc", rq, sq)

    m = _SHAPE_CACHE.hit(key)

    if m is None:

        size = int(math.ceil(2 * rq + 2))
        c = size / 2.0
        ys, xs = np.mgrid[0:size, 0:size].astype(np.float32) + 0.5
        d = np.hypot(xs - c, ys - c)
        m = np.clip(rq - d + 0.5, 0, 1)

        if sq > 0:
            m = m - np.clip(rq - sq - d + 0.5, 0, 1)

        m = _SHAPE_CACHE.put(key, m.astype(np.float32))

    size = m.shape[0]

    _blend_mask(cv, m, cx - size / 2.0, cy - size / 2.0, color, alpha)


def shadow(cv, x1, y1, x2, y2, r, blur, alpha=0.45, dy=0):
    """Soft drop shadow behind a floating card."""

    w, h = int(x2 - x1), int(y2 - y1)
    blur = max(2, int(blur))

    key = ("shadow", w, h, int(r), blur)
    m = _SHAPE_CACHE.hit(key)

    if m is None:

        pad = blur * 2
        base = np.zeros((h + 2 * pad, w + 2 * pad), np.float32)
        base[pad:pad + h, pad:pad + w] = _rrect_mask(w, h, int(r))
        k = blur * 2 + 1
        m = _SHAPE_CACHE.put(key, cv2.GaussianBlur(base, (k, k), blur / 2.0))

    pad = blur * 2
    mh, mw = m.shape
    ox, oy = x1 - pad, y1 - pad + dy

    # the card itself hides the shadow's interior, so only blend the
    # visible border band (big win for large panels)
    r = int(r)
    ix1, ix2 = pad + r, pad + w - r
    iy1, iy2 = pad - dy + r, pad - dy + h - r

    if ix2 - ix1 < 4 or iy2 - iy1 < 4:
        _blend_mask(cv, m, ox, oy, BLACK, alpha)
        return

    iy1, iy2 = max(iy1, 0), min(iy2, mh)

    _blend_mask(cv, m[:iy1], ox, oy, BLACK, alpha)
    _blend_mask(cv, m[iy2:], ox, oy + iy2, BLACK, alpha)
    _blend_mask(cv, m[iy1:iy2, :ix1], ox, oy + iy1, BLACK, alpha)
    _blend_mask(cv, m[iy1:iy2, ix2:], ox + ix2, oy + iy1, BLACK, alpha)


def put_rounded(cv, img, x, y, r):
    """Copy an image onto the canvas with anti-aliased round corners."""

    h, w = img.shape[:2]
    H, W = cv.shape[:2]
    x, y = int(x), int(y)

    if x < 0 or y < 0 or x + w > W or y + h > H:

        x1, y1 = max(x, 0), max(y, 0)
        x2, y2 = min(x + w, W), min(y + h, H)

        if x2 > x1 and y2 > y1:
            cv[y1:y2, x1:x2] = img[y1 - y:y2 - y, x1 - x:x2 - x]

        return

    r = int(min(r, w // 2, h // 2))

    if r <= 0:
        cv[y:y + h, x:x + w] = img
        return

    m = _corner_mask(r)[:, :, None]

    corners = [
        (slice(y, y + r), slice(x, x + r), m),
        (slice(y, y + r), slice(x + w - r, x + w), m[:, ::-1]),
        (slice(y + h - r, y + h), slice(x, x + r), m[::-1]),
        (slice(y + h - r, y + h), slice(x + w - r, x + w), m[::-1, ::-1]),
    ]

    saved = [cv[a, b].astype(np.float32) for a, b, _ in corners]

    cv[y:y + h, x:x + w] = img

    for (a, b, mm), bg in zip(corners, saved):

        fg = cv[a, b].astype(np.float32)
        cv[a, b] = (fg * mm + bg * (1.0 - mm) + 0.5).astype(np.uint8)


# ------------------------------------------------------------
# text
# ------------------------------------------------------------

def _text_mask(s, px, weight):

    key = (s, px, weight)
    hit = _TEXT_CACHE.hit(key)

    if hit is not None:
        return hit

    if HAVE_PIL:

        f = _font(weight, px)

        try:
            asc, desc = f.getmetrics()
        except Exception:
            asc, desc = px, px // 4

        width = int(math.ceil(f.getlength(s))) if s else 0

        img = Image.new("L", (width + 2, asc + desc + 1), 0)

        if s:
            try:
                ImageDraw.Draw(img).text((1, asc), s, font=f, fill=255,
                                         anchor="ls")
            except Exception:
                ImageDraw.Draw(img).text((1, 0), s, font=f, fill=255)

        mask = np.asarray(img, dtype=np.float32) * (1.0 / 255.0)
        hit = (mask, asc, width)

    else:

        s2 = s.replace("\u2026", "...").replace("\u00b7", "|")
        scale = px / 30.0
        th = max(1, int(round(px / 14.0)))
        (tw, tht), base = cv2.getTextSize(s2, cv2.FONT_HERSHEY_SIMPLEX,
                                          scale, th)
        asc = tht + 1
        img = np.zeros((asc + base + 2, tw + 2), np.uint8)
        cv2.putText(img, s2, (1, asc), cv2.FONT_HERSHEY_SIMPLEX, scale,
                    255, th, AA)
        hit = (img.astype(np.float32) / 255.0, asc, tw)

    return _TEXT_CACHE.put(key, hit)


def text(cv, s, x, y, px, color, weight="regular", anchor="l", alpha=1.0):
    """Draw text vertically centred on y. anchor: l / c / r."""

    px = max(6, int(round(px)))
    mask, asc, w = _text_mask(s, px, weight)

    if anchor == "c":
        x -= w / 2.0
    elif anchor == "r":
        x -= w

    baseline = y + 0.36 * px

    _blend_mask(cv, mask, x - 1, baseline - asc, color, alpha)

    return w


def text_w(s, px, weight="regular"):
    return _text_mask(s, max(6, int(round(px))), weight)[2]


def ellipsize(s, px, weight, max_w):

    if text_w(s, px, weight) <= max_w:
        return s

    while s and text_w(s + "\u2026", px, weight) > max_w:
        s = s[:-1]

    return s + "\u2026"


def wrap(s, px, weight, max_w):

    lines, cur = [], ""

    for word in s.split():

        trial = (cur + " " + word).strip()

        if cur and text_w(trial, px, weight) > max_w:
            lines.append(cur)
            cur = word
        else:
            cur = trial

    if cur:
        lines.append(cur)

    return lines


# ------------------------------------------------------------
# icons (4x supersampled, cached per size)
# ------------------------------------------------------------

def _icon_mask(name, px):

    key = ("icon", name, px)
    hit = _SHAPE_CACHE.hit(key)

    if hit is not None:
        return hit

    S = px * SS
    m = np.zeros((S, S), np.uint8)
    c = S / 2.0
    k = c * 0.92
    T = max(SS, int(round(S * 0.095)))

    def p(fx, fy):
        return (int(round(c + fx * k)), int(round(c + fy * k)))

    def R(v):
        return max(1, int(round(v * k)))

    def line(a, b, v=255, t=None):
        cv2.line(m, p(*a), p(*b), v, t or T, AA)

    def round_box(x1, y1, x2, y2, rr, v=255):
        cv2.rectangle(m, p(x1 + rr, y1), p(x2 - rr, y2), v, -1, AA)
        cv2.rectangle(m, p(x1, y1 + rr), p(x2, y2 - rr), v, -1, AA)
        for cx, cy in ((x1 + rr, y1 + rr), (x2 - rr, y1 + rr),
                       (x1 + rr, y2 - rr), (x2 - rr, y2 - rr)):
            cv2.circle(m, p(cx, cy), R(rr), v, -1, AA)

    def star(cx, cy, r):
        q = r * 0.26
        pts = [(cx, cy - r), (cx + q, cy - q), (cx + r, cy),
               (cx + q, cy + q), (cx, cy + r), (cx - q, cy + q),
               (cx - r, cy), (cx - q, cy - q)]
        cv2.fillPoly(m, [np.array([p(*a) for a in pts], np.int32)], 255, AA)

    def mic():
        rr = 0.3
        cv2.ellipse(m, p(0, -0.88 + rr), (R(rr), R(rr)), 0, 180, 360,
                    255, T, AA)
        cv2.ellipse(m, p(0, 0.22 - rr), (R(rr), R(rr)), 0, 0, 180,
                    255, T, AA)
        line((-rr, -0.88 + rr), (-rr, 0.22 - rr))
        line((rr, -0.88 + rr), (rr, 0.22 - rr))
        cv2.ellipse(m, p(0, -0.08), (R(0.6), R(0.6)), 0, 0, 180,
                    255, T, AA)
        line((0, 0.52), (0, 0.86))
        line((-0.34, 0.86), (0.34, 0.86))

    if name == "mic":
        mic()

    elif name == "mic_off":
        mic()
        line((-0.82, -0.82), (0.82, 0.82), 0, T * 3)
        line((-0.82, -0.82), (0.82, 0.82))

    elif name == "filter":
        star(-0.18, 0.16, 0.78)
        star(0.6, -0.56, 0.34)

    elif name == "color":
        cv2.circle(m, p(0, 0), R(0.84), 255, T, AA)
        for fx, fy in ((-0.4, -0.12), (-0.08, -0.46), (0.34, -0.3),
                       (0.36, 0.16)):
            cv2.circle(m, p(fx, fy), R(0.14), 255, -1, AA)

    elif name == "quality":
        for fy, kx in ((-0.56, 0.36), (0.0, -0.38), (0.56, 0.12)):
            line((-0.86, fy), (0.86, fy))
            cv2.circle(m, p(kx, fy), R(0.32), 0, -1, AA)
            cv2.circle(m, p(kx, fy), R(0.22), 255, -1, AA)

    elif name == "stats":
        for i, hh in enumerate((0.55, 1.05, 0.78, 1.45)):
            x0 = -0.8 + i * 0.44
            round_box(x0, 0.78 - hh, x0 + 0.26, 0.78, 0.07)

    elif name == "shield":
        pts = [(0, -0.9), (0.74, -0.62), (0.74, -0.02)]
        for i in range(1, 9):
            tt = i / 8.0
            bx = (1 - tt) ** 2 * 0.74 + 2 * (1 - tt) * tt * 0.66 + tt * tt * 0
            by = ((1 - tt) ** 2 * -0.02 + 2 * (1 - tt) * tt * 0.58
                  + tt * tt * 0.92)
            pts.append((bx, by))
        full = pts + [(-x, y) for x, y in reversed(pts[1:-1])]
        cv2.polylines(m, [np.array([p(*a) for a in full], np.int32)],
                      True, 255, T, AA)
        line((-0.3, 0.02), (-0.06, 0.26))
        line((-0.06, 0.26), (0.34, -0.2))

    elif name == "lock":
        cv2.ellipse(m, p(0, -0.18), (R(0.38), R(0.42)), 0, 180, 360,
                    255, T, AA)
        line((-0.38, -0.18), (-0.38, 0.04))
        line((0.38, -0.18), (0.38, 0.04))
        round_box(-0.66, -0.02, 0.66, 0.88, 0.16)
        cv2.circle(m, p(0, 0.4), R(0.13), 0, -1, AA)

    elif name == "phone":
        cv2.ellipse(m, p(0, 0.42), (R(0.9), R(0.72)), 0, 196, 344,
                    255, int(T * 2.4), AA)
        line((-0.86, 0.22), (-0.66, 0.56), 255, int(T * 2.9))
        line((0.86, 0.22), (0.66, 0.56), 255, int(T * 2.9))

    elif name == "menu":
        for fy in (-0.52, 0.0, 0.52):
            line((-0.72, fy), (0.72, fy))

    elif name == "close":
        line((-0.6, -0.6), (0.6, 0.6))
        line((-0.6, 0.6), (0.6, -0.6))

    elif name == "slash":
        line((-0.7, 0.7), (0.7, -0.7))

    out = cv2.resize(m, (px, px), interpolation=cv2.INTER_AREA)

    return _SHAPE_CACHE.put(key, out.astype(np.float32) / 255.0)


def icon(cv, name, cx, cy, px, color, alpha=1.0):

    px = max(6, int(round(px)))

    _blend_mask(cv, _icon_mask(name, px), cx - px / 2.0, cy - px / 2.0,
                color, alpha)


def spinner(cv, cx, cy, radius, thick, angle, color, alpha=1.0):

    radius, thick = int(round(radius)), max(1, int(round(thick)))
    ang = int(angle // 6) * 6

    key = ("spin", radius, thick, ang)
    msk = _SHAPE_CACHE.hit(key)

    if msk is None:

        size = 2 * (radius + thick) + 4
        S = size * SS
        big = np.zeros((S, S), np.uint8)
        cv2.ellipse(big, (S // 2, S // 2), (radius * SS, radius * SS), 0,
                    ang, ang + 100, 255, thick * SS, AA)
        msk = _SHAPE_CACHE.put(key, cv2.resize(
            big, (size, size), interpolation=cv2.INTER_AREA
        ).astype(np.float32) / 255.0)

    size = msk.shape[0]

    _blend_mask(cv, msk, cx - size / 2.0, cy - size / 2.0, color, alpha)


# ------------------------------------------------------------
# the call screen
# ------------------------------------------------------------

class CallUI:

    TABS = [("filter", "Filters"), ("color", "Colour"),
            ("quality", "Quality"), ("secure", "Security")]

    DOCK = [
        ("mic", "Mic", "mic"),
        ("filter", "Filters", "filter"),
        ("color", "Colour", "color"),
        ("quality", "Quality", "quality"),
        ("stats", "Stats", "stats"),
        ("secure", "Security", "shield"),
        ("end", "End", "phone"),
    ]

    TIPS = {
        "mic": "Mute / unmute  \u00b7  M",
        "filter": "Video filters  \u00b7  F",
        "color": "Colour tint  \u00b7  C",
        "quality": "Quality & frame rate  \u00b7  U",
        "stats": "Stats overlay  \u00b7  S",
        "secure": "Encryption details  \u00b7  L",
        "end": "End call  \u00b7  Q",
    }

    def __init__(self):

        now = time.time()

        self._pending = None
        self._pending_n = 0
        self._apply_size(BASE_W, BASE_H)

        self.last_t = now
        self.dt = 1.0 / UI_FPS

        self.mx = -1
        self.my = -1
        self.inside = False

        self.hits = []
        self.hov = {}
        self.press = {}
        self.hover_t0 = {}
        self.tip = None
        self.toast = None

        self.panel_open = False
        self.panel_p = 0.0
        self.tab = "filter"
        self.tab_pos = 0.0
        self.drag = None
        self.slider_rect = (0, 1)

        self.modal = None
        self.modal_p = 0.0

        self.ending = False
        self.ending_t0 = 0.0
        self.final_duration = 0
        self.finished = False

        self.accent = [float(c) for c in DEFAULT_ACCENT]
        self.mic_lvl = 0.0
        self.call_started = None

        self.tile_cache = {}
        self.ticker_hex = ""
        self.ticker_t = 0.0

    # --------------------------------------------------------
    # size / scale
    # --------------------------------------------------------

    def _apply_size(self, w, h):

        self.W, self.H = int(w), int(h)
        self.s = _clamp(min(self.W / BASE_W, self.H / BASE_H), 0.6, 3.0)

        top = np.array(BG_TOP, np.float32)
        bot = np.array(BG_BOT, np.float32)

        t = np.linspace(0, 1, self.H, dtype=np.float32)[:, None, None]
        grad = top * (1 - t) + bot * t

        # tiny dither removes the banding dark gradients get on big screens
        noise = np.random.default_rng(7).uniform(
            -0.6, 0.6, (self.H, self.W, 1)).astype(np.float32)

        self.bg = np.clip(grad + noise + 0.5, 0, 255).astype(np.uint8)
        self.tile_cache = {}

    def P(self, v):
        return int(round(v * self.s))

    def sync_size(self, window):
        """Render at the real window size so pixels map 1:1."""

        try:
            _, _, w, h = cv2.getWindowImageRect(window)
        except Exception:
            return

        if w < 320 or h < 200:
            return

        if w > MAX_RENDER_W:
            h = int(h * MAX_RENDER_W / w)
            w = MAX_RENDER_W

        if (w, h) == (self.W, self.H):
            self._pending = None
            return

        if self._pending != (w, h):
            self._pending = (w, h)
            self._pending_n = 0
            return

        self._pending_n += 1

        if self._pending_n >= 2:
            self._apply_size(w, h)
            self._pending = None

    # --------------------------------------------------------
    # input
    # --------------------------------------------------------

    def on_mouse(self, event, x, y, flags):

        self.mx, self.my = x, y
        self.inside = True

        if event == cv2.EVENT_MOUSEMOVE:

            if self.drag == "jpeg":
                self._slider_set(x)

        elif event == cv2.EVENT_LBUTTONDOWN:

            self._click(x, y)

        elif event == cv2.EVENT_LBUTTONUP:

            self.drag = None

    def _click(self, x, y):

        for x1, y1, x2, y2, hid in reversed(self.hits):

            if self.modal and not hid.startswith("end_"):
                continue

            if x1 <= x <= x2 and y1 <= y <= y2:

                self.press[hid] = time.time()
                self._action(hid, x)
                return

    def on_key(self, key):

        ch = chr(key).lower() if 32 <= key < 127 else ""

        if self.modal == "end":

            if key == 27 or ch == "n":
                self.modal = None
            elif ch in ("y", "q") or key in (10, 13):
                self._confirm_end()

            return

        if key == 27:

            if self.panel_open:
                self.panel_open = False
            else:
                self._open_end()

        elif ch == "q":
            self._open_end()
        elif ch == "m":
            self._toggle_mic()
        elif ch == "f":
            self._cycle_filter()
        elif ch == "c":
            self._cycle_color()
        elif ch == "u":
            self._cycle_quality()
        elif ch == "s":
            self._toggle_stats()
        elif ch == "l":
            self._open_tab("secure")
        elif ch == "p":
            self.panel_open = not self.panel_open

    # --------------------------------------------------------
    # actions
    # --------------------------------------------------------

    def _toast(self, msg):
        self.toast = (msg, time.time())

    def _toggle_mic(self):

        toggle_microphone()

        self._toast("Microphone muted" if is_microphone_muted()
                    else "Microphone on")

    def _toggle_stats(self):

        with settings.lock:
            settings.show_stats = not settings.show_stats
            state = settings.show_stats

        self._toast("Stats overlay " + ("on" if state else "off"))

    def _set_filter(self, index):

        with settings.lock:
            settings.filter_index = index % len(settings.FILTERS)
            name = settings.FILTERS[settings.filter_index]

        self._toast("Filter: " + name.title())

    def _cycle_filter(self):

        with settings.lock:
            nxt = settings.filter_index + 1

        self._set_filter(nxt)

    def _set_color(self, index):

        with settings.lock:
            settings.color_index = index % len(settings.COLORS)
            name = settings.COLORS[settings.color_index][0]

        self._toast("Colour: " + name.title())

    def _cycle_color(self):

        with settings.lock:
            nxt = settings.color_index + 1

        self._set_color(nxt)

    def _set_quality(self, value):

        with settings.lock:
            settings.jpeg_quality = int(_clamp(value, 30, 98))
            q = settings.jpeg_quality

        self._toast(f"Picture quality: JPEG {q}")

    def _cycle_quality(self):

        values = [v for _, v in settings.QUALITY_PRESETS]

        with settings.lock:
            cur = settings.jpeg_quality

        self._set_quality(next((v for v in values if v > cur), values[0]))

    def _slider_set(self, x):

        x1, x2 = self.slider_rect
        frac = _clamp((x - x1) / float(max(1, x2 - x1)), 0.0, 1.0)

        with settings.lock:
            settings.jpeg_quality = int(round(30 + frac * 68))

    def _open_tab(self, name, force=False):

        if self.panel_open and self.tab == name and not force:
            self.panel_open = False
        else:
            self.tab = name
            self.panel_open = True

    def _open_end(self):

        self.modal = "end"
        self.drag = None

    def _confirm_end(self):

        now = time.time()

        if self.call_started:
            self.final_duration = now - self.call_started

        self.modal = None
        self.ending = True
        self.ending_t0 = now

        # cut the call immediately: sockets / camera / mic stop
        stop_event.set()

    def _action(self, hid, x=0):

        if hid == "d:mic":
            self._toggle_mic()
        elif hid in ("d:filter", "d:color", "d:quality", "d:secure"):
            self._open_tab(hid[2:])
        elif hid == "d:stats":
            self._toggle_stats()
        elif hid == "d:end":
            self._open_end()
        elif hid in ("menu", "panel_close"):
            self.panel_open = not self.panel_open
        elif hid == "badge":
            self._open_tab("secure", force=True)
        elif hid.startswith("tab:"):
            self.tab = hid[4:]
        elif hid.startswith("filter:"):
            self._set_filter(int(hid[7:]))
        elif hid.startswith("color:"):
            self._set_color(int(hid[6:]))
        elif hid.startswith("q:"):
            self._set_quality(int(hid[2:]))
        elif hid.startswith("fps:"):

            with settings.lock:
                settings.target_fps = int(hid[4:])

            self._toast(f"Frame rate limit: {int(hid[4:])} fps")

        elif hid == "slider":
            self.drag = "jpeg"
            self._slider_set(x)
        elif hid == "end_no":
            self.modal = None
        elif hid == "end_yes":
            self._confirm_end()

    # --------------------------------------------------------
    # per-frame state
    # --------------------------------------------------------

    def _acc(self):
        return tuple(int(round(c)) for c in self.accent)

    def _hovered(self, x1, y1, x2, y2):

        if self.modal is not None or not self.inside:
            return False

        return x1 <= self.mx <= x2 and y1 <= self.my <= y2

    def _hv(self, key, target):

        v = self.hov.get(key, 0.0)
        v += ((1.0 if target else 0.0) - v) * min(1.0, self.dt * 16.0)

        self.hov[key] = v

        if target:
            self.hover_t0.setdefault(key, time.time())
        else:
            self.hover_t0.pop(key, None)

        return v

    def _pressed(self, key, now):

        return max(0.0, 1.0 - (now - self.press.get(key, 0.0)) / 0.16)

    def _update(self, now, dt):

        _, tint, _, _ = settings.snapshot()

        goal = tint if tint is not None else DEFAULT_ACCENT

        for i in range(3):
            self.accent[i] += (goal[i] - self.accent[i]) * min(1.0, dt * 8.0)

        step = dt / 0.24

        self.panel_p += _clamp(
            (1.0 if self.panel_open else 0.0) - self.panel_p, -step, step)

        mstep = dt / 0.18

        self.modal_p += _clamp(
            (1.0 if self.modal else 0.0) - self.modal_p, -mstep, mstep)

        idx = [t for t, _ in self.TABS].index(self.tab)
        self.tab_pos += (idx - self.tab_pos) * min(1.0, dt * 18.0)

        lvl = 0.0 if is_microphone_muted() else ui_info.get("mic_level", 0.0)
        k = 20.0 if lvl > self.mic_lvl else 6.0
        self.mic_lvl += (lvl - self.mic_lvl) * min(1.0, dt * k)

        events = ui_info.get("events")

        if events and (self.toast is None or now - self.toast[1] > 1.2):
            try:
                self._toast(events.popleft())
            except IndexError:
                pass

        if now - self.ticker_t > 0.25:
            self.ticker_t = now
            self.ticker_hex = ui_info.get("last_cipher_hex") or ""

    def _layout(self):

        P = self.P
        W, H = self.W, self.H

        pad = P(20)
        top_h = P(68)
        dock_h = P(112)
        ticker_h = P(30)
        panel_w = P(360)
        gap = P(16)

        e = _ease(self.panel_p)

        stage = (pad, top_h,
                 W - pad - (panel_w + gap) * e,
                 H - dock_h - ticker_h)

        sw = stage[2] - stage[0]
        sh = stage[3] - stage[1]

        tw = max(P(120), min((sw - gap) / 2.0, sh * 4.0 / 3.0))
        th = tw * 3.0 / 4.0

        tx = stage[0] + (sw - (2 * tw + gap)) / 2.0
        ty = stage[1] + (sh - th) / 2.0

        local = (int(tx), int(ty), int(tx + tw), int(ty + th))
        remote = (int(tx + tw + gap), int(ty),
                  int(tx + 2 * tw + gap), int(ty + th))

        px1 = W - pad - panel_w + (1.0 - e) * (panel_w + pad + P(12))

        return {
            "pad": pad,
            "top_h": top_h,
            "stage": stage,
            "local": local,
            "remote": remote,
            "panel": (int(px1), stage[1], int(px1 + panel_w), stage[3]),
            "ticker_y": stage[3] + ticker_h / 2.0,
            "dock_h": dock_h,
        }

    # --------------------------------------------------------
    # render
    # --------------------------------------------------------

    def render(self, local_img, remote_img):

        now = time.time()
        dt = _clamp(now - self.last_t, 0.001, 0.1)

        self.last_t = now
        self.dt = dt

        self._update(now, dt)

        self.hits = []
        self.tip = None

        acc = self._acc()

        if self.ending:
            return self._render_end(now)

        if self.call_started is None and SESSION_READY.is_set():
            self.call_started = now

        cv = self.bg.copy()

        L = self._layout()

        self._video(cv, "local", local_img, L["local"], now, acc)
        self._video(cv, "remote", remote_img, L["remote"], now, acc)

        self._topbar(cv, L, now, acc)
        self._ticker(cv, L, acc)
        self._dock(cv, L, now, acc)

        if self.panel_p > 0.005:
            self._panel(cv, L, now, acc)

        self._toast_draw(cv, L, now)

        if self.tip and self.modal_p < 0.01:
            self._tip_draw(cv)

        if self.modal_p > 0.005:
            cv = self._modal(cv, now)

        return cv

    # ---------------- video tiles ---------------------------

    def _fit(self, name, frame, w, h):

        cached = self.tile_cache.get(name)

        if cached and cached[0] is frame and cached[1] == (w, h):
            return cached[2]

        fh, fw = frame.shape[:2]
        scale = max(w / float(fw), h / float(fh))

        nw = max(w, int(math.ceil(fw * scale)))
        nh = max(h, int(math.ceil(fh * scale)))

        interp = cv2.INTER_AREA if scale < 1.0 else cv2.INTER_LINEAR
        img = cv2.resize(frame, (nw, nh), interpolation=interp)

        ox, oy = (nw - w) // 2, (nh - h) // 2
        img = img[oy:oy + h, ox:ox + w]

        if name == "local":
            img = cv2.flip(img, 1)

        img = np.ascontiguousarray(img)

        self.tile_cache[name] = (frame, (w, h), img)

        return img

    def _waiting_tile(self, cv, name, rect, now, acc):

        P = self.P
        x1, y1, x2, y2 = rect

        rrect(cv, x1, y1, x2, y2, P(16), SURFACE)

        cx = (x1 + x2) / 2.0
        cy = (y1 + y2) / 2.0 - P(20)
        av = P(42)

        disc(cv, cx, cy, av, _mix(SURFACE_2, acc, 0.22))

        who = PEER_NAME if name == "remote" else LOCAL_NAME

        text(cv, who[0], cx, cy, P(34), _mix(C_TEXT, acc, 0.25),
             "semibold", "c")

        spinner(cv, cx, cy, av + P(9), P(3), (now * 320.0) % 360.0, acc)

        if name == "remote":
            title = f"Waiting for {PEER_NAME}"
            if SESSION_READY.is_set():
                sub = "Secure session ready \u00b7 waiting for video"
            elif ROLE == "BOB":
                sub = f"{PEER_NAME} starts the call and chooses the QKMS key"
            else:
                sub = f"Connecting to {PEER_NAME} at {PEER_IP}\u2026"
        else:
            cam_err = ui_info.get("camera_error")
            title = "Camera unavailable" if cam_err else "Starting camera"
            sub = (ellipsize(cam_err, self.P(12), "regular", (x2 - x1) * 0.85)
                   if cam_err else "Opening video device\u2026")

        text(cv, title, cx, cy + av + P(34), P(16), C_TEXT, "semibold", "c")
        text(cv, sub, cx, cy + av + P(58), P(12), C_TEXT_2, "regular", "c")

    def _chip(self, cv, x, y, label, color=C_TEXT, icon_name=None,
              icon_color=None, align="l", px=None):

        P = self.P
        px = px or P(12)
        h = P(26)
        padx = P(10)
        ic = P(13)
        gap = P(6)

        w = padx * 2 + text_w(label, px, "medium") + (ic + gap if icon_name else 0)

        if align == "r":
            x -= w

        rrect(cv, x, y, x + w, y + h, h / 2.0, BLACK, 0.55)

        tx = x + padx

        if icon_name:
            icon(cv, icon_name, tx + ic / 2.0, y + h / 2.0, ic,
                 icon_color or color)
            tx += ic + gap

        text(cv, label, tx, y + h / 2.0, px, color, "medium")

        return w

    def _video(self, cv, name, frame, rect, now, acc):

        P = self.P
        x1, y1, x2, y2 = rect
        w, h = x2 - x1, y2 - y1
        r = P(16)

        fresh = True

        if name == "remote" and frame is not None:
            fresh = (now - ui_info.get("last_recv", 0.0)) < 2.5

        if frame is None:

            self._waiting_tile(cv, name, rect, now, acc)

        else:

            tile = self._fit(name, frame, w, h)

            if not fresh:
                tile = cv2.convertScaleAbs(tile, alpha=0.3)

            put_rounded(cv, tile, x1, y1, r)

            if not fresh:

                cx, cy = (x1 + x2) / 2.0, (y1 + y2) / 2.0
                text(cv, "Connection lost", cx, cy - P(10), P(18), C_WARN,
                     "semibold", "c")
                text(cv, "Waiting for the encrypted stream\u2026", cx,
                     cy + P(16), P(12), C_TEXT_2, "regular", "c")

        # border / hover / speaking
        hov = self._hv("vid:" + name, self._hovered(x1, y1, x2, y2))

        rrect(cv, x1, y1, x2, y2, r, _mix(BORDER, BORDER_2, hov), 1.0,
              stroke=max(1, P(1)))

        if name == "local" and not is_microphone_muted() and self.mic_lvl > 0.08:

            rrect(cv, x1 - P(2), y1 - P(2), x2 + P(2), y2 + P(2), r + P(2),
                  C_GOOD, _clamp(self.mic_lvl * 1.4, 0, 0.9),
                  stroke=max(2, P(2)))

        # chips
        m = P(12)

        if name == "local":

            muted = is_microphone_muted()

            self._chip(cv, x1 + m, y2 - m - P(26), "You",
                       C_TEXT, "mic_off" if muted else "mic",
                       C_BAD if muted else C_TEXT)

            if frame is not None and SESSION_READY.is_set():
                self._chip(cv, x1 + m, y1 + m, "Encrypted before send",
                           C_GOOD, "lock")

        else:

            self._chip(cv, x1 + m, y2 - m - P(26), PEER_NAME, C_TEXT)

            if frame is not None and fresh:
                self._chip(cv, x1 + m, y1 + m,
                           "Decrypted \u00b7 AES-256-GCM", C_GOOD, "lock")
            elif frame is not None:
                self._chip(cv, x1 + m, y1 + m, "No signal", C_WARN, "lock")

        if settings.show_stats and frame is not None:
            self._video_stats(cv, name, x2 - m, y1 + m, fresh,
                              compact=w < P(520))

    def _video_stats(self, cv, name, x2, y, live, compact=False):

        fname, _, quality, target = settings.snapshot()

        if name == "local":

            cap = capture_meter.rate()
            snd = send_meter.rate()
            w, h = ui_info.get("local_res", (FRAME_WIDTH, FRAME_HEIGHT))

            rows = [
                ("Capture", f"{cap:.1f} fps", _fps_color(cap, FRAME_FPS)),
                ("Sending", f"{snd:.1f} fps", _fps_color(snd, target)),
                ("Uplink", _fmt_kbps(send_meter.kbps()), C_TEXT),
                ("Audio out",
                 "Muted" if is_microphone_muted()
                 else (f"{audio_tx_meter.rate():.0f} pkt/s"
                       if audio_tx_meter.rate() > 0 else "\u2013"),
                 C_BAD if is_microphone_muted()
                 else _fps_color(audio_tx_meter.rate(), 50)),
                ("Quality", f"JPEG {quality}", C_TEXT),
                ("Resolution", f"{w}\u00d7{h}", C_TEXT),
                ("Filter", fname.title(), C_TEXT),
            ]

        else:

            rcv = recv_meter.rate()
            res = ui_info.get("remote_res")

            rows = [
                ("Receiving", f"{rcv:.1f} fps", _fps_color(rcv, target)),
                ("Downlink", _fmt_kbps(recv_meter.kbps()), C_TEXT),
                ("Audio in",
                 (f"{audio_rx_meter.rate():.0f} pkt/s"
                  if time.time() - ui_info.get("last_audio", 0) < 2 else "\u2013"),
                 _fps_color(audio_rx_meter.rate(), 50)),
                ("Resolution",
                 f"{res[0]}\u00d7{res[1]}" if res else "\u2013", C_TEXT),
                ("Integrity", "Verified" if live else "\u2013",
                 C_GOOD if live else C_TEXT_3),
            ]

        if compact:
            rows = rows[:4] if name == "local" else rows[:3]

        P = self.P
        px = P(11)
        rh = P(19)
        padx = P(12)
        pady = P(8)
        w = P(170 if compact else 190)
        h = pady * 2 + rh * len(rows)
        x1 = x2 - w

        rrect(cv, x1, y, x2, y + h, P(10), BLACK, 0.55)

        for i, (k, v, c) in enumerate(rows):

            yy = y + pady + rh * i + rh / 2.0

            text(cv, k, x1 + padx, yy, px, C_TEXT_2, "medium")
            text(cv, v, x2 - padx, yy, px, c, "semibold", "r")

    # ---------------- top bar -------------------------------

    def _topbar(self, cv, L, now, acc):

        P = self.P
        W = self.W
        pad = L["pad"]
        cy = L["top_h"] / 2.0

        # security badge
        ready = SESSION_READY.is_set()
        col = C_GOOD if ready else C_WARN

        l1 = "End-to-end encrypted" if ready else "Securing session\u2026"
        l2 = (f"AES-256-GCM \u00b7 QKMS key #{key_label()}" if ready
              else "Waiting for key handshake")

        h = P(44)
        ic = P(30)

        w = (P(7) + ic + P(10)
             + max(text_w(l1, P(13), "semibold"), text_w(l2, P(11), "medium"))
             + P(18))

        x1, y1 = pad, cy - h / 2.0
        x2, y2 = x1 + w, y1 + h

        hov = self._hv("badge", self._hovered(x1, y1, x2, y2))

        rrect(cv, x1, y1, x2, y2, h / 2.0, col, 0.10 + 0.07 * hov)
        rrect(cv, x1, y1, x2, y2, h / 2.0, col, 0.35, stroke=max(1, P(1)))

        icx = x1 + P(7) + ic / 2.0

        if not ready:
            p = (now * 0.9) % 1.0
            disc(cv, icx, cy, ic / 2.0 + P(7) * p, col, (1 - p) * 0.5,
                 stroke=max(1.0, P(1.5)))

        disc(cv, icx, cy, ic / 2.0, col, 0.2)
        icon(cv, "lock", icx, cy, P(15), col)

        tx = icx + ic / 2.0 + P(10)

        text(cv, l1, tx, cy - P(8), P(13), C_TEXT, "semibold")
        text(cv, l2, tx, cy + P(9), P(11), col, "medium")

        self.hits.append((x1, y1, x2, y2, "badge"))

        # title + timer
        text(cv, "QKMS Secure Video Conference", W / 2.0, cy - P(8), P(14),
             C_TEXT, "semibold", "c")

        elapsed = (now - self.call_started) if self.call_started else 0
        t = _fmt_time(elapsed)

        dot_r = P(3.5)
        tw = text_w(t, P(12), "mono")
        sx = W / 2.0 - (dot_r * 2 + P(7) + tw) / 2.0

        if self.call_started:
            disc(cv, sx + dot_r, cy + P(10), dot_r, C_GOOD,
                 0.55 + 0.45 * math.sin(now * 3.0) ** 2)
        else:
            disc(cv, sx + dot_r, cy + P(10), dot_r, C_TEXT_3)

        text(cv, t, sx + dot_r * 2 + P(7), cy + P(10), P(12), C_TEXT_2, "mono")

        # menu button
        b = P(40)
        bx2 = W - pad
        bx1 = bx2 - b
        by1 = cy - b / 2.0
        by2 = by1 + b

        hov = self._hv("menu", self._hovered(bx1, by1, bx2, by2))
        pk = self._pressed("menu", now)
        g = P(1.5) * pk

        if self.panel_open:
            fill = _mix(SURFACE_2, acc, 0.30 + 0.1 * hov)
        else:
            fill = _mix(SURFACE_2, SURFACE_3, hov)

        rrect(cv, bx1 + g, by1 + g, bx2 - g, by2 - g, P(12), fill)
        rrect(cv, bx1 + g, by1 + g, bx2 - g, by2 - g, P(12), BORDER, 1.0,
              stroke=max(1, P(1)))
        icon(cv, "menu", (bx1 + bx2) / 2.0, cy, P(16),
             C_TEXT if (self.panel_open or hov > 0.5) else C_TEXT_2)

        self.hits.append((bx1, by1, bx2, by2, "menu"))

        # connection state
        connected = (now - ui_info.get("last_recv", 0.0)) < 2.5

        label = "Connected" if connected else "Waiting for peer"
        color = C_GOOD if connected else C_WARN

        rx = bx1 - P(16)
        lw = text(cv, label, rx, cy, P(12), color, "semibold", "r")

        target = max(1, settings.snapshot()[3])
        ratio = recv_meter.rate() / target if connected else 0.0

        bars = (4 if ratio >= 0.8 else 3 if ratio >= 0.55
                else 2 if ratio >= 0.3 else 1 if connected else 0)

        bw, bg = P(4), P(3)
        bx = rx - lw - P(10) - (4 * bw + 3 * bg)
        base = cy + P(7)

        for i in range(4):

            hh = P(5) + i * P(4)
            x = bx + i * (bw + bg)

            rrect(cv, x, base - hh, x + bw, base, P(1.5),
                  color if i < bars else SURFACE_3)

    # ---------------- ciphertext strip ----------------------

    def _ticker(self, cv, L, acc):

        P = self.P
        pad = L["pad"]
        y = L["ticker_y"]

        right = (f"AES-256-GCM  \u00b7  QKMS BB84 key #{key_label()}  "
                 "\u00b7  raw key never sent")

        rw = text(cv, right, self.W - pad, y, P(11), C_TEXT_3, "medium", "r")

        icon(cv, "lock", pad + P(6), y, P(12), C_TEXT_3)

        lx = pad + P(18)
        lw = text(cv, "CIPHERTEXT", lx, y, P(10), C_TEXT_3, "semibold")

        hx = lx + lw + P(10)
        max_w = self.W - pad - rw - P(24) - hx

        raw = self.ticker_hex

        if raw:

            groups = [raw[i:i + 4] for i in range(0, len(raw), 4)]
            s = " ".join(groups)

            while groups and text_w(s, P(11), "mono") > max_w:
                groups.pop()
                s = " ".join(groups)

            text(cv, s, hx, y, P(11), _mix(C_TEXT_2, acc, 0.45), "mono")

        else:

            text(cv, "waiting for secure session", hx, y, P(11), C_TEXT_3,
                 "mono")

    # ---------------- dock ----------------------------------

    def _dock(self, cv, L, now, acc):

        P = self.P
        W, H = self.W, self.H

        slot = P(74)
        btn = P(48)
        end_w = P(70)

        widths = [slot] * (len(self.DOCK) - 1) + [end_w + P(22)]

        padx = P(10)
        cw = sum(widths) + 2 * padx
        ch = P(86)

        cx1 = W / 2.0 - cw / 2.0
        cy1 = H - P(14) - ch
        cx2, cy2 = cx1 + cw, cy1 + ch

        shadow(cv, cx1, cy1, cx2, cy2, P(22), P(14), 0.35, P(4))
        rrect(cv, cx1, cy1, cx2, cy2, P(22), SURFACE)
        rrect(cv, cx1, cy1, cx2, cy2, P(22), BORDER, 1.0, stroke=max(1, P(1)))

        muted = is_microphone_muted()
        fname, tint, _, _ = settings.snapshot()

        by = cy1 + P(10)
        bcy = by + btn / 2.0
        label_y = cy2 - P(15)

        x = cx1 + padx

        for (bid, label, icon_name), sw in zip(self.DOCK, widths):

            key = "d:" + bid
            bcx = x + sw / 2.0

            hit = (x, cy1 + P(4), x + sw, cy2 - P(4))

            hov = self._hv(key, self._hovered(*hit))
            pk = self._pressed(key, now)
            shrink = P(2) * pk

            active = (
                (bid == "stats" and settings.show_stats)
                or (bid in ("filter", "color", "quality", "secure")
                    and self.panel_open and self.tab == bid)
            )

            ic_col = C_TEXT
            lab_col = _mix(C_TEXT_2, C_TEXT, hov)

            if bid == "end":

                fill = _mix(C_DANGER, C_DANGER_HI, hov)
                ic_col = WHITE

            elif bid == "mic" and muted:

                fill = _mix(C_BAD, _mix(C_BAD, WHITE, 0.15), hov)
                ic_col = WHITE
                label = "Muted"
                lab_col = C_BAD

            elif active:

                fill = _mix(SURFACE_2, acc, 0.30 + 0.08 * hov)
                ic_col = _mix(acc, WHITE, 0.55)
                lab_col = C_TEXT

            else:

                fill = _mix(SURFACE_2, SURFACE_3, hov)

            if bid == "end":

                rrect(cv, bcx - end_w / 2.0 + shrink, by + shrink,
                      bcx + end_w / 2.0 - shrink, by + btn - shrink,
                      btn / 2.0, fill)

            else:

                rad = btn / 2.0 - shrink
                disc(cv, bcx, bcy, rad, fill)

                if not active and not (bid == "mic" and muted):
                    disc(cv, bcx, bcy, rad, BORDER_2, 0.6 + 0.4 * hov,
                         stroke=max(1.0, P(1)))

            if bid == "mic" and not muted and self.mic_lvl > 0.04:
                disc(cv, bcx, bcy, btn / 2.0 + P(4), C_GOOD,
                     _clamp(self.mic_lvl * 1.6, 0, 1), stroke=max(1.5, P(2)))

            ic_name = "mic_off" if (bid == "mic" and muted) else icon_name

            icon(cv, ic_name, bcx, bcy, P(24 if bid == "end" else 20), ic_col)

            # small status dots
            if bid == "filter" and fname != "NONE":
                disc(cv, bcx + btn * 0.36, by + btn * 0.14, P(4.5), acc)
                disc(cv, bcx + btn * 0.36, by + btn * 0.14, P(4.5), SURFACE,
                     stroke=max(1.0, P(1.5)))

            if bid == "color" and tint is not None:
                disc(cv, bcx + btn * 0.36, by + btn * 0.14, P(5), tint)
                disc(cv, bcx + btn * 0.36, by + btn * 0.14, P(5), SURFACE,
                     stroke=max(1.0, P(1.5)))

            text(cv, label, bcx, label_y, P(11), lab_col, "medium", "c")

            self.hits.append((*hit, key))

            if hov > 0.5 and now - self.hover_t0.get(key, now) > 0.45:
                self.tip = (self.TIPS[bid], bcx, cy1 - P(10))

            x += sw

    # ---------------- side panel ----------------------------

    def _option(self, cv, x1, y1, x2, y2, label, selected, hid, acc, live,
                px=None):

        P = self.P
        hov = self._hv(hid, live and self._hovered(x1, y1, x2, y2))
        r = P(10)

        if selected:

            rrect(cv, x1, y1, x2, y2, r, _mix(SURFACE_2, acc, 0.24 + 0.06 * hov))
            rrect(cv, x1, y1, x2, y2, r, acc, 1.0, stroke=max(1, P(1.5)))
            tc = C_TEXT
            wt = "semibold"

        else:

            rrect(cv, x1, y1, x2, y2, r, _mix(SURFACE_2, SURFACE_3, hov))
            tc = _mix(C_TEXT_2, C_TEXT, hov)
            wt = "medium"

        text(cv, label, (x1 + x2) / 2.0, (y1 + y2) / 2.0, px or P(12), tc,
             wt, "c")

        if live:
            self.hits.append((x1, y1, x2, y2, hid))

    def _section(self, cv, label, x, y):
        text(cv, label.upper(), x, y, self.P(10), C_TEXT_3, "semibold")

    def _kv(self, cv, x1, x2, y, rows, rh):

        P = self.P

        for i, (k, v, c) in enumerate(rows):

            yy = y + rh * i + rh / 2.0
            kw = text(cv, k, x1, yy, P(12), C_TEXT_2)
            v = ellipsize(v, P(12), "semibold", x2 - x1 - kw - P(12))
            text(cv, v, x2, yy, P(12), c, "semibold", "r")

            if i < len(rows) - 1:
                _fill(cv, x1, y + rh * (i + 1), x2, y + rh * (i + 1) + 1,
                      BORDER)

        return y + rh * len(rows)

    def _paragraph(self, cv, s, x, y, max_w, px=None, color=C_TEXT_3):

        P = self.P
        px = px or P(12)

        for line in wrap(s, px, "regular", max_w):
            text(cv, line, x, y, px, color)
            y += px * 1.45

        return y

    def _panel(self, cv, L, now, acc):

        P = self.P
        x1, y1, x2, y2 = L["panel"]
        live = self.panel_p > 0.95 and self.modal is None

        shadow(cv, x1, y1, x2, y2, P(16), P(16), 0.35, P(6))
        rrect(cv, x1, y1, x2, y2, P(16), SURFACE)
        rrect(cv, x1, y1, x2, y2, P(16), BORDER, 1.0, stroke=max(1, P(1)))

        px1 = x1 + P(18)
        px2 = x2 - P(18)

        # header
        hy = y1 + P(26)

        text(cv, "Call settings", px1, hy, P(15), C_TEXT, "semibold")

        cb = P(28)
        cx1, cy1 = px2 - cb, hy - cb / 2.0
        hov = self._hv("panel_close", live and self._hovered(
            cx1, cy1, cx1 + cb, cy1 + cb))

        if hov > 0.02:
            rrect(cv, cx1, cy1, cx1 + cb, cy1 + cb, P(8), SURFACE_3, hov)

        icon(cv, "close", cx1 + cb / 2.0, hy, P(11),
             _mix(C_TEXT_2, C_TEXT, hov))

        if live:
            self.hits.append((cx1, cy1, cx1 + cb, cy1 + cb, "panel_close"))

        # segmented tabs
        sy = hy + P(24)
        sh = P(34)

        rrect(cv, px1, sy, px2, sy + sh, P(10), SURFACE_2)

        seg_w = (px2 - px1 - P(6)) / 4.0
        kx = px1 + P(3) + self.tab_pos * seg_w

        rrect(cv, kx, sy + P(3), kx + seg_w, sy + sh - P(3), P(8), SURFACE_3)
        rrect(cv, kx, sy + P(3), kx + seg_w, sy + sh - P(3), P(8), BORDER_2,
              0.8, stroke=max(1, P(1)))

        for i, (tid, label) in enumerate(self.TABS):

            tx1 = px1 + P(3) + i * seg_w
            tx2 = tx1 + seg_w

            hv = self._hv("tab:" + tid, live and self._hovered(
                tx1, sy, tx2, sy + sh))

            sel = tid == self.tab

            text(cv, label, (tx1 + tx2) / 2.0, sy + sh / 2.0, P(12),
                 C_TEXT if sel else _mix(C_TEXT_2, C_TEXT, hv),
                 "semibold" if sel else "medium", "c")

            if live:
                self.hits.append((tx1, sy, tx2, sy + sh, "tab:" + tid))

        y0 = sy + sh + P(20)

        if self.tab == "filter":
            self._tab_filter(cv, px1, px2, y0, acc, live)
        elif self.tab == "color":
            self._tab_color(cv, px1, px2, y0, acc, live)
        elif self.tab == "quality":
            self._tab_quality(cv, px1, px2, y0, acc, live)
        else:
            self._tab_secure(cv, px1, px2, y0, now)

    def _tab_filter(self, cv, x1, x2, y0, acc, live):

        P = self.P

        with settings.lock:
            cur = settings.filter_index

        gap = P(8)
        bh = P(38)
        cw = (x2 - x1 - gap) / 2.0

        for i, name in enumerate(settings.FILTERS):

            col, row = i % 2, i // 2
            bx = x1 + col * (cw + gap)
            by = y0 + row * (bh + gap)

            self._option(cv, bx, by, bx + cw, by + bh, name.title(),
                         i == cur, f"filter:{i}", acc, live)

        rows = (len(settings.FILTERS) + 1) // 2

        self._paragraph(
            cv,
            f"Filters are applied to your outgoing video before it is "
            f"encrypted, so {PEER_NAME} sees them end-to-end. Press F "
            f"to cycle.",
            x1, y0 + rows * (bh + gap) + P(16), x2 - x1)

    def _tab_color(self, cv, x1, x2, y0, acc, live):

        P = self.P

        with settings.lock:
            cur = settings.color_index

        cw = (x2 - x1) / 4.0
        rh = P(76)
        sr = P(17)

        for i, (name, bgr) in enumerate(settings.COLORS):

            col, row = i % 4, i // 4
            cx = x1 + cw * (col + 0.5)
            cy = y0 + P(22) + row * rh

            hit = (cx - cw / 2.0, cy - sr - P(6), cx + cw / 2.0,
                   cy + sr + P(26))

            hov = self._hv(f"color:{i}", live and self._hovered(*hit))

            if bgr is None:
                disc(cv, cx, cy, sr, SURFACE_3)
                icon(cv, "slash", cx, cy, sr * 1.3, C_BAD)
            else:
                disc(cv, cx, cy, sr, bgr)

            if i == cur:
                disc(cv, cx, cy, sr + P(5), C_TEXT, 1.0,
                     stroke=max(1.5, P(2)))
            elif hov > 0.02:
                disc(cv, cx, cy, sr + P(5), C_TEXT_2, 0.5 * hov,
                     stroke=max(1.5, P(2)))

            text(cv, name.title(), cx, cy + sr + P(16), P(11),
                 C_TEXT if i == cur else C_TEXT_2,
                 "semibold" if i == cur else "medium", "c")

            if live:
                self.hits.append((*hit, f"color:{i}"))

        y = y0 + 2 * rh + P(14)

        self._section(cv, "Current accent", x1, y)
        text(cv, settings.COLORS[cur][0].title(), x1, y + P(26), P(20), acc,
             "semibold")

        self._paragraph(
            cv,
            "Sets the app accent colour and adds a soft tint to your "
            "outgoing video. Press C to cycle.",
            x1, y + P(60), x2 - x1)

    def _tab_quality(self, cv, x1, x2, y0, acc, live):

        P = self.P

        with settings.lock:
            q = settings.jpeg_quality
            fps_t = settings.target_fps

        gap = P(6)
        bh = P(34)

        # presets
        self._section(cv, "Picture quality", x1, y0)

        bw = (x2 - x1 - 3 * gap) / 4.0
        y = y0 + P(14)

        for i, (name, val) in enumerate(settings.QUALITY_PRESETS):

            bx = x1 + i * (bw + gap)
            self._option(cv, bx, y, bx + bw, y + bh, name.title(), q == val,
                         f"q:{val}", acc, live)

        # slider
        y += bh + P(26)

        text(cv, "JPEG quality", x1, y, P(12), C_TEXT_2)
        text(cv, str(q), x2, y, P(13), acc, "semibold", "r")

        sx1, sx2 = x1 + P(8), x2 - P(8)
        sy = y + P(24)

        self.slider_rect = (sx1, sx2)

        frac = (q - 30) / 68.0
        kx = sx1 + frac * (sx2 - sx1)

        track = P(4)

        rrect(cv, sx1, sy - track / 2.0, sx2, sy + track / 2.0, track / 2.0,
              SURFACE_3)
        rrect(cv, sx1, sy - track / 2.0, kx, sy + track / 2.0, track / 2.0,
              acc)

        hit = (sx1 - P(10), sy - P(14), sx2 + P(10), sy + P(14))
        hov = self._hv("slider", live and self._hovered(*hit))

        if self.drag == "jpeg" or hov > 0.02:
            disc(cv, kx, sy, P(15), acc,
                 0.22 if self.drag == "jpeg" else 0.18 * hov)

        disc(cv, kx, sy, P(8), WHITE)
        disc(cv, kx, sy, P(8), acc, 1.0, stroke=max(1.5, P(2)))

        if live:
            self.hits.append((*hit, "slider"))

        # fps
        y = sy + P(30)

        self._section(cv, "Frame rate limit", x1, y)

        y += P(14)

        for i, f in enumerate(settings.FPS_PRESETS):

            bx = x1 + i * (bw + gap)
            self._option(cv, bx, y, bx + bw, y + bh, f"{f} fps", fps_t == f,
                         f"fps:{f}", acc, live)

        # live details
        y += bh + P(24)

        self._section(cv, "Live details", x1, y)

        w, h = ui_info.get("local_res", (FRAME_WIDTH, FRAME_HEIGHT))
        rres = ui_info.get("remote_res")

        rows = [
            ("Resolution (tx / rx)",
             f"{w}\u00d7{h} / " + (f"{rres[0]}\u00d7{rres[1]}" if rres else "\u2013"),
             C_TEXT),
            ("Capture", f"{capture_meter.rate():.1f} fps", C_TEXT),
            ("Send / receive",
             f"{send_meter.rate():.1f} / {recv_meter.rate():.1f} fps", C_TEXT),
            ("Uplink / downlink",
             f"{_fmt_kbps(send_meter.kbps())} / {_fmt_kbps(recv_meter.kbps())}",
             C_TEXT),
        ]

        self._kv(cv, x1, x2, y + P(8), rows, P(24))

    def _tab_secure(self, cv, x1, x2, y0, now):

        P = self.P

        ready = SESSION_READY.is_set()
        col = C_GOOD if ready else C_WARN

        # status header
        ir = P(22)
        icx = x1 + ir
        icy = y0 + ir

        for k in range(2):
            p = ((now * 0.6) + k * 0.5) % 1.0
            disc(cv, icx, icy, ir + P(10) * p, col, (1 - p) * 0.35,
                 stroke=max(1.0, P(1.5)))

        disc(cv, icx, icy, ir, col, 0.16)
        icon(cv, "shield", icx, icy, P(24), col)

        tx = icx + ir + P(14)

        text(cv, "End-to-end encrypted" if ready else "Securing session\u2026",
             tx, icy - P(9), P(14), C_TEXT, "semibold")
        text(cv, f"Only you and {PEER_NAME} can see this call", tx,
             icy + P(10), P(12), C_TEXT_2)

        fp = ui_info.get("key_fingerprint", "--------")

        rows = [
            ("Cipher", "AES-256-GCM", C_TEXT),
            ("Key source", f"QKMS BB84 \u00b7 ID {key_label()}", C_TEXT),
            ("Fingerprint", fp, C_TEXT),
            ("Session", session_label(), C_TEXT),
            ("Raw key sent", "No", C_GOOD),
            ("Handshake", "Established" if ready else "Pending", col),
            ("Replay guard", "Sequence + AAD", C_TEXT),
            ("Packets tx / rx",
             f"{send_meter.total_events} / {recv_meter.total_events}", C_TEXT),
        ]

        y = self._kv(cv, x1, x2, y0 + 2 * ir + P(12), rows, P(24))

        # ciphertext box
        y += P(12)
        bh = P(52)

        rrect(cv, x1, y, x2, y + bh, P(10), SURFACE_2)

        text(cv, "LIVE CIPHERTEXT", x1 + P(12), y + P(13), P(9), C_TEXT_3,
             "semibold")

        hexs = self.ticker_hex

        if hexs:
            s = " ".join(hexs[i:i + 4] for i in range(0, 32, 4))
        else:
            s = "waiting\u2026"

        s = ellipsize(s, P(12), "mono", x2 - x1 - P(24))

        text(cv, s, x1 + P(12), y + P(34), P(12),
             _mix(C_TEXT_2, self._acc(), 0.45), "mono")

    # ---------------- overlays ------------------------------

    def _toast_draw(self, cv, L, now):

        if not self.toast:
            return

        msg, t0 = self.toast
        age = now - t0

        if age > 1.9:
            self.toast = None
            return

        slide = _ease(age / 0.22)
        fade = 1.0 - _ease((age - 1.5) / 0.4)

        P = self.P
        h = P(36)
        w = text_w(msg, P(13), "medium") + P(36)

        st = L["stage"]
        cx = (st[0] + st[2]) / 2.0
        y = st[3] - P(50) + P(10) * (1 - slide)

        x1, x2 = cx - w / 2.0, cx + w / 2.0

        shadow(cv, x1, y, x2, y + h, h / 2.0, P(10), 0.45 * fade, P(3))
        rrect(cv, x1, y, x2, y + h, h / 2.0, SURFACE_3, fade)
        rrect(cv, x1, y, x2, y + h, h / 2.0, BORDER_2, fade,
              stroke=max(1, P(1)))
        text(cv, msg, cx, y + h / 2.0, P(13), C_TEXT, "medium", "c", fade)

    def _tip_draw(self, cv):

        P = self.P
        msg, cx, y2 = self.tip

        h = P(28)
        w = text_w(msg, P(12), "medium") + P(24)

        x1 = _clamp(cx - w / 2.0, P(8), self.W - P(8) - w)
        y1 = y2 - h

        shadow(cv, x1, y1, x1 + w, y2, P(8), P(8), 0.4, P(2))
        rrect(cv, x1, y1, x1 + w, y2, P(8), SURFACE_3)
        text(cv, msg, x1 + w / 2.0, y1 + h / 2.0, P(12), C_TEXT, "medium", "c")

    def _modal(self, cv, now):

        P = self.P
        p = _ease(self.modal_p)

        cv = cv2.convertScaleAbs(cv, alpha=1.0 - 0.55 * p)

        s = 0.94 + 0.06 * p
        w, h = P(400) * s, P(226) * s

        x1 = (self.W - w) / 2.0
        y1 = (self.H - h) / 2.0
        x2, y2 = x1 + w, y1 + h

        shadow(cv, x1, y1, x2, y2, P(20), P(22), 0.55 * p, P(8))
        rrect(cv, x1, y1, x2, y2, P(20), SURFACE, p)
        rrect(cv, x1, y1, x2, y2, P(20), BORDER_2, p, stroke=max(1, P(1)))

        if p < 0.5 or self.modal != "end":
            return cv

        a = _clamp((p - 0.5) * 2.0, 0, 1)
        cx = (x1 + x2) / 2.0

        disc(cv, cx, y1 + P(48), P(24), C_DANGER, a)
        icon(cv, "phone", cx, y1 + P(48), P(24), WHITE, a)

        text(cv, "End this call?", cx, y1 + P(98), P(18), C_TEXT,
             "semibold", "c", a)
        text(cv, f"The encrypted session with {PEER_NAME} will be closed.",
             cx, y1 + P(124), P(12), C_TEXT_2, "regular", "c", a)

        by1 = y2 - P(62)
        by2 = y2 - P(20)

        self._modal_btn(cv, x1 + P(24), by1, cx - P(6), by2, "Stay",
                        SURFACE_3, _mix(SURFACE_3, WHITE, 0.08), "end_no",
                        now, a)
        self._modal_btn(cv, cx + P(6), by1, x2 - P(24), by2, "End call",
                        C_DANGER, C_DANGER_HI, "end_yes", now, a)

        return cv

    def _modal_btn(self, cv, x1, y1, x2, y2, label, c1, c2, hid, now, a):

        raw = self.inside and x1 <= self.mx <= x2 and y1 <= self.my <= y2
        hov = self._hv(hid, raw)
        g = self.P(1.5) * self._pressed(hid, now)

        rrect(cv, x1 + g, y1 + g, x2 - g, y2 - g, self.P(12),
              _mix(c1, c2, hov), a)
        text(cv, label, (x1 + x2) / 2.0, (y1 + y2) / 2.0, self.P(13), WHITE,
             "semibold", "c", a)

        self.hits.append((x1, y1, x2, y2, hid))

    # ---------------- call ended screen ---------------------

    def _render_end(self, now):

        P = self.P
        t = now - self.ending_t0

        cv = cv2.convertScaleAbs(self.bg, alpha=0.7)

        cx, cy = self.W / 2.0, self.H / 2.0 - P(40)

        for k in range(3):
            p = ((t * 0.7) + k / 3.0) % 1.0
            disc(cv, cx, cy, P(46) + P(40) * p, C_DANGER, (1 - p) * 0.3,
                 stroke=max(1.5, P(2)))

        disc(cv, cx, cy, P(44), C_DANGER)
        icon(cv, "phone", cx, cy, P(40), WHITE)

        a = _ease((t - 0.15) / 0.4)

        text(cv, "Call ended", cx, cy + P(92), P(26), C_TEXT, "semibold",
             "c", a)
        text(cv, "Duration  " + _fmt_time(self.final_duration), cx,
             cy + P(126), P(14), C_TEXT_2, "mono", "c", a)
        text(cv, "Encrypted session closed. The raw QKMS key was never "
                 "transmitted.", cx, cy + P(156), P(12), C_TEXT_3,
             "regular", "c", a)

        if t > 2.2:
            self.finished = True

        return cv


def gui():

    global running

    # ASCII only: Qt looks windows up by name, and a non-ASCII name
    # (the old en dash) made setMouseCallback fail with
    # "NULL window handler", which crashed the whole call.
    window = f"{LOCAL_NAME} - QKMS Secure Video Conference"

    ui = CallUI()

    flags = (cv2.WINDOW_NORMAL
             | getattr(cv2, "WINDOW_FREERATIO", 0)
             | getattr(cv2, "WINDOW_GUI_NORMAL", 0))

    cv2.namedWindow(window, flags)
    cv2.resizeWindow(window, BASE_W, BASE_H)

    # show one frame first so the native window really exists
    cv2.imshow(window, ui.render(None, None))
    cv2.waitKey(1)

    try:
        cv2.setMouseCallback(
            window,
            lambda event, x, y, flags, param: ui.on_mouse(event, x, y, flags)
        )
    except cv2.error as exc:
        print("[GUI] Mouse input unavailable, keyboard shortcuts still work:",
              str(exc).strip().splitlines()[-1])

    print("[GUI] Click the dock buttons or use the keyboard:")
    print("[GUI]   M mic | F filter | C colour | U quality | S stats "
          "| L encryption | P menu | Q/ESC end call")

    frame_budget = 1.0 / UI_FPS

    try:

        while not ui.finished and running:

            t0 = time.time()

            ui.sync_size(window)

            # frames are replaced, never mutated, so no copy is needed
            with local_frame_lock:
                left = local_frame

            with remote_frame_lock:
                right = remote_frame

            cv2.imshow(window, ui.render(left, right))

            wait_ms = max(1, int((frame_budget - (time.time() - t0)) * 1000))
            key = cv2.waitKey(wait_ms)

            if key != -1:
                ui.on_key(key & 0xFF)

            # window closed with the X button
            try:
                if cv2.getWindowProperty(window, cv2.WND_PROP_VISIBLE) < 1:
                    break
            except cv2.error:
                break

    finally:

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
    print("QKMS SECURE VIDEO CONFERENCE - ALICE")
    print("SESSION HANDSHAKE + AES-256-GCM")
    print("SECURE VIDEO + SECURE AUDIO")
    print("=" * 70)
    print(f"Local / Peer     : {LOCAL_IP} / {PEER_IP}")
    print(f"QKMS Key ID      : {KEY_ID}")
    print("Encryption       : AES-256-GCM")
    print("Raw key sent     : NO")
    print(f"Video TX/RX      : {SEND_VIDEO_PORT}/{RECEIVE_VIDEO_PORT}")
    print(f"Audio TX/RX      : {SEND_AUDIO_PORT}/{RECEIVE_AUDIO_PORT}")
    print(f"Session ID       : {SESSION_ID}")
    print("=" * 70)

    try:
        key = get_qkms_key(KEY_ID)

        threads = [
            threading.Thread(target=camera_capture, daemon=True),
            threading.Thread(target=video_receiver, args=(key,), daemon=True),
            threading.Thread(target=video_sender, args=(key,), daemon=True),
            threading.Thread(target=audio_receiver, args=(key,), daemon=True),
            threading.Thread(target=audio_sender, args=(key,), daemon=True),
            threading.Thread(target=audio_playback, daemon=True),
        ]

        for thread in threads:
            thread.start()

        gui()

    except KeyboardInterrupt:
        print("\n[SYSTEM] Keyboard interrupt")

    except Exception as exc:
        print("[SYSTEM] Error:", exc)

    finally:
        running = False
        stop_event.set()
        cv2.destroyAllWindows()
        print("[SYSTEM] Alice stopped")


if __name__ == "__main__":
    main()
