import socket
import struct
import cv2
import numpy as np
import threading
import time
import queue
import sounddevice as sd


# ============================================================
# QKMS VIDEO CONFERENCE - STAGE 3
# ALICE
# TWO-WAY VIDEO + AUDIO
# AUTOMATIC MICROPHONE SELECTION
# ============================================================

ROLE = "ALICE"

LOCAL_IP = "10.11.80.94"
PEER_IP = "10.11.80.93"


# ============================================================
# VIDEO
# ============================================================

SEND_VIDEO_PORT = 7000
RECEIVE_VIDEO_PORT = 7001

CAMERA = "/dev/video0"

WIDTH = 640
HEIGHT = 480
FPS = 30

JPEG_QUALITY = 70


# ============================================================
# AUDIO
# ============================================================

SEND_AUDIO_PORT = 7002
RECEIVE_AUDIO_PORT = 7003

AUDIO_RATE = 48000
AUDIO_CHANNELS = 1
AUDIO_DTYPE = "int16"
AUDIO_BLOCKSIZE = 960

# Default speaker / Bluetooth speaker
AUDIO_OUTPUT_DEVICE = None


# ============================================================
# AUDIO PROCESSING
# ============================================================

NOISE_GATE_THRESHOLD = 500
NOISE_GATE_ATTENUATION = 0.12
MIC_GAIN = 1.0


# ============================================================
# QUEUES
# ============================================================

audio_send_queue = queue.Queue(maxsize=10)
audio_play_queue = queue.Queue(maxsize=100)

local_frame_queue = queue.Queue(maxsize=1)
remote_frame_queue = queue.Queue(maxsize=1)


# ============================================================
# GLOBAL STATE
# ============================================================

running = True

mic_muted = False
mic_state_lock = threading.Lock()

audio_input_device = None
audio_input_name = ""


# ============================================================
# MICROPHONE STATE
# ============================================================

def is_microphone_muted():

    with mic_state_lock:
        return mic_muted


def clear_audio_send_queue():

    while True:

        try:
            audio_send_queue.get_nowait()

        except queue.Empty:
            break


def toggle_microphone():

    global mic_muted

    with mic_state_lock:
        mic_muted = not mic_muted
        state = mic_muted

    if state:

        clear_audio_send_queue()

        print("[MIC] Microphone MUTED")

    else:

        print("[MIC] Microphone UNMUTED")


# ============================================================
# DRAW MIC BUTTON
# ============================================================

def draw_mic_button(frame):

    display = frame.copy()

    if is_microphone_muted():
        label = "MIC: MUTED"
    else:
        label = "MIC: ON"

    x1 = 20
    y1 = 425
    x2 = 190
    y2 = 470

    cv2.rectangle(
        display,
        (x1, y1),
        (x2, y2),
        (40, 40, 40),
        -1
    )

    cv2.rectangle(
        display,
        (x1, y1),
        (x2, y2),
        (255, 255, 255),
        1
    )

    cv2.putText(
        display,
        label,
        (x1 + 10, y1 + 29),
        cv2.FONT_HERSHEY_SIMPLEX,
        0.65,
        (255, 255, 255),
        2,
        cv2.LINE_AA
    )

    return display


# ============================================================
# MIC BUTTON
# ============================================================

def microphone_mouse_callback(
    event,
    x,
    y,
    flags,
    param
):

    if event != cv2.EVENT_LBUTTONDOWN:
        return

    if (
        20 <= x <= 190
        and
        425 <= y <= 470
    ):

        toggle_microphone()


# ============================================================
# RECEIVE EXACT BYTES
# ============================================================

def recv_exact(sock, size):

    data = b""

    while len(data) < size:

        chunk = sock.recv(
            size - len(data)
        )

        if not chunk:
            return None

        data += chunk

    return data


# ============================================================
# CONNECT WITH RETRY
# ============================================================

def connect_with_retry(
    host,
    port,
    name
):

    while running:

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        )

        sock.settimeout(3)

        try:

            print(
                f"[{name}] Connecting to "
                f"{host}:{port}"
            )

            sock.connect(
                (
                    host,
                    port
                )
            )

            sock.settimeout(None)

            print(
                f"[{name}] Connected to "
                f"{host}:{port}"
            )

            return sock

        except (
            ConnectionRefusedError,
            socket.timeout,
            OSError
        ) as e:

            sock.close()

            if not running:
                return None

            print(
                f"[{name}] Peer not ready "
                f"({e}). Retrying in 2 seconds..."
            )

            time.sleep(2)

    return None


# ============================================================
# BUILD MICROPHONE CANDIDATE LIST
# ============================================================

def get_microphone_candidates():

    candidates = []

    try:

        devices = sd.query_devices()

    except Exception as e:

        print(
            f"[AUDIO] Cannot query devices: {e}"
        )

        return []


    wireless_words = (
        "BLUETOOTH",
        "WIRELESS",
        "HEADSET",
        "HANDS-FREE",
        "HANDSFREE",
        "AIRPODS",
        "BUDS",
        "JABRA",
        "BOSE",
        "SONY",
        "BOAT",
        "SENNHEISER"
    )

    usb_words = (
        "USB MICROPHONE",
        "USB MIC",
        "USB AUDIO"
    )

    virtual_words = (
        "PIPEWIRE",
        "PULSEAUDIO",
        "DEFAULT",
        "SYSDEFAULT",
        "MONITOR",
        "HDMI"
    )

    for index, device in enumerate(devices):

        name = str(
            device.get("name", "")
        )

        upper = name.upper()

        try:
            max_input = int(
                device.get(
                    "max_input_channels",
                    0
                )
            )

        except Exception:

            max_input = 0

        if max_input <= 0:
            continue


        # ----------------------------------------------------
        # Wireless / Bluetooth
        # ----------------------------------------------------

        if any(
            word in upper
            for word in wireless_words
        ):

            score = 1000
            reason = "Wireless/Bluetooth microphone"


        # ----------------------------------------------------
        # External USB
        # ----------------------------------------------------

        elif any(
            word in upper
            for word in usb_words
        ):

            # C270 is handled separately below.
            if "C270" in upper or "WEBCAM" in upper:

                score = 800
                reason = "Logitech C270 microphone"

            else:

                score = 900
                reason = "External USB microphone"


        # ----------------------------------------------------
        # C270
        # ----------------------------------------------------

        elif (
            "C270" in upper
            or
            "WEBCAM" in upper
        ):

            score = 800
            reason = "Logitech C270 microphone"


        # ----------------------------------------------------
        # Built-in
        # ----------------------------------------------------

        elif any(
            word in upper
            for word in (
                "ALC222",
                "ANALOG",
                "BUILT-IN",
                "INTERNAL"
            )
        ):

            score = 200
            reason = "Built-in microphone"


        # ----------------------------------------------------
        # Virtual / default
        # ----------------------------------------------------

        elif any(
            word in upper
            for word in virtual_words
        ):

            score = 50
            reason = "Virtual/default microphone"


        # ----------------------------------------------------
        # Other physical input
        # ----------------------------------------------------

        else:

            score = 400
            reason = "Other physical microphone"


        candidates.append(
            (
                score,
                index,
                name,
                max_input,
                reason
            )
        )


    candidates.sort(
        key=lambda x: (
            -x[0],
            x[1]
        )
    )

    return candidates


# ============================================================
# OPEN MICROPHONE SAFELY
#
# IMPORTANT:
# We DO NOT use check_input_settings() as final validation.
#
# We actually open the InputStream.
# If it fails, next microphone is tried.
# ============================================================

def open_microphone_with_fallback():

    global audio_input_device
    global audio_input_name

    print()
    print(
        "[AUDIO] Searching for best available microphone..."
    )

    candidates = get_microphone_candidates()

    if not candidates:

        print(
            "[AUDIO] ERROR: No microphone "
            "input devices found."
        )

        return None


    print(
        "[AUDIO] Microphone candidates:"
    )

    for (
        score,
        index,
        name,
        max_input,
        reason
    ) in candidates:

        print(
            f"    [{index}] "
            f"{name} | "
            f"{reason}"
        )


    # --------------------------------------------------------
    # Try each candidate by actually opening it.
    # --------------------------------------------------------

    for (
        score,
        index,
        name,
        max_input,
        reason
    ) in candidates:

        if not running:
            return None

        print()
        print(
            "[AUDIO] Trying microphone:"
        )

        print(
            f"        Device index  : {index}"
        )

        print(
            f"        Device name   : {name}"
        )

        print(
            f"        Input channels: {max_input}"
        )

        print(
            f"        Reason         : {reason}"
        )


        try:

            stream = sd.InputStream(

                device=index,

                samplerate=AUDIO_RATE,

                channels=AUDIO_CHANNELS,

                dtype=AUDIO_DTYPE,

                blocksize=AUDIO_BLOCKSIZE,

                latency="low",

                callback=audio_capture_callback

            )

            stream.start()


            audio_input_device = index
            audio_input_name = name


            print()
            print(
                "[AUDIO] MICROPHONE OPENED SUCCESSFULLY"
            )

            print(
                f"        Device index : {index}"
            )

            print(
                f"        Device name  : {name}"
            )

            print(
                f"        Selection    : {reason}"
            )

            print(
                f"        Format       : "
                f"{AUDIO_RATE} Hz / "
                f"{AUDIO_CHANNELS} channel / "
                f"{AUDIO_BLOCKSIZE} samples"
            )

            return stream


        except Exception as e:

            print(
                f"[AUDIO] FAILED: {name}"
            )

            print(
                f"        {e}"
            )

            print(
                "[AUDIO] Trying next microphone..."
            )

            try:
                stream.close()
            except Exception:
                pass


    print()
    print(
        "[AUDIO] ERROR: No microphone could be opened."
    )

    return None


# ============================================================
# VIDEO SENDER
# ============================================================

def video_sender():

    global running

    print(
        "[VIDEO SEND] Opening camera..."
    )

    cap = cv2.VideoCapture(
        CAMERA,
        cv2.CAP_V4L2
    )

    if not cap.isOpened():

        print(
            "[VIDEO SEND] ERROR: "
            "Cannot open camera"
        )

        running = False
        return


    cap.set(
        cv2.CAP_PROP_FRAME_WIDTH,
        WIDTH
    )

    cap.set(
        cv2.CAP_PROP_FRAME_HEIGHT,
        HEIGHT
    )

    cap.set(
        cv2.CAP_PROP_FPS,
        FPS
    )


    print(
        "[VIDEO SEND] Camera: "
        f"{int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))}x"
        f"{int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))} "
        f"@ {cap.get(cv2.CAP_PROP_FPS):.1f} FPS"
    )


    sock = connect_with_retry(
        PEER_IP,
        SEND_VIDEO_PORT,
        "VIDEO SEND"
    )

    if sock is None:

        cap.release()
        return


    frame_count = 0
    total_bytes = 0

    start_time = time.time()
    last_report = start_time


    try:

        while running:

            ret, frame = cap.read()

            if not ret:

                print(
                    "[VIDEO SEND] "
                    "Camera read failed"
                )

                time.sleep(0.01)
                continue


            try:

                if local_frame_queue.full():

                    local_frame_queue.get_nowait()

                local_frame_queue.put_nowait(
                    frame.copy()
                )

            except (
                queue.Empty,
                queue.Full
            ):

                pass


            success, encoded = cv2.imencode(
                ".jpg",
                frame,
                [
                    cv2.IMWRITE_JPEG_QUALITY,
                    JPEG_QUALITY
                ]
            )

            if not success:
                continue


            jpeg_data = encoded.tobytes()

            header = struct.pack(
                "!I",
                len(jpeg_data)
            )


            try:

                sock.sendall(header)
                sock.sendall(jpeg_data)

            except (
                BrokenPipeError,
                ConnectionResetError,
                OSError
            ) as e:

                print(
                    f"[VIDEO SEND] "
                    f"Connection lost: {e}"
                )

                break


            frame_count += 1
            total_bytes += len(jpeg_data)


            now = time.time()

            if now - last_report >= 5:

                elapsed = (
                    now - start_time
                )

                measured_fps = (
                    frame_count / elapsed
                    if elapsed > 0
                    else 0
                )

                bitrate_kbps = (
                    total_bytes * 8
                    / elapsed
                    / 1000
                    if elapsed > 0
                    else 0
                )

                print(
                    "[VIDEO SEND] "
                    f"FPS={measured_fps:.2f} | "
                    f"Frame={len(jpeg_data)/1024:.1f} KB | "
                    f"Bitrate={bitrate_kbps:.1f} kbps"
                )

                last_report = now


    except Exception as e:

        if running:

            print(
                f"[VIDEO SEND] Error: {e}"
            )


    finally:

        cap.release()

        try:
            sock.close()
        except Exception:
            pass

        print(
            "[VIDEO SEND] Stopped"
        )


# ============================================================
# VIDEO RECEIVER
# ============================================================

def video_receiver():

    global running

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    conn = None


    try:

        server.bind(
            (
                LOCAL_IP,
                RECEIVE_VIDEO_PORT
            )
        )

        server.listen(1)

        print(
            "[VIDEO RECV] Listening on "
            f"{LOCAL_IP}:{RECEIVE_VIDEO_PORT}"
        )


        conn, addr = server.accept()

        print(
            "[VIDEO RECV] Peer connected from "
            f"{addr[0]}:{addr[1]}"
        )


        frame_count = 0
        start_time = time.time()
        last_report = start_time


        while running:

            header = recv_exact(
                conn,
                4
            )

            if header is None:
                break


            frame_size = struct.unpack(
                "!I",
                header
            )[0]


            if (
                frame_size <= 0
                or
                frame_size > 5 * 1024 * 1024
            ):

                print(
                    "[VIDEO RECV] "
                    f"Invalid frame size: {frame_size}"
                )

                break


            jpeg_data = recv_exact(
                conn,
                frame_size
            )

            if jpeg_data is None:
                break


            frame_array = np.frombuffer(
                jpeg_data,
                dtype=np.uint8
            )

            frame = cv2.imdecode(
                frame_array,
                cv2.IMREAD_COLOR
            )

            if frame is None:
                continue


            try:

                if remote_frame_queue.full():

                    remote_frame_queue.get_nowait()

                remote_frame_queue.put_nowait(
                    frame
                )

            except (
                queue.Empty,
                queue.Full
            ):

                pass


            frame_count += 1

            now = time.time()

            if now - last_report >= 5:

                elapsed = (
                    now - start_time
                )

                receive_fps = (
                    frame_count / elapsed
                    if elapsed > 0
                    else 0
                )

                print(
                    "[VIDEO RECV] "
                    f"FPS={receive_fps:.2f}"
                )

                last_report = now


    except Exception as e:

        if running:

            print(
                f"[VIDEO RECV] Error: {e}"
            )


    finally:

        if conn is not None:

            try:
                conn.close()
            except Exception:
                pass

        server.close()

        print(
            "[VIDEO RECV] Stopped"
        )


# ============================================================
# AUDIO PROCESSING
# ============================================================

def process_microphone_audio(indata):

    audio_array = (
        indata[:, 0]
        .astype(
            np.float32,
            copy=True
        )
    )


    if MIC_GAIN != 1.0:

        audio_array *= float(
            MIC_GAIN
        )


    magnitude = np.abs(
        audio_array
    )


    quiet_mask = (
        magnitude
        <
        float(
            NOISE_GATE_THRESHOLD
        )
    )


    audio_array[
        quiet_mask
    ] *= float(
        NOISE_GATE_ATTENUATION
    )


    audio_array = np.clip(
        audio_array,
        -32768.0,
        32767.0
    )


    audio_array = (
        audio_array.astype(
            np.int16
        )
    )


    return audio_array.tobytes()


# ============================================================
# AUDIO CAPTURE CALLBACK
# ============================================================

def audio_capture_callback(
    indata,
    frames,
    time_info,
    status
):

    if status:

        print(
            f"[AUDIO MIC] {status}"
        )


    if is_microphone_muted():
        return


    try:

        audio_data = (
            process_microphone_audio(
                indata
            )
        )

    except Exception as e:

        print(
            f"[AUDIO MIC] "
            f"Processing error: {e}"
        )

        return


    try:

        if audio_send_queue.full():

            audio_send_queue.get_nowait()

        audio_send_queue.put_nowait(
            audio_data
        )

    except (
        queue.Empty,
        queue.Full
    ):

        pass


# ============================================================
# AUDIO SENDER
# ============================================================

def audio_sender():

    global running

    sock = connect_with_retry(
        PEER_IP,
        SEND_AUDIO_PORT,
        "AUDIO SEND"
    )

    if sock is None:
        return


    stream = None


    try:

        # IMPORTANT:
        # Open the real stream here.
        # If selected device fails, retry candidates.

        stream = open_microphone_with_fallback()


        if stream is None:

            print(
                "[AUDIO SEND] "
                "No usable microphone."
            )

            return


        print()
        print(
            "[AUDIO SEND] "
            "Microphone active"
        )

        print(
            f"[AUDIO SEND] Device: "
            f"{audio_input_name}"
        )

        print(
            "[AUDIO SEND] "
            "48 kHz / mono / 960 samples"
        )


        while running:

            try:

                audio_data = (
                    audio_send_queue.get(
                        timeout=0.5
                    )
                )

            except queue.Empty:

                continue


            if is_microphone_muted():
                continue


            header = struct.pack(
                "!I",
                len(audio_data)
            )


            try:

                sock.sendall(header)
                sock.sendall(audio_data)

            except (
                BrokenPipeError,
                ConnectionResetError,
                OSError
            ) as e:

                print(
                    "[AUDIO SEND] "
                    f"Connection lost: {e}"
                )

                break


    except Exception as e:

        if running:

            print(
                f"[AUDIO SEND] Error: {e}"
            )


    finally:

        if stream is not None:

            try:
                stream.stop()
            except Exception:
                pass

            try:
                stream.close()
            except Exception:
                pass


        try:
            sock.close()
        except Exception:
            pass


        print(
            "[AUDIO SEND] Stopped"
        )


# ============================================================
# AUDIO RECEIVER
# ============================================================

def audio_receiver():

    global running

    server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    conn = None


    try:

        server.bind(
            (
                LOCAL_IP,
                RECEIVE_AUDIO_PORT
            )
        )

        server.listen(1)


        print(
            "[AUDIO RECV] Listening on "
            f"{LOCAL_IP}:{RECEIVE_AUDIO_PORT}"
        )


        conn, addr = server.accept()


        print(
            "[AUDIO RECV] Peer connected from "
            f"{addr[0]}:{addr[1]}"
        )


        expected_size = (
            AUDIO_BLOCKSIZE
            *
            AUDIO_CHANNELS
            *
            2
        )


        while running:

            header = recv_exact(
                conn,
                4
            )

            if header is None:
                break


            audio_size = struct.unpack(
                "!I",
                header
            )[0]


            if (
                audio_size <= 0
                or
                audio_size > 100000
            ):

                print(
                    "[AUDIO RECV] "
                    f"Invalid audio size: "
                    f"{audio_size}"
                )

                break


            audio_data = recv_exact(
                conn,
                audio_size
            )

            if audio_data is None:
                break


            if audio_size != expected_size:

                print(
                    "[AUDIO RECV] "
                    f"Unexpected packet size: "
                    f"{audio_size}"
                )

                continue


            try:

                if audio_play_queue.full():

                    audio_play_queue.get_nowait()

                audio_play_queue.put_nowait(
                    audio_data
                )

            except (
                queue.Empty,
                queue.Full
            ):

                pass


    except Exception as e:

        if running:

            print(
                f"[AUDIO RECV] Error: {e}"
            )


    finally:

        if conn is not None:

            try:
                conn.close()
            except Exception:
                pass

        server.close()

        print(
            "[AUDIO RECV] Stopped"
        )


# ============================================================
# AUDIO PLAYBACK CALLBACK
# ============================================================

def audio_playback_callback(
    outdata,
    frames,
    time_info,
    status
):

    if status:

        print(
            f"[AUDIO SPEAKER] {status}"
        )


    required_samples = (
        frames
        *
        AUDIO_CHANNELS
    )


    output = np.zeros(
        required_samples,
        dtype=np.int16
    )


    position = 0


    while position < required_samples:

        try:

            chunk = (
                audio_play_queue.get_nowait()
            )

        except queue.Empty:

            break


        chunk_array = np.frombuffer(
            chunk,
            dtype=np.int16
        )


        remaining = (
            required_samples
            -
            position
        )


        copy_count = min(
            len(chunk_array),
            remaining
        )


        output[
            position:
            position + copy_count
        ] = chunk_array[
            :copy_count
        ]


        position += copy_count


    output = output.reshape(
        frames,
        AUDIO_CHANNELS
    )


    outdata[:] = output


# ============================================================
# AUDIO PLAYBACK
# ============================================================

def audio_playback():

    global running

    try:

        print(
            "[AUDIO PLAY] "
            "Starting default speaker"
        )


        with sd.OutputStream(

            device=AUDIO_OUTPUT_DEVICE,

            samplerate=AUDIO_RATE,

            channels=AUDIO_CHANNELS,

            dtype=AUDIO_DTYPE,

            blocksize=AUDIO_BLOCKSIZE,

            latency="low",

            callback=audio_playback_callback

        ):

            print(
                "[AUDIO PLAY] "
                "Speaker active"
            )


            while running:

                time.sleep(0.1)


    except Exception as e:

        if running:

            print(
                f"[AUDIO PLAY] Error: {e}"
            )


# ============================================================
# MAIN
# ============================================================

def main():

    global running

    print("=" * 70)
    print(
        "QKMS VIDEO CONFERENCE - STAGE 3"
    )
    print(
        "ALICE - TWO-WAY VIDEO + AUDIO"
    )
    print(
        "AUTOMATIC MICROPHONE SELECTION"
    )
    print("=" * 70)


    print(
        f"Role              : {ROLE}"
    )

    print(
        f"Local IP          : {LOCAL_IP}"
    )

    print(
        f"Peer IP           : {PEER_IP}"
    )

    print(
        f"Video Send        : {SEND_VIDEO_PORT}"
    )

    print(
        f"Video Receive     : {RECEIVE_VIDEO_PORT}"
    )

    print(
        f"Audio Send        : {SEND_AUDIO_PORT}"
    )

    print(
        f"Audio Receive     : {RECEIVE_AUDIO_PORT}"
    )

    print(
        "Audio Input       : Automatic"
    )

    print(
        "Audio Output      : Default"
    )

    print(
        f"Audio Format      : "
        f"{AUDIO_RATE} Hz / "
        f"mono / "
        f"{AUDIO_BLOCKSIZE} samples"
    )

    print()


    threading.Thread(
        target=video_receiver,
        daemon=True
    ).start()

    time.sleep(0.5)


    threading.Thread(
        target=video_sender,
        daemon=True
    ).start()


    threading.Thread(
        target=audio_receiver,
        daemon=True
    ).start()

    time.sleep(0.5)


    threading.Thread(
        target=audio_sender,
        daemon=True
    ).start()


    threading.Thread(
        target=audio_playback,
        daemon=True
    ).start()


    print()
    print(
        "[SYSTEM] Video + audio conference started"
    )

    print(
        "[SYSTEM] Automatic microphone selection enabled"
    )

    print(
        "[SYSTEM] Priority:"
    )

    print(
        "         1. Bluetooth/Wireless"
    )

    print(
        "         2. External USB"
    )

    print(
        "         3. Logitech C270"
    )

    print(
        "         4. Built-in"
    )

    print(
        "[SYSTEM] Click MIC button to mute/unmute"
    )

    print(
        "[SYSTEM] Press Q to stop"
    )

    print()


    try:

        while running:

            local_frame = None
            remote_frame = None


            try:

                while True:

                    local_frame = (
                        local_frame_queue.get_nowait()
                    )

            except queue.Empty:

                pass


            try:

                while True:

                    remote_frame = (
                        remote_frame_queue.get_nowait()
                    )

            except queue.Empty:

                pass


            if local_frame is not None:

                local_display = (
                    draw_mic_button(
                        local_frame
                    )
                )

                cv2.imshow(
                    "Alice - Local Camera",
                    local_display
                )

                cv2.setMouseCallback(
                    "Alice - Local Camera",
                    microphone_mouse_callback
                )


            if remote_frame is not None:

                cv2.imshow(
                    "Bob - Remote Video",
                    remote_frame
                )


            key = (
                cv2.waitKey(1)
                &
                0xFF
            )


            if key == ord("q"):

                print(
                    "\n[SYSTEM] Q pressed"
                )

                running = False
                break


            time.sleep(0.001)


    except KeyboardInterrupt:

        print(
            "\n[SYSTEM] Keyboard interrupt"
        )

        running = False


    finally:

        running = False

        time.sleep(1)

        cv2.destroyAllWindows()

        print(
            "[SYSTEM] Alice conference stopped"
        )


# ============================================================
# START
# ============================================================

if __name__ == "__main__":

    main()
