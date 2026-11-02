# QKMS controlled key-rotation standalone module

- Rotation interval: 300 seconds (5 minutes), measured with `time.monotonic()`.
- Method: controlled two-phase reconnect state (`prepare`, authenticated ACK, `commit`).
- Control authentication: HKDF-SHA256 derives a separate 32-byte HMAC-SHA256 key from the locally held 256-bit BB84 key and the proposed session ID. The raw BB84 key is never put on the wire.
- `rotation_security.py` deliberately does not open sockets, pause media, query the QKMS DB/API, or change Alice/Bob globals. Those operations must be integrated against the exact current endpoint implementations.

Run tests:

```bash
python3 -m pip install cryptography
python3 -m unittest discover -s tests -v
```

This is a tested standalone primitive, not yet an end-to-end Alice/Bob rotation implementation.
