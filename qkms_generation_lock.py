
"""Shared in-process lock for every API entry point that starts BB84."""

import threading

# Prevent two BB84 generation operations from running simultaneously.
BB84_GENERATION_LOCK = threading.Lock()
