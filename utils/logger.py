#!/usr/bin/env python3

# =============================================================================
#
# Quantum Key Management System (QKMS)
#
# File        : logger.py
#
# Author      : Pradum
#
# Description :
# -----------------------------------------------------------------------------
# Central logging module for the Distributed Quantum Key Management System.
#
# All QKMS components use this logger instead of print().
#
# Logs are displayed on the terminal and also stored inside:
#
#     qkms/logs/qkms.log
#
# =============================================================================

import logging
import os

from config.config import LOG_DIRECTORY

# =============================================================================
# Create log directory if it does not exist
# =============================================================================

os.makedirs(LOG_DIRECTORY, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIRECTORY, "qkms.log")

# =============================================================================
# Create Logger
# =============================================================================

logger = logging.getLogger("QKMS")

logger.setLevel(logging.INFO)

# Prevent duplicate handlers
if not logger.handlers:

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    # Console output
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    # File output
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
