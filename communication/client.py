#!/usr/bin/env python3

# =============================================================================
#
# Quantum Key Management System (QKMS)
#
# File        : client.py
#
# Description :
# -----------------------------------------------------------------------------
# TCP client used by the Alice QKMS to communicate with the Bob Agent.
#
# =============================================================================

import socket

from config.config import BOB_IP
from config.config import BOB_AGENT_PORT
from config.config import BUFFER_SIZE
from config.config import ENCODING

from utils.logger import logger


def send_command(command):

    logger.info(f"Connecting to Bob Agent ({BOB_IP}:{BOB_AGENT_PORT})")

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:

        client.connect((BOB_IP, BOB_AGENT_PORT))

        logger.info(f"Sending command : {command}")

        client.send(command.encode(ENCODING))

        response = client.recv(BUFFER_SIZE).decode(ENCODING)

        logger.info(f"Response : {response}")

        client.close()

        return response

    except Exception as error:

        logger.error(f"Communication Error : {error}")

        return "FAILED"
