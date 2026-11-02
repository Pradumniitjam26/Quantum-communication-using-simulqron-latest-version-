#!/usr/bin/env python3

# =============================================================================
#
# Quantum Key Management System (QKMS)
#
# File : protocol_manager.py
#
# Description :
# Dispatcher for all supported QKD protocols.
#
# =============================================================================

from protocols.bb84.bb84_manager import execute_bb84


def execute_protocol(protocol_name):

    protocol = protocol_name.upper()

    if protocol == "BB84":

        return execute_bb84()

    elif protocol == "E92":

        print("\nE92 is under development.\n")

        return False

    elif protocol == "CVQKD":

        print("\nCVQKD is under development.\n")

        return False

    else:

        print("\nUnknown Protocol.\n")

        return False
