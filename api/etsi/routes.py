#!/usr/bin/env python3

"""
ETSI QKD REST API
"""

from fastapi import APIRouter
from protocol_manager import execute_protocol
from database.key_manager import (
    latest_key,
    get_key,
    list_active_keys
)
router = APIRouter(
    prefix="/etsi/v1",
    tags=["ETSI QKD API"]
)


@router.get("/status")
def etsi_status():

    return {

        "vendor": "Pradum QKMS",

        "version": "1.0",

        "service": "Quantum Key Management System",

        "protocol": "BB84",

        "status": "ACTIVE"

    }
@router.get("/keys/latest")
def latest():

    return {
        "key": latest_key()
    }


@router.get("/keys")
def active():

    return {
        "keys": list_active_keys()
    }


@router.get("/keys/{key_id}")
def key(key_id: int):

    return {
        "key": get_key(key_id)
    }


@router.post("/keys/generate")
def generate():

    success = execute_protocol("BB84")

    if not success:

        return {
            "status": "FAILED"
        }

    return {

        "status": "SUCCESS",

        "protocol": "BB84",

        "key": latest_key()

    }
