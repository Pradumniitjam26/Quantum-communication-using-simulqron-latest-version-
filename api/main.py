#!/usr/bin/env python3

"""
Quantum Key Management System
REST API
"""

from fastapi import FastAPI
from api.routes.key_routes import router
from api.etsi.routes import router as etsi_router

app = FastAPI(

    title="Quantum Key Management System",

    version="1.0"

)

app.include_router(router)     # <-- ADD THIS LINE HERE
app.include_router(etsi_router)
@app.get("/")
def home():

    return {

        "project": "Quantum Key Management System",

        "version": "1.0",

        "status": "Running"

    }


@app.get("/status")
def status():

    return {

        "service": "QKMS",

        "state": "ACTIVE"

    }
