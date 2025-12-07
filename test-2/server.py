from fastapi import FastAPI, Request, Response, status, BackgroundTasks
from lxml import etree
from server_funcs import process_signed_message

'''
from nacl.signing import VerifyKey, SigningKey
from nacl.encoding import Base64Encoder
import base64
import httpx

import os
import uuid
import requests
from datetime import datetime
from datetime import timezone
from config import (
    GOPACS_PARTICIPANT_API, GOPACS_MESSAGE_BROKER,
    MY_DOMAIN, MY_ROLE, MY_PRIVATE_KEY_B64,
    OAUTH_TOKEN_URL, CLIENT_ID, CLIENT_SECRET
)
'''

@app.post("/shapeshifter/api/v3/message")
async def uftp_endpoint(request: Request, background_tasks: BackgroundTasks):
    raw_body = await request.body()
    print("STATUS: Raw body received")

    try:
        root = etree.fromstring(raw_body)
        localname = etree.QName(root.tag).localname

        if localname != "SignedMessage":
            return Response(
                status_code=status.HTTP_400_BAD_REQUEST,
                content="Expected SignedMessage root element",
            )

        # Background task process_signed_message
        background_tasks.add_task(process_signed_message, root)

        # Onmiddellijke confirmatie aan GOPACS:
        return Response(
            status_code=200,
            content="SignedMessage received"
        )

    except Exception as e:
        return Response(
            status_code=400,
            content=f"Bad Request: {e}"
        )
