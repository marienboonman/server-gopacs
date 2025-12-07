from fastapi import FastAPI, Request, Response, status, BackgroundTasks
from nacl.signing import VerifyKey, SigningKey
from nacl.encoding import Base64Encoder
import base64
import httpx
from lxml import etree
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


app = FastAPI()

async def get_oauth_token(CLIENT_ID: str, CLIENT_SECRET: str) -> str:
    """Vraag een Bearer token op via client credentials flow (zoals GOPACS voorschrijft)"""
    data = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    async with httpx.AsyncClient() as client:
        r = await client.post(OAUTH_TOKEN_URL, data=data)
        r.raise_for_status()
        #print('BEARER TOKEN')
        #print(r.json()['access_token'])
        #print('==============')
        return r.json()["access_token"]

async def get_public_key(sender_role: str, sender_domain: str) -> bytes:
    """
    Gebruik Haal publicKey van de afzender op via Participant API.
    /v2/participants/{role}/{domain}  → publicKey (base64)
    """
    url = f"{GOPACS_PARTICIPANT_API}/{sender_role}/{sender_domain}"
    async with httpx.AsyncClient() as client:
        r = await client.get(url)
        r.raise_for_status()
        data = r.json()
        public_key_b64 = data["publicKey"]
        return base64.b64decode(public_key_b64)


def verify_and_extract_inner_xml(body_b64: str, public_key_bytes: bytes) -> bytes:
    """
    Decodeer Body (base64) en verifieer libsodium-signature,
    retourneer de inner XML bytes (bijv. <FlexRequest>…</FlexRequest>).
    """
    signed_bytes = base64.b64decode(body_b64)
    #print("DEBUG verify() signed_bytes len:", len(signed_bytes))
    #print("DEBUG PUBLIC KEY USED:", base64.b64encode(public_key_bytes).decode())
    #print("DEBUG BODY B64 RECEIVED:", body_b64)
    verify_key = VerifyKey(public_key_bytes)
    inner_xml = verify_key.verify(signed_bytes)
    #print("DEBUG INNER XML BYTES (returned by verify):", inner_xml)
    with open("Received {}.xml".format(datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')), "wb") as f:
        f.write(inner_xml)
        f.close()
    return inner_xml


def sign_message(inner_xml: bytes) -> str:
    """
    Sign inner XML met jouw private key en retourneer base64-encoded SignedMessage Bod>
    """
    priv = base64.b64decode(MY_PRIVATE_KEY_B64)
    signing_key = SigningKey(priv[:32])  # Ed25519 seed
    signed = signing_key.sign(inner_xml)
    return base64.b64encode(signed).decode("ascii")

async def send_signed_message(body_b64: bytes, bearer_token: str,MY_DOMAIN,MY_ROLE):
    signed_msg = etree.Element(
        "SignedMessage",
        SenderDomain=MY_DOMAIN,
        SenderRole=MY_ROLE,
        Body=body_b64,
    )
    #body_tag = etree.SubElement(signed_msg, "Body")
    #body_tag_text = body_b64

    xml_bytes = etree.tostring(
        signed_msg, xml_declaration=True, encoding="UTF-8", standalone="yes"
    )
    print("OUTGOING MESSAGE: ")
    print(xml_bytes.decode("utf-8"))
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/xml",
        "Accept": "application/json",
    }
    print('STATUS: message ready to send')
    print('STATUS: sending to: ', GOPACS_MESSAGE_BROKER)
    print('HEADERS')
    print(headers)
    print('==============')
    print('CONTENT')
    print(xml_bytes)
    print('==============')
    r = requests.post(GOPACS_MESSAGE_BROKER,xml_bytes, headers = headers)
    print(r)
    print(r.text)

async def handle_flex_request(flex_request_root: etree._Element):
    """
    Bouw en verstuur een FlexRequestResponse (functionele ack) terug naar de DSO.
    """
    now = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    version = flex_request_root.attrib["Version"]
    sender_domain = flex_request_root.attrib["SenderDomain"]
    recipient_domain = flex_request_root.attrib["RecipientDomain"]
    conversation_id = flex_request_root.attrib["ConversationID"]
    flex_req_msg_id = flex_request_root.attrib["MessageID"]

    # Simpel: altijd "Accepted" – hier kun je later je eigen business rules toevoegen.
    flex_resp = etree.Element(
        "FlexRequestResponse",
        Version=version,
        SenderDomain=recipient_domain,   # nu ben JIJ de afzender (AGR)
        RecipientDomain=sender_domain,   # en de DSO de ontvanger
        TimeStamp=now, # TODO: nu-tijd in UTC
        MessageID= str(uuid.uuid4()), # TODO: echte UUID genereren
        ConversationID=conversation_id,
        Result="Accepted",
        FlexRequestMessageID=flex_req_msg_id,
    )

    inner_bytes = etree.tostring(
        flex_resp, xml_declaration=True, encoding="UTF-8", standalone="yes"
    )

    token = await get_oauth_token(CLIENT_ID, CLIENT_SECRET)
    print('STATUS: Received token')
    print('RESPONSE INNER BYTES')
    print(inner_bytes.decode("utf-8"))
    print('============')
    signed_body = sign_message(inner_bytes)
    await send_signed_message(signed_body, token,recipient_domain,"AGR")

async def process_signed_message(root):
    sender_domain = root.attrib["SenderDomain"]
    sender_role = root.attrib["SenderRole"]
    body_b64 = root.attrib["Body"]

    # Public key ophalen
    public_key_bytes = await get_public_key(sender_role, sender_domain)

    # Verify en inner XML extraheren
    inner_xml_bytes = verify_and_extract_inner_xml(body_b64, public_key_bytes)
    with open('test.xml','wb') as f:
        f.write(inner_xml_bytes)
        f.close()
    # Parse inner XML
    inner_root = etree.XML(inner_xml_bytes)
    msg_type = etree.QName(inner_root.tag).localname

    # FlexRequest verwerken
    if msg_type == "FlexRequest":
        await handle_flex_request(inner_root)

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
