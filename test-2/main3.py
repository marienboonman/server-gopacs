from fastapi import FastAPI, Request, Response, status, BackgroundTasks
from nacl.signing import VerifyKey, SigningKey
from nacl.encoding import Base64Encoder
import base64
import httpx
from lxml import etree
import xml.dom.minidom
import os
import uuid
import requests
from datetime import datetime
from datetime import timezone
from config import (
    GOPACS_PARTICIPANT_API, GOPACS_MESSAGE_BROKER,
    MY_DOMAIN, MY_ROLE, MY_PRIVATE_KEY_B64,
    OAUTH_TOKEN_URL, CLIENT_ID, CLIENT_SECRET,
    authdebug, senddebug
)



app = FastAPI()

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
        background_tasks.add_task(handle_flex_request, root)

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


"""
FUNC FOR MAIN BACKGROUND TASK
"""

async def handle_flex_request(root):
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    
    sender_domain = root.attrib["SenderDomain"]
    sender_role = root.attrib["SenderRole"]
    body_b64 = root.attrib["Body"]

    # Public key ophalen
    public_key_bytes = await get_public_key(sender_role, sender_domain)

    # Verify en inner XML extraheren
    incoming_message = verify_and_extract_inner_xml(body_b64, public_key_bytes)

    #SAVE INCOMING MESSAGE AND PRINT
    filename = 'messaging/{}_Request.xml'.format(datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
    with open(filename,'wb') as f:
        f.write(incoming_message)
        f.close()
    
    print('INCOMING MESSAGE SAVED:')
    print(xml.dom.minidom.parseString(incoming_message).toprettyxml())
    print('============')

    response_inner_bytes = construct_flex_response(incoming_message, timestamp)
    
    filename = 'messaging/{}_Response.xml'.format(datetime.now(timezone.utc).strftime('%Y%m%d%H%M%SZ'))
    with open(filename,'wb') as f:
        f.write(incoming_message)
        f.close()
    
    print('OUTGOING MESSAGE SAVED:')
    print(xml.dom.minidom.parseString(response_inner_bytes).toprettyxml())
    print('============')


    token = await get_oauth_token(CLIENT_ID, CLIENT_SECRET)
    print('STATUS: Received token')
    if authdebug:
        print('RESPONSE INNER BYTES')
        print(response_inner_bytes.decode("utf-8"))
        print('============')
    signed_response_body = sign_message(response_inner_bytes)
    print('STATUS: Response is signed')
    await send_signed_message(signed_response_body, token,recipient_domain,"AGR")


"""
FUNCS FOR INCOMING MESSAGE
"""

def verify_and_extract_inner_xml(body_b64: str, public_key_bytes: bytes) -> bytes:
    """
    Decodeer Body (base64) en verifieer libsodium-signature,
    retourneer de inner XML bytes (bijv. <FlexRequest>…</FlexRequest>).
    """
    signed_bytes = base64.b64decode(body_b64)
    verify_key = VerifyKey(public_key_bytes)
    inner_xml = verify_key.verify(signed_bytes)
    return inner_xml


"""
FUNCS FOR OUTGOING MESSAGE
"""
def construct_flex_response(incoming_message: str, timestamp: str) -> str:
        # Parse inner XML en extract waarden om te gebruiken in response
    incoming_message_root = etree.XML(incoming_message)
    msg_type = etree.QName(incoming_message_root.tag).localname
    version = incoming_message_root.attrib["Version"]
    sender_domain = incoming_message_root.attrib["SenderDomain"]
    recipient_domain = incoming_message_root.attrib["RecipientDomain"]
    conversation_id = incoming_message_root.attrib["ConversationID"]
    flex_req_msg_id = incoming_message_root.attrib["MessageID"]
    
    # Bouw response op
    flex_resp = etree.Element(
        "FlexRequestResponse",
        Version=version,
        SenderDomain=recipient_domain,   # nu ben JIJ de afzender (AGR)
        RecipientDomain=sender_domain,   # en de DSO de ontvanger
        TimeStamp=timestamp,                   # TODO: nu-tijd in UTC
        MessageID= str(uuid.uuid4()),    # TODO: echte UUID genereren
        ConversationID=conversation_id,
        Result="Accepted",
        FlexRequestMessageID=flex_req_msg_id,
    )

    response_inner_bytes = etree.tostring(
        flex_resp, xml_declaration=True, encoding="UTF-8", standalone="yes"
    )
    return response_inner_bytes

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
    if senddebug:
        print("OUTGOING MESSAGE: ")
        print(xml_bytes.decode("utf-8"))
    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "application/xml",
        "Accept": "application/json",
    }
    if senddebug:    
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

"""
FUNCS FOR AUTHORISATION
"""

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
