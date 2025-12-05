from fastapi import FastAPI, Request, Response, status
from nacl.signing import VerifyKey, SigningKey
from nacl.encoding import Base64Encoder
import base64
import httpx
from lxml import etree
import os
from datetime import datetime
from datetime import timezone
from config import (
    GOPACS_PARTICIPANT_API, GOPACS_MESSAGE_BROKER,
    MY_DOMAIN, MY_ROLE, MY_PRIVATE_KEY_B64,
    OAUTH_TOKEN_URL, CLIENT_ID, CLIENT_SECRET, MY_PUBLIC_KEY
)

app = FastAPI()
GOPACS_MESSAGE_BROKER = "http://enexis.energyfact.nl:9000/shapeshifter/api/v3/message"

async def get_oauth_token() -> str:
    return "LOCAL-TEST-TOKEN"
    """Vraag een Bearer token op via client credentials flow (zoals GOPACS voorschrijft)."""


async def get_public_key(sender_role: str, sender_domain: str, MY_PUBLIC_KEY: str) -> bytes:
    """
    Eigen public key als mock netbeheerder
    """
    public_key_b64 = MY_PUBLIC_KEY
    return base64.b64decode(public_key_b64)

def extract_inner_xml_bytes(raw_xml_bytes: bytes) -> bytes:
    start = raw_xml_bytes.index(b'>') + 1
    end = raw_xml_bytes.rindex(b'<')
    return raw_xml_bytes[start:end]

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
    return inner_xml

def sign_inner_xml(inner_xml: bytes) -> str:
    """
    Sign inner XML met jouw private key en retourneer base64-encoded SignedMessage Body.
    """
    priv = base64.b64decode(MY_PRIVATE_KEY_B64)
    signing_key = SigningKey(priv[:32])  # Ed25519 seed
    signed = signing_key.sign(inner_xml)
    return base64.b64encode(signed).decode("ascii")

async def send_signed_message(inner_xml: bytes, bearer_token: str):
    """
    Stuur een SignedMessage (met jouw domain/role) naar de GOPACS message broker.
    """
    body_b64 = sign_inner_xml(inner_xml)

    signed_msg = etree.Element(
        "SignedMessage",
        SenderDomain=MY_DOMAIN,
        SenderRole=MY_ROLE,
        Body=body_b64,
    )
    xml_bytes = etree.tostring(
        signed_msg, xml_declaration=True, encoding="UTF-8", standalone="yes"
    )

    headers = {
        "Authorization": f"Bearer {bearer_token}",
        "Content-Type": "text/xml",
        "Accept": "application/json",
    }

    async with httpx.AsyncClient() as client:
        r = await client.post(GOPACS_MESSAGE_BROKER, headers=headers, content=xml_bytes)
        r.raise_for_status()
        return r

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
        MessageID="REPLACE-WITH-UUID",                 # TODO: echte UUID genereren
        ConversationID=conversation_id,
        Result="Accepted",
        FlexRequestMessageID=flex_req_msg_id,
    )

    inner_bytes = etree.tostring(
        flex_resp, xml_declaration=True, encoding="UTF-8", standalone="yes"
    )

    token = await get_oauth_token()
    await send_signed_message(inner_bytes, token)


@app.post("/shapeshifter/api/v3/message")
async def uftp_endpoint(request: Request):
    """
    Jouw UFTP endpoint.
    """
    raw_body = await request.body()   # <-- bytes, niet aanpassen!

    try:
        # -------------------------------------------------------
        # 1) Alleen de ATTRIBUTEN van SignedMessage lezen
        #    (inner XML niet parsen!)
        # -------------------------------------------------------
        root = etree.fromstring(raw_body)

        localname = etree.QName(root.tag).localname
        if localname != "SignedMessage":
            return Response(
                status_code=status.HTTP_400_BAD_REQUEST,
                content="Expected SignedMessage root element",
            )

        sender_domain = root.attrib["SenderDomain"]
        sender_role = root.attrib["SenderRole"]
        body_b64 = root.attrib["Body"]  # bevat base64(SIGNATURE || XML)

        # -------------------------------------------------------
        # 2) Public key ophalen
        # -------------------------------------------------------
        public_key_bytes = await get_public_key(sender_role, sender_domain)


        # -------------------------------------------------------
        # 3) Body verify → inner XML bytes terug
        # -------------------------------------------------------
        inner_xml_bytes = verify_and_extract_inner_xml(body_b64, public_key_bytes)
        print('INNER XML BYTES: {}'.format(inner_xml_bytes))

                # -------------------------------------------------------
        # 4) NU pas inner XML parsen
        # -------------------------------------------------------
        inner_root = etree.XML(inner_xml_bytes)
        print('INNER ROOT: {}'.format(inner_root))
        msg_type = etree.QName(inner_root.tag).localname
        print('MSG TYPE: {}'.format(msg_type))
        # -------------------------------------------------------
        # 5) Verwerken op basis van type
        # -------------------------------------------------------
        if msg_type == "FlexRequest":
            await handle_flex_request(inner_root)

        return Response(status_code=status.HTTP_200_OK)

    except Exception as e:
        return Response(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=f"Bad Request: {e}",
        )


'''
@app.post("/shapeshifter/api/v3/message")
async def uftp_endpoint(request: Request):
    """
    Jouw UFTP endpoint.
    - ontvangt SignedMessage
    - verifieert afzender
    - decodeert inner message (bijv. FlexRequest)
    - stuurt HTTP 200 OK als technische ack
    - stuurt (asynchroon) een FlexRequestResponse terug
    """
    raw_body = await request.body()

    try:
        root = etree.fromstring(raw_body)
        if root.tag != "SignedMessage":
            return Response(
                status_code=status.HTTP_400_BAD_REQUEST,
                content="Expected SignedMessage root element",
            )

        sender_domain = root.attrib["SenderDomain"]
        sender_role = root.attrib["SenderRole"]  # DSO of AGR
        body_b64 = root.attrib["Body"]

        # 1) public key ophalen en inner XML verifiëren
        public_key_bytes = await get_public_key(sender_role, sender_domain)
        inner_xml = verify_and_extract_inner_xml(body_b64, public_key_bytes)

        # 2) inner XML parsen om te zien wat voor bericht het is
        inner_root = etree.fromstring(inner_xml)
        msg_type = inner_root.tag  # FlexRequest, FlexOrder, TestMessage, ...

        # Voorbeeld: bij FlexRequest meteen een FlexRequestResponse "Accepted" maken
        if msg_type == "FlexRequest":
            await handle_flex_request(inner_root)

        # Altijd HTTP 200 OK als het bericht technisch goed was
        return Response(status_code=status.HTTP_200_OK)

    except Exception as e:
        # Bij parsing/validatie fouten een 400 teruggeven (zoals GOPACS ook doet) :contentReference[oaicite:1]{index=1}
        return Response(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=f"Bad Request: {e}",
        )
'''