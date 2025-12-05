from fastapi import FastAPI, Request
import base64
from lxml import etree
from nacl.signing import VerifyKey

app = FastAPI()

public_key_bytes =base64.b64decode("qkCIC6PGTHmlsUNFe5REGugcvW0roiHJ6cO8KEcq694=")

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


@app.post("/shapeshifter/api/v3/message")
async def receive_signed_message(request: Request):
    body = await request.body()
    print("📩 BERICHT BINNEN (mock broker):")
    print(body.decode())
    root = etree.fromstring(body)
    body_b64 = root.attrib["Body"]
    inner_xml_bytes = verify_and_extract_inner_xml(body_b64, public_key_bytes)
    print("📩 BERICHT UITGEPAKT (mock broker):")
    print(inner_xml_bytes)
    # Altijd HTTP 200 OK teruggeven — net als de echte broker
    return {"status": "OK"}

