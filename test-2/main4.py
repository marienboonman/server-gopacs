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
from datetime import timedelta
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
        sender_domain = root.attrib["SenderDomain"]
        sender_role = root.attrib["SenderRole"]
        body_b64 = root.attrib["Body"]

        print('OBJECTTYPE: ', type(root))
        #print(root)
        #print('===============')
        #print(xml.dom.minidom.parseString(base64.b64decode(body_b64)).toprettyxml())
        #print(root.toprettyxml()) #NEEDS FIXING


        # Public key ophalen
        public_key_bytes = await get_public_key(sender_role, sender_domain)

        # Verify en inner XML extraheren
        incoming_message = verify_and_extract_inner_xml(body_b64, public_key_bytes)

        incoming_message_name = etree.QName(incoming_message.tag).localname
        print('LOCAL NAME: ', incoming_message_name)
        #print([elem.tag for elem in etree.XML(incoming_message).iter()])
        #print(etree.XML(incoming_message).attrib["SignedMessage"])
        print('INCOMING MESSAGE RECEIVED:')
        printable = etree.tostring(incoming_message, pretty_print=True)
        print(printable)
        del printable
        print(incoming_message)
        print('============')

        if incoming_message_name == "FlexRequest":
#            return Response(
#                status_code=status.HTTP_400_BAD_REQUEST,
#                content="Expected SignedMessage root element",
#            )

            # Background task process_signed_message
            background_tasks.add_task(handle_flex_request, incoming_message)

            # Onmiddellijke confirmatie aan GOPACS:
            
            return Response(
                status_code=200,
                content="SignedMessage received"
            )

        if localname == "FlexOfferResponse":
#            return Response(
#                status_code=status.HTTP_400_BAD_REQUEST,
#                content="Expected SignedMessage root element",
#            )

            # Background task process_signed_message
            background_tasks.add_task(handle_flex_offer_response, incoming_message)

            # Onmiddellijke confirmatie aan GOPACS:
            
            return Response(
                status_code=200,
                content="FlexOfferResponse received"
            )

    except Exception as e:
        return Response(
            status_code=400,
            content=f"Bad Request: {e}"
        )

"""
FUNC FOR MAIN BACKGROUND TASK
"""

async def handle_flex_request(FlexRequest):
    
    #haal my_domain uit incoming message 
    #print(type(incoming_message))
    my_domain = FlexRequest.attrib["RecipientDomain"]
    print(my_domain)
    #SAVE INCOMING MESSAGE AND PRINT
    requestTimeStamp = FlexRequest.attrib["TimeStamp"]
    filename = 'messaging/{}_Request.xml'.format(requestTimeStamp)
    with open(filename,'wb') as f:
        f.write(etree.tostring(FlexRequest,pretty_print = True))
        f.close()
    
    #print('OBJECTTYPE: ', type(incoming_message))

    print('INCOMING FlexRequest MESSAGE SAVED:')
    printable = etree.tostring(FlexRequest, pretty_print=True)
    print(printable)
    del printable
    print('============')


    FlexRequestResponse = construct_flex_request_response(FlexRequest)
    responseTimeStamp = FlexRequestResponse.attrib["TimeStamp"]
    filename = 'messaging/{}_Response.xml'.format(responseTimeStamp)
    with open(filename,'wb') as f:
        f.write(etree.tostring(FlexRequestResponse,pretty_print = True))
        f.close()
    
    print('OBJECTTYPE: ', type(response_inner_bytes))

    print('OUTGOING FlexRequestResponse SAVED:')
    printable = etree.tostring(FlexRequestResponse,pretty_print = True)
    print(printable)
    del printable
    print('============')


    token = await get_oauth_token(CLIENT_ID, CLIENT_SECRET)
    print('STATUS: Received token')

    response_inner_bytes = etree.tostring(
        FlexRequestResponse, xml_declaration=True, encoding="UTF-8", standalone="yes")

    if authdebug:
        print('RESPONSE INNER BYTES')
        print(response_inner_bytes.decode("utf-8"))
        print('============')

    signed_response_body = sign_message(response_inner_bytes)
    print('STATUS: Response is signed')
    print('OBJECTTYPE: ', type(signed_response_body))
    await send_signed_message(signed_response_body, token,my_domain,"AGR")
    
    FlexOffer = construct_flex_offer(FlexRequest)
    print('FLEXOFFER:')
    printable = etree.tostring(FlexOffer,pretty_print = True)
    print(printable)
    del printable
    print('============')

    FlexOfferBytes = etree.tostring(
        FlexOffer, xml_declaration=True, encoding="UTF-8", standalone="yes")
    signed_flex_offer = sign_message(FlexOfferBytes)
    await send_signed_message(signed_flex_offer, token, my_domain,"AGR")
    #await send_flexoffer()

async def handle_flex_offer_response(FlexOfferResponse):
    
    #haal my_domain uit incoming message 
    my_domain = FlexOfferResponse.attrib["RecipientDomain"]

    #SAVE INCOMING MESSAGE AND PRINT
    OfferResponseTimeStamp = FlexOfferResponse.attrib["TimeStamp"]
    filename = 'messaging/{}_FlexOfferResponse.xml'.format(FlexOfferResponseTimeStamp)
    with open(filename,'wb') as f:
        f.write(etree.tostring(FlexOfferResponse,pretty_print = True))
        f.close()
    
    #print('OBJECTTYPE: ', type(incoming_message))

    print('INCOMING FelxOfferResponse MESSAGE SAVED:')
    printable = etree.tostring(FlexOfferResponse,pretty_print = True)
    print(printable)
    del printable
    print('============')



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
    return etree.XML(inner_xml)

"""
OUTGOING MESSAGE HANDLING
"""

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
MESSAGE BUILDING
"""
def construct_flex_request_response(FlexRequest: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        # Parse inner XML en extract waarden om te gebruiken in response
    #incoming_message_root = etree.XML(incoming_message)
    #msg_type = etree.QName(incoming_message_root.tag).localname
    version =FlexRequest.attrib["Version"]
    sender_domain = FlexRequest.attrib["SenderDomain"]
    recipient_domain = FlexRequest.attrib["RecipientDomain"]
    conversation_id = FlexRequest.attrib["ConversationID"]
    flex_req_msg_id = FlexRequest.attrib["MessageID"]
    
    # Bouw response op
    FlexRequestResponse = etree.Element(
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


    return FlexRequestResponse

def construct_flex_offer(FlexRequest: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    expiration = (datetime.now(timezone.utc)+timedelta(hours = 1)).strftime('%Y-%m-%dT%H:%M:%SZ')

        # Parse inner XML en extract waarden om te gebruiken in response
    #incoming_message_root = etree.XML(incoming_message)
    #msg_type = etree.QName(incoming_message_root.tag).localname
    version = FlexRequest.attrib["Version"]
    sender_domain = FlexRequest.attrib["SenderDomain"]
    recipient_domain = FlexRequest.attrib["RecipientDomain"]
    conversation_id = FlexRequest.attrib["ConversationID"]
    flex_req_msg_id = FlexRequest.attrib["MessageID"]
    
    # Bouw flexoffer op
    #flex_option = etree.Element(
    #)

    flex_resp = etree.Element("FlexOffer",
        Version=version,
        SenderDomain=recipient_domain,   # nu ben JIJ de afzender (AGR)
        RecipientDomain=sender_domain,   # en de DSO de ontvanger
        TimeStamp=timestamp,                   # TODO: nu-tijd in UTC
        MessageID= str(uuid.uuid4()),    # TODO: echte UUID genereren
        ConversationID=conversation_id,
        
        TimeZone = FlexRequest.attrib["TimeZone"],
        Period = FlexRequest.attrib["Period"],
        CongestionPoint = FlexRequest.attrib["CongestionPoint"],
        ExpirationDateTime= expiration,
        FlexRequestMessageID=flex_req_msg_id,
        ContractID = FlexRequest.attrib["ContractID"],
        BaselineReference = "",
        Currency="EUR",
    )
    flex_resp.set("ISP-Duration", FlexRequest.attrib["ISP-Duration"])

    OfferOption = etree.SubElement(flex_resp, "OfferOption")
    OfferOption.set('OptionReference',str(uuid.uuid4()))
    OfferOption.set('Price','0.00')

    for elem in incoming_message_root:
        if elem.tag == 'ISP':
            isp = etree.SubElement(OfferOption, "ISP")
            isp.set('Start',elem.attrib["Start"])
            isp.set('Duration',elem.attrib["Duration"])
            isp.set('Power',elem.attrib["MaxPower"])


    #response_inner_bytes = etree.tostring(
    #    flex_resp, xml_declaration=True, encoding="UTF-8", standalone="yes"
    #)
    return FlexOffer



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
