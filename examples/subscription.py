import json
import time
import ssl
from threading import Thread

from aciClient import ACI
import websocket


def on_message(ws, message):
    print("Websocket received a message")
    # Message contains the data transmited from ACI in plaintext
    print(json.loads(message)["imdata"])


def on_close(ws, close_status_code, close_msg):
    print("Websocket was closed")


def on_open(ws):
    print("Websocket was opened")


def open_websocket(ip: str, token: str):
    ws = websocket.WebSocketApp(
        f"wss://{ip}/socket{token}",
        on_message=on_message,
        on_open=on_open,
        on_close=on_close,
    )
    ws.run_forever(sslopt={"cert_reqs": ssl.CERT_NONE})


def main():
    hostname = "sandboxapicdc.cisco.com"
    username = "admin"
    password = "!v3G@!4@Y"

    aci = ACI(hostname, username, password)

    # Login to ACI
    aci.login()

    # Open websocket to ACI with the login token

    Thread(target=open_websocket, args=(aci.apicIp, aci.token)).start()
    time.sleep(5)

    # Subscribe to an ACI object
    endpoint = "node/class/faultInst.json"
    timeout = 60  # Optional. Default value in ACI
    query_parameters = "order-by=faultInst.lastTransition|asc"  # Optional

    response = aci.subscribe(
        uri=f"{endpoint}?{query_parameters}",
        timeout=timeout,
    )

    subscription_id = response["subscriptionId"]
    initial_data = response["imdata"]

    print(f"Got {len(initial_data)} objects in initial call.")

    while True:
        time.sleep(30)
        print("Refreshing subscription")
        aci.subscription_refresh(subscription_id=subscription_id)


if __name__ == "__main__":
    main()
