import requests
import time

controller_ip = '10.0.2.2'  # Replace with your controller's IP accessible from h1 (often Mininet VM default gateway)
controller_port = 8080       # Default Ryu REST API port
receiver_ip = '10.0.0.2'     # Receiver host IP (e.g., h2 in Mininet)

while True:
    try:
        resp = requests.get(f'http://{controller_ip}:{controller_port}/getport', timeout=5)
        port = int(resp.text)
        print(f"Current allowed port: {port}")
        # You can place your sending code here, e.g. TCP client sending to receiver_ip:port
        # For demo, just print; see below for example send logic.
    except Exception as e:
        print(f"Failed to get port: {e}")
    time.sleep(5)
