# sender.py
import socket
import threading
import time

class PacketSender:
    def __init__(self, dest_ip, listener):
        self.dest_ip = dest_ip
        self.listener = listener  # instance of PortChangeListener in same process
        self.running = True

    def send_packets(self):
        while self.running:
            if self.listener.current_port:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(2)
                        s.connect((self.dest_ip, self.listener.current_port))
                        message = f"Hello to port {self.listener.current_port}"
                        s.sendall(message.encode())
                        print(f"Sent: {message}")
                except Exception as e:
                    print(f"Send error: {e}")
            else:
                print("No port selected yet.")
            time.sleep(2)  # send every 2 seconds

    def stop(self):
        self.running = False

if __name__ == "__main__":
    from port_listener import PortChangeListener

    listener = PortChangeListener()
    listener.start()

    sender = PacketSender(dest_ip='10.0.0.2', listener=listener)  # example dest IP
    sender_thread = threading.Thread(target=sender.send_packets)
    sender_thread.start()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        sender.stop()
        listener.stop()
        print("Sender and listener stopped.")
