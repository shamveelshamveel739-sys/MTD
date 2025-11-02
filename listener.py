# port_listener.py
import socket
import threading

class PortChangeListener:
    def __init__(self, listen_ip='0.0.0.0', listen_port=9999):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.current_port = None
        self._stop_event = threading.Event()

    def start(self):
        self._stop_event.clear()
        t = threading.Thread(target=self._server_thread)
        t.daemon = True
        t.start()
        print(f"Port change listener started on {self.listen_ip}:{self.listen_port}")

    def stop(self):
        self._stop_event.set()

    def _server_thread(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.listen_ip, self.listen_port))
            s.listen()
            s.settimeout(1.0)
            while not self._stop_event.is_set():
                try:
                    conn, addr = s.accept()
                    with conn:
                        data = conn.recv(1024)
                        if data:
                            new_port = data.decode().strip()
                            print(f"Received new port notification: {new_port}")
                            self._handle_port_update(new_port)
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Socket error: {e}")

    def _handle_port_update(self, new_port):
        self.current_port = int(new_port)
        print(f"Updated sending port to: {self.current_port}")

if __name__ == "__main__":
    listener = PortChangeListener()
    listener.start()
    try:
        while True:
            pass
    except KeyboardInterrupt:
        listener.stop()
        print("Listener stopped.")
