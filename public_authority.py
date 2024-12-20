import socket
import struct
import ssl
from des import Des
from rsa import RSA_Algorithm
from typing import Tuple
import threading
import json
import time

Local_keys = ""
client_Keys = ""

class RSAPair():
    def __init__(self) -> None:
        self.public_key: tuple[int, int] = None
        self.private_key: tuple[int, int] = None


class PublicAuthority():
    def __init__(self) -> None:
        self.host               = socket.gethostname()
        self.port               = 5022
        self.server_socket      = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.local_keys         = ""
        self.client_keys:bytes  = ""
        self.DES                = Des()
        self.RSA                = RSA_Algorithm()
        self.local_RSA          = RSAPair()
        self.store: dict[str, RSAPair] = {}
        self.client_counter     = 0 
        self.lock               = threading.Lock()

    def pack_tuple(self, int_tuple: tuple[int, int]) -> bytes:
        return struct.pack('qq', *int_tuple) 

    def unpack_tuple(self, packed_data: bytes) -> tuple[int, int]:
        return struct.unpack('qq', packed_data)
    
    def pack_rsa(self, encrypted_message):
        return struct.pack(f'<{len(encrypted_message)}Q', *encrypted_message)

    def unpack_rsa(packed_message):
        num_integers = len(packed_message) // 8 
        return list(struct.unpack(f'<{num_integers}Q', packed_message))

    def start_server_socket(self):
        self.server_socket.bind((self.host, self.port)) 
        self.server_socket.listen(2)

        for _ in range(2): 
            client_connection, client_address = self.server_socket.accept()
            print(f"Connected to a client from: {client_address}")
    
            thread = threading.Thread(target=self.handle_client, args=(client_connection, client_address))
            thread.start()

    def handle_client(self, connection: ssl.SSLSocket, address: Tuple[str, int]):
        connection.send(self.pack_tuple(self.local_RSA.public_key))

        client_data = connection.recv(3024)
        client_key = self.unpack_tuple(client_data)
        print(f"[Register] Client", address, "- Public Key:", client_key)

        key_index = chr(ord('A') + self.client_counter)
        print("Register to name: ", key_index, '\n')

        self.lock.acquire()
        try:
            temp                    = RSAPair()
            temp.public_key         = client_key
            self.store[key_index]   = temp
            self.client_counter     += 1
        finally:
            self.lock.release()

        connection.send(key_index.encode())

        client_data = connection.recv(3024)
        received_data = {k.strip(): v for k, v in json.loads(client_data.decode('utf-8')).items()}
        print("Received data:", received_data, '\n')

        if received_data['type'] == 'REQUEST_PUBLIC_KEY' and received_data['client_id'] != key_index:
            while True: 
                self.lock.acquire()
                try:
                    if self.client_counter > 1:
                        time.sleep(0.1)
                        break
                finally:
                    self.lock.release()
                    time.sleep(2)

            raw_public_key = self.pack_tuple(self.store[received_data['client_id']].public_key)
            data = {"public_key": raw_public_key.hex(), "timestamp":received_data['timestamp'] }
            message = self.RSA.encrypt(json.dumps(data), self.local_RSA.private_key)
            connection.send(self.pack_rsa(message))
            
            print(f"Data sent to client -", key_index, ": ")
            print(json.dumps(data))
            print()

        while True:
            data = connection.recv(3024).decode()
            print(f"Message from {address}: {data}")
            if not data:
                break
            print(f"Message from {address}: {data}")            

            response = input(' -> ')
            connection.send(response.encode('utf-8'))

        connection.close() 

    def Start(self):
        # Generate Our RSA KEY
        print("Generating Public Authority RSA Keys....")
        self.local_RSA.public_key, self.local_RSA.private_key = self.RSA.generate_keypair()
        print(f"Local Public Key : ", self.local_RSA.public_key)
        print(f"Local Private Key : ", self.local_RSA.private_key, '\n')

        self.start_server_socket()


if __name__ == '__main__':
   PublicAuthority().Start()
