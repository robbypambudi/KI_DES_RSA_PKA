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

class RSA_Container():
    def __init__(self) -> None:
        self.public_key: tuple[int, int] = None
        self.private_key: tuple[int, int] = None


class PublicAuthority():
    def __init__(self) -> None:
        self.host           = socket.gethostname()
        self.port           = 5022
        self.server_socket  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.local_keys     = ""
        self.client_keys:bytes    = ""
        self.DES            = Des()
        self.RSA            = RSA_Algorithm()
        self.local_RSA      = RSA_Container()
        self.store: dict[str, RSA_Container] = {}
        self.client_counter = 0 
        self.lock = threading.Lock()

    def pack_tuple(int_tuple: tuple[int, int]) -> bytes:
        return struct.pack('qq', *int_tuple) 

    def unpack_tuple(packed_data: bytes) -> tuple[int, int]:
        return struct.unpack('qq', packed_data)
    
    def pack_rsa(encrypted_message):
        return struct.pack(f'<{len(encrypted_message)}Q', *encrypted_message)

    def unpack_rsa(packed_message):
        num_integers = len(packed_message) // 8 
        return list(struct.unpack(f'<{num_integers}Q', packed_message))

    def start_server_socket(self):
        self.server_socket.bind((self.host, self.port)) 
        self.server_socket.listen(2)

        # Accept two clients
        for _ in range(2): 
            client_connection, client_address = self.server_socket.accept()
            print(f"Connected to a client from: {client_address}")
    
            thread = threading.Thread(target=self.handle_client, args=(client_connection, client_address))
            thread.start()

    def handle_client(self, connection: ssl.SSLSocket, address: Tuple[str, int]):
        # Send Our Public Key
        connection.send(self.pack_tuple(self.local_RSA.public_key))

        # Receive Client Public Key
        client_data = connection.recv(1024)
        client_key = self.unpack_tuple(client_data)
        print(f"[Register] Client", address, "- Public Key:", client_key)

        key_index = chr(ord('A') + self.client_counter)
        print("Register to name: ", key_index, '\n')

        self.lock.acquire()
        try:
            temp = RSA_Container()
            temp.public_key = client_key
            self.store[key_index] = temp
            self.client_counter += 1
        finally:
            self.lock.release()

        # Send back client identity
        connection.send(key_index.encode())

        # Check if client is requesting a public key
        client_data = connection.recv(1024)
        received_data = json.loads(client_data.decode('utf-8'))
        print("Received data:", received_data, '\n')

        if received_data['type'] == 'REQUEST_PUBLIC_KEY' and received_data['id']  != key_index:
            while True: 
                self.lock.acquire()
                try:
                    if self.client_counter > 1:
                        time.sleep(0.1)
                        break
                finally:
                    self.lock.release()
                    time.sleep(2)

            # send the requested public key
            raw_public_key = self.pack_tuple(self.store[received_data['id']].public_key)
            data = {"public_key": raw_public_key.hex(), "timestamp":received_data['timestamp'] }
            message = self.RSA.encrypt(json.dumps(data), self.local_RSA.private_key)
            connection.send(self.pack_rsa(message))
            
            print(f"Data sent to client -", key_index, ": ")
            print(json.dumps(data))
            print()
        # Handle Incoming / Outgoing Message
        while True:
            data = connection.recv(1024).decode()
            if not data:
                break
            # Decrypt the encrypted message from client. Convert to bytes from hex
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
    Program = PublicAuthority()
    Program.Start()


# Keys are distributed and exchange using secure RSA Keys

# 1. Client send keys -> Server receive keys
# 2. Server send keys -> Client receive key

# 1. Client encrypt -> Server Decrypt
# 2. Server Encrypt -> Client Decrypt