import socket
import struct
import ssl
from des import Des
from rsa import RSA_Algorithm
import time
import json
import threading


class RSAPair():
    def __init__(self) -> None:
        self.pub_key: tuple[int, int] = None
        self.priv_key: tuple[int, int] = None

class SecureClient():
    def __init__(self) -> None:
        self.client_id              = ""
        self.hostname                 = socket.gethostname()
        self.auth_port          = 5022
        self.secure_port          = 5023
        self.auth_socket        = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secure_socket        = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.shared_key   = None
        self.local_keys : bytes  = '\0'
        self.server_keys: bytes  = '\0'
        self.server_address            = ""
        self.server_port          = ""
        self.client_address = ""
        self.des_handler                  = Des()
        self.rsa_handler                  = RSA_Algorithm()
        self.auth_keys          = RSAPair()
        self.local_keys            = RSAPair()
        self.partner_keys           = RSAPair()
        self.des_key: bytes      = '\0'
        self.lock = threading.Lock()

    def pack_tuple(int_tuple: tuple[int, int]) -> bytes:
        return struct.pack('qq', *int_tuple) 

    def unpack_tuple(packed_data: bytes) -> tuple[int, int]:
        return struct.unpack('qq', packed_data)
    
    def pack_encrypted_data(encrypted_message):
        return struct.pack(f'<{len(encrypted_message)}Q', *encrypted_message)

    def unpack_encrypted_data(packed_message):
        num_integers = len(packed_message) // 8 
        return list(struct.unpack(f'<{num_integers}Q', packed_message))
    
    def initiate_auth_connection(self):
      
        self.auth_socket .connect((self.hostname , self.auth_port )) 
        self.server_address , self.server_port  = self.auth_socket .getpeername()
        print(f"Connected to Public Authority at {self.auth_port}")

        return True

    def initiate_secure_connection(self):
        self.secure_socket.bind((self.hostname , self.secure_port )) 
        self.secure_socket.listen(1)

        # Wrap the socket with SSL
        self.shared_key, self.client_address = self.secure_socket .accept()
        print(f"Connected securely at {self.secure_port}")

        return True

    def encrypt_message(self, msg: str, msg_type: str):
        return json.dumps({'type': msg_type, 'message': msg})

    def handle_encrypted_communication(self):
        # Handle Incoming / Outgoing Message
        while True:
            data = self.shared_key.recv(3024)
            if not data:
                break
            
            # Decrypt the message
            print("\nRaw from client: " + str(data))
            raw_msg = self.des_handler .Decrypt_using_key(data, self.des_key)
            msg = json.loads(raw_msg)
            print("decrypted from client: ", msg)
            print()

            if msg['type'] == 'GENERATE':
                # Receive Des Key des_handler  Key
                print("\nGetting des_handler  Key from Client A ....")
                message = self.shared_key.recv(3024)
                unpacked_key = self.unpack_encrypted_data(message)

                # Decrypt with  Our Private Key
                encrypted_des = bytes.fromhex(self.rsa_handler .decrypt(unpacked_key, self.local_keys .priv_key))
                # Decrypt with Client A Public Key
                self.des_key = bytes.fromhex(self.rsa_handler .decrypt(self.unpack_encrypted_data(encrypted_des), self.partner_keys .pub_key))
                
                print(f"des_handler  Key: ", self.des_key, '\n')

                continue

            data = input(' -> ')
            # Encrypt the string before sending to client
            data = self.encrypt_message(data, 'MSG').encode('utf-8') 
            encrypted_message = self.des_handler .Encrypt(data, self.des_key)
            self.shared_key.send(encrypted_message) 

        self.shared_key.close()
        self.auth_socket .close()

    def start(self):
        if self.initiate_auth_connection() == False:
            return
        
        # Receive Server rsa_handler  keys from server
        print("Waiting for Public Authority to send it's rsa_handler  Public Key...")
        server_data = self.auth_socket .recv(3024)
        self.auth_keys .pub_key = self.unpack_tuple(server_data)
        print(f"Public Authority - Public Key : ", self.auth_keys .pub_key, '\n')

        # Send our rsa_handler  Keys to Public Authority Server
        print("Register our Public key to Public Authority Server....")
        self.local_keys .pub_key, self.local_keys .priv_key = self.rsa_handler .generate_keypair()
        self.auth_socket .send(self.pack_tuple(self.local_keys .pub_key))        

        print(f"Local rsa_handler  - Public Key : ", self.local_keys .pub_key)
        print(f"Local rsa_handler  - Private Key: ", self.local_keys .priv_key, '\n')

        # Set our ID identity
        self.client_id  = self.auth_socket .recv(3024).decode()
        print(f"Our Identity: ", self.client_id )

        if self.initiate_secure_connection() == False:
            return
        
        # Wait for client A talk to us
        a_message = self.shared_key.recv(3024)
        print("\nEncrypted message from client - A : ")
        print(a_message)

        # Decrypt Client A message
        print("\nDecrypting client A message ...")
        message = self.unpack_encrypted_data(a_message)
        message_json = json.loads(self.rsa_handler .decrypt(message, self.local_keys .priv_key))
        print(message_json)
        print()

        N1 = message_json['N1']

        # Request Client A public key to Public Authority
        print("Requesting client A public key .....")
        payload = {
        "type": "REQUEST_PUBLIC_KEY",
        "client_id ": message_json['client_id '],
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")  
        }

        self.auth_socket .sendall(json.dumps(payload).encode('utf-8'))

        response = self.auth_socket .recv(3024)
        response = self.unpack_encrypted_data(response)
        response_json = json.loads(self.rsa_handler .decrypt(response, self.auth_keys .pub_key))
        self.partner_keys .pub_key = self.unpack_tuple(bytes.fromhex(response_json['pub_key']))
        print(f"Public Authority Response: ", response_json)
        print(f"Client A - Public Key: ", self.partner_keys .pub_key, '\n')

        # Send Our Response To Client A
        N2 = self.des_handler .Random_Bytes(8).hex()
        payload = {
            "type": "STEP_6",
            "client_id ": "B",
            "N1": message_json['N1'],
            "N2": N2,
        }

        print("Sending our response to Client A ....")
        print(payload)
        message = self.rsa_handler .encrypt(json.dumps(payload), self.partner_keys .pub_key)
        self.shared_key.send(self.pack_encrypted_data(message))

        # Get a message from client A
        response = self.shared_key.recv(3024)
        response = self.unpack_encrypted_data(response)
        response_json = json.loads(self.rsa_handler .decrypt(response, self.local_keys .priv_key))
        print("\nDecrypting client A message ...")
        print(response_json)

        if(response_json['N2'] != N2):
            print("Invalid Nonce N2")
            return

        # Receive Des Key des_handler  Key
        print("\nGetting des_handler  Key from Client A ....")
        message = self.shared_key.recv(3024)
        unpacked_key = self.unpack_encrypted_data(message)

        # Decrypt with  Our Private Key
        encrypted_des = bytes.fromhex(self.rsa_handler .decrypt(unpacked_key, self.local_keys .priv_key))
        # Decrypt with Client A Public Key
        self.des_key = bytes.fromhex(self.rsa_handler .decrypt(self.unpack_encrypted_data(encrypted_des), self.partner_keys .pub_key))
        
        print(f"des_handler  Key: ", self.des_key, '\n')
        
        # Handle Encrypted Communication
        self.handle_encrypted_communication()


if __name__ == '__main__':
    SecureClient().start()


# Keys are distributed and exchange using secure rsa_handler  Keys

# 1. Client send keys -> Server receive keys
# 2. Server send keys -> Client receive key

# 1. Client encrypt -> Server Decrypt
# 2. Server Encrypt -> Client Decrypt