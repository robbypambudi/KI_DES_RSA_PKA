import socket
import struct
import ssl
import json
import time
import threading
from des import Des
from rsa import RSA_Algorithm

Local_keys = ""
server_Keys = ""

class RSAPair():
    def __init__(self) -> None:
        self.public_key: tuple[int, int] = None
        self.private_key: tuple[int, int] = None

class SecureClient():
    def __init__(self) -> None:
        self.client_id             = ""
        self.hostname                = socket.gethostname()
        self.auth_port          = 5022
        self.secure_port          = 5023
        self.auth_socket        = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.secure_socket        = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.shared_key: bytes      = '\0'
        self.server_address            = ""
        self.server_port          = ""
        self.des_handler                  = Des()
        self.rsa_handler                  = RSA_Algorithm()
        self.auth_keys          = RSAPair()
        self.local_keys            = RSAPair()
        self.partner_keys           = RSAPair()
        self.ssl_context         = None
        self.lock                = threading.Lock()
        self.regen_required  = False

    @staticmethod
    def pack_tuple(int_tuple: tuple[int, int]) -> bytes:
        return struct.pack('qq', *int_tuple) 

    @staticmethod
    def unpack_tuple(packed_data: bytes) -> tuple[int, int]:
        return struct.unpack('qq', packed_data)
    
    @staticmethod
    def pack_rsa(encrypted_message):
        return struct.pack(f'<{len(encrypted_message)}Q', *encrypted_message)

    @staticmethod
    def unpack_rsa(packed_message):
        num_integers = len(packed_message) // 8 
        return list(struct.unpack(f'<{num_integers}Q', packed_message))
    
    def initiate_auth_connection(self):       
        self.auth_socket .connect((self.hostname, self.auth_port )) 
        self.server_address , self.server_port  = self.auth_socket .getpeername()
        print(f"Connected to server at IP: {self.server_address }, Port: {self.server_port }")

        # Additional Validation
        confirmation = input("Do you want to accept this server connection? (yes/no): ")
        if confirmation.lower() == 'no' :
            print("Connection Refused ! Terminating Connection ...")
            self.auth_socket .close()
            return False
        else :
            print("Connection Accepted !\n")
            True

    def initiate_secure_connection(self):
        self.secure_socket .connect((self.hostname, self.secure_port )) 
        self.server_address , self.server_port  = self.secure_socket .getpeername()
        print(f"Connected to server at IP: {self.server_address }, Port: {self.server_port }")

        # Additional Validation
        confirmation = input("Do you want to accept this server connection? (yes/no): ")
        if confirmation.lower() == 'no' :
            print("Connection Refused ! Terminating Connection ...")
            self.secure_socket .close()
            return False
        else :
            print("Connection Accepted !\n")
            True

    # New des_handler  Key Every 1 Minute
    def refresh_des_key(self):
        while True:
            time.sleep(60)
            self.lock.acquire()
            try:
                self.regen_required  = True
            finally:
                self.lock.release()
            print("\nWarn: Should Regenerate des_handler  Key Now")

            # Wait Until it's set back to false
            while True: 
                self.lock.acquire()
                try:
                    if self.regen_required  == False:
                        time.sleep(0.1)
                        break
                finally:
                    self.lock.release()
                    time.sleep(4)
    
    def encrypt_message(self, message: str, type: str):
        payload = {
            'type': type,
            'message': message
        }
        return json.dumps(payload)
    
    def handle_encrypted_communication(self):
        # Handle Incoming / Outgoing Message
        message = input(" -> ") 

        while message.strip() != 'bye':
            # Encrypt the string before send to server
            message = self.encrypt_message(message, 'MSG').encode('utf-8')  
            encrypted_message = self.des_handler .Encrypt(message, self.shared_key)
            self.secure_socket .send(encrypted_message) 

            # Listen to response
            data = self.secure_socket .recv(3024)

            # Decrypt the encrypted message from server
            print('\nRaw from Client: ' + str(data))
            raw_msg = self.des_handler .Decrypt_using_key(data, self.shared_key)
            msg = json.loads(raw_msg)
            
            print("decrypted from client: ", msg)
            print()

            self.lock.acquire()
            try:
                if self.regen_required  == True:
                    self.regen_required  = False
                    message = self.encrypt_message('Re-Generate des_handler ', 'GENERATE').encode('utf-8')  
                    encrypted_message = self.des_handler .Encrypt(message, self.shared_key)
                    self.secure_socket .send(encrypted_message)

                    # Send des_handler  Key
                    print("\nSending des_handler  Key to Client B ....")
                    self.shared_key = self.des_handler .Random_Bytes(8)

                    # Encrypt with our private key
                    encrypted_des = self.rsa_handler .encrypt(self.shared_key.hex(), self.local_keys .private_key) 
                    # Encrypt with Client B public key
                    encrypted_des = self.rsa_handler .encrypt(self.pack_rsa(encrypted_des).hex(), self.partner_keys .public_key)
                    self.secure_socket .send(self.pack_rsa(encrypted_des))

                    print(f"New des_handler  Key: ", self.shared_key, '\n')
            finally:
                self.lock.release()

            message = input(" -> ")

        self.secure_socket .close()
        self.auth_socket .close()

    def start(self):
        if self.initiate_auth_connection() == False:
            return
        
        # Receive Server rsa_handler  keys from server
        print("Waiting for Public Authority to send it's rsa_handler  Public Key...")
        server_data = self.auth_socket .recv(3024)
        self.auth_keys .public_key = self.unpack_tuple(server_data)
        print(f"Public Authority - Public Key : ", self.auth_keys .public_key, '\n')

        # Send our rsa_handler  Keys to Public Authority Server
        print("Register our Public key to Public Authority Server....")
        self.local_keys .public_key, self.local_keys .private_key = self.rsa_handler .generate_keypair()
        self.auth_socket .send(self.pack_tuple(self.local_keys .public_key))        

        print(f"Local rsa_handler  - Public Key : ", self.local_keys .public_key)
        print(f"Local rsa_handler  - Private Key: ", self.local_keys .private_key, '\n')

        # Set our ID identity
        self.client_id = self.auth_socket .recv(3024).decode()
        print(f"Our Identity: ", self.client_id, "\n")

        # Wait for Client B & Request it's public key from Public Authority
        print("Requesting client B public key .....")
        payload = {
        "type": "REQUEST_PUBLIC_KEY",
        "client_id": "B",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")  
        }

        self.auth_socket .sendall(json.dumps(payload).encode('utf-8'))

        response = self.auth_socket .recv(3024)
        response = self.unpack_rsa(response)
        response_json = json.loads(self.rsa_handler .decrypt(response, self.auth_keys .public_key))
        self.partner_keys .public_key = self.unpack_tuple(bytes.fromhex(response_json['public_key']))
        print(f"Public Authority Response: ", response_json)
        print(f"Client B - Public Key: ", self.partner_keys .public_key, '\n')

        # Make client connection
        if self.initiate_secure_connection() == False:
            return
        
        # Send Our Identifier (IDa) and Nonce (N1) to client B
        N1 = self.des_handler .Random_Bytes(8).hex()
        payload = {
            "type": "STEP_3",
            "client_id": "A",
            "N1": N1
        }

        message = self.rsa_handler .encrypt(json.dumps(payload), self.partner_keys .public_key)
        self.secure_socket .send(self.pack_rsa(message))
        print(f"Data sent to client - B :", json.dumps(payload))
        print(f"encrypted:", self.pack_rsa(message), "\n")

        # Wait for client B message
        print("Getting response from client B ....")
        b_message = self.secure_socket .recv(3024)
        message = self.unpack_rsa(b_message)
        message_json = json.loads(self.rsa_handler .decrypt(message, self.local_keys .private_key))
        print(message_json)

        if(message_json['N1'] != N1):
            print("Invalid Nonce N1")
            return
        
        N2 = message_json['N2']
        final_payload = {
            "type": "STEP_7",
            "client_id": "A",
            "N2": N2
        }

        # Send a message again to client B
        message = self.rsa_handler .encrypt(json.dumps(final_payload), self.partner_keys .public_key)
        self.secure_socket .send(self.pack_rsa(message))

        # Send des_handler  Key
        print(f"\nData sent to client - B :", json.dumps(final_payload))
        print("\nSending des_handler  Key to Client B ....")
        self.shared_key = self.des_handler .Random_Bytes(8)

        # Encrypt with our private key
        encrypted_des = self.rsa_handler .encrypt(self.shared_key.hex(), self.local_keys .private_key) 
        # Encrypt with Client B public key
        encrypted_des = self.rsa_handler .encrypt(self.pack_rsa(encrypted_des).hex(), self.partner_keys .public_key)
        self.secure_socket .send(self.pack_rsa(encrypted_des))

        print(f"des_handler  Key: ", self.shared_key, '\n')

        thread = threading.Thread(target=self.refresh_des_key, daemon=True)
        thread.start()

        # Handle Encrypted Communication
        self.handle_encrypted_communication()


if __name__ == '__main__':
    SecureClient().start()