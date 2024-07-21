import base64
import json
from os import urandom
import Pyro4
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms

from src.manage_logs.manage_logs_v_2 import ComponentType, LogType, ManagementLogs
from src.utils.get_ip import get_ip
from src.utils.types.agent_type import AgentType


class SecurityManagement:

    def __init__(self, name_agent: str, management_logs: ManagementLogs):
        self.management_logs = management_logs
        self.management_data = management_logs.data_management_instance
        self.id_agent = None
        self.private_key = self.generate_private_key()
        self.public_key = self.generate_public_key()
        self.name_agent = name_agent
        self.shared_key_cifrate_yp = None
        self.shared_key__cifrate_ns = None
        self.public_key_yp = None
        self.uri_yp = None
        self.ns = None
        self.server = None
        self.agent_data = None
        self.upload_agent_data()
        self.management_logs.start_new_session_log()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'SecurityManagement initialized', LogType.START_SESSION)

    def set_ns(self, ns: Pyro4.Proxy):
        self.ns = ns

    def __get_padding(self):
        return padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )

    def __encode_base64(self, data):
        return base64.b64encode(data).decode()

    def __encode_request(self, iv, encrypted_data, encrypted_key):
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Encoding request...', LogType.SERIALIZATION)
        iv_base64 = self.__encode_base64(iv)
        encrypted_data_base64 = self.__encode_base64(encrypted_data)
        encrypted_key_base64 = self.__encode_base64(encrypted_key)
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Request encoded successfully', LogType.SERIALIZATION)

        return {
            "iv": iv_base64,
            "data": encrypted_data_base64,
            "key": encrypted_key_base64,
            "id": self.id_agent,
        }

    def __decodify_base64(self, data_base64):
        return base64.b64decode(data_base64)

    def __decode_response(self, response):
        iv = self.__decodify_base64(response["iv"])
        encrypted_data = self.__decodify_base64(response["data"])
        encrypted_key = self.__decodify_base64(response["key"])

        return iv, encrypted_data, encrypted_key

    def __hash_key_shared(self, key: str):
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Hashing shared key...', LogType.SHARED_KEY)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(key.encode())
        hash_value = digest.finalize()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Shared key hashed successfully', LogType.SHARED_KEY)
        return hash_value

    def __create_cipher(self, iv, key):
        return Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    def encrypt_data_with_public_key(self, data: dict, public_key: rsa.RSAPublicKey, id_agent: str):
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Encrypting data with hybrid encryption...', LogType.ENCRYPTION)
        data_bytes = json.dumps(data).encode("utf-8")
        iv = urandom(16)
        shared_key = Fernet.generate_key()
        shared_key_bytes = base64.urlsafe_b64decode(shared_key)
        cipher = self.__create_cipher(iv, shared_key_bytes)
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data_bytes) + encryptor.finalize()
        encrypted_key = public_key.encrypt(
            shared_key_bytes,
            self.__get_padding()
        )
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Data encrypted with hybrid encryption successfully', LogType.ENCRYPTION)
        return self.__encode_request(iv, encrypted_data, encrypted_key)

    def decrypt_data(self, response):
        try:
            self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Decrypting data...', LogType.DECRYPTION)
            iv, encrypted_data, encrypted_key = self.__decode_response(response)
            decrypted_key = self.private_key.decrypt(
                encrypted_key,
                self.__get_padding()
            )
            cipher = self.__create_cipher(iv, decrypted_key[:32])
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Data decrypted successfully', LogType.DECRYPTION)
            decoded_data = json.loads(decrypted_data.decode())
            return decoded_data
        except Exception as e:
            print('Error: ', e)
            self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, f'Error: {e}', LogType.ERROR, success=False)
            return None

    def decrypt_data_responded_by_yp(self, response):
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Decrypting data responded by yp...', LogType.DECRYPTION)
        decrypted_data = self.decrypt_data(response)
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Data decrypted responded by yp successfully', LogType.DECRYPTION)
        self.uri_yp = decrypted_data["server_uri"]
        self.public_key_yp = decrypted_data["public_key"]
        public_key_yp = base64.b64decode(self.public_key_yp)
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Public key yp set successfully', LogType.SHARED_KEY)

        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Serializing public key yp...', LogType.SERIALIZATION)
        self.public_key_yp = serialization.load_pem_public_key(public_key_yp, backend=default_backend())
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Public key yp serialized successfully', LogType.SERIALIZATION)
        self.server = Pyro4.Proxy(self.uri_yp)

    def __find_public_key_yp(self, data_decoding):
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Finding public key yp...', LogType.SHARED_KEY)
        for key, value in data_decoding.items():
            if isinstance(value, dict):
                self.__find_public_key_yp(value)
            else:
                if key == "public_key_yp":
                    self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Public key yp found', LogType.SHARED_KEY)
                    self.__set_public_key_yp(value)
                    return True
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Public key yp not found', LogType.SHARED_KEY, success=False)
        return False

    def __set_public_key_yp(self, public_key_yp: str):
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Setting public key yp...', LogType.SHARED_KEY)
        public_key_yp = base64.b64decode(public_key_yp)
        self.public_key_yp = serialization.load_pem_public_key(public_key_yp, backend=default_backend())
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Public key yp set successfully', LogType.SHARED_KEY)

    def __convert_in_bytes_data_to_send_yp(self):
        data_send = {
            "public_key": self.serialize_public_key().decode(),
        }

        # Serializar el diccionario a JSON y codificar a bytes
        return json.dumps(data_send).encode('utf-8')

    def __convert_in_bytes_data_to_send_deamon(self, data_cifrated_yp: dict, code_otp: str = ''):
        if not code_otp:
            code_otp = ""
        data_send = {
            "code_otp": code_otp,
            "data_cifrated_yp": data_cifrated_yp,
        }

        # Serializar el diccionario a JSON y codificar a bytes
        return json.dumps(data_send).encode('utf-8')

    def encrypt_data_with_shared_key(self, code_otp: str = ""):
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Encrypting data yp...', LogType.ENCRYPTION)
        self.id_agent = self.agent_data['id']
        data_yp_bytes = self.__convert_in_bytes_data_to_send_yp()
        iv = urandom(16)
        self.__set_shared_key_yp(code_otp)
        cipher = self.__create_cipher(iv, self.shared_key_cifrate_yp[:32])
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data_yp_bytes) + encryptor.finalize()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Data encrypted yp successfully', LogType.ENCRYPTION)

        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Encoding data yp...', LogType.SERIALIZATION)
        iv_base64 = self.__encode_base64(iv)
        encrypted_data_base64 = self.__encode_base64(encrypted_data)
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Data encoded yp successfully', LogType.SERIALIZATION)

        data_yp = {
            "iv": iv_base64,
            "data": encrypted_data_base64,
        }

        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Encrypting data deamon...', LogType.ENCRYPTION)
        data_deamon_bytes = self.__convert_in_bytes_data_to_send_deamon(data_yp, code_otp)
        iv = urandom(16)
        self.__set_shared_key_deamon()
        cipher = self.__create_cipher(iv, self.shared_key__cifrate_ns[:32])
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data_deamon_bytes) + encryptor.finalize()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Data encrypted deamon successfully', LogType.ENCRYPTION)

        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Encoding data deamon...', LogType.SERIALIZATION)
        iv_base64 = self.__encode_base64(iv)
        encrypted_data_base64 = self.__encode_base64(encrypted_data)
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Data encoded deamon successfully', LogType.SERIALIZATION)

        data_send_deamon = {
            "id": self.id_agent,
            "iv": iv_base64,
            "data": encrypted_data_base64,
        }

        return data_send_deamon

    def generate_private_key(self):
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Generating private key...', LogType.KEY_GENERATION)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Private key generated successfully', LogType.KEY_GENERATION)
        return private_key

    def generate_public_key(self):
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Generating public key...', LogType.KEY_GENERATION)
        public_key = self.private_key.public_key()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Public key generated successfully', LogType.KEY_GENERATION)
        return public_key

    def serialize_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def serialize_private_key(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

    def __set_shared_key_yp(self, code_otp: str = ""):
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Setting shared key yp...', LogType.SHARED_KEY)
        if not code_otp:
            code_otp = ""
        ip = get_ip()
        shared_key = self.agent_data['ultimate_shared_key']
        key_shared_complete = (ip + code_otp + self.id_agent + code_otp + shared_key + ip + self.id_agent + shared_key +
                               code_otp)
        self.shared_key_cifrate_yp = self.__hash_key_shared(key_shared_complete)
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Shared key yp set successfully', LogType.SHARED_KEY)

    def __set_shared_key_deamon(self):
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Setting shared key deamon...', LogType.SHARED_KEY)
        ip = get_ip()
        shared_key = self.agent_data['ultimate_shared_key']
        key_shared_complete = (shared_key + ip + self.id_agent + shared_key + ip + shared_key + ip + self.id_agent +
                               shared_key)
        self.shared_key__cifrate_ns = self.__hash_key_shared(key_shared_complete)
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Shared key deamon set successfully', LogType.SHARED_KEY)

    def deserialize_public_key(self, public_key: str):
        public_key = base64.b64decode(public_key)
        return serialization.load_pem_public_key(public_key, backend=default_backend())

    def upload_agent_data(self):
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Uploading agent data...', LogType.UPLOAD)
        data = self.management_data.load()
        if data:
            self.agent_data = data
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Agent data uploaded successfully', LogType.UPLOAD)

    def save_agent_data(self):
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Saving agent data...', LogType.UPLOAD)
        self.management_data.save(self.agent_data)
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Agent data saved successfully', LogType.UPLOAD)

    def delete_agent_data(self):
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Deleting agent data...', LogType.UPLOAD)
        self.management_data.delete()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Agent data deleted successfully', LogType.UPLOAD)

    def set_data_agent(self, data: AgentType):
        self.agent_data = data
        self.id_agent = data['id']
        self.save_agent_data()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Agent data set successfully', LogType.UPLOAD)

    def get_data_agent(self) -> AgentType:
        self.upload_agent_data()
        self.id_agent = self.agent_data['id']
        return self.agent_data
