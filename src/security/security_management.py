import base64
import json
from os import urandom
import time
import Pyro4
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
import uuid

from src.manage_logs.manage_logs_v_2 import ComponentType, LogType, ManagementLogs
from src.utils.get_ip import get_ip
from src.utils.types.agent_type import AgentType


class SecurityManagement:
    def __init__(self, name_agent: str, management_logs: ManagementLogs, shared_key: str):
        self.management_logs = management_logs
        self.management_data = management_logs.data_management_instance
        self.id_agent = None
        
        # Cargar los datos del agente y obtener su UUID existente
        self.agent_data = self.management_data.load() or {}
        self.uuid_agent = self.agent_data.get('uuid')
        
        # Solo establecer el UUID en ManagementLogs si existe
        if self.uuid_agent:
            self.management_logs.set_default_agent_uuid(self.uuid_agent)
        
        # Generar claves
        self.private_key = self.generate_private_key()
        self.public_key = self.generate_public_key()
        self.name_agent = name_agent
        self.shared_key_cifrate_yp = None
        self.shared_key__cifrate_ns = None
        self.public_key_yp = None
        self.uri_yp = None
        self.ns = None
        self.server = None
        
        # Determinar el tipo de agente
        self.agent_type = None
        if 'is_provider' in self.agent_data and self.agent_data['is_provider']:
            if 'name' in self.agent_data:
                if 'adder' in self.agent_data['name'].lower():
                    self.agent_type = 'Addition'
                elif 'subtract' in self.agent_data['name'].lower():
                    self.agent_type = 'Subtraction'
                elif 'multiplication' in self.agent_data['name'].lower():
                    self.agent_type = 'Multiplication'
                elif 'division' in self.agent_data['name'].lower():
                    self.agent_type = 'Division'
        elif 'is_consumer' in self.agent_data and self.agent_data['is_consumer']:
            self.agent_type = 'Consumer'
        
        # Iniciar la sesión
        self.management_logs.start_new_session_log()
        
        # Log de inicialización
        self.management_logs.log_message(
            ComponentType.SECURITY_MANAGEMENT,
            'SecurityManagement initialized',
            LogType.START_SESSION,
            agent_uuid=self.uuid_agent,
            agent_type=self.agent_type
        )
        
        # Guardar la clave compartida
        if self.uuid_agent:
            self.agent_data['ultimate_shared_key'] = shared_key
            self.save_agent_data()

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
        start_time = time.perf_counter()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Encoding request...', LogType.SERIALIZATION)
        iv_base64 = self.__encode_base64(iv)
        encrypted_data_base64 = self.__encode_base64(encrypted_data)
        encrypted_key_base64 = self.__encode_base64(encrypted_key)
        end_time = time.perf_counter()
        serialization_time = end_time - start_time
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Request encoded successfully', LogType.END_SERIALIZATION, time_str=f"{serialization_time:.9f}")

        return {
            "iv": iv_base64,
            "data": encrypted_data_base64,
            "key": encrypted_key_base64,
            "id": self.uuid_agent,
        }

    def __decodify_base64(self, data_base64):
        return base64.b64decode(data_base64)

    def __decode_response(self, response):
        iv = self.__decodify_base64(response["iv"])
        encrypted_data = self.__decodify_base64(response["data"])
        encrypted_key = self.__decodify_base64(response["key"])

        return iv, encrypted_data, encrypted_key

    def __hash_key_shared(self, key: str):
        start_time = time.perf_counter()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Hashing shared key...', LogType.SHARED_KEY)
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(key.encode())
        hash_value = digest.finalize()
        end_time = time.perf_counter()
        hashing_time = end_time - start_time
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Shared key hashed successfully', LogType.END_SHARED_KEY, time_str=f"{hashing_time:.9f}")
        return hash_value

    def __create_cipher(self, iv, key):
        return Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    def encrypt_data_with_public_key(self, data: dict, public_key: rsa.RSAPublicKey, id_agent: str):
        start_time = time.perf_counter()
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
        end_time = time.perf_counter()
        encryption_time = end_time - start_time
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Data encrypted with hybrid encryption successfully', LogType.END_ENCRYPTION, time_str=f"{encryption_time:.9f}")
        return self.__encode_request(iv, encrypted_data, encrypted_key)

    def decrypt_data(self, response):
        try:
            start_time = time.perf_counter()
            self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Decrypting data...', LogType.DECRYPTION)
            iv, encrypted_data, encrypted_key = self.__decode_response(response)
            decrypted_key = self.private_key.decrypt(
                encrypted_key,
                self.__get_padding()
            )
            cipher = self.__create_cipher(iv, decrypted_key[:32])
            decryptor = cipher.decryptor()
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            end_time = time.perf_counter()
            decryption_time = end_time - start_time
            self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Data decrypted successfully', LogType.END_DECRYPTION, time_str=f"{decryption_time:.9f}")
            decoded_data = json.loads(decrypted_data.decode())
            return decoded_data
        except Exception as e:
            print('Error: ', e)
            self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, f'Error: {e}', LogType.ERROR, success=False)
            return None

    def decrypt_data_responded_by_yp(self, response):
        start_time = time.perf_counter()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Decrypting data responded by yp...', LogType.DECRYPTION)
        decrypted_data = self.decrypt_data(response)
        end_time = time.perf_counter()
        decryption_time = end_time - start_time
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Data decrypted responded by yp successfully', LogType.END_DECRYPTION, time_str=f"{decryption_time:.9f}")
        self.uri_yp = decrypted_data["server_uri"]
        self.public_key_yp = decrypted_data["public_key"]
        public_key_yp = base64.b64decode(self.public_key_yp)
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Public key yp set successfully', LogType.SHARED_KEY)

        start_time = time.perf_counter()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Serializing public key yp...', LogType.SERIALIZATION)
        self.public_key_yp = serialization.load_pem_public_key(public_key_yp, backend=default_backend())
        end_time = time.perf_counter()
        serialization_time = end_time - start_time
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Public key yp serialized successfully', LogType.END_SERIALIZATION, time_str=f"{serialization_time:.9f}")
        self.server = Pyro4.Proxy(self.uri_yp)

    def __find_public_key_yp(self, data_decoding):
        start_time = time.perf_counter()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Finding public key yp...', LogType.SHARED_KEY)
        for key, value in data_decoding.items():
            if isinstance(value, dict):
                self.__find_public_key_yp(value)
            else:
                if key == "public_key_yp":
                    self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Public key yp found', LogType.END_SHARED_KEY, time_str=f"{time.perf_counter() - start_time:.9f}")
                    self.__set_public_key_yp(value)
                    return True
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Public key yp not found', LogType.END_SHARED_KEY, success=False, time_str=f"{time.perf_counter() - start_time:.9f}")
        return False

    def __set_public_key_yp(self, public_key_yp: str):
        start_time = time.perf_counter()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Setting public key yp...', LogType.SHARED_KEY)
        public_key_yp = base64.b64decode(public_key_yp)
        self.public_key_yp = serialization.load_pem_public_key(public_key_yp, backend=default_backend())
        end_time = time.perf_counter()
        set_key_time = end_time - start_time
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Public key yp set successfully', LogType.END_SHARED_KEY, time_str=f"{set_key_time:.9f}")

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
        start_time_total = time.perf_counter()

        # Encrypt data yp
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Encrypting data yp...', LogType.ENCRYPTION)
        self.uuid_agent = self.agent_data['uuid']
        data_yp_bytes = self.__convert_in_bytes_data_to_send_yp()
        iv = urandom(16)
        self.__set_shared_key_yp(code_otp)
        cipher = self.__create_cipher(iv, self.shared_key_cifrate_yp[:32])
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data_yp_bytes) + encryptor.finalize()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Data encrypted yp successfully', LogType.END_ENCRYPTION, time_str=f"{time.perf_counter() - start_time_total:.9f}")

        # Encode data yp
        start_time = time.perf_counter()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Encoding data yp...', LogType.SERIALIZATION)
        iv_base64 = self.__encode_base64(iv)
        encrypted_data_base64 = self.__encode_base64(encrypted_data)
        end_time = time.perf_counter()
        encoding_time = end_time - start_time
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Data encoded yp successfully', LogType.END_SERIALIZATION, time_str=f"{encoding_time:.9f}")

        data_yp = {
            "iv": iv_base64,
            "data": encrypted_data_base64,
        }

        # Encrypt data deamon
        start_time = time.perf_counter()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Encrypting data deamon...', LogType.ENCRYPTION)
        data_deamon_bytes = self.__convert_in_bytes_data_to_send_deamon(data_yp, code_otp)
        iv = urandom(16)
        self.__set_shared_key_deamon()
        cipher = self.__create_cipher(iv, self.shared_key__cifrate_ns[:32])
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data_deamon_bytes) + encryptor.finalize()
        end_time = time.perf_counter()
        encryption_time = end_time - start_time
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Data encrypted deamon successfully', LogType.END_ENCRYPTION, time_str=f"{encryption_time:.9f}")

        # Encode data deamon
        start_time = time.perf_counter()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Encoding data deamon...', LogType.SERIALIZATION)
        iv_base64 = self.__encode_base64(iv)
        encrypted_data_base64 = self.__encode_base64(encrypted_data)
        end_time = time.perf_counter()
        encoding_time = end_time - start_time
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Data encoded deamon successfully', LogType.END_SERIALIZATION, time_str=f"{encoding_time:.9f}")

        data_send_deamon = {
            "id": self.uuid_agent,
            "iv": iv_base64,
            "data": encrypted_data_base64,
        }

        total_time = time.perf_counter() - start_time_total
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Total encryption and encoding time', LogType.END_ENCRYPTION, time_str=f"{total_time:.9f}")

        return data_send_deamon

    def generate_private_key(self):
        start_time = time.perf_counter()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Generating private key...', LogType.KEY_GENERATION)
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        end_time = time.perf_counter()
        key_generation_time = end_time - start_time
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Private key generated successfully', LogType.END_KEY_GENERATION, time_str=f"{key_generation_time:.9f}")
        return private_key

    def generate_public_key(self):
        start_time = time.perf_counter()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Generating public key...', LogType.KEY_GENERATION)
        public_key = self.private_key.public_key()
        end_time = time.perf_counter()
        key_generation_time = end_time - start_time
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Public key generated successfully', LogType.END_KEY_GENERATION, time_str=f"{key_generation_time:.9f}")
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
        start_time = time.perf_counter()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Setting shared key yp...', LogType.SHARED_KEY)
        if not code_otp:
            code_otp = ""
        ip = get_ip()
        shared_key = self.agent_data['ultimate_shared_key']
        key_shared_complete = (ip + code_otp + self.uuid_agent + code_otp + shared_key + ip + self.uuid_agent + shared_key +
                               code_otp)
        self.shared_key_cifrate_yp = self.__hash_key_shared(key_shared_complete)
        end_time = time.perf_counter()
        set_key_time = end_time - start_time
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Shared key yp set successfully', LogType.END_SHARED_KEY, time_str=f"{set_key_time:.9f}")

    def __set_shared_key_deamon(self):
        start_time = time.perf_counter()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Setting shared key deamon...', LogType.SHARED_KEY)
        ip = get_ip()
        shared_key = self.agent_data['ultimate_shared_key']
        key_shared_complete = (shared_key + ip + self.uuid_agent + shared_key + ip + shared_key + ip + self.uuid_agent +
                               shared_key)
        self.shared_key__cifrate_ns = self.__hash_key_shared(key_shared_complete)
        end_time = time.perf_counter()
        set_key_time = end_time - start_time
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Shared key deamon set successfully', LogType.END_SHARED_KEY, time_str=f"{set_key_time:.9f}")

    def deserialize_public_key(self, public_key: str):
        public_key = base64.b64decode(public_key)
        return serialization.load_pem_public_key(public_key, backend=default_backend())

    def upload_agent_data(self):
        start_time = time.perf_counter()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Uploading agent data...', LogType.UPLOAD)
        data = self.management_data.load()
        if data:
            self.agent_data = data
        end_time = time.perf_counter()
        upload_time = end_time - start_time
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Agent data uploaded successfully', LogType.END_UPLOAD, time_str=f"{upload_time:.9f}")

    def save_agent_data(self):
        start_time = time.perf_counter()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Saving agent data...', LogType.UPLOAD)
        self.management_data.save(self.agent_data)
        end_time = time.perf_counter()
        save_time = end_time - start_time
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Agent data saved successfully', LogType.END_UPLOAD, time_str=f"{save_time:.9f}")

    def delete_agent_data(self):
        start_time = time.perf_counter()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Deleting agent data...', LogType.UPLOAD)
        self.management_data.delete()
        end_time = time.perf_counter()
        delete_time = end_time - start_time
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Agent data deleted successfully', LogType.END_UPLOAD, time_str=f"{delete_time:.9f}")

    def set_data_agent(self, data: AgentType):
        self.agent_data = data
        self.uuid_agent = data['uuid']
        self.save_agent_data()
        self.management_logs.log_message(ComponentType.SECURITY_MANAGEMENT, 'Agent data set successfully', LogType.END_UPLOAD)

    def get_data_agent(self) -> AgentType:
        self.upload_agent_data()
        self.uuid_agent = self.agent_data['uuid']
        return self.agent_data
