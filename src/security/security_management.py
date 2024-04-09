import base64
import json
from os import urandom

import Pyro4
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, modes, algorithms
from utils.errors import ErrorTypes
from utils.get_ip import get_ip


class SecurityManagement:

    def __init__(self):
        self.id_agent = None
        self.private_key = self.generate_private_key()
        self.public_key = self.generate_public_key()
        self.shared_key_cifrate_yp = None
        self.shared_key__cifrate_ns = None
        self.public_key_yp = None
        self.uri_yp = None
        self.ns = None
        self.server = None

    def set_id_agent(self, id_agent: str):
        self.id_agent = id_agent

    def register_ok(self, server, ns):
        self.server = server
        self.ns = ns
        self.server.report_status_ok()

    def __get_padding(self):
        return padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )

    def __encode_base64(self, data):
        return base64.b64encode(data).decode()

    def __encode_request(self, iv, encrypted_data, encrypted_key):
        # Codificar el IV, los datos cifrados y la clave cifrada en base64 para su transmisión o almacenamiento
        iv_base64 = self.__encode_base64(iv)
        encrypted_data_base64 = self.__encode_base64(encrypted_data)
        encrypted_key_base64 = self.__encode_base64(encrypted_key)

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

        # Crea una instancia del digest de hash
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())

        # Pasa los datos a hashear (necesitan estar en bytes)
        digest.update(key.encode())

        # Finaliza el proceso de hash y obtiene el valor hash resultante
        hash_value = digest.finalize()

        return hash_value

    def __create_cipher(self, iv, key):
        return Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())

    def encrypt_data_with_public_key(self, data: dict, public_key: rsa.RSAPublicKey, id_agent: str):
        self.id_agent = id_agent
        # Convertir los datos a bytes
        data_bytes = json.dumps(data).encode("utf-8")

        # Generar un IV aleatorio
        iv = urandom(16)

        # Generar una clave simétrica segura
        shared_key = Fernet.generate_key()

        # Decodificar la clave de base64 a bytes
        shared_key_bytes = base64.urlsafe_b64decode(shared_key)

        # Crear el objeto de cifrado AES usando la clave simétrica
        cipher = self.__create_cipher(iv, shared_key_bytes)
        encryptor = cipher.encryptor()

        # Cifrar los datos
        encrypted_data = encryptor.update(data_bytes) + encryptor.finalize()

        # Cifrar la clave simétrica con la clave pública RSA
        encrypted_key = public_key.encrypt(
            shared_key_bytes,
            self.__get_padding()
        )

        return self.__encode_request(iv, encrypted_data, encrypted_key)

    def decrypt_data(self, response):
        iv, encrypted_data, encrypted_key = self.__decode_response(response)

        # Decrypt the AES key using the RSA private key
        decrypted_key = self.private_key.decrypt(
            encrypted_key,
            self.__get_padding()
        )
        cipher = self.__create_cipher(iv, decrypted_key[:32])
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        return json.loads(decrypted_data.decode("utf-8"))

    def decrypt_data_responded_by_yp(self, response):
        # Se desencripta la clave privada del agente
        decrypted_data = self.decrypt_data(response)
        self.uri_yp = decrypted_data["server_uri"]
        self.public_key_yp = decrypted_data["public_key"]

        # Se decodifica la clave pública del yp
        public_key_yp = base64.b64decode(self.public_key_yp)
        self.public_key_yp = serialization.load_pem_public_key(public_key_yp, backend=default_backend())

    def __find_public_key_yp(self, data_decoding):
        for key, value in data_decoding.items():
            if isinstance(value, dict):
                self.__find_public_key_yp(value)
            else:
                if key == "public_key_yp":
                    self.__set_public_key_yp(value)
                    return True
        return False

    def __set_public_key_yp(self, public_key_yp: str):
        public_key_yp = base64.b64decode(public_key_yp)
        self.public_key_yp = serialization.load_pem_public_key(public_key_yp, backend=default_backend())

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

    def encrypt_data_with_shared_key(self, key, id_agent: str, code_otp: str = ""):
        self.id_agent = id_agent
        data_yp_bytes = self.__convert_in_bytes_data_to_send_yp()
        print('Data send yp: ', data_yp_bytes)

        # Generar un IV aleatorio
        iv = urandom(16)
        
        self.__set_shared_key_yp(key, code_otp)

        print('Shared key yp: ', self.shared_key_cifrate_yp)

        # Crear el objeto de cifrado
        cipher = self.__create_cipher(iv, self.shared_key_cifrate_yp[:32])
        encryptor = cipher.encryptor()

        # Cifrar los datos
        encrypted_data = encryptor.update(data_yp_bytes) + encryptor.finalize()

        # Retornar el IV y los datos cifrados (ambos necesarios para el descifrado)

        iv_base64 = self.__encode_base64(iv)
        encrypted_data_base64 = self.__encode_base64(encrypted_data)

        data_yp = {
            "iv": iv_base64,
            "data": encrypted_data_base64,
        }

        print('Data send yp cifrated: ', data_yp)

        data_deamon_bytes = self.__convert_in_bytes_data_to_send_deamon(data_yp, code_otp)

        print('Data send deamon: ', data_deamon_bytes)

        # Generar un IV aleatorio
        iv = urandom(16)

        self.__set_shared_key_deamon(key)

        print('Shared key deamon: ', self.shared_key__cifrate_ns)

        # Crear el objeto de cifrado
        cipher = self.__create_cipher(iv, self.shared_key__cifrate_ns[:32])
        encryptor = cipher.encryptor()

        # Cifrar los datos
        encrypted_data = encryptor.update(data_deamon_bytes) + encryptor.finalize()

        # Retornar el IV y los datos cifrados (ambos necesarios para el descifrado)

        iv_base64 = self.__encode_base64(iv)
        encrypted_data_base64 = self.__encode_base64(encrypted_data)

        data_send_deamon = {
            "id": self.id_agent,
            "iv": iv_base64,
            "data": encrypted_data_base64,
        }

        print('Data send deamon cifrated: ', data_send_deamon)

        return data_send_deamon

    def generate_private_key(self):
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

    def generate_public_key(self):
        return self.private_key.public_key()

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

    def __set_shared_key_yp(self, shared_key: str, code_otp: str = ""):
        if not code_otp:
            code_otp = ""
        ip = get_ip()
        key_shared_complete = ip + code_otp + self.id_agent + code_otp + shared_key + ip + self.id_agent + shared_key + code_otp
        self.shared_key_cifrate_yp = self.__hash_key_shared(key_shared_complete)

    def __set_shared_key_deamon(self, shared_key: str):
        ip = get_ip()
        key_shared_complete = shared_key + ip + self.id_agent + shared_key + ip +  shared_key  + ip + self.id_agent + shared_key
        self.shared_key__cifrate_ns = self.__hash_key_shared(key_shared_complete)

    def deserialize_public_key(self, public_key: str):
        public_key = base64.b64decode(public_key)
        return serialization.load_pem_public_key(public_key, backend=default_backend())
