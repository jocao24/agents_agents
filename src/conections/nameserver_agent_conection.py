import threading

import Pyro4

from src.security.security_management import SecurityManagement
from utils.errors import ErrorTypes
from utils.types.agent_type import AgentType
from utils.get_ip import get_ip


class NameServerAgentConnection:

    def __init__(self, data_agent: AgentType):
        self.name_agent = data_agent['name']
        self.description_agent = data_agent['description']
        self.id_agent = data_agent['id']
        self.local_ip = data_agent['local_ip']
        self.skills = data_agent['skills']
        self.ns_instance = None
        self.name_server = None
        self.ip_name_server = None
        self.uri = None
        self.daemon = Pyro4.Daemon(host=self.local_ip)

    def conect_to_nameserver_automatically(self):
        self.name_server = Pyro4.locateNS()
        self.conect_to_gateway()
        self.set_ip_name_server()
        return self.ip_name_server

    def conect_to_nameserver_manually(self, ip_name_server: str = None):
        self.ip_name_server = ip_name_server
        self.name_server = Pyro4.locateNS(host=self.ip_name_server, port=9090)
        self.conect_to_gateway()

    def get_name_server_instance(self):
        return self.ns_instance

    def get_uri_agent(self, agent):
        return self.daemon.register(agent)

    def conect_to_gateway(self):
        uri_ns_controller = self.name_server.lookup("gateway_manager")
        proxi = Pyro4.Proxy(uri_ns_controller)
        self.ns_instance = proxi

    def set_ip_name_server(self):
        self.ip_name_server = str(self.name_server).split("@")[1].split(":")[0]

    def register_agent(self, uri):
        self.ns_instance._pyroHandshake = self.get_data_agent()
        self.name_server.register(f'{self.id_agent}-{self.name_agent}', uri, metadata={"agent": self.get_data_agent()})

    def register(self, key_shared: str, agent, management_security: SecurityManagement, code_otp: str = '', is_client: bool = False) :

        try:
            request_data_to_pre_register = management_security.encrypt_data_with_shared_key(key_shared, self.id_agent, code_otp)
            print("Data encrypted to pre-register: ", request_data_to_pre_register)

            self.ns_instance._pyroHandshake = request_data_to_pre_register
            response = self.ns_instance.register(self.id_agent)
            management_security.decrypt_data_responded_by_yp(response)

            # Se establece un prxy con el yp
            proxi_yp = Pyro4.Proxy(management_security.uri_yp)

            data_agent = {
                "name": self.name_agent,
                "description": self.description_agent,
                "skills": self.skills,
                "is_client": is_client,
            }
            data_encrypted = management_security.encrypt_data_with_public_key(data_agent, management_security.public_key_yp, self.id_agent)

            # Se envía la key cifrada con la clave pública del yp, el iv y los datos cifrados
            proxi_yp.register_agent(data_encrypted)

            self.name_server.register(f'{self.id_agent}', self.get_uri_agent(agent))
            management_security.register_ok(proxi_yp, self.name_server)

            # Inicializa un hilo para el daemon
            daemon_thread = threading.Thread(target=self.daemon.requestLoop)
            daemon_thread.daemon = True
            daemon_thread.start()

            return True, False, '', False
        except Exception as e:
            parts_message = (str(e).split(') rejected: '))[1].split(": ")
            type_error = parts_message[0]
            message_error = parts_message[1]
            error_type = ErrorTypes(type_error, message_error)
            print(error_type)
            # Se corta el mensa
            message = error_type
            return None, True, message, False

    def get_data_agent(self):
        return {
            "name_agent": self.name_agent,
            "description_agent": self.description_agent,
            "id_agent": self.id_agent,
            "local_ip": get_ip(),
            "ip_name_server": self.ip_name_server,
            "skills": self.skills,
        }

    def activate_daemon(self):
        self.daemon.requestLoop()
