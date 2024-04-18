import threading
import Pyro4
from src.security.security_management import SecurityManagement
from src.utils.custom_exception import CustomException
from src.utils import ErrorTypes
from src.utils.types import AgentType
from src.utils.get_ip import get_ip


class AgentConnectionHandler:

    def __init__(self, security_management: SecurityManagement, remote_object):
        self.gateway_proxy = None
        self.name_server = None
        self.uri = None
        self.security_management = security_management
        self.ip_name_server = self.security_management.get_data_agent()['ip_name_server']
        self.daemon = Pyro4.Daemon(host=get_ip())
        self.remote_object = remote_object
        self.security_management.ns = self.name_server
        self.conect_to_nameserver()
        self.security_management.management_logs.log_message('AgentConnectionHandler -> AgentConnectionHandler initialized')

    def conect_to_nameserver(self):
        self.security_management.management_logs.log_message('AgentConnectionHandler -> Connecting to the NameServer')
        self.name_server = Pyro4.locateNS(host=self.ip_name_server, port=9090)
        self.security_management.set_ns(self.name_server)
        self.security_management.management_logs.log_message('AgentConnectionHandler -> Connected to the NameServer')
        self.conect_to_gateway()

    def get_name_server_instance(self):
        return self.gateway_proxy

    def get_uri_agent(self, agent):
        self.security_management.management_logs.log_message('AgentConnectionHandler -> Registering the agent')
        uri = self.daemon.register(agent)
        self.security_management.management_logs.log_message('AgentConnectionHandler -> Agent registered')
        return uri

    def conect_to_gateway(self):
        self.security_management.management_logs.log_message('AgentConnectionHandler -> Connecting to the Gateway')
        uri_gateway = self.name_server.lookup("gateway_manager")
        self.gateway_proxy = Pyro4.Proxy(uri_gateway)
        self.security_management.management_logs.log_message('AgentConnectionHandler -> Connected to the Gateway')

    def set_ip_name_server(self):
        self.ip_name_server = str(self.name_server).split("@")[1].split(":")[0]

    def register(self, code_otp: str = ''):

        try:
            print('Registering the agent')
            self.security_management.management_logs.log_message('AgentConnectionHandler -> Registering the agent')

            self.security_management.management_logs.log_message('AgentConnectionHandler -> Encrypting the data to pre-register')
            request_data_to_pre_register = self.security_management.encrypt_data_with_shared_key(code_otp)
            print('Data encrypted to pre-register')
            self.security_management.management_logs.log_message('AgentConnectionHandler -> Data encrypted to pre-register')

            self.gateway_proxy._pyroHandshake = request_data_to_pre_register

            self.security_management.management_logs.log_message('AgentConnectionHandler -> Pre-registering the agent')
            response = self.gateway_proxy.register(self.security_management.id_agent)
            self.security_management.management_logs.log_message('AgentConnectionHandler -> Agent pre-registered')

            self.security_management.management_logs.log_message('AgentConnectionHandler -> Decrypting the data responded by the Yellow Page')
            self.security_management.decrypt_data_responded_by_yp(response)
            self.security_management.management_logs.log_message('AgentConnectionHandler -> Data decrypted')
            public_key_yp = self.security_management.public_key_yp

            self.security_management.management_logs.log_message('AgentConnectionHandler -> Encrypting the data to register')
            data_encrypted = self.security_management.encrypt_data_with_public_key(self.security_management.get_data_agent(), public_key_yp, self.security_management.id_agent)
            self.security_management.management_logs.log_message('AgentConnectionHandler -> Data encrypted to register')

            self.security_management.management_logs.log_message('AgentConnectionHandler -> Registering the agent')
            self.security_management.server.register_agent(data_encrypted)
            self.security_management.management_logs.log_message('AgentConnectionHandler -> Agent registered')

            self.security_management.management_logs.log_message('AgentConnectionHandler -> Activating the daemon')
            self.name_server.register(f'{self.security_management.id_agent}', self.get_uri_agent(self.remote_object))
            daemon_thread = threading.Thread(target=self.daemon.requestLoop)
            daemon_thread.daemon = True
            daemon_thread.start()
        except Exception as e:
            self.security_management.management_logs.log_message(f'AgentConnectionHandler -> Error: {str(e)}')
            raise e

    def activate_daemon(self):
        self.security_management.management_logs.log_message('AgentConnectionHandler -> Daemon activated')
        self.daemon.requestLoop()
