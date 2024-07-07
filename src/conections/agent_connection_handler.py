import threading
import time
import Pyro4
from ..security.security_management import SecurityManagement
from ..utils.get_ip import get_ip
from ..utils.types.agent_type import AgentType
from ..utils.custom_exception import CustomException
from ..utils.errors import ErrorTypes


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
        start_time_total = time.perf_counter()

        try:
            print('Registering the agent')
            self.security_management.management_logs.log_message('AgentConnectionHandler -> Registering the agent')
            
            start_time = time.perf_counter()
            self.security_management.management_logs.log_message('AgentConnectionHandler -> Encrypting the data to pre-register')
            request_data_to_pre_register = self.security_management.encrypt_data_with_shared_key(code_otp)
            end_time = time.perf_counter()
            encryption_time = end_time - start_time
            self.security_management.management_logs.log_message(f'AgentConnectionHandler -> Data encrypted to pre-register: {self._shorten_string(request_data_to_pre_register["data"])} (Time: {encryption_time:.6f} seconds)')

            print('Data encrypted to pre-register')
            self.gateway_proxy._pyroHandshake = request_data_to_pre_register

            start_time = time.perf_counter()
            self.security_management.management_logs.log_message('AgentConnectionHandler -> Pre-registering the agent')
            response = self.gateway_proxy.register(self.security_management.id_agent)
            end_time = time.perf_counter()
            preregistration_time = end_time - start_time
            self.security_management.management_logs.log_message(f'AgentConnectionHandler -> Agent pre-registered: {self._shorten_string(response["data"])} (Time: {preregistration_time:.6f} seconds)')

            start_time = time.perf_counter()
            self.security_management.management_logs.log_message('AgentConnectionHandler -> Decrypting the data responded by the Yellow Page')
            self.security_management.decrypt_data_responded_by_yp(response)
            end_time = time.perf_counter()
            decryption_time = end_time - start_time
            self.security_management.management_logs.log_message(f'AgentConnectionHandler -> Data decrypted (Time: {decryption_time:.6f} seconds)')
            public_key_yp = self.security_management.public_key_yp

            self.security_management.management_logs.log_message('AgentConnectionHandler -> Encrypting the data to register')
            data_encrypted = self.security_management.encrypt_data_with_public_key(self.security_management.get_data_agent(), public_key_yp, self.security_management.id_agent)
            self.security_management.management_logs.log_message(f'AgentConnectionHandler -> Data encrypted to register {self._shorten_string(data_encrypted["data"])}')

            start_time = time.perf_counter()
            self.security_management.management_logs.log_message('AgentConnectionHandler -> Encrypting the data to register')
            self.security_management.server.register_agent(self._shorten_string(data_encrypted))
            end_time = time.perf_counter()
            registration_encryption_time = end_time - start_time
            self.security_management.management_logs.log_message(f'AgentConnectionHandler -> Data encrypted to register {self._shorten_string(data_encrypted["data"])} (Time: {registration_encryption_time:.6f} seconds)')

            self.security_management.management_logs.log_message('AgentConnectionHandler -> Registering the agent. Delivering its capabilities, features, description, functions, etc. ')
            self.name_server.register(f'{self.security_management.id_agent}', self.get_uri_agent(self.remote_object))
            end_time_total = time.perf_counter()
            total_time = end_time_total - start_time_total
            self.security_management.management_logs.log_message(f'AgentConnectionHandler -> Agent registered (Time: {total_time:.6f} seconds)')
            daemon_thread = threading.Thread(target=self.daemon.requestLoop)
            print(f'Agent {self.security_management.id_agent} - {self.security_management.get_data_agent()["name"]} registered in {total_time:.6f} seconds')
            daemon_thread.daemon = True
            daemon_thread.start()
        except Exception as e:
            end_time_total = time.perf_counter()
            total_time = end_time_total - start_time_total
            self.security_management.management_logs.log_message(f'AgentConnectionHandler -> Error: {str(e)} (Time: {total_time:.6f} seconds)')
            raise e

    def activate_daemon(self):
        self.security_management.management_logs.log_message('AgentConnectionHandler -> Daemon activated')
        self.daemon.requestLoop()

    def _shorten_string(self, s: str) -> str:
        if len(s) > 10:
            return f'{s[:5]}...{s[-5:]}'
        return s
