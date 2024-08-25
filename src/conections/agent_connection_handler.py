import threading
import time
import Pyro4
from src.security.security_management import SecurityManagement
from src.utils.get_ip import get_ip
from src.utils.types.agent_type import AgentType
from src.utils.custom_exception import CustomException
from src.utils.errors import ErrorTypes
from src.manage_logs.manage_logs_v_2 import ComponentType, LogType

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
        self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'AgentConnectionHandler initialized', LogType.START_SESSION)

    
    def conect_to_nameserver(self):
        start_time = time.perf_counter()
        self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Connecting to the NameServer', LogType.CONNECTION)
        self.name_server = Pyro4.locateNS(host=self.ip_name_server, port=9090)
        self.security_management.set_ns(self.name_server)
        end_time = time.perf_counter()
        connection_time = end_time - start_time
        self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Connected to the NameServer', LogType.END_CONNECTION, time_str=f"{connection_time:.9f}")
        self.conect_to_gateway()

    def get_name_server_instance(self):
        return self.gateway_proxy

    def get_uri_agent(self, agent):
        start_time = time.perf_counter()
        self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Registering URI of the agent', LogType.REGISTRATION_URI)
        uri = self.daemon.register(agent)
        end_time = time.perf_counter()
        registration_time = end_time - start_time
        self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Agent URI registered of the Agent', LogType.END_REGISTRATION_URI, time_str=f"{registration_time:.9f}")
        return uri

    def conect_to_gateway(self):
        start_time = time.perf_counter()
        self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Connecting to the Gateway', LogType.CONNECTION)
        uri_gateway = self.name_server.lookup("gateway_manager")
        self.gateway_proxy = Pyro4.Proxy(uri_gateway)
        end_time = time.perf_counter()
        connection_time = end_time - start_time
        self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Connected to the Gateway', LogType.END_CONNECTION, time_str=f"{connection_time:.9f}")

    def set_ip_name_server(self):
        self.ip_name_server = str(self.name_server).split("@")[1].split(":")[0]

    def register(self, code_otp: str = ''):
        start_time_total = time.perf_counter()

        try:
            print('Registering the agent')
            self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Initial Registering the agent', LogType.TIME_TOTAL_REGISTRATION)
            
            # ENCRYPTION
            start_time = time.perf_counter()
            self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Encrypting the data to pre-register', LogType.ENCRYPTION)
            request_data_to_pre_register = self.security_management.encrypt_data_with_shared_key(code_otp)
            end_time = time.perf_counter()
            encryption_time = end_time - start_time
            self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, f'Data encrypted to pre-register: {self._shorten_string(request_data_to_pre_register["data"])}', LogType.END_ENCRYPTION, time_str=f"{encryption_time:.9f}")

            print('Data encrypted to pre-register')
            self.gateway_proxy._pyroHandshake = request_data_to_pre_register

            # PREREGISTRATION
            start_time = time.perf_counter()
            self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Pre-registering the agent', LogType.PREREGISTRATION)
            response = self.gateway_proxy.register(self.security_management.uuid_agent)
            end_time = time.perf_counter()
            preregistration_time = end_time - start_time
            self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, f'Agent pre-registered: {self._shorten_string(response["data"])}', LogType.END_PREREGISTRATION, time_str=f"{preregistration_time:.9f}")

            # DECRYPTION
            start_time = time.perf_counter()
            self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Decrypting the data responded by the Yellow Page', LogType.DECRYPTION)
            self.security_management.decrypt_data_responded_by_yp(response)
            end_time = time.perf_counter()
            decryption_time = end_time - start_time
            self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Data decrypted', LogType.END_DECRYPTION, time_str=f"{decryption_time:.9f}")
            public_key_yp = self.security_management.public_key_yp

            # REGISTRATION ENCRYPTION
            self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Encrypting the data to register', LogType.ENCRYPTION)
            data_encrypted = self.security_management.encrypt_data_with_public_key(self.security_management.get_data_agent(), public_key_yp, self.security_management.uuid_agent)
            self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Data encrypted to register {self._shorten_string(data_encrypted["data"])}', LogType.END_ENCRYPTION)

            # FINAL REGISTRATION
            start_time = time.perf_counter()
            self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Registering the agent with the Gateway', LogType.REGISTRATION)
            self.security_management.server.register_agent(self._shorten_string(data_encrypted))
            end_time = time.perf_counter()
            registration_time = end_time - start_time
            self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Agent registered with Gateway', LogType.END_REGISTRATION, time_str=f"{registration_time:.9f}")

            # FINALIZE REGISTRATION
            self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Registering the agent. Delivering its capabilities | features | description| functions | etc.', LogType.REGISTRATION)
            self.name_server.register(f'{self.security_management.uuid_agent}', self.get_uri_agent(self.remote_object))
            end_time_total = time.perf_counter()
            total_time = end_time_total - start_time_total
            self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Agent registered', LogType.END_REGISTRATION, time_str=f"{total_time:.9f}")
            daemon_thread = threading.Thread(target=self.daemon.requestLoop)
            print('Agent {self.security_management.uuid_agent} - {self.security_management.get_data_agent()["name"]} registered in {total_time:.9f} seconds')
            self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Agent registered', LogType.END_TIME_TOTAL_REGISTRATION, success=True, time_str=f"{total_time:.9f}")
            daemon_thread.daemon = True
            daemon_thread.start()
        except Exception as e:
            end_time_total = time.perf_counter()
            total_time = end_time_total - start_time_total
            self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, f'Error: {str(e)}', LogType.ERROR, success=False, time_str=f"{total_time:.9f}")
            raise e

    def activate_daemon(self):
        self.security_management.management_logs.log_message(ComponentType.AGENT_CONNECTION_HANDLER, 'Daemon activated', LogType.DAEMON_START)
        self.daemon.requestLoop()

    def _shorten_string(self, s: str) -> str:
        if len(s) > 10:
            return f'{s[:5]}...{s[-5:]}'
        return s
