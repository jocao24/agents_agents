import Pyro4
import time
from src.security.security_management import SecurityManagement
from .agent_base import BaseAgent
from src.utils.types.agent_type import RequestAgentType, ResponseAgentType
from src.manage_logs.manage_logs_v_2 import ComponentType, LogType

class AgentProvider(BaseAgent):
    def __init__(self, management_security: SecurityManagement, agent_name):
        super().__init__(management_security, agent_name)
        self.management_security = management_security
        self.proxy_yellow_page = None
        self.list_agents = {}
        self.agent_name = agent_name
        self.management_security.management_logs.log_message(ComponentType.AGENT_PROVIDER, f'{agent_name} -> {agent_name} initialized', LogType.START_SESSION)

    def perform_operation(self, data_request):
        raise NotImplementedError("This method should be overridden by subclasses")

    @Pyro4.expose
    def execute(self, data: dict):
        try:
            start_time_total = time.perf_counter()
            self.management_security.management_logs.log_message(ComponentType.AGENT_PROVIDER, f'{self.agent_name} -> Execute received', LogType.REQUEST)

            start_time = time.perf_counter()
            data_desencrypted = self.management_security.decrypt_data(data)
            end_time = time.perf_counter()
            self.management_security.management_logs.log_message(ComponentType.AGENT_PROVIDER, f'{self.agent_name} -> Data decrypted', LogType.END_DECRYPTION, time_str=f"{end_time - start_time:.9f}")

            data_agent_request: RequestAgentType = RequestAgentType(**data_desencrypted)
            data_request = data_agent_request["request_data"]
            data_request["id_request"] = data_agent_request["id_request"]

            data_complete = self.management_security.management_data.load()

            request_data = data_complete.get("requests", [])
            request_data.append(data_request)
            data_complete["requests"] = request_data

            result = self.perform_operation(data_request)

            id_agent = data_agent_request["id_agent"]
            public_key_org = self.list_agents[id_agent]["public_key"]
            public_key = self.management_security.deserialize_public_key(public_key_org)

            response_data: ResponseAgentType = {
                "id_request": data_agent_request["id_request"],
                "data_response": {
                    "result": result
                }
            }

            data_response = data_complete.get("responses", [])
            data_response.append(response_data)
            data_complete["responses"] = data_response

            self.management_security.management_data.save(data_complete)

            start_time = time.perf_counter()
            result_encr = self.management_security.encrypt_data_with_public_key(response_data, public_key, self.management_security.id_agent)
            end_time = time.perf_counter()
            self.management_security.management_logs.log_message(ComponentType.AGENT_PROVIDER, f'{self.agent_name} -> Result encrypted to send', LogType.END_ENCRYPTION, time_str=f"{end_time - start_time:.9f}")

            end_time_total = time.perf_counter()
            self.management_security.management_logs.log_message(ComponentType.AGENT_PROVIDER, f'{self.agent_name} -> Total execution time', LogType.END_REQUEST, time_str=f"{end_time_total - start_time_total:.9f}")
            return result_encr
        except Exception as e:
            end_time_total = time.perf_counter()
            self.management_security.management_logs.log_message(ComponentType.AGENT_PROVIDER, f'Error: {e}', LogType.ERROR)
            self.management_security.management_logs.log_message(ComponentType.AGENT_PROVIDER, f'{self.agent_name} -> Total execution time with error', LogType.END_REQUEST, time_str=f"{end_time_total - start_time_total:.9f}")
            return str(e)
