import Pyro5.api
from src.agents_remote_objects.base.agent_base import BaseAgent
from src.security.security_management import SecurityManagement
from utils.types.agent_type import RequestAgentType, ResponseAgentType


class AgentProvider(BaseAgent):
    def __init__(self, management_security: SecurityManagement, agent_name):
        super().__init__(management_security, agent_name)
        self.management_security = management_security
        self.proxy_yellow_page = None
        self.list_agents = {}
        self.agent_name = agent_name
        self.management_security.management_logs.log_message(f'{agent_name} -> {agent_name} initialized')

    def perform_operation(self, data_request):
        raise NotImplementedError("This method should be overridden by subclasses")

    @Pyro5.api.expose
    def execute(self, data: dict):
        try:
            self.management_security.management_logs.log_message(f'{self.agent_name} -> Execute received')
            data_desencrypted = self.management_security.decrypt_data(data)
            self.management_security.management_logs.log_message(f'{self.agent_name} -> Data decrypted')

            data_agent_request: RequestAgentType = RequestAgentType(**data_desencrypted)
            data_request = data_agent_request["request_data"]

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

            result_encr = self.management_security.encrypt_data_with_public_key(response_data, public_key, self.management_security.id_agent)
            self.management_security.management_logs.log_message(f'{self.agent_name} -> Result encrypted to send')
            return result_encr
        except Exception as e:
            self.management_security.management_logs.log_message(f'Error: {e}')
            return str(e)
