import uuid

import Pyro4
from .agent_base import BaseAgent
from ...security.security_management import SecurityManagement
from ...utils.get_ip import get_ip
from ...utils.types.agent_type import RequestAgentType


@Pyro4.expose
class AgentConsumer(BaseAgent):
    def __init__(self, management_security: SecurityManagement, agent_name: str):
        super().__init__(management_security, agent_name)
        self.management_security = management_security
        self.agent_name = agent_name
        self.list_agents = {}
        self.management_security.management_logs.log_message(f"{self.agent_name} -> Initialized")

    def get_list_agents(self):
        if self.list_agents:
            """Returns a simplified list of agents with basic details."""
            self.management_security.management_logs.log_message(f"{self.agent_name} -> Getting list of agents")
            return [{
                "name": agent["name"],
                "description": agent["description"],
                "skills": agent["skills"],
                "id": agent_id
            } for agent_id, agent in self.list_agents.items()]
        else:
            return []

    def send_request_to_agent(self, id_agent: str, request_data: dict):
        self.management_security.management_logs.log_message(f"{self.agent_name} -> Sending request to agent {id_agent}")
        if id_agent in self.list_agents:
            agent_data = self.list_agents[id_agent]
            public_key = self.management_security.deserialize_public_key(agent_data["public_key"])
            try:
                agent_uri = self.management_security.ns.lookup(id_agent)
                agent_proxy = Pyro4.Proxy(agent_uri)
                data_send: RequestAgentType = {
                    'id_request': str(uuid.uuid4()),
                    'id_agent': self.management_security.id_agent,
                    'ip_agent': get_ip(),
                    'request_data': request_data
                }

                data_complete = self.management_security.management_data.load()

                request_data = data_complete.get("requests", [])
                request_data.append(data_send)
                data_complete["requests"] = request_data

                encrypted_request = self.management_security.encrypt_data_with_public_key(data_send, public_key,
                                                                                          id_agent)
                encrypted_response = agent_proxy.execute(encrypted_request)
                if encrypted_response is not None:
                    response = self.management_security.decrypt_data(encrypted_response)

                    data_response = data_complete.get("responses", [])
                    data_response.append(response)
                    data_complete["responses"] = data_response
                    self.management_security.management_data.save(data_complete)

                    self.management_security.management_logs.log_message(
                        f"{self.agent_name} -> Received response from agent {id_agent}")
                    return response
            except Pyro4.errors.CommunicationError as e:
                self.management_security.management_logs.log_message(
                    f"{self.agent_name} -> Communication error with agent {id_agent}: {str(e)}")
            except Exception as e:
                self.management_security.management_logs.log_message(
                    f"{self.agent_name} -> Error during request to agent {id_agent}: {str(e)}")
        else:
            self.management_security.management_logs.log_message(
                f"{self.agent_name} -> Specified agent {id_agent} does not exist")
        return None
