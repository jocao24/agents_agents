import uuid
import Pyro4
import time
from .agent_base import BaseAgent
from src.security.security_management import SecurityManagement
from src.utils.get_ip import get_ip
from src.utils.types.agent_type import RequestAgentType
from src.manage_logs.manage_logs_v_2 import ComponentType, LogType

@Pyro4.expose
class AgentConsumer(BaseAgent):
    def __init__(self, management_security: SecurityManagement, agent_name: str):
        super().__init__(management_security, agent_name)
        self.management_security = management_security
        self.agent_name = agent_name
        self.list_agents = {}
        self.management_security.management_logs.log_message(ComponentType.AGENT_CONSUMER, f"{self.agent_name} -> Initialized", LogType.START_SESSION)

    def get_list_agents(self):
        """Returns a simplified list of agents with basic details."""
        start_time = time.perf_counter()
        self.management_security.management_logs.log_message(ComponentType.AGENT_CONSUMER, f"{self.agent_name} -> Getting list of agents", LogType.REQUEST)
        result = []
        if self.list_agents:
            result = [{
                "name": agent["name"],
                "description": agent["description"],
                "skills": agent["skills"],
                "id": agent_id
            } for agent_id, agent in self.list_agents.items()]
        
        end_time = time.perf_counter()
        self.management_security.management_logs.log_message(ComponentType.AGENT_CONSUMER, f"{self.agent_name} -> Got list of agents", LogType.END_REQUEST, time_str=f"{end_time - start_time:.9f}")
        return result

    def send_request_to_agent(self, id_agent: str, request_data: dict):
        start_time_total = time.perf_counter()
        self.management_security.management_logs.log_message(ComponentType.AGENT_CONSUMER, f"{self.agent_name} -> Sending request to agent {id_agent}", LogType.REQUEST)
        
        if id_agent in self.list_agents:
            agent_data = self.list_agents[id_agent]
            public_key = self.management_security.deserialize_public_key(agent_data["public_key"])
            try:
                agent_uri = self.management_security.ns.lookup(id_agent)
                agent_proxy = Pyro4.Proxy(agent_uri)
                data_send: RequestAgentType = {
                    'id_request': str(uuid.uuid4()),
                    'id_agent': self.management_security.uuid_agent,
                    'ip_agent': get_ip(),
                    'request_data': request_data
                }

                data_complete = self.management_security.management_data.load()

                request_data = data_complete.get("requests", [])
                request_data.append(data_send)
                data_complete["requests"] = request_data

                start_time = time.perf_counter()
                encrypted_request = self.management_security.encrypt_data_with_public_key(data_send, public_key, id_agent)
                end_time = time.perf_counter()
                self.management_security.management_logs.log_message(ComponentType.AGENT_CONSUMER, f"{self.agent_name} -> Request encrypted", LogType.END_ENCRYPTION, time_str=f"{end_time - start_time:.9f}")
                
                start_time = time.perf_counter()
                encrypted_response = agent_proxy.execute(encrypted_request)
                end_time = time.perf_counter()
                self.management_security.management_logs.log_message(ComponentType.AGENT_CONSUMER, f"{self.agent_name} -> Response received", LogType.END_REQUEST, time_str=f"{end_time - start_time:.9f}")

                if encrypted_response is not None:
                    start_time = time.perf_counter()
                    response = self.management_security.decrypt_data(encrypted_response)
                    end_time = time.perf_counter()
                    self.management_security.management_logs.log_message(ComponentType.AGENT_CONSUMER, f"{self.agent_name} -> Response decrypted", LogType.END_DECRYPTION, time_str=f"{end_time - start_time:.9f}")

                    data_response = data_complete.get("responses", [])
                    data_response.append(response)
                    data_complete["responses"] = data_response
                    self.management_security.management_data.save(data_complete)

                    self.management_security.management_logs.log_message(ComponentType.AGENT_CONSUMER, f"{self.agent_name} -> Received response from agent {id_agent}", LogType.RESPONSE)
                    end_time_total = time.perf_counter()
                    self.management_security.management_logs.log_message(ComponentType.AGENT_CONSUMER, f"{self.agent_name} -> Total request time", LogType.END_REQUEST, time_str=f"{end_time_total - start_time_total:.9f}")
                    return response

            except Pyro4.errors.CommunicationError as e:
                end_time_total = time.perf_counter()
                self.management_security.management_logs.log_message(ComponentType.AGENT_CONSUMER, f"{self.agent_name} -> Communication error with agent {id_agent}: {str(e)}", LogType.ERROR)
                self.management_security.management_logs.log_message(ComponentType.AGENT_CONSUMER, f"{self.agent_name} -> Total request time", LogType.END_REQUEST, time_str=f"{end_time_total - start_time_total:.9f}")
            except Exception as e:
                end_time_total = time.perf_counter()
                self.management_security.management_logs.log_message(ComponentType.AGENT_CONSUMER, f"{self.agent_name} -> Error during request to agent {id_agent}: {str(e)}", LogType.ERROR)
                self.management_security.management_logs.log_message(ComponentType.AGENT_CONSUMER, f"{self.agent_name} -> Total request time", LogType.END_REQUEST, time_str=f"{end_time_total - start_time_total:.9f}")
        else:
            end_time_total = time.perf_counter()
            self.management_security.management_logs.log_message(ComponentType.AGENT_CONSUMER, f"{self.agent_name} -> Specified agent {id_agent} does not exist", LogType.ERROR)
            self.management_security.management_logs.log_message(ComponentType.AGENT_CONSUMER, f"{self.agent_name} -> Total request time", LogType.END_REQUEST, time_str=f"{end_time_total - start_time_total:.9f}")
        return None
