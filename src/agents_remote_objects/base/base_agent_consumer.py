import uuid
import Pyro4
import time
from .agent_base import BaseAgent
from src.security.security_management import SecurityManagement
from src.utils.get_ip import get_ip
from src.utils.types.agent_type import RequestAgentType, ResponseAgentType
from src.manage_logs.manage_logs_v_2 import ComponentType, LogType

@Pyro4.expose
class AgentConsumer(BaseAgent):
    def __init__(self, management_security: SecurityManagement, agent_name):
        super().__init__(management_security, agent_name)
        self.management_security = management_security
        self.proxy_yellow_page = None
        self.list_agents = {}
        self.agent_name = agent_name
        self.management_security.management_logs.log_message(
            ComponentType.AGENT_CONSUMER, 
            f'{agent_name} -> {agent_name} initialized', 
            LogType.START_SESSION,
            agent_uuid=self.management_security.uuid_agent,
            agent_type=self.management_security.agent_type
        )

    def prepare_request_data(self, data):
        raise NotImplementedError("This method should be overridden by subclasses")

    def process_response(self, response_data):
        raise NotImplementedError("This method should be overridden by subclasses")

    def execute_request(self, data, provider_uuid):
        try:
            start_time_total = time.perf_counter()
            
            # Preparar datos de la solicitud
            request_data = self.prepare_request_data(data)
            request_id = str(uuid.uuid4())
            
            # Log de inicio de solicitud
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_CONSUMER, 
                f'{self.agent_name} -> Preparing request {request_id}', 
                LogType.REQUEST,
                agent_uuid=self.management_security.uuid_agent,
                uuid_agent_request=request_id
            )

            # Crear estructura de solicitud
            data_request: RequestAgentType = {
                "id_request": request_id,
                "id_agent": self.management_security.uuid_agent,
                "request_data": request_data
            }

            # Guardar solicitud
            data_complete = self.management_security.management_data.load()
            request_list = data_complete.get("requests", [])
            request_list.append(data_request)
            data_complete["requests"] = request_list
            self.management_security.management_data.save(data_complete)

            # Encriptar datos
            start_time_enc = time.perf_counter()
            public_key = self.management_security.deserialize_public_key(
                self.list_agents[provider_uuid]["public_key"]
            )
            data_encrypted = self.management_security.encrypt_data_with_public_key(
                data_request, public_key, self.management_security.id_agent
            )
            end_time_enc = time.perf_counter()
            
            # Log de encriptación
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_CONSUMER, 
                f'{self.agent_name} -> Request {request_id} encrypted', 
                LogType.END_ENCRYPTION,
                time_str=f"{end_time_enc - start_time_enc:.9f}",
                agent_uuid=self.management_security.uuid_agent,
                uuid_agent_request=request_id
            )

            # Enviar solicitud
            start_time_send = time.perf_counter()
            provider_uri = self.list_agents[provider_uuid]["uri"]
            provider_proxy = Pyro4.Proxy(provider_uri)
            response_encrypted = provider_proxy.execute(data_encrypted)
            end_time_send = time.perf_counter()
            
            # Log de envío
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_CONSUMER, 
                f'{self.agent_name} -> Request {request_id} sent to provider', 
                LogType.REQUEST,
                time_str=f"{end_time_send - start_time_send:.9f}",
                agent_uuid=self.management_security.uuid_agent,
                uuid_agent_request=request_id,
                uuid_agent_response=provider_uuid
            )

            # Desencriptar respuesta
            start_time_dec = time.perf_counter()
            response_decrypted = self.management_security.decrypt_data(response_encrypted)
            end_time_dec = time.perf_counter()
            
            # Log de desencriptación
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_CONSUMER, 
                f'{self.agent_name} -> Response for request {request_id} decrypted', 
                LogType.END_DECRYPTION,
                time_str=f"{end_time_dec - start_time_dec:.9f}",
                agent_uuid=self.management_security.uuid_agent,
                uuid_agent_request=request_id,
                uuid_agent_response=provider_uuid
            )

            # Procesar respuesta
            response_data: ResponseAgentType = ResponseAgentType(**response_decrypted)
            result = self.process_response(response_data["data_response"])
            
            # Guardar respuesta
            data_complete = self.management_security.management_data.load()
            response_list = data_complete.get("responses", [])
            response_list.append(response_data)
            data_complete["responses"] = response_list
            self.management_security.management_data.save(data_complete)

            # Log final
            end_time_total = time.perf_counter()
            total_time = end_time_total - start_time_total
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_CONSUMER, 
                f'{self.agent_name} -> Request {request_id} completed', 
                LogType.END_REQUEST,
                time_str=f"{total_time:.9f}",
                agent_uuid=self.management_security.uuid_agent,
                uuid_agent_request=request_id,
                uuid_agent_response=provider_uuid
            )

            return result

        except Exception as e:
            end_time_total = time.perf_counter()
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_CONSUMER, 
                f'Error executing request: {e}', 
                LogType.ERROR,
                agent_uuid=self.management_security.uuid_agent,
                uuid_agent_request=request_id if 'request_id' in locals() else None,
                uuid_agent_response=provider_uuid
            )
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_CONSUMER, 
                f'{self.agent_name} -> Request failed', 
                LogType.END_REQUEST,
                time_str=f"{end_time_total - start_time_total:.9f}",
                agent_uuid=self.management_security.uuid_agent,
                uuid_agent_request=request_id if 'request_id' in locals() else None,
                uuid_agent_response=provider_uuid
            )
            raise e

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
        request_uuid = request_data.get('request_uuid', str(uuid.uuid4()))
        
        # Log de inicio del ciclo completo de la solicitud
        self.management_security.management_logs.log_message(
            ComponentType.AGENT_CONSUMER, 
            f"{self.agent_name} -> Starting complete request cycle with agent {id_agent}", 
            LogType.CONSUMER_REQUEST_START,
            agent_uuid=self.management_security.uuid_agent,
            uuid_request=request_uuid
        )
        
        if id_agent in self.list_agents:
            agent_data = self.list_agents[id_agent]
            public_key = self.management_security.deserialize_public_key(agent_data["public_key"])
            try:
                agent_uri = self.management_security.ns.lookup(id_agent)
                agent_proxy = Pyro4.Proxy(agent_uri)
                
                # Crear objeto con los datos a encriptar
                data_to_encrypt = {
                    'id_request': str(uuid.uuid4()),
                    'id_agent': self.management_security.uuid_agent,
                    'ip_agent': get_ip(),
                    'request_data': request_data
                }

                # Encriptar solo los datos de la solicitud
                start_time = time.perf_counter()
                encrypted_data = self.management_security.encrypt_data_with_public_key(data_to_encrypt, public_key, id_agent)
                end_time = time.perf_counter()
                
                # Crear objeto final con UUIDs sin encriptar
                final_data = {
                    'id_agent': self.management_security.uuid_agent,
                    'request_uuid': request_uuid,
                    'encrypted_data': encrypted_data
                }

                data_complete = self.management_security.management_data.load()
                request_data = data_complete.get("requests", [])
                request_data.append(final_data)
                data_complete["requests"] = request_data

                self.management_security.management_logs.log_message(
                    ComponentType.AGENT_CONSUMER, 
                    f"{self.agent_name} -> Request encrypted", 
                    LogType.END_ENCRYPTION, 
                    time_str=f"{end_time - start_time:.9f}",
                    agent_uuid=self.management_security.uuid_agent,
                    uuid_request=request_uuid
                )
                
                start_time = time.perf_counter()
                encrypted_response = agent_proxy.execute(final_data)
                end_time = time.perf_counter()
                self.management_security.management_logs.log_message(
                    ComponentType.AGENT_CONSUMER, 
                    f"{self.agent_name} -> Response received", 
                    LogType.END_REQUEST, 
                    time_str=f"{end_time - start_time:.9f}",
                    agent_uuid=self.management_security.uuid_agent,
                    uuid_request=request_uuid
                )

                start_time = time.perf_counter()
                response_data = self.management_security.decrypt_data(encrypted_response)
                end_time = time.perf_counter()
                self.management_security.management_logs.log_message(
                    ComponentType.AGENT_CONSUMER, 
                    f"{self.agent_name} -> Response decrypted", 
                    LogType.END_DECRYPTION, 
                    time_str=f"{end_time - start_time:.9f}",
                    agent_uuid=self.management_security.uuid_agent,
                    uuid_request=request_uuid
                )

                data_response = data_complete.get("responses", [])
                data_response.append(response_data)
                data_complete["responses"] = data_response
                self.management_security.management_data.save(data_complete)

                end_time_total = time.perf_counter()
                # Log de fin del ciclo completo de la solicitud
                self.management_security.management_logs.log_message(
                    ComponentType.AGENT_CONSUMER, 
                    f"{self.agent_name} -> Completed request cycle with agent {id_agent}", 
                    LogType.CONSUMER_REQUEST_END, 
                    time_str=f"{end_time_total - start_time_total:.9f}",
                    agent_uuid=self.management_security.uuid_agent,
                    uuid_request=request_uuid
                )
                return response_data

            except Exception as e:
                end_time_total = time.perf_counter()
                self.management_security.management_logs.log_message(
                    ComponentType.AGENT_CONSUMER, 
                    f"{self.agent_name} -> Error during request to agent {id_agent}: {str(e)}", 
                    LogType.ERROR,
                    agent_uuid=self.management_security.uuid_agent,
                    uuid_request=request_uuid
                )
                # Log de fin del ciclo completo de la solicitud (en caso de error)
                self.management_security.management_logs.log_message(
                    ComponentType.AGENT_CONSUMER, 
                    f"{self.agent_name} -> Failed request cycle with agent {id_agent}", 
                    LogType.CONSUMER_REQUEST_END, 
                    time_str=f"{end_time_total - start_time_total:.9f}",
                    agent_uuid=self.management_security.uuid_agent,
                    uuid_request=request_uuid
                )
        else:
            end_time_total = time.perf_counter()
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_CONSUMER, 
                f"{self.agent_name} -> Specified agent {id_agent} does not exist", 
                LogType.ERROR,
                agent_uuid=self.management_security.uuid_agent,
                uuid_request=request_uuid
            )
            # Log de fin del ciclo completo de la solicitud (en caso de error)
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_CONSUMER, 
                f"{self.agent_name} -> Failed request cycle with agent {id_agent}", 
                LogType.CONSUMER_REQUEST_END, 
                time_str=f"{end_time_total - start_time_total:.9f}",
                agent_uuid=self.management_security.uuid_agent,
                uuid_request=request_uuid
            )
        return None
