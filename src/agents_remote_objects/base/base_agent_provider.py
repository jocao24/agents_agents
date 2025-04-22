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
        self.management_security.management_logs.log_message(
            ComponentType.AGENT_PROVIDER, 
            f'{agent_name} -> {agent_name} initialized', 
            LogType.START_SESSION,
            agent_uuid=self.management_security.uuid_agent,
            agent_type=self.management_security.agent_type
        )

    def perform_operation(self, data_request):
        raise NotImplementedError("This method should be overridden by subclasses")

    @Pyro4.expose
    def execute(self, data: dict):
        try:
            start_time_total = time.perf_counter()
            
            # Obtener UUIDs del objeto data sin desencriptar
            requester_uuid = data.get("id_agent")
            request_uuid = data.get("request_uuid")
            
            # Log de inicio de recepción de solicitud
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_PROVIDER, 
                f'{self.agent_name} -> Starting request reception', 
                LogType.PROVIDER_REQUEST_START,
                agent_uuid=self.management_security.uuid_agent,
                uuid_request=request_uuid,
                uuid_agent_request=requester_uuid
            )
            
            # Log de recepción de solicitud
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_PROVIDER, 
                f'{self.agent_name} -> Request received', 
                LogType.REQUEST,
                agent_uuid=self.management_security.uuid_agent,
                uuid_request=request_uuid,
                uuid_agent_request=requester_uuid
            )
            
            # Desencriptar datos
            start_time = time.perf_counter()
            encrypted_data = data.get("encrypted_data")
            data_desencrypted = self.management_security.decrypt_data(encrypted_data)
            end_time = time.perf_counter()
            
            # Log de desencriptación
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_PROVIDER, 
                f'{self.agent_name} -> Request data decrypted', 
                LogType.END_DECRYPTION, 
                time_str=f"{end_time - start_time:.9f}",
                agent_uuid=self.management_security.uuid_agent,
                uuid_request=request_uuid,
                uuid_agent_request=requester_uuid
            )
            
            # Procesar datos de la solicitud
            data_agent_request: RequestAgentType = RequestAgentType(**data_desencrypted)
            data_request = data_agent_request["request_data"]
            request_id = data_agent_request["id_request"]
            
            # Log de inicio de procesamiento
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_PROVIDER, 
                f'{self.agent_name} -> Starting request processing', 
                LogType.PROVIDER_PROCESS_START,
                agent_uuid=self.management_security.uuid_agent,
                uuid_request=request_uuid,
                uuid_agent_request=requester_uuid
            )

            # Guardar solicitud
            data_complete = self.management_security.management_data.load()
            request_data = data_complete.get("requests", [])
            request_data.append(data_request)
            data_complete["requests"] = request_data

            # Ejecutar operación
            start_time_op = time.perf_counter()
            result = self.perform_operation(data_request)
            end_time_op = time.perf_counter()
            
            # Log de finalización de operación
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_PROVIDER, 
                f'{self.agent_name} -> Operation completed for request {request_id}', 
                LogType.END_REQUEST,
                time_str=f"{end_time_op - start_time_op:.9f}",
                agent_uuid=self.management_security.uuid_agent,
                uuid_request=request_uuid,
                uuid_agent_request=requester_uuid
            )

            # Preparar respuesta
            response_data: ResponseAgentType = {
                "id_request": request_id,
                "data_response": {
                    "result": result,
                    "processing_time": f"{end_time_op - start_time_op:.9f}"
                }
            }

            # Guardar respuesta
            data_response = data_complete.get("responses", [])
            data_response.append(response_data)
            data_complete["responses"] = data_response
            self.management_security.management_data.save(data_complete)

            # Encriptar respuesta
            public_key = self.management_security.deserialize_public_key(
                self.list_agents[requester_uuid]["public_key"]
            )
            start_time_enc = time.perf_counter()
            result_encr = self.management_security.encrypt_data_with_public_key(
                response_data, public_key, self.management_security.id_agent
            )
            end_time_enc = time.perf_counter()
            
            # Log de respuesta encriptada
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_PROVIDER, 
                f'{self.agent_name} -> Response encrypted for request {request_id}', 
                LogType.END_ENCRYPTION, 
                time_str=f"{end_time_enc - start_time_enc:.9f}",
                agent_uuid=self.management_security.uuid_agent,
                uuid_request=request_uuid,
                uuid_agent_request=requester_uuid
            )

            # Log de fin de procesamiento
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_PROVIDER, 
                f'{self.agent_name} -> Completed request processing', 
                LogType.PROVIDER_PROCESS_END,
                time_str=f"{end_time_enc - start_time_op:.9f}",
                agent_uuid=self.management_security.uuid_agent,
                uuid_request=request_uuid,
                uuid_agent_request=requester_uuid
            )

            # Log final de la operación completa
            end_time_total = time.perf_counter()
            total_time = end_time_total - start_time_total
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_PROVIDER, 
                f'{self.agent_name} -> Request {request_id} completed', 
                LogType.PROVIDER_REQUEST_END, 
                time_str=f"{total_time:.9f}",
                agent_uuid=self.management_security.uuid_agent,
                uuid_request=request_uuid,
                uuid_agent_request=requester_uuid
            )
            
            return result_encr
            
        except Exception as e:
            end_time_total = time.perf_counter()
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_PROVIDER, 
                f'Error processing request: {e}', 
                LogType.ERROR,
                agent_uuid=self.management_security.uuid_agent,
                uuid_request=request_uuid if 'request_uuid' in locals() else None,
                uuid_agent_request=requester_uuid if 'requester_uuid' in locals() else None
            )
            self.management_security.management_logs.log_message(
                ComponentType.AGENT_PROVIDER, 
                f'{self.agent_name} -> Request processing failed', 
                LogType.PROVIDER_REQUEST_END, 
                time_str=f"{end_time_total - start_time_total:.9f}",
                agent_uuid=self.management_security.uuid_agent,
                uuid_request=request_uuid if 'request_uuid' in locals() else None,
                uuid_agent_request=requester_uuid if 'requester_uuid' in locals() else None
            )
            return str(e)
