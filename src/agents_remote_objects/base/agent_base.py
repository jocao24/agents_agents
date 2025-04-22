import Pyro4
import time
from src.security.security_management import SecurityManagement
from src.manage_logs.manage_logs_v_2 import ComponentType, LogType

@Pyro4.expose
class BaseAgent:
    def __init__(self, management_security: SecurityManagement, agent_name: str):
        self.management_security = management_security
        self.agent_name = agent_name
        self.list_agents = []
        self.management_security.management_logs.log_message(
            ComponentType.BASE_AGENT, 
            f"{self.agent_name} -> Initialized", 
            LogType.START_SESSION,
            agent_uuid=self.management_security.uuid_agent,
            agent_type=self.management_security.agent_type
        )

    def ping(self):
        """Method to verify connectivity."""
        start_time = time.perf_counter()
        self.management_security.management_logs.log_message(
            ComponentType.BASE_AGENT, 
            f"{self.agent_name} -> Ping received", 
            LogType.CONNECTION,
            agent_uuid=self.management_security.uuid_agent,
            agent_type=self.management_security.agent_type
        )
        end_time = time.perf_counter()
        self.management_security.management_logs.log_message(
            ComponentType.BASE_AGENT, 
            f"{self.agent_name} -> Ping processed", 
            LogType.END_CONNECTION, 
            time_str=f"{end_time - start_time:.9f}",
            agent_uuid=self.management_security.uuid_agent,
            agent_type=self.management_security.agent_type
        )
        return "pong"

    def update_list_agents(self, encrypted_data: dict):
        """Updates the list of agents based on the encrypted data received."""
        start_time_total = time.perf_counter()
        self.management_security.management_logs.log_message(
            ComponentType.BASE_AGENT, 
            f"{self.agent_name} -> Updating list of agents", 
            LogType.ENCRYPTION, 
            agent_uuid=self.management_security.uuid_agent,
            agent_type=self.management_security.agent_type
        )
        
        try:
            start_time = time.perf_counter()
            data_decrypted = self.management_security.decrypt_data(encrypted_data)
            end_time = time.perf_counter()
            decryption_time = end_time - start_time
            self.management_security.management_logs.log_message(
                ComponentType.BASE_AGENT, 
                f"{self.agent_name} -> List of agents updated successfully", 
                LogType.END_DECRYPTION, 
                time_str=f"{decryption_time:.9f}",
                agent_uuid=self.management_security.uuid_agent,
                agent_type=self.management_security.agent_type
            )
            
            self.list_agents = data_decrypted
        except Exception as e:
            self.management_security.management_logs.log_message(
                ComponentType.BASE_AGENT, 
                f"{self.agent_name} -> Error updating list of agents: {e}", 
                LogType.ERROR,
                agent_uuid=self.management_security.uuid_agent,
                agent_type=self.management_security.agent_type
            )

        end_time_total = time.perf_counter()
        total_time = end_time_total - start_time_total
        self.management_security.management_logs.log_message(
            ComponentType.BASE_AGENT, 
            f"{self.agent_name} -> Total update list agents time", 
            LogType.END_ENCRYPTION, 
            time_str=f"{total_time:.9f}",
            agent_uuid=self.management_security.uuid_agent,
            agent_type=self.management_security.agent_type
        )

    def receive_list_agents(self, encrypted_data: dict):
        """Method to receive the list of agents from the Yellow Page."""
        start_time = time.perf_counter()
        self.update_list_agents(encrypted_data)
        end_time = time.perf_counter()
        self.management_security.management_logs.log_message(
            ComponentType.BASE_AGENT, 
            f"{self.agent_name} -> Received list of agents", 
            LogType.END_ENCRYPTION, 
            time_str=f"{end_time - start_time:.9f}",
            agent_uuid=self.management_security.uuid_agent,
            agent_type=self.management_security.agent_type
        )
