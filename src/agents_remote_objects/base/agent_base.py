import Pyro4
from ...security.security_management import SecurityManagement


@Pyro4.expose
class BaseAgent:
    def __init__(self, management_security: SecurityManagement, agent_name: str):
        self.management_security = management_security
        self.agent_name = agent_name
        self.list_agents = []
        self.management_security.management_logs.log_message(f"{self.agent_name} -> Initialized")

    def ping(self):
        """Method to verify connectivity."""
        self.management_security.management_logs.log_message(f"{self.agent_name} -> Ping received")
        return "pong"

    def update_list_agents(self, encrypted_data: dict):
        """Updates the list of agents based on the encrypted data received."""
        self.management_security.management_logs.log_message(f"{self.agent_name} -> Updating list of agents")
        try:
            data_decrypted = self.management_security.decrypt_data(encrypted_data)
            self.list_agents = data_decrypted
            self.management_security.management_logs.log_message(f"{self.agent_name} -> List of agents updated successfully")
        except Exception as e:
            self.management_security.management_logs.log_message(f"{self.agent_name} -> Error updating list of agents: {e}")

    def receive_list_agents(self, encrypted_data: dict):
        """Method to receive the list of agents from the Yellow Page."""
        self.update_list_agents(encrypted_data)
