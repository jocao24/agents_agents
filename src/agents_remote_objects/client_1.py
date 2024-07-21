import Pyro4
from .base.base_agent_consumer import AgentConsumer
from src.menus.agent import execute_agent
from src.security.security_management import SecurityManagement
from src.manage_logs.manage_logs_v_2 import ComponentType, LogType

@Pyro4.expose
class Client1(AgentConsumer):
    def __init__(self, management_security: SecurityManagement):
        super().__init__(management_security, agent_name="AgentConsumer1")

    def request_service(self, service_id: str, request_data: dict):
        """Method to send a service request to a specific agent based on the service_id."""
        self.management_security.management_logs.log_message(ComponentType.CLIENT, f"{self.agent_name} -> Requesting service {service_id}", LogType.REQUEST)
        response = self.send_request_to_agent(service_id, request_data)
        if response:
            self.management_security.management_logs.log_message(ComponentType.CLIENT, f"{self.agent_name} -> Received valid response from service {service_id}", LogType.RESPONSE)
        else:
            self.management_security.management_logs.log_message(ComponentType.CLIENT, f"{self.agent_name} -> Failed to receive response from service {service_id}", LogType.ERROR)
        return response

    def list_available_services(self):
        """Prints out all available services that this client can interact with."""
        self.management_security.management_logs.log_message(ComponentType.CLIENT, f"{self.agent_name} -> Listing available services", LogType.REQUEST)
        available_services = self.get_list_agents()
        if available_services:
            for service in available_services:
                print(f"Service ID: {service['id']}, Name: {service['name']}, Description: {service['description']}")
            self.management_security.management_logs.log_message(ComponentType.CLIENT, f"{self.agent_name} -> Successfully listed available services", LogType.RESPONSE)
        else:
            self.management_security.management_logs.log_message(ComponentType.CLIENT, f"{self.agent_name} -> No services available", LogType.ERROR)


def execute_client_1(management_security: SecurityManagement):
    client_1 = Client1(management_security)
    execute_agent({
        'agent': client_1,
        'name': "AgentConsumer1",
        'management_security': management_security,
        'is_provider': False,
        'is_consumer': True
    })
