from src.agents_remote_objects.base.base_agent_consumer import AgentConsumer
import Pyro5.api

from src.menus.agent import execute_agent
from src.security.security_management import SecurityManagement


@Pyro5.api.expose
class Client1(AgentConsumer):
    def __init__(self, management_security: SecurityManagement):
        super().__init__(management_security, agent_name="AgentConsumer1")

    def request_service(self, service_id: str, request_data: dict):
        self.management_security.management_logs.log_message(f"{self.agent_name} -> Requesting service {service_id}")
        response = self.send_request_to_agent(service_id, request_data)
        if response:
            self.management_security.management_logs.log_message(f"{self.agent_name} -> Received valid response from service {service_id}")
        else:
            self.management_security.management_logs.log_message(f"{self.agent_name} -> Failed to receive response from service {service_id}")
        return response

    def list_available_services(self):
        self.management_security.management_logs.log_message(f"{self.agent_name} -> Listing available services")
        available_services = self.get_list_agents()
        if available_services:
            for service in available_services:
                print(f"Service ID: {service['id']}, Name: {service['name']}, Description: {service['description']}")
            self.management_security.management_logs.log_message(f"{self.agent_name} -> Successfully listed available services")
        else:
            self.management_security.management_logs.log_message(f"{self.agent_name} -> No services available")


def execute_client_1(management_security: SecurityManagement):
    client_1 = Client1(management_security)
    execute_agent({
        'agent': client_1,
        'name': "AgentConsumer1",
        'management_security': management_security,
        'is_provider': False,
        'is_consumer': True
    })
