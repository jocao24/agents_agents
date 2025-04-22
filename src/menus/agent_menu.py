from src.utils.separators import show_separators, show_center_text_with_separators
from src.security.security_management import SecurityManagement
import uuid
from src.manage_logs.manage_logs_v_2 import LogType, ComponentType 
import time

class AgentMenu:
    def __init__(self, management_security: SecurityManagement, remote_object):
        self.management_security = management_security
        self.remote_object = remote_object
        self.running = True

    def view_logs(self):
        """View logs of the current session."""
        print("Fetching logs of the current session...")
        current_session_logs = self.management_security.management_logs.get_current_session_logs()
        print(current_session_logs)

    def view_all_logs(self):
        """View all logs related to the agent's activity."""
        print("Fetching all logs...")
        all_logs = self.management_security.management_logs.get_all_logs()
        print(all_logs)

    def view_agent_data(self):
        """Display the current state and data of the agent."""
        data_agent = self.management_security.get_data_agent()
        del data_agent['ultimate_shared_key']
        del data_agent['logs']
        print("Agent Data:")
        for key, value in data_agent.items():
            print(f"{key}: {value}")

    def export_logs_to_csv(self):
        self.management_security.management_logs.export_logs_to_csv(self.management_security.name_agent)
        print(f"Logs have been exported to data/logs_{self.management_security.name_agent}.csv")

    def exit_menu(self):
        """Exit the menu."""
        print("Exiting...")
        self.running = False

    def view_requests_and_responses(self):
        """View requests made by this agent and their responses if it's a consumer."""
        data_agent = self.management_security.get_data_agent()
        requests = data_agent.get('requests', [])
        responses = data_agent.get('responses', [])

        if not requests:
            print("No requests to display.")
            return

        print(show_separators())
        print(show_center_text_with_separators("Requests and Responses Summary"))
        print(show_separators())

        for request in requests:
            # Obtén la respuesta correspondiente al ID de solicitud
            response = next((resp for resp in responses if resp['id_request'] == request['id_request']), None)

            # Prepara detalles de la solicitud
            request_details = ', '.join([f"{k}: {v}" for k, v in request.items() if k != 'id_request'])
            result = response['data_response']['result'] if response and 'data_response' in response and 'result' in \
                                                            response['data_response'] else 'No response yet'

            print(f"Request ID: {request['id_request']} | Data: {request_details} | Result: {result}")

        print(show_separators())

    def request_resources(self):
        """Allow a consumer agent to request resources from other agents."""
        agents = self.remote_object.get_list_agents()
        if not agents:
            print("No agents available.")
            return

        print(show_separators())
        print("Available Agents:")
        for index, agent in enumerate(agents, start=1):
            if agent['id'] == self.management_security.id_agent:
                continue
            print(f"{index}. {agent['name']} ({agent['description']})")
        print(show_separators())

        choice = input("Select an agent to request resources from (or press 'r' to refresh the list): ")
        if choice.lower() == 'r':
            self.request_resources()
            return

        if choice.isdigit() and int(choice) <= len(agents):
            agent_id = agents[int(choice) - 1]['id']
            num1 = float(input("Enter number 1: "))
            num2 = float(input("Enter number 2: "))
            request_uuid = str(uuid.uuid4())
            
            # Registrar tiempo de inicio
            start_time = time.perf_counter()
            
            # Log de inicio de la solicitud del usuario
            self.management_security.management_logs.log_message(
                ComponentType.MENU,
                f'User started request with agent {agent_id}',
                LogType.USER_REQUEST_START,
                agent_uuid=self.management_security.uuid_agent,
                uuid_request=request_uuid
            )
            
            response = self.remote_object.send_request_to_agent(agent_id, {
                'num1': num1, 
                'num2': num2,
                'request_uuid': request_uuid
            })

            print(show_separators())
            print(show_center_text_with_separators("Response from Agent"))
            print(show_separators())
            
            if response is None:
                print("Error: No response received from the agent.")
            elif isinstance(response, str):
                print(f"Error: {response}")
            else:
                print(f"Request ID: {response['id_request']}")
                print(f"Result: {response['data_response']['result']}")
            print(show_separators())
            
            # Calcular tiempo total
            end_time = time.perf_counter()
            total_time = end_time - start_time
            
            # Log de fin de la solicitud del usuario con el tiempo total
            self.management_security.management_logs.log_message(
                ComponentType.MENU,
                f'User completed request with agent {agent_id}',
                LogType.USER_REQUEST_END,
                time_str=f"{total_time:.9f}",
                agent_uuid=self.management_security.uuid_agent,
                uuid_request=request_uuid
            )
        else:
            print("Invalid option. Please select a valid number.")

    def view_available_agents(self):
        """Show the list of available agents."""
        agents = self.remote_object.get_list_agents()
        if agents:
            for agent in agents:
                if agent['id'] == self.management_security.id_agent:
                    continue
                print(f"Agent ID: {agent['id']}, Name: {agent['name']}, Description: {agent['description']}")
        else:
            print("No agents available at the moment.")

    def show_menu(self):
        """Show the menu options and handle user input."""
        menu_options = {
            1: ("View Agent Data", self.view_agent_data),
            2: ("View Logs of Current Session", self.view_logs),
            3: ("View All Logs", self.view_all_logs),
            4: ("Export Logs to CSV", self.export_logs_to_csv),
            5: ("Exit", self.exit_menu),
            6: ("View Requests and Responses", self.view_requests_and_responses),
        }

        data_agent = self.management_security.get_data_agent()
        if data_agent.get('is_consumer', False):
            menu_options[6] = ("Request Resources from Other Agents", self.request_resources)
            menu_options[7] = ("View Available Agents", self.view_available_agents)

        while self.running:
            print(show_separators())
            print(show_center_text_with_separators("Agent Menu"))
            print(show_separators())
            for option, (description, _) in sorted(menu_options.items()):
                print(f"{option}. {description}")
            print(show_separators())

            choice = input("Choose an option: ")
            if choice.isdigit() and int(choice) in menu_options:
                _, action = menu_options[int(choice)]
                action()
                if int(choice) == 5:
                    break
            else:
                print("Invalid option. Please enter a valid number.")
            print(show_separators())
