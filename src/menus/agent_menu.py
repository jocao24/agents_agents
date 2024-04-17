from src.security.security_management import SecurityManagement
from utils.separators import show_separators, show_center_text_with_separators


class AgentMenu:
    def __init__(self, management_security: SecurityManagement, remote_object):
        self.management_security = management_security
        self.remote_object = remote_object
        self.running = True

    def view_logs(self):
        """View all logs related to the agent's activity."""
        print("Fetching logs...")
        all_logs = self.management_security.management_logs.get_all_logs()
        print(all_logs)

    def view_agent_data(self):
        """Display the current state and data of the agent."""
        data_agent = self.management_security.get_data_agent()
        del data_agent['ultimate_shared_key']
        del data_agent['logs']
        del data_agent['requests']
        del data_agent['responses']
        print("Agent Data:")
        for key, value in data_agent.items():
            print(f"{key}: {value}")

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
            response = self.remote_object.send_request_to_agent(agent_id, {'num1': num1, 'num2': num2})

            print(show_separators())
            print(show_center_text_with_separators("Response from Agent"))
            print(show_separators())
            print(f"Request ID: {response['id_request']}")
            print(f"Result: {response['data_response']['result']}")
            print(show_separators())
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
            2: ("View Logs", self.view_logs),
            3: ("View Requests and Responses", self.view_requests_and_responses),
            6: ("Exit", self.exit_menu),
        }

        data_agent = self.management_security.get_data_agent()
        if data_agent.get('is_consumer', False):
            menu_options[4] = ("Request Resources from Other Agents", self.request_resources)
            menu_options[5] = ("View Available Agents", self.view_available_agents)

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
                if int(choice) == 6:
                    break
            else:
                print("Invalid option. Please enter a valid number.")
            print(show_separators())
