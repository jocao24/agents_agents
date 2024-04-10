import time

from src.security.security_management import SecurityManagement
from src.management_data.manage_data_agent import ManageDataAgent
from src.conections.conect_agent_to_naverserver import connect_agent_to_nameserver

from utils.errors import ErrorTypes


def execute_client(client, client_name: str, management_security: SecurityManagement):
    key_shared = input('Enter the shared key: ')
    data_agent = ManageDataAgent().get_data_conection_agent(client_name)
    nameserver_conection, data_agent = connect_agent_to_nameserver(data_agent, client_name)
    ManageDataAgent().save_data_conecction_agent(data_agent)

    authenticate_user(nameserver_conection, key_shared, client, management_security, client_name)

    # Autenticación exitosa y recogida inicial de agentes
    skills, agents = refresh_agents_list(client)

    while True:
        display_skills(skills)
        skill_selection = input('Enter the number of the skill you want to use or refresh the list: ')

        if skill_selection.lower() == 'r':
            skills, agents = refresh_agents_list(client)
            continue
        elif skill_selection.isdigit():
            skill_selection = int(skill_selection)
            if 1 <= skill_selection <= len(skills):
                id_agent = agents[skill_selection - 1]['id']
                perform_operation(client, id_agent)
            else:
                print('Invalid selection. Please enter a valid number or R to refresh.')
        else:
            print('Invalid input. Please enter a number or R to refresh the list.')


def authenticate_user(nameserver_conection, key_shared, client, management_security, client_name):
    code_otp = ''
    while True:
        try:
            _, error, message, _ = nameserver_conection.register(key_shared, client, management_security, code_otp,
                                                                 True)
            if error:
                print(message)
                if message == ErrorTypes.ip_blocked:
                    exit()
                elif message in [ErrorTypes.otp_required, ErrorTypes.otp_incorrect]:
                    code_otp = input("Enter OTP Code: ")
                    continue
            break
        except Exception as e:
            print(e)
            input('Press enter to try again. ')
    print('Authenticated successfully.')
    print(f"The client {client_name} is ready for operations.")
    time.sleep(1)


def refresh_agents_list(client):
    print('Fetching list of available agents...')
    agents = client.get_list_agents()
    skills = [agent['skills'] for agent in agents]
    return skills, agents


def display_skills(skills):
    print('Available skills (enter R to refresh): ')
    for i, skill in enumerate(skills, 1):
        print(f"{i}. {skill}")
    print(f"{len(skills) + 1}. Exit")


def perform_operation(client, id_agent):
    while True:
        try:
            num1 = float(input('Enter the first number: '))
            num2 = float(input('Enter the second number: '))
            print('Sending request to the agent...')
            result = client.send_request_agent(id_agent, {'num1': num1, 'num2': num2})
            print(f"Result: {result}")
            break
        except ValueError:
            print('Invalid number. Please enter a valid number.')
