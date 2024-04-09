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
    code_otp = ''
    while True:
        try:
            _, error, message, _ = nameserver_conection.register(key_shared, client, management_security, code_otp, True)
            if error:
                print(message)
                if message == ErrorTypes.ip_blocked:
                    exit()
                if message == ErrorTypes.otp_required or message == ErrorTypes.otp_incorrect:
                    code_otp = input("Enter Code OTP")
                    continue
            break
        except Exception as e:
            print(e)
            pass
    print('Authenticated successfully.')
    print(f"The client {client_name} is ready for operations.")
    # Se agrega un tiempo de espera para que el cliente pueda recibir la lista de agentes
    # Se esparan 1 segundos para que el cliente pueda recibir la lista de agentes
    time.sleep(1)
    print('Available skills: ')
    i = 1
    skills = []
    for agent in client.get_list_agents():
        print(f"{i}. {agent['skills']}")
        skills.append(agent['skills'])
        i += 1
    print(f"{i}. Exit")

    skill = None
    request_skill = True
    while request_skill:
        skill = input(f'Enter the number of the skill you want to use. For exit, enter {len(skills) + 1}: ')
        if skill == str(len(skills) + 1):
            exit()
        elif skill.isdigit() and 1 <= int(skill) <= len(skills):
            request_skill = False
        else:
            print('Invalid number. Please enter a valid number.')

    id_agent = client.get_list_agents()[int(skill) - 1]['id']
    request_numbers = True
    while request_numbers:
        try:
            num1 = float(input('Enter the first number: '))
            num2 = float(input('Enter the second number: '))

            print('Sending request to the gateway...')
            result = client.send_request_agent(id_agent, {'num1': num1, 'num2': num2})
            print(f"Result: {result}")
            request_numbers = False
        except ValueError as e:
            print('Invalid number. Please enter a valid number.')
