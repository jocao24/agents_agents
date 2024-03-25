import threading
import time

import Pyro4
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from domain.class_for_agents.authenticate_agent import ManagementSecurity
from domain.class_for_agents.conect_agent_and_nameserver import NameServerAgentConnection
from domain.class_for_agents.manage_data_agent import ManageDataAgent
from domain.conect_agent_to_naverserver import connect_agent_to_nameserver
from cryptography.hazmat.backends import default_backend


def execute_client(client, client_name: str, management_security: ManagementSecurity):
    key_shared = input('Enter the shared key: ')
    data_agent = ManageDataAgent().get_data_conection_agent(client_name)
    nameserver_conection, data_agent = connect_agent_to_nameserver(data_agent, client_name)
    ManageDataAgent().save_data_conecction_agent(data_agent)
    while True:
        try:
            is_authenticated, error, message, is_exit = nameserver_conection.register(key_shared, client, management_security, '', True)
            if error and not is_authenticated:
                print(message)
            if is_exit:
                exit()
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
