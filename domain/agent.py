import threading

import Pyro4
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from domain.class_for_agents.authenticate_agent import ManagementSecurity
from domain.class_for_agents.conect_agent_and_nameserver import NameServerAgentConnection
from domain.class_for_agents.manage_data_agent import ManageDataAgent
from domain.conect_agent_to_naverserver import connect_agent_to_nameserver
from cryptography.hazmat.backends import default_backend


def execute_agent(agent, agent_name: str, management_security: ManagementSecurity):
    key_shared = input('Enter the shared key: ')
    data_agent = ManageDataAgent().get_data_conection_agent(agent_name)
    nameserver_conection, data_agent = connect_agent_to_nameserver(data_agent, agent_name)
    ManageDataAgent().save_data_conecction_agent(data_agent)
    while True:
        try:
            is_authenticated, error, message, is_exit = nameserver_conection.register(key_shared, agent, management_security)
            if error and not is_authenticated:
                print(message)
            if is_exit:
                exit()
            break
        except Exception as e:
            print(e)
            pass
    print('Authenticated successfully.')
    print("The agent.py is ready for operations.")
    while True:
        input()
