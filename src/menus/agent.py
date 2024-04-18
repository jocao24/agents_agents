import os
import threading

import time

from typing_extensions import Any, TypedDict
from src.conections.agent_connection_handler import AgentConnectionHandler
from src.conections.agent_networking import request_data_agent, request_ip
from src.menus.agent_menu import AgentMenu
from src.security.security_management import SecurityManagement
from src.utils import ErrorTypes


class RegisterAgentType(TypedDict):
    agent: Any
    name: str
    management_security: SecurityManagement
    is_provider: bool
    is_consumer: bool


def execute_agent(agent_register: RegisterAgentType):
    agent, name_agent, management_security, is_provider, is_consumer = agent_register.values()
    data_agent = management_security.get_data_agent()
    code_otp = None
    shared_key = None
    if data_agent.get('ultimate_shared_key') is None or data_agent.get('ultimate_shared_key') == '':
        shared_key = input('Enter the shared key: ')
        management_security.set_data_agent(data_agent)

    if data_agent['id'] == '':
        data_agent = request_data_agent(name_agent)
        data_agent['is_provider'] = is_provider
        data_agent['is_consumer'] = is_consumer
        data_agent['ultimate_shared_key'] = shared_key

        management_security.set_data_agent(data_agent)

    nameserver_conection = None
    try:
        nameserver_conection = AgentConnectionHandler(management_security, agent)
    except Exception as e:
        print('Error connecting to the nameserver.')
        ip_ns = request_ip()
        data_agent['ip_name_server'] = ip_ns
        management_security.set_data_agent(data_agent)
        nameserver_conection = AgentConnectionHandler(management_security, agent)

    while True:
        try:
            nameserver_conection.register(code_otp)
            break
        except Exception as e:
            error_message = str(e).split('rejected: ')[-1]
            error_key, _, error_desc = error_message.partition(': ')
            error_key = error_key.strip()
            error_desc = error_desc.strip()

            if error_key in ErrorTypes.__members__:
                error_type = ErrorTypes[error_key]
                if error_type in (ErrorTypes.ip_blocked, ErrorTypes.otp_required, ErrorTypes.otp_incorrect):
                    if error_type == ErrorTypes.ip_blocked:
                        exit()
                    else:
                        print(error_desc)
                        code_otp = input("Enter Code OTP: ")
                        continue
            print(error_desc)
            print(f"Error: {e}")
            input("Press enter to try again.")
    print('Authenticated successfully.')
    menu = AgentMenu(management_security, agent)
    menu.show_menu()
    nameserver_conection.daemon.close()
    nameserver_conection.daemon.shutdown()
    os._exit(0)

