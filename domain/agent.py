import Pyro4
from domain.class_for_agents.authenticate_agent import AuthenticateAgent
from domain.class_for_agents.conect_agent_and_nameserver import NameServerAgentConnection
from domain.class_for_agents.manage_data_agent import ManageDataAgent
from domain.conect_agent_to_naverserver import connect_agent_to_nameserver


def execute_agent(agent, agent_name: str):
    data_agent = ManageDataAgent().get_data_conection_agent(agent_name)
    nameserver_conection, data_agent = connect_agent_to_nameserver(data_agent, agent_name)
    ns_instance = nameserver_conection.get_name_server_instance()
    ManageDataAgent().save_data_conecction_agent(data_agent)
    uri = nameserver_conection.get_uri_agent(agent)
    authentication = AuthenticateAgent(data_agent, uri, ns_instance)
    is_authenticated, error, message, is_exit = authentication.authenticate_without_otp()
    if error and not is_authenticated:
        print(message)
        if is_exit:
            exit()

    while not is_authenticated:
        print('OTP is required. Please enter the OTP: ')
        code_otp = input('Enter the OTP code: ')
        gateway_proxy, is_authenticated, error, message = authentication.authenticate_with_otp(code_otp)
        if error and not is_authenticated:
            print(message)

    print('Authenticated successfully.')
    nameserver_conection.register_agent(uri)
    print("The agent.py is ready for operations.")
    nameserver_conection.activate_daemon()
