import uuid
from src.conections.nameserver_agent_conection import NameServerAgentConnection
from utils.types.agent_type import AgentType
from utils.get_ip import get_ip
from utils.validate_ip import validate_ip


def request_data_agent(name_agent: str):
    description_agent = input('Enter the description of the agents.py: ')
    skills = input('Enter the skills of the agents.py separated by commas: ')
    skills = skills.split(',')
    id_client = str(uuid.uuid4())

    while True:
        ip_name_server = input("Enter the IP of the nameserver. If it is the same as the NameServer, press enter: ")
        if ip_name_server:
            is_valid_ip = validate_ip(ip_name_server)
            if not is_valid_ip:
                print("The IP entered is not valid. Please enter a valid IP.")
                continue
            break
        ip_name_server = get_ip()
        break

    data_agent = {
        "name": name_agent,
        "description": description_agent,
        "id": id_client,
        "local_ip": get_ip(),
        "ip_name_server": ip_name_server,
        "skills": skills,
    }
    nameserver_conection = NameServerAgentConnection({
        "name": name_agent,
        "description": description_agent,
        "id": id_client,
        "local_ip": get_ip(),
        "ip_name_server": ip_name_server,
        "skills": skills,

    })
    nameserver_conection.conect_to_nameserver_manually(ip_name_server)
    return nameserver_conection, data_agent


def connect_agent_to_nameserver(data_agent: AgentType, name_agent: str):
    data_agent_saved = data_agent
    nameserver_conection = None
    while True:
        opt_select = input("Do you want to use the nameserver IP saved in the configuration file? (y/n): ")
        if opt_select.lower() == 'y':
            is_valid_ip = False
            if data_agent_saved:
                is_valid_ip = validate_ip(data_agent_saved["ip_name_server"])
            if not is_valid_ip or not data_agent_saved:
                print("The IP of the ns saved in the configuration file is not valid. Please enter a valid IP.")
                nameserver_conection, data_agent_saved = request_data_agent(name_agent)
            nameserver_conection = NameServerAgentConnection(data_agent_saved)
            nameserver_conection.conect_to_nameserver_manually(data_agent_saved["ip_name_server"])
            break
        elif opt_select.lower() == 'n':
            nameserver_conection, data_agent_saved = request_data_agent(name_agent)
            break
        else:
            print("Invalid option. Please enter a valid option.")

    return nameserver_conection, data_agent_saved
