import uuid
from src.utils.get_ip import get_ip
from src.utils.validate_ip import validate_ip


def request_ip() -> str:
    while True:
        ip_name_server = input("Enter the IP of the nameserver. If it is the same as the NameServer, press enter: ")
        if ip_name_server:
            is_valid_ip = validate_ip(ip_name_server)
            if not is_valid_ip:
                print("The IP entered is not valid. Please enter a valid IP.")
                continue
            return ip_name_server
        return get_ip()


def request_data_agent(name_agent: str):
    description_agent = input('Enter the description of the agents_remote_objects.py: ')
    skills = input('Enter the skills of the agents_remote_objects.py separated by commas: ')
    skills = skills.split(',')
    id_agent = str(uuid.uuid4())
    ip_name_server = request_ip()

    data_agent = {
        "name": name_agent,
        "description": description_agent,
        "id": id_agent,
        "ip_name_server": ip_name_server,
        "skills": skills,
    }
    return data_agent
