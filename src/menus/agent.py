from src.security.security_management import SecurityManagement
from src.management_data.manage_data_agent import ManageDataAgent
from src.conections.conect_agent_to_naverserver import connect_agent_to_nameserver

from utils.errors import ErrorTypes


def execute_agent(agent, agent_name: str, management_security: SecurityManagement):
    key_shared = input('Enter the shared key: ')
    data_agent = ManageDataAgent().get_data_conection_agent(agent_name)
    nameserver_conection, data_agent = connect_agent_to_nameserver(data_agent, agent_name)
    ManageDataAgent().save_data_conecction_agent(data_agent)
    code_otp = None
    while True:
        try:
            _, error, message, _ = nameserver_conection.register(key_shared, agent, management_security, code_otp)
            if error:
                print(message)
                if message == ErrorTypes.ip_blocked:
                    exit()
                elif message == ErrorTypes.otp_required or message == ErrorTypes.otp_incorrect:
                    code_otp = input("Enter Code OTP")
                    continue
                elif error and message:
                    input("The Yellow Page is not registered. Press enter to try again.")

            break
        except Exception as e:
            print(e)
            input("The Yellow Page is not registered. Press enter to try again.")
            pass
    print('Authenticated successfully.')
    print("The agents_remote_objects.py is ready for operations.")
    while True:
        input()
