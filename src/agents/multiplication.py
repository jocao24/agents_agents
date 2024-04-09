import Pyro4
from src.menus.agent import execute_agent
from src.security.security_management import SecurityManagement


@Pyro4.expose
class Multiplication:
    def __init__(self, management_security: SecurityManagement):
        self.management_security = management_security
        self.proxy_yellow_page = None
        self.list_agents = {}

    @Pyro4.expose
    def ping(self, data: dict):
        print("The multiplication agent receives a ping from the Yellow Page.\n " + str(data))
        data_desencrypted = self.management_security.decrypt_data(data)
        print("The ping is decrypted using hybrid encryption: \n" + str(data_desencrypted))
        print(data_desencrypted)

    @Pyro4.expose
    def receive_list_agents(self, data: dict):
        print("The multiplication agent receives from the Yellow Page the agent directory in encrypted form.\n " + str(data))
        data_desencrypted = self.management_security.decrypt_data(data)
        print("The agent directory is decrypted using hybrid encryption: \n" + str(data_desencrypted))
        self.list_agents = data_desencrypted

    @Pyro4.expose
    def execute(self, data: dict):
        print("The multiplication agent receives a request to perform a multiplication operation.\n " + str(data))
        data_desencrypted = self.management_security.decrypt_data(data)
        print("The request is decrypted using hybrid encryption: \n" + str(data_desencrypted))
        if data_desencrypted["num1"] and data_desencrypted["num2"]:
            print("The multiplication agents.py has received: " + str((data_desencrypted["num1"], data_desencrypted["num2"])))
            result = data_desencrypted["num1"] * data_desencrypted["num2"]
            print("The multiplication agent is sending: " + str(result))
            id_agent = data["id"]
            public_key_org = self.list_agents[id_agent]["public_key"]
            # Se decodifica la clave publica del agente y se deserializa
            public_key = self.management_security.deserialize_public_key(public_key_org)
            result_encr = self.management_security.encrypt_data_with_public_key({
                "result": str(result)
            }, public_key, self.management_security.id_agent)
            print("The result is encrypted using the public key of the agent that sent the request: \n" + str(result_encr))
            return result_encr
        else:
            return "The data is not valid."


def execute_multiplication(management_security: SecurityManagement):
    multiplication = Multiplication(management_security)
    execute_agent(multiplication, "multiplication", management_security)