import Pyro4
from domain.agent import execute_agent
from domain.class_for_agents.authenticate_agent import ManagementSecurity


class Adder:
    def __init__(self, management_security: ManagementSecurity):
        self.management_security = management_security
        self.proxy_yellow_page = None
        self.list_agents = {}

    @Pyro4.expose
    def ping(self, data: dict):
        data_desencrypted = self.management_security.decrypt_data(data)
        print(data_desencrypted)

    @Pyro4.expose
    def receive_list_agents(self, data: dict):
        data_desencrypted = self.management_security.decrypt_data(data)
        print(data_desencrypted)
        self.list_agents = data_desencrypted

    @Pyro4.expose
    def execute(self, data: dict):
        data_desencrypted = self.management_security.decrypt_data(data)
        if data_desencrypted["num1"] and data_desencrypted["num2"]:
            print("The sum agent.py has received: " + str((data_desencrypted["num1"], data_desencrypted["num2"])))
            result = data_desencrypted["num1"] + data_desencrypted["num2"]
            print("The sum agent.py is sending: " + str(result))
            # Se busca la llave publica del agente que envio la peticion
            id_agent = data["id"]
            public_key_org = self.list_agents[id_agent]["public_key"]
            # Se decodifica la clave publica del agente y se deserializa
            public_key = self.management_security.deserialize_public_key(public_key_org)
            result_encr = self.management_security.encrypt_data_with_public_key({
                "result": str(result)
            }, public_key, self.management_security.id_agent)
            return result_encr
        else:
            return "The data is not valid."


def execute_adder(management_security: ManagementSecurity):
    adder = Adder(management_security)
    execute_agent(adder, "adder", management_security)

