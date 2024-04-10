import Pyro4
from src.security.security_management import SecurityManagement
from src.menus.client import execute_client


class Client1:
    def __init__(self, management_security: SecurityManagement):
        self.management_security = management_security
        self.proxy_yellow_page = None
        self.list_agents = []

    @Pyro4.expose
    def ping(self, data: dict):
        print("The client_1 agent receives a ping from the Yellow Page.\n " + str(data))
        data_desencrypted = self.management_security.decrypt_data(data)
        print("The ping is decrypted using hybrid encryption: \n" + str(data_desencrypted))
        print(data_desencrypted)

    @Pyro4.expose
    def update_list_agents(self, data: dict):
        print("The client_1 agent receives from the Yellow Page the agent directory in encrypted form.\n " + str(data))
        data_desencrypted = self.management_security.decrypt_data(data)
        print("The agent directory is decrypted using hybrid encryption: \n" + str(data_desencrypted))
        print(self.list_agents)

    @Pyro4.expose

    def receive_list_agents(self, data: dict):
        print("The client_1 agent receives from the Yellow Page the agent directory in encrypted form.\n " + str(data))
        data_desencrypted = self.management_security.decrypt_data(data)
        print("The agent directory is decrypted using hybrid encryption: \n" + str(data_desencrypted))
        self.list_agents = data_desencrypted

    def get_list_agents(self):
        list_agents = []
        for agent_id in self.list_agents:
            agent = self.list_agents[agent_id]
            list_agents.append({
                "name": agent["name"],
                "description": agent["description"],
                "skills": agent["skills"],
                "id": agent_id,
            })
        return list_agents

    def send_request_agent(self, id_agent: str, data: dict):
        agent_data = None
        public_key = None
        for agent in self.list_agents:
            if agent == id_agent:
                agent_data = self.list_agents[agent]
                # Se decodifica la clave publica del agente y se deserializa
                public_key = self.management_security.deserialize_public_key(agent_data["public_key"])
                break
        if agent_data:
            agent_proxy = Pyro4.Proxy(self.management_security.ns.lookup(agent_data["id"]))
            encrypted_data = self.management_security.encrypt_data_with_public_key(data, public_key, self.management_security.id_agent)
            response_encrypted = agent_proxy.execute(encrypted_data)
            response = self.management_security.decrypt_data(response_encrypted)
            print(response)
            return response
        else:
            print("The agents_remote_objects.py does not exist.")


def execute_client_1(management_security: SecurityManagement):
    client_1 = Client1(management_security)
    execute_client(client_1, "client_1", management_security)
