import Pyro4
from domain.agent import execute_agent
from domain.class_for_agents.authenticate_agent import ManagementSecurity
from domain.client import execute_client


class Client1:
    def __init__(self, management_security: ManagementSecurity):
        self.management_security = management_security
        self.proxy_yellow_page = None
        self.list_agents = []

    @Pyro4.expose
    def ping(self, data: dict):
        data_desencrypted = self.management_security.decrypt_data(data)
        print(data_desencrypted)

    @Pyro4.expose
    def update_list_agents(self, data: dict):
        data_desencrypted = self.management_security.decrypt_data(data)
        self.list_agents = data_desencrypted
        print(self.list_agents)

    @Pyro4.expose
    def receive_list_agents(self, data: dict):
        data_desencrypted = self.management_security.decrypt_data(data)
        print(data_desencrypted)
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
            print("The agent.py does not exist.")


def execute_client_1(management_security: ManagementSecurity):
    client_1 = Client1(management_security)
    execute_client(client_1, "client_1", management_security)
