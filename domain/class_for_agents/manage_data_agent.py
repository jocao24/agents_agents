import os
from Pyro4.util import json
from utils.types.agent_type import AgentType


class ManageDataAgent:

    def save_data_conecction_agent(self, data_client: AgentType):
        name_client = data_client['name']
        if not os.path.exists('agents/data'):
            os.makedirs('agents/data')
        with open(f'agents/data/{name_client}.json', 'w') as file:
            json.dump(data_client, file)

    def get_data_conection_agent(self, name_client):
        try:
            with open(f'agents/data/{name_client}.json', 'r') as file:
                data = json.load(file)
                data_client: AgentType = AgentType(**data)
                return data_client
        except FileNotFoundError:
            return None
