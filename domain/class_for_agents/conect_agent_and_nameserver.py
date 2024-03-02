import Pyro4

from utils.types.agent_type import AgentType
from utils.get_ip import get_ip


class NameServerAgentConnection:

    def __init__(self, data_agent: AgentType):
        self.name_agent = data_agent['name']
        self.description_agent = data_agent['description']
        self.id_agent = data_agent['id']
        self.local_ip = data_agent['local_ip']
        self.skills = data_agent['skills']
        self.ns_instance = None
        self.name_server = None
        self.ip_name_server = None
        self.uri = None
        self.daemon = Pyro4.Daemon(host=self.local_ip)

    def conect_to_nameserver_automatically(self):
        self.name_server = Pyro4.locateNS()
        self.conect_to_controller()
        self.set_ip_name_server()
        return self.ip_name_server

    def conect_to_nameserver_manually(self,  ip_name_server: str = None):
        self.ip_name_server = ip_name_server
        self.name_server = Pyro4.locateNS(host=self.ip_name_server, port=9090)
        self.conect_to_controller()

    def get_name_server_instance(self):
        return self.ns_instance

    def get_uri_agent(self, agent):
        return self.daemon.register(agent)

    def conect_to_controller(self):
        uri_ns_controller = self.name_server.lookup("ns_controller")
        self.ns_instance = Pyro4.Proxy(uri_ns_controller)

    def set_ip_name_server(self):
        self.ip_name_server = str(self.name_server).split("@")[1].split(":")[0]

    def register_agent(self, uri):
        self.name_server = Pyro4.locateNS(host=self.ip_name_server, port=9090)
        self.name_server.register(self.name_agent, uri)

    def get_data_agent(self):
        return {
            "name_agent": self.name_agent,
            "description_agent": self.description_agent,
            "id_agent": self.id_agent,
            "local_ip": get_ip(),
            "ip_name_server": self.ip_name_server,
            "skills": self.skills,
        }

    def activate_daemon(self):
        self.daemon.requestLoop()
