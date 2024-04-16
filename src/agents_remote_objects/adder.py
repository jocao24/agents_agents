from typing_extensions import TypedDict
from src.agents_remote_objects.base.base_agent_provider import AgentProvider
from src.menus.agent import execute_agent
from src.security.security_management import SecurityManagement


class RequestAdderType(TypedDict):
    num1: int
    num2: int


class Adder(AgentProvider):
    def __init__(self, management_security):
        super().__init__(management_security, "Adder")

    def perform_operation(self, data_request):
        num1 = float((data_request["num1"]))
        num2 = float(data_request["num2"])
        return num1 + num2


def execute_adder(management_security: SecurityManagement):
    adder = Adder(management_security)
    execute_agent({
        "agent": adder,
        "name": "Adder",
        "management_security": management_security,
        "is_provider": True,
        "is_consumer": False
    })
