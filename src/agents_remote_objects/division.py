from typing_extensions import TypedDict
from .base.base_agent_provider import AgentProvider
from ..menus.agent import execute_agent
from ..security.security_management import SecurityManagement

class RequestDivissionType(TypedDict):
    num1: int
    num2: int


class Division(AgentProvider):
    def __init__(self, management_security):
        super().__init__(management_security, "Division")

    def perform_operation(self, data_request):
        num1 = data_request["num1"]
        num2 = data_request["num2"]
        if num2 == 0:
            raise ValueError("Cannot divide by zero.")
        return num1 / num2


def execute_division(management_security: SecurityManagement):
    division = Division(management_security)
    execute_agent({
        "agent": division,
        "name": "Division",
        "management_security": management_security,
        "is_provider": True,
        "is_consumer": False
    })
