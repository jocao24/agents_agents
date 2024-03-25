import Pyro4
from domain.agent import execute_agent
from domain.class_for_agents.authenticate_agent import ManagementSecurity


@Pyro4.expose
class Substract:
    def perform_operation(self, num1, num2):
        print("The subtraction agent.py has received: " + str((num1, num2)))
        result = num1 - num2
        print("The subtraction agent.py is sending: " + str(result))
        return result


def execute_substract(management_security: ManagementSecurity):
    execute_agent(Substract, "to_substract", management_security)
