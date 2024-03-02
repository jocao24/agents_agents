import Pyro4
from domain.agent import execute_agent


@Pyro4.expose
class Substract:
    def perform_operation(self, num1, num2):
        print("The subtraction agent.py has received: " + str((num1, num2)))
        result = num1 - num2
        print("The subtraction agent.py is sending: " + str(result))
        return result


def execute_substract():
    execute_agent(Substract, "to_substract")
