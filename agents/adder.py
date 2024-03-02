import Pyro4
from domain.agent import execute_agent


@Pyro4.expose
class Adder:
    def perform_operation(self, num1, num2):
        print("The sum agent.py has received: " + str((num1, num2)))
        result = num1 + num2
        print("The sum agent.py is sending: " + str(result))
        return result


def execute_adder():
    execute_agent(Adder, "to_adder")
