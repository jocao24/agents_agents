import Pyro4
from domain.agent import execute_agent


@Pyro4.expose
class Multiplication:
    def perform_operation(self, num1, num2):
        print("The multiplication agent.py has received: " + str((num1, num2)))
        result = num1 * num2
        print("The multiplication agent.py is sending: " + str(result))
        return result


def execute_multiplication():
    execute_agent(Multiplication, "multiplication")
