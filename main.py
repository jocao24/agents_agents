from agents.adder import execute_adder
from agents.substract import execute_substract
from agents.multiplication import execute_multiplication
from agents.division import execute_division
from domain.class_for_agents.authenticate_agent import ManagementSecurity

if __name__ == '__main__':
    agents_names = {
        1: "Sum Agent",
        2: "Subtraction Agent",
        3: "Multiplication Agent",
        4: "Division Agent"
    }
    agents_functions = {
        1: execute_adder,
        2: execute_substract,
        3: execute_multiplication,
        4: execute_division,
    }
    while True:
        print("Which agent.py do you want to execute?")
        i = 1
        for key, value in agents_names.items():
            print(f"{key}. {value}")
            i += 1

        print(f"{i}. Exit")

        option = input("Enter the number of the agent you want to execute: ")
        if option.isdigit():
            managament_security = ManagementSecurity()
            option = int(option)
            if option in agents_names:
                agents_functions[option](managament_security)
            elif option == i:
                break
            else:
                print("Invalid option. Please enter a valid option.")


