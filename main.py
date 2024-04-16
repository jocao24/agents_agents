from src.agents_remote_objects.adder import execute_adder
from src.agents_remote_objects.client_1 import execute_client_1
from src.agents_remote_objects.substract import execute_subtract
from src.agents_remote_objects.multiplication import execute_multiplication
from src.agents_remote_objects.division import execute_division
from src.manage_logs.manage_logs import ManagementLogs
from src.security.manage_data_agent import DataManagement
from src.security.security_management import SecurityManagement

if __name__ == '__main__':
    agents_names = {
        1: "Sum Agent",
        2: "Subtraction Agent",
        3: "Multiplication Agent",
        4: "Division Agent",
        5: 'Agent Consumer',
    }
    agents_functions = {
        1: execute_adder,
        2: execute_subtract,
        3: execute_multiplication,
        4: execute_division,
        5: execute_client_1,
    }
    while True:
        print("Which agents_remote_objects.py do you want to execute?")
        i = 1
        for key, value in agents_names.items():
            print(f"{key}. {value}")
            i += 1

        print(f"{i}. Exit")

        option = input("Enter the number of the agent you want to execute: ")
        if option.isdigit():
            option = int(option)
            if option in agents_names:
                agent_name = agents_names[option]
                agent_name = agent_name.replace(" ", "_").lower()
                management_data = DataManagement(agent_name)
                management_logs= ManagementLogs(management_data)
                managament_security = SecurityManagement(agent_name, management_logs)
                agents_functions[option](managament_security)
            elif option == i:
                break
            else:
                print("Invalid option. Please enter a valid option.")
