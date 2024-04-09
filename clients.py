from src.agents import execute_client_1
from src.security.security_management import SecurityManagement

if __name__ == '__main__':
    agents_names = {
        1: "Client 1",
    }
    agents_functions = {
        1: execute_client_1,
    }
    while True:
        print("Which agents.py do you want to execute?")
        i = 1
        for key, value in agents_names.items():
            print(f"{key}. {value}")
            i += 1

        print(f"{i}. Exit")

        option = input("Enter the number of the client you want to execute: ")
        if option.isdigit():
            managament_security = SecurityManagement()
            option = int(option)
            if option in agents_names:
                agents_functions[option](managament_security)
            elif option == i:
                break
            else:
                print("Invalid option. Please enter a valid option.")


