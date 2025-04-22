import sys
import uuid
from src.manage_logs.manage_logs_v_2 import ManagementLogs
from src.security.manage_data_agent import DataManagement
from src.security.security_management import SecurityManagement

# Importing agent execution functions
from src.agents_remote_objects.adder import execute_adder
from src.agents_remote_objects.client_1 import execute_client_1
from src.agents_remote_objects.substract import execute_subtract
from src.agents_remote_objects.multiplication import execute_multiplication
from src.agents_remote_objects.division import execute_division

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

def execute_agent(agent_function, shared_key, code_otp, description, skills, ip_name_server, agent_name, agent_id, agent_type):
    # Primero, crear y cargar los datos del agente
    management_data = DataManagement(f'{agent_name}_{agent_id}')
    existing_data = management_data.load() or {}
    
    # Asegurar que tengamos un UUID consistente
    uuid_agent = existing_data.get('uuid')
    if not uuid_agent:
        uuid_agent = str(uuid.uuid4())
        
    # Preparar los datos del agente
    data_agent = {
        "name": f'{agent_name}_{agent_id}',
        "description": description,
        "id": existing_data.get('id'),
        "uuid": uuid_agent,
        "ip_name_server": ip_name_server,
        "skills": skills,
        "ultimate_shared_key": shared_key,
        "code_otp": code_otp,
        "is_provider": True if agent_type != 5 else False,
        "is_consumer": True if agent_type == 5 else False,
    }
    
    # Guardar los datos antes de inicializar cualquier componente
    management_data.save(data_agent)
    
    # Ahora crear los componentes con el UUID ya establecido
    management_logs = ManagementLogs(management_data)
    management_logs.set_default_agent_uuid(uuid_agent)
    
    management_security = SecurityManagement(agent_name, management_logs, shared_key)
    
    # Ejecutar el agente
    agent_function(management_security)

if __name__ == "__main__":
    if len(sys.argv) < 9:
        print("Usage: python execute_agent.py <agent_type> <shared_key> <code_otp> <description> <skills> <ip_name_server> <agent_name> <agent_id>")
        sys.exit(1)

    agent_type = int(sys.argv[1])
    shared_key = sys.argv[2]
    code_otp = sys.argv[3]
    description = sys.argv[4]
    skills = sys.argv[5].split(',')
    ip_name_server = sys.argv[6]
    agent_name = sys.argv[7]
    agent_id = sys.argv[8]

    if agent_type not in agents_functions:
        print(f"Invalid agent type: {agent_type}")
        sys.exit(1)

    agent_function = agents_functions[agent_type]
    execute_agent(agent_function, shared_key, code_otp, description, skills, ip_name_server, agent_name, agent_id, agent_type)
