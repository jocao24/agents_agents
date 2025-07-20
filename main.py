import ctypes
import subprocess
import os
import sys
import threading
import platform
import shutil

# Determinar sistema operativo
IS_WINDOWS = platform.system() == "Windows"

if IS_WINDOWS:
    import win32gui
    import win32con
    import pywintypes
else:
    # Crear stubs para evitar errores en Linux/WSL
    class _Dummy:
        def __getattr__(self, _):
            return lambda *args, **kwargs: None

    win32gui = win32con = pywintypes = _Dummy()

import time
import csv
import uuid
import pyautogui
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from src.security.manage_data_agent import DataManagement
from src.utils.get_ip import get_ip
from src.utils.validate_ip import validate_ip

# Variables globales para la clave compartida, el código TOTP y la IP del nameserver
shared_key = None
code_otp = ""
ip_name_server = None
agent_processes = []

# Diccionario global para almacenar el conteo de agentes por tipo
agent_counts = {
    "Addition": 0,
    "Subtraction": 0,
    "Multiplication": 0,
    "Division": 0,
    "Consumer": 0
}

def export_all_logs_to_csv():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(current_dir, 'data') + os.sep

    if not os.path.exists(data_dir):
        print(f"Data directory does not exist: {data_dir}")
        return

    all_logs = []

    def extract_logs(filename):
        agent_name = filename[len('data_'):-len('.enc')]
        data_management = DataManagement(agent_name)
        data = data_management.load()
        if 'logs' in data:
            logs = data['logs']
            log_entries = [log.split(',') + [agent_name] for log in logs.strip().split('\n') if log]
            return log_entries
        return []

    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(extract_logs, filename) for filename in os.listdir(data_dir) if filename.startswith('data_') and filename.endswith('.enc')]
        for future in as_completed(futures):
            all_logs.extend(future.result())

    headers = ["session_id", "timestamp", "component", "message", "log_type", "success", "time", "agent_uuid", "yellow_page_uuid", "agent_type", "uuid_agent_request", "uuid_agent_response", "uuid_request", "agent_name"]    
    csv_filename = os.path.join(data_dir, 'all_logs.csv')
    with open(csv_filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(all_logs)
    print(f"All logs have been exported to {csv_filename}")

def log_agent_batch(agent_type, num_agents, total_time, start_time, end_time):
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(current_dir, 'data') + os.sep
    csv_filename = os.path.join(data_dir, 'agent_batches.csv')
    headers = ["session_id", "agent_type", "num_agents", "total_time", "start_time", "end_time"]

    if not os.path.exists(data_dir):
        os.makedirs(data_dir)

    new_file = not os.path.exists(csv_filename)

    session_id = str(uuid.uuid4())
    agent_type_str = {1: "Addition", 2: "Subtraction", 3: "Multiplication", 4: "Division", 5: "Consumer"}.get(agent_type, "Unknown")

    with open(csv_filename, mode='a', newline='') as file:
        writer = csv.writer(file)
        if new_file:
            writer.writerow(headers)
        writer.writerow([session_id, agent_type_str, num_agents, total_time, start_time, end_time])
    print(f"Agent batch logged with session ID: *{session_id[-4:]}")

def request_ip():
    global ip_name_server
    if ip_name_server:
        return ip_name_server
    while True:
        ip_name_server = input("Enter the IP of the nameserver. If it is the same as the NameServer, press enter: ")
        if ip_name_server:
            is_valid_ip = validate_ip(ip_name_server)
            if not is_valid_ip:
                print("The IP entered is not valid. Please enter a valid IP.")
                continue
            return ip_name_server
        ip_name_server = get_ip()
        return ip_name_server

def request_data_agent(agent_name: str, agent_type: int, previous_data=None):
    global shared_key, code_otp, ip_name_server

    # Nombre del archivo según el tipo de agente y el número de agentes existentes
    data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data') + os.sep
    agent_files = [f for f in os.listdir(data_dir) if f.startswith(f'data_agent_{agent_name}_') and f.endswith('.enc')]
    agent_index = len(agent_files) + 1
    filename = f'data_agent_{agent_name}_{agent_index}.enc'
    
    # Si existen archivos previos, cargar y desencriptar el último
    if agent_files:
        last_agent_file = sorted(agent_files)[-1]
        data_management = DataManagement(last_agent_file)
        previous_data = data_management.load()
        use_previous = input("Previous data found. Do you want to use it? (y/n) default: y: ") or 'y'
        if use_previous.lower() == 'y':
            shared_key = previous_data['shared_key']
            code_otp = previous_data['code_otp']
            ip_name_server = previous_data['ip_name_server']
            return previous_data

    if previous_data:
        change = input("Do you want to change the description and skills? (y/n) default: n: ") or 'n'
        if change.lower() == 'y':
            description_agent = input('Enter the new description of the agent: ')
            skills = input('Enter the new skills of the agent separated by commas: ')
            skills = skills.split(',')
        else:
            description_agent = previous_data['description']
            skills = previous_data['skills']
    else:
        description_agent = input('Enter the description of the agent: ')
        skills = input('Enter the skills of the agent separated by commas: ')
        skills = skills.split(',')

    id_agent = str(uuid.uuid4())
    ip_name_server = request_ip()

    if not shared_key:
        shared_key = input('Enter the shared key: ')

    if not code_otp or not code_otp.isdigit():
        code_otp = input('Enter the TOTP code: ')

    data_agent = {
        "name": agent_name,
        "description": description_agent,
        "id": id_agent,
        "ip_name_server": ip_name_server,
        "skills": skills,
        "shared_key": shared_key,
        "code_otp": code_otp
    }

    # Guardar los datos en el archivo correspondiente
    data_management = DataManagement(filename)
    data_management.save(data_agent)

    return data_agent

def create_and_execute_agent(agent_type, shared_key, code_otp, description, skills, ip_name_server, agent_name, agent_id):
    if IS_WINDOWS:
        window_title = f"{agent_name}_{agent_id}"
        command = f'start /MIN cmd /C "title {window_title} & {sys.executable} connect_agent.py {agent_type} {shared_key} {code_otp} \"{description}\" \"{skills}\" {ip_name_server} {agent_name} {agent_id}"'
        process = subprocess.Popen(command, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP, shell=True)
        time.sleep(1)
        hwnd = get_hwnd_by_title(window_title)
        if hwnd:
            print(f"Obtained hwnd for process {process.pid}: {hwnd}")
            win32gui.ShowWindow(hwnd, win32con.SW_HIDE)
        else:
            print(f"Failed to obtain hwnd for process {process.pid}")
    else:
        # Linux/WSL: abrir una nueva ventana de terminal visible
        args_list = [
            sys.executable, "connect_agent.py", str(agent_type), shared_key,
            code_otp, description, skills, ip_name_server, agent_name, agent_id
        ]

        # Determinar emulador de terminal disponible
        if shutil.which("gnome-terminal"):
            cmd = ["gnome-terminal", "--"] + args_list
        elif shutil.which("x-terminal-emulator"):
            cmd = ["x-terminal-emulator", "-e"] + args_list
        elif shutil.which("xterm"):
            cmd = ["xterm", "-e"] + args_list
        else:
            # Fallback: ejecutar en la misma consola
            cmd = args_list
        process = subprocess.Popen(cmd)
        hwnd = None
    return (process, agent_name, hwnd, shared_key, code_otp, description, skills, ip_name_server, agent_id)

def create_and_execute_agents(agent_type, num_agents, shared_key, code_otp, description, skills, ip_name_server, previous_data=None):
    global agent_counts
    
    # Mapeo del tipo de agente a su nombre base
    agent_name_base = {1: "agent_adder", 2: "agent_subtractor", 3: "agent_multiplier", 4: "agent_divider", 5: "agent_consumer"}.get(agent_type, "agent")
    agent_type_str = {1: "Addition", 2: "Subtraction", 3: "Multiplication", 4: "Division", 5: "Consumer"}.get(agent_type, "Unknown")

    # Contar el número de agentes ya creados de este tipo
    start_index = agent_counts[agent_type_str] + 1

    start_time = datetime.now()

    # Crear agentes de 20 en 20
    agents_created = 0
    while agents_created < num_agents:
        batch_size = min(20, num_agents - agents_created)  # Crear 20 o menos agentes si quedan menos de 20
        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            futures = [
                executor.submit(
                    create_and_execute_agent,
                    agent_type,
                    shared_key,
                    code_otp,
                    description,
                    ", ".join(skills),
                    ip_name_server,
                    agent_name_base,
                    f"{start_index + i}"
                ) for i in range(agents_created, agents_created + batch_size)
            ]
            for future in futures:
                agent_processes.append(future.result())

        agents_created += batch_size
        agent_counts[agent_type_str] += batch_size  # Actualizar el conteo global para este tipo de agente

        if agents_created < num_agents:
            time.sleep(8)

    end_time = datetime.now()
    total_time = (end_time - start_time).total_seconds()
    log_agent_batch(agent_type, num_agents, total_time, start_time.isoformat(), end_time.isoformat())
def get_hwnd_by_title(title):
    if not IS_WINDOWS:
        return None
    def callback(hwnd, titles):
        if win32gui.IsWindowVisible(hwnd) and title in win32gui.GetWindowText(hwnd):
            titles.append(hwnd)
    titles = []
    win32gui.EnumWindows(callback, titles)
    return titles[0] if titles else None

def allow_set_foreground_window():
    if IS_WINDOWS:
        ctypes.windll.user32.AllowSetForegroundWindow(ctypes.windll.kernel32.GetCurrentProcessId())

def show_window(hwnd):
    if not IS_WINDOWS:
        return
    if hwnd and win32gui.IsWindow(hwnd):
        print(f"Showing window with hwnd: {hwnd}")
        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
        time.sleep(0.5)
        try:
            allow_set_foreground_window()
            foreground_thread_id = ctypes.windll.user32.GetWindowThreadProcessId(ctypes.windll.user32.GetForegroundWindow(), None)
            target_thread_id = ctypes.windll.user32.GetWindowThreadProcessId(hwnd, None)
            ctypes.windll.user32.AttachThreadInput(target_thread_id, foreground_thread_id, True)
            win32gui.BringWindowToTop(hwnd)
            win32gui.SetForegroundWindow(hwnd)
            win32gui.SetActiveWindow(hwnd)
            ctypes.windll.user32.AttachThreadInput(target_thread_id, foreground_thread_id, False)
        except pywintypes.error:
            pass  # Ocultar el error
    else:
        print("Invalid window handle, cannot bring window to front.")

def hide_window(hwnd):
    if IS_WINDOWS and hwnd and win32gui.IsWindow(hwnd):
        win32gui.ShowWindow(hwnd, win32con.SW_HIDE)

def open_agent_console(agent_index):
    for i, (_, _, hwnd, _, _, _, _, _, _) in enumerate(agent_processes):
        if i == agent_index:
            show_window(hwnd)
        else:
            hide_window(hwnd)

def terminate_all_agents():
    def terminate_agent(process, hwnd):
        try:
            if IS_WINDOWS and hwnd:
                win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
                time.sleep(0.5)
            if process.poll() is None:
                if IS_WINDOWS:
                    ctypes.windll.kernel32.TerminateProcess(int(process._handle), -1)
                else:
                    process.terminate()
                process.wait()
                return f"Forcefully terminated process {process.pid}"
            else:
                return f"Process {process.pid} already terminated"
        except Exception as e:
            return f"Error terminating process {process.pid}: {e}"

    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(terminate_agent, process, hwnd) for process, _, hwnd, _, _, _, _, _, _ in agent_processes]
        for future in as_completed(futures):
            print(future.result())

def manage_agents():
    while True:
        print("Manage agents by category:")
        print("1. Addition")
        print("2. Subtraction")
        print("3. Multiplication")
        print("4. Division")
        print("5. Consumer")
        print("6. Return to main menu")

        option = input("Enter the number of the desired option: ")

        if option == '6':
            break

        if option not in {'1', '2', '3', '4', '5'}:
            print("Invalid option. Please try again.")
            continue

        agent_type = int(option)
        agent_name_base = {1: "agent_adder", 2: "agent_subtractor", 3: "agent_multiplier", 4: "agent_divider", 5: "agent_consumer"}.get(agent_type, "agent")

        filtered_agents = [(i, agent) for i, agent in enumerate(agent_processes) if agent[1].startswith(agent_name_base)]

        if not filtered_agents:
            print(f"No agents found for category {agent_name_base}.")
            continue

        while True:
            print(f"Running agents in category {agent_name_base}:")
            for count, (index, (_, agent_name, _, _, _, _, _, _, agent_id)) in enumerate(filtered_agents, start=1):
                short_uuid = f"*{str(agent_id).split('-')[-1]}"
                print(f"{count}. {agent_name}_{short_uuid}")

            print(f"{len(filtered_agents) + 1}. Return to previous menu")

            agent_option = input("Select the agent you want to interact with: ")

            if not agent_option.isdigit() or int(agent_option) < 1 or int(agent_option) > len(filtered_agents) + 1:
                print("Invalid option. Please try again.")
                continue

            if int(agent_option) == len(filtered_agents) + 1:
                break

            open_agent_console(filtered_agents[int(agent_option) - 1][0])

def manage_all_agents():
    while True:
        print("All running agents:")
        for count, (index, (_, agent_name, _, _, _, _, _, _, agent_id)) in enumerate(agent_processes, start=1):
            short_uuid = f"*{str(agent_id).split('-')[-1]}"
            print(f"{count}. {agent_name}_{short_uuid}")

        print(f"{len(agent_processes) + 1}. Return to main menu")

        agent_option = input("Select the agent you want to interact with: ")

        if not agent_option.isdigit() or int(agent_option) < 1 or int(agent_option) > len(agent_processes) + 1:
            print("Invalid option. Please try again.")
            continue

        if int(agent_option) == len(agent_processes) + 1:
            break
        open_agent_console(int(agent_option) - 1)

# -----------------------------
# MODO SIMPLIFICADO PARA LINUX
# -----------------------------

if not IS_WINDOWS:
    # CLI mínimo: lanza un agente en la consola actual
    from connect_agent import agents_functions, execute_agent

    print("=== Agent Launcher (Linux/WSL modo simplificado) ===")
    while True:
        print("Seleccione el tipo de agente que desea ejecutar:")
        print("1. Addition")
        print("2. Subtraction")
        print("3. Multiplication")
        print("4. Division")
        print("5. Consumer")
        print("6. Salir")
        opt = input("Opción: ")
        if opt == '6':
            sys.exit(0)
        if opt not in {'1','2','3','4','5'}:
            print("Opción inválida\n")
            continue

        agent_type = int(opt)
        shared_key = input("Shared key: ")
        code_otp = input("Código TOTP: ")
        description = input("Descripción del agente: ")
        skills = input("Habilidades (separadas por coma): ").split(',')
        ip_name_server = input("IP del NameServer (enter para autodetectar): ") or get_ip()
        agent_name = input("Nombre base del agente (ej. agent_adder): ") or {
            1: "agent_adder", 2: "agent_subtractor", 3: "agent_multiplier", 4: "agent_divider", 5: "agent_consumer"}.get(agent_type, "agent")
        agent_id = str(uuid.uuid4())

        agent_function = agents_functions[agent_type]
        # Ejecutar de forma bloqueante en la misma terminal
        execute_agent(agent_function, shared_key, code_otp, description, skills, ip_name_server, agent_name, agent_id, agent_type)

        print("Agente finalizado. ¿Desea lanzar otro? (y/n) -> ", end='')
        if (input().lower() or 'n') != 'y':
            break

    sys.exit(0)

# -------------------------------------------
# Código ORIGINAL para Windows a partir de aquí
# -------------------------------------------

if __name__ == "__main__":
    start_time = datetime.now()
    print(f"Program started at: {start_time.isoformat()}")

    previous_agent_data = {}

    if not shared_key:
        shared_key = input("Enter the shared key to use for all agents: ")

    while True:
        print("Main Menu:")
        print("1. Register agents by batch")
        print("2. Manage agents by category")
        print("3. Export all logs to CSV")
        print("5. Exit")

        option = input("Enter the number of the desired option: ")

        if option == '5':
            break

        if option == '3':
            export_all_logs_to_csv()
            continue

        if option == '2':
            manage_agents()
            continue

        if option == '1':
            print("Select the type of agent you want to execute:")
            print("1. Addition")
            print("2. Subtraction")
            print("3. Multiplication")
            print("4. Division")
            print("5. Consumer")

            agent_option = input("Enter the number of the desired option: ")

            if agent_option not in {'1', '2', '3', '4', '5'}:
                print("Invalid option. Please try again.")
                continue

            agent_type = int(agent_option)

            num_agents = input(f"Enter the number of agents of type {agent_option} you want to execute: ")

            if not num_agents.isdigit():
                print("Invalid number. Please try again.")
                continue

            num_agents = int(num_agents)

            agent_data = request_data_agent(f"agent_{agent_type}", agent_type)
            previous_agent_data[agent_type] = agent_data

            shared_key = agent_data["shared_key"]
            code_otp = agent_data["code_otp"]
            description = agent_data["description"]
            skills = agent_data["skills"]
            ip_name_server = agent_data["ip_name_server"]

            create_and_execute_agents(agent_type, num_agents, shared_key, code_otp, description, skills, ip_name_server)
            continue

        print("Invalid option. Please try again.")

    end_time = datetime.now()
    print(f"Program ended at: {end_time.isoformat()}")

    terminate_all_agents()

    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data', 'session_times.csv'), mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["start_time", "end_time"])
        writer.writerow([start_time.isoformat(), end_time.isoformat()])
    print("Session times saved successfully.")
