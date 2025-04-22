import csv
from datetime import datetime
from enum import Enum, auto
import os
import threading
import uuid
from src.security.manage_data_agent import DataManagement


class LogType(Enum):
    ENCRYPTION = auto()
    END_ENCRYPTION = auto()
    DECRYPTION = auto()
    END_DECRYPTION = auto()
    TIME_TOTAL_REGISTRATION = auto()
    END_TIME_TOTAL_REGISTRATION = auto()
    REGISTRATION = auto()
    END_REGISTRATION = auto()
    REGISTRATION_URI = auto()
    END_REGISTRATION_URI = auto()
    PREREGISTRATION = auto()
    END_PREREGISTRATION = auto()
    UPLOAD = auto()
    END_UPLOAD = auto()
    START_SESSION = auto()
    END_SESSION = auto()
    KEY_GENERATION = auto()
    END_KEY_GENERATION = auto()
    SHARED_KEY = auto()
    END_SHARED_KEY = auto()
    SERIALIZATION = auto()
    END_SERIALIZATION = auto()
    CONNECTION = auto()
    END_CONNECTION = auto()
    ERROR = auto()
    DAEMON_START = auto()
    DAEMON_END = auto()
    OTHER = auto()
    REQUEST = auto()
    END_REQUEST = auto()
    RESPONSE = auto()
    END_RESPONSE = auto()
    DELETE_ACL_BLACKLIST = auto(),
    ADD_ACL_BLACKLIST = auto(),
    ADD_ACL_WHITELIST = auto(),
    END_ADD_ACL_BLACKLIST = auto(),
    DELETE_ACL_WHITELIST = auto(),
    END_ADD_ACL_WHITELIST = auto(),
    EXIT = auto(),
    END_DELETE_ACL_BLACKLIST = auto(),
    END_DELETE_ACL_WHITELIST = auto(),
    QUERY = auto(),
    USER_REQUEST_START = auto(),
    USER_REQUEST_END = auto(),
    CONSUMER_REQUEST_START = auto(),
    CONSUMER_REQUEST_END = auto(),
    PROVIDER_REQUEST_START = auto(),
    PROVIDER_REQUEST_END = auto(),
    PROVIDER_PROCESS_START = auto(),
    PROVIDER_PROCESS_END = auto(),


class ComponentType(Enum):
    SECURITY_MANAGEMENT = auto()
    AGENT_CONNECTION_HANDLER = auto()
    SESSION_MANAGER = auto()
    ADDER = auto()
    BASE_AGENT = auto()
    AGENT_CONSUMER = auto()
    AGENT_PROVIDER = auto()
    CLIENT = auto()
    MENU = auto()


class LogEntry:
    def __init__(self, session_id: str, timestamp: datetime, component: ComponentType, message: str, log_type: LogType,
                 success: bool = True, time_str: str = None, agent_uuid: str = None, 
                 yellow_page_uuid: str = None, agent_type: str = None, uuid_agent_request: str = None, 
                 uuid_agent_response: str = None, uuid_request: str = None):
        self.session_id = session_id
        self.timestamp = timestamp
        self.component = component
        self.message = message
        self.log_type = log_type
        self.success = success
        self.agent_uuid = agent_uuid
        self.yellow_page_uuid = yellow_page_uuid
        self.agent_type = agent_type
        self.uuid_agent_request = uuid_agent_request
        self.uuid_agent_response = uuid_agent_response
        self.uuid_request = uuid_request
        if time_str:
            self.time_str = time_str
        else:
            self.time_str = '0'

    def __str__(self):
        return f"{self.session_id},{self.timestamp.isoformat()},{self.component.name},{self.message},{self.log_type.name},{self.success},{self.time_str},{self.agent_uuid or ''},{self.yellow_page_uuid or ''},{self.agent_type or ''},{self.uuid_agent_request or ''},{self.uuid_agent_response or ''},{self.uuid_request or ''}\n"

    def formatted_str(self):
        success_str = "Success" if self.success else "Failure"
        uuid_info = f" | Agent UUID: {self.agent_uuid}" if self.agent_uuid else ""
        yp_info = f" | Yellow Page UUID: {self.yellow_page_uuid}" if self.yellow_page_uuid else ""
        agent_type_info = f" | Agent Type: {self.agent_type}" if self.agent_type else ""
        request_info = f" | Request Agent: {self.uuid_agent_request}" if self.uuid_agent_request else ""
        response_info = f" | Response Agent: {self.uuid_agent_response}" if self.uuid_agent_response else ""
        request_uuid_info = f" | Request UUID: {self.uuid_request}" if self.uuid_request else ""
        return f"{self.timestamp.isoformat()} -- {self.component.name} -- {self.message} -- {self.log_type.name}, {success_str}, {self.time_str}{uuid_info}{yp_info}{agent_type_info}{request_info}{response_info}{request_uuid_info}"

    def display_str(self):
        time_str = self.timestamp.strftime("%H:%M:%S.%f")
        success_str = "Success" if self.success else "Failure"
        uuid_info = f" | Agent UUID: {self.agent_uuid}" if self.agent_uuid else ""
        yp_info = f" | Yellow Page UUID: {self.yellow_page_uuid}" if self.yellow_page_uuid else ""
        agent_type_info = f" | Agent Type: {self.agent_type}" if self.agent_type else ""
        request_info = f" | Request Agent: {self.uuid_agent_request}" if self.uuid_agent_request else ""
        response_info = f" | Response Agent: {self.uuid_agent_response}" if self.uuid_agent_response else ""
        request_uuid_info = f" | Request UUID: {self.uuid_request}" if self.uuid_request else ""
        return f"{time_str} - {self.component.name} - {self.message} - {self.log_type.name}, {success_str}, {self.time_str}{uuid_info}{yp_info}{agent_type_info}{request_info}{response_info}{request_uuid_info}"


class ManagementLogs:
    def __init__(self, data_management_instance: DataManagement):
        self.data_management_instance = data_management_instance
        self.session_id = ''
        self.log_buffer = []
        self.lock = threading.Lock()
        self.flush_interval = 5  # time in seconds
        self._start_periodic_flush()
        self.default_agent_uuid = None

    def set_default_agent_uuid(self, uuid: str):
        """Establece el UUID del agente por defecto para todos los logs."""
        self.default_agent_uuid = uuid

    def _start_periodic_flush(self):
        threading.Timer(self.flush_interval, self._flush_buffer).start()

    def _flush_buffer(self):
        with self.lock:
            if self.log_buffer:
                current_data = self.data_management_instance.load()
                if 'logs' in current_data:
                    current_data['logs'] += ''.join([str(log) for log in self.log_buffer])
                else:
                    current_data['logs'] = ''.join([str(log) for log in self.log_buffer])
                self.data_management_instance.save(current_data)
                self.log_buffer = []  # Clear the buffer after saving
        self._start_periodic_flush()

    def log_message(self, component: ComponentType, message: str, log_type: LogType, success: bool = True,
                    time_str: str = None, agent_uuid: str = None, 
                    yellow_page_uuid: str = None, agent_type: str = None, uuid_agent_request: str = None,
                    uuid_agent_response: str = None, uuid_request: str = None) -> str:
        timestamp = datetime.now()
        
        # Usar el UUID proporcionado o el UUID por defecto, sin crear uno nuevo
        final_agent_uuid = agent_uuid or self.default_agent_uuid
        
        log_entry = LogEntry(
            self.session_id, timestamp, component, message, log_type, success, time_str, 
            final_agent_uuid, yellow_page_uuid, agent_type, 
            uuid_agent_request, uuid_agent_response, uuid_request
        )
        with self.lock:
            self.log_buffer.append(log_entry)
        return str(log_entry)

    def start_new_session_log(self):
        """Logs the start of a new session."""
        self.session_id = str(uuid.uuid4())
        session_start_message = f"New session started with UUID: {self.session_id}"
        
        self.log_message(
            ComponentType.SESSION_MANAGER, 
            session_start_message, 
            LogType.START_SESSION,
            agent_uuid=self.default_agent_uuid
        )

    def get_all_logs(self) -> str:
        data = self.data_management_instance.load()
        logs = data['logs'] + ''.join([str(log) for log in self.log_buffer])
        return logs

    def get_current_session_logs(self) -> str:
        """Retrieve logs of the current session."""
        current_logs = [log for log in self.log_buffer if log.session_id == self.session_id]
        formatted_logs = '\n'.join([log.display_str() for log in current_logs])
        return f"Logs:\n{formatted_logs}"

    def export_logs_to_csv(self, name_agent: str):
        """Export all logs to a CSV file."""
        data = self.data_management_instance.load()
        all_logs = data['logs'] + ''.join([str(log) for log in self.log_buffer])
        log_entries = [log.split(',') for log in all_logs.strip().split('\n')]

        headers = ["session_id", "timestamp", "component", "message", "log_type", "success", "time", "agent_uuid", "yellow_page_uuid", "agent_type", "uuid_agent_request", "uuid_agent_response", "uuid_request"]

        # Obtén la ruta del directorio actual (el que contiene el script que se está ejecutando)
        current_dir = os.path.dirname(os.path.abspath(__file__))

        # Navega un nivel hacia atrás para ubicarte en el directorio que contiene 'src'
        project_root = os.path.abspath(os.path.join(current_dir, os.pardir, os.pardir))

        # Concatena la carpeta 'data' a la ruta del proyecto
        data_dir = os.path.join(project_root, 'data') + os.sep

        with open(f'{data_dir}logs_{name_agent}.csv', mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(headers)
            writer.writerows(log_entries)
