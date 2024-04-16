import datetime
import threading
from src.security.manage_data_agent import DataManagement


class ManagementLogs:
    def __init__(self, data_management_instance: DataManagement):
        self.data_management_instance = data_management_instance
        self.log_buffer = ""
        self.lock = threading.Lock()
        self.flush_interval = 5  # time in seconds
        self._start_periodic_flush()

    def _start_periodic_flush(self):
        """Starts a timer that flushes the log buffer to storage every `self.flush_interval` seconds."""
        threading.Timer(self.flush_interval, self._flush_buffer).start()

    def _flush_buffer(self):
        """Flushes the current log buffer to persistent storage."""
        with self.lock:
            if self.log_buffer:
                current_data = self.data_management_instance.load()
                current_data['logs'] += self.log_buffer
                self.data_management_instance.save(current_data)
                self.log_buffer = ""  # Clear the buffer after saving
        self._start_periodic_flush()  # Reset the timer

    def log_message(self, message) -> str:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"{timestamp} - {message}\n"
        with self.lock:
            self.log_buffer += log_entry
        return log_entry

    def start_new_session_log(self):
        """Logs the start of a new session."""
        session_start = "\n===== New Session Started =====\n"
        with self.lock:
            self.log_buffer += session_start

    def get_end_session_log(self):
        """Retrieves logs of the most recent session."""
        all_logs = self.get_all_logs()
        return all_logs

    def get_all_logs(self):
        data = self.data_management_instance.load()
        logs = data['logs'] + self.log_buffer
        return logs

