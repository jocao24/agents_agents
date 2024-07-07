import os
from src.utils.get_system_uuid import get_system_uuid
from src.utils.types.agent_type import AgentType
from src.security.secure_storage import SecureStorage


class DataManagement:
    def __init__(self, name_agent: str):
        if not hasattr(self, 'initialized', ):
            self.file_path = f'data/{name_agent}.enc'
            self.secure_storage = SecureStorage(get_system_uuid().encode(), self.file_path)
            self._ensure_file_exists()
            self.initialized = True

    def _ensure_file_exists(self):
        if not os.path.exists(self.file_path):
            self.save({
                'id': '',
                'name': '',
                'description': '',
                'ip_name_server': '',
                'skills': [],
                'ultimate_shared_key': '',
                'logs': '',
                'agent_is_consumers_services': False,
                'requests': [],
                'responses': []

            })

    def save(self, data: AgentType):
        self.secure_storage.encrypt_data(data)

    def load(self) -> AgentType:
        data_from_storage = self.secure_storage.decrypt_data()
        data_client: AgentType = AgentType(**data_from_storage)
        return data_client

    def delete(self):
        if os.path.exists(self.file_path):
            os.remove(self.file_path)
