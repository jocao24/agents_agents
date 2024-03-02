from typing_extensions import TypedDict, NotRequired


class AgentType(TypedDict):
    id: str
    name: str
    description: str
    local_ip: str
    ip_name_server: NotRequired[str]
    skills: list[str]

