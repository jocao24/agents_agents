from typing_extensions import TypedDict, NotRequired


class RequestAgentType(TypedDict):
    id_request: str
    id_agent: str
    request_data: dict
    ip_agent: str


class ResponseAgentType(TypedDict):
    id_request: str
    data_response: dict


class AgentType(TypedDict):
    id: str
    uuid: str
    name: str
    description: str
    ip_name_server: str
    skills: list[str]
    ultimate_shared_key: NotRequired[str]
    logs: NotRequired[str]
    agent_is_consumers_services: NotRequired[bool]
    requests: NotRequired[list[RequestAgentType]]
    responses: NotRequired[list[ResponseAgentType]]
    is_consumer: NotRequired[bool]
    is_provider: NotRequired[bool]





