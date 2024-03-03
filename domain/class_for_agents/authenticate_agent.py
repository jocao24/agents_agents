from utils.types.agent_type import AgentType
import Pyro4


class AuthenticateAgent:
    def __init__(self, data_agent: AgentType, uri, ns_instance):
        self.ns_instance = ns_instance
        self.uri = uri
        self.data_agent = data_agent

    def authenticate_without_otp(self):
        is_otp_required = False
        is_error = False
        message = ""
        try:
            gateway_instance = self.ns_instance.authenticate_agent_in_gateway({
                "name": self.data_agent["name"],
                "description": self.data_agent["description"],
                "id": self.data_agent["id"],
                "skills": self.data_agent["skills"],
                "uri": self.uri
            })

            is_authenticated = gateway_instance.get('is_authenticated', False)
            if "error" in gateway_instance:
                is_error = True
                if str(gateway_instance["error"]).upper() == "OTP_REQUIRED":
                    is_otp_required = True
                    message = 'The OTP is required. Please enter the OTP: '
                else:
                    message = gateway_instance["error"]

            return gateway_instance, is_authenticated, is_error, message
        except Exception as e:
            is_error = True
            message = str(e)
            return None, False, is_error, message

    def authenticate_with_otp(self, code_otp: str):
        error = False
        message = ""
        try:
            gateway_instance = self.ns_instance.authenticate_agent_in_gateway({
                "name": self.data_agent["name"],
                "description": self.data_agent["description"],
                "id": self.data_agent["id"],
                "skills": self.data_agent["skills"],
                "code_otp": code_otp,
                "uri": self.uri
            })
            is_authenticated = gateway_instance.get('is_authenticated', False)

            if is_authenticated:
                gateway_uri = gateway_instance.get('gateway_uri', None)
                if not gateway_uri:
                    print("A gateway URI was not provided.")  # No se proporcion� una URI del gateway.
                    exit()

                gateway_proxy = Pyro4.Proxy(gateway_uri)
                print("Gateway located. Starting client...", gateway_uri)
                return gateway_proxy, is_authenticated, error, message
            else:
                error = True
                message = gateway_instance['error'] + '. ' + gateway_instance['message']
                return None, is_authenticated, error, message
        except Exception as e:
            error = True
            message = str(e)
            return None, False, error, message
