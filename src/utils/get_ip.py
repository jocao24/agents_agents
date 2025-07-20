import socket
import subprocess


# Devuelve una IP IPv4 no loopback. Compatible Windows/Linux/WSL


def get_ip():
    try:
        # 1) UDP a 8.8.8.8
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
        finally:
            s.close()

        # 2) hostname -I (Linux)
        try:
            output = subprocess.check_output(["hostname", "-I"], text=True).strip()
            if output:
                for cand in output.split():
                    if cand and not cand.startswith("127."):
                        return cand
        except Exception:
            pass

        # 3) gethostbyname
        try:
            ip = socket.gethostbyname(socket.gethostname())
            if ip and not ip.startswith("127."):
                return ip
        except Exception:
            pass

        return "127.0.0.1"
    except Exception as e:
        print("Error obtaining local IP address:", e)
        return "127.0.0.1"
