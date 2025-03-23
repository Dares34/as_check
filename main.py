import socket
import time
from ipaddress import IPv4Address, AddressValueError
import logging
from pprint import pprint

logger = logging.getLogger(__name__)

logging.basicConfig(
    filename="app.log",
    filemode="a",
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - %(name)s - (%(filename)s:%(lineno)d) - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

REGIONAL_WHOIS = {
    "ripe": "whois.ripe.net",
    "arin": "whois.arin.net",
    "apnic": "whois.apnic.net",
    "lacnic": "whois.lacnic.net",
    "afrinic": "whois.afrinic.net",
}
RADB_WHOIS = "whois.radb.net"


def data_processing(
    response, server_type, data={"AS": None, "AS_name": None, "country": None}
):
    print(server_type)
    pprint(response)
    for line in response.splitlines():
        line = line.strip()
        if not line or line.startswith(("%", "#")):
            continue

        if ":" not in line:
            continue

        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()

        if server_type == "radb":
            if key == "origin":
                data["AS"] = value.split()[-1]
            elif key == "descr" and not data.get("AS_name"):
                data["AS_name"] = value
            elif key == "country":
                data["country"] = value.upper()
        else:
            if key in ["org-name", "as-name", "asname"]:
                data["AS_name"] = value
            elif key == "descr" and not data.get("AS_name"):
                data["AS_name"] = value.split(",")[0].strip()
            elif key == "org-name" and not data.get("AS_name"):
                data["AS_name"] = value

            if key in ["origin", "originas", "aut-num"]:
                data["AS"] = value.split()[-1]
            elif key in ["country", "country-code"]:
                data["country"] = value.upper()
    print(data)
    return data if data["AS"] else False


def get_whois(ip, server):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10)
            s.connect((server, 43))
            s.send(f"{ip}\r\n".encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
        server_type = "radb" if server == RADB_WHOIS else "regional"
        return data_processing(response.decode(), server_type)
    except Exception as e:
        logger.error(f"WHOIS ошибка ({server}): {e}")
        return False


def validate_request(ip):
    try:
        IPv4Address(ip)
    except AddressValueError:
        logger.error(f"Invalid IP: {ip}")
        return -3

    regional_server = None
    iana_response = get_whois(ip, "whois.iana.org")
    if iana_response and isinstance(iana_response, str):
        regional_server = iana_response
    else:
        regional_server = REGIONAL_WHOIS["ripe"]
        logger.warning("Использования сервера ripe")

    time.sleep(1)
    regional_info = get_whois(ip, regional_server)

    if not regional_info:
        time.sleep(1)
        regional_info = get_whois(ip, RADB_WHOIS)
        logger.info("Falling back to RADB")

    if regional_info and regional_info.get("AS"):
        if regional_info.get("country") == "RU":
            logger.info(
                f"Russian AS found: AS{regional_info['AS']} ({regional_info.get('AS_name')})"
            )
            regional_info["RU"] = True
            return regional_info
        else:
            logger.info(
                f"Foreign AS found: AS{regional_info['AS']} ({regional_info.get('country')})"
            )
            regional_info["RU"] = False
            return regional_info
    else:
        logger.error("No AS information found")
        return -2


if __name__ == "__main__":
    test_ips = [
        # "82.98.86.175",
        # "217.69.128.44",
        "64.233.160.0",  # Google (US)
        # "94.103.153.133",  # Yandex (RU)
        # "142.251.45.78",  # Google (US)
        # "84.252.160.0",
    ]

    for ip in test_ips:
        print(f"Checking {ip}: {validate_request(ip)}")
