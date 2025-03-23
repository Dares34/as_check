import socket
import time
from ipaddress import IPv4Address, AddressValueError
from pprint import pprint
import logging

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


def data_processing(response, server_type):
    data = {}
    for line in response.splitlines():
        line = line.strip()
        if not line or line.startswith(("%", "#")):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if server_type == "iana":
            if key == "whois":
                return value
        else:
            if key in ["origin", "as-handle", "aut-num"]:
                data["AS"] = value.split()[-1]
            elif key in ["country", "country-code"]:
                data["country"] = value.upper()
            elif key in ["org-name", "as-name", "descr", "organization"]:
                data["AS_name"] = value
    return data if data else False


def check_russian_as(info):
    return info.get("country") == "RU" and "AS" in info and "AS_name" in info


def get_whois(ip, whois_server):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((whois_server, 43))
        s.send(f"{ip}\r\n".encode())
        response = b""
        while True:
            data = s.recv(4096)
            if not data:
                break
            response += data
        s.close()
        server_type = "iana" if whois_server == "whois.iana.org" else "regional"
        return data_processing(response.decode(), server_type)
    except Exception as e:
        logger.info(f"Ошибка при запросе к {whois_server}: {e}")
        return False


def validate_request(ip):
    try:
        IPv4Address(ip)
        iana_server = get_whois(ip, "whois.iana.org")
        if iana_server:
            regional_server = iana_server
        else:
            regional_server = REGIONAL_WHOIS["ripe"]

        time.sleep(1)
        regional_info = get_whois(ip, regional_server)
        if not regional_info:
            time.sleep(1)
            regional_info = get_whois(ip, RADB_WHOIS)

        if regional_info:
            if check_russian_as(regional_info):
                logger.info(f"IP {ip} принадлежит российской AS:")
                logger.info(regional_info)
                regional_info['RU'] = True
                return regional_info
            else:
                logger.info(f"IP {ip} не принадлежит российской AS.")
                regional_info['RU'] = False
                return regional_info
        else:
            logger.error("Не удалось получить данные о AS.")
            return -2
    except AddressValueError:
        logger.error("Некорректный IP-адрес.")
        return -3
    except Exception as e:
        logger.error(f"Ошибка: {e}")
        return -4


if __name__ == "__main__":
    print(validate_request("82.98.86.175"))

    print(validate_request("217.69.128.44"))

    validate_request("77.88.55.88")