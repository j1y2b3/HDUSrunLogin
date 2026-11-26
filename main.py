import argparse
import hashlib
import hmac
import json
import re
import time
import socket
import urllib.error
import urllib.parse
import urllib.request

from encodeinfo import encode_info

from typing import Any


class NoAvailablePortalError(RuntimeError):
    pass

class NotOnlineError(RuntimeError):
    pass

def _is_legal_ip(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False


class Manager:

    def __init__(self):
        self.TIMEOUT = 1
        self.CALLBACK = "callback"
        self.TOKEN_API = "/cgi-bin/get_challenge"
        self.INFO_API = "/cgi-bin/rad_user_info"
        self.LOGOUT_API = "/cgi-bin/rad_user_dm"
        self.LOGIN_API = "/cgi-bin/srun_portal"
        self.BASE, self.AC_ID = self._detect_base_url()

    def _search_acid(self, data: str) -> str | None:
        ac_id = re.search("ac_id=[0-9]*", data)
        if ac_id is not None:
            ac_id = re.search("[0-9]+", ac_id.group(0))
        if ac_id is not None:
            ac_id = ac_id.group(0)
        return ac_id

    def _detect_base_url(self) -> tuple[str, str]:
        url = "https://portal.hdu.edu.cn"
        try:
            with urllib.request.urlopen(url, timeout=self.TIMEOUT) as res:
                data = res.read().decode("utf-8", errors="replace")
            ac_id = self._search_acid(data)
            if ac_id is not None:
                return url, ac_id
        except urllib.error.URLError:
            pass

        url = "https://yue.hdu.edu.cn"
        try:
            with urllib.request.urlopen(url, timeout=self.TIMEOUT) as res:
                data = res.read().decode("utf-8", errors="replace")
            ac_id = self._search_acid(data)
            if ac_id is not None:
                return url, ac_id
        except urllib.error.URLError:
            pass

        url = "https://login.hdu.edu.cn"
        try:
            with urllib.request.urlopen(url, timeout=self.TIMEOUT) as res:
                data = res.url
            ac_id = self._search_acid(data)
            if ac_id is not None:
                return url, ac_id
        except urllib.error.URLError:
            pass

        raise NoAvailablePortalError("No available portal, may not in HDU network.")

    def _get_ip(self, username: str | None = None) -> str:
        if username is not None:
            ip = socket.gethostbyname(socket.gethostname())
            url = f"{self.BASE}{self.TOKEN_API}"
            params = {"username": username, "ip": ip}
            data = self.get_jsonp_req(url, params)
            return data["client_ip"]

        ip = socket.gethostbyname(socket.gethostname())
        data = self.get_jsonp_req(self.info(ip))
        if "client_ip" in data:
            return data["client_ip"]

        ip = "127.0.0.1"
        data = self.get_jsonp_req(self.info(ip))
        return data["client_ip"]

    def get_jsonp_req(self, url: str, params: dict | None = None) -> Any:
        if params is not None:
            url = f"{url}?callback={self.CALLBACK}&{urllib.parse.urlencode(params)}"
        with urllib.request.urlopen(url) as res:
            data = res.read().decode("utf-8", errors="replace")
            data = data[len(self.CALLBACK) + 1 : -1]
        return json.loads(data)

    def info(self, ip: str | None) -> Any:
        if ip is not None and not _is_legal_ip(ip):
            raise ValueError(f"Invalid IP: '{ip}'.")
        if ip is None:
            ip = self._get_ip()

        url = f"{self.BASE}{self.INFO_API}"
        params = {"ip": ip}
        return f"{url}?callback={self.CALLBACK}&{urllib.parse.urlencode(params)}"

    def login(self, username: str, password: str, ip: str | None = None) -> str:
        if ip is not None and not _is_legal_ip(ip):
            raise ValueError(f"Invalid IP: '{ip}'.")
        if ip is None:
            ip = self._get_ip()

        N = 200
        TYPE = 1
        ENC = "srun_bx1"
        ACTION = "login"
        DEVICE = "Linux"
        PLATFORM = "Linux"
        DOUBLE_STACK = 0

        token_url = f"{self.BASE}{self.TOKEN_API}"
        token_params = {"username": username, "ip": ip}
        token = self.get_jsonp_req(token_url, token_params)
        token = token["challenge"]

        hmd5 = hmac.new(token.encode(), password.encode(), hashlib.md5).hexdigest()

        info = encode_info({
            "username": username,
            "password": password,
            "ip": ip,
            "acid": self.AC_ID,
            "enc_ver": ENC
        }, token)

        chksum = token + username
        chksum += token + hmd5
        chksum += token + self.AC_ID
        chksum += token + ip
        chksum += token + str(N)
        chksum += token + str(TYPE)
        chksum += token + info
        chksum = hashlib.sha1(chksum.encode('utf-8')).hexdigest()

        params = {
            "action": ACTION,
            "username": username,
            "password": "{MD5}" + hmd5,
            "os": DEVICE,
            "name": PLATFORM,
            "double_stack": DOUBLE_STACK,
            "chksum": chksum,
            "info": info,
            "ac_id": self.AC_ID,
            "ip": ip,
            "n": N,
            "type": TYPE
        }
        url = f"{self.BASE}{self.LOGIN_API}"
        return f"{url}?callback={self.CALLBACK}&{urllib.parse.urlencode(params)}"

    def logout(self, username: str | None = None, ip: str | None = None) -> str:
        if ip is not None and not _is_legal_ip(ip):
            raise ValueError(f"Invalid IP: '{ip}'.")
        if ip is None:
            ip = self._get_ip()
        if username is None:
            data = self.get_jsonp_req(self.info(ip))
            if data.get("error") == "not_online_error":
                raise NotOnlineError(f"'{ip}' is not online.")
            if "user_name" not in data:
                raise ValueError(f"info API '{self.BASE}{self.INFO_API}' error: not return username.")
            username = str(data["user_name"])

        UNBIND = "1"
        TIME = str(int(time.time()))

        sign = TIME + username + ip + UNBIND + TIME
        sign = hashlib.sha1(sign.encode('utf-8')).hexdigest()

        url = f"{self.BASE}{self.LOGOUT_API}"
        params = {
            "ip": ip,
            "username": username,
            "time": TIME,
            "unbind": UNBIND,
            "sign": sign
        }
        return f"{url}?callback={self.CALLBACK}&{urllib.parse.urlencode(params)}"


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-y", action="store_true", help="confirm send request")

    info_parsers = subparsers.add_parser("info", parents=(common, ))
    info_parsers.add_argument("--ip")

    login_parsers = subparsers.add_parser("login", parents=(common, ))
    login_parsers.add_argument("--ip")
    login_parsers.add_argument("--username", required=True)
    login_parsers.add_argument("--password", required=True)

    logout_parsers = subparsers.add_parser("logout", parents=(common, ))
    logout_parsers.add_argument("--ip")
    logout_parsers.add_argument("--username")

    args = parser.parse_args()
    manager = Manager()

    if args.mode == "info":
        res = manager.info(args.ip)
    elif args.mode == "login":
        res = manager.login(args.username, args.password, args.ip)
    elif args.mode == "logout":
        res = manager.logout(args.username, args.ip)

    if args.y:
        res = manager.get_jsonp_req(res)

    if not args.y:
        print(f"Add '-y' to send GET request: \n{res}")
    elif isinstance(res, dict):
        print(f"Result:\n{json.dumps(res, indent=2, ensure_ascii=False)}")
    else:
        print(res)


if __name__ == "__main__":
    main()