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

def _get_jsonp_req(url: str, params: dict[str, Any], ischeck: bool = True) -> Any:
    CALLBACK = "callback"
    url = f"{url}?callback={CALLBACK}&{urllib.parse.urlencode(params)}"
    if ischeck:
        return url
    with urllib.request.urlopen(url) as res:
        data = res.read().decode("utf-8", errors="replace")
        data = data[len(CALLBACK) + 1 : -1]
    return json.loads(data)


class Manager:

    def __init__(self):
        self.TIMEOUT = 1
        self.TOKEN_API = "/cgi-bin/get_challenge"
        self.INFO_API = "/cgi-bin/rad_user_info"
        self.LOGOUT_API = "/cgi-bin/rad_user_dm"
        self.LOGIN_API = "/cgi-bin/srun_portal"
        self.BASE, self.AC_ID = self._detect_base_url()

    def _detect_base_url(self) -> tuple[str, str]:
        # ac_id = None

        url = "https://portal.hdu.edu.cn"
        try:
            with urllib.request.urlopen(url, timeout=self.TIMEOUT) as res:
                # PUBLIC_NET_WARNING = "此网站仅限于内部网络（内网）访问，而您当前所使用的访问地址属于公共网络（公网），因此无法直接访问。"
                data = res.read().decode("utf-8", errors="replace")
                # if data == PUBLIC_NET_WARNING:
                #     raise urllib.error.URLError(PUBLIC_NET_WARNING)
                data = re.search("ac_id=[0-9]*", data)
                if data is not None:
                    data = re.search("[0-9]+", data.group(0))
                if data is not None:
                    ac_id = data.group(0)
            # if ac_id is not None:
            return url, ac_id
        except urllib.error.URLError:
            pass

        url = "https://yue.hdu.edu.cn"
        try:
            with urllib.request.urlopen(url, timeout=self.TIMEOUT) as res:
                data = res.read().decode("utf-8", errors="replace")
                data = re.search("ac_id=[0-9]*", data)
                if data is not None:
                    data = re.search("[0-9]+", data.group(0))
                if data is not None:
                    ac_id = data.group(0)
            # if ac_id is not None:
            return url, ac_id
        except urllib.error.URLError:
            pass

        url = "https://login.hdu.edu.cn"
        try:
            with urllib.request.urlopen(url, timeout=self.TIMEOUT) as res:
                data = res.url
                data = re.search("ac_id=[0-9]*", data)
                if data is not None:
                    data = re.search("[0-9]+", data.group(0))
                if data is not None:
                    ac_id = data.group(0)
            # if ac_id is not None:
            return url, ac_id
        except urllib.error.URLError:
            pass

        # if ac_id is None:
        #     raise NoAvailablePortalError("Not got 'ac_id'.")
        raise NoAvailablePortalError("No available base URL, may not in HDU network.")

    def _get_ip(self, username: str | None = None) -> str:
        if username is not None:
            ip = socket.gethostbyname(socket.gethostname())
            url = f"{self.BASE}{self.TOKEN_API}"
            params = {"username": username, "ip": ip}
            data = _get_jsonp_req(url, params, ischeck=False)
            return data["client_ip"]

        ip = socket.gethostbyname(socket.gethostname())
        data = self.info(ip, ischeck=False)
        if "client_ip" in data:
            return data["client_ip"]

        ip = "127.0.0.1"
        data = self.info(ip, ischeck=False)
        return data["client_ip"]

    def info(self, ip: str | None, ischeck: bool = True) -> Any:
        if ip is not None and not _is_legal_ip(ip):
            raise ValueError(f"Invalid IP: '{ip}'.")
        if ip is None:
            ip = self._get_ip()

        url = f"{self.BASE}{self.INFO_API}"
        params = {"ip": ip}
        return _get_jsonp_req(url, params, ischeck)

    def login(self, username: str, password: str, ip: str | None = None, ischeck: bool = True) -> Any:
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
        token = _get_jsonp_req(token_url, token_params, False)
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
        return _get_jsonp_req(url, params, ischeck)

    def logout(self, username: str | None = None, ip: str | None = None, ischeck: bool = True) -> Any:
        if ip is not None and not _is_legal_ip(ip):
            raise ValueError(f"Invalid IP: '{ip}'.")
        if ip is None and username is None:
            raise ValueError("'ip' and 'username' cannot be both None.")
        if ip is None:
            ip = self._get_ip()
        if username is None:
            data = self.info(ip, ischeck=False)
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
        return _get_jsonp_req(url, params, ischeck)


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
    ischeck = not args.y
    manager = Manager()
    res = None

    if args.mode == "info":
        res = manager.info(args.ip, ischeck=ischeck)
    elif args.mode == "login":
        res = manager.login(args.username, args.password, args.ip, ischeck=ischeck)
    elif args.mode == "logout":
        res = manager.logout(args.username, args.ip, ischeck=ischeck)

    if ischeck:
        print(f"Add '-y' to send GET request: \n{res}")
    elif isinstance(res, dict):
        print(f"Result:\n{json.dumps(res, indent=2, ensure_ascii=False)}")
    else:
        print(res)


if __name__ == "__main__":
    main()