from http.server import BaseHTTPRequestHandler, HTTPServer

from main import Manager


class Handler(BaseHTTPRequestHandler):

    def do_GET(self):
        ip = self.client_address[0]
        print(ip)

        manager = Manager()
        print(manager.logout(ip=ip))
        print(manager.get_jsonp_req(manager.logout(ip=ip)))

        body = "啥都木有\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 8000), Handler).serve_forever()