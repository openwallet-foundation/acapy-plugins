from sys import argv

from http.server import BaseHTTPRequestHandler, HTTPServer

class BaseServer(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        self._set_headers()
        self.wfile.write("GET request for {}".format(self.path)
                  .encode("utf-8"))

    def do_HEAD(self):
        self._set_headers()

    def do_POST(self):
        self._set_headers()
        self.wfile.write("POST request for {}".format(self.path)
                  .encode("utf-8"))

if __name__ == "__main__":
    port = int(argv[1])

    server_address = ("", port)
    httpd = HTTPServer(
           server_address=("0.0.0.0", port),
           RequestHandlerClass=BaseServer
           )

    httpd.serve_forever()
