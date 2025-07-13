import http.server
import ssl

PORT = 8443
DIRECTORY = "."

class SecureHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

if __name__ == "__main__":
    httpd = http.server.HTTPServer(('0.0.0.0', PORT), SecureHTTPRequestHandler)

    httpd.socket = ssl.wrap_socket(
        httpd.socket,
        keyfile="key.pem",
        certfile="cert.pem",
        server_side=True
    )

    print(f"Serving HTTPS on https://localhost:{PORT}")
    httpd.serve_forever()
