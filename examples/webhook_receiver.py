from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sys


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)

        print("\n--- WEBHOOK RECEIVED ---", flush=True)
        print(f"Path: {self.path}", flush=True)
        print("Headers:", flush=True)

        for key, value in self.headers.items():
            print(f"  {key}: {value}", flush=True)

        print("Body:", flush=True)

        try:
            parsed = json.loads(body.decode("utf-8"))
            print(json.dumps(parsed, indent=2), flush=True)
        except Exception:
            print(body.decode("utf-8", errors="replace"), flush=True)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")
        self.wfile.flush()

    def log_message(self, format, *args):
        sys.stdout.write("[http] " + format % args + "\n")
        sys.stdout.flush()


def main():
    server = HTTPServer(("127.0.0.1", 8787), Handler)
    print("Listening on http://127.0.0.1:8787/webhook", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
