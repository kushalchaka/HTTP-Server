import socket
import sys
import threading
import os
import json
from datetime import datetime

HOST = '0.0.0.0'
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
UPLOAD_DIR = 'Upload'
DOWNLOAD_DIR = 'Download'
VISITORS_FILE = 'Upload/visitors.json'
DOS_THRESHOLD = 100
DOS_WINDOW = 60

lock = threading.Lock()
banned_ips = set()
visitors = {}
request_tracker = {}

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

def load_visitors():
    global visitors
    try:
        if os.path.exists(VISITORS_FILE):
            with open(VISITORS_FILE, 'r') as f:
                visitors = json.load(f)
            print(f"Loaded {len(visitors)} visitors from {VISITORS_FILE}")
    except Exception as e:
        print(f"Error loading visitors: {e}")
        visitors = {}

def save_visitors():
    try:
        with open(VISITORS_FILE, 'w') as f:
            json.dump(visitors, f, indent=2)
        print(f"Saved {len(visitors)} visitors to {VISITORS_FILE}")
    except Exception as e:
        print(f"Error saving visitors: {e}")

def check_dos_attack(ip):
    global request_tracker, banned_ips

    current_time = datetime.now().timestamp()

    with lock:
        if ip not in request_tracker:
            request_tracker[ip] = []

        request_tracker[ip] = [
            timestamp for timestamp in request_tracker[ip]
            if current_time - timestamp < DOS_WINDOW
        ]

        request_tracker[ip].append(current_time)

        if len(request_tracker[ip]) > DOS_THRESHOLD:
            if ip not in banned_ips:
                banned_ips.add(ip)
                print(f"DoS ATTACK DETECTED! IP {ip} banned ({len(request_tracker[ip])} requests in {DOS_WINDOW}s)")
            return True

        return False

def update_visitor(ip):
    global visitors

    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    with lock:
        if ip not in visitors:
            visitors[ip] = {
                'count': 1,
                'first_visit': current_time,
                'last_visit': current_time
            }
        else:
            visitors[ip]['count'] += 1
            visitors[ip]['last_visit'] = current_time

def get_cookie_header(ip):
    with lock:
        if ip in visitors:
            visit_count = visitors[ip]['count']
            last_visit = visitors[ip]['last_visit']
            return f"visitor_id={ip}; visit_count={visit_count}; last_visit={last_visit}"
    return f"visitor_id={ip}; visit_count=1"

def parse_http_request(request_data):
    try:
        lines = request_data.split(b'\r\n')
        request_line = lines[0].decode('utf-8')
        parts = request_line.split(' ')

        if len(parts) != 3:
            return None, None, None, None

        method, path, protocol = parts

        headers = {}
        i = 1
        while i < len(lines) and lines[i] != b'':
            header_line = lines[i].decode('utf-8')
            if ':' in header_line:
                key, value = header_line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
            i += 1

        body = b'\r\n'.join(lines[i+1:]) if i < len(lines) else b''

        return method, path, headers, body
    except Exception as e:
        print(f"Error parsing request: {e}")
        return None, None, None, None

def build_http_response(status_code, status_text, headers=None, body=b'', ip=None):
    response = f"HTTP/1.1 {status_code} {status_text}\r\n"

    if headers is None:
        headers = {}

    headers['Server'] = 'PythonHTTPServer/1.0'
    headers['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    headers['Content-Length'] = str(len(body))

    headers['Access-Control-Allow-Origin'] = '*'
    headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, HEAD, OPTIONS'
    headers['Access-Control-Allow-Headers'] = 'Content-Type'
    headers['Access-Control-Expose-Headers'] = 'Set-Cookie'

    if ip:
        headers['Set-Cookie'] = get_cookie_header(ip)

    for key, value in headers.items():
        response += f"{key}: {value}\r\n"

    response += "\r\n"
    return response.encode() + body

def handle_get(path, include_body=True, ip=None):
    if path == '/' or path == '':
        if os.path.exists('index.html'):
            try:
                with open('index.html', 'rb') as f:
                    content = f.read()

                headers = {
                    'Content-Type': 'text/html; charset=utf-8',
                    'Cache-Control': 'no-cache',
                }

                if include_body:
                    return build_http_response(200, 'OK', headers=headers, body=content, ip=ip)
                else:
                    return build_http_response(200, 'OK', headers=headers, body=b'', ip=ip)
            except Exception as e:
                return build_http_response(500, 'Internal Server Error',
                                          body=f'500 Internal Server Error: {str(e)}'.encode(), ip=ip)
        else:
            return build_http_response(404, 'Not Found', body=b'404 Not Found - index.html not found', ip=ip)

    filepath = os.path.join(UPLOAD_DIR, path.lstrip('/'))

    if '..' in filepath or not filepath.startswith(UPLOAD_DIR):
        return build_http_response(403, 'Forbidden', body=b'403 Forbidden', ip=ip)

    if not os.path.exists(filepath):
        return build_http_response(404, 'Not Found', body=b'404 Not Found', ip=ip)

    if not os.path.isfile(filepath):
        return build_http_response(403, 'Forbidden', body=b'403 Forbidden - Not a file', ip=ip)

    try:
        with open(filepath, 'rb') as f:
            content = f.read()

        content_type = 'application/octet-stream'  # default
        if filepath.endswith('.html') or filepath.endswith('.htm'):
            content_type = 'text/html; charset=utf-8'
        elif filepath.endswith('.css'):
            content_type = 'text/css'
        elif filepath.endswith('.js'):
            content_type = 'application/javascript'
        elif filepath.endswith('.json'):
            content_type = 'application/json'
        elif filepath.endswith('.txt'):
            content_type = 'text/plain'

        headers = {
            'Content-Type': content_type,
            'Cache-Control': 'no-cache',
        }

        if include_body:
            return build_http_response(200, 'OK', headers=headers, body=content, ip=ip)
        else:
            return build_http_response(200, 'OK', headers=headers, body=b'', ip=ip)
    except PermissionError:
        return build_http_response(403, 'Forbidden', body=b'403 Forbidden - Permission denied', ip=ip)
    except Exception as e:
        return build_http_response(500, 'Internal Server Error',
                                  body=f'500 Internal Server Error: {str(e)}'.encode(), ip=ip)

def handle_post(path, body, ip=None):
    filepath = os.path.join(UPLOAD_DIR, path.lstrip('/'))

    if '..' in filepath or not filepath.startswith(UPLOAD_DIR):
        return build_http_response(403, 'Forbidden', body=b'403 Forbidden', ip=ip)

    if os.path.exists(filepath):
        return build_http_response(409, 'Conflict',
                                  body=b'409 Conflict - File already exists. Use PUT to update.', ip=ip)

    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        with open(filepath, 'wb') as f:
            f.write(body)

        return build_http_response(201, 'Created',
                                  body=f'File uploaded successfully to {path}'.encode(), ip=ip)
    except PermissionError:
        return build_http_response(403, 'Forbidden', body=b'403 Forbidden - Permission denied', ip=ip)
    except Exception as e:
        return build_http_response(500, 'Internal Server Error',
                                  body=f'500 Internal Server Error: {str(e)}'.encode(), ip=ip)

def handle_put(path, body, ip=None):
    filepath = os.path.join(UPLOAD_DIR, path.lstrip('/'))

    if '..' in filepath or not filepath.startswith(UPLOAD_DIR):
        return build_http_response(403, 'Forbidden', body=b'403 Forbidden', ip=ip)

    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        with open(filepath, 'wb') as f:
            f.write(body)

        return build_http_response(200, 'OK',
                                  body=f'File updated successfully at {path}'.encode(), ip=ip)
    except PermissionError:
        return build_http_response(403, 'Forbidden', body=b'403 Forbidden - Permission denied', ip=ip)
    except Exception as e:
        return build_http_response(500, 'Internal Server Error',
                                  body=f'500 Internal Server Error: {str(e)}'.encode(), ip=ip)

def handle_download(path, ip=None):
    source_path = os.path.join(UPLOAD_DIR, path.lstrip('/'))
    dest_path = os.path.join(DOWNLOAD_DIR, os.path.basename(path.lstrip('/')))

    if '..' in source_path or not source_path.startswith(UPLOAD_DIR):
        return build_http_response(403, 'Forbidden', body=b'403 Forbidden', ip=ip)

    if not os.path.exists(source_path):
        return build_http_response(404, 'Not Found', body=b'404 Not Found - Source file does not exist', ip=ip)

    if not os.path.isfile(source_path):
        return build_http_response(403, 'Forbidden', body=b'403 Forbidden - Not a file', ip=ip)

    try:
        with open(source_path, 'rb') as f:
            content = f.read()

        with open(dest_path, 'wb') as f:
            f.write(content)

        message = f'File downloaded successfully from {path} to Download/{os.path.basename(dest_path)} ({len(content)} bytes)'
        return build_http_response(200, 'OK', body=message.encode(), ip=ip)
    except PermissionError:
        return build_http_response(403, 'Forbidden', body=b'403 Forbidden - Permission denied', ip=ip)
    except Exception as e:
        return build_http_response(500, 'Internal Server Error',
                                  body=f'500 Internal Server Error: {str(e)}'.encode(), ip=ip)

def handle_client(client_socket, addr):
    ip = addr[0]
    print(f"Connection from {ip}:{addr[1]}")

    try:
        client_socket.settimeout(5.0)

        if check_dos_attack(ip):
            response = build_http_response(429, 'Too Many Requests',
                                          body=b'429 Too Many Requests - DoS protection triggered',
                                          ip=ip)
            client_socket.sendall(response)
            client_socket.close()
            print(f"Connection rejected {ip}:{addr[1]} (DoS)")
            return

        update_visitor(ip)

        request_data = b''
        headers_complete = False
        content_length = 0

        while True:
            try:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break

                request_data += chunk

                if not headers_complete and b'\r\n\r\n' in request_data:
                    headers_complete = True
                    header_end = request_data.index(b'\r\n\r\n')
                    headers_part = request_data[:header_end].decode('utf-8', errors='ignore')

                    if 'content-length:' in headers_part.lower():
                        for line in headers_part.split('\r\n'):
                            if line.lower().startswith('content-length:'):
                                content_length = int(line.split(':')[1].strip())
                                break

                    if content_length == 0:
                        break

                if headers_complete and content_length > 0:
                    header_end = request_data.index(b'\r\n\r\n')
                    body_start = header_end + 4
                    body_received = len(request_data) - body_start

                    if body_received >= content_length:
                        break

            except socket.timeout:
                break
            except Exception as e:
                print(f"Error receiving data: {e}")
                break

        if not request_data:
            print(f"No data received from {ip}:{addr[1]}")
            return

        method, path, headers, body = parse_http_request(request_data)

        if method is None:
            print(f"Bad request from {ip}:{addr[1]}")
            response = build_http_response(400, 'Bad Request', body=b'400 Bad Request', ip=ip)
            client_socket.sendall(response)
            return

        print(f"[{ip}] {method} {path} (visit #{visitors[ip]['count']})")

        if method == 'OPTIONS':
            response = build_http_response(200, 'OK', ip=ip)
        elif method == 'GET':
            response = handle_get(path, include_body=True, ip=ip)
        elif method == 'HEAD':
            response = handle_get(path, include_body=False, ip=ip)
        elif method == 'POST':
            # Check if this is a download request
            if path.startswith('/download/'):
                actual_path = path.replace('/download/', '/', 1)
                response = handle_download(actual_path, ip=ip)
            else:
                response = handle_post(path, body, ip=ip)
        elif method == 'PUT':
            response = handle_put(path, body, ip=ip)
        else:
            response = build_http_response(405, 'Method Not Allowed',
                                          body=b'405 Method Not Allowed', ip=ip)

        client_socket.sendall(response)

    except Exception as e:
        print(f"Error handling client {addr}: {e}")
        import traceback
        traceback.print_exc()
        try:
            response = build_http_response(500, 'Internal Server Error',
                                          body=b'500 Internal Server Error', ip=ip)
            client_socket.sendall(response)
        except:
            pass
    finally:
        try:
            client_socket.close()
        except:
            pass
        print(f"Connection closed {ip}:{addr[1]}")

def main():
    load_visitors()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(100)

    print(f"HTTP Server listening on {HOST}:{PORT}")

    try:
        while True:
            client_socket, addr = server_socket.accept()

            if addr[0] in banned_ips:
                print(f"BANNED IP attempted connection: {addr[0]}")
                client_socket.close()
                continue

            client_thread = threading.Thread(target=handle_client,
                                            args=(client_socket, addr),
                                            daemon=True)
            client_thread.start()
    except KeyboardInterrupt:
        print("\nServer shutting down...")
        save_visitors()
    finally:
        server_socket.close()
        print("Server stopped.")

if __name__ == '__main__':
    main()
