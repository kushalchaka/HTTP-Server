import socket
import sys
import threading
import os
import json
from datetime import datetime

# Configuration
HOST = '0.0.0.0'
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
UPLOAD_DIR = 'Upload'
VISITORS_FILE = 'visitors.json'
DOS_THRESHOLD = 100  # Maximum requests per minute
DOS_WINDOW = 60  # Time window in seconds

# Thread-safe data structures
lock = threading.Lock()
banned_ips = set()
visitors = {}  # Format: {ip: {'count': int, 'last_visit': timestamp}}
request_tracker = {}  # Format: {ip: [timestamp1, timestamp2, ...]}

# banned_ips.add('127.0.0.1')  # Uncomment to ban localhost

# Create Upload directory if it doesn't exist
os.makedirs(UPLOAD_DIR, exist_ok=True)

def load_visitors():
    """Load visitor data from JSON file."""
    global visitors
    try:
        if os.path.exists(VISITORS_FILE):
            with open(VISITORS_FILE, 'r') as f:
                visitors = json.load(f)
            print(f"[*] Loaded {len(visitors)} visitors from {VISITORS_FILE}")
    except Exception as e:
        print(f"[!] Error loading visitors: {e}")
        visitors = {}

def save_visitors():
    """Save visitor data to JSON file."""
    try:
        with open(VISITORS_FILE, 'w') as f:
            json.dump(visitors, f, indent=2)
        print(f"[*] Saved {len(visitors)} visitors to {VISITORS_FILE}")
    except Exception as e:
        print(f"[!] Error saving visitors: {e}")

def check_dos_attack(ip):
    """
    Check if an IP is performing a DoS attack.
    Returns True if IP should be banned, False otherwise.
    """
    global request_tracker, banned_ips

    current_time = datetime.now().timestamp()

    with lock:
        # Initialize tracking for new IPs
        if ip not in request_tracker:
            request_tracker[ip] = []

        # Remove requests older than DOS_WINDOW seconds
        request_tracker[ip] = [
            timestamp for timestamp in request_tracker[ip]
            if current_time - timestamp < DOS_WINDOW
        ]

        # Add current request
        request_tracker[ip].append(current_time)

        # Check if threshold exceeded
        if len(request_tracker[ip]) > DOS_THRESHOLD:
            if ip not in banned_ips:
                banned_ips.add(ip)
                print(f"[!] DoS ATTACK DETECTED! IP {ip} banned ({len(request_tracker[ip])} requests in {DOS_WINDOW}s)")
            return True

        return False

def update_visitor(ip):
    """Update visitor tracking information."""
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
    """Generate Set-Cookie header for visitor tracking."""
    with lock:
        if ip in visitors:
            visit_count = visitors[ip]['count']
            last_visit = visitors[ip]['last_visit']
            return f"visitor_id={ip}; visit_count={visit_count}; last_visit={last_visit}"
    return f"visitor_id={ip}; visit_count=1"

def parse_http_request(request_data):
    """Parse HTTP request and return method, path, headers, and body."""
    try:
        lines = request_data.split(b'\r\n')
        request_line = lines[0].decode('utf-8')
        parts = request_line.split(' ')

        if len(parts) != 3:
            return None, None, None, None

        method, path, protocol = parts

        # Parse headers
        headers = {}
        i = 1
        while i < len(lines) and lines[i] != b'':
            header_line = lines[i].decode('utf-8')
            if ':' in header_line:
                key, value = header_line.split(':', 1)
                headers[key.strip().lower()] = value.strip()
            i += 1

        # Body is everything after the empty line
        body = b'\r\n'.join(lines[i+1:]) if i < len(lines) else b''

        return method, path, headers, body
    except Exception as e:
        print(f"Error parsing request: {e}")
        return None, None, None, None

def build_http_response(status_code, status_text, headers=None, body=b'', ip=None):
    """Build an HTTP response."""
    response = f"HTTP/1.1 {status_code} {status_text}\r\n"

    if headers is None:
        headers = {}

    # Add default headers
    headers['Server'] = 'PythonHTTPServer/1.0'
    headers['Date'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    headers['Content-Length'] = str(len(body))

    # Add cookie for visitor tracking
    if ip:
        headers['Set-Cookie'] = get_cookie_header(ip)

    for key, value in headers.items():
        response += f"{key}: {value}\r\n"

    response += "\r\n"
    return response.encode() + body

def handle_get(path, include_body=True, ip=None):
    """Handle GET and HEAD requests."""
    # Remove leading slash
    filepath = os.path.join(UPLOAD_DIR, path.lstrip('/'))

    # Prevent directory traversal
    if '..' in filepath or not filepath.startswith(UPLOAD_DIR):
        return build_http_response(403, 'Forbidden', body=b'403 Forbidden', ip=ip)

    if not os.path.exists(filepath):
        return build_http_response(404, 'Not Found', body=b'404 Not Found', ip=ip)

    if not os.path.isfile(filepath):
        return build_http_response(403, 'Forbidden', body=b'403 Forbidden - Not a file', ip=ip)

    try:
        with open(filepath, 'rb') as f:
            content = f.read()

        headers = {
            'Content-Type': 'application/octet-stream',
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
    """Handle POST request - upload a new file."""
    filepath = os.path.join(UPLOAD_DIR, path.lstrip('/'))

    # Prevent directory traversal
    if '..' in filepath or not filepath.startswith(UPLOAD_DIR):
        return build_http_response(403, 'Forbidden', body=b'403 Forbidden', ip=ip)

    # Check if file already exists
    if os.path.exists(filepath):
        return build_http_response(409, 'Conflict',
                                  body=b'409 Conflict - File already exists. Use PUT to update.', ip=ip)

    try:
        # Create parent directories if needed
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
    """Handle PUT request - update/replace an existing file."""
    filepath = os.path.join(UPLOAD_DIR, path.lstrip('/'))

    # Prevent directory traversal
    if '..' in filepath or not filepath.startswith(UPLOAD_DIR):
        return build_http_response(403, 'Forbidden', body=b'403 Forbidden', ip=ip)

    try:
        # Create parent directories if needed
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

def handle_client(client_socket, addr):
    """Handle a client connection."""
    ip = addr[0]
    print(f"[+] Connection from {ip}:{addr[1]}")

    try:
        # Check for DoS attack FIRST
        if check_dos_attack(ip):
            response = build_http_response(429, 'Too Many Requests',
                                          body=b'429 Too Many Requests - DoS protection triggered',
                                          ip=ip)
            client_socket.sendall(response)
            client_socket.close()
            print(f"[-] Connection rejected {ip}:{addr[1]} (DoS)")
            return

        # Update visitor tracking
        update_visitor(ip)

        # Receive request
        request_data = b''
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            request_data += chunk
            # Check if we've received the full request
            if b'\r\n\r\n' in request_data:
                # For POST/PUT, we need to check Content-Length
                header_end = request_data.index(b'\r\n\r\n')
                headers_part = request_data[:header_end].decode('utf-8', errors='ignore')

                if 'Content-Length:' in headers_part:
                    for line in headers_part.split('\r\n'):
                        if line.lower().startswith('content-length:'):
                            content_length = int(line.split(':')[1].strip())
                            body_start = header_end + 4
                            body_received = len(request_data) - body_start

                            # Keep receiving until we have the full body
                            while body_received < content_length:
                                chunk = client_socket.recv(4096)
                                if not chunk:
                                    break
                                request_data += chunk
                                body_received = len(request_data) - body_start
                            break
                else:
                    break

        if not request_data:
            return

        # Parse request
        method, path, headers, body = parse_http_request(request_data)

        if method is None:
            response = build_http_response(400, 'Bad Request', body=b'400 Bad Request', ip=ip)
            client_socket.sendall(response)
            return

        print(f"[{ip}] {method} {path} (visit #{visitors[ip]['count']})")

        # Handle different methods
        if method == 'GET':
            response = handle_get(path, include_body=True, ip=ip)
        elif method == 'HEAD':
            response = handle_get(path, include_body=False, ip=ip)
        elif method == 'POST':
            response = handle_post(path, body, ip=ip)
        elif method == 'PUT':
            response = handle_put(path, body, ip=ip)
        else:
            response = build_http_response(405, 'Method Not Allowed',
                                          body=b'405 Method Not Allowed', ip=ip)

        client_socket.sendall(response)

    except Exception as e:
        print(f"[-] Error handling client {addr}: {e}")
        try:
            response = build_http_response(500, 'Internal Server Error',
                                          body=b'500 Internal Server Error', ip=ip)
            client_socket.sendall(response)
        except:
            pass
    finally:
        client_socket.close()
        print(f"[-] Connection closed {ip}:{addr[1]}")

def main():
    """Main server function."""
    # Load visitor data
    load_visitors()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(100)

    print(f"[*] HTTP Server listening on {HOST}:{PORT}")
    print(f"[*] Upload directory: {os.path.abspath(UPLOAD_DIR)}")
    print(f"[*] DoS Protection: {DOS_THRESHOLD} requests per {DOS_WINDOW} seconds")
    print(f"[*] Visitor tracking enabled")

    try:
        while True:
            client_socket, addr = server_socket.accept()

            # Check if IP is manually banned
            if addr[0] in banned_ips:
                print(f"[!] BANNED IP attempted connection: {addr[0]}")
                client_socket.close()
                continue

            # Handle client in a new thread
            client_thread = threading.Thread(target=handle_client,
                                            args=(client_socket, addr),
                                            daemon=True)
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[*] Server shutting down...")
        save_visitors()
    finally:
        server_socket.close()
        print("[*] Server stopped.")

if __name__ == '__main__':
    main()
