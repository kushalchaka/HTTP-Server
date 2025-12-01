import socket
import sys
import os

DOWNLOAD_DIR = 'Download'

os.makedirs(DOWNLOAD_DIR, exist_ok=True)

def build_http_request(method, path, host, body=b''):
    request = f"{method} /{path} HTTP/1.1\r\n"
    request += f"Host: {host}\r\n"
    request += "User-Agent: PythonHTTPClient/1.0\r\n"
    request += "Connection: close\r\n"

    if body:
        request += f"Content-Length: {len(body)}\r\n"

    request += "\r\n"
    return request.encode() + body

def parse_http_response(response_data):
    try:
        header_end = response_data.index(b'\r\n\r\n')
        headers_part = response_data[:header_end].decode('utf-8', errors='ignore')
        body = response_data[header_end + 4:]

        lines = headers_part.split('\r\n')
        status_line = lines[0]

        parts = status_line.split(' ', 2)
        if len(parts) >= 3:
            status_code = int(parts[1])
            status_text = parts[2]
        else:
            status_code = 0
            status_text = 'Unknown'

        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip().lower()] = value.strip()

        return status_code, status_text, headers, body
    except Exception as e:
        print(f"Error parsing response: {e}")
        return 0, 'Parse Error', {}, b''

def send_request(host, port, method, filename, file_content=None):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(5.0)  # 5 second timeout
        client_socket.connect((host, port))
        print(f"[*] Connected to {host}:{port}")

        if method in ['POST', 'PUT']:
            if file_content is None:
                print(f"[-] Error: File content required for {method}")
                return
            request = build_http_request(method, filename, host, body=file_content)
        else:
            request = build_http_request(method, filename, host)

        client_socket.sendall(request)
        print(f"[*] Sent {method} request for /{filename}")

        response_data = b''
        content_length = None
        headers_received = False

        while True:
            try:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                response_data += chunk

                if not headers_received and b'\r\n\r\n' in response_data:
                    headers_received = True
                    header_end = response_data.index(b'\r\n\r\n')
                    headers_part = response_data[:header_end].decode('utf-8', errors='ignore')

                    for line in headers_part.split('\r\n'):
                        if line.lower().startswith('content-length:'):
                            content_length = int(line.split(':')[1].strip())
                            break

                if headers_received and content_length is not None:
                    header_end = response_data.index(b'\r\n\r\n')
                    body_received = len(response_data) - (header_end + 4)
                    if body_received >= content_length:
                        break

            except socket.timeout:
                break

        client_socket.close()

        status_code, status_text, headers, body = parse_http_response(response_data)

        print(f"\n[*] Response: {status_code} {status_text}")
        print("[*] Headers:")
        for key, value in headers.items():
            print(f"    {key}: {value}")

        return status_code, status_text, headers, body

    except ConnectionRefusedError:
        print(f"[-] Error: Connection refused. Is the server running on {host}:{port}?")
        return None, None, None, None
    except socket.timeout:
        print(f"[-] Error: Connection timed out")
        return None, None, None, None
    except Exception as e:
        print(f"[-] Error: {e}")
        return None, None, None, None

def handle_get(host, port, filename):
    status_code, status_text, headers, body = send_request(host, port, 'GET', filename)

    if status_code == 200:
        filepath = os.path.join(DOWNLOAD_DIR, os.path.basename(filename))

        try:
            with open(filepath, 'wb') as f:
                f.write(body)
            print(f"\n[+] File saved to: {filepath}")
            print(f"[+] Size: {len(body)} bytes")
        except Exception as e:
            print(f"[-] Error saving file: {e}")
    else:
        print(f"\n[*] Response body:")
        print(body.decode('utf-8', errors='ignore'))

def handle_head(host, port, filename):
    status_code, status_text, headers, body = send_request(host, port, 'HEAD', filename)

    if body:
        print(f"\n[*] Note: Server sent {len(body)} bytes in body (should be empty for HEAD)")

def handle_post(host, port, filename):
    filepath = os.path.join(DOWNLOAD_DIR, os.path.basename(filename))

    if not os.path.exists(filepath):
        print(f"[-] Error: File not found: {filepath}")
        return

    try:
        with open(filepath, 'rb') as f:
            file_content = f.read()

        print(f"[*] Uploading file: {filepath} ({len(file_content)} bytes)")
        status_code, status_text, headers, body = send_request(host, port, 'POST',
                                                               filename, file_content)

        if body:
            print(f"\n[*] Response body:")
            print(body.decode('utf-8', errors='ignore'))

    except Exception as e:
        print(f"[-] Error reading file: {e}")

def handle_put(host, port, filename):
    filepath = os.path.join(DOWNLOAD_DIR, os.path.basename(filename))

    if not os.path.exists(filepath):
        print(f"[-] Error: File not found: {filepath}")
        return

    try:
        with open(filepath, 'rb') as f:
            file_content = f.read()

        print(f"[*] Updating file: {filepath} ({len(file_content)} bytes)")
        status_code, status_text, headers, body = send_request(host, port, 'PUT',
                                                               filename, file_content)

        if body:
            print(f"\n[*] Response body:")
            print(body.decode('utf-8', errors='ignore'))

    except Exception as e:
        print(f"[-] Error reading file: {e}")

def print_usage():
    print("Usage: python client.py <serverHost> <serverPort> <filename> <command> [options]")
    print("\nCommands:")
    print("  GET  - Download file from server to Download/")
    print("  HEAD - Get file headers only (no body)")
    print("  POST - Upload new file from Download/ to server")
    print("  PUT  - Update existing file from Download/ to server")
    print("\nOptions:")
    print("  -d <count>  - DoS test mode: send <count> rapid requests")
    print("\nExamples:")
    print("  python client.py localhost 8080 test.txt GET")
    print("  python client.py 127.0.0.1 8080 data.bin POST")
    print("  python client.py localhost 8080 test.txt GET -d 200  # DoS test with 200 requests")

def dos_test(host, port, filename, count):
    print(f"[*] Starting DoS test: {count} rapid GET requests to {host}:{port}")
    print(f"[*] Target file: {filename}")
    print()

    import time
    start_time = time.time()
    success_count = 0
    banned = False

    for i in range(count):
        try:
            status_code, status_text, headers, body = send_request(host, port, 'GET', filename)

            if status_code == 200:
                success_count += 1
                print(f"[{i+1}/{count}] Success: 200 OK")
            elif status_code == 429:
                print(f"[{i+1}/{count}] BANNED: 429 Too Many Requests")
                banned = True
                break
            else:
                print(f"[{i+1}/{count}] Response: {status_code} {status_text}")
        except Exception as e:
            print(f"[{i+1}/{count}] Error: {e}")

    end_time = time.time()
    elapsed = end_time - start_time

    print(f"\n[*] DoS Test Results:")
    print(f"    Total requests: {count}")
    print(f"    Successful: {success_count}")
    print(f"    Time elapsed: {elapsed:.2f} seconds")
    print(f"    Requests/second: {count/elapsed:.2f}")

    if banned:
        print(f"    Status: IP BANNED by server DoS protection")
    else:
        print(f"    Status: No ban detected")

def main():
    if len(sys.argv) < 5:
        print_usage()
        sys.exit(1)

    host = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print("[-] Error: Port must be a number")
        sys.exit(1)

    filename = sys.argv[3]
    command = sys.argv[4].upper()

    dos_mode = False
    dos_count = 0
    if len(sys.argv) >= 7 and sys.argv[5] == '-d':
        dos_mode = True
        try:
            dos_count = int(sys.argv[6])
        except ValueError:
            print("[-] Error: DoS count must be a number")
            sys.exit(1)

    if dos_mode:
        dos_test(host, port, filename, dos_count)
        return

    print(f"[*] Client starting...")
    print(f"[*] Server: {host}:{port}")
    print(f"[*] File: {filename}")
    print(f"[*] Command: {command}")
    print()

    if command == 'GET':
        handle_get(host, port, filename)
    elif command == 'HEAD':
        handle_head(host, port, filename)
    elif command == 'POST':
        handle_post(host, port, filename)
    elif command == 'PUT':
        handle_put(host, port, filename)
    else:
        print(f"[-] Error: Unknown command '{command}'")
        print_usage()
        sys.exit(1)

if __name__ == '__main__':
    main()
