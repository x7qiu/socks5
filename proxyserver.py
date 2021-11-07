import logging
import socket
import socketserver
import struct
import select


logging.basicConfig(level=logging.DEBUG)
SOCKS_VERSION = 5

class ThreadedSocksServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True

class Socks5Handler(socketserver.BaseRequestHandler):
    def handle(self):

        methods = self.client_greeting()

        # server choice
        logging.debug(f"client methods: {methods}")
        if 2 in methods:
            chosen_method = 2
        else:
            chosen_method = 0

        self.request.sendall(struct.pack("!BB", SOCKS_VERSION, chosen_method))

        # client authentication
        if chosen_method == 2:
            username, password = self.client_auth()
            self.request.sendall(struct.pack("!BB", 1, 0))

        # client request
        cmd, destination_address, destination_port = self.client_request()

        if cmd == 1:        # TCP CONNECT
            try:
                remote_sock = socket.create_connection((destination_address, destination_port))
                logging.info(f"connecting to {destination_address}, {destination_port}")
            except OSError as e:
                logging.error(e.strerror)

            # TODO: support IPv6
            server_ip, server_port = remote_sock.getsockname()
            logging.debug(f"server_ip: {server_ip}, port: {server_port}")
            self.request.sendall(struct.pack("!BBBB", SOCKS_VERSION, 0, 0, 1) + socket.inet_aton(server_ip) + struct.pack("!H", server_port))
            self.relay_tcp(self.request, remote_sock)
        elif cmd == 2:      # BIND
            pass
        elif cmd == 3:      # UDP ASSOCIATE
            pass
        else:
            logging.error("unsupported CMD")
        # server reply

    def client_greeting(self):
        header = self.request.recv(2)
        version, nmethods = struct.unpack("!BB", header)

        assert version == SOCKS_VERSION
        assert nmethods > 0

        methods_bytes = self.request.recv(nmethods)
        methods = []
        # unpack one byte at a time
        for i in range(nmethods):
            method,  = struct.unpack("!B", methods_bytes[i:i+1])
            methods.append(method)

        return methods

    def client_auth(self):
        # RFC1929 client auth
        version, username_len = struct.unpack("!BB", self.request.recv(2))

        assert version == 1
        assert 0 < username_len < 256

        username = self.request.recv(username_len)
        password_len, = struct.unpack("!B", self.request.recv(1))
        passwd = self.request.recv(password_len)

        return username, passwd

    def client_request(self):
        ver, cmd, rsv, address_type = struct.unpack("!BBBB", self.request.recv(4))
        assert ver == SOCKS_VERSION

        if address_type == 1:       # IPv4
            destination_address = socket.inet_ntop(socket.AF_INET, self.request.recv(4))
        elif address_type == 3:     # FQDN
            FQDN_length, = struct.unpack("!B", self.request.recv(1))
            FQDN = self.request.recv(FQDN_length)
            # TODO: use getadrinfo() to support IPv6
            destination_address = socket.gethostbyname(FQDN)    # IPv4 only
        elif address_type == 4:     # IPv6
            destination_address = socket.inet_ntop(socket.AF_INET6, self.request.recv(16))
        else:
            logging.error("unsupported address type")

        destination_port, = struct.unpack("!H", self.request.recv(2))

        return cmd, destination_address, destination_port

    def relay_tcp(self, local_sock, remote_sock):
        while True:
            readable, writable, exceptional = select.select([local_sock, remote_sock], [], [])

            if local_sock in readable:
                data = local_sock.recv(4096)
                if not data:
                    break
                try:
                    remote_sock.sendall(data)
                except:
                    break

            if remote_sock in readable:
                data = remote_sock.recv(4096)
                if not data:
                    break
                try:
                    local_sock.sendall(data)
                except:
                    break

        local_sock.close()
        remote_sock.close()

if __name__ == "__main__":
    HOST, PORT = "localhost", 9999

    with ThreadedSocksServer((HOST, PORT), Socks5Handler) as server:
        server.serve_forever()
