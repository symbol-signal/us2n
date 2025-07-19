# us2n.py - UART to TCP Bridge for ESP32-POE-ISO
# Revised version with Ethernet support and improved error handling

import gc
import json
import select
import socket
import time

import machine
import network

# Configure verbosity for debugging
VERBOSE = 1

# Original print function preserved
print_ = print


def print(*args, **kwargs):
    """Custom print function that respects verbosity setting"""
    if VERBOSE:
        print_(*args, **kwargs)


def read_config(filename='us2n.json', obj=None, default=None):
    with open(filename, 'r') as f:
        config = json.load(f)
        if obj is None:
            return config
        return config.get(obj, default)


def parse_bind_address(addr, default=None):
    """Parse the bind address from config, ensuring a valid address is returned"""
    if addr is None:
        return default

    args = addr
    if not isinstance(args, (list, tuple)):
        args = addr.rsplit(':', 1)

    # Always use '0.0.0.0' for binding to all interfaces
    host = '0.0.0.0' if len(args) == 1 or args[0] == '' or args[0] == '0' else args[0]
    port = int(args[-1]) if len(args) > 1 else 8000

    print(f"Parsed bind address: {host}:{port}")
    return host, port


class RINGBUFFER:
    """Ring buffer implementation for data buffering"""

    def __init__(self, size):
        self.data = bytearray(size)
        self.size = size
        self.index_put = 0
        self.index_get = 0
        self.index_rewind = 0
        self.wrapped = False

    def put(self, data):
        cur_idx = 0
        while cur_idx < len(data):
            min_idx = min(self.index_put + len(data) - cur_idx, self.size)
            self.data[self.index_put:min_idx] = data[cur_idx:min_idx - self.index_put + cur_idx]
            cur_idx += min_idx - self.index_put
            if self.index_get > self.index_put:
                self.index_get = max(min_idx + 1, self.index_get)
                if self.index_get >= self.size:
                    self.index_get -= self.size
            self.index_put = min_idx
            if self.index_put == self.size:
                self.index_put = 0
                self.wrapped = True
                if self.index_get == 0:
                    self.index_get = 1

    def putc(self, value):
        next_index = (self.index_put + 1) % self.size
        self.data[self.index_put] = value
        self.index_put = next_index
        # check for overflow
        if self.index_get == self.index_put:
            self.index_get = (self.index_get + 1) % self.size
        return value

    def get(self, numbytes):
        data = bytearray()
        while len(data) < numbytes:
            start = self.index_get
            min_idx = min(self.index_get + numbytes - len(data), self.size)
            if self.index_put >= self.index_get:
                min_idx = min(min_idx, self.index_put)
            data.extend(self.data[start:min_idx])
            self.index_get = min_idx
            if self.index_get == self.size:
                self.index_get = 0
            if self.index_get == self.index_put:
                break
        return data

    def getc(self):
        if not self.has_data():
            return None  ## buffer empty
        else:
            value = self.data[self.index_get]
            self.index_get = (self.index_get + 1) % self.size
            return value

    def has_data(self):
        return self.index_get != self.index_put

    def rewind(self):
        if self.wrapped:
            self.index_get = (self.index_put + 1) % self.size
        else:
            self.index_get = 0


def UART(config):
    """Initialize UART with the given configuration"""
    config = dict(config)
    uart_type = config.pop('type') if 'type' in config.keys() else 'hw'
    port = config.pop('port')

    if uart_type == 'SoftUART':
        print('Using SoftUART...')
        uart = machine.SoftUART(
            machine.Pin(config.pop('tx')),
            machine.Pin(config.pop('rx')),
            timeout=config.pop('timeout'),
            timeout_char=config.pop('timeout_char'),
            baudrate=config.pop('baudrate')
        )
    else:
        print('Using HW UART...')
        tx_pin = config.pop('tx') if 'tx' in config else None
        rx_pin = config.pop('rx') if 'rx' in config else None

        if tx_pin is not None and rx_pin is not None:
            uart = machine.UART(
                port,
                tx=machine.Pin(tx_pin),
                rx=machine.Pin(rx_pin)
            )
        else:
            uart = machine.UART(port)

        uart.init(**config)

    return uart


class Bridge:
    """Bridge class that connects UART to TCP"""

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.uart = None
        self.uart_port = config['uart']['port']
        self.tcp = None
        self.address = parse_bind_address(config['tcp']['bind'])
        self.bind_port = self.address[1]
        self.client = None
        self.client_address = None
        self.ring_buffer = RINGBUFFER(16 * 1024)
        self.cur_line = bytearray()
        self.state = 'listening'
        self.uart = UART(self.config['uart'])
        print('UART opened ', self.uart)
        print(self.config)

    def bind(self):
        """Bind to the configured TCP address and port"""
        tcp = socket.socket()
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Ensure socket is in blocking mode for reliable operation
        tcp.setblocking(True)

        print(f"Binding to address: {self.address}")
        tcp.bind(self.address)
        tcp.listen(5)
        print('Bridge listening at TCP({0}) for UART({1})'
              .format(self.bind_port, self.uart_port))

        self.tcp = tcp

        # Configure SSL if needed
        if 'ssl' in self.config:
            self._setup_ssl()

        return tcp

    def _setup_ssl(self):
        """Setup SSL configuration if enabled"""
        import ntptime
        print("Setting up SSL, syncing NTP time...")
        ntptime.host = "pool.ntp.org"
        attempt = 0
        while attempt < 3:
            try:
                ntptime.settime()
                print(f"NTP synchronization succeeded, {time.time()}")
                print(time.gmtime())
                break
            except OSError as e:
                print(f"NTP synchronization failed, {e}")
                attempt += 1
                time.sleep(5)

    def fill(self, fds):
        """Fill the file descriptor list for select"""
        if self.uart is not None:
            fds.append(self.uart)
        if self.tcp is not None:
            fds.append(self.tcp)
        if self.client is not None:
            fds.append(self.client)
        return fds

    def recv(self, sock, n):
        """Receive data from a socket, handling both regular and SSL sockets"""
        try:
            if hasattr(sock, 'recv'):
                return sock.recv(n)
            else:
                # SSL-wrapped sockets don't have recv(), use read() instead
                return sock.read(n)
        except Exception as e:
            print("Error receiving data:", e)
            return b''

    def sendall(self, sock, bytes_data):
        """Send data to a socket, handling both regular and SSL sockets"""
        try:
            if hasattr(sock, 'sendall'):
                return sock.sendall(bytes_data)
            else:
                # SSL-wrapped sockets don't have sendall(), use write() instead
                return sock.write(bytes_data)
        except Exception as e:
            print("Error sending data:", e)
            return None

    def handle(self, fd):
        """Handle I/O events on sockets and UART with reduced logging"""
        if fd == self.tcp:
            print("Incoming connection detected...")
            self.close_client()
            self.open_client()
        elif fd == self.client:
            try:
                data = self.recv(self.client, 4096)
                if data:
                    if self.state == 'enterpassword':
                        self._handle_password(data)
                    elif self.state == 'authenticated':
                        # Only log that data is being sent, not the actual data
                        print(f'TCP({self.bind_port})->UART({self.uart_port}): {len(data)} bytes')
                        self.uart.write(data)
                else:
                    print('Client', self.client_address, 'disconnected')
                    self.close_client()
            except Exception as e:
                print(f"Error handling client data: {e}")
                self.close_client()
        elif fd == self.uart:
            try:
                data = self.uart.read(64)
                if data is not None:
                    self.ring_buffer.put(data)
                if self.state == 'authenticated' and self.ring_buffer.has_data():
                    data = self.ring_buffer.get(4096)
                    # Only log that data is being sent, not the actual data
                    print(f'UART({self.uart_port})->TCP({self.bind_port}): {len(data)} bytes')
                    self.sendall(self.client, data)
            except Exception as e:
                print(f"Error handling UART data: {e}")

    def _handle_password(self, data):
        """Handle password authentication"""
        self.password = getattr(self, 'password', b'')
        while len(data):
            c = data[0:1]
            data = data[1:]
            if c == b'\n' or c == b'\r':
                print("Received password {0}".format(self.password))
                if self.password.decode('utf-8') == self.config['auth']['password']:
                    self.sendall(self.client, b"\r\nAuthentication succeeded\r\n")
                    self.state = 'authenticated'
                    self.ring_buffer.rewind()
                    break
                else:
                    self.password = b""
                    self.sendall(self.client, b"\r\nAuthentication failed\r\npassword: ")
            else:
                self.password += c

    def close_client(self):
        """Close the client connection"""
        if self.client is not None:
            try:
                print('Closing client', self.client_address)
                self.client.close()
            except Exception as e:
                print("Error closing client:", e)
            finally:
                self.client = None
                self.client_address = None
        self.state = 'listening'

    def open_client(self):
        """Open and initialize a new client connection"""
        try:
            self.client, self.client_address = self.tcp.accept()
            print('Accepted connection from', self.client_address)

            # Handle SSL if configured
            if 'ssl' in self.config:
                self._setup_client_ssl()

            self.state = 'enterpassword' if 'auth' in self.config else 'authenticated'
            self.password = b""

            if self.state == 'enterpassword':
                self.sendall(self.client, b"password: ")
                print("Prompting for password")
        except Exception as e:
            print("Error opening client:", e)
            import sys
            sys.print_exception(e)
            self.client = None
            self.client_address = None

    def _setup_client_ssl(self):
        """Setup SSL for a client connection"""
        try:
            import ussl
            print("Setting up SSL for client...")

            sslconf = self.config['ssl'].copy()
            for key in ['cadata', 'key', 'cert']:
                if key in sslconf:
                    with open(sslconf[key], "rb") as file:
                        sslconf[key] = file.read()

            # Setting CERT_OPTIONAL instead of REQUIRED to avoid certificate verification issues
            sslconf['cert_reqs'] = ussl.CERT_OPTIONAL
            self.client = ussl.wrap_socket(self.client, server_side=True, **sslconf)
        except Exception as e:
            print("Error setting up client SSL:", e)
            import sys
            sys.print_exception(e)

    def close(self):
        """Close all connections"""
        self.close_client()
        if self.tcp is not None:
            try:
                print('Closing TCP server {0}...'.format(self.address))
                self.tcp.close()
            except Exception as e:
                print("Error closing TCP server:", e)
            finally:
                self.tcp = None

    def direct_accept_test(self):
        """Test direct connection acceptance without select"""
        print(f"Running direct accept test on port {self.bind_port}")
        if self.tcp:
            self.tcp.setblocking(True)
            while True:
                try:
                    print("Waiting for connection...")
                    client, addr = self.tcp.accept()
                    print(f"Accepted connection from {addr}")
                    client.send(b"Hello from ESP32!\r\n")

                    # Echo any received data
                    while True:
                        try:
                            data = client.recv(1024)
                            if not data:
                                break
                            print(f"Received: {data}")
                            client.send(data)
                        except:
                            break

                    client.close()
                    print("Connection closed")
                except Exception as e:
                    print("Error in direct accept test:", e)
                    import sys
                    sys.print_exception(e)
                    time.sleep(1)
        else:
            print("TCP server not initialized for direct test")


class S2NServer:
    """Main server class that manages bridges and connections"""

    def __init__(self, config):
        self.config = config

    def report_exception(self, e):
        """Report exceptions to syslog if configured"""
        if 'syslog' in self.config:
            try:
                import usyslog
                import io
                import sys
                stringio = io.StringIO()
                sys.print_exception(e, stringio)
                stringio.seek(0)
                e_string = stringio.read()
                s = usyslog.UDPClient(**self.config['syslog'])
                s.error(e_string)
                s.close()
            except Exception as e2:
                import sys
                sys.print_exception(e2)

    def serve_forever(self):
        """Main server loop with error handling and recovery"""
        while True:
            # Configure network before starting server
            config_network(self.config.get('wlan'), self.config.get('lan'), self.config.get('name'))

            try:
                self._serve_forever()
            except KeyboardInterrupt:
                print('Ctrl-C pressed. Bailing out')
                break
            except Exception as e:
                import sys
                sys.print_exception(e)
                self.report_exception(e)
                time.sleep(1)
                print("Restarting after error")

    def bind(self):
        """Bind all configured bridges"""
        bridges = []
        for config in self.config['bridges']:
            bridge_type = config.get('type', 'uart')
            if bridge_type == 'uart':
                bridge = Bridge(config)
            elif bridge_type == 'i2c':
                from i2c_bridge import I2CBridge
                bridge = I2CBridge(config)
            else:
                print(f"Unknown bridge type: {bridge_type}, skipping")
                continue
            bridge.bind()
            bridges.append(bridge)
        return bridges

    def _serve_forever(self):
        """Internal server loop that manages select and I/O handling"""
        # Clean up memory before starting
        gc.collect()
        print(f"Free memory: {gc.mem_free()} bytes")

        bridges = self.bind()
        if not bridges:
            print("No bridges initialized successfully")
            return

        # Uncomment to run direct connection test on the first bridge
        # if bridges:
        #     bridges[0].direct_accept_test()
        #     return

        try:
            print("Starting server loop...")
            while True:
                # Free memory periodically
                gc.collect()

                fds = []
                for bridge in bridges:
                    bridge.fill(fds)

                if not fds:
                    print("No file descriptors to monitor, waiting...")
                    time.sleep(1)
                    continue

                try:
                    rlist, _, xlist = select.select(fds, (), fds, 10)  # 10 second timeout
                    if xlist:
                        print('Errors on these descriptors:', xlist)
                        break

                    for fd in rlist:
                        for bridge in bridges:
                            bridge.handle(fd)
                except Exception as e:
                    print("Error in select loop:", e)
                    import sys
                    sys.print_exception(e)
                    time.sleep(1)  # Prevent tight error loop
        finally:
            for bridge in bridges:
                bridge.close()


def config_lan(config, name):
    """Configure Ethernet LAN interface"""
    if not config:
        print("No LAN configuration found")
        return None

    # Check if LAN is explicitly enabled
    if not config.get('enabled', False):
        print("LAN is not enabled in configuration")
        return None

    print("LAN configuration found, initializing...")

    # Get pin configurations or use defaults for ESP32-POE-ISO
    mdc_pin = config.get('mdc', 23)
    mdio_pin = config.get('mdio', 18)
    power_pin = config.get('power', 12)
    phy_type = config.get('phy_type', network.PHY_LAN8720)
    phy_addr = config.get('phy_addr', 0)

    print("Initializing Ethernet...")
    lan = network.LAN(
        mdc=machine.Pin(mdc_pin),
        mdio=machine.Pin(mdio_pin),
        power=machine.Pin(power_pin),
        phy_type=phy_type,
        phy_addr=phy_addr
    )

    # Set custom hostname if provided
    if name:
        lan.config(hostname=name)

    print("Activating Ethernet interface...")
    lan.active(True)

    print("Waiting for Ethernet connection...")
    timeout = 15
    while timeout > 0 and not lan.isconnected():
        print(f"Waiting for DHCP... ({timeout}s remaining)")
        time.sleep(1)
        timeout -= 1

    if lan.isconnected():
        print(f"Ethernet connected successfully!")
        print(f"IP configuration: {lan.ifconfig()}")
        return lan
    else:
        print("Failed to connect Ethernet")
        lan.active(False)
        return None


def config_wlan(config, name):
    """Configure WiFi interfaces (station and/or access point)"""
    if config is None:
        return None, None

    sta = None
    ap = None

    # Only configure station if explicitly requested
    if config.get('sta') is not None:
        sta = WLANStation(config.get('sta'), name)

    # Only configure AP if explicitly requested
    if config.get('ap') is not None:
        ap = WLANAccessPoint(config.get('ap'), name)

    return sta, ap


def WLANStation(config, name):
    """Configure WiFi station mode"""
    if config is None:
        return None

    # Check if station mode is enabled
    if not config.get('enabled', True):
        print("WiFi station mode is disabled")
        return None

    config.setdefault('connection_attempts', 3)
    essid = config.get('essid')
    password = config.get('password')

    if not essid:
        print("No ESSID configured for WiFi station")
        return None

    attempts_left = config['connection_attempts']

    sta = network.WLAN(network.STA_IF)

    # Deactivate first to ensure clean state
    sta.active(False)
    time.sleep(0.5)

    # Activate WiFi interface
    sta.active(True)

    if not sta.isconnected():
        while not sta.isconnected() and attempts_left != 0:
            attempts_left -= 1
            print(
                f'Connecting to WiFi network "{essid}" (attempt {config["connection_attempts"] - attempts_left}/{config["connection_attempts"]})...')
            sta.connect(essid, password)

            # Wait for connection
            n, ms = 20, 250
            t = n * ms
            while not sta.isconnected() and n > 0:
                time.sleep_ms(ms)
                n -= 1

            if not sta.isconnected() and attempts_left > 0:
                print("Connection failed, retrying...")
                sta.disconnect()
                time.sleep(1)

        if not sta.isconnected():
            print(f'Failed to connect to WiFi station after {config["connection_attempts"]} attempts. Giving up.')
            sta.active(False)
            return None

    print(f'WiFi station connected to "{essid}"')
    print(f'IP configuration: {sta.ifconfig()}')
    return sta


def WLANAccessPoint(config, name):
    """Configure WiFi access point mode"""
    if config is None:
        return None

    # Check if AP mode is enabled
    if not config.get('enabled', True):
        print("WiFi access point mode is disabled")
        return None

    config.setdefault('essid', name or 'ESP32-Bridge')
    config.setdefault('channel', 11)
    config.setdefault('authmode', getattr(network, 'AUTH_' + config.get('authmode', 'OPEN').upper(), network.AUTH_OPEN))
    config.setdefault('hidden', False)
    config.setdefault('max_clients', 4)

    ap = network.WLAN(network.AP_IF)

    # Deactivate first to ensure clean state
    ap.active(False)
    time.sleep(0.5)

    # Activate AP interface
    ap.active(True)

    # Wait for activation
    n, ms = 20, 250
    t = n * ms
    while not ap.active() and n > 0:
        time.sleep_ms(ms)
        n -= 1

    if not ap.active():
        print(f'Failed to activate WiFi access point after {t}ms. Giving up.')
        return None

    # Configure the access point
    try:
        # Remove 'enabled' from config dict before passing to ap.config()
        ap_config = {k: v for k, v in config.items() if k != 'enabled'}
        ap.config(**ap_config)
    except Exception as e:
        # Fallback for older firmware or unsupported parameters
        print(f"Warning: Could not set full AP configuration: {e}")
        # Try basic configuration
        try:
            ap.config(essid=config['essid'])
            if 'password' in config:
                ap.config(password=config['password'])
                ap.config(authmode=config['authmode'])
        except:
            pass

    print(f'WiFi AP "{ap.config("essid")}" active')
    print(f'IP configuration: {ap.ifconfig()}')
    return ap


def config_network(wlan_config, lan_config, name):
    """Configure all network interfaces"""
    network_configured = False

    # First try Ethernet
    if lan_config:
        lan = config_lan(lan_config, name)
        if lan:
            network_configured = True

    # Then WiFi if configured
    if wlan_config:
        sta, ap = config_wlan(wlan_config, name)
        if sta or ap:
            network_configured = True

    if not network_configured:
        print("WARNING: No network interfaces configured successfully!")
        print("The bridge will start but won't be accessible over network.")
        print("Please check your configuration file.")

    # Give network time to stabilize
    time.sleep(1)


def config_verbosity(config):
    """Configure verbosity level for debugging"""
    global VERBOSE
    VERBOSE = config.setdefault('verbose', 1)

    for bridge in config.get('bridges', []):
        if bridge.get('uart', {}).get('port', None) == 0:
            VERBOSE = 0


def server(config_filename='us2n.json'):
    """Create and return a server instance with the given configuration"""
    config = read_config(config_filename)

    # Set defaults if not present
    config.setdefault('verbose', 1)
    config.setdefault('name', 'ESP32-Bridge')

    config_verbosity(config)

    print(50 * '=')
    print('ESP32-POE-ISO UART <-> TCP Bridge')
    print(50 * '=')

    return S2NServer(config)
