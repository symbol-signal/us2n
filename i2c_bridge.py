# i2c_bridge.py - I2C to TCP Bridge for ESP32
# Implements SMBus2-compatible remote I2C protocol with raw I2C support

import socket
import time

import machine


class I2CBridge:
    """I2C Bridge class that connects I2C to TCP using SMBus2-compatible protocol"""

    # Command codes
    CMD_READ_BYTE = 0x01
    CMD_WRITE_BYTE = 0x02
    CMD_READ_BYTE_DATA = 0x03
    CMD_WRITE_BYTE_DATA = 0x04
    CMD_READ_WORD_DATA = 0x05
    CMD_WRITE_WORD_DATA = 0x06
    CMD_READ_BLOCK_DATA = 0x07
    CMD_WRITE_BLOCK_DATA = 0x08
    CMD_READ_I2C_BLOCK = 0x09
    CMD_WRITE_I2C_BLOCK = 0x0A
    CMD_READ_RAW = 0x0B  # Raw I2C read (no register)
    CMD_WRITE_RAW = 0x0C  # Raw I2C write (no register)
    CMD_WRITE_READ = 0x0D  # Combined write-then-read with repeated start
    CMD_SCAN = 0x10
    CMD_SET_SPEED = 0x11
    CMD_GET_INFO = 0x12

    # Status codes
    STATUS_OK = 0x00
    STATUS_NACK = 0x01
    STATUS_ERROR = 0x02
    STATUS_INVALID_CMD = 0x03
    STATUS_INVALID_PARAM = 0x04
    STATUS_TIMEOUT = 0x05
    STATUS_BUSY = 0x06

    def __init__(self, config):
        super().__init__()
        self.config = config
        self.i2c = None
        self.tcp = None

        # Import parse_bind_address from main module
        from us2n import parse_bind_address
        self.address = parse_bind_address(config['tcp']['bind'])
        self.bind_port = self.address[1]

        self.client = None
        self.client_address = None
        self.state = 'listening'
        self.cmd_buffer = bytearray()
        self.pending_length = None  # For I2C block reads

        # Initialize I2C
        i2c_config = self.config.get('i2c', {})
        sda_pin = i2c_config.get('sda', 21)
        scl_pin = i2c_config.get('scl', 22)
        freq = i2c_config.get('freq', 400000)
        i2c_id = i2c_config.get('id', 0)

        self.i2c = machine.I2C(
            i2c_id,
            scl=machine.Pin(scl_pin),
            sda=machine.Pin(sda_pin),
            freq=freq
        )
        print(f'I2C initialized on SDA={sda_pin}, SCL={scl_pin}, freq={freq}Hz')

        # Scan for devices
        devices = self.i2c.scan()
        print(f'I2C devices found: {[hex(d) for d in devices]}')
        print(self.config)

    def bind(self):
        """Bind to the configured TCP address and port"""
        tcp = socket.socket()
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.setblocking(True)

        print(f"Binding I2C bridge to address: {self.address}")
        tcp.bind(self.address)
        tcp.listen(5)
        print('I2C Bridge listening at TCP({0})'.format(self.bind_port))

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
        """Handle I/O events on sockets"""
        if fd == self.tcp:
            print("Incoming I2C connection detected...")
            self.close_client()
            self.open_client()
        elif fd == self.client:
            try:
                data = self.recv(self.client, 4096)
                if data:
                    if self.state == 'enterpassword':
                        self._handle_password(data)
                    elif self.state == 'authenticated':
                        self.cmd_buffer.extend(data)
                        try:
                            self._process_commands()
                        except Exception as e:
                            print(f"ERROR in process_commands: {e}")
                            import sys
                            sys.print_exception(e)
                else:
                    print('I2C Client', self.client_address, 'disconnected')
                    self.close_client()
            except Exception as e:
                print(f"Error handling I2C client data: {e}")
                import sys
                sys.print_exception(e)
                self.close_client()

    def _process_commands(self):
        """Process commands from the buffer"""
        while len(self.cmd_buffer) >= 5:  # Minimum command size
            # Parse header
            cmd = self.cmd_buffer[0]
            addr = self.cmd_buffer[1]
            reg = self.cmd_buffer[2]
            data_len = (self.cmd_buffer[3] << 8) | self.cmd_buffer[4]

            # Check if we have the complete command
            if len(self.cmd_buffer) < 5 + data_len:
                break

            # Extract data payload
            data = self.cmd_buffer[5:5 + data_len]

            # Store the requested length for I2C block reads
            if cmd == self.CMD_READ_I2C_BLOCK:
                self.pending_length = data_len

            # Remove processed command from buffer
            self.cmd_buffer = self.cmd_buffer[5 + data_len:]

            try:
                # Process the command - special handling for raw reads
                if cmd == self.CMD_READ_RAW:
                    # For raw reads, the length is passed in the reg field
                    response = self._execute_raw_read(addr, reg)
                else:
                    response = self._execute_command(cmd, addr, reg, data)

                # Send response
                self.sendall(self.client, response)
            except Exception as e:
                print(f"ERROR in _process_commands: {e}")
                import sys
                sys.print_exception(e)
                # Send error response
                error_resp = self._error_response(self.STATUS_ERROR)
                self.sendall(self.client, error_resp)

    def _execute_raw_read(self, addr, length):
        """Execute raw read command"""
        try:
            if length > 32:
                return self._error_response(self.STATUS_INVALID_PARAM)
            buf = bytearray(length)
            #print(f"DEBUG: raw_read addr={hex(addr)}, length={length}")  # Add this
            self.i2c.readfrom_into(addr, buf)
            return self._success_response(buf)
        except OSError as e:
            print(f"I2C error on addr {hex(addr)}: {e}")  # Enhanced
            return self._error_response(self.STATUS_NACK)

    def _execute_command(self, cmd, addr, reg, data):
        """Execute an I2C command and return response"""
        try:
            if cmd == self.CMD_READ_BYTE:
                return self._cmd_read_byte(addr)
            elif cmd == self.CMD_WRITE_BYTE:
                return self._cmd_write_byte(addr, data)
            elif cmd == self.CMD_READ_BYTE_DATA:
                return self._cmd_read_byte_data(addr, reg)
            elif cmd == self.CMD_WRITE_BYTE_DATA:
                return self._cmd_write_byte_data(addr, reg, data)
            elif cmd == self.CMD_READ_WORD_DATA:
                return self._cmd_read_word_data(addr, reg)
            elif cmd == self.CMD_WRITE_WORD_DATA:
                return self._cmd_write_word_data(addr, reg, data)
            elif cmd == self.CMD_READ_BLOCK_DATA:
                return self._cmd_read_block_data(addr, reg)
            elif cmd == self.CMD_WRITE_BLOCK_DATA:
                return self._cmd_write_block_data(addr, reg, data)
            elif cmd == self.CMD_READ_I2C_BLOCK:
                return self._cmd_read_i2c_block(addr, reg)
            elif cmd == self.CMD_WRITE_I2C_BLOCK:
                return self._cmd_write_i2c_block(addr, reg, data)
            elif cmd == self.CMD_WRITE_RAW:
                return self._cmd_write_raw(addr, data)
            elif cmd == self.CMD_WRITE_READ:
                return self._cmd_write_read(addr, reg, data)
            elif cmd == self.CMD_SCAN:
                return self._cmd_scan()
            elif cmd == self.CMD_SET_SPEED:
                return self._cmd_set_speed(data)
            elif cmd == self.CMD_GET_INFO:
                return self._cmd_get_info()
            else:
                return self._error_response(self.STATUS_INVALID_CMD)
        except OSError as e:
            print(f"I2C error: {e}")
            return self._error_response(self.STATUS_NACK)
        except Exception as e:
            print(f"Command execution error: {e}")
            import sys
            sys.print_exception(e)
            return self._error_response(self.STATUS_ERROR)

    def _success_response(self, data=b''):
        """Build a success response"""
        length = len(data)
        return bytes([self.STATUS_OK, (length >> 8) & 0xFF, length & 0xFF]) + data

    def _error_response(self, status):
        """Build an error response"""
        return bytes([status, 0x00, 0x00])

    def _cmd_read_byte_data(self, addr, reg):
        """Read byte from register"""
        #print(f"DEBUG: read_byte_data addr={hex(addr)}, reg={hex(reg)}")  # Add this
        self.i2c.writeto(addr, bytes([reg]))
        buf = bytearray(1)
        self.i2c.readfrom_into(addr, buf)
        return self._success_response(buf)

    def _cmd_write_byte(self, addr, data):
        """Write single byte to device"""
        if len(data) != 1:
            return self._error_response(self.STATUS_INVALID_PARAM)
        self.i2c.writeto(addr, data)
        return self._success_response()

    def _cmd_write_byte_data(self, addr, reg, data):
        """Write byte to register"""
        #print(f"DEBUG: write_byte_data addr={hex(addr)}, reg={hex(reg)}, data={data.hex()}")  # Add this
        if len(data) != 1:
            return self._error_response(self.STATUS_INVALID_PARAM)
        self.i2c.writeto(addr, bytes([reg]) + data)
        return self._success_response()

    def _cmd_write_byte_data(self, addr, reg, data):
        """Write byte to register"""
        if len(data) != 1:
            return self._error_response(self.STATUS_INVALID_PARAM)
        self.i2c.writeto(addr, bytes([reg]) + data)
        return self._success_response()

    def _cmd_read_word_data(self, addr, reg):
        """Read word from register (little-endian)"""
        self.i2c.writeto(addr, bytes([reg]))
        buf = bytearray(2)
        self.i2c.readfrom_into(addr, buf)
        return self._success_response(buf)

    def _cmd_write_word_data(self, addr, reg, data):
        """Write word to register (little-endian)"""
        if len(data) != 2:
            return self._error_response(self.STATUS_INVALID_PARAM)
        self.i2c.writeto(addr, bytes([reg]) + data)
        return self._success_response()

    def _cmd_read_block_data(self, addr, reg):
        """Read SMBus block (first byte is length)"""
        self.i2c.writeto(addr, bytes([reg]))
        # Read length byte first
        length_buf = bytearray(1)
        self.i2c.readfrom_into(addr, length_buf)
        length = length_buf[0]
        if length > 32:
            length = 32
        # Read the rest of the block
        data_buf = bytearray(length)
        self.i2c.readfrom_into(addr, data_buf)
        # Return length byte + data
        return self._success_response(length_buf + data_buf)

    def _cmd_write_block_data(self, addr, reg, data):
        """Write SMBus block"""
        if len(data) > 32:
            return self._error_response(self.STATUS_INVALID_PARAM)
        # Prepend length byte
        self.i2c.writeto(addr, bytes([reg, len(data)]) + data)
        return self._success_response()

    def _cmd_read_i2c_block(self, addr, reg):
        """Read I2C block of specified length"""
        # Use the stored pending_length
        length = min(self.pending_length or 32, 32)
        self.i2c.writeto(addr, bytes([reg]))
        buf = bytearray(length)
        self.i2c.readfrom_into(addr, buf)
        self.pending_length = None  # Clear after use
        return self._success_response(buf)

    def _cmd_write_i2c_block(self, addr, reg, data):
        """Write I2C block"""
        if len(data) > 32:
            return self._error_response(self.STATUS_INVALID_PARAM)
        self.i2c.writeto(addr, bytes([reg]) + data)
        return self._success_response()

    def _cmd_write_raw(self, addr, data):
        """Write raw I2C data without register"""
        #print(f"DEBUG: write_raw addr={hex(addr)}, data={data.hex()}")  # Add this
        if len(data) > 32:
            return self._error_response(self.STATUS_INVALID_PARAM)
        self.i2c.writeto(addr, data)
        return self._success_response()

    def _cmd_write_read(self, addr, read_length, write_data):
        """Combined write-then-read with repeated start"""
        # Note: read_length is passed in the reg field
        if len(write_data) > 32 or read_length > 32:
            return self._error_response(self.STATUS_INVALID_PARAM)

        # MicroPython doesn't have a direct write-then-read method
        # We'll use writeto with stop=False followed by readfrom
        try:
            # Write without stop bit
            self.i2c.writeto(addr, write_data, stop=False)
            # Read with repeated start
            buf = bytearray(read_length)
            self.i2c.readfrom_into(addr, buf)
            return self._success_response(buf)
        except:
            # If stop=False not supported, fall back to regular write then read
            self.i2c.writeto(addr, write_data)
            buf = bytearray(read_length)
            self.i2c.readfrom_into(addr, buf)
            return self._success_response(buf)

    def _cmd_scan(self):
        """Scan I2C bus for devices"""
        #print("DEBUG: I2C scan requested")  # Add this
        devices = self.i2c.scan()
        #print(f"DEBUG: Found devices: {[hex(d) for d in devices]}")  # Add this
        return self._success_response(bytes(devices))

    def _cmd_set_speed(self, data):
        """Set I2C bus speed"""
        if len(data) != 4:
            return self._error_response(self.STATUS_INVALID_PARAM)
        # Extract speed (big-endian)
        speed = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3]
        # Reinitialize I2C with new speed
        i2c_config = self.config.get('i2c', {})
        sda_pin = i2c_config.get('sda', 21)
        scl_pin = i2c_config.get('scl', 22)
        i2c_id = i2c_config.get('id', 0)

        self.i2c = machine.I2C(
            i2c_id,
            scl=machine.Pin(scl_pin),
            sda=machine.Pin(sda_pin),
            freq=speed
        )
        print(f'I2C speed changed to {speed}Hz')
        return self._success_response()

    def _cmd_get_info(self):
        """Get bridge information"""
        info = {
            'version': '1.1',
            'protocol': 'SMBus2',
            'max_block_size': 32,
            'supports_raw': True
        }
        info_str = str(info).encode('utf-8')
        return self._success_response(info_str)

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
                print('Closing I2C client', self.client_address)
                self.client.close()
            except Exception as e:
                print("Error closing client:", e)
            finally:
                self.client = None
                self.client_address = None
                self.cmd_buffer = bytearray()
                self.pending_length = None
        self.state = 'listening'

    def open_client(self):
        """Open and initialize a new client connection"""
        try:
            self.client, self.client_address = self.tcp.accept()
            print('Accepted I2C connection from', self.client_address)

            # Handle SSL if configured
            if 'ssl' in self.config:
                self._setup_client_ssl()

            self.state = 'enterpassword' if 'auth' in self.config else 'authenticated'
            self.password = b""

            if self.state == 'enterpassword':
                self.sendall(self.client, b"password: ")
                print("Prompting for password")
        except Exception as e:
            print("Error opening I2C client:", e)
            import sys
            sys.print_exception(e)
            self.client = None
            self.client_address = None

    def _setup_client_ssl(self):
        """Setup SSL for a client connection"""
        try:
            import ussl
            print("Setting up SSL for I2C client...")

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
                print('Closing I2C TCP server {0}...'.format(self.address))
                self.tcp.close()
            except Exception as e:
                print("Error closing TCP server:", e)
            finally:
                self.tcp = None
