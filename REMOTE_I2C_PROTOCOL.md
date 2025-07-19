# Remote I2C TCP Protocol Specification

## Overview

This document defines a binary TCP protocol for remote I2C/SMBus communication. The protocol allows clients to perform I2C operations on remote devices over a network connection, using a command structure compatible with the popular Python smbus2 library.

## Protocol Structure

### Request Format

All requests follow this binary structure:

```
[CMD:1][ADDR:1][REG:1][LEN:2][DATA:n]
```

- **CMD** (1 byte): Command code identifying the operation
- **ADDR** (1 byte): I2C device address (7-bit address, right-aligned)
- **REG** (1 byte): Register address (0x00 if not applicable)
- **LEN** (2 bytes, big-endian): Length of data payload
- **DATA** (n bytes): Optional data payload

### Response Format

All responses follow this binary structure:

```
[STATUS:1][LEN:2][DATA:n]
```

- **STATUS** (1 byte): Status code indicating success or error
- **LEN** (2 bytes, big-endian): Length of data payload
- **DATA** (n bytes): Response data (if applicable)

## Command Codes

### SMBus2 Compatible Operations

| Command | Code | Description | smbus2 Equivalent |
|---------|------|-------------|-------------------|
| CMD_READ_BYTE | 0x01 | Read single byte | `read_byte(addr)` |
| CMD_WRITE_BYTE | 0x02 | Write single byte | `write_byte(addr, value)` |
| CMD_READ_BYTE_DATA | 0x03 | Read byte from register | `read_byte_data(addr, register)` |
| CMD_WRITE_BYTE_DATA | 0x04 | Write byte to register | `write_byte_data(addr, register, value)` |
| CMD_READ_WORD_DATA | 0x05 | Read word from register | `read_word_data(addr, register)` |
| CMD_WRITE_WORD_DATA | 0x06 | Write word to register | `write_word_data(addr, register, value)` |
| CMD_READ_BLOCK_DATA | 0x07 | Read block (SMBus block) | `read_block_data(addr, register)` |
| CMD_WRITE_BLOCK_DATA | 0x08 | Write block (SMBus block) | `write_block_data(addr, register, data)` |
| CMD_READ_I2C_BLOCK | 0x09 | Read I2C block | `read_i2c_block_data(addr, register, length)` |
| CMD_WRITE_I2C_BLOCK | 0x0A | Write I2C block | `write_i2c_block_data(addr, register, data)` |

### Extended Operations

| Command | Code | Description |
|---------|------|-------------|
| CMD_SCAN | 0x10 | Scan for I2C devices on the bus |
| CMD_SET_SPEED | 0x11 | Set I2C bus speed (Hz) |
| CMD_GET_INFO | 0x12 | Get bridge information and capabilities |

## Status Codes

| Status | Code | Description |
|--------|------|-------------|
| STATUS_OK | 0x00 | Operation completed successfully |
| STATUS_NACK | 0x01 | No acknowledgment from I2C device |
| STATUS_ERROR | 0x02 | General I2C communication error |
| STATUS_INVALID_CMD | 0x03 | Unknown or unsupported command |
| STATUS_INVALID_PARAM | 0x04 | Invalid parameters for command |
| STATUS_TIMEOUT | 0x05 | I2C operation timed out |
| STATUS_BUSY | 0x06 | I2C bus is busy |

## Command Details

### CMD_READ_BYTE (0x01)
Read a single byte from a device without specifying a register.

**Request:**
- REG: Ignored (set to 0x00)
- LEN: 0x0000
- DATA: None

**Response:**
- LEN: 0x0001
- DATA: Single byte read value

### CMD_WRITE_BYTE (0x02)
Write a single byte to a device without specifying a register.

**Request:**
- REG: Ignored (set to 0x00)
- LEN: 0x0001
- DATA: Single byte to write

**Response:**
- LEN: 0x0000
- DATA: None

### CMD_READ_BYTE_DATA (0x03)
Read a single byte from a specific register.

**Request:**
- REG: Register address
- LEN: 0x0000
- DATA: None

**Response:**
- LEN: 0x0001
- DATA: Single byte read value

### CMD_WRITE_BYTE_DATA (0x04)
Write a single byte to a specific register.

**Request:**
- REG: Register address
- LEN: 0x0001
- DATA: Single byte to write

**Response:**
- LEN: 0x0000
- DATA: None

### CMD_READ_WORD_DATA (0x05)
Read a 16-bit word from a specific register (little-endian).

**Request:**
- REG: Register address
- LEN: 0x0000
- DATA: None

**Response:**
- LEN: 0x0002
- DATA: 16-bit value (little-endian)

### CMD_WRITE_WORD_DATA (0x06)
Write a 16-bit word to a specific register (little-endian).

**Request:**
- REG: Register address
- LEN: 0x0002
- DATA: 16-bit value (little-endian)

**Response:**
- LEN: 0x0000
- DATA: None

### CMD_READ_BLOCK_DATA (0x07)
Read a block of data using SMBus block protocol (first byte is length).

**Request:**
- REG: Register address
- LEN: 0x0000
- DATA: None

**Response:**
- LEN: Number of bytes read (including length byte)
- DATA: Block data (first byte is length, followed by data)

### CMD_WRITE_BLOCK_DATA (0x08)
Write a block of data using SMBus block protocol.

**Request:**
- REG: Register address
- LEN: Number of bytes to write (not including length byte)
- DATA: Data to write (length is prepended automatically)

**Response:**
- LEN: 0x0000
- DATA: None

### CMD_READ_I2C_BLOCK (0x09)
Read a fixed-length block of data using I2C protocol.

**Request:**
- REG: Register address
- LEN: Number of bytes to read (max 32)
- DATA: None

**Response:**
- LEN: Number of bytes read
- DATA: Block data

### CMD_WRITE_I2C_BLOCK (0x0A)
Write a block of data using I2C protocol.

**Request:**
- REG: Register address
- LEN: Number of bytes to write
- DATA: Data to write

**Response:**
- LEN: 0x0000
- DATA: None

### CMD_SCAN (0x10)
Scan the I2C bus for responsive devices.

**Request:**
- ADDR: Ignored (set to 0x00)
- REG: Ignored (set to 0x00)
- LEN: 0x0000
- DATA: None

**Response:**
- LEN: Number of devices found
- DATA: Array of device addresses (1 byte each)

### CMD_SET_SPEED (0x11)
Set the I2C bus clock speed.

**Request:**
- ADDR: Ignored (set to 0x00)
- REG: Ignored (set to 0x00)
- LEN: 0x0004
- DATA: Speed in Hz (32-bit, big-endian)

**Response:**
- LEN: 0x0000
- DATA: None

## Examples

### Example 1: Read Temperature from LM75 (0x48)
```
# Read temperature register (0x00)
Request:  [0x03][0x48][0x00][0x00][0x00]
Response: [0x00][0x00][0x01][0x19]  # 25°C
```

### Example 2: Write Configuration to MCP23017 (0x20)
```
# Write 0xFF to IODIRA register (0x00)
Request:  [0x04][0x20][0x00][0x00][0x01][0xFF]
Response: [0x00][0x00][0x00]  # Success
```

### Example 3: Read 16 bytes from EEPROM (0x50)
```
# Read from address 0x00
Request:  [0x09][0x50][0x00][0x00][0x10]
Response: [0x00][0x00][0x10][...16 bytes of data...]
```

### Example 4: Scan I2C Bus
```
Request:  [0x10][0x00][0x00][0x00][0x00]
Response: [0x00][0x00][0x03][0x20][0x48][0x50]  # Found 3 devices
```

## Implementation Notes

1. **Byte Order**: All multi-byte values use big-endian encoding except where noted (e.g., word data uses little-endian to match SMBus specification)

2. **Timeouts**: Implementations should use reasonable timeouts (e.g., 1 second) for I2C operations

3. **Error Handling**: If an I2C operation fails, return appropriate status code with zero-length data

4. **Maximum Block Size**: Block operations are limited to 32 bytes to ensure compatibility with common I2C hardware

5. **Address Format**: 7-bit I2C addresses are right-aligned in the address byte (bits 6-0)

6. **Connection Model**: The protocol is designed for persistent TCP connections. Clients may keep connections open for multiple operations.

## Security Considerations

This protocol does not include authentication or encryption. For secure deployments:
- Use TLS/SSL for transport encryption
- Implement authentication at the TCP level
- Restrict network access to trusted clients
- Consider implementing command whitelisting for specific devices