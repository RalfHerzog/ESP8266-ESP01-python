(Micro)Python connector to ESP8266 ESP-01(S) using AT-Commands via serial UART.

## (Micro)Python ESP8266 ESP-01 AT-driver

This project implements the most important AT commands to drive an ESP8266 ESP-01(S) in python or micropython.

The wireless chip is known for its energy efficient data transmission compared to USB-integrated wifi adapters used by
an operating system. The communication with the chip uses AT commands via a serial line interface (UART). It is
therefore not suitable as a general wifi adapter but very useful in low-energy scenarios like microcontrollers for IoT.

[ESP8266 ESP-01 with usb adapter](img/esp8266 esp-01.jpg "ESP8266 ESP-01 with usb adapter")

#### Example use-case

A non-wifi raspberry pi (version 1+2) or rpi zero (v1.2 + v1.3) which run on battery or low power can use the python
implementation to connect a custom python application to a wireless network. For raspberry pico, an implementation in
[micropython](https://micropython.org/) is available in the
[_micropython_](https://github.com/RalfHerzog/ESP8266-ESP01-python/tree/micropython) branch.

### Features

* [X] Join wireless networks
* [X] Disconnect from wireless network
* [X] TCP-Client
* [X] TCP-Server
* [X] Sample raw TCP server
* [X] Sample raw TCP client
* [X] Sample HTTP server (builds on top of TCP server)
* [X] Sample HTTP client (builds on top of TCP client)

### Sample code

---
HTTP-Client on raspberry pi pico receiving own external ip address

```python
import ulogger
from machine import Pin, UART
from esp8266.esp8266_01 import Esp8266, Type

# Connected to UART1 at GP4 and GP5
uart = UART(1, 115200, tx=Pin(4), rx=Pin(5))

esp = Esp8266(
    log_level=ulogger.DEBUG,
    read_func=uart.read,
    readline_func=lambda: uart.readline() or b'',
    send_func=uart.write,
    # Unfortunately setting timeout for UART after initialization is not possible
    timeout_func=None
)
# Test connection
if esp.attention():
    # Try to connect to remote server
    if esp.connect(t=Type.TCP, address='api.ipify.org', port=80):
        # Send query
        query = f'GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n'
        if esp.send(query):
            # Show response on console
            print(esp.receive()['data'].decode('ASCII'))
        # Close connection if not already done by the server
        esp.ip_close()
```

### TODO

* [ ] Sample mqtt client
* [ ] Check timeout implementation for efficiency (micropython)
* [ ] SSL support for secure data transport
* [ ] Functionality covered by tests (partial)
* [ ] ~~Act as wireless access point (not supported)~~