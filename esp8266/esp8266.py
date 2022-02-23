#!/usr/bin/env python

import re
import time
from enum import Enum
from typing import Optional, List, Dict, Any

import serial


class Esp8266(serial.Serial):
    class WifiMode(Enum):
        CLIENT = 1
        ACCESS_POINT = 2
        BOTH = 3

    class WifiMultiplex(Enum):
        SINGLE = 0
        MULTIPLE = 1

    class WifiEncryption(Enum):
        OPEN = 0
        WEP = 1
        WPA_PSK = 2
        WPA2_PSK = 3
        WPA_WPA2_PSK = 4

    class WifiDHCP(Enum):
        SOFT_AP = 0
        STATION = 1
        BOTH = 2

    class Status(Enum):
        GOT_IP = 2
        CONNECTED = 3
        DISCONNECTED = 4

    class Type(Enum):
        TCP = 'TCP'
        UDP = 'UDP'

    class ServerMode(Enum):
        DELETE = 0
        CREATE = 1

    class TransferMode(Enum):
        NORMAL = 0
        UNVARNISHED = 1

    @staticmethod
    def rpi():
        esp = Esp8266(
            port='/dev/serial0',
            baudrate=115200,
            timeout=1,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS
        )
        esp.__clear_buffer()
        return esp

    @staticmethod
    def usb():
        esp = Esp8266(
            port='/dev/ttyUSB0',
            baudrate=115200,
            timeout=1,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS
        )
        esp.__clear_buffer()
        return esp

    def __init__(self, verbose=True, **kwargs):
        super().__init__(**kwargs)
        self.verbose = verbose

        super().close()
        super().open()

    def attention(self):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT
        return self.__success(self.execute('AT'))

    def reset(self):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+RST
        success = self.__success(self.execute('AT+RST', expect='ready\r\n'))
        # Dummy read. Sometimes there is more data sent
        self.execute('')
        return success

    def version(self):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+GMR
        response = self.execute('AT+GMR')
        versions = {}
        for line in response:
            if line.startswith('AT version:'):
                versions['AT'] = line[len('AT version:'):]
            elif line.startswith('SDK version:'):
                versions['SDK'] = line[len('SDK version:'):]
            else:
                raise RuntimeError(f'Unhandled line "{line}"')
        return versions

    def deep_sleep(self, milliseconds: int):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+GSLP
        return self.__success(self.execute(f'AT+GSLP={milliseconds}'))

    def echo(self, enable: bool):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#ATE
        if enable is None:
            return self.__success(self.execute(f'AT+ATE0'))
        else:
            return self.__success(self.execute(f'AT+ATE1'))

    def mode(self, mode: Optional[WifiMode] = None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWMODE
        if mode:
            if mode not in Esp8266.WifiMode:
                raise RuntimeError(f'Unsupported wifi mode "{str(mode)}"')
            return self.__success(self.execute(f'AT+CWMODE={str(mode)}'))
        else:
            response = self.execute(f'AT+CWMODE?', payload_only=True)
            modes: List[Esp8266.WifiMode] = []
            for line in response:
                if line.startswith('+CWMODE:'):
                    modes.append(Esp8266.WifiMode(int(line[len('+CWMODE:'):])))
                else:
                    raise RuntimeError(f'Unhandled line "{line}"')
            return modes

    def join(self, ssid: Optional[str] = None, password: Optional[str] = None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWJAP
        if ssid is None and password:
            raise RuntimeError(f'Empty ssid')
        if ssid and password is None:
            raise RuntimeError(f'Empty password')
        if ssid and password:
            return self.__success(self.execute(f'AT+CWJAP="{ssid}","{password}"'))
        else:
            response = self.execute(f'AT+CWJAP?')
            if not self.__success(response):
                return False
            for line in response:
                if line.startswith('+CWJAP:'):
                    regex = r"\+CWJAP:\"(?P<wifi>.+)\",\"(?P<mac>[a-z0-9]{2}(:?[a-z0-9]{2}){5})\",(?P<channel>\d+),(?P<signal>-?\d+)"
                    match = re.search(regex, line)
                    return match.groupdict()

    def list_aps(self, ssid: Optional[str] = None, mac: Optional[str] = None, channel: Optional[int] = None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWLAP
        if ssid:
            # Filter list
            response = self.execute(f'AT+CWLAP="{ssid}","{mac if channel else ""}",{channel if channel else 0}')
        else:
            response = self.execute(f'AT+CWLAP')

        if not self.__success(response):
            return False
        for line in response:
            if line.startswith('+CWLAP:'):
                regex = r"\+CWLAP:\((?P<encryption>\d),\"(?P<wifi>.+)\",(?P<rssi>-?\d+),\"(?P<mac>[a-z0-9]{2}(:?[a-z0-9]{2}){5})\",(?P<channel>\d+),(?P<unknown1>-?\d+),(?P<unknown2>\d+)\)"
                match = re.search(regex, line)
                if match:
                    d = match.groupdict()
                    d['encryption'] = Esp8266.WifiEncryption(int(d['encryption']))
                    d['rssi'] = int(d['rssi'])
                    d['channel'] = int(d['channel'])
                    return d
                else:
                    raise RuntimeError(f'Regex mismatch "{line}"')
            else:
                raise RuntimeError(f'Unexpected response "{line}"')
        return False

    def quit(self):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWQAP
        return self.__success(self.execute(f'AT+CWQAP'))

    def soft_ap(self, ssid: Optional[str] = None, password: Optional[str] = None, channel: Optional[int] = None,
                encryption: Optional[WifiEncryption] = None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWSAP
        if ssid and password and channel and encryption:
            return self.__success(self.execute(f'AT+CWSAP="{ssid}","{password}",{channel},{encryption.value}'))
        else:
            response = self.execute(f'AT+CWSAP?')
            if not self.__success(response):
                return False
            for line in response:
                if line.startswith('+CWSAP:'):
                    # Unchecked due to limited capabilities of ESP-01
                    regex = r"\+CWSAP:\"(?P<ssid>.+)\",\"(?P<password>.+)\",(?P<channel>\d+),(?P<encryption>\d)"
                    match = re.search(regex, line)
                    if match:
                        d = match.groupdict()
                        d['encryption'] = Esp8266.WifiEncryption(int(d['encryption']))
                        d['channel'] = int(d['channel'])
                        return d
                else:
                    raise RuntimeError(f'Unexpected response "{line}"')
        return False

    def list_clients(self):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWLIF
        response = self.execute(f'AT+CWLIF?')
        if not self.__success(response):
            return False
        # Unchecked due to limited capabilities of ESP-01
        regex = r"(?P<ip>[0-9]{1,3}(\.[0-9]{1,3}){3}),(?P<unknown>.*)"
        for line in response:
            match = re.search(regex, line)
            if match:
                return match.groupdict()
            else:
                raise RuntimeError(f'Unexpected response "{line}"')

    def dhcp(self, mode: WifiDHCP, enable: bool):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWDHCP
        return self.__success(self.execute(f'AT+CWDHCP={mode.value},{0 if enable else 1}'))

    def station_mac(self, mac: Optional[str] = None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPSTAMAC
        if mac is None:
            response = self.execute(f'AT+CIPSTAMAC?')
            if self.__success(response):
                return response[0][len('+CIPSTAMAC:"'):-1]
        else:
            return self.__success(self.execute(f'AT+CIPSTAMAC="{mac}"'))
        return False

    def soft_ap_mac(self, mac: Optional[str] = None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPAPMAC
        if mac is None:
            response = self.execute(f'AT+CIPAPMAC?')
            if self.__success(response):
                return response[0][len('+CIPAPMAC:"'):-1]
        else:
            return self.__success(self.execute(f'AT+CIPAPMAC="{mac}"'))
        return False

    def station_ip(self, ip: Optional[str] = None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPSTA
        if ip:
            return self.__success(self.execute(f'AT+CIPSTA="{ip}"'))
        else:
            response = self.execute(f'AT+CIPSTA?')
            if not self.__success(response):
                return False
            response = self.__filter_lines(f'AT+CIPSTA?', response, payload_only=True)
            # '+CIPSTA:ip:"0.0.0.0"', '+CIPSTA:gateway:"0.0.0.0"', '+CIPSTA:netmask:"0.0.0.0"'
            d = {}
            for line in response:
                if line.startswith(f'+CIPSTA:ip:"'):
                    d['ip'] = line[len('+CIPSTA:ip:"'):-1]
                elif line.startswith(f'+CIPSTA:gateway:"'):
                    d['gateway'] = line[len('+CIPSTA:gateway:"'):-1]
                elif line.startswith(f'+CIPSTA:netmask:"'):
                    d['netmask'] = line[len('+CIPSTA:netmask:"'):-1]
                else:
                    raise RuntimeError(f'Unexpected response "{line}"')
            return d

    def soft_ap_ip(self, ip: Optional[str] = None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPAP
        if ip:
            return self.__success(self.execute(f'AT+CIPAP="{ip}"'))
        else:
            response = self.execute(f'AT+CIPAP?')
            if not self.__success(response):
                return False
            response = self.__filter_lines(f'AT+CIPAP?', response, payload_only=True)
            # '+CIPSTA:ip:"0.0.0.0"', '+CIPSTA:gateway:"0.0.0.0"', '+CIPSTA:netmask:"0.0.0.0"'
            d = {}
            for line in response:
                if line.startswith(f'+CIPAP:ip:"'):
                    d['ip'] = line[len('+CIPAP:ip:"'):-1]
                elif line.startswith(f'+CIPAP:gateway:"'):
                    d['gateway'] = line[len('+CIPAP:gateway:"'):-1]
                elif line.startswith(f'+CIPAP:netmask:"'):
                    d['netmask'] = line[len('+CIPAP:netmask:"'):-1]
                else:
                    raise RuntimeError(f'Unexpected response "{line}"')
            return d

    def status(self):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPSTATUS
        response = self.execute(f'AT+CIPSTATUS')
        for line in response:
            if line.startswith('STATUS:'):
                status = Esp8266.Status(int(line[len('STATUS:'):]))
                return {'status': status}
            else:
                raise RuntimeError(f'Unexpected response "{line}"')
        return response

    def connect(self, t: Optional[Type] = None, address: Optional[str] = None, port: Optional[int] = None,
                ipd: Optional[int] = None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPSTART
        if t is None and address is None and port is None and ipd is None:
            return self.execute(f'AT+CIPSTART=?', payload_only=True)
        if t and address and port:
            if ipd is None:
                # Single connection
                response = self.execute(f'AT+CIPSTART="{t.value}","{address}",{port}')
            else:
                # Multiplex connection
                response = self.execute(f'AT+CIPSTART={ipd},"{t.value}","{address}",{port}')
            if not self.__success(response) and response[0] != 'ALREADY CONNECTED':
                return False
            return True
        else:
            raise RuntimeError(f't, address and port must not be None')

    @staticmethod
    def _check_send(lines: List[str]):
        for i, line in enumerate(lines):
            if line == 'SEND OK\r\n':  # and len(lines) > i + 1 and lines[i + 1] == '\r\n':
                return True
        return False

    def send(self, data: Optional[str] = None, ipd: Optional[int] = None):
        # def send(self, length: Optional[int] = None, i: Optional[int] = None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPSEND
        if data is None and ipd is None:
            return self.__success(self.execute(f'AT+CIPSEND=?'))
        length = len(data)
        if ipd is None:
            response = self.execute(f'AT+CIPSEND={length}')
        else:
            response = self.execute(f'AT+CIPSEND={ipd},{length}')
        if not self.__success(response):
            raise RuntimeError(f'Error setting send data length')
        if self.verbose:
            print(f'=> Write {length} bytes ...')
        self._write(data)
        self.read_lines(check_end_func=Esp8266._check_send)
        return True

    def receive(self, ipd: Optional[int] = None) -> Dict[str, Any]:
        if ipd:
            response = self.read_lines(check_end_func=lambda lines: lines[0].startswith(f'+IPD,{ipd},'))
        else:
            response = self.read_lines(check_end_func=lambda lines: lines[0].startswith('+IPD,'))
        line = response[0]
        regex = r'\+IPD,(?P<id>\d+)?,?(?P<length>\d+):'
        match = re.search(regex, line)
        if match is None:
            raise RuntimeError(f'regex mismatch "{line}"')
        d = match.groupdict()
        if 'id' in d:
            d['id'] = int(d['id'])
        length = d['length'] = int(d['length'])
        pos = match.span()[1]
        data = line[pos:].encode('ASCII')

        # response = self.read_lines(check_end_func=lambda lines: len(data) + len(''.join(lines)) >= length)
        response = self.read_raw(length - len(data))
        data += response

        d['data'] = data
        return d

    def close(self, ipd: Optional[int] = None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPCLOSE
        if ipd is not None:
            return self.__success(self.execute(f'AT+CIPCLOSE={ipd}'))
        else:
            return self.__success(self.execute(f'AT+CIPCLOSE'))

    def ip(self):
        # +CIFSR:STAIP,"172.16.9.157"
        response = self.execute(f'AT+CIFSR')
        for line in response:
            if line.startswith('+CIFSR:STAIP,"'):
                return line[len('+CIFSR:STAIP,"'):-1]

    def multiplex(self, mode: Optional[WifiMultiplex] = None):
        if mode is None:
            response = self.execute(f'AT+CIPMUX?')
            if not self.__success(response):
                return False
            multiplex_mode = response[0][len('+CIPMUX:'):]
            return Esp8266.WifiMultiplex(int(multiplex_mode))
        if mode not in Esp8266.WifiMultiplex:
            raise RuntimeError(f'Unsupported multiplex mode {mode}')
        return self.__success(self.execute(f'AT+CIPMUX={mode.value}'))

    def server(self, mode: Optional[ServerMode], port: int = 333):
        if self.multiplex() is not Esp8266.WifiMultiplex.MULTIPLE:
            if not self.multiplex(Esp8266.WifiMultiplex.MULTIPLE):
                return False

        if mode is Esp8266.ServerMode.CREATE:
            return self.__success(self.execute(f'AT+CIPSERVER={mode.value},{port}'))
        elif mode is Esp8266.ServerMode.DELETE:
            if self.__success(self.execute(f'AT+CIPSERVER={mode.value}')):
                self.reset()
                return True
            return False
        else:
            raise RuntimeError(f'Unknown server mode "{mode}"')

    def transfer_mode(self, mode: Optional[TransferMode] = None):
        if mode is None:
            response = self.execute(f'AT+CIPMODE?')
            if not self.__success(response):
                return False
            mode = response[0][len('+CIPMODE:'):]
            return Esp8266.TransferMode(int(mode))
        if mode not in Esp8266.TransferMode:
            raise RuntimeError(f'Unknown transfer mode "{mode}"')
        return self.__success(self.execute(f'AT+CIPMODE={mode.value}'))

    def server_timeout(self, seconds: Optional[int] = None):
        if seconds is None:
            response = self.execute(f'AT+CIPSTO?')
            if not self.__success(response):
                return False
            return int(response[0][len('+CIPSTO:'):])
        if seconds < 0:
            raise RuntimeError(f'Server timeout cannot be negative')
        return self.__success(self.execute(f'AT+CIPSTO={seconds}'))

    def execute(self, command: str, expect: Optional[str] = None, payload_only=False) -> List[str]:
        if self.verbose:
            print(f'=> {command}')

        if command != '':
            self._write(command)
        if expect:
            resp_lines = self.read_lines(check_end_func=lambda lines: expect in lines)
        else:
            resp_lines = self.read_lines()
        trimmed_resp_lines = self.__trim_lines(resp_lines)
        filtered_lines = self.__filter_lines(command, trimmed_resp_lines, payload_only=payload_only)

        [print(f'<= {line}') for line in filtered_lines if self.verbose]

        return filtered_lines

    def _write(self, text):
        self._write_raw(f"{text}\r\n")

    def _write_raw(self, text):
        super().write(text.encode('ASCII'))

    def read_raw(self, size: int, timeout: float = 5.0):
        self.timeout = timeout
        data = []
        while size > 0:
            chunk = super().read(size)
            if chunk is None:
                break
            size -= len(chunk)
            data.append(chunk.decode('ASCII'))
        return bytearray(''.join(data).encode('ASCII'))

    def read_lines(self, check_end_func=None, timeout: float = 5.0) -> List[str]:
        lines = []
        while True:
            self.timeout = timeout
            line = super().readline()

            if len(line) == 0:
                if self.verbose:
                    print(f'Timeout waiting for reply')
                break
            try:
                line_decoded = line.decode()
            except UnicodeDecodeError:
                if self.verbose:
                    print(f'Error decode: {line}')
                continue
            lines.append(line_decoded)
            if check_end_func is None:
                if line_decoded == "OK\r\n" or line_decoded == "ERROR\r\n":
                    break
            elif check_end_func(lines):
                break
        return lines

    @staticmethod
    def __trim_lines(lines):
        length = len(lines)
        if length == 0:
            return []

        trimmed_lines = []
        for index in range(length):
            trimmed_lines.append(lines[index].rstrip())
        return trimmed_lines

    @staticmethod
    def __filter_lines(command, lines, payload_only=False) -> List[str]:
        if len(lines) == 0:
            return []

        filtered_lines = []
        for index, line in enumerate(lines):
            if index == 0 and line == command:
                continue
            if len(line) == 0:
                continue
            if payload_only and index == len(lines) - 1 and (line == "OK" or line == "Error"):
                continue
            filtered_lines.append(line)
        return filtered_lines

    @staticmethod
    def __success(lines):
        if len(lines) == 0:
            return False
        return lines[len(lines) - 1] == 'OK'

    def __clear_buffer(self, timeout: float = 1.0):
        verbose = self.verbose
        self.verbose = False
        self.read_lines(timeout=timeout)
        self.verbose = verbose

    def serve(self, server):
        if not isinstance(server.__class__, Esp8266.__Server.__class__):
            raise RuntimeError(f'server must be an instance of {Esp8266.__Server.__class__}')
        server.listen(self)

    @staticmethod
    def _check_accept(lines: List[str]) -> bool:
        if len(lines) < 2:
            return False
        regex = r'^(?P<ipd>\d),(?P<state>CONNECT|CLOSED)\r\n$'
        first_line, second_line = lines[0], lines[1]
        match = re.match(regex, first_line)
        if match and second_line == '\r\n':
            return True
        return False

    def accept(self) -> Optional[int]:
        while True:
            verbose = self.verbose
            self.verbose = False
            lines = self.read_lines(timeout=0, check_end_func=self._check_accept)
            self.verbose = verbose

            if lines:
                if self.verbose:
                    [print(f'<= {line}') for line in lines]
                regex = r'^(?P<ipd>\d),(?P<state>CONNECT|CLOSED)\r\n$'
                first_line = lines[0]
                match = re.match(regex, first_line)
                if match.group('state') == 'CONNECT':
                    return int(match.group('ipd'))
                else:
                    return None

    class __Server:
        def __init__(self, port: int):
            self.verbose = False

            if not isinstance(port, int):
                raise RuntimeError(f'server port must be numeric (int)')

            self.__port = port

        def listen(self, esp):
            if not isinstance(esp, Esp8266):
                raise RuntimeError(f'esp must be an instance of {Esp8266.__class__} but is {esp.__class__}')
            esp.server(Esp8266.ServerMode.CREATE, self.__port)

            while True:
                ipd = esp.accept()
                if ipd is None:
                    continue
                d = esp.receive()
                data = d['data']

                if esp.verbose:
                    print(f'<= {data.decode("ASCII")}')

                response = self.process(data)

                esp.send(response, ipd)
                esp.close(ipd)

        def process(self, data: bytearray):
            raise NotImplementedError('Must be implemented by sub-class')

    class DummyHTTP(__Server):
        def __init__(self, port: int):
            super(Esp8266.DummyHTTP, self).__init__(port)

        def process(self, data: bytearray):
            request = data.decode('ASCII')

            # Header not passed be callback function
            payload = "This is an answer!"
            frame = "HTTP/1.1 200 OK\r\n" \
                    "Server: Pi\r\n" \
                    f"Content-Length: {len(payload)}\r\n" \
                    "\r\n" + payload
            return frame


# x = threading.Thread(target=lambda: {
#     print("Thread")
# })
# x.start()

time.sleep(1)

#
#   Hello World client in Python
#   Connects REQ socket to tcp://localhost:5555
#   Sends "Hello" to server, expects "World" back
#

# import zmq
#
# context = zmq.Context()
#
# #  Socket to talk to server
# print("Connecting to hello world server…")
# socket = context.socket(zmq.REQ)
# socket.connect("inproc://somename")
#
# #  Do 10 requests, waiting each time for a response
# for request in range(10):
#     print("Sending request %s …" % request)
#     socket.send(b"Hello")
#
#     #  Get the reply.
#     message = socket.recv()
#     print("Received reply %s [ %s ]" % (request, message))

# esp8266 = Esp8266.rpi()
esp8266 = Esp8266.usb()


# print(esp8266.mode())
# print(esp8266.list_aps())
# print(esp8266.list_aps("BND"))
# print(esp8266.join())
# print(esp8266.quit())
# print(esp8266.soft_ap())
# print(esp8266.list_clients())
# print(esp8266.dhcp(Esp8266.WifiDHCP.STATION, True))
# print(esp8266.station_mac())
# print(esp8266.station_mac("58:bf:25:dc:79:2f"))
# print(esp8266.soft_ap_mac())
# print(esp8266.soft_ap_mac("58:bf:25:dc:79:2f"))
# print(esp8266.station_ip())
# print(esp8266.station_ip("172.16.9.198"))
# print(esp8266.soft_ap_ip())
# print(esp8266.soft_ap_ip("172.16.9.198"))
# print(esp8266.status())
# print(esp8266.connect())
# print(esp8266.send())
# print(esp8266.connect(Esp8266.Type.TCP, "api.ipify.org", 80))
# query = f'GET / HTTP/1.1\r\nHost: api.ipify.org\r\n\r\n'
# print(esp8266.send(query))
# print(esp8266.receive())
# print(esp8266.close())
# print(esp8266.ip())
# print(esp8266.multiplex())
# print(esp8266.multiplex(Esp8266.WifiMultiplex.SINGLE))
# print(esp8266.server(Esp8266.ServerMode.CREATE))
# print(esp8266.server(Esp8266.ServerMode.DELETE))
# print(esp8266.transfer_mode())
# print(esp8266.transfer_mode(Esp8266.TransferMode.NORMAL))
# print(esp8266.server_timeout())
# print(esp8266.server_timeout(180))


# print(esp8266.reset())

# print(esp8266.attention())
# print(esp8266.version())
# esp8266.mode(Esp8266.WifiMode.CLIENT)
# esp8266.join('IoT', 'bb22f1a57e6a84e0b82d9e58670410f2')
# print(esp8266.get_ip())
# print(esp8266.get_mac())
# print(esp8266.multiplex(Esp8266.WifiMultiplex.MULTIPLE))


def http_handle(request_lines):
    content = "This is an answer!"
    return content


print(esp8266.serve(Esp8266.DummyHTTP(port=80)))

# print(esp8266.http_server(port=80, callback=http_handle))
