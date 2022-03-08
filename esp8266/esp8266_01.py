#!/usr/bin/env python3
import re
import os
import time
import ulogger


class WifiMode:
    CLIENT = 1
    ACCESS_POINT = 2
    BOTH = 3

    ALL = (CLIENT, ACCESS_POINT, BOTH)


class WifiMultiplex:
    SINGLE = 0
    MULTIPLE = 1

    ALL = (SINGLE, MULTIPLE)


class WifiEncryption:
    OPEN = 0
    WEP = 1
    WPA_PSK = 2
    WPA2_PSK = 3
    WPA_WPA2_PSK = 4

    ALL = (OPEN, WEP, WPA_PSK, WPA2_PSK, WPA_WPA2_PSK)


class WifiDHCP:
    SOFT_AP = 0
    STATION = 1
    BOTH = 2

    ALL = (SOFT_AP, STATION, BOTH)


class Status:
    GOT_IP = 2
    CONNECTED = 3
    DISCONNECTED = 4

    ALL = (GOT_IP, CONNECTED, DISCONNECTED)


class Type:
    TCP = 'TCP'
    UDP = 'UDP'

    ALL = (TCP, UDP)


class ServerMode:
    DELETE = 0
    CREATE = 1
    QUERY = 2

    ALL = (DELETE, CREATE, QUERY)


class TransferMode:
    NORMAL = 0
    UNVARNISHED = 1

    ALL = (NORMAL, UNVARNISHED)


class WifiAP:
    def __init__(self, ssid: str, mac: str, encryption: int, rssi: int, channel: int, *kwargs):
        self.ssid = ssid
        self.mac = mac
        self.encryption = encryption
        self.rssi = rssi
        self.channel = channel
        self.unknown = kwargs


class WifiStation:
    def __init__(self, ssid: str, mac: str, signal: int, channel: int, *kwargs):
        self.ssid = ssid
        self.mac = mac
        self.signal = int(signal)
        self.channel = int(channel)
        self.unknown = kwargs


class WifiClient:
    def __init__(self, ip: str, mac: str = None, unknown=None):
        self.ip = ip
        self.mac = mac
        self.unknown = unknown


class Esp8266:
    def __init__(self, read_func, send_func, readline_func, timeout_func=None, log_level=0):
        self.read_func = read_func
        self.send_func = send_func
        self.readline_func = readline_func
        self.timeout_func = timeout_func
        self.blocking = False

        self.logger = ulogger.Logger(self.__class__.__name__)
        self.logger.level = log_level

        self.clear_buffer()

    def attention(self):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT
        return self.__success(self.execute('AT'))

    def reset(self):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+RST
        success = self.__success(self.execute('AT+RST', expect=b'ready\r\n'), custom_end=b'ready')
        # Dummy read. Sometimes there is more data sent
        self.execute('')
        return success

    def version(self):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+GMR
        response = self.execute('AT+GMR')
        if not self.__success(response):
            return False

        lines = self.__filter_lines('AT+GMR', response)
        versions = {
            'AT': lines[0][len('AT version:'):],
            'SDK': lines[1][len('SDK version:'):],
            'version': lines[2],
            'date': lines[3]
        }
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

    def mode(self, mode=None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWMODE
        if mode is not None:
            if mode not in WifiMode.ALL:
                raise RuntimeError(f'Unsupported wifi mode "{str(mode)}"')
            return self.__success(self.execute(f'AT+CWMODE={str(mode)}'))
        else:
            response = self.execute(f'AT+CWMODE?', payload_only=True)
            modes = []
            for line in response:
                if line.startswith('+CWMODE:'):
                    modes.append(int(line[len('+CWMODE:'):]))
                else:
                    raise RuntimeError(f'Unhandled line "{line}"')
            return modes

    def join(self, ssid=None, password=None, retries=1):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWJAP
        if ssid is None and password:
            raise RuntimeError(f'Empty ssid')
        if ssid and password is None:
            raise RuntimeError(f'Empty password')
        if ssid and password:
            wifi_station = self.join()
            if wifi_station and wifi_station.ssid == ssid:
                return True

            response = self.execute(f'AT+CWJAP="{ssid}","{password}"', sanitized_command=f'AT+CWJAP="{ssid}","XXXXXX"')
            retry = 1
            while retry <= retries and not self.__success(response):
                self.logger.info(f'Retry to connect to wifi {retry}/{retries}')
                time.sleep(1)
                wifi_station = self.join()
                if not wifi_station:
                    response = self.execute(f'AT+CWJAP="{ssid}","{password}"')
                retry += 1
            return self.__success(response)
        else:
            response = self.execute(f'AT+CWJAP?')
            if not self.__success(response):
                return False
            for line in self.__filter_lines('AT+CWJAP?', response):
                if line.startswith('+CWJAP:'):
                    regex = r"\+CWJAP:\"(.+)\",\"([a-z0-9][a-z0-9]:[a-z0-9][a-z0-9]:[a-z0-9][a-z0-9]:[a-z0-9][a-z0-9]:[a-z0-9][a-z0-9]:[a-z0-9][a-z0-9])\",(\d+),(-?\d+)"
                    match = re.search(regex, line)
                    if match is not None:
                        return WifiStation(
                            ssid=match.group(1), mac=match.group(2), channel=match.group(3), signal=match.group(4)
                        )
            return False

    def list_aps(self, ssid=None, mac=None, channel=None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWLAP
        if ssid is not None:
            # Filter list
            response = self.execute(f'AT+CWLAP="{ssid}","{mac if mac else ""}",{channel if channel else 0}')
        else:
            response = self.execute(f'AT+CWLAP')
        if not self.__success(response):
            return False

        aps = []
        for line in self.__filter_lines('+CWLAP', response, payload_only=True):
            if line.startswith('+CWLAP:'):
                regex = r"\+CWLAP:\((\d),\"(.+)\",(-?\d+),\"([a-z0-9][a-z0-9](:?[a-z0-9][a-z0-9])(:?[a-z0-9][a-z0-9])(:?[a-z0-9][a-z0-9])(:?[a-z0-9][a-z0-9])(:?[a-z0-9][a-z0-9]))\",(\d+),(-?\d+)?,(\d+)\)?"
                match = re.search(regex, line)
                if match is not None:
                    aps.append(WifiAP(
                        match.group(2),
                        match.group(4),
                        int(match.group(1)),
                        int(match.group(3)),
                        int(match.group(5)),
                        match.group(6),
                        match.group(7)
                    ))
                else:
                    raise RuntimeError(f'Regex mismatch "{line}"')
            else:
                raise RuntimeError(f'Unexpected response "{line}"')
        return aps

    def quit(self):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWQAP
        return self.__success(self.execute(f'AT+CWQAP'))

    def soft_ap(self, ssid=None, password=None, channel=None, encryption=None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWSAP
        if ssid is not None and password is not None and channel is not None and encryption is not None:
            return self.__success(self.execute(f'AT+CWSAP="{ssid}","{password}",{channel},{encryption}'))
        elif ssid is None and password is None and channel is None and encryption is None:
            response = self.execute(f'AT+CWSAP?')
            if not self.__success(response):
                return False
            for line in response:
                if line.startswith('+CWSAP:'):
                    # Unchecked due to limited capabilities of ESP-01
                    regex = r"\+CWSAP:\"(.+)\",\"(.+)\",(\d+),(\d)"
                    match = re.search(regex, line)
                    if match is not None:
                        d = {
                            'ssid': match.group(1),
                            'password': match.group(2),
                            'channel': int(match.group(3)),
                            'encryption': int(match.group(4))
                        }
                        return d
                else:
                    raise RuntimeError(f'Unexpected response "{line}"')
        else:
            raise RuntimeError(f'Missing argument(s): [ssid, password, channel, encryption]')
        return False

    def list_clients(self):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWLIF
        response = self.execute(f'AT+CWLIF?')
        if not self.__success(response):
            return False
        # Unchecked due to limited capabilities of ESP-01
        regex = r"([0-9]{1,3}(\.[0-9]{1,3})(\.[0-9]{1,3})(\.[0-9]{1,3})),(.+)"

        clients = []
        for line in response:
            match = re.search(regex, line)
            if match is not None:
                clients.append(WifiClient(match.group(1), unknown=match.group(2)))
            else:
                raise RuntimeError(f'Unexpected response "{line}"')
        return clients

    def dhcp(self, mode: int, enable: bool):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWDHCP
        return self.__success(self.execute(f'AT+CWDHCP={mode},{0 if enable else 1}'))

    def station_mac(self, mac=None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPSTAMAC
        if mac is None:
            response = self.execute(f'AT+CIPSTAMAC?')
            if self.__success(response):
                return response[0][len('+CIPSTAMAC:"'):-1]
        else:
            return self.__success(self.execute(f'AT+CIPSTAMAC="{mac}"'))
        return False

    def soft_ap_mac(self, mac=None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPAPMAC
        if mac is None:
            response = self.execute(f'AT+CIPAPMAC?')
            if self.__success(response):
                return response[0][len('+CIPAPMAC:"'):-1]
        else:
            return self.__success(self.execute(f'AT+CIPAPMAC="{mac}"'))
        return False

    def station_ip(self, ip=None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPSTA
        if ip is not None:
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

    def soft_ap_ip(self, ip=None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPAP
        if ip is not None:
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
                status = int(line[len('STATUS:'):])
                return {'status': status}
            else:
                raise RuntimeError(f'Unexpected response "{line}"')
        return response

    def connect(self, t=None, address=None, port=None, ipd=None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPSTART
        if t is None and address is None and port is None and ipd is None:
            return self.execute(f'AT+CIPSTART=?', payload_only=True)
        if t and address and port:
            if ipd is None:
                # Single connection
                response = self.execute(f'AT+CIPSTART="{t}","{address}",{port}')
            else:
                # Multiplex connection
                response = self.execute(f'AT+CIPSTART={ipd},"{t}","{address}",{port}')
            if not self.__success(response) and len(response) > 0 and response[0] != 'ALREADY CONNECTED':
                return False
            return True
        else:
            raise RuntimeError(f't, address and port must not be None')

    @staticmethod
    def _check_send(lines):
        for i, line in enumerate(lines):
            if line == b'SEND OK\r\n':  # and len(lines) > i + 1 and lines[i + 1] == '\r\n':
                return True
            if line == b'SEND FAIL\r\n':
                return False
        return None

    def send(self, data=None, ipd=None, timeout: float = 0.0):
        # def send(self, length = None, i = None):
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

        self.logger.info(f'=> Write {length} bytes ...')
        if isinstance(data, str):
            n_bytes = self.write(data, timeout=timeout)
        elif isinstance(data, (bytes, bytearray)):
            n_bytes = self.write_raw(data, timeout=timeout)
        else:
            raise RuntimeError(f'data type {type(data)} cannot be sent')

        lines = self.read_lines(check_end_func=Esp8266._check_send)
        return Esp8266._check_send(lines)

    def receive(self, ipd=None, timeout=1.0, log_timeout=True):
        if ipd is not None:
            response = self.read_lines(
                timeout=timeout,
                check_end_func=lambda lines: lines[-1].startswith(f'+IPD,{ipd},'.encode()),
                log_timeout=log_timeout
            )
        else:
            response = self.read_lines(
                timeout=timeout,
                check_end_func=lambda lines: lines[-1].startswith('+IPD,'.encode()),
                log_timeout=log_timeout
            )
        if len(response) == 0 or response[-1] == b'+IPD,':
            return {
                'id': None,
                'length': -1,
                'data': None
            }
        line = response[-1]
        if b':' not in line:
            return {
                'id': None,
                'length': len(line),
                'data': line
            }
        line, data = line.split(b':', 1)
        header = line.decode()
        regex = r'^\+IPD,(\d+)(,\d+)?'
        match = re.search(regex, header)
        self.logger.debug(f'Match result is {match} of {regex} against {line}')
        if match is None:
            return False
        n_groups = len(match.groups())
        d = {}
        if n_groups == 3:
            d['id'] = int(match.group(1))
            length = d['length'] = int(match.group(2)[1:])
        else:
            length = d['length'] = int(match.group(1))
        # pos = match.span()[1]
        # data = line[pos:].encode("ASCII")
        # data = line[pos:].encode('unicode_escape')
        self.logger.info(f'<= Received {len(data)} of {length} bytes (start)')

        # response = self.read_lines(check_end_func=lambda lines: len(data) + len(''.join(lines)) >= length)
        remaining_length = length - len(data)
        t = time.time()
        while remaining_length > 0:
            self.logger.info(f'remaining_length: {remaining_length}')
            response = self.read_raw(remaining_length)
            self.logger.info(f'<= Received {len(response)} bytes (continuing)')
            if len(response) == 0 and time.time() - t > timeout:
                break
            remaining_length -= len(response)
            data += response

        if remaining_length != 0:
            self.logger.info(f'Remaining data not received: {remaining_length} bytes')

        d2 = self.receive(ipd=ipd, timeout=1, log_timeout=False)
        if d2 and d2['data'] is not None:
            data += d2['data']

        d['data'] = data
        return d

    def read_raw(self, size: int, timeout: float = 0.5):
        if self.timeout_func is not None:
            self.timeout_func(timeout)
        data = bytearray()
        t = time.time()
        while size > 0 or self.blocking:
            chunk = self.read_func(size)
            if chunk is None:
                if size > 0 and not self.blocking and self.timeout_func is None and (time.time() - t) > timeout:
                    self.logger.warn(f'Timeout waiting for reply')
                    break
                continue
            # https://stackoverflow.com/a/31213916
            # encoded_chunk = self.__bytes_escape(chunk)
            size -= len(chunk)
            [data.append(b) for b in chunk]
            # data.append(chunk)
        # return ''.join([d.decode('UTF-8') for d in data]).encode('UTF-8')
        return data

    @staticmethod
    def __bytes_escape(b):
        return b \
            .decode('string_escape') \
            .replace('\\', '\\\\') \
            .replace('\'', '\\\'') \
            .replace('\"', '\\"') \
            .replace('\a', '\\a') \
            .replace('\b', '\\b') \
            .replace('\f', '\\f') \
            .replace('\n', '\\n') \
            .replace('\r', '\\r') \
            .replace('\t', '\\t') \
            .replace('\v', '\\v') \
            .encode('string_escape')

    def ip_close(self, ipd=None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPCLOSE
        if ipd is not None:
            return self.__success(self.execute(f'AT+CIPCLOSE={ipd}'))
        else:
            return self.__success(self.execute(f'AT+CIPCLOSE'))

    def ip(self):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIFSR
        # +CIFSR:STAIP,"172.16.9.157"
        response = self.execute(f'AT+CIFSR')
        for line in response:
            if line.startswith('+CIFSR:STAIP,"'):
                return line[len('+CIFSR:STAIP,"'):-1]

    def multiplex(self, mode: int = None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPMUX
        if mode is None:
            response = self.execute(f'AT+CIPMUX?')
            if not self.__success(response):
                return False
            multiplex_mode = response[0][len('+CIPMUX:'):]
            return int(multiplex_mode)
        if mode not in WifiMultiplex.ALL:
            raise RuntimeError(f'Unsupported multiplex mode {mode}')
        return self.__success(self.execute(f'AT+CIPMUX={mode}'))

    def server(self, mode: int, port=333):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPSERVER
        if self.multiplex() is not WifiMultiplex.MULTIPLE:
            if not self.multiplex(WifiMultiplex.MULTIPLE):
                return False

        if mode is ServerMode.QUERY:
            return self.__success(self.execute(f'AT+CIPSERVER?'))
        elif mode is ServerMode.CREATE:
            if port is None:
                raise RuntimeError('port needs to be set for server start')
            return self.__success(self.execute(f'AT+CIPSERVER={mode},{port}'))
        elif mode is ServerMode.DELETE:
            if self.__success(self.execute(f'AT+CIPSERVER={mode}')):
                self.reset()
                return True
            return False
        else:
            raise RuntimeError(f'Unknown server mode "{mode}"')

    def transfer_mode(self, mode=None):
        if mode is None:
            response = self.execute(f'AT+CIPMODE?')
            if not self.__success(response):
                return False
            mode = response[0][len('+CIPMODE:'):]
            return int(mode)
        if mode not in TransferMode.ALL:
            raise RuntimeError(f'Unknown transfer mode "{mode}"')
        return self.__success(self.execute(f'AT+CIPMODE={mode}'))

    def server_timeout(self, seconds=None):
        if seconds is None:
            response = self.execute(f'AT+CIPSTO?')
            if not self.__success(response):
                return False
            return int(response[0][len('+CIPSTO:'):])
        if seconds < 0:
            raise RuntimeError(f'Server timeout cannot be negative')
        return self.__success(self.execute(f'AT+CIPSTO={seconds}'))

    def execute(self, command: str, expect=None, payload_only=False, sanitized_command=None):
        self.logger.info(f'=> {sanitized_command or command}')

        if command != '':
            self.write(command)
        if expect is not None:
            resp_lines = self.read_lines(check_end_func=lambda lines: expect in lines)
        else:
            resp_lines = self.read_lines()
        trimmed_resp_lines = self.__trim_lines(resp_lines)
        filtered_lines = self.__filter_lines(command, trimmed_resp_lines, payload_only=payload_only)

        # TODO Change to debug again
        [self.logger.debug(f'<= {line}') for line in filtered_lines]

        return filtered_lines

    def write(self, text, timeout: float = 0.0):
        return self.write_raw(f"{text}\r\n".encode('ASCII'), timeout=timeout)

    def write_raw(self, data: bytes, timeout: float = 0.0):
        n_bytes = self.send_func(data)
        if n_bytes is None:
            self.logger.warn(f'Timeout waiting for send data')
            return None
        if n_bytes != len(data):
            self.logger.error(f'Wrote only {n_bytes} of {len(data)} bytes')
            return n_bytes
        time.sleep(timeout)
        return n_bytes

    def read_lines(self, check_end_func=None, timeout: float = 20.0, log_timeout=True):
        if self.timeout_func is not None:
            self.timeout_func(timeout)
        lines = []
        t = time.time()
        while True:
            line = self.readline_func()
            if len(line) == 0:
                if self.timeout_func is None and (time.time() - t) > timeout:
                    if log_timeout:
                        self.logger.warn(f'Timeout waiting for reply')
                    break
                continue
            lines.append(line)
            if check_end_func is None:
                if line == b"OK\r\n" or line == b"ERROR\r\n":
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
    def __filter_lines(command, lines, payload_only=False):
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

    def __success(self, lines, custom_end=None):
        if len(lines) == 0:
            self.logger.debug(f'Response validation returned [{False}]')
            return False
        success = lines[len(lines) - 1] == b'OK' or (custom_end is not None and lines[len(lines) - 1] == custom_end)
        self.logger.debug(f'Response validation returned [{success}]')
        return success

    def clear_buffer(self, timeout: float = 0.5):
        self.read_lines(timeout=timeout, log_timeout=False)

    def set_blocking(self, blocking):
        self.blocking = blocking

    def serve(self, server):
        if not isinstance(server.__class__, Server.__class__):
            raise RuntimeError(f'server must be an instance of {Server.__class__}')
        server.listen(self)

    @staticmethod
    def _check_accept(lines):
        if len(lines) < 2:
            return None
        regex = r'^(\d),(CONNECT|CLOSED)\r\n$'
        first_line, second_line = lines[0], lines[1]
        match = re.match(regex, first_line)
        if match and second_line == b'\r\n':
            return True
        return False

    def accept(self):
        while True:
            lines = self.read_lines(timeout=0, check_end_func=self._check_accept, log_timeout=False)

            if lines:
                [self.logger.debug(f'<= {line}') for line in lines]
                regex = r'^(\d),(CONNECT|CLOSED)\r\n$'
                first_line = lines[0]
                match = re.match(regex, first_line)
                if match is None:
                    continue
                if match.group(1) == 'CONNECT':
                    return int(match.group(1))
                else:
                    return None


class Server:
    def __init__(self, port: int, log_level=ulogger.INFO, receive_timeout=0.5):
        if not isinstance(port, int):
            raise RuntimeError(f'server port must be numeric (int)')

        self.__port = port
        self.__receive_timeout = receive_timeout
        self.logger = ulogger.Logger(self.__class__.__name__)
        self.logger.level = log_level

    def listen(self, esp):
        if not isinstance(esp, Esp8266):
            raise RuntimeError(f'esp must be an instance of {Esp8266.__class__} but is {esp.__class__}')
        esp.server(ServerMode.DELETE)
        esp.server(ServerMode.CREATE, self.__port)

        while True:
            ipd = esp.accept()
            if ipd is None:
                continue

            try:
                d = esp.receive(timeout=self.__receive_timeout)
            except RuntimeError:
                continue

            if not d or d['length'] == -1:
                self.logger.info(f'No data was sent after accepting connection')
            data: bytearray = d['data']

            if data is not None:
                self.logger.debug(f'<= {data.decode("ASCII")}')

            response = self.process(data)

            esp.send(response, ipd)
            esp.ip_close(ipd)

    def process(self, data: bytearray):
        raise NotImplementedError('Must be implemented by sub-class')


class DummyHTTPServer(Server):
    def __init__(self, port: int):
        super(DummyHTTPServer, self).__init__(port)

    def process(self, data: bytearray):
        request = data.decode('ASCII')

        # Header not passed be callback function
        payload = "This is a reply!"
        frame = "HTTP/1.0 200 OK\r\n" \
                "Server: Pi\r\n" \
                f"Content-Length: {len(payload)}\r\n" \
                "\r\n" + payload
        return frame


class DummyTCPServer(Server):
    def __init__(self, port: int):
        super(DummyTCPServer, self).__init__(port, receive_timeout=0)

    def process(self, data: bytearray):
        response = b'\x88\xd2\xc9\x36\x2e\x3c\x1b\x0f\x30\x84'
        return response


if __name__ == "__main__":
    # esp8266 = Esp8266.rpi()
    esp8266 = Esp8266(
        read_func=None,
        readline_func=None,
        send_func=None,
        timeout_func=None
    )

    # print(esp8266.mode())
    # print(esp8266.list_aps())
    # print(esp8266.list_aps("BND"))
    # print(esp8266.join())
    # print(esp8266.quit())
    # print(esp8266.soft_ap())
    # print(esp8266.list_clients())
    # print(esp8266.dhcp(WifiDHCP.STATION, True))
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
    # print(esp8266.connect(Type.TCP, "api.ipify.org", 80))
    # query = f'GET / HTTP/1.1\r\nHost: api.ipify.org\r\n\r\n'
    # print(esp8266.send(query))
    # print(esp8266.receive())
    # print(esp8266.ip_close())
    # print(esp8266.ip())
    # print(esp8266.multiplex())
    # print(esp8266.multiplex(WifiMultiplex.SINGLE))
    # print(esp8266.server(ServerMode.CREATE))
    # print(esp8266.server(ServerMode.DELETE))
    # print(esp8266.transfer_mode())
    # print(esp8266.transfer_mode(TransferMode.NORMAL))
    # print(esp8266.server_timeout())
    # print(esp8266.server_timeout(180))
    # print(esp8266.reset())
    # print(esp8266.attention())
    # print(esp8266.version())
    # print(esp8266.mode(WifiMode.CLIENT))
    # print(esp8266.join())
    # print(esp8266.join(os.getenv('WIFI_SSID', 'SSID'), os.getenv('WIFI_PASSWORD', 'MySecureWifiPassword')))

    # print(esp8266.serve(DummyHTTPServer(port=80)))
    # print(esp8266.serve(DummyTCP(port=333)))
