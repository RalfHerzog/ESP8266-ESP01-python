#!/usr/bin/env python
import datetime
import re
import sys
import threading
import time
from typing import Optional

import serial


class Esp8266(serial.Serial):
    class WifiMode:
        CLIENT = 1
        ACCESS_POINT = 2
        BOTH = 3

        MODES = (CLIENT, ACCESS_POINT, BOTH)

    class WifiMultiplex:
        SINGLE = 0
        MULTIPLE = 1

        MODES = (SINGLE, MULTIPLE)

    @staticmethod
    def rpi():
        return Esp8266(
            port='/dev/serial0',
            baudrate=115200,
            timeout=1,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS
        )

    @staticmethod
    def usb():
        return Esp8266(
            port='/dev/ttyUSB0',
            baudrate=115200,
            timeout=1,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS
        )

    def __init__(self, verbose=True, **kwargs):
        super().__init__(**kwargs)
        self.verbose = verbose

        super().close()
        super().open()

    def attention(self):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT
        return self.__success(self.execute('AT'))

    def version(self):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+GMR
        response = self.execute('AT+GMR')
        versions = {}
        for line in response:
            if line.startswith('AT version:'):
                versions['AT'] = line[len('AT version:'):]
            if line.startswith('SDK version:'):
                versions['SDK'] = line[len('SDK version:'):]
        return versions

    def reset(self):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+RST
        success = self.__success(self.execute('AT+RST', expect='ready\r\n'))
        # Dummy read
        self.execute('')
        return success

    def mode(self, mode: Optional[WifiMode] = None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWMODE
        if mode:
            if mode not in Esp8266.WifiMode.MODES:
                raise RuntimeError(f'Unsupported wifi mode {str(mode)}')
            return self.__success(self.execute(f'AT+CWMODE={str(mode)}'))
        else:
            return self.execute(f'AT+CWMODE?')

    def join(self, ssid, password):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWJAP
        return self.__success(self.execute(f'AT+CWJAP="{ssid}","{password}"'))

    def get_joined(self):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWJAP?
        response = self.execute(f'AT+CWJAP?')
        if not self.__success(response):
            return False
        for line in response:
            if line.startswith('+CWJAP:'):
                regex = r"\+CWJAP:\"(?P<wifi>.+)\",\"(?P<mac>[a-z0-9]{2}(:?[a-z0-9]{2}){5})\",(?P<channel>\d+),(?P<signal>-?\d+)"
                match = re.search(regex, line)
                return match.groupdict()
        return False

    def list_aps(self):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWLAP
        response = self.execute(f'AT+CWLAP')
        if not self.__success(response):
            return False
        for line in response:
            if line.startswith('+CWLAP:'):
                regex = r"\+CWLAP:\((?P<encryption>\d),\"(?P<wifi>.+)\",(?P<rssi>-?\d+),\"(?P<mac>[a-z0-9]{2}(:?[a-z0-9]{2}){5})\",(?P<channel>\d+),(?P<unknown1>-?\d+),(?P<unknown2>\d+)\)"
                match = re.search(regex, line)
                return match.groupdict()
        return False

    def soft_ap(self, ssid, pwd, channel, encryption):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWSAP
        raise NotImplementedError()

    def list_clients(self, ssid, pwd, channel, encryption):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWLIF
        raise NotImplementedError()

    def dhcp(self, mode, enable):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CWDHCP
        raise NotImplementedError()

    def set_mac(self, mac):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPAPMAC
        raise NotImplementedError()

    def set_station_mac(self, mac):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPSTAMAC
        raise NotImplementedError()

    def set_station_ip(self, ip):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPSTA
        raise NotImplementedError()

    def set_soft_ap_ip(self, ip):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPAP
        raise NotImplementedError()

    def status(self):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPSTATUS
        response = self.execute(f'AT+CIPSTATUS')
        for line in response:
            if line.startswith('STATUS:'):
                return {'status': line[len('STATUS:'):]}
        return response

    def connect(self, type, address, port, id: Optional[int] = None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPSTART
        raise NotImplementedError()

    def send(self, length, id: Optional[int] = None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPSEND
        raise NotImplementedError()

    def close(self, id: Optional[int] = None):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+CIPCLOSE
        if id:
            self.execute(f'AT+CIPCLOSE={id}')
        else:
            self.execute(f'AT+CIPCLOSE')

    def quit(self):
        return self.__success(self.execute(f'AT+CWQAP'))

    def get_ip(self):
        # +CIFSR:STAIP,"172.16.9.157"
        response = self.execute(f'AT+CIFSR')
        ip = None
        for line in response:
            if line.startswith('+CIFSR:STAIP,"'):
                ip = line[len('+CIFSR:STAIP,"'):-1]
                break
        return ip

    def get_mac(self):
        # +CIFSR:STAMAC,"18:fe:34:a2:40:3a"
        response = self.execute(f'AT+CIFSR')
        mac = None
        for line in response:
            if line.startswith('+CIFSR:STAMAC,"'):
                mac = line[len('+CIFSR:STAMAC,"'):-1]
                break
        return mac

    def multiplex(self, mode):
        if mode not in Esp8266.WifiMultiplex.MODES:
            raise RuntimeError(f'Unsupported multiplex mode {str(mode)}')
        return self.__success(self.execute(f'AT+CIPMUX={str(mode)}'))

    def deep_sleep(self, milliseconds: int):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#AT+GSLP
        raise NotImplementedError()

    def echo(self, enable: bool):
        # https://room-15.github.io/blog/2015/03/26/esp8266-at-command-reference/#ATE
        raise NotImplementedError()

    def serve(self, server):
        if not isinstance(server.__class__, Esp8266.Server.__class__):
            raise RuntimeError(f'server must be an instance of {Esp8266.Server.__class__}')
        server.listen(self)

    def execute(self, command: str, expect: Optional[str] = None):
        if self.verbose:
            print(f'=> {command}')

        if command != '':
            self.write(command)
        if expect:
            resp_lines = self.read_lines(check_end_func=lambda lines: expect in lines)
        else:
            resp_lines = self.read_lines()
        trimmed_resp_lines = self.__trim_lines(resp_lines)
        filtered_lines = self.__filter_lines(command, trimmed_resp_lines)

        if self.verbose:
            for line in filtered_lines:
                print(f'<= {line}')

        return filtered_lines

    def write(self, text):
        self.__write_raw(f"{text}\r\n")

    def __write_raw(self, text):
        super().write(text.encode('ASCII'))

    def read_lines(self, check_end_func=None, timeout=5):
        lines = []
        last_empty_line: Optional[datetime.datetime] = None
        while True:
            line = super().readline()
            if len(line) == 0:
                last_empty_line = last_empty_line or datetime.datetime.now()
                time_delta: datetime.timedelta = datetime.datetime.now() - last_empty_line
                if time_delta.total_seconds() >= timeout:
                    print(f'Timeout waiting for reply')
                    break
                time.sleep(0.1)
                continue
            try:
                line_decoded = line.decode()
            except UnicodeDecodeError:
                print(f'Error decode: {line}')
                # raise
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
    def __filter_lines(command, lines):
        if len(lines) == 0:
            return []

        filtered_lines = []
        length = len(lines)
        for index in range(length):
            if index == 0 and lines[index] == command:
                continue
            if index == 1 and len(lines[index]) == 0:
                continue
            filtered_lines.append(lines[index])
        return filtered_lines

    @staticmethod
    def __success(lines):
        if len(lines) == 0:
            return False
        return lines[len(lines) - 1] == 'OK'

    class Server:
        def __init__(self):
            raise RuntimeError('Not instantiable')

        class HTTP:
            def __init__(self, port, callback):
                if not isinstance(port, int):
                    raise RuntimeError(f'server port must be numeric (int)')
                if callback is None:
                    raise RuntimeError(f'callback must be a function')

                self.__port = port
                self.__callback = callback

            def listen(self, esp):
                if not isinstance(esp, Esp8266):
                    raise RuntimeError(f'esp8266 must be an instance of {Esp8266.__class__}')
                esp.execute(f'AT+CIPSERVER=1,{str(self.__port)}')

                while True:
                    lines = esp.read_lines(check_end_func=Esp8266.Server.HTTP.__http_server_check_incoming_connection)

                    # Extract http request
                    request_lines = []
                    ipd = None
                    for line in lines:
                        if line.startswith('+IPD,'):
                            remaining_line = line[len('+IPD,'):]
                            next_comma_pos = remaining_line.find(',')
                            next_colon_pos = remaining_line.find(':')
                            ipd = remaining_line[:next_comma_pos]
                            request_line = remaining_line[next_colon_pos + 1:]
                            request_lines.append(request_line)
                        elif ipd is not None:
                            request_lines.append(line)

                    if esp.verbose:
                        for line in request_lines:
                            sys.stdout.write(f'<= {line}')

                    response = self.__callback(request_lines)

                    if not response.startswith('HTTP/'):
                        # Header not passed be callback function
                        response = "HTTP/1.0 200 OK\r\n" \
                                   "Server: Pi\r\n" \
                                   f"Content-Length: {len(response)}\r\n" \
                                   "\r\n" + response

                    if esp.verbose:
                        print(f'=> {response}')

                    esp.execute(f'AT+CIPSEND={ipd},{len(response)}')

                    esp.write(response)
                    esp.read_lines(check_end_func=Esp8266.Server.HTTP.__http_server_check_send)

                    esp.write(f'AT+CIPCLOSE={ipd}')
                    esp.read_lines(check_end_func=Esp8266.Server.HTTP.__http_server_check_close)

            @staticmethod
            def __http_server_check_incoming_connection(lines):
                ipd_index = None
                for index, line in enumerate(lines):
                    if line.startswith('+IPD,'):
                        ipd_index = index
                    if ipd_index is not None and index > ipd_index and line == "\r\n":
                        return True
                return False

            @staticmethod
            def __http_server_check_send(lines):
                for line in lines:
                    if line == "SEND OK\r\n":
                        return True
                return False

            @staticmethod
            def __http_server_check_close(lines):
                for line in lines:
                    if line == "CLOSE OK\r\n":
                        return True
                    if line == "ERROR\r\n":
                        return True
                return False


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
print(esp8266.status())
print(esp8266.list_aps())
print(esp8266.get_joined())
esp8266.quit()
esp8266.reset()
print(esp8266.attention())
print(esp8266.version())
esp8266.mode(Esp8266.WifiMode.CLIENT)
esp8266.join('IoT', 'bb22f1a57e6a84e0b82d9e58670410f2')
print(esp8266.get_ip())
# print(esp8266.get_mac())
print(esp8266.multiplex(Esp8266.WifiMultiplex.MULTIPLE))


def http_handle(request_lines):
    content = "This is an answer!"
    return content


print(esp8266.serve(Esp8266.Server.HTTP(port=80, callback=http_handle)))

# print(esp8266.http_server(port=80, callback=http_handle))
