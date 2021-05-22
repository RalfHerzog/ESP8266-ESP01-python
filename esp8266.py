#!/usr/bin/env python
import time
import serial
import sys


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

    def __init__(self, verbose=True, **kwargs):
        super().__init__(**kwargs)
        self.verbose = verbose

        super().close()
        super().open()

    def attention(self):
        return self.__success(
            self.__execute('AT')
        )

    def version(self):
        response = self.__execute('AT+GMR')
        versions = {}
        for line in response:
            if line.startswith('AT version:'):
                versions['AT'] = line[len('AT version:'):]
            if line.startswith('SDK version:'):
                versions['SDK'] = line[len('SDK version:'):]
        return versions

    def reset(self):
        return self.__success(
            self.__execute('AT+RST')
        )

    def mode(self, mode):
        if mode not in Esp8266.WifiMode.MODES:
            raise RuntimeError(f'Unsupported wifi mode {str(mode)}')
        return self.__success(
            self.__execute(f'AT+CWMODE={str(mode)}')
        )

    def join(self, ssid, password):
        return self.__success(
            self.__execute(f'AT+CWJAP="{ssid}","{password}"')
        )

    def get_ip(self):
        # +CIFSR:STAIP,"172.16.9.157"
        response = self.__execute(f'AT+CIFSR')
        ip = None
        for line in response:
            if line.startswith('+CIFSR:STAIP,"'):
                ip = line[len('+CIFSR:STAIP,"'):-1]
                break
        return ip

    def get_mac(self):
        # +CIFSR:STAMAC,"18:fe:34:a2:40:3a"
        response = self.__execute(f'AT+CIFSR')
        mac = None
        for line in response:
            if line.startswith('+CIFSR:STAMAC,"'):
                mac = line[len('+CIFSR:STAMAC,"'):-1]
                break
        return mac

    def multiplex(self, mode):
        if mode not in Esp8266.WifiMultiplex.MODES:
            raise RuntimeError(f'Unsupported multiplex mode {str(mode)}')
        return self.__success(
            self.__execute(f'AT+CIPMUX={str(mode)}')
        )

    def http_server(self, port, callback):
        if not isinstance(port, int):
            raise RuntimeError(f'server port must be numeric (int)')
        if callback is None:
            raise RuntimeError(f'callback must be a function')

        self.__execute(f'AT+CIPSERVER=1,{str(port)}')

        while True:
            lines = self.__read_lines(check_end_func=Esp8266.__http_server_check_incoming_connection)

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

            if self.verbose:
                for line in request_lines:
                    sys.stdout.write(f'<= {line}')

            response = callback(request_lines)

            if self.verbose:
                print(f'=> {response}')

            self.__execute(f'AT+CIPSEND={ipd},{len(response)}')

            self.__write(response)
            self.__read_lines(check_end_func=Esp8266.__http_server_check_send)

            self.__write(f'AT+CIPCLOSE={ipd}')
            self.__read_lines(check_end_func=Esp8266.__http_server_check_close)

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

    def __execute(self, command):
        if self.verbose:
            print(f'=> {command}')

        self.__write(command)
        resp_lines = self.__read_lines()
        trimmed_resp_lines = self.__trim_lines(resp_lines)
        filtered_lines = self.__filter_lines(command, trimmed_resp_lines)

        if self.verbose:
            for line in filtered_lines:
                print(f'<= {line}')

        return filtered_lines

    def __write(self, text):
        self.__write_raw(f"{text}\r\n")

    def __write_raw(self, text):
        super().write(text.encode('ASCII'))

    def __read_lines(self, check_end_func=None):
        lines = []
        while True:
            line = super().readline()
            if len(line) == 0:
                time.sleep(1)
                continue
            line_decoded = line.decode()
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


esp8266 = Esp8266.rpi()
print(esp8266.attention())
# print(esp8266.version())
# esp8266.reset()
esp8266.mode(Esp8266.WifiMode.CLIENT)
esp8266.join('IoT', 'bb22f1a57e6a84e0b82d9e58670410f2')
print(esp8266.get_ip())
# print(esp8266.get_mac())
print(esp8266.multiplex(Esp8266.WifiMultiplex.MULTIPLE))


def http_handle(request_lines):
    content = "This is an answer!"
    return "HTTP/1.0 200 OK\r\n" \
           "Server: Pi\r\n" \
           f"Content-Length: {len(content)}\r\n" \
           "\r\n" + content


print(esp8266.http_server(port=80, callback=http_handle))
