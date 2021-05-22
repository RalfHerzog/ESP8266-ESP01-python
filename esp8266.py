#!/usr/bin/env python
import time
import serial


class Esp8266(serial.Serial):
    class WifiMode:
        CLIENT = 1
        ACCESS_POINT = 2
        BOTH = 3

        MODES = (CLIENT, ACCESS_POINT, BOTH)

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

    def wifi_version(self):
        return self.__success(
            self.__execute('AT+GMR')
        )

    def wifi_reset(self):
        return self.__success(
            self.__execute('AT+RST')
        )

    def wifi_mode(self, mode):
        if mode not in Esp8266.WifiMode.MODES:
            raise RuntimeError(f'Unsupported wifi mode {str(mode)}')
        return self.__success(
            self.__execute(f'AT+CWMODE={str(mode)}')
        )

    def wifi_join(self, ssid, password):
        return self.__success(
            self.__execute(f'AT+CWJAP="{ssid}","{password}"')
        )

    def wifi_get_ip(self):
        # +CIFSR:STAIP,"172.16.9.157"
        response = self.__execute(f'AT+CIFSR')
        ip = None
        for line in response:
            if line.startswith('+CIFSR:STAIP,"'):
                ip = line[len('+CIFSR:STAIP,"'):-1]
                break
        return ip

    def wifi_get_mac(self):
        # +CIFSR:STAMAC,"18:fe:34:a2:40:3a"
        response = self.__execute(f'AT+CIFSR')
        mac = None
        for line in response:
            if line.startswith('+CIFSR:STAMAC,"'):
                mac = line[len('+CIFSR:STAMAC,"'):-1]
                break
        return mac

    def __execute(self, command):
        if self.verbose:
            print("=> " + command)

        self.__write(command)
        resp_lines = self.__read_lines()
        trimmed_resp_lines = self.__trim_lines(resp_lines)
        filtered_lines = self.__filter_lines(command, trimmed_resp_lines)

        if self.verbose:
            for line in filtered_lines:
                print("<= " + line)

        return filtered_lines

    def __write(self, str):
        super().write((str + "\r\n").encode('ASCII'))

    def __read_lines(self):
        lines = []
        while True:
            line = super().readline()
            if len(line) == 0:
                time.sleep(1)
                continue
            line_decoded = line.decode()
            lines.append(line_decoded)
            if line_decoded == "OK\r\n" or line_decoded == "ERROR\r\n":
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
esp8266.attention()
# esp8266.wifi_version()
# esp8266.wifi_reset()
esp8266.wifi_mode(Esp8266.WifiMode.CLIENT)
esp8266.wifi_join('IoT', 'bb22f1a57e6a84e0b82d9e58670410f2')
print(esp8266.wifi_get_ip())
print(esp8266.wifi_get_mac())
