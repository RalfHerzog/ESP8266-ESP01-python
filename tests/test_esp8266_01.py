import unittest
from itertools import combinations

import pytest as pytest

from esp8266.esp8266_01 import *

unittest.TestLoader.sortTestMethodsUsing = None


class MyTestCase(unittest.TestCase):
    ENABLE_SIDE_EFFECTS = False
    SSID = 'SSID at home'
    PASSWORD = 'MySecurePassword'
    CHANNEL = 6
    ENCRYPTION = WifiEncryption.WPA_WPA2_PSK

    def setUp(self) -> None:
        logging.basicConfig(level=logging.DEBUG)
        self.esp: Esp8266 = Esp8266.usb()

    def test_attention(self):
        assert self.esp.attention()

    def test_version(self):
        version = self.esp.version()
        assert isinstance(version, Dict)
        assert 'AT' in version
        assert 'SDK' in version
        assert 'version' in version
        assert 'date' in version

    def test_reset(self):
        if self.ENABLE_SIDE_EFFECTS:
            assert self.esp.reset()

    def test_deep_sleep(self):
        if self.ENABLE_SIDE_EFFECTS:
            assert self.esp.deep_sleep(1)

    def test_echo(self):
        # Seems to be unsupported
        # assert self.esp.echo(enable=True)
        # assert self.esp.echo(enable=False)
        ...

    def test_mode(self):
        modes = self.esp.mode()
        assert isinstance(modes, List)
        assert len(modes) > 0
        assert isinstance(modes[0], WifiMode)
        assert modes[0] == WifiMode.CLIENT

        # assert self.esp.mode(Esp8266.WifiMode.CLIENT) is True
        assert self.esp.mode(WifiMode.ACCESS_POINT) is False

        with pytest.raises(TypeError):
            self.esp.mode('')

    def test_join(self):
        with pytest.raises(RuntimeError):
            self.esp.join(ssid='Password is missing here')
        with pytest.raises(RuntimeError):
            self.esp.join(password='SSID is missing here')

        if self.ENABLE_SIDE_EFFECTS:
            assert self.esp.join(self.SSID, self.PASSWORD)

    def test_list_aps(self):
        aps: List[WifiAP] = self.esp.list_aps()
        assert isinstance(aps, List)
        assert len(aps) > 0
        for ap in aps:
            assert isinstance(ap, WifiAP)

        if len(aps) > 0:
            aps.sort(key=lambda a: a.rssi, reverse=True)
            ap: WifiAP = aps[0]
            scanned_aps = self.esp.list_aps(ssid=ap.ssid, channel=ap.channel, mac=ap.mac)
            scanned_ap = scanned_aps[0]
            assert scanned_ap.ssid == ap.ssid

    def test_quit(self):
        if self.ENABLE_SIDE_EFFECTS:
            assert self.esp.quit()

    def test_soft_ap(self):
        d = {
            'ssid': self.SSID,
            'password': self.PASSWORD,
            'channel': self.CHANNEL,
            'encryption': self.ENCRYPTION
        }

        for n in range(1, len(d.keys())):
            key_combination_list = list(combinations(d.keys(), n))
            for tpl in key_combination_list:
                d2 = {}
                for k in tpl:
                    d2[k] = d[k]
                with pytest.raises(RuntimeError):
                    self.esp.soft_ap(**d2)

        if self.ENABLE_SIDE_EFFECTS:
            # Seems to be unsupported
            self.esp.soft_ap(
                ssid=self.SSID,
                password=self.PASSWORD,
                channel=self.CHANNEL,
                encryption=self.ENCRYPTION
            )

    def test_list_clients(self):
        if self.esp.soft_ap():
            clients = self.esp.list_clients()
            assert isinstance(clients, List)
            assert len(clients) > 0
            for client in clients:
                assert isinstance(client, WifiClient)

    def test_dhcp(self):
        assert self.esp.dhcp(WifiDHCP.STATION, True)
        # Soft AP seems to be unsupported
        # assert self.esp.dhcp(WifiDHCP.SOFT_AP, False)

    def test_station_mac(self):
        # TODO
        # self.esp.station_mac()
        ...

    def test_soft_ap_mac(self):
        # TODO
        # self.esp.soft_ap_mac()
        ...

    def test_station_ip(self):
        # TODO
        # self.esp.station_ip()
        ...

    def test_soft_ap_ip(self):
        # TODO
        # self.esp.soft_ap_ip()
        ...

    def test_status(self):
        # TODO
        # self.esp.status()
        ...

    def test_connect(self):
        # TODO
        # self.esp.connect()
        ...

    def test__check_send(self):
        # TODO
        # self.esp._check_send()
        ...

    def test_send(self):
        # TODO
        # self.esp.send()
        ...

    def test_receive(self):
        # TODO
        # self.esp.receive()
        ...

    def test_ip_close(self):
        # TODO
        # self.esp.ip_close()
        ...

    def test_ip(self):
        # TODO
        # self.esp.ip()
        ...

    def test_multiplex(self):
        # TODO
        # self.esp.multiplex()
        ...

    def test_server(self):
        # TODO
        # self.esp.server()
        ...

    def test_transfer_mode(self):
        # TODO
        # self.esp.transfer_mode()
        ...

    def test_server_timeout(self):
        # TODO
        # self.esp.server_timeout()
        ...

    def test_execute(self):
        # TODO
        # self.esp.execute()
        ...

    def test__write(self):
        # TODO
        # self.esp._write()
        ...

    def test__write_raw(self):
        # TODO
        # self.esp._write_raw()
        ...

    def test_read_raw(self):
        # TODO
        # self.esp.read_raw()
        ...

    def test_read_lines(self):
        # TODO
        # self.esp.read_lines()
        ...

    def test___trim_lines(self):
        # TODO
        # self.esp.__trim_lines()
        ...

    def test___filter_lines(self):
        # TODO
        # self.esp.__filter_lines()
        ...

    def test___success(self):
        # TODO
        # self.esp.__success()
        ...

    def test___clear_buffer(self):
        # TODO
        # self.esp.__clear_buffer()
        ...

    def test_serve(self):
        # TODO
        # self.esp.serve()
        ...

    def test__check_accept(self):
        # TODO
        # self.esp._check_accept()
        ...

    def test_accept(self):
        # TODO
        # self.esp.accept()
        ...

    def tearDown(self) -> None:
        ...


if __name__ == '__main__':
    unittest.main()
