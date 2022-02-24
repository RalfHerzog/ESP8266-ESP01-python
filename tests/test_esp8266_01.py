import logging
import unittest
from typing import List, Dict

from esp8266.esp8266_01 import *

unittest.TestLoader.sortTestMethodsUsing = None


class MyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        logging.basicConfig(level=logging.DEBUG)
        self.esp: Esp8266 = Esp8266.usb()

    def test_attention(self):
        assert self.esp.attention()

    def test_mode(self):
        modes = self.esp.mode()
        assert isinstance(modes, List)
        assert len(modes) > 0
        assert isinstance(modes[0], WifiMode)
        assert modes[0] == WifiMode.CLIENT

        # assert self.esp.mode(Esp8266.WifiMode.CLIENT) is True
        assert self.esp.mode(WifiMode.ACCESS_POINT) is False

    def test_list_aps(self):
        aps = self.esp.list_aps()
        assert isinstance(aps, List)
        assert len(aps) > 0
        for ap in aps:
            assert isinstance(ap, WifiAP)

    def test_version(self):
        version = self.esp.version()
        assert isinstance(version, Dict)
        assert 'AT' in version
        assert 'SDK' in version
        assert 'version' in version
        assert 'date' in version

    def test_reset(self):
        assert self.esp.reset()

    def tearDown(self) -> None:
        ...


if __name__ == '__main__':
    unittest.main()
