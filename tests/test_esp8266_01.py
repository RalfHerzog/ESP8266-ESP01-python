import unittest

from esp8266.esp8266_01 import Esp8266


class MyTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.esp: Esp8266 = Esp8266.usb()
        self.esp.verbose = False

    def test_attention(self):
        assert self.esp.attention()

    def tearDown(self) -> None:
        ...


if __name__ == '__main__':
    unittest.main()
