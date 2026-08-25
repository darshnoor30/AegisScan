import unittest

from aegisscan.ports import DEFAULT_PORTS, parse_ports


class PortParserTests(unittest.TestCase):
    def test_default_preset(self) -> None:
        self.assertEqual(parse_ports("default"), list(DEFAULT_PORTS))

    def test_ranges_are_sorted_and_deduplicated(self) -> None:
        self.assertEqual(parse_ports("443,80,80,8000-8002"), [80, 443, 8000, 8001, 8002])

    def test_named_preset(self) -> None:
        self.assertIn(443, parse_ports("web"))

    def test_rejects_out_of_range_port(self) -> None:
        with self.assertRaisesRegex(ValueError, "outside"):
            parse_ports("0,80")

    def test_rejects_descending_range(self) -> None:
        with self.assertRaisesRegex(ValueError, "ascending"):
            parse_ports("100-90")

    def test_rejects_oversized_result(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot exceed"):
            parse_ports("1-20", maximum=10)


if __name__ == "__main__":
    unittest.main()

