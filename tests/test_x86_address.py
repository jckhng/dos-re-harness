"""Synthetic selector and DOSBox-X breakpoint contracts; no game data."""
import unittest

from dos_re_harness.remote_protocol import RspClient


def descriptor(base, limit, access=0x92, flags=0x40):
    return bytes((limit & 255, (limit >> 8) & 255, base & 255,
                  (base >> 8) & 255, (base >> 16) & 255, access,
                  ((limit >> 16) & 15) | flags, (base >> 24) & 255))


class AddressTests(unittest.TestCase):
    def test_selector_base_replaces_real_mode_arithmetic(self):
        from dos_re_harness.x86_address import decode_gdt_segment
        table = bytes(8) + descriptor(0x12340000, 0x23456)
        segment = decode_gdt_segment(table, 8)
        self.assertEqual(segment.base, 0x12340000)
        self.assertEqual(segment.limit, 0x23456)
        self.assertTrue(segment.default_32)
        self.assertEqual(segment.address(0x12345, 16), 0x12352345)
        self.assertEqual(decode_gdt_segment(table, 11).base, segment.base)

    def test_page_granularity_and_code_descriptor(self):
        from dos_re_harness.x86_address import decode_gdt_segment
        segment = decode_gdt_segment(bytes(8) + descriptor(0, 0xfffff, 0x9a, 0xc0), 8)
        self.assertEqual(segment.limit, 0xffffffff)
        self.assertEqual(segment.access, 0x9a)
        self.assertEqual(segment.address(0xffffffff, 1), 0xffffffff)

    def test_16_bit_descriptor(self):
        from dos_re_harness.x86_address import decode_gdt_segment
        segment = decode_gdt_segment(bytes(8) + descriptor(0x1000, 0xffff, flags=0), 8)
        self.assertFalse(segment.default_32)
        self.assertEqual(segment.address(0xffff, 1), 0x10fff)

    def test_descriptor_bounds_and_unsupported_types_reject(self):
        from dos_re_harness.x86_address import decode_gdt_segment
        table = bytes(8) + descriptor(0, 0xffff)
        for selector in (0, 3, 4, 12, 16, -1, 0x10000, True, 8.0):
            with self.subTest(selector=selector), self.assertRaises(ValueError):
                decode_gdt_segment(table, selector)
        with self.assertRaises(ValueError):
            decode_gdt_segment(table[:-1], 8)
        for access, flags in ((0x12, 0x40), (0x82, 0x40), (0x96, 0x40), (0x9a, 0x20)):
            with self.subTest(access=access, flags=flags), self.assertRaises(ValueError):
                decode_gdt_segment(bytes(8) + descriptor(0, 0xffff, access, flags), 8)

    def test_ranges_reject_segment_overrun_and_linear_wrap(self):
        from dos_re_harness.x86_address import decode_gdt_segment
        segment = decode_gdt_segment(bytes(8) + descriptor(0xffffff00, 0xffff), 8)
        self.assertEqual(segment.address(255, 1), 0xffffffff)
        for offset, size in ((256, 1), (255, 2), (0xffff, 2), (-1, 1), (0, 0), (0, -1), (True, 1), (0, 1.5)):
            with self.subTest(offset=offset, size=size), self.assertRaises(ValueError):
                segment.address(offset, size)

    def test_cold_real_mode_alias_round_trips(self):
        from dos_re_harness.x86_address import real_mode_breakpoint
        for linear in (0, 15, 16, 0xabcde, 0xfffff):
            packed = real_mode_breakpoint(linear)
            self.assertEqual(((packed >> 16) << 4) + (packed & 0xffff), linear)
        for linear in (-1, 0x100000, True, 1.5):
            with self.subTest(linear=linear), self.assertRaises(ValueError):
                real_mode_breakpoint(linear)

    def test_breakpoint_helpers_preserve_wire_encoding_and_deduplication(self):
        client = RspClient.__new__(RspClient)
        packets = []
        client.packet = lambda payload: packets.append(payload) or "OK"
        client.insert_segmented_breakpoint(0x28, 0xabcd)
        client.insert_segmented_breakpoint(0x28, 0xabcd)
        client.remove_segmented_breakpoint(0x28, 0xabcd)
        self.assertEqual(packets, ["Z0,28abcd,1", "z0,28abcd,1"])

    def test_high_offset_cannot_spill_into_selector(self):
        client = RspClient.__new__(RspClient)
        packets = []
        client.packet = lambda payload: packets.append(payload) or "OK"
        for operation in (client.insert_segmented_breakpoint, client.remove_segmented_breakpoint):
            for segment, offset in ((0x28, 0x10000), (0x28, 0x23456), (0x10000, 0), (-1, 0)):
                with self.subTest(segment=segment, offset=offset), self.assertRaises(ValueError):
                    operation(segment, offset)
        self.assertEqual(packets, [])

    def test_existing_packing_import_remains_compatible(self):
        from dos_re_harness.remote_capture import pack_segment_offset as old_pack
        from dos_re_harness.x86_address import pack_segment_offset
        self.assertIs(old_pack, pack_segment_offset)
        self.assertEqual(old_pack(0xabcd, 0x1234), 0xabcd1234)


if __name__ == "__main__":
    unittest.main()
