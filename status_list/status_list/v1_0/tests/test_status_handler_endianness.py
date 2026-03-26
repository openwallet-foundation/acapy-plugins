"""Tests for bit order/numbering in status lists.

The W3C and IETF specs use different bit numbering within each byte:
- W3C Bitstring Status List: big-endian bit order (MSB first)
- IETF Token Status List: little-endian bit order (LSB first)

For an 8-bit list with only index 0 set to 1:
- W3C ("big"): first byte = 0x80 (binary: 10000000)
- IETF ("little"): first byte = 0x01 (binary: 00000001)
"""

from bitarray import bitarray


def test_bit_order_difference():
    """Verify W3C and IETF produce different byte representations for same logical bits."""
    # Same logical bits: index 0 = 1, rest = 0
    source_bits = bitarray("10000000")

    # IETF (little-endian): index 0 → bit 0 of byte → 0x01
    ietf_bits = bitarray(source_bits, endian="little")
    ietf_bytes = ietf_bits.tobytes()
    assert ietf_bytes[0] == 0x01

    # W3C (big-endian): index 0 → bit 7 of byte → 0x80
    w3c_bits = bitarray(source_bits, endian="big")
    w3c_bytes = w3c_bits.tobytes()
    assert w3c_bytes[0] == 0x80


def test_ietf_little_endian_encoding():
    """Test IETF encoding: setting index 0 should produce 0x01."""
    bits = bitarray("10000000")  # Index 0 set
    encoded = bitarray(bits, endian="little")
    assert encoded.tobytes()[0] == 0x01


def test_w3c_big_endian_encoding():
    """Test W3C encoding: setting index 0 should produce 0x80."""
    bits = bitarray("10000000")  # Index 0 set
    encoded = bitarray(bits, endian="big")
    assert encoded.tobytes()[0] == 0x80
