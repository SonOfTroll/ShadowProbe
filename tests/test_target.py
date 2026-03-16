"""Unit tests for target parsing."""

import pytest
from shadowprobe.core.target import TargetParser


@pytest.fixture
def parser():
    return TargetParser()


class TestTargetParser:
    def test_single_ip(self, parser):
        result = parser.parse("192.168.1.1")
        assert result == ["192.168.1.1"]

    def test_cidr_24(self, parser):
        result = parser.parse("10.0.0.0/30")
        assert result == ["10.0.0.1", "10.0.0.2"]

    def test_ip_range(self, parser):
        result = parser.parse("192.168.1.1-5")
        assert result == [
            "192.168.1.1", "192.168.1.2", "192.168.1.3",
            "192.168.1.4", "192.168.1.5",
        ]

    def test_comma_separated(self, parser):
        result = parser.parse("10.0.0.1,10.0.0.2")
        assert result == ["10.0.0.1", "10.0.0.2"]

    def test_localhost(self, parser):
        result = parser.parse("127.0.0.1")
        assert result == ["127.0.0.1"]

    def test_hostname_localhost(self, parser):
        result = parser.parse("localhost")
        assert "127.0.0.1" in result

    def test_invalid_target_raises(self, parser):
        with pytest.raises(ValueError):
            parser.parse("not_a_valid_target_xyz_12345")

    def test_deduplicate(self, parser):
        result = parser.parse_targets(["10.0.0.1", "10.0.0.1"])
        assert result == ["10.0.0.1"]

    def test_parse_multiple(self, parser):
        result = parser.parse_targets(["192.168.1.1", "10.0.0.1"])
        assert len(result) == 2
        assert "192.168.1.1" in result
        assert "10.0.0.1" in result
