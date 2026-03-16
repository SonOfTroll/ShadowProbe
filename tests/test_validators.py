"""Unit tests for validators."""

import pytest
from shadowprobe.utils.validators import (
    parse_ip_range,
    parse_port_range,
    validate_cidr,
    validate_ip,
    validate_port,
)


class TestValidateIP:
    def test_valid_ipv4(self):
        assert validate_ip("192.168.1.1") is True

    def test_valid_ipv6(self):
        assert validate_ip("::1") is True

    def test_invalid(self):
        assert validate_ip("999.999.999.999") is False
        assert validate_ip("abc") is False
        assert validate_ip("") is False


class TestValidateCIDR:
    def test_valid(self):
        assert validate_cidr("192.168.1.0/24") is True
        assert validate_cidr("10.0.0.0/8") is True

    def test_invalid(self):
        assert validate_cidr("192.168.1.0/99") is False
        assert validate_cidr("not_cidr") is False


class TestValidatePort:
    def test_valid(self):
        assert validate_port(1) is True
        assert validate_port(80) is True
        assert validate_port(65535) is True

    def test_invalid(self):
        assert validate_port(0) is False
        assert validate_port(65536) is False
        assert validate_port(-1) is False


class TestParsePortRange:
    def test_single(self):
        assert parse_port_range("80") == [80]

    def test_comma(self):
        assert parse_port_range("22,80,443") == [22, 80, 443]

    def test_range(self):
        result = parse_port_range("79-81")
        assert result == [79, 80, 81]

    def test_mixed(self):
        result = parse_port_range("22,80,100-102")
        assert 22 in result
        assert 80 in result
        assert 100 in result
        assert 101 in result
        assert 102 in result

    def test_top100(self):
        result = parse_port_range("top100")
        assert len(result) == 100

    def test_invalid_port_raises(self):
        with pytest.raises(ValueError):
            parse_port_range("99999")

    def test_invalid_range_raises(self):
        with pytest.raises(ValueError):
            parse_port_range("100-50")


class TestParseIPRange:
    def test_valid(self):
        result = parse_ip_range("10.0.0.1-3")
        assert result == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_single_host(self):
        result = parse_ip_range("10.0.0.5-5")
        assert result == ["10.0.0.5"]

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            parse_ip_range("invalid")
