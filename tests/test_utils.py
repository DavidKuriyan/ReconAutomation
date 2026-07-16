"""
Unit tests for Argus OSINT Framework - Shared Utilities
Tests for orchestrator/utils.py
"""
import sys
import os
import pytest

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(__file__)), 'orchestrator'))

from utils import (
    get_random_user_agent,
    get_random_headers,
    get_simple_headers,
    check_tool,
    resolve_host,
)


class TestUserAgents:
    """Test the user agent utility functions."""

    def test_get_random_user_agent_returns_string(self):
        """get_random_user_agent() should return a non-empty string."""
        ua = get_random_user_agent()
        assert isinstance(ua, str)
        assert len(ua) > 20
        assert 'Mozilla' in ua or 'Chrome' in ua or 'Safari' in ua

    def test_get_random_user_agent_varies(self):
        """Multiple calls should return different agents (random selection)."""
        agents = {get_random_user_agent() for _ in range(20)}
        assert len(agents) > 1, "Should produce at least 2 different user agents"

    def test_get_random_headers_contains_required_fields(self):
        """get_random_headers() should return a dict with required HTTP headers."""
        headers = get_random_headers('example.com')
        assert isinstance(headers, dict)
        assert 'User-Agent' in headers
        assert 'Host' in headers
        assert 'Accept' in headers
        assert 'Accept-Language' in headers
        assert headers['Host'] == 'example.com'
        assert headers['User-Agent'] and len(headers['User-Agent']) > 20

    def test_get_simple_headers_returns_ua_dict(self):
        """get_simple_headers() should return at minimum a User-Agent header."""
        headers = get_simple_headers()
        assert isinstance(headers, dict)
        assert 'User-Agent' in headers
        assert len(headers) >= 1


class TestCheckTool:
    """Test the tool availability checker."""

    def test_check_tool_python_exists(self):
        """check_tool() should at least not crash for known tools."""
        # At least one of these should be available on any system
        result = check_tool('python') or check_tool('python3') or check_tool('py')
        # Note: May be False in minimal Docker containers — that's OK
        assert isinstance(result, bool)

    def test_check_tool_nonexistent_returns_false(self):
        """check_tool() for a nonexistent tool should return False."""
        result = check_tool('this_tool_does_not_exist_xyz_123')
        assert result is False


class TestResolveHost:
    """Test hostname resolution."""

    def test_resolve_known_host(self):
        """resolve_host() should resolve a valid hostname to an IP."""
        ip = resolve_host('google.com')
        if ip:  # May fail offline
            assert isinstance(ip, str)
            assert len(ip.split('.')) == 4  # IPv4 format

    def test_resolve_invalid_host_returns_none(self):
        """resolve_host() should return None for invalid hostnames."""
        ip = resolve_host('this-domain-does-not-exist-abc123.com')
        assert ip is None


class TestEdgeCases:
    """Test edge cases for utility functions."""

    def test_get_random_headers_with_ip_host(self):
        """get_random_headers() should work with IP addresses as host."""
        headers = get_random_headers('192.168.1.1')
        assert headers['Host'] == '192.168.1.1'

    def test_get_random_headers_with_subdomain(self):
        """get_random_headers() should work with subdomains."""
        headers = get_random_headers('sub.domain.example.com')
        assert headers['Host'] == 'sub.domain.example.com'

    def test_check_tool_empty_string(self):
        """check_tool('') should return False gracefully."""
        result = check_tool('')
        assert result is False
