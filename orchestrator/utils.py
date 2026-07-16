"""
Shared Utilities for Argus OSINT Framework
Consolidates common functions used across multiple modules:
- User agent rotation
- Random HTTP headers generation
- Tool availability checking
- HTTP request helpers
"""

import os
import subprocess
import random
from typing import Dict, List, Optional, Tuple

# =============================================================================
# User Agents (Tuple - immutable, memory efficient)
# =============================================================================
USER_AGENTS: Tuple[str, ...] = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
)

_UA_LIST: List[str] = list(USER_AGENTS)  # Mutable copy for list-based consumers


def get_random_user_agent() -> str:
    """Return a random User-Agent string from the shared pool."""
    return random.choice(_UA_LIST)


def get_random_headers(host: str) -> Dict[str, str]:
    """Generate randomized HTTP headers for evasion."""
    return {
        'User-Agent': get_random_user_agent(),
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Host': host,
    }


def get_simple_headers() -> Dict[str, str]:
    """Generate minimal HTTP headers with just a random User-Agent."""
    return {'User-Agent': get_random_user_agent()}


# =============================================================================
# Tool Availability Check
# =============================================================================

def check_tool(tool: str) -> bool:
    """Check if a command-line tool is available in PATH."""
    try:
        if os.name == 'nt':
            result = subprocess.run(['where', tool], capture_output=True, text=True)
        else:
            result = subprocess.run(['which', tool], capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return False


def run_command(cmd: List[str], timeout: int = 60) -> Tuple[bool, str, str]:
    """Run an external command with timeout and error handling.
    
    Uses a list-based command (shell=False) to avoid shell injection.
    For batch files on Windows, prepend ['cmd.exe', '/c'] to the cmd list.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=False
        )
        return True, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "Command timed out"
    except FileNotFoundError:
        return False, "", f"Command not found: {cmd[0] if cmd else 'empty'}"
    except Exception as e:
        return False, "", str(e)


# =============================================================================
# Network helpers
# =============================================================================

def resolve_host(host: str, timeout: int = 5) -> Optional[str]:
    """Resolve a hostname to an IP address."""
    import socket
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None
