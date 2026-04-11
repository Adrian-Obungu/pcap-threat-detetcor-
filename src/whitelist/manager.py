"""
Whitelist manager with file locking and input validation.
"""
import os
import re
import fcntl
import time
from typing import List, Tuple

WHITELIST_PATH = "data/whitelist/whitelist.txt"
LOCK_TIMEOUT = 5  # seconds

def _acquire_lock(fd):
    start = time.time()
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            if time.time() - start > LOCK_TIMEOUT:
                raise TimeoutError("Could not acquire lock on whitelist file")
            time.sleep(0.1)

def _release_lock(fd):
    fcntl.flock(fd, fcntl.LOCK_UN)

def _validate_arp(line: str) -> bool:
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:[0-9a-fA-F:]{17}$', line))

def _validate_ip(line: str) -> bool:
    return bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line))

def _validate_domain(line: str) -> bool:
    # Simple domain validation (no protocol, no path)
    return bool(re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,62})+$', line))

def _validate_exfil(line: str) -> bool:
    # src:dest:proto
    parts = line.split(':')
    if len(parts) != 3:
        return False
    ip_part = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    proto_part = r'tcp|udp|icmp'
    return bool(re.match(f'^{ip_part}:{ip_part}:{proto_part}$', line))

def validate_line(line: str) -> Tuple[bool, str]:
    """Validate a whitelist entry and return (valid, category)."""
    line = line.strip()
    if not line or line.startswith('#'):
        return True, 'comment'
    if _validate_arp(line):
        return True, 'arp'
    if _validate_ip(line):
        return True, 'port_scan'
    if _validate_domain(line):
        return True, 'dns'
    if _validate_exfil(line):
        return True, 'exfil'
    return False, 'invalid'

def load_whitelist() -> List[str]:
    """Return list of valid whitelist entries (no comments, no empty lines)."""
    if not os.path.exists(WHITELIST_PATH):
        return []
    with open(WHITELIST_PATH, 'r') as f:
        _acquire_lock(f.fileno())
        try:
            lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        finally:
            _release_lock(f.fileno())
    return lines

def add_whitelist_entry(entry: str) -> bool:
    """Append a validated entry to the whitelist file."""
    valid, category = validate_line(entry)
    if not valid:
        return False
    with open(WHITELIST_PATH, 'a') as f:
        _acquire_lock(f.fileno())
        try:
            f.write(entry + '\n')
        finally:
            _release_lock(f.fileno())
    return True

def remove_whitelist_entry(entry: str) -> bool:
    """Remove exact entry line from whitelist file (case‑sensitive)."""
    if not os.path.exists(WHITELIST_PATH):
        return False
    with open(WHITELIST_PATH, 'r') as f:
        _acquire_lock(f.fileno())
        try:
            lines = f.readlines()
        finally:
            _release_lock(f.fileno())
    new_lines = [line for line in lines if line.strip() != entry]
    if len(new_lines) == len(lines):
        return False  # not found
    with open(WHITELIST_PATH, 'w') as f:
        _acquire_lock(f.fileno())
        try:
            f.writelines(new_lines)
        finally:
            _release_lock(f.fileno())
    return True
