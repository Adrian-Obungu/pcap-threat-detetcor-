"""
Whitelist manager with Pydantic validation, atomic file writes, and idempotent operations.
"""
import os
import tempfile
from typing import List, Union, Optional
from pydantic import BaseModel, Field, field_validator
import json

WHITELIST_PATH = "data/whitelist/whitelist.txt"

# ---------------------- Pydantic Models ----------------------
class ARPWhitelistEntry(BaseModel):
    type: str = "arp"
    ip: str = Field(..., pattern=r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    mac: str = Field(..., pattern=r'^[0-9a-fA-F:]{17}$')

    @field_validator('mac')
    def validate_mac(cls, v):
        # Normalize to lowercase
        return v.lower()

class IPWhitelistEntry(BaseModel):
    type: str = "ip"
    ip: str = Field(..., pattern=r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

class DomainWhitelistEntry(BaseModel):
    type: str = "domain"
    domain: str = Field(..., pattern=r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,62})+$')

class ExfilWhitelistEntry(BaseModel):
    type: str = "exfil"
    src: str = Field(..., pattern=r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    dst: str = Field(..., pattern=r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    proto: str = Field(..., pattern=r'^(tcp|udp|icmp)$')

WhitelistEntry = Union[ARPWhitelistEntry, IPWhitelistEntry, DomainWhitelistEntry, ExfilWhitelistEntry]

def parse_line(line: str) -> Optional[WhitelistEntry]:
    """Parse a raw string line into a Pydantic model, or return None if invalid."""
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    # Try ARP
    if ':' in line and line.count(':') == 1:
        parts = line.split(':')
        if len(parts) == 2:
            try:
                return ARPWhitelistEntry(ip=parts[0], mac=parts[1])
            except:
                pass
    # Try IP
    if line.count('.') == 3 and ':' not in line and not any(c.isalpha() for c in line):
        try:
            return IPWhitelistEntry(ip=line)
        except:
            pass
    # Try domain
    if '.' in line and not any(c in line for c in '/:') and not line[0].isdigit():
        try:
            return DomainWhitelistEntry(domain=line)
        except:
            pass
    # Try exfil (src:dst:proto)
    if line.count(':') == 2:
        parts = line.split(':')
        if len(parts) == 3:
            try:
                return ExfilWhitelistEntry(src=parts[0], dst=parts[1], proto=parts[2])
            except:
                pass
    return None

def entry_to_string(entry: WhitelistEntry) -> str:
    """Convert Pydantic model back to plain string for storage."""
    if entry.type == "arp":
        return f"{entry.ip}:{entry.mac}"
    elif entry.type == "ip":
        return entry.ip
    elif entry.type == "domain":
        return entry.domain
    elif entry.type == "exfil":
        return f"{entry.src}:{entry.dst}:{entry.proto}"
    raise ValueError(f"Unknown type: {entry.type}")

# ---------------------- Atomic File Operations ----------------------
def _read_entries() -> List[WhitelistEntry]:
    """Read and parse all entries from the whitelist file."""
    if not os.path.exists(WHITELIST_PATH):
        return []
    with open(WHITELIST_PATH, 'r') as f:
        lines = f.readlines()
    entries = []
    for line in lines:
        entry = parse_line(line)
        if entry:
            entries.append(entry)
    return entries

def _write_entries(entries: List[WhitelistEntry]) -> None:
    """Atomically write entries to the whitelist file using a temporary file."""
    # Ensure directory exists
    os.makedirs(os.path.dirname(WHITELIST_PATH), exist_ok=True)
    # Write to a temporary file in the same directory
    fd, temp_path = tempfile.mkstemp(dir=os.path.dirname(WHITELIST_PATH), prefix=".whitelist_tmp_")
    with os.fdopen(fd, 'w') as f:
        for entry in entries:
            f.write(entry_to_string(entry) + '\n')
    # Atomic replace
    os.replace(temp_path, WHITELIST_PATH)

# ---------------------- Public API (Idempotent) ----------------------
def load_whitelist() -> List[str]:
    """Return list of whitelist strings (plain text) for UI display."""
    entries = _read_entries()
    return [entry_to_string(e) for e in entries]

def add_whitelist_entry(entry_str: str) -> bool:
    """Add an entry if valid and not already present. Idempotent."""
    entry = parse_line(entry_str)
    if not entry:
        return False
    current = _read_entries()
    # Check for duplicate (by string representation)
    new_str = entry_to_string(entry)
    if any(entry_to_string(e) == new_str for e in current):
        return True  # already exists, idempotent success
    current.append(entry)
    _write_entries(current)
    return True

def remove_whitelist_entry(entry_str: str) -> bool:
    """Remove an entry if it exists. Idempotent."""
    entry = parse_line(entry_str)
    if not entry:
        return False
    target_str = entry_to_string(entry)
    current = _read_entries()
    new_entries = [e for e in current if entry_to_string(e) != target_str]
    if len(new_entries) == len(current):
        return False  # not found
    _write_entries(new_entries)
    return True
