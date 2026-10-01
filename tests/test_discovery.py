import pytest
from scanner.discovery import parse_os_release, discover_tools, detect_distribution
from scanner.models import SystemContext

def test_parse_os_release():
    sample = """
    NAME="Ubuntu"
    VERSION="24.04 LTS (Noble Numbat)"
    ID=ubuntu
    ID_LIKE=debian
    PRETTY_NAME="Ubuntu 24.04 LTS"
    VERSION_ID="24.04"
    """
    data = parse_os_release(sample)
    assert data["ID"] == "ubuntu"
    assert data["VERSION_ID"] == "24.04"
    assert data["PRETTY_NAME"] == "Ubuntu 24.04 LTS"

def test_parse_os_release_fedora():
    sample = """
    NAME="Fedora Linux"
    VERSION="40 (Workstation Edition)"
    ID=fedora
    VERSION_ID="40"
    """
    data = parse_os_release(sample)
    assert data["ID"] == "fedora"
    assert data["VERSION_ID"] == "40"

def test_discover_tools_structure():
    tools = discover_tools()
    assert isinstance(tools, dict)
    assert "systemctl" in tools
    assert "ss" in tools
    assert "nft" in tools
    assert isinstance(tools["ss"], bool)
