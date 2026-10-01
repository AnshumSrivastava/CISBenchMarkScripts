import pytest
from scanner.logs import parse_failed_logins, parse_successful_logins

SAMPLE_LOGS = [
    "Sep 30 12:00:01 server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2",
    "Sep 30 12:00:05 server sshd[1235]: Failed password for root from 10.0.0.50 port 54322 ssh2",
    "Sep 30 12:01:00 server sshd[1236]: Accepted publickey for ducus from 192.168.1.50 port 49152 ssh2",
    "Sep 30 12:01:10 server systemd-logind[400]: Session opened for user ducus",
    "Sep 30 12:02:00 server sudo[1240]: ducus : TTY=pts/0 ; PWD=/home/ducus ; USER=root ; COMMAND=/bin/ls"
]

def test_parse_failed_logins():
    failures = parse_failed_logins(SAMPLE_LOGS)
    assert len(failures) == 2
    assert "admin" in failures[0]
    assert "root" in failures[1]

def test_parse_successful_logins():
    successes = parse_successful_logins(SAMPLE_LOGS)
    assert len(successes) == 2
    assert "Accepted publickey" in successes[0]
    assert "Session opened for user ducus" in successes[1]

def test_empty_log_parsing():
    assert parse_failed_logins([]) == []
    assert parse_successful_logins([]) == []
