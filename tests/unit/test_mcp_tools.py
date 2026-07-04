# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Unit tests for the MCP threat intelligence tools in app/mcp_tools.py."""

import base64
from unittest.mock import MagicMock, patch

import requests

from app.mcp_tools import (
    check_abuseipdb_score,
    check_google_safebrowsing,
    check_virustotal_reputation,
    is_valid_ip,
)


def test_is_valid_ip() -> None:
    """Test the is_valid_ip helper function."""
    assert is_valid_ip("192.168.1.1") is True
    assert is_valid_ip("8.8.8.8") is True
    assert is_valid_ip("2001:4860:4860::8888") is True
    assert is_valid_ip("invalid-ip") is False
    assert is_valid_ip("999.999.999.999") is False


@patch("app.mcp_tools.os.getenv")
def test_virustotal_skipped_when_no_key(mock_getenv: MagicMock) -> None:
    """Test that check_virustotal_reputation skips gracefully when key is missing."""
    mock_getenv.return_value = None
    res = check_virustotal_reputation("8.8.8.8")
    assert res["status"] == "skipped"
    assert "not configured" in res["message"]


@patch("app.mcp_tools.os.getenv")
@patch("app.mcp_tools.requests.get")
def test_virustotal_success_ip(mock_get: MagicMock, mock_getenv: MagicMock) -> None:
    """Test VirusTotal check for IP address with success response."""
    mock_getenv.return_value = "fake-vt-key"

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 0,
                    "harmless": 70,
                },
                "reputation": 15,
            }
        }
    }
    mock_get.return_value = mock_response

    res = check_virustotal_reputation("8.8.8.8")
    assert res["status"] == "success"
    assert res["malicious_count"] == 1
    assert res["harmless_count"] == 70
    assert res["reputation"] == 15
    mock_get.assert_called_once_with(
        "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
        headers={"x-apikey": "fake-vt-key", "accept": "application/json"},
        timeout=10,
    )


@patch("app.mcp_tools.os.getenv")
@patch("app.mcp_tools.requests.get")
def test_virustotal_success_url(mock_get: MagicMock, mock_getenv: MagicMock) -> None:
    """Test VirusTotal check for URL with success response."""
    mock_getenv.return_value = "fake-vt-key"

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 2,
                    "harmless": 65,
                },
                "reputation": -5,
            }
        }
    }
    mock_get.return_value = mock_response

    url_to_test = "http://malicious-domain.com/phish"
    res = check_virustotal_reputation(url_to_test)
    assert res["status"] == "success"
    assert res["malicious_count"] == 5
    assert res["suspicious_count"] == 2
    assert res["reputation"] == -5

    # Check that URL is base64url encoded correctly
    url_id = base64.urlsafe_b64encode(url_to_test.encode()).decode().strip("=")
    mock_get.assert_called_once_with(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers={"x-apikey": "fake-vt-key", "accept": "application/json"},
        timeout=10,
    )


@patch("app.mcp_tools.os.getenv")
@patch("app.mcp_tools.requests.get")
def test_virustotal_error_handling(mock_get: MagicMock, mock_getenv: MagicMock) -> None:
    """Test that VirusTotal handles API connection errors gracefully."""
    mock_getenv.return_value = "fake-vt-key"
    mock_get.side_effect = requests.RequestException("Connection timeout")

    res = check_virustotal_reputation("8.8.8.8")
    assert res["status"] == "error"
    assert "Connection timeout" in res["message"]


@patch("app.mcp_tools.os.getenv")
def test_abuseipdb_skipped_when_no_key(mock_getenv: MagicMock) -> None:
    """Test AbuseIPDB skips gracefully when API key is missing."""
    mock_getenv.return_value = None
    res = check_abuseipdb_score("8.8.8.8")
    assert res["status"] == "skipped"
    assert "not configured" in res["message"]


@patch("app.mcp_tools.os.getenv")
def test_abuseipdb_invalid_ip(mock_getenv: MagicMock) -> None:
    """Test AbuseIPDB validates IP address format and returns error if invalid."""
    mock_getenv.return_value = "fake-abuse-key"
    res = check_abuseipdb_score("invalid-ip")
    assert res["status"] == "error"
    assert "Invalid IP address" in res["message"]


@patch("app.mcp_tools.os.getenv")
@patch("app.mcp_tools.requests.get")
def test_abuseipdb_success(mock_get: MagicMock, mock_getenv: MagicMock) -> None:
    """Test AbuseIPDB success response parsing."""
    mock_getenv.return_value = "fake-abuse-key"

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 85,
            "totalReports": 34,
            "countryCode": "US",
            "isp": "Google LLC",
            "usageType": "Data Center",
            "isPublic": True,
        }
    }
    mock_get.return_value = mock_response

    res = check_abuseipdb_score("8.8.8.8")
    assert res["status"] == "success"
    assert res["abuse_confidence_score"] == 85
    assert res["total_reports"] == 34
    assert res["country_code"] == "US"
    assert res["isp"] == "Google LLC"
    mock_get.assert_called_once_with(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": "fake-abuse-key", "Accept": "application/json"},
        params={"ipAddress": "8.8.8.8", "maxAgeInDays": "90"},
        timeout=10,
    )


@patch("app.mcp_tools.os.getenv")
def test_safebrowsing_skipped_when_no_key(mock_getenv: MagicMock) -> None:
    """Test Google Safe Browsing skips gracefully when key is missing."""
    mock_getenv.return_value = None
    res = check_google_safebrowsing("http://example.com")
    assert res["status"] == "skipped"
    assert "not configured" in res["message"]


@patch("app.mcp_tools.os.getenv")
@patch("app.mcp_tools.requests.post")
def test_safebrowsing_flagged_success(
    mock_post: MagicMock, mock_getenv: MagicMock
) -> None:
    """Test Safe Browsing returns matches when a threat is detected."""
    mock_getenv.return_value = "fake-sb-key"

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "matches": [
            {
                "threatType": "MALWARE",
                "platformType": "ANY_PLATFORM",
                "threatEntryType": "URL",
                "threat": {"url": "http://malware.com"},
            }
        ]
    }
    mock_post.return_value = mock_response

    res = check_google_safebrowsing("http://malware.com")
    assert res["status"] == "success"
    assert res["is_flagged"] is True
    assert len(res["matches"]) == 1
    assert res["matches"][0]["threatType"] == "MALWARE"


@patch("app.mcp_tools.os.getenv")
@patch("app.mcp_tools.requests.post")
def test_safebrowsing_clean_success(
    mock_post: MagicMock, mock_getenv: MagicMock
) -> None:
    """Test Safe Browsing returns is_flagged = False when no threat matches are returned."""
    mock_getenv.return_value = "fake-sb-key"

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {}  # Empty dict is returned by Google API if clean
    mock_post.return_value = mock_response

    res = check_google_safebrowsing("http://clean-site.com")
    assert res["status"] == "success"
    assert res["is_flagged"] is False
    assert res["matches"] == []
