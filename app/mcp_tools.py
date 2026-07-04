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
"""MCP security tools for VirusTotal, AbuseIPDB, and Google Safe Browsing APIs."""

import base64
import ipaddress
import logging
import os
from typing import Any

import requests

# Configure Logger
logger = logging.getLogger("sentinel-ai.mcp_tools")


def is_valid_ip(target: str) -> bool:
    """Helper function to verify if a string is a valid IP address."""
    try:
        ipaddress.ip_address(target.strip())
        return True
    except ValueError:
        return False


def check_virustotal_reputation(target: str) -> dict[str, Any]:
    """Check the security reputation of a URL or IP address using the VirusTotal v3 API.

    Args:
        target: The URL or IP address to investigate.

    Returns:
        A structured dictionary containing reputation metrics or configuration status.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        logger.warning("VIRUSTOTAL_API_KEY not configured in environment.")
        return {
            "status": "skipped",
            "message": "VirusTotal API key is not configured in .env.",
            "malicious_count": 0,
            "suspicious_count": 0,
            "harmless_count": 0,
            "reputation": 0,
        }

    target = target.strip()
    headers = {"x-apikey": api_key, "accept": "application/json"}

    try:
        if is_valid_ip(target):
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"
            response = requests.get(url, headers=headers, timeout=10)
        else:
            # For URLs, VirusTotal requires base64 URL identifier without padding
            url_id = base64.urlsafe_b64encode(target.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 404:
            return {
                "status": "success",
                "message": "Target not found in VirusTotal database.",
                "malicious_count": 0,
                "suspicious_count": 0,
                "harmless_count": 0,
                "reputation": 0,
            }

        response.raise_for_status()
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        reputation = attributes.get("reputation", 0)

        return {
            "status": "success",
            "malicious_count": stats.get("malicious", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "harmless_count": stats.get("harmless", 0),
            "reputation": reputation,
        }

    except Exception as e:
        logger.error(f"Error querying VirusTotal: {e}", exc_info=True)
        return {
            "status": "error",
            "message": f"VirusTotal API error: {e!s}",
        }


def check_abuseipdb_score(ip_address: str) -> dict[str, Any]:
    """Check the abuse confidence score of an IP address using the AbuseIPDB v2 API.

    Args:
        ip_address: The IP address to check.

    Returns:
        A structured dictionary containing abuse scores and metadata.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        logger.warning("ABUSEIPDB_API_KEY not configured in environment.")
        return {
            "status": "skipped",
            "message": "AbuseIPDB API key is not configured in .env.",
            "abuse_confidence_score": 0,
            "total_reports": 0,
            "country_code": "unknown",
            "isp": "unknown",
        }

    ip_address = ip_address.strip()
    if not is_valid_ip(ip_address):
        return {
            "status": "error",
            "message": "Invalid IP address format.",
        }

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_address, "maxAgeInDays": "90"}

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json().get("data", {})

        return {
            "status": "success",
            "ip_address": data.get("ipAddress"),
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "total_reports": data.get("totalReports", 0),
            "country_code": data.get("countryCode", "unknown"),
            "isp": data.get("isp", "unknown"),
            "usage_type": data.get("usageType"),
            "is_public": data.get("isPublic"),
        }

    except Exception as e:
        logger.error(f"Error querying AbuseIPDB: {e}", exc_info=True)
        return {
            "status": "error",
            "message": f"AbuseIPDB API error: {e!s}",
        }


def check_google_safebrowsing(url: str) -> dict[str, Any]:
    """Check the safety of a URL using the Google Safe Browsing Lookup API (v4).

    Args:
        url: The URL to check.

    Returns:
        A structured dictionary containing URL safety status and match detail.
    """
    api_key = os.getenv("SAFE_BROWSING_API_KEY")
    if not api_key:
        logger.warning("SAFE_BROWSING_API_KEY not configured in environment.")
        return {
            "status": "skipped",
            "message": "Google Safe Browsing API key is not configured in .env.",
            "is_flagged": False,
            "matches": [],
        }

    url = url.strip()
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}"
    headers = {"Content-Type": "application/json"}
    payload = {
        "client": {"clientId": "sentinel-ai", "clientVersion": "0.1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        response = requests.post(api_url, headers=headers, json=payload, timeout=10)
        response.raise_for_status()
        data = response.json()
        matches = data.get("matches", [])

        return {
            "status": "success",
            "is_flagged": len(matches) > 0,
            "matches": matches,
        }

    except Exception as e:
        logger.error(f"Error querying Google Safe Browsing: {e}", exc_info=True)
        return {
            "status": "error",
            "message": f"Google Safe Browsing API error: {e!s}",
        }
