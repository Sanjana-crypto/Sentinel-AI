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
"""Unit tests for the email_analyzer agent's custom logic and schemas."""

import json

from google.adk.models.llm_response import LlmResponse
from google.genai import types

from app.agent import (
    EmailAnalysis,
    email_analyzer_after_model,
    email_analyzer_error_handler,
    sanitize_input,
)


def test_sanitize_input() -> None:
    """Test that input sanitization cleans up strings correctly."""
    # Test normal string
    assert sanitize_input("hello") == "hello"

    # Test None input
    assert sanitize_input(None) == ""

    # Test non-string input
    assert sanitize_input(12345) == "12345"

    # Test null byte stripping
    assert sanitize_input("hello\x00world") == "helloworld"

    # Test trimming/truncating
    long_input = "a" * 60000
    sanitized = sanitize_input(long_input)
    assert len(sanitized) < 60000
    assert "... [Input truncated for length] ..." in sanitized


def test_email_analysis_schema() -> None:
    """Test the validity of the Pydantic schemas."""
    data = {
        "headers": {
            "sender": "sender@domain.com",
            "reply_to": "reply@domain.com",
            "subject": "Urgent Action Required",
        },
        "authentication": {"spf": "pass", "dkim": "pass", "dmarc": "fail"},
        "urgency_detected": True,
        "urgency_justification": "Subject says Urgent Action Required",
        "brand_impersonation_detected": True,
        "impersonated_brand": "PayPal",
        "extracted_urls": ["http://phish-link.com"],
        "confidence_score": 0.95,
        "detailed_summary": "Suspicious email impersonating PayPal with urgent tone.",
    }
    model_instance = EmailAnalysis(**data)
    assert model_instance.headers.sender == "sender@domain.com"
    assert model_instance.authentication.spf == "pass"
    assert model_instance.urgency_detected is True
    assert model_instance.confidence_score == 0.95


def test_email_analyzer_error_handler() -> None:
    """Test that the model error handler returns a valid fallback LlmResponse."""
    resp = email_analyzer_error_handler(None, None, Exception("API quota exceeded"))
    assert isinstance(resp, LlmResponse)
    assert resp.content is not None
    assert resp.content.parts is not None
    assert len(resp.content.parts) == 1

    text = resp.content.parts[0].text
    assert text is not None

    # Verify it parses as EmailAnalysis
    parsed = json.loads(text)
    analysis = EmailAnalysis(**parsed)
    assert analysis.headers.sender == "error@sentinel.ai"
    assert (
        "API quota exceeded" in analysis.detailed_summary
        or "API quota exceeded" in analysis.urgency_justification
    )


def test_email_analyzer_after_model_valid() -> None:
    """Test that after_model callback returns None for valid JSON output."""
    data = {
        "headers": {
            "sender": "sender@domain.com",
            "reply_to": "reply@domain.com",
            "subject": "Hello",
        },
        "authentication": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
        "urgency_detected": False,
        "urgency_justification": "",
        "brand_impersonation_detected": False,
        "impersonated_brand": "none",
        "extracted_urls": [],
        "confidence_score": 1.0,
        "detailed_summary": "All checks passed.",
    }
    llm_resp = LlmResponse(
        content=types.Content(
            role="model", parts=[types.Part.from_text(text=json.dumps(data))]
        )
    )
    result = email_analyzer_after_model(None, llm_resp)
    # Valid output should return None so execution continues normally
    assert result is None


def test_email_analyzer_after_model_invalid() -> None:
    """Test that after_model callback returns fallback response for invalid JSON."""
    llm_resp = LlmResponse(
        content=types.Content(
            role="model", parts=[types.Part.from_text(text="This is not JSON at all!")]
        )
    )
    result = email_analyzer_after_model(None, llm_resp)
    assert result is not None
    assert isinstance(result, LlmResponse)

    text = result.content.parts[0].text
    parsed = json.loads(text)
    analysis = EmailAnalysis(**parsed)
    assert analysis.headers.sender == "unknown"
    assert (
        "Fallback: Analysis generated invalid output format"
        in analysis.detailed_summary
    )
