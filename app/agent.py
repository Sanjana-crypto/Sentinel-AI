# ruff: noqa
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

import datetime
import os
import google.auth
from dotenv import load_dotenv
load_dotenv(override=True)

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logger.info(f"GEMINI_API_KEY loaded: {'YES' if os.getenv('GEMINI_API_KEY') else 'NO'}")


from google.adk.agents import Agent
from google.adk.apps import App
from google.adk.models import Gemini
from google.adk import Event, Workflow
from google.genai import types
from google.genai import Client as GenaiClient
from functools import cached_property
from app.groq_llm import GroqLLM

from pydantic import BaseModel, Field
from typing import Any, Optional
import json
import logging

from app.mcp_tools import (
    check_virustotal_reputation,
    check_abuseipdb_score,
    check_google_safebrowsing,
)

# Configure Logger
logger = logging.getLogger("sentinel-ai.email_analyzer")


# Pydantic Schemas for Structured Email Analysis
class AuthenticationResults(BaseModel):
    spf: str = Field(
        description="SPF verification result (e.g., pass, fail, softfail, neutral, none, or unknown)"
    )
    dkim: str = Field(
        description="DKIM verification result (e.g., pass, fail, none, or unknown)"
    )
    dmarc: str = Field(
        description="DMARC verification result (e.g., pass, fail, none, or unknown)"
    )


class EmailHeaders(BaseModel):
    sender: str = Field(description="The sender address extracted from 'From' header")
    reply_to: str = Field(
        description="The address from 'Reply-To' header (or empty/none if not present)"
    )
    subject: str = Field(description="The email subject line")


class EmailAnalysis(BaseModel):
    headers: EmailHeaders = Field(description="Parsed email headers")
    authentication: AuthenticationResults = Field(
        description="SPF, DKIM, and DMARC verification results"
    )
    urgency_detected: bool = Field(
        description="True if urgency language patterns or urgent calls to action are detected"
    )
    urgency_justification: str = Field(
        description="Reason/evidence for detecting urgency language patterns, if any"
    )
    brand_impersonation_detected: bool = Field(
        description="True if brand impersonation attempts (e.g., pretending to be PayPal, Google, Bank of America, etc.) are detected"
    )
    impersonated_brand: str = Field(
        description="The name of the brand being impersonated, or empty/none if none detected"
    )
    extracted_urls: list[str] = Field(
        description="List of all URLs extracted from the email body"
    )
    confidence_score: float = Field(
        description="Confidence score between 0.0 and 1.0 indicating how confident the analyst is in this assessment"
    )
    detailed_summary: str = Field(
        description="Detailed summary of the email header and content analysis findings"
    )


# Error Handling Callback and Validation Callback for email_analyzer
def email_analyzer_error_handler(
    callback_context: Any, llm_request: Any, error: Exception
) -> Any:
    """Fallback handler for model/API failures."""
    logger.error(f"Model error in email_analyzer: {error}", exc_info=True)
    fallback_data = {
        "headers": {
            "sender": "error@sentinel.ai",
            "reply_to": "error@sentinel.ai",
            "subject": "Error: Failed to process email",
        },
        "authentication": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"},
        "urgency_detected": False,
        "urgency_justification": f"Model error: {error}",
        "brand_impersonation_detected": False,
        "impersonated_brand": "none",
        "extracted_urls": [],
        "confidence_score": 0.0,
        "detailed_summary": f"An error occurred during email analysis: {error}",
    }
    fallback_json = json.dumps(fallback_data)
    from google.adk.models.llm_response import LlmResponse

    return LlmResponse(
        content=types.Content(
            role="model", parts=[types.Part.from_text(text=fallback_json)]
        )
    )


def email_analyzer_after_model(callback_context: Any, llm_response: Any) -> Any:
    """Validate structure of LLM response and handle validation failures with fallback."""
    if not llm_response or not llm_response.content or not llm_response.content.parts:
        return None

    # Extract text from response parts
    text = "".join(
        part.text
        for part in llm_response.content.parts
        if part.text and not part.thought
    )

    try:
        from google.adk.utils._schema_utils import validate_schema

        # Check if the output conforms to EmailAnalysis schema
        validate_schema(EmailAnalysis, text)
        return None  # Let it proceed normally
    except Exception as e:
        logger.warning(
            f"Email Analysis JSON validation failed: {e}. Output was: {text[:200]}"
        )
        fallback_data = {
            "headers": {
                "sender": "unknown",
                "reply_to": "unknown",
                "subject": "unknown",
            },
            "authentication": {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"},
            "urgency_detected": False,
            "urgency_justification": f"Validation failed: {e}",
            "brand_impersonation_detected": False,
            "impersonated_brand": "none",
            "extracted_urls": [],
            "confidence_score": 0.0,
            "detailed_summary": f"Fallback: Analysis generated invalid output format. Original output: {text}",
        }
        fallback_json = json.dumps(fallback_data)
        from google.adk.models.llm_response import LlmResponse

        return LlmResponse(
            content=types.Content(
                role="model", parts=[types.Part.from_text(text=fallback_json)]
            )
        )


def sanitize_input(input_text: Any) -> str:
    """Sanitize the raw input to prevent injection attacks and format issues."""
    if input_text is None:
        return ""
    if not isinstance(input_text, str):
        input_text = str(input_text)

    # Strip null bytes and common control characters
    cleaned = input_text.replace("\x00", "")

    # Limit input size to prevent token overflow (e.g. max 50,000 characters)
    max_length = 50000
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + "\n... [Input truncated for length] ..."

    return cleaned.strip()




os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "False"

# Configure the LLM using Groq API
model = GroqLLM(
    model="llama-3.3-70b-versatile",
)


def init_state(node_input: Any) -> Event:
    """Initialize the workflow session state with the user's raw input."""
    from google.adk.events import EventActions

    sanitized = sanitize_input(node_input)
    return Event(
        output=sanitized,
        actions=EventActions(state_delta={"raw_input": sanitized}),
    )


orchestrator = Agent(
    name="orchestrator",
    model=model,
    instruction="""
    You are the Lead Cyber Security Orchestrator agent.
    Your task is to analyze the raw security alert, email, or URL input provided by the user.
    Define the goals of this security investigation. Outline the key questions to answer:
    1. Is there email header or content spoofing?
    2. Are there suspicious URLs that need investigation?
    3. What indicators of compromise (IOCs) should be extracted?
    Produce an investigation plan.
    User input: {raw_input}
    """,
    output_key="orchestrator_guidance",
)

email_analyzer = Agent(
    name="email_analyzer",
    model=model,
    instruction="""
    You are a Phishing Email Analyst.
    Your task is to analyze the raw email input (headers and body) and produce a structured analysis.
    
    You must populate each field of the response schema:
    1. Parse email headers:
       - Extract the sender's address from the 'From' header (e.g. "From: Sender <sender@domain.com>").
       - Extract the 'Reply-To' header if present (or "none"/"unknown" if not).
       - Extract the 'Subject' header.
    2. Check Authentication Results:
       - Look for SPF, DKIM, and DMARC verification results in the raw input (often under "Authentication-Results" or mentioned in the text). Classify each as "pass", "fail", "softfail", "neutral", "none", or "unknown".
    3. Detect urgency language patterns:
       - Examine the tone of the subject and body for urgency, fear-inducing language, threat of account suspension, or immediate actions required. Set urgency_detected to true/false and provide urgency_justification.
    4. Identify brand impersonation attempts:
       - Determine if the sender/email body is pretending to be a known trusted brand (e.g., PayPal, Google, Bank of America, Netflix, UPS, etc.) but using a different sender domain or suspicious URLs. Set brand_impersonation_detected and impersonated_brand accordingly.
    5. Extract all URLs from email body:
       - Extract all URLs present in the email body text and list them.
    6. Assign a confidence_score between 0.0 and 1.0 based on how clear and consistent the signals are.
    7. Provide a concise detailed_summary of your findings.
    
    Refer to the orchestrator plan: {orchestrator_guidance}
    Raw email/input: {raw_input}
    """,
    output_schema=EmailAnalysis,
    output_key="email_analysis",
    on_model_error_callback=email_analyzer_error_handler,
    after_model_callback=email_analyzer_after_model,
)

url_investigator = Agent(
    name="url_investigator",
    model=model,
    instruction="""
    You are a Suspect URL Analyst.
    Your task is to examine any URLs present in the raw input or the email analysis.
    Analyze them for spoofing, lookalike domains (typosquatting), redirect chains, and reputation issues.
    
    You have access to tools to perform real-time checks:
    - check_google_safebrowsing: Verify if a URL is flagged for malware, social engineering, or other threats.
    - check_virustotal_reputation: Get the reputation score and malicious/suspicious flag counts for the URL.
    
    Always invoke these tools for any URLs you discover. If no URLs are found, state that clearly.
    Combine tool outputs to provide a comprehensive analysis of URL safety.
    
    Refer to:
    - Orchestrator plan: {orchestrator_guidance}
    - Email Analysis: {email_analysis}
    Raw email/input: {raw_input}
    """,
    tools=[check_virustotal_reputation, check_google_safebrowsing],
    output_key="url_investigation",
)

ioc_extractor = Agent(
    name="ioc_extractor",
    model=model,
    instruction="""
    You are an Indicators of Compromise (IOC) Extractor agent.
    Identify and extract all potential IOCs from the raw input and prior analyses.
    
    You have access to real-time intelligence tools to check the extracted IOCs:
    - check_virustotal_reputation: To get reputation statistics for URLs, domains, or IP addresses.
    - check_abuseipdb_score: To check the abuse confidence score, total reports, country, and ISP of IP addresses.
    - check_google_safebrowsing: To lookup URL safety status.
    
    For all extracted URLs, domains, or IP addresses, you MUST invoke the appropriate tools to retrieve real-time status.
    Compile your findings and the tool results into a structured table or bullet list. Categorize IOCs into:
    1. Email addresses (Senders, Return-Paths, etc.)
    2. Domains and Subdomains
    3. URLs (with safety/reputation details from tools)
    4. IP Addresses (with abuse score/reputation from tools)
    5. Hashes or other relevant technical markers
    
    Refer to:
    - Email Analysis: {email_analysis}
    - URL Investigation: {url_investigation}
    Raw email/input: {raw_input}
    """,
    tools=[
        check_virustotal_reputation,
        check_abuseipdb_score,
        check_google_safebrowsing,
    ],
    output_key="extracted_iocs",
)

threat_assessor = Agent(
    name="threat_assessor",
    model=model,
    instruction="""
    You are a Threat Risk Assessor agent.
    Synthesize all prior findings to compute a final risk assessment.
    Determine the Threat Risk Level: Low, Medium, High, or Critical.
    Provide a clear, logical justification for the risk score based on:
    - Email Analysis: {email_analysis}
    - URL Investigation: {url_investigation}
    - Extracted IOCs: {extracted_iocs}
    """,
    output_key="threat_assessment",
)

report_generator = Agent(
    name="report_generator",
    model=model,
    instruction="""
    You are the SOC Report Generator agent.
    Compile all findings into a professional, structured markdown Security Operations Center (SOC) investigation report.
    The report MUST contain the following sections:
    1. ## Executive Summary: Summary of the alert, investigation, and final risk level.
    2. ## Threat Assessment & Risk Score: The risk level (Low, Medium, High, Critical) and justification.
    3. ## Email Analysis: Findings from email header and content analysis.
    4. ## URL Investigation: Findings from URL analysis.
    5. ## Extracted IOCs: Table or list of all domains, IPs, URLs, and emails.
    6. ## Recommended Action Items: Next steps for remediation (e.g. block sender, block URL on firewall, reset password, etc.).
    
    Refer to:
    - Orchestrator plan: {orchestrator_guidance}
    - Email Analysis: {email_analysis}
    - URL Investigation: {url_investigation}
    - Extracted IOCs: {extracted_iocs}
    - Threat Assessment: {threat_assessment}
    """,
    output_key="soc_report",
)


def complete_workflow(node_input: str) -> Event:
    """Return the final SOC report directly as a response message to the user."""
    return Event(content=types.Content(parts=[types.Part.from_text(text=node_input)]))


root_agent = Workflow(
    name="sentinel_ai_workflow",
    edges=[
        (
            "START",
            init_state,
            orchestrator,
            email_analyzer,
            url_investigator,
            ioc_extractor,
            threat_assessor,
            report_generator,
            complete_workflow,
        )
    ],
)

app = App(
    root_agent=root_agent,
    name="app",
)
