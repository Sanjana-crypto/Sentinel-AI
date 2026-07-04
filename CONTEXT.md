# Sentinel AI

## Project Purpose
`sentinel-ai` is a security-oriented multi-agent cyber investigation workflow built on Google's ADK (Agent Development Kit) 2.0 framework. It automates Security Operations Center (SOC) investigation tasks when analyzing potential phishing emails or suspicious URLs.

The project leverages a sequential multi-agent graph containing the following nodes:
1.  **Orchestrator**: Master agent that structures the investigation plan.
2.  **Email Analyzer**: Analyzes email headers (e.g. SPF, DKIM, DMARC) and body contents for phishing indicators.
3.  **URL Investigator**: Assesses suspect URLs for typosquatting, lookalike domains, and redirection.
4.  **IOC Extractor**: Extracts technical Indicators of Compromise (IPs, domains, hashes, etc.) into structured tables.
5.  **Threat Assessor**: Scores the risk level (Low, Medium, High, Critical) with a logical justification.
6.  **Report Generator**: Compiles all findings into a standardized SOC markdown report.

---

## Coding Standards

### 1. Framework Alignment
*   Use ADK 2.0 graph structures (`Workflow`, `Agent`, `Event`) for orchestrating agent interactions.
*   Prefer top-level imports from `google.adk` (e.g., `from google.adk import Agent, Workflow, Event`).

### 2. State & Data Handling
*   Avoid direct state manipulation on session objects. Modify the `Event`'s `state` parameter or utilize `output_key` on `Agent` nodes.
*   Use standard curly braces formatting `{state_key}` in agent instructions to reference stored context from previous nodes dynamically.

### 3. Code Quality & Format
*   Use type hints for all function signatures and parameters.
*   Adhere to Python coding standards checkable with `ruff`.
*   Maintain clean, self-documenting code with comprehensive docstrings.

### 4. Environments & Credentials
*   Do not hardcode API credentials or environment secrets.
*   Use a `.env` file for local development settings.
