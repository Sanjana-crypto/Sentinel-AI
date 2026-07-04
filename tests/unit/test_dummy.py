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
"""Unit tests for sentinel-ai agent structure and workflow."""

from google.adk import Workflow
from google.adk.agents import Agent

from app.agent import (
    app,
    email_analyzer,
    ioc_extractor,
    orchestrator,
    report_generator,
    root_agent,
    threat_assessor,
    url_investigator,
)


def test_agent_definitions() -> None:
    """Test that all 6 agents are correctly defined as ADK Agent nodes."""
    agents = [
        orchestrator,
        email_analyzer,
        url_investigator,
        ioc_extractor,
        threat_assessor,
        report_generator,
    ]
    for agent in agents:
        assert isinstance(agent, Agent)
        assert agent.name is not None
        assert agent.model is not None


def test_agent_output_keys() -> None:
    """Test that all agents have the correct output keys configured for state management."""
    assert orchestrator.output_key == "orchestrator_guidance"
    assert email_analyzer.output_key == "email_analysis"
    assert url_investigator.output_key == "url_investigation"
    assert ioc_extractor.output_key == "extracted_iocs"
    assert threat_assessor.output_key == "threat_assessment"
    assert report_generator.output_key == "soc_report"


def test_workflow_definition() -> None:
    """Test that the root agent is a Workflow and correctly named."""
    assert isinstance(root_agent, Workflow)
    assert root_agent.name == "sentinel_ai_workflow"
    assert app.root_agent == root_agent
