# Aegis — Behavioral Liability & Assurance Platform
# Copyright (C) 2026 Aegis Project Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

"""Tool bucketing taxonomy — MCP/OpenClaw tool classification by skill type.

Skills declare which tools they need (read, write, web_fetch, sessions_spawn, etc.).
This module maps tool names to three security/operational buckets per skill type:

  - Core Operational Primitives (Expected): Fundamental tools required for the skill.
  - Contextual Enhancers (Atypical but useful): Tools for complex edge cases.
  - High-Risk / Anomalous Vectors (Warning): Severe deviations; poor config or security risk.

Used by the integrity pipeline to flag tool overreach when a skill requests tools
that are anomalous for its classified type.
"""

from __future__ import annotations

from dataclasses import dataclass


# ── Known MCP/OpenClaw tool names (canonical set for reference) ─────────────
# read, write, edit, apply_patch, exec, process, web_fetch, web_search,
# browser, image, canvas, lobster, llm_task, memory_search, memory_get,
# sessions_spawn, sessions_list, sessions_history, session_status, sessions_send,
# agents_list, message, nodes, cron, gateway


@dataclass(frozen=True)
class ToolBucketProfile:
    """Tool bucketing for a skill category.

    core_tools: Core Operational Primitives — expected, no flag.
    contextual_tools: Contextual Enhancers — atypical but useful, note only.
    high_risk_tools: High-Risk / Anomalous Vectors — warning, security risk.
    """

    name: str
    core_tools: frozenset[str]
    contextual_tools: frozenset[str]
    high_risk_tools: frozenset[str]


TOOL_BUCKET_TAXONOMY: dict[str, ToolBucketProfile] = {
    "data-science": ToolBucketProfile(
        name="Data Science / ML",
        core_tools=frozenset({
            "read", "write", "edit", "exec", "process", "web_fetch",
            "canvas", "image", "lobster", "llm_task",
        }),
        contextual_tools=frozenset({
            "web_search", "browser", "memory_search", "memory_get",
            "sessions_spawn", "sessions_list", "sessions_history", "session_status",
            "agents_list",
        }),
        high_risk_tools=frozenset({
            "apply_patch", "message", "nodes", "cron", "gateway", "sessions_send",
        }),
    ),
    "browser-automation": ToolBucketProfile(
        name="Browser Automation",
        core_tools=frozenset({
            "browser", "read", "write", "web_search", "web_fetch", "image",
        }),
        contextual_tools=frozenset({
            "edit", "canvas", "memory_search", "memory_get",
            "sessions_list", "session_status", "sessions_history",
            "lobster", "llm_task", "cron",
        }),
        high_risk_tools=frozenset({
            "apply_patch", "exec", "process", "sessions_spawn", "sessions_send",
            "message", "nodes", "gateway", "agents_list",
        }),
    ),
    "api-integration": ToolBucketProfile(
        name="API Integration",
        core_tools=frozenset({
            "web_fetch", "read", "write", "lobster", "llm_task",
        }),
        contextual_tools=frozenset({
            "edit", "exec", "memory_search", "memory_get",
            "sessions_list", "session_status", "sessions_history",
            "cron", "canvas",
        }),
        high_risk_tools=frozenset({
            "apply_patch", "web_search", "browser", "image",
            "sessions_spawn", "sessions_send", "message", "nodes", "gateway",
            "process", "agents_list",
        }),
    ),
    "devtools": ToolBucketProfile(
        name="Developer Tools",
        core_tools=frozenset({
            "read", "write", "edit", "apply_patch", "exec", "process",
            "web_search", "web_fetch",
            "sessions_spawn", "sessions_send", "sessions_history",
        }),
        contextual_tools=frozenset({
            "canvas", "memory_search", "memory_get",
            "sessions_list", "session_status", "agents_list",
            "lobster", "llm_task",
        }),
        high_risk_tools=frozenset({
            "browser", "image", "message", "nodes", "cron", "gateway",
        }),
    ),
    "document-processing": ToolBucketProfile(
        name="Document Processing",
        core_tools=frozenset({
            "read", "write", "edit", "image", "llm_task", "web_fetch",
        }),
        contextual_tools=frozenset({
            "canvas", "memory_search", "memory_get",
            "sessions_list", "session_status", "sessions_history",
            "lobster", "browser",
        }),
        high_risk_tools=frozenset({
            "apply_patch", "exec", "process", "web_search",
            "sessions_spawn", "sessions_send", "message", "nodes", "cron",
            "gateway", "agents_list",
        }),
    ),
    "system-ops": ToolBucketProfile(
        name="System Operations",
        core_tools=frozenset({
            "read", "exec", "process", "nodes", "cron", "gateway",
            "web_fetch", "lobster",
        }),
        contextual_tools=frozenset({
            "write", "edit", "browser", "canvas",
            "memory_search", "memory_get",
            "sessions_list", "sessions_history", "session_status",
            "llm_task",
        }),
        high_risk_tools=frozenset({
            "apply_patch", "web_search", "image",
            "sessions_spawn", "sessions_send", "message", "agents_list",
        }),
    ),
    "communication": ToolBucketProfile(
        name="Communication",
        core_tools=frozenset({
            "message", "read", "write", "web_search", "web_fetch",
            "cron", "lobster", "llm_task",
        }),
        contextual_tools=frozenset({
            "edit", "browser", "image", "canvas",
            "memory_search", "memory_get",
            "sessions_list", "sessions_history", "session_status",
            "sessions_send", "agents_list",
        }),
        high_risk_tools=frozenset({
            "apply_patch", "exec", "process", "nodes", "gateway",
            "sessions_spawn",
        }),
    ),
    "crypto-web3": ToolBucketProfile(
        name="Crypto / Web3",
        core_tools=frozenset({
            "web_fetch", "write", "exec", "read", "cron", "message", "lobster",
        }),
        contextual_tools=frozenset({
            "browser", "edit", "memory_search", "memory_get",
            "sessions_list", "session_status", "sessions_history",
            "llm_task", "canvas",
        }),
        high_risk_tools=frozenset({
            "apply_patch", "web_search", "process", "image",
            "nodes", "gateway", "sessions_spawn", "sessions_send", "agents_list",
        }),
    ),
    "security": ToolBucketProfile(
        name="Security",
        core_tools=frozenset({
            "read", "exec", "process", "web_fetch", "sessions_history", "llm_task",
        }),
        contextual_tools=frozenset({
            "write", "edit", "web_search", "browser", "canvas",
            "memory_search", "memory_get",
            "sessions_list", "session_status", "lobster",
        }),
        high_risk_tools=frozenset({
            "apply_patch", "image", "sessions_spawn", "sessions_send",
            "message", "nodes", "cron", "gateway", "agents_list",
        }),
    ),
    "finance": ToolBucketProfile(
        name="Finance",
        core_tools=frozenset({
            "web_fetch", "read", "write", "cron", "lobster", "llm_task",
        }),
        contextual_tools=frozenset({
            "edit", "browser", "canvas", "memory_search", "memory_get",
            "sessions_list", "session_status", "sessions_history",
            "exec", "web_search",
        }),
        high_risk_tools=frozenset({
            "apply_patch", "process", "image",
            "sessions_spawn", "sessions_send", "message", "nodes",
            "gateway", "agents_list",
        }),
    ),
    "database": ToolBucketProfile(
        name="Database",
        core_tools=frozenset({
            "read", "write", "exec", "web_fetch", "lobster",
        }),
        contextual_tools=frozenset({
            "edit", "memory_search", "memory_get",
            "sessions_list", "session_status", "sessions_history",
            "llm_task", "canvas",
        }),
        high_risk_tools=frozenset({
            "apply_patch", "process", "web_search", "browser", "image",
            "sessions_spawn", "sessions_send", "message", "nodes",
            "cron", "gateway", "agents_list",
        }),
    ),
    "ai-agents": ToolBucketProfile(
        name="AI Agents / Orchestration",
        core_tools=frozenset({
            "sessions_list", "sessions_history", "session_status",
            "sessions_send", "sessions_spawn", "agents_list",
            "llm_task", "lobster", "message",
        }),
        contextual_tools=frozenset({
            "read", "write", "edit", "memory_search", "memory_get", "canvas",
            "web_fetch", "web_search",  # Agents may fetch as part of tool use
        }),
        high_risk_tools=frozenset({
            "apply_patch", "exec", "process", "browser", "image",
            "nodes", "cron", "gateway",
        }),
    ),
    "research": ToolBucketProfile(
        name="Research / Education",
        core_tools=frozenset({
            "web_search", "web_fetch", "read", "write",
            "memory_search", "memory_get", "browser", "llm_task", "image",
        }),
        contextual_tools=frozenset({
            "edit", "canvas", "sessions_list", "session_status", "sessions_history",
            "lobster", "cron",
        }),
        high_risk_tools=frozenset({
            "apply_patch", "exec", "process",
            "sessions_spawn", "sessions_send", "message", "nodes",
            "gateway", "agents_list",
        }),
    ),
    "infrastructure": ToolBucketProfile(
        name="Infrastructure / DevOps",
        core_tools=frozenset({
            "exec", "read", "write", "edit", "process", "web_fetch", "gateway",
        }),
        contextual_tools=frozenset({
            "memory_search", "memory_get",
            "sessions_list", "session_status", "sessions_history",
            "canvas", "lobster", "llm_task", "cron",
        }),
        high_risk_tools=frozenset({
            "apply_patch", "web_search", "browser", "image",
            "sessions_spawn", "sessions_send", "message", "nodes", "agents_list",
        }),
    ),
}

# General/fallback: all high-impact tools are suspicious when unclassified
_ALL_HIGH_RISK_TOOLS = frozenset({
    "apply_patch", "exec", "process", "sessions_spawn", "sessions_send",
    "message", "nodes", "gateway", "agents_list", "browser",
})

DEFAULT_TOOL_PROFILE = ToolBucketProfile(
    name="General Purpose",
    core_tools=frozenset(),
    contextual_tools=frozenset(),
    high_risk_tools=_ALL_HIGH_RISK_TOOLS,
)


def compute_tool_overreach(
    *,
    declared_tools: list[str],
    skill_category: str,
    tool_profile: ToolBucketProfile | None = None,
) -> list[str]:
    """Compute tool overreach — tools anomalous for this skill type.

    Returns list of one-line messages. Tone: curious, worth double-checking.
    Only high_risk_tools produce messages; contextual_tools are noted but not flagged.
    """
    if not declared_tools:
        return []

    profile = tool_profile or TOOL_BUCKET_TAXONOMY.get(
        skill_category, DEFAULT_TOOL_PROFILE
    )
    declared_set = {t.strip().lower() for t in declared_tools if t}

    # Only flag tools in high_risk_tools
    anomalous = declared_set & profile.high_risk_tools
    if not anomalous:
        return []

    category_display = profile.name
    messages = []
    for tool in sorted(anomalous):
        msg = (
            f"This {category_display} skill requests tool '{tool}'. "
            "Unusual for this type — worth double-checking."
        )
        messages.append(msg)
    return messages


def get_tool_profile(skill_category: str) -> ToolBucketProfile:
    """Return the tool bucket profile for a skill category."""
    return TOOL_BUCKET_TAXONOMY.get(skill_category, DEFAULT_TOOL_PROFILE)
