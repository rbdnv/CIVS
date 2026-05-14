from __future__ import annotations

from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import security_service
from app.core.time_utils import utc_now
from app.db.tables import AgentInteraction, SecurityEvent
from app.models.agent import AgentInteractionCompleteRequest, AgentInteractionEvaluateRequest


SENSITIVE_KEYS = {
    "api_key",
    "authorization",
    "cookie",
    "password",
    "private_key",
    "secret",
    "token",
}


class AgentGatewayService:
    """Server-side guard and reporting layer for external AI-agent calls."""

    async def evaluate_interaction(
        self,
        request: AgentInteractionEvaluateRequest,
        db: AsyncSession,
        current_user: Dict[str, Any],
    ) -> AgentInteraction:
        actor_user_id = str(current_user["user_id"])
        profile_snapshot = redact_sensitive_data(request.profile_snapshot)
        checks = self.build_checks(
            profile_snapshot=profile_snapshot,
            request_text=request.request_text,
            intended_tool_action=request.intended_tool_action,
        )
        blocked_checks = [check for check in checks if not check["accepted"]]
        accepted = len(blocked_checks) == 0
        verdict = "ACCEPT" if accepted else "REJECT"
        trust_score = min((check["trust_score"] for check in checks), default=1.0)
        created_at = utc_now()

        interaction = AgentInteraction(
            id=str(uuid.uuid4()),
            civs_user_id=actor_user_id,
            project_name=request.project_name.strip(),
            external_user_id=request.external_user_id,
            external_username=request.external_username,
            session_id=request.session_id,
            profile_snapshot=profile_snapshot,
            request_text=request.request_text,
            checks=checks,
            verdict=verdict,
            trust_score=trust_score,
            classification=verdict,
            blocked=not accepted,
            tool_action=request.intended_tool_action,
            created_at=created_at,
        )

        db.add(interaction)
        if blocked_checks:
            db.add(
                SecurityEvent(
                    event_type="agent_interaction_blocked",
                    severity="high",
                    user_id=actor_user_id,
                    description="CIVS blocked an external AI-agent request before LLM execution.",
                    details={
                        "interaction_id": interaction.id,
                        "project_name": interaction.project_name,
                        "external_user_id": interaction.external_user_id,
                        "session_id": interaction.session_id,
                        "verdict": verdict,
                        "trust_score": trust_score,
                        "blocked_checks": blocked_checks,
                    },
                )
            )
        await db.commit()
        await db.refresh(interaction)
        return interaction

    async def complete_interaction(
        self,
        interaction_id: str,
        request: AgentInteractionCompleteRequest,
        db: AsyncSession,
        current_user: Dict[str, Any],
    ) -> AgentInteraction:
        interaction = await self.get_interaction(interaction_id, db)
        actor_user_id = str(current_user["user_id"])
        actor_role = current_user.get("role", "agent")

        if actor_role != "admin" and interaction.civs_user_id != actor_user_id:
            db.add(
                SecurityEvent(
                    event_type="agent_interaction_completion_denied",
                    severity="medium",
                    user_id=actor_user_id,
                    description="A user attempted to complete an agent interaction owned by another CIVS user.",
                    details={
                        "interaction_id": interaction_id,
                        "owner_user_id": interaction.civs_user_id,
                        "actor_role": actor_role,
                    },
                )
            )
            await db.commit()
            raise PermissionError("Access denied: can only complete your own agent interactions")

        interaction.response_text = request.response_text
        interaction.tool_action = request.tool_action or interaction.tool_action
        interaction.tool_details = redact_sensitive_data(request.tool_details)
        interaction.error = request.error
        interaction.completed_at = utc_now()

        await db.commit()
        await db.refresh(interaction)
        return interaction

    async def get_interaction(self, interaction_id: str, db: AsyncSession) -> AgentInteraction:
        result = await db.execute(
            select(AgentInteraction).where(AgentInteraction.id == interaction_id)
        )
        interaction = result.scalar_one_or_none()
        if interaction is None:
            raise KeyError(interaction_id)
        return interaction

    async def list_interactions(
        self,
        db: AsyncSession,
        *,
        project_name: Optional[str] = None,
        external_user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        blocked: Optional[bool] = None,
        limit: int = 50,
    ) -> List[AgentInteraction]:
        query = select(AgentInteraction)

        if project_name:
            query = query.where(AgentInteraction.project_name == project_name)
        if external_user_id:
            query = query.where(AgentInteraction.external_user_id == external_user_id)
        if session_id:
            query = query.where(AgentInteraction.session_id == session_id)
        if blocked is not None:
            query = query.where(AgentInteraction.blocked == blocked)

        result = await db.execute(
            query.order_by(desc(AgentInteraction.created_at)).limit(limit)
        )
        return list(result.scalars().all())

    def build_checks(
        self,
        *,
        profile_snapshot: Dict[str, Any],
        request_text: str,
        intended_tool_action: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        goal, interests_text = extract_profile_context(profile_snapshot)
        checks = [
            evaluate_text("profile.goal", goal),
            evaluate_text("profile.interests", interests_text),
            evaluate_text("question", request_text),
        ]

        if intended_tool_action:
            checks.append(evaluate_text("intended_tool_action", intended_tool_action))

        return checks


def extract_profile_context(profile_snapshot: Dict[str, Any]) -> tuple[str, str]:
    profile_data = profile_snapshot.get("data", {})
    if not isinstance(profile_data, dict):
        profile_data = {}

    goal = profile_data.get("goal", profile_snapshot.get("goal", ""))
    interests = profile_data.get("interests", profile_snapshot.get("interests", []))

    if isinstance(interests, list):
        interests_text = ", ".join(str(item) for item in interests)
    else:
        interests_text = str(interests or "")

    return str(goal or ""), interests_text


def evaluate_text(label: str, content: Any) -> Dict[str, Any]:
    normalized = str(content or "").strip()

    if not normalized:
        if label == "question":
            return {
                "label": label,
                "content": normalized,
                "accepted": False,
                "classification": "REJECT",
                "trust_score": 0.0,
                "suspicious_patterns": {"invalid_input": ["empty question"]},
                "message": "question: empty requests cannot be sent to the protected AI agent.",
            }

        return {
            "label": label,
            "content": normalized,
            "accepted": True,
            "classification": "ACCEPT",
            "trust_score": 1.0,
            "suspicious_patterns": {},
            "message": f"{label}: suspicious patterns not detected.",
        }

    suspicious_patterns = security_service.check_suspicious_content(normalized)
    accepted = len(suspicious_patterns) == 0

    return {
        "label": label,
        "content": normalized,
        "accepted": accepted,
        "classification": "ACCEPT" if accepted else "REJECT",
        "trust_score": 1.0 if accepted else 0.0,
        "suspicious_patterns": suspicious_patterns,
        "message": (
            f"{label}: suspicious patterns not detected."
            if accepted
            else f"{label}: CIVS detected prompt/memory injection indicators."
        ),
    }


def redact_sensitive_data(value: Any) -> Any:
    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            normalized_key = str(key).lower()
            if normalized_key in SENSITIVE_KEYS or any(part in normalized_key for part in SENSITIVE_KEYS):
                redacted[key] = "***hidden***"
            else:
                redacted[key] = redact_sensitive_data(item)
        return redacted

    if isinstance(value, list):
        return [redact_sensitive_data(item) for item in value]

    return value


def build_evaluate_response(interaction: AgentInteraction) -> Dict[str, Any]:
    checks = interaction.checks or []
    blocked_checks = [check for check in checks if not check.get("accepted", True)]
    accepted = not interaction.blocked

    return {
        "interaction_id": interaction.id,
        "accepted": accepted,
        "blocked": bool(interaction.blocked),
        "verdict": interaction.verdict,
        "classification": interaction.classification,
        "trust_score": interaction.trust_score,
        "checks": checks,
        "blocked_checks": blocked_checks,
        "message": (
            "CIVS allowed the request to reach the protected AI agent."
            if accepted
            else "CIVS blocked the request before it reached the protected AI agent."
        ),
        "created_at": interaction.created_at,
    }


agent_gateway_service = AgentGatewayService()
