"""
Health Check API
Provides platform status, dependency status, and observability metrics.
"""

import os
from datetime import datetime

from fastapi import APIRouter
from sqlalchemy import text

from app.schemas.schemas import HealthResponse
from app.models.database import SessionLocal
from app.services.enrichment import _enrichment_db
from app.services.mitre_mapper import get_all_techniques

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Platform Health Check"
)
def health_check():

    services = {}

    # --------------------------------------------------
    # Database Check
    # --------------------------------------------------

    try:
        db = SessionLocal()

        db.execute(text("SELECT 1"))

        services["database"] = "healthy"

        db.close()

    except Exception as e:
        services["database"] = f"error: {str(e)}"

    # --------------------------------------------------
    # Enrichment Database Check
    # --------------------------------------------------

    try:

        cve_count = len(
            _enrichment_db.get("cves", {})
        )

        services["enrichment_db"] = (
            f"healthy ({cve_count} CVEs)"
        )

    except Exception as e:

        services["enrichment_db"] = (
            f"error: {str(e)}"
        )

    # --------------------------------------------------
    # MITRE Database Check
    # --------------------------------------------------

    try:

        techniques = get_all_techniques()

        services["mitre_catalog"] = (
            f"healthy ({len(techniques)} techniques)"
        )

    except Exception as e:

        services["mitre_catalog"] = (
            f"error: {str(e)}"
        )

    # --------------------------------------------------
    # Gemini Status
    # --------------------------------------------------

    services["gemini"] = (
        "configured"
        if os.getenv("GEMINI_API_KEY")
        else "not_configured"
    )

    # --------------------------------------------------
    # Groq Status
    # --------------------------------------------------

    services["groq"] = (
        "configured"
        if os.getenv("GROQ_API_KEY")
        else "not_configured"
    )

    # --------------------------------------------------
    # Overall Status
    # --------------------------------------------------

    overall = "healthy"

    for value in services.values():

        if str(value).startswith("error"):

            overall = "degraded"
            break

    return HealthResponse(
        status=overall,
        version="1.0.0",
        timestamp=datetime.utcnow().isoformat() + "Z",
        services=services,
    )