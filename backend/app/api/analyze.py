"""
Threat Analysis API
"""

import json
import uuid
from datetime import datetime
from fastapi import UploadFile, File, Form
import tempfile
import os

from app.services.file_parser import extract_text_from_file

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)

from sqlalchemy.orm import Session

from app.models.database import (
    Analysis,
    get_db,
)

from app.schemas.schemas import (
    ThreatAnalysisRequest,
    ThreatAnalysisResponse,
)

from app.services.ioc_extractor import (
    extract_iocs,
)

from app.services.enrichment import (
    enrich_iocs,
)

from app.services.mitre_mapper import (
    map_to_mitre,
)

from app.services.risk_scoring import (
    calculate_risk,
)

from app.services.ai_report_generator import (
    generate_ai_report,
)

from app.services.detection_rules import (
    generate_detection_rules,
)

router = APIRouter()


@router.post(
    "/analyze-threat",
    response_model=ThreatAnalysisResponse
)
def analyze_threat(
    request: ThreatAnalysisRequest,
    db: Session = Depends(get_db)
):

    try:

        # ----------------------------------
        # IOC Extraction
        # ----------------------------------

        iocs = extract_iocs(
            request.content
        )

        # ----------------------------------
        # Enrichment
        # ----------------------------------

        enrichment = enrich_iocs(
            iocs
        )

        # ----------------------------------
        # MITRE Mapping
        # ----------------------------------

        mitre_mapping = map_to_mitre(
            text=request.content,
            iocs=iocs,
            enrichment=enrichment,
        )

        # ----------------------------------
        # Risk Scoring
        # ----------------------------------

        risk_score, risk_level, risk_factors = (
            calculate_risk(
                iocs,
                enrichment
            )
        )

        # ----------------------------------
        # AI Report
        # ----------------------------------

        ai_report = generate_ai_report(
            raw_text=request.content,
            iocs=iocs,
            enrichment=enrichment,
            mitre_techniques=mitre_mapping,
            risk_score=risk_score,
            risk_level=risk_level,
            risk_factors=risk_factors,
        )

        # ----------------------------------
        # Detection Rules
        # ----------------------------------

        detection_rules = (
            generate_detection_rules(
                iocs,
                mitre_mapping,
            )
        )

        # ----------------------------------
        # Save to Database
        # ----------------------------------

        analysis_id = str(
            uuid.uuid4()
        )

        db_record = Analysis(
            id=analysis_id,
            input_type=request.input_type,
            input_preview=request.content[:250],
            risk_score=risk_score,
            risk_level=risk_level,
            iocs_count=len(iocs),
            mitre_count=len(mitre_mapping),

            iocs_json=json.dumps(
                [i.model_dump() for i in iocs]
            ),

            enrichment_json=json.dumps(
                enrichment.model_dump()
            ),

            mitre_mapping_json=json.dumps(
                [m.model_dump() for m in mitre_mapping]
            ),

            risk_factors_json=json.dumps(
                [r.model_dump() for r in risk_factors]
            ),

            ai_report_json=json.dumps(
                ai_report.model_dump()
            ),

            detection_rules_json=json.dumps(
                detection_rules.model_dump()
            ),
        )

        db.add(db_record)
        db.commit()

        return ThreatAnalysisResponse(
            analysis_id=analysis_id,
            timestamp=datetime.utcnow().isoformat() + "Z",
            iocs=iocs,
            enrichment=enrichment,
            mitre_mapping=mitre_mapping,
            risk_score=risk_score,
            risk_level=risk_level,
            risk_factors=risk_factors,
            ai_report=ai_report,
            detection_rules=detection_rules,
        )

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )

@router.post("/analyze-threat/upload")
async def analyze_uploaded_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):

    suffix = os.path.splitext(file.filename)[1]

    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=suffix
    ) as temp_file:

        content = await file.read()

        temp_file.write(content)

        temp_path = temp_file.name

    try:

        extracted_text = extract_text_from_file(
            temp_path
        )

        return analyze_threat(
            ThreatAnalysisRequest(
                input_type="file",
                content=extracted_text
            ),
            db
        )

    finally:

        if os.path.exists(temp_path):
            os.remove(temp_path)