"""
Analysis History APIs
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.models.database import Analysis, get_db
from app.schemas.schemas import (
    AnalysisSummary,
    AnalysisHistoryResponse,
)

router = APIRouter()


@router.get(
    "/analyses",
    response_model=AnalysisHistoryResponse
)
def list_analyses(
    page: int = 1,
    page_size: int = 10,
    db: Session = Depends(get_db)
):

    query = db.query(Analysis)

    total = query.count()

    records = (
        query
        .order_by(Analysis.timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return AnalysisHistoryResponse(
        total=total,
        page=page,
        page_size=page_size,
        analyses=[
            AnalysisSummary(**r.to_summary())
            for r in records
        ]
    )


@router.get("/analyses/{analysis_id}")
def get_analysis(
    analysis_id: str,
    db: Session = Depends(get_db)
):

    record = (
        db.query(Analysis)
        .filter(Analysis.id == analysis_id)
        .first()
    )

    if not record:
        raise HTTPException(
            status_code=404,
            detail="Analysis not found"
        )

    return record.to_dict()