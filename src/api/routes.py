from typing import List, Literal, Dict, Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.utils.config import config
from src.utils.logger import get_logger
from src.core.rule_parser import RuleParser
from src.core.attack_mapper import AttackMapper
from src.core.coverage_engine import CoverageEngine

logger = get_logger(__name__)
router = APIRouter()

class RuleInput(BaseModel):
    name: str = Field(..., description="Human-readable rule name")
    query: str = Field(..., description="Detection rule query (KQL, SPL, etc.)")

class AnalyzeRequest(BaseModel):
    platform: Literal["sentinel", "splunk", "generic"] = Field(..., description="Rule source platform")
    rules: List[RuleInput]

class TechniqueOut(BaseModel):
    id: str
    name: str
    confidence: float

class RuleMappingOut(BaseModel):
    rule_name: str
    platform: str
    techniques: List[TechniqueOut]

class CoverageItemOut(BaseModel):
    technique_id: str
    technique_name: str
    rule_count: int
    rules: List[str]

class AnalyzeResponse(BaseModel):
    mappings: List[RuleMappingOut]
    coverage_summary: Dict[str, Any]

@router.get("/health")
async def health_check():
    try:
        config.validate()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    return {"status": "ok"}

@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_rules(payload: AnalyzeRequest):
    """
    Analyze rules:
    - Parse rules
    - Map to ATT&CK via GPT-4
    - Compute coverage summary
    """
    try:
        config.validate()
    except Exception as e:
        logger.error(f"Config validation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    parser = RuleParser()
    mapper = AttackMapper()
    coverage_engine = CoverageEngine()

    parsed_rules = []
    for r in payload.rules:
        parsed = parser.parse(name=r.name, query=r.query, platform=payload.platform)
        parsed_rules.append(parsed)

    mappings_raw = await mapper.map_rules(parsed_rules)
    mappings: List[RuleMappingOut] = []
    for m in mappings_raw:
        mappings.append(
            RuleMappingOut(
                rule_name=m["rule_name"],
                platform=m["platform"],
                techniques=[
                    TechniqueOut(
                        id=t["id"],
                        name=t.get("name", ""),
                        confidence=float(t.get("confidence", 0.0)),
                    )
                    for t in m.get("techniques", [])
                    if t.get("id")
                ],
            )
        )

    coverage_summary = coverage_engine.build_coverage(
        [
            {
                "rule_name": mr.rule_name,
                "platform": mr.platform,
                "techniques": [
                    {"id": t.id, "name": t.name, "confidence": t.confidence}
                    for t in mr.techniques
                ],
            }
            for mr in mappings
        ]
    )

    return AnalyzeResponse(
        mappings=mappings,
        coverage_summary=coverage_summary,
    )
