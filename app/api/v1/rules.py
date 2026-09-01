from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.schemas import RuleCreate, RuleResponse
from app.services import RuleService

router = APIRouter(prefix="/rules", tags=["rules"])


@router.post("/", response_model=RuleResponse, status_code=201)
async def create_rule(rule: RuleCreate, db: Session = Depends(get_db)):
    existing = RuleService.get_rule_by_name(db, rule.name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Rule with name '{rule.name}' already exists",
        )
    return RuleService.create_rule(db, rule)


@router.get("/", response_model=List[RuleResponse])
async def list_rules(
    skip: int = 0,
    limit: int = 100,
    enabled_only: bool = False,
    db: Session = Depends(get_db),
):
    return RuleService.get_rules(db, skip=skip, limit=limit, enabled_only=enabled_only)


@router.get("/{rule_id}", response_model=RuleResponse)
async def get_rule(rule_id: str, db: Session = Depends(get_db)):
    rule = RuleService.get_rule(db, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@router.put("/{rule_id}", response_model=RuleResponse)
async def update_rule(rule_id: str, rule: RuleCreate, db: Session = Depends(get_db)):
    updated = RuleService.update_rule(db, rule_id, rule)
    if not updated:
        raise HTTPException(status_code=404, detail="Rule not found")
    return updated


@router.delete("/{rule_id}", status_code=204)
async def delete_rule(rule_id: str, db: Session = Depends(get_db)):
    if not RuleService.delete_rule(db, rule_id):
        raise HTTPException(status_code=404, detail="Rule not found")


@router.patch("/{rule_id}/toggle", response_model=RuleResponse)
async def toggle_rule(rule_id: str, enabled: bool, db: Session = Depends(get_db)):
    rule = RuleService.toggle_rule(db, rule_id, enabled)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule
