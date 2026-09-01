"""Rule-related service operations."""

from typing import Optional
from sqlalchemy.orm import Session
from app.models.rule import Rule
from app.schemas import RuleCreate


class RuleService:
    @staticmethod
    def create_rule(db: Session, rule_data: RuleCreate) -> Rule:
        db_rule = Rule(**rule_data.model_dump())
        db.add(db_rule)
        db.commit()
        db.refresh(db_rule)
        return db_rule

    @staticmethod
    def get_rule(db: Session, rule_id: str) -> Optional[Rule]:
        return db.query(Rule).filter(Rule.id == rule_id).first()

    @staticmethod
    def get_rule_by_name(db: Session, name: str) -> Optional[Rule]:
        return db.query(Rule).filter(Rule.name == name).first()

    @staticmethod
    def get_rules(db: Session, skip: int = 0, limit: int = 100, enabled_only: bool = False):
        query = db.query(Rule)
        if enabled_only:
            query = query.filter(Rule.enabled == True)  # noqa: E712
        return query.order_by(Rule.created_at.desc()).offset(skip).limit(limit).all()

    @staticmethod
    def update_rule(db: Session, rule_id: str, rule_data: RuleCreate) -> Optional[Rule]:
        db_rule = db.query(Rule).filter(Rule.id == rule_id).first()
        if not db_rule:
            return None
        for key, value in rule_data.model_dump().items():
            setattr(db_rule, key, value)
        db.commit()
        db.refresh(db_rule)
        return db_rule

    @staticmethod
    def delete_rule(db: Session, rule_id: str) -> bool:
        db_rule = db.query(Rule).filter(Rule.id == rule_id).first()
        if not db_rule:
            return False
        db.delete(db_rule)
        db.commit()
        return True

    @staticmethod
    def toggle_rule(db: Session, rule_id: str, enabled: bool) -> Optional[Rule]:
        db_rule = db.query(Rule).filter(Rule.id == rule_id).first()
        if not db_rule:
            return None
        db_rule.enabled = enabled
        db.commit()
        db.refresh(db_rule)
        return db_rule
