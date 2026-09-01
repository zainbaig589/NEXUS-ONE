from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from app.config import settings

engine = create_engine(
    settings.DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in settings.DATABASE_URL else {},
    echo=settings.DEBUG,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db(seed: bool = False):
    from app.models import event, alert, incident, incident_report, rule  # noqa: F401
    Base.metadata.create_all(bind=engine)
    if seed:
        seed_rules()


def seed_rules():
    """Seed the database with default SOC detection rules."""
    from app.models.rule import Rule
    
    db = SessionLocal()
    try:
        # Check if rules already exist
        if db.query(Rule).count() > 0:
            return
        
        default_rules = [
            Rule(
                name="Brute Force Login Detection",
                description="Detects multiple failed login attempts from the same source",
                rule_type="threshold",
                severity="high",
                conditions={
                    "type": "combination",
                    "logic": "and",
                    "conditions": [
                        {
                            "type": "pattern_match",
                            "field": "event_type",
                            "pattern": "failed_login",
                        },
                        {
                            "type": "threshold",
                            "field": "payload.failed_attempts",
                            "operator": "gte",
                            "value": 5,
                        },
                    ],
                },
                enabled=True,
            ),
            Rule(
                name="Suspicious IP Connection",
                description="Detects connections from known suspicious IP ranges",
                rule_type="pattern_match",
                severity="medium",
                conditions={
                    "type": "pattern_match",
                    "field": "payload.src_ip",
                    "pattern": r"^10\.(0|1)\..*",  # Example: 10.0.x.x or 10.1.x.x
                },
                enabled=True,
            ),
            Rule(
                name="Large Data Transfer",
                description="Detects unusually large data transfers that may indicate exfiltration",
                rule_type="threshold",
                severity="critical",
                conditions={
                    "type": "threshold",
                    "field": "payload.bytes_transferred",
                    "operator": "gt",
                    "value": 1000000000,  # 1GB
                },
                enabled=True,
            ),
            Rule(
                name="Privilege Escalation Attempt",
                description="Detects privilege escalation events",
                rule_type="pattern_match",
                severity="high",
                conditions={
                    "type": "pattern_match",
                    "field": "event_type",
                    "pattern": "privilege_escalation",
                },
                enabled=True,
            ),
            Rule(
                name="Malware Detection",
                description="Detects known malware signatures",
                rule_type="pattern_match",
                severity="critical",
                conditions={
                    "type": "combination",
                    "logic": "or",
                    "conditions": [
                        {
                            "type": "pattern_match",
                            "field": "event_type",
                            "pattern": "malware_detected",
                        },
                        {
                            "type": "pattern_match",
                            "field": "payload.signature",
                            "pattern": r".*trojan.*|.*ransomware.*|.*virus.*",
                        },
                    ],
                },
                enabled=True,
            ),
        ]
        
        for rule in default_rules:
            db.add(rule)
        
        db.commit()
    finally:
        db.close()
