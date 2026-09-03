"""Tests for repeated scenario execution.

Verifies that each scenario run creates:
- New events with unique IDs
- New alerts with unique IDs
- New incidents with unique IDs
- Dynamic timestamps
- Proper isolation between runs
"""

import pytest
from sqlalchemy.orm import Session

from app.demo.service import DemoOrchestrator
from app.models.event import Event
from app.models.alert import Alert
from app.models.incident import Incident


def _events_for_run(db: Session, demo_run_id: str):
    """Filter events by _demo_run_id in payload (SQLite-compatible)."""
    return [
        e for e in db.query(Event).all()
        if e.payload.get("_demo_run_id") == demo_run_id
    ]


def test_first_scenario_execution(db_session: Session):
    """First scenario run should create new telemetry."""
    orchestrator = DemoOrchestrator()
    result = orchestrator.run(db_session)

    assert result.events_created == 6
    assert result.alerts_created >= 6
    assert result.incidents_created >= 1
    assert result.primary_incident_id is not None
    assert result.demo_run_id is not None

    # Verify events were persisted
    events = _events_for_run(db_session, result.demo_run_id)
    assert len(events) == 6

    # Verify all events have unique IDs
    event_ids = [e.id for e in events]
    assert len(event_ids) == len(set(event_ids))

    # Verify timestamps are dynamic (within last 15 minutes to account for offsets)
    from datetime import datetime, timedelta
    now = datetime.utcnow()
    for event in events:
        assert event.timestamp > now - timedelta(minutes=15)
        assert event.timestamp < now + timedelta(minutes=15)


def test_second_scenario_execution(db_session: Session):
    """Second scenario run should create NEW telemetry, not reuse old."""
    # Run first scenario
    orchestrator1 = DemoOrchestrator()
    result1 = orchestrator1.run(db_session)

    # Record state after first run
    events_after_first = db_session.query(Event).count()
    alerts_after_first = db_session.query(Alert).count()
    incidents_after_first = db_session.query(Incident).count()

    # Run second scenario
    orchestrator2 = DemoOrchestrator()
    result2 = orchestrator2.run(db_session)

    # Verify new telemetry was created
    assert result2.demo_run_id != result1.demo_run_id
    assert result2.primary_incident_id != result1.primary_incident_id

    # Verify database grew
    events_after_second = db_session.query(Event).count()
    alerts_after_second = db_session.query(Alert).count()
    incidents_after_second = db_session.query(Incident).count()

    assert events_after_second > events_after_first
    assert alerts_after_second > alerts_after_first
    # Note: incidents may not increase if old ones are closed and new ones created
    # The key is that we have a NEW incident ID

    # Verify second run's events are distinct from first run's events
    events_run1 = _events_for_run(db_session, result1.demo_run_id)
    events_run2 = _events_for_run(db_session, result2.demo_run_id)

    event_ids_run1 = {e.id for e in events_run1}
    event_ids_run2 = {e.id for e in events_run2}

    # No overlap in event IDs
    assert len(event_ids_run1 & event_ids_run2) == 0


def test_third_scenario_execution(db_session: Session):
    """Third scenario run should also create NEW telemetry."""
    # Run two scenarios first
    orchestrator1 = DemoOrchestrator()
    result1 = orchestrator1.run(db_session)

    orchestrator2 = DemoOrchestrator()
    result2 = orchestrator2.run(db_session)

    # Run third scenario
    orchestrator3 = DemoOrchestrator()
    result3 = orchestrator3.run(db_session)

    # All three should have unique IDs
    assert result1.demo_run_id != result2.demo_run_id
    assert result2.demo_run_id != result3.demo_run_id
    assert result1.demo_run_id != result3.demo_run_id

    assert result1.primary_incident_id != result2.primary_incident_id
    assert result2.primary_incident_id != result3.primary_incident_id
    assert result1.primary_incident_id != result3.primary_incident_id

    # Verify all three sets of events exist
    for run_id in [result1.demo_run_id, result2.demo_run_id, result3.demo_run_id]:
        events = _events_for_run(db_session, run_id)
        assert len(events) == 6


def test_scenario_creates_unique_event_ids(db_session: Session):
    """Each scenario run must generate unique event IDs."""
    orchestrator = DemoOrchestrator()

    # Run scenario 3 times
    results = []
    all_event_ids = set()

    for _ in range(3):
        result = orchestrator.run(db_session)
        results.append(result)

        events = _events_for_run(db_session, result.demo_run_id)

        for event in events:
            # Each event ID should be unique across all runs
            assert event.id not in all_event_ids
            all_event_ids.add(event.id)


def test_scenario_creates_unique_alert_ids(db_session: Session):
    """Each scenario run must generate unique alert IDs."""
    orchestrator = DemoOrchestrator()

    all_alert_ids = set()

    for _ in range(3):
        result = orchestrator.run(db_session)

        # Get alerts created in this run (they reference events from this run)
        events = _events_for_run(db_session, result.demo_run_id)
        event_ids = {e.id for e in events}

        alerts = db_session.query(Alert).filter(Alert.event_id.in_(event_ids)).all()

        for alert in alerts:
            # Each alert ID should be unique across all runs
            assert alert.id not in all_alert_ids
            all_alert_ids.add(alert.id)


def test_scenario_creates_unique_incident_ids(db_session: Session):
    """Each scenario run must create a new incident with unique ID."""
    orchestrator = DemoOrchestrator()

    incident_ids = []

    for _ in range(3):
        result = orchestrator.run(db_session)
        assert result.primary_incident_id is not None
        incident_ids.append(result.primary_incident_id)

    # All incident IDs should be unique
    assert len(incident_ids) == len(set(incident_ids))


def test_scenario_uses_dynamic_timestamps(db_session: Session):
    """Each scenario run must use current timestamps, not hardcoded ones."""
    from datetime import datetime, timedelta

    orchestrator = DemoOrchestrator()
    result = orchestrator.run(db_session)

    events = _events_for_run(db_session, result.demo_run_id)

    now = datetime.utcnow()

    for event in events:
        # Timestamps should be within a reasonable window (scenario uses 0-10 min offsets)
        assert event.timestamp > now - timedelta(minutes=15)
        assert event.timestamp < now + timedelta(minutes=15)


def test_scenario_persists_events(db_session: Session):
    """Events must be persisted to database, not just in memory."""
    orchestrator = DemoOrchestrator()

    events_before = db_session.query(Event).count()

    result = orchestrator.run(db_session)

    events_after = db_session.query(Event).count()

    # Database should have grown
    assert events_after == events_before + result.events_created

    # Verify we can query the events
    events = _events_for_run(db_session, result.demo_run_id)
    assert len(events) == result.events_created


def test_scenario_detects_new_events(db_session: Session):
    """Detection must process the newly generated events."""
    orchestrator = DemoOrchestrator()

    alerts_before = db_session.query(Alert).count()

    result = orchestrator.run(db_session)

    alerts_after = db_session.query(Alert).count()

    # New alerts should have been created
    assert alerts_after > alerts_before
    assert result.alerts_created > 0


def test_scenario_correlates_new_alerts(db_session: Session):
    """Correlation must create incidents from the new alerts."""
    orchestrator = DemoOrchestrator()

    result = orchestrator.run(db_session)

    # Should have created at least one incident
    assert result.incidents_created >= 1
    assert result.primary_incident_id is not None

    # Verify the incident exists
    incident = db_session.query(Incident).filter(
        Incident.id == result.primary_incident_id
    ).first()
    assert incident is not None
    assert incident.alert_count > 0


def test_old_incidents_closed_before_new_run(db_session: Session):
    """Previous open incidents should be closed before a new run."""
    orchestrator = DemoOrchestrator()

    # Run first scenario
    result1 = orchestrator.run(db_session)
    incident1 = db_session.query(Incident).filter(
        Incident.id == result1.primary_incident_id
    ).first()
    assert incident1.status == "new"

    # Run second scenario
    result2 = orchestrator.run(db_session)

    # First incident should now be closed
    db_session.refresh(incident1)
    assert incident1.status == "closed"

    # Second incident should be new
    incident2 = db_session.query(Incident).filter(
        Incident.id == result2.primary_incident_id
    ).first()
    assert incident2.status == "new"
