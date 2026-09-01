"""Regression coverage for detection batch accounting."""

import pytest

from app.models.event import Event


def _create_unprocessed_events(db_session, count):
    db_session.add_all(
        [
            Event(
                source="backlog",
                event_type=f"backlog_{index}",
                severity="info",
                payload={},
            )
            for index in range(count)
        ]
    )
    db_session.commit()


@pytest.mark.parametrize(
    ("event_count", "limit", "expected_count"),
    [
        (0, 5, 0),
        (2, 5, 2),
        (3, 3, 3),
        (5, 2, 2),
    ],
)
def test_process_unprocessed_reports_actual_event_count(
    client, db_session, event_count, limit, expected_count
):
    _create_unprocessed_events(db_session, event_count)

    response = client.post(f"/api/v1/detection/process?limit={limit}")

    assert response.status_code == 200
    assert response.json()["processed_count"] == expected_count
    assert (
        db_session.query(Event).filter(Event.processed == True).count()  # noqa: E712
        == expected_count
    )
