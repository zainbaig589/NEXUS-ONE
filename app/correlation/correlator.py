"""Event correlation logic (stub)."""


class EventCorrelator:
    """Applies correlation strategies to link events."""

    def __init__(self, strategy="time_window"):
        self.strategy = strategy

    def process(self, events):
        """Process events using the configured correlation strategy."""
        raise NotImplementedError
