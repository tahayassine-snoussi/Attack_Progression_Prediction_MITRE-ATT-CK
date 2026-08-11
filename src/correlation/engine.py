from correlationEngine import CorrelationEngine


def correlate_zeek_events(events, correlation_rule):
    engine = CorrelationEngine()

    return engine.correlate(
        events,
        correlation_rule
    )