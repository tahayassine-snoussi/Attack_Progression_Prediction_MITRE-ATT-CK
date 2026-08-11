from correlationEngine import CorrelationEngine


def correlate_zeek_events(event, correlation_rule):
    engine = CorrelationEngine()
    events = get_needed_logs(event, correlation_rule)

    return engine.correlate(events, correlation_rule)


# TO FIX 
def get_needed_logs(event, mapping):
    needed_logs = []

    for log_type in mapping["needed_logs"]:
        if log_type in event:
            needed_logs.append(event[log_type])

    return needed_logs
