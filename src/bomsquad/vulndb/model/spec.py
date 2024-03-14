from bomsquad.vulndb.model.openssf import Event
from bomsquad.vulndb.model.openssf import Range


class Spec:
    @classmethod
    def event(cls, event: Event) -> str:
        if event.introduced:
            return f">= {event.introduced}"
        if event.fixed:
            return f"< {event.fixed}"
        if event.last_affected:
            return f">{event.last_affected}"
        if event.limit:
            return f"<= {event.limit}"
        raise ValueError("Invalid event")

    @classmethod
    def range(cls, range: Range) -> str:
        output = []
        for event in range.events:
            output.append(cls.event(event))
        return " and ".join(output)
