from .schemas import Entity


class EntityMemory:
    def __init__(self) -> None:
        self._entities: list[Entity] = []

    def push(self, entities: list[Entity]) -> None:
        for entity in reversed(entities):
            self._entities = [
                e for e in self._entities if (e.type, e.value) != (entity.type, entity.value)
            ]
            self._entities.insert(0, entity)

    def recent(self, n: int = 10) -> list[Entity]:
        return self._entities[:n]

    def context_block(self) -> str:
        entities = self.recent(10)
        if not entities:
            return ""
        listing = ", ".join(f"{e.type}: {e.value}" for e in entities)
        return f"Known entities from this conversation (newest first): {listing}"

    def clear(self) -> None:
        self._entities = []
