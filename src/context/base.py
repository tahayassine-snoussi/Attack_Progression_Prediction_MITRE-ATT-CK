from abc import ABC, abstractmethod
from typing import Any, Optional


class ContextProvider(ABC):

    @abstractmethod
    def supports(self, context_key: str) -> bool:
        """
        Return True if this provider knows how to resolve
        the requested context key.
        """
        pass

    @abstractmethod
    def resolve(
        self,
        context_key: str,
        event: dict
    ) -> Optional[Any]:
        """
        Resolve a context value for the given event.

        Return:
            value -> context successfully resolved
            None  -> context unavailable
        """
        pass