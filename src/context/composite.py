from .base import ContextProvider


class CompositeContextProvider(ContextProvider):

    def __init__(self):
        self.providers = []

    def register(self, provider: ContextProvider):
        self.providers.append(provider)

    def supports(self, context_key: str) -> bool:

        return any(
            provider.supports(context_key)
            for provider in self.providers
        )

    def resolve(
        self,
        context_key: str,
        event: dict
    ):
        for provider in self.providers:

            if not provider.supports(context_key):
                continue

            return provider.resolve(
                context_key,
                event
            )

        return None