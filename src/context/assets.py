from .base import ContextProvider


class AssetInventoryProvider(ContextProvider):

    def __init__(self, assets=None):

        self.assets = assets or {}

    # ---------------------------------------------------------
    # SUPPORT
    # ---------------------------------------------------------

    def supports(self, context_key: str) -> bool:

        return (
            ".role" in context_key
            or ".category" in context_key
        )

    # ---------------------------------------------------------
    # RESOLVE
    # ---------------------------------------------------------

    def resolve(
        self,
        context_key: str,
        event: dict
    ):

        fields = event.get(
            "decoded_fields",
            {}
        )

        if ".role" in context_key:

            ip_field = context_key.replace(
                ".role",
                ""
            )

            attribute = "role"

        elif ".category" in context_key:

            ip_field = context_key.replace(
                ".category",
                ""
            )

            attribute = "category"

        else:

            return None

        ip = fields.get(
            ip_field
        )

        if not ip:
            return None

        asset = self.assets.get(
            ip
        )

        if not asset:
            return None

        return asset.get(
            attribute
        )