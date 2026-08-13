import ipaddress

from .base import ContextProvider


class NetworkBoundaryProvider(ContextProvider):

    def __init__(
        self,
        internal_ranges=None,
        vpn_ranges=None,
        dmz_ranges=None
    ):

        self.internal_ranges = [
            ipaddress.ip_network(network)
            for network in (internal_ranges or [])
        ]

        self.vpn_ranges = [
            ipaddress.ip_network(network)
            for network in (vpn_ranges or [])
        ]

        self.dmz_ranges = [
            ipaddress.ip_network(network)
            for network in (dmz_ranges or [])
        ]

    # ---------------------------------------------------------
    # SUPPORT
    # ---------------------------------------------------------

    def supports(self, context_key: str) -> bool:

        return context_key.endswith(".location")

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

        ip_field = context_key.replace(
            ".location",
            ""
        )

        ip_string = fields.get(
            ip_field
        )

        if not ip_string:
            return None

        try:
            ip = ipaddress.ip_address(
                ip_string
            )

        except ValueError:
            return None

        # VPN gets priority
        for network in self.vpn_ranges:

            if ip in network:
                return "vpn_zone"

        # DMZ
        for network in self.dmz_ranges:

            if ip in network:
                return "dmz"

        # Internal
        for network in self.internal_ranges:

            if ip in network:
                return "internal"

        # If it is not known internal/VPN/DMZ
        return "external"