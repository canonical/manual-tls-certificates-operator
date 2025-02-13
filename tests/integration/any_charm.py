from any_charm_base import AnyCharmBase  # type: ignore[import]
from certificate_transfer import (  # type: ignore[import]
    CertificateTransferRequires,
)
from ops.charm import CollectStatusEvent
from ops.model import ActiveStatus, WaitingStatus


class AnyCharm(AnyCharmBase):
    def __init__(self, *args, **kwargs):  # type: ignore
        super().__init__(*args, **kwargs)
        self.certificate_transfer = CertificateTransferRequires(
            self,
            "send-ca-cert",
        )
        self.framework.observe(self.on.collect_unit_status, self._on_collect_unit_status)

    def _on_collect_unit_status(self, event: CollectStatusEvent):
        if self.certificate_transfer.get_all_certificates():
            event.add_status(ActiveStatus("Received trust certificate"))
            return
        event.add_status(WaitingStatus("Waiting for certificate"))
