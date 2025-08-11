import json

import ops
from any_charm_base import AnyCharmBase  # type: ignore[import]
from certificate_transfer import (  # type: ignore[import]
    CertificateTransferRequires,
)

REQUIRES_RELATION_NAME = "require-certificate-transfer"


class AnyCharm(AnyCharmBase):
    def __init__(self, *args, **kwargs):  # type: ignore
        super().__init__(*args, **kwargs)
        self.certificate_transfer = CertificateTransferRequires(
            self,
            REQUIRES_RELATION_NAME,
        )
        self.framework.observe(self.on.collect_unit_status, self._on_collect_unit_status)

    def _on_collect_unit_status(self, event: ops.CollectStatusEvent):
        try:
            rel = self.model.get_relation(REQUIRES_RELATION_NAME)
            rel_data = rel.data.get(rel.units.pop(), None)
            if json.loads(rel_data).pop().get("ca"):
                event.add_status(ops.ActiveStatus("Received trust certificate"))
                return
        except Exception:
            pass
        event.add_status(ops.WaitingStatus("Waiting for certificate"))
