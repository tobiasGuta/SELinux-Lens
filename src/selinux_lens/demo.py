"""Fictional AVC fixtures for UI evaluation without elevated access."""

from __future__ import annotations

from datetime import datetime, timezone
from time import time

from .audit import parse_ausearch
from .models import Snapshot


def demo_snapshot() -> Snapshot:
    now = time()
    lines = [
        (
            f'type=AVC msg=audit({now-12:.3f}:101): avc:  denied  {{ read }} for '
            'pid=1200 comm="httpd" name="notes.txt" dev="nvme0n1p3" '
            'scontext=system_u:system_r:httpd_t:s0 '
            'tcontext=unconfined_u:object_r:user_home_t:s0 '
            'tclass=file permissive=0'
        ),
        (
            f'type=AVC msg=audit({now-45:.3f}:102): avc: denied {{ write }} for '
            'pid=2300 comm="container-app" name="shared-data" '
            'scontext=system_u:system_r:container_t:s0:c12,c21 '
            'tcontext=unconfined_u:object_r:default_t:s0 '
            'tclass=dir permissive=0'
        ),
        (
            f'type=USER_AVC msg=audit({now-90:.3f}:103): avc: denied {{ execute }} for '
            'pid=1800 comm="sample-service" name="helper" '
            'scontext=system_u:system_r:sample_service_t:s0 '
            'tcontext=system_u:object_r:bin_t:s0 '
            'tclass=file permissive=1'
        ),
    ]
    return Snapshot(
        "Demo (fictional)",
        parse_ausearch("\n".join(lines)),
        "demo",
        "Demo data is fictional. It does not describe your Fedora system.",
    )
