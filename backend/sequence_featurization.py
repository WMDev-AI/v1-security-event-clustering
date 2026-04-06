"""
Temporal sequence windows for sequence encoders (LSTM / Transformer).

Each row i is aligned with event i in the original corpus order. Windows are built
along the time-sorted order of events (by parsed timestamp, stable tie-break by index),
then mapped back so row i uses the last `seq_len` events that precede or equal event i
in that temporal ordering (right-padded at the start of the timeline).
"""
from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

import numpy as np

if TYPE_CHECKING:
    from event_parser import SecurityEvent


_TS_FORMATS = (
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
)


def _event_time_key(event: SecurityEvent, index: int) -> float:
    ts = (event.timestamp or "").strip()
    if not ts:
        return float(index)
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(ts[:26], fmt).timestamp()
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")[:26]).timestamp()
    except ValueError:
        return float(index)


def build_temporal_sequences(
    features: np.ndarray,
    events: list,
    seq_len: int,
) -> np.ndarray:
    """
    Build [N, seq_len, D] float32 tensor aligned with rows of `features`.

    Parameters
    ----------
    features : ndarray, shape [N, D]
    events : list of SecurityEvent (same length as N)
    seq_len : int, >= 1
    """
    if features.ndim != 2:
        raise ValueError("features must be 2D [N, D]")
    n, d = features.shape
    if len(events) != n:
        raise ValueError("events length must match features rows")
    if seq_len < 1:
        raise ValueError("seq_len must be >= 1")

    order = np.argsort([_event_time_key(e, i) for i, e in enumerate(events)], kind="stable")
    inv = np.empty_like(order)
    inv[order] = np.arange(n, dtype=np.int64)

    fs = features[order].astype(np.float32, copy=False)
    out_sorted = np.zeros((n, seq_len, d), dtype=np.float32)

    for i in range(n):
        start = max(0, i - seq_len + 1)
        chunk = fs[start : i + 1]
        L = chunk.shape[0]
        out_sorted[i, seq_len - L :] = chunk

    return out_sorted[inv]


def expand_rows_to_sequences(features: np.ndarray, seq_len: int) -> np.ndarray:
    """
    When no temporal context is available (e.g. prediction on isolated batch),
    repeat each row `seq_len` times: [N, D] -> [N, seq_len, D].
    """
    if features.ndim != 2:
        raise ValueError("features must be 2D")
    x = features[:, np.newaxis, :].astype(np.float32, copy=False)
    return np.broadcast_to(x, (features.shape[0], seq_len, features.shape[1])).copy()
