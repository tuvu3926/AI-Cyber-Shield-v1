"""CSV-backed repositories with append-only writes."""

from __future__ import annotations

import csv
from pathlib import Path
from threading import Lock
from typing import Any


CSV_INJECTION_PREFIXES = ("=", "+", "-", "@", "\t", "\r", "\n")


class CsvRepository:
    """Small append-oriented CSV repository.

    This avoids the previous read/concat/write pattern, which rewrote the full
    file on every request and became slow as history grew.
    """

    def __init__(self, path: Path, columns: list[str]) -> None:
        self.path = Path(path)
        self.columns = columns
        self._lock = Lock()
        self.ensure_exists()

    def ensure_exists(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            with self.path.open("w", newline="", encoding="utf-8") as handle:
                csv.DictWriter(handle, fieldnames=self.columns).writeheader()

    def append(self, record: dict[str, Any]) -> None:
        self.ensure_exists()
        row = {column: self._sanitize(record.get(column, "")) for column in self.columns}
        with self._lock:
            with self.path.open("a", newline="", encoding="utf-8") as handle:
                csv.DictWriter(handle, fieldnames=self.columns).writerow(row)

    def list_records(self, limit: int | None = None) -> list[dict[str, str]]:
        self.ensure_exists()
        with self.path.open("r", newline="", encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        if limit is not None and limit > 0:
            return rows[-limit:]
        return rows

    @staticmethod
    def _sanitize(value: Any) -> Any:
        if not isinstance(value, str):
            return value
        if value.startswith(CSV_INJECTION_PREFIXES):
            return f"'{value}"
        return value
    def clear(self) -> None:
        """Clear all records but keep header."""
        with self._lock:
            with self.path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=self.columns)
                writer.writeheader()
                def clear(self) -> None:
                    """Clear all records but keep header."""
        with self._lock:
            # Ghi đè file chỉ với header
            with self.path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(handle, fieldnames=self.columns)
                writer.writeheader()
    
    def delete_all(self) -> int:
        """Delete all records. Returns number of records deleted."""
        records_before = self.list_records()
        count = len(records_before)
        self.clear()
        return count
    
    def get_record_count(self) -> int:
        """Get total number of records."""
        return len(self.list_records())