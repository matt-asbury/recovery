from __future__ import annotations

import os
import sqlite3
import tempfile
from typing import Any, Optional

from recovery.file_list import DEFAULT_MIN_CONFIDENCE, DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from recovery.models import FileCategory, FoundFile, format_bytes

LARGE_RESULT_THRESHOLD = 5_000


class ResultsStore:
    """SQLite-backed store for scan results."""

    def __init__(self, path: Optional[str] = None) -> None:
        if path is None:
            fd, path = tempfile.mkstemp(prefix="recovery-results-", suffix=".db")
            os.close(fd)
        self.path = path
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def close(self) -> None:
        self._conn.close()

    def clear(self) -> None:
        self._conn.execute("DELETE FROM found_files")
        self._conn.commit()

    def count(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) AS c FROM found_files").fetchone()
        return int(row["c"]) if row else 0

    def add(self, found: FoundFile) -> int:
        index = self.count()
        self._conn.execute(
            """
            INSERT INTO found_files (
                file_index, offset, size, extension, category, signature_name,
                source_device, confidence, preview_note, created_at, modified_at, selected
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                index,
                found.offset,
                found.size,
                found.extension,
                found.category.value,
                found.signature_name,
                found.source_device,
                found.confidence,
                found.preview_note,
                found.created_at,
                found.modified_at,
                1 if found.selected else 0,
            ),
        )
        self._conn.commit()
        return index

    def extend(self, files: list[FoundFile]) -> None:
        for found in files:
            self.add(found)

    def get(self, index: int) -> Optional[FoundFile]:
        row = self._conn.execute(
            "SELECT * FROM found_files WHERE file_index = ?",
            (index,),
        ).fetchone()
        return _row_to_found(row) if row else None

    def set_selected(self, indices: list[int], selected: bool) -> None:
        if not indices:
            return
        placeholders = ",".join("?" for _ in indices)
        self._conn.execute(
            f"UPDATE found_files SET selected = ? WHERE file_index IN ({placeholders})",
            [1 if selected else 0, *indices],
        )
        self._conn.commit()

    def set_selected_matching(
        self,
        *,
        category: str = "all",
        search: str = "",
        extension: str = "all",
        min_confidence: str = DEFAULT_MIN_CONFIDENCE,
        selected: bool,
    ) -> None:
        query, params = _filtered_query(
            "UPDATE found_files SET selected = ?",
            category=category,
            search=search,
            extension=extension,
            min_confidence=min_confidence,
            update_selected=1 if selected else 0,
        )
        self._conn.execute(query, params)
        self._conn.commit()

    def selected_files(self) -> list[FoundFile]:
        rows = self._conn.execute(
            "SELECT * FROM found_files WHERE selected = 1 ORDER BY file_index"
        ).fetchall()
        return [_row_to_found(row) for row in rows]

    def paginate(
        self,
        *,
        category: str = "all",
        search: str = "",
        extension: str = "all",
        min_confidence: str = DEFAULT_MIN_CONFIDENCE,
        page: int = 0,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> dict[str, Any]:
        page_size = max(1, min(page_size, MAX_PAGE_SIZE))
        total = self._filtered_count(category, search, extension, min_confidence)
        total_pages = max(1, (total + page_size - 1) // page_size) if total else 1
        page = max(0, min(page, total_pages - 1 if total else 0))
        offset = page * page_size

        query, params = _filtered_query(
            "SELECT * FROM found_files",
            category=category,
            search=search,
            extension=extension,
            min_confidence=min_confidence,
            order_by="ORDER BY file_index",
            limit=page_size,
            offset=offset,
        )
        rows = self._conn.execute(query, params).fetchall()
        files = [(row["file_index"], _row_to_found(row)) for row in rows]
        return {
            "files": files,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "showing_from": offset + 1 if total else 0,
            "showing_to": min(offset + page_size, total),
        }

    def summarize(
        self,
        *,
        category: str = "all",
        search: str = "",
        extension: str = "all",
        min_confidence: str = DEFAULT_MIN_CONFIDENCE,
    ) -> dict[str, Any]:
        total = self.count()
        visible_total = self._filtered_count(category, search, "all", min_confidence)
        filtered_total = self._filtered_count(category, search, extension, min_confidence)

        selected_all = self._conn.execute(
            "SELECT COUNT(*) AS c FROM found_files WHERE selected = 1"
        ).fetchone()["c"]
        selected_bytes = self._conn.execute(
            "SELECT COALESCE(SUM(size), 0) AS s FROM found_files WHERE selected = 1"
        ).fetchone()["s"]

        query, params = _filtered_query(
            "SELECT COALESCE(SUM(size), 0) AS s, COUNT(*) AS c FROM found_files",
            category=category,
            search=search,
            extension=extension,
            min_confidence=min_confidence,
        )
        filtered_row = self._conn.execute(query, params).fetchone()
        filtered_bytes = filtered_row["s"]
        selected_filtered = self._conn.execute(
            *_filtered_query(
                "SELECT COUNT(*) AS c FROM found_files",
                category=category,
                search=search,
                extension=extension,
                min_confidence=min_confidence,
                selected_only=True,
            )
        ).fetchone()["c"]
        selected_filtered_bytes = self._conn.execute(
            *_filtered_query(
                "SELECT COALESCE(SUM(size), 0) AS s FROM found_files",
                category=category,
                search=search,
                extension=extension,
                min_confidence=min_confidence,
                selected_only=True,
            )
        ).fetchone()["s"]

        by_category = {cat.value: 0 for cat in FileCategory}
        for row in self._conn.execute(
            "SELECT category, COUNT(*) AS c FROM found_files GROUP BY category"
        ):
            by_category[row["category"]] = row["c"]

        by_confidence = {"high": 0, "medium": 0, "low": 0}
        for row in self._conn.execute(
            "SELECT confidence, COUNT(*) AS c FROM found_files GROUP BY confidence"
        ):
            level = row["confidence"] if row["confidence"] in by_confidence else "medium"
            by_confidence[level] = row["c"]

        extensions = self._extension_counts(category, search, min_confidence)

        return {
            "total": total,
            "visible_total": visible_total,
            "filtered_total": filtered_total,
            "selected": selected_filtered,
            "selected_all": selected_all,
            "selected_bytes": selected_bytes,
            "selected_size_human": format_bytes(selected_bytes),
            "selected_filtered_bytes": selected_filtered_bytes,
            "selected_filtered_size_human": format_bytes(selected_filtered_bytes),
            "filtered_bytes": filtered_bytes,
            "filtered_size_human": format_bytes(filtered_bytes),
            "by_category": by_category,
            "by_confidence": by_confidence,
            "extensions": extensions,
            "large_result_set": total >= LARGE_RESULT_THRESHOLD,
        }

    def _extension_counts(
        self,
        category: str,
        search: str,
        min_confidence: str,
    ) -> list[dict[str, Any]]:
        query, params = _filtered_query(
            "SELECT extension, COUNT(*) AS c FROM found_files",
            category=category,
            search=search,
            extension="all",
            min_confidence=min_confidence,
            group_by="GROUP BY extension",
            order_by="ORDER BY c DESC, extension ASC",
        )
        rows = self._conn.execute(query, params).fetchall()
        return [{"ext": row["extension"], "count": row["c"]} for row in rows]

    def _filtered_count(
        self,
        category: str,
        search: str,
        extension: str,
        min_confidence: str,
    ) -> int:
        query, params = _filtered_query(
            "SELECT COUNT(*) AS c FROM found_files",
            category=category,
            search=search,
            extension=extension,
            min_confidence=min_confidence,
        )
        return int(self._conn.execute(query, params).fetchone()["c"])

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS found_files (
                file_index INTEGER PRIMARY KEY,
                offset INTEGER NOT NULL,
                size INTEGER NOT NULL,
                extension TEXT NOT NULL,
                category TEXT NOT NULL,
                signature_name TEXT NOT NULL,
                source_device TEXT NOT NULL,
                confidence TEXT NOT NULL,
                preview_note TEXT NOT NULL DEFAULT '',
                created_at REAL,
                modified_at REAL,
                selected INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_found_category ON found_files(category);
            CREATE INDEX IF NOT EXISTS idx_found_confidence ON found_files(confidence);
            CREATE INDEX IF NOT EXISTS idx_found_extension ON found_files(extension);
            """
        )
        self._conn.commit()


def _row_to_found(row: sqlite3.Row) -> FoundFile:
    return FoundFile(
        offset=row["offset"],
        size=row["size"],
        extension=row["extension"],
        category=FileCategory(row["category"]),
        signature_name=row["signature_name"],
        source_device=row["source_device"],
        confidence=row["confidence"],
        preview_note=row["preview_note"],
        created_at=row["created_at"],
        modified_at=row["modified_at"],
        selected=bool(row["selected"]),
    )


def _filtered_query(
    select_clause: str,
    *,
    category: str = "all",
    search: str = "",
    extension: str = "all",
    min_confidence: str = DEFAULT_MIN_CONFIDENCE,
    update_selected: Optional[int] = None,
    selected_only: bool = False,
    group_by: str = "",
    order_by: str = "",
    limit: Optional[int] = None,
    offset: Optional[int] = None,
) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []

    if update_selected is not None:
        params.append(update_selected)

    if category != "all":
        clauses.append("category = ?")
        params.append(category)

    ext = extension.strip().lower().lstrip(".")
    if ext and ext != "all":
        clauses.append("extension = ?")
        params.append(ext)

    if selected_only:
        clauses.append("selected = 1")

    if min_confidence != "low":
        allowed = _confidence_values(min_confidence)
        placeholders = ",".join("?" for _ in allowed)
        clauses.append(f"confidence IN ({placeholders})")
        params.extend(allowed)

    term = search.strip().lower()
    if term:
        like = f"%{term}%"
        clauses.append(
            "("
            "LOWER(printf('recovered_%012x.%s', offset, extension)) LIKE ? OR "
            "LOWER(extension) LIKE ? OR "
            "LOWER(signature_name) LIKE ? OR "
            "LOWER(preview_note) LIKE ? OR "
            "LOWER(printf('%x', offset)) LIKE ? OR "
            "LOWER(printf('0x%x', offset)) LIKE ?"
            ")"
        )
        params.extend([like, like, like, like, like, like])

    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    query = select_clause + where
    if group_by:
        query += f" {group_by}"
    if order_by:
        query += f" {order_by}"
    if limit is not None:
        query += " LIMIT ?"
        params.append(limit)
    if offset is not None:
        query += " OFFSET ?"
        params.append(offset)
    return query, params


def _confidence_values(min_confidence: str) -> list[str]:
    if min_confidence == "high":
        return ["high"]
    if min_confidence == "medium":
        return ["high", "medium"]
    return ["high", "medium", "low"]
