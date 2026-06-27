from __future__ import annotations

from typing import Any

from recovery.models import FoundFile, FileCategory, format_bytes

DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500
LARGE_RESULT_THRESHOLD = 5_000


def normalize_extension(extension: str) -> str:
    return extension.strip().lower().lstrip(".")


def filter_files(
    files: list[FoundFile],
    category: str = "all",
    search: str = "",
    extension: str = "all",
) -> list[tuple[int, FoundFile]]:
    term = search.strip().lower()
    ext_filter = normalize_extension(extension)
    matches: list[tuple[int, FoundFile]] = []

    for index, found in enumerate(files):
        if category != "all" and found.category.value != category:
            continue
        if ext_filter and ext_filter != "all" and found.extension.lower() != ext_filter:
            continue
        if term and not _matches_search(found, term):
            continue
        matches.append((index, found))

    return matches


def extension_counts(
    files: list[FoundFile],
    category: str = "all",
    search: str = "",
) -> list[dict[str, Any]]:
    """Extension counts after category/search filters, before extension filter."""
    matches = filter_files(files, category, search, extension="all")
    counts: dict[str, int] = {}
    for _index, found in matches:
        ext = found.extension.lower()
        counts[ext] = counts.get(ext, 0) + 1
    return [
        {"ext": ext, "count": count}
        for ext, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    ]


def summarize_files(
    files: list[FoundFile],
    category: str = "all",
    search: str = "",
    extension: str = "all",
) -> dict[str, Any]:
    filtered = filter_files(files, category, search, extension)
    selected = sum(1 for _index, found in filtered if found.selected)
    selected_bytes = sum(found.size for found in files if found.selected)
    selected_filtered_bytes = sum(found.size for _index, found in filtered if found.selected)
    filtered_bytes = sum(found.size for _index, found in filtered)
    by_category: dict[str, int] = {cat.value: 0 for cat in FileCategory}
    for found in files:
        by_category[found.category.value] = by_category.get(found.category.value, 0) + 1

    return {
        "total": len(files),
        "filtered_total": len(filtered),
        "selected": selected,
        "selected_all": sum(1 for found in files if found.selected),
        "selected_bytes": selected_bytes,
        "selected_size_human": format_bytes(selected_bytes),
        "selected_filtered_bytes": selected_filtered_bytes,
        "selected_filtered_size_human": format_bytes(selected_filtered_bytes),
        "filtered_bytes": filtered_bytes,
        "filtered_size_human": format_bytes(filtered_bytes),
        "by_category": by_category,
        "extensions": extension_counts(files, category, search),
        "large_result_set": len(files) >= LARGE_RESULT_THRESHOLD,
    }


def paginate_files(
    files: list[FoundFile],
    *,
    category: str = "all",
    search: str = "",
    extension: str = "all",
    page: int = 0,
    page_size: int = DEFAULT_PAGE_SIZE,
) -> dict[str, Any]:
    page_size = max(1, min(page_size, MAX_PAGE_SIZE))
    filtered = filter_files(files, category, search, extension)
    total = len(filtered)
    total_pages = max(1, (total + page_size - 1) // page_size) if total else 1
    page = max(0, min(page, total_pages - 1 if total else 0))

    start = page * page_size
    end = start + page_size
    page_items = filtered[start:end]

    return {
        "files": page_items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "showing_from": start + 1 if total else 0,
        "showing_to": min(end, total),
    }


def _matches_search(found: FoundFile, term: str) -> bool:
    haystack = " ".join(
        [
            found.filename,
            found.extension,
            found.signature_name,
            found.preview_note or "",
            f"{found.offset:x}",
            f"0x{found.offset:x}",
        ]
    ).lower()
    return term in haystack
