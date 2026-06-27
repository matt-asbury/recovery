from recovery.models import FileCategory, FoundFile
from recovery.results_store import ResultsStore


def _file(index: int, *, confidence: str = "medium", selected: bool = False) -> FoundFile:
    return FoundFile(
        offset=index * 1024,
        size=1000 + index,
        extension="jpg",
        category=FileCategory.IMAGE,
        signature_name="JPEG",
        source_device="/dev/rdisk1",
        confidence=confidence,
        selected=selected,
    )


def test_add_and_get() -> None:
    store = ResultsStore(":memory:")
    index = store.add(_file(0))
    assert index == 0
    found = store.get(0)
    assert found is not None
    assert found.size == 1000


def test_paginate_respects_confidence() -> None:
    store = ResultsStore(":memory:")
    store.add(_file(0, confidence="high"))
    store.add(_file(1, confidence="low"))
    page = store.paginate(min_confidence="medium")
    assert page["total"] == 1
    assert page["files"][0][1].confidence == "high"


def test_selected_files() -> None:
    store = ResultsStore(":memory:")
    store.add(_file(0, selected=True))
    store.add(_file(1))
    assert len(store.selected_files()) == 1


def test_summarize_counts() -> None:
    store = ResultsStore(":memory:")
    store.add(_file(0, confidence="high"))
    store.add(_file(1, confidence="low"))
    summary = store.summarize(min_confidence="medium")
    assert summary["total"] == 2
    assert summary["visible_total"] == 1
