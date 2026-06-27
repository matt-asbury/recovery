from recovery.file_list import filter_files, paginate_files, summarize_files
from recovery.models import FileCategory, FoundFile


def _file(index: int, *, selected: bool = False, extension: str = "jpg") -> FoundFile:
    return FoundFile(
        offset=index,
        size=1000 + index,
        extension=extension,
        category=FileCategory.IMAGE,
        signature_name="JPEG",
        source_device="/dev/rdisk1",
        selected=selected,
    )


def test_filter_files_by_category() -> None:
    files = [
        FoundFile(0, 100, "mp4", FileCategory.VIDEO, "MP4", "/dev/rdisk1"),
        _file(1),
    ]
    matches = filter_files(files, category="image")
    assert len(matches) == 1
    assert matches[0][1].extension == "jpg"


def test_summarize_selected_counts() -> None:
    files = [_file(0, selected=True), _file(1), _file(2, selected=True)]
    summary = summarize_files(files)
    assert summary["selected_all"] == 2
    assert summary["total"] == 3


def test_paginate_files() -> None:
    files = [_file(index) for index in range(25)]
    page = paginate_files(files, page=1, page_size=10)
    assert page["total"] == 25
    assert page["total_pages"] == 3
    assert len(page["files"]) == 10
    assert page["files"][0][0] == 10
