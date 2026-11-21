"""Render sanitized diagnostic snapshots and write them safely to disk."""

from __future__ import annotations

import errno
from html import escape as _html_escape
import io
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any
import zipfile


_REPORT_MEMBERS = ("report.md", "report.jsonl", "report.html")
_MARKDOWN_SPECIAL = frozenset("\\`*_{}[]!|()~")
_LABEL_ABBREVIATIONS = {
    "api": "API",
    "cpu": "CPU",
    "dns": "DNS",
    "gpu": "GPU",
    "html": "HTML",
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "jsonl": "JSONL",
    "mac": "MAC",
    "nvme": "NVMe",
    "os": "OS",
    "raid": "RAID",
    "ram": "RAM",
    "usb": "USB",
    "utc": "UTC",
    "uuid": "UUID",
    "vram": "VRAM",
    "x11": "X11",
}


def _validate_json_value(value: Any, path: str = "snapshot") -> None:
    """Reject values that would make a report invalid or have ambiguous JSON types."""
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_value(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"{path} contains a non-string object key")
            _validate_json_value(item, f"{path}.{key}")
        return
    raise TypeError(f"{path} contains a non-JSON value")


def _validate_snapshot(snapshot: dict[str, Any]) -> None:
    if not isinstance(snapshot, dict):
        raise TypeError("snapshot must be a dictionary")

    required = {
        "schema_version": str,
        "timestamp": str,
        "app_version": str,
        "selected_sections": list,
        "privacy": bool,
        "sections": dict,
        "errors": list,
    }
    for key, expected_type in required.items():
        if key not in snapshot or not isinstance(snapshot[key], expected_type):
            raise ValueError(f"snapshot field {key!r} must be {expected_type.__name__}")
    if any(not isinstance(section, str) for section in snapshot["selected_sections"]):
        raise ValueError("snapshot selected_sections must contain strings")
    if any(not isinstance(section, str) for section in snapshot["sections"]):
        raise ValueError("snapshot sections must have string keys")
    _validate_json_value(snapshot)


def _json_dumps(value: Any, *, indent: int | None = None) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, indent=indent)


def _clean_inline_text(value: str) -> str:
    """Keep dynamic text on one line and escape Markdown/HTML-sensitive syntax."""
    clean: list[str] = []
    for character in value:
        codepoint = ord(character)
        if character == "\n" or character == "\r":
            clean.append(" ⏎ ")
        elif character == "\t":
            clean.append(" ⇥ ")
        elif codepoint < 0x20 or codepoint == 0x7F:
            clean.append("�")
        elif character == "&":
            clean.append("&amp;")
        elif character == "<":
            clean.append("&lt;")
        elif character == ">":
            clean.append("&gt;")
        elif character in _MARKDOWN_SPECIAL:
            clean.append("\\" + character)
        else:
            clean.append(character)
    return "".join(clean)


def _humanize_label(value: str) -> str:
    """Turn internal snake/kebab/camel-case names into readable report labels."""
    separated = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", value)
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", separated)
    words = re.split(r"[_\-\s]+", separated.strip())
    return " ".join(
        _LABEL_ABBREVIATIONS.get(word.casefold(), word if word.isupper() or any(char.isupper() for char in word[1:]) else word.capitalize())
        for word in words
        if word
    )


def _display_value(value: Any) -> str:
    if value is None:
        return "Not available"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (dict, list)):
        return _json_dumps(value)
    return str(value)


def _record_columns(records: list[dict[str, Any]]) -> list[str]:
    columns: list[str] = []
    for record in records:
        for key in record:
            if key not in columns:
                columns.append(key)
    return columns


def _markdown_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    rendered_headers = " | ".join(_clean_inline_text(_humanize_label(header)) for header in headers)
    lines = [f"| {rendered_headers} |", f"| {' | '.join('---' for _ in headers)} |"]
    lines.extend(
        "| " + " | ".join(_clean_inline_text(cell) for cell in row) + " |"
        for row in rows
    )
    return lines


def _markdown_section_tables(data: Any) -> list[str]:
    """Render nested mappings as key/value tables and record lists as column tables."""
    simple_rows: list[tuple[str, str]] = []
    record_tables: list[tuple[str, list[dict[str, Any]]]] = []

    def visit(value: Any, prefix: str = "") -> None:
        if isinstance(value, dict):
            if not value:
                simple_rows.append((prefix or "Details", "No details"))
                return
            for key, child in value.items():
                label = f"{prefix} / {_humanize_label(key)}" if prefix else _humanize_label(key)
                if isinstance(child, dict):
                    visit(child, label)
                elif isinstance(child, list) and (not child or all(isinstance(item, dict) for item in child)):
                    if child:
                        record_tables.append((label, child))
                    else:
                        simple_rows.append((label, "No entries"))
                else:
                    simple_rows.append((label, _display_value(child)))
            return
        if isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
            record_tables.append((prefix or "Records", value))
        elif isinstance(value, list):
            simple_rows.extend((f"{prefix or 'Value'} [{index}]", _display_value(item)) for index, item in enumerate(value, 1))
            if not value:
                simple_rows.append((prefix or "Value", "No entries"))
        else:
            simple_rows.append((prefix or "Value", _display_value(value)))

    visit(data)
    lines: list[str] = []
    if simple_rows:
        lines.extend(_markdown_table(["Field", "Value"], [[field, value] for field, value in simple_rows]))
    for title, records in record_tables:
        columns = _record_columns(records)
        lines.extend(("", f"**{_clean_inline_text(title)}**", ""))
        if columns:
            rows = [
                [str(index), *[_display_value(record.get(column)) for column in columns]]
                for index, record in enumerate(records, 1)
            ]
            lines.extend(_markdown_table(["#", *columns], rows))
        else:
            lines.extend(("| # | Details |", "| --- | --- |", "| 1 | No details |"))
    return lines or ["No details were available."]


def render_markdown(snapshot: dict[str, Any]) -> str:
    """Render a human-readable Markdown document from one sanitized snapshot."""
    _validate_snapshot(snapshot)
    selected = snapshot["selected_sections"]
    selected_value = ", ".join(_humanize_label(item) for item in selected) if selected else "None"
    lines = [
        "# TaskPup System Diagnostic Report",
        "",
        f"- **Schema version:** {_clean_inline_text(snapshot['schema_version'])}",
        f"- **Generated (UTC):** {_clean_inline_text(snapshot['timestamp'])}",
        f"- **TaskPup version:** {_clean_inline_text(snapshot['app_version'])}",
        f"- **Privacy protection:** {'Enabled' if snapshot['privacy'] else 'Disabled'}",
        f"- **Selected sections:** {_clean_inline_text(selected_value)}",
        "",
        "> Automated redaction may not catch every sensitive value. Review this report before sharing it.",
    ]

    sections = snapshot["sections"]
    if sections:
        for name, data in sections.items():
            lines.extend(("", f"## {_clean_inline_text(_humanize_label(name))}", ""))
            lines.extend(_markdown_section_tables(data))
    else:
        lines.extend(("", "## Diagnostic sections", "", "No diagnostic sections were available."))

    errors = snapshot["errors"]
    lines.extend(("", "## Collection Errors", ""))
    lines.extend(_markdown_section_tables(errors) if errors else ["No collection errors were reported."])
    return "\n".join(lines).rstrip() + "\n"


def render_jsonl(snapshot: dict[str, Any]) -> str:
    """Render schema-versioned JSON Lines records from one sanitized snapshot."""
    _validate_snapshot(snapshot)
    timestamp = snapshot["timestamp"]
    common = {"schema_version": snapshot["schema_version"], "timestamp": timestamp}
    records: list[dict[str, Any]] = [
        {
            **common,
            "record_type": "metadata",
            "section": None,
            "data": {
                "app_version": snapshot["app_version"],
                "selected_sections": snapshot["selected_sections"],
                "privacy": snapshot["privacy"],
            },
        }
    ]
    records.extend(
        {
            **common,
            "record_type": "section",
            "section": name,
            "data": data,
        }
        for name, data in snapshot["sections"].items()
    )
    records.extend(
        {
            **common,
            "record_type": "error",
            "section": error.get("section") if isinstance(error, dict) and isinstance(error.get("section"), str) else None,
            "data": error,
        }
        for error in snapshot["errors"]
    )
    return "".join(_json_dumps(record) + "\n" for record in records)


def render_html(snapshot: dict[str, Any]) -> str:
    """Render a standalone offline HTML document with safely escaped snapshot data."""
    _validate_snapshot(snapshot)

    def make_table(headers: list[str], rows: list[list[str]]) -> str:
        head = "".join(f'<th scope="col">{_html_escape(_humanize_label(header))}</th>' for header in headers)
        body = "".join(
            "<tr>" + "".join(f"<td>{_html_escape(cell)}</td>" for cell in row) + "</tr>"
            for row in rows
        )
        return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'

    def render_data(data: Any) -> str:
        simple_rows: list[tuple[str, str]] = []
        record_tables: list[tuple[str, list[dict[str, Any]]]] = []

        def visit(value: Any, prefix: str = "") -> None:
            if isinstance(value, dict):
                if not value:
                    simple_rows.append((prefix or "Details", "No details"))
                    return
                for key, child in value.items():
                    label = f"{prefix} / {_humanize_label(key)}" if prefix else _humanize_label(key)
                    if isinstance(child, dict):
                        visit(child, label)
                    elif isinstance(child, list) and (not child or all(isinstance(item, dict) for item in child)):
                        if child:
                            record_tables.append((label, child))
                        else:
                            simple_rows.append((label, "No entries"))
                    else:
                        simple_rows.append((label, _display_value(child)))
                return
            if isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
                record_tables.append((prefix or "Records", value))
            elif isinstance(value, list):
                simple_rows.extend((f"{prefix or 'Value'} [{index}]", _display_value(item)) for index, item in enumerate(value, 1))
                if not value:
                    simple_rows.append((prefix or "Value", "No entries"))
            else:
                simple_rows.append((prefix or "Value", _display_value(value)))

        visit(data)
        parts: list[str] = []
        if simple_rows:
            parts.append(make_table(["Field", "Value"], [[field, value] for field, value in simple_rows]))
        for title, records in record_tables:
            columns = _record_columns(records)
            parts.append(f"<h3>{_html_escape(title)}</h3>")
            if columns:
                rows = [
                    [str(index), *[_display_value(record.get(column)) for column in columns]]
                    for index, record in enumerate(records, 1)
                ]
                parts.append(make_table(["#", *columns], rows))
            else:
                parts.append(make_table(["#", "Details"], [["1", "No details"]]))
        return "".join(parts) if parts else "<p>No details were available.</p>"

    def render_group(title: str, data: Any) -> str:
        return f"<section><h2>{_html_escape(_humanize_label(title))}</h2>{render_data(data)}</section>"

    selected = ", ".join(_humanize_label(item) for item in snapshot["selected_sections"]) or "None"
    sections = "".join(render_group(name, data) for name, data in snapshot["sections"].items())
    if not sections:
        sections = "<section><h2>Diagnostic sections</h2><p>No diagnostic sections were available.</p></section>"
    errors = render_group("Collection Errors", snapshot["errors"])
    privacy = "Enabled" if snapshot["privacy"] else "Disabled"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>TaskPup System Diagnostic Report</title>
  <style>
    :root {{ color-scheme: dark; font-family: system-ui, sans-serif; background: #17171c; color: #eeeeF4; }}
    body {{ max-width: 1100px; margin: 0 auto; padding: 1.5rem; line-height: 1.55; }}
    header {{ border-bottom: 2px solid #8f6bff; margin-bottom: 1.5rem; padding-bottom: 1rem; }}
    h1 {{ color: #bca7ff; margin-bottom: .25rem; }}
    h2 {{ color: #bca7ff; border-bottom: 1px solid #45424f; padding-bottom: .35rem; }}
    h3 {{ color: #cfc4ec; margin-bottom: .5rem; }}
    dl {{ display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: .35rem 1rem; }}
    dt {{ color: #b5b0c2; font-weight: 650; }}
    dd {{ margin: 0; overflow-wrap: anywhere; }}
    section {{ margin: 1.5rem 0; }}
    .table-wrap {{ overflow-x: auto; margin: .75rem 0 1.25rem; }}
    table {{ width: 100%; border-collapse: collapse; background: #222229; }}
    th, td {{ border: 1px solid #45424f; padding: .55rem .7rem; text-align: left; vertical-align: top; overflow-wrap: anywhere; }}
    th {{ color: #cfc4ec; background: #2c2933; }}
    tbody tr:nth-child(even) {{ background: #25242b; }}
    .privacy {{ color: #9de6b1; }}
    @media (max-width: 600px) {{ body {{ padding: 1rem; }} dl {{ grid-template-columns: 1fr; gap: .15rem; }} dd {{ margin-bottom: .45rem; }} }}
    @media print {{ :root {{ color-scheme: light; background: white; color: #111; }} body {{ max-width: none; padding: 0; }} h1, h2, h3, dt, th {{ color: #33235e; }} table, th, td {{ background: white !important; color: #111; border-color: #999; }} section {{ break-inside: avoid; }} }}
  </style>
</head>
<body>
  <header>
    <h1>TaskPup System Diagnostic Report</h1>
    <p>Sit. Stay. SIGKILL.</p>
    <dl>
      <dt>Schema version</dt><dd>{_html_escape(snapshot['schema_version'])}</dd>
      <dt>Generated (UTC)</dt><dd>{_html_escape(snapshot['timestamp'])}</dd>
      <dt>TaskPup version</dt><dd>{_html_escape(snapshot['app_version'])}</dd>
      <dt>Privacy protection</dt><dd class="privacy">{privacy}</dd>
      <dt>Selected sections</dt><dd>{_html_escape(selected)}</dd>
    </dl>
    <p>Automated redaction may not catch every sensitive value. Review this report before sharing it.</p>
  </header>
  {sections}
  {errors}
</body>
</html>
"""


def _make_zip(snapshot: dict[str, Any]) -> bytes:
    reports = (
        ("report.md", render_markdown(snapshot)),
        ("report.jsonl", render_jsonl(snapshot)),
        ("report.html", render_html(snapshot)),
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, text in reports:
            member = zipfile.ZipInfo(name)
            member.compress_type = zipfile.ZIP_DEFLATED
            member.external_attr = (stat.S_IFREG | 0o600) << 16
            archive.writestr(member, text.encode("utf-8"))

    payload = output.getvalue()
    with zipfile.ZipFile(io.BytesIO(payload), mode="r") as archive:
        names = archive.namelist()
        if len(names) != len(_REPORT_MEMBERS) or set(names) != set(_REPORT_MEMBERS):
            raise ValueError("generated ZIP has unexpected report members")
        if archive.testzip() is not None:
            raise ValueError("generated ZIP failed its integrity check")
    return payload


def _atomic_write(destination: Path, payload: bytes, *, overwrite: bool) -> None:
    """Atomically install a 0600 file without following its final path component."""
    destination = Path(destination)
    name = destination.name
    if not name or name in {".", ".."}:
        raise ValueError("destination must name a file")

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    directory_fd = os.open(destination.parent or Path("."), flags)
    temporary_name: str | None = None
    try:
        for _ in range(100):
            candidate = f".taskpup-report-{secrets.token_hex(8)}.tmp"
            create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            try:
                file_fd = os.open(candidate, create_flags, 0o600, dir_fd=directory_fd)
                temporary_name = candidate
                break
            except FileExistsError:
                continue
        else:
            raise FileExistsError("could not allocate a temporary report file")

        try:
            os.fchmod(file_fd, 0o600)
            with os.fdopen(file_fd, "wb", closefd=True) as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
        except BaseException:
            # fdopen owns file_fd after construction; if construction itself failed,
            # closing an already-closed descriptor is harmlessly guarded below.
            try:
                os.close(file_fd)
            except OSError:
                pass
            raise

        try:
            existing = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None

        if existing is not None:
            if stat.S_ISLNK(existing.st_mode):
                raise OSError(f"refusing to write through symbolic-link destination: {destination}")
            if not stat.S_ISREG(existing.st_mode):
                raise OSError(f"destination is not a regular file: {destination}")
            if not overwrite:
                raise FileExistsError(errno.EEXIST, "destination already exists", str(destination))
            os.replace(temporary_name, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
            temporary_name = None
        else:
            # Hard-linking the fully written temporary file gives atomic no-clobber
            # semantics even if another process creates the destination concurrently.
            os.link(
                temporary_name,
                name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
                follow_symlinks=False,
            )
            os.unlink(temporary_name, dir_fd=directory_fd)
            temporary_name = None
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def write_report(
    snapshot: dict[str, Any],
    destination: Path,
    format: str,
    *,
    overwrite: bool = False,
) -> None:
    """Render and atomically write one report format to ``destination``.

    ``format`` is one of ``md``, ``jsonl``, ``html`` or ``zip``. By default an
    existing destination is preserved. Callers should set ``overwrite=True``
    only after the user has explicitly approved replacement in the UI.
    """
    _validate_snapshot(snapshot)
    if not isinstance(overwrite, bool):
        raise TypeError("overwrite must be a bool")
    if format == "md":
        payload = render_markdown(snapshot).encode("utf-8")
    elif format == "jsonl":
        payload = render_jsonl(snapshot).encode("utf-8")
    elif format == "html":
        payload = render_html(snapshot).encode("utf-8")
    elif format == "zip":
        payload = _make_zip(snapshot)
    else:
        raise ValueError("format must be one of: md, jsonl, html, zip")
    _atomic_write(Path(destination), payload, overwrite=overwrite)

