"""Render the Markdown runbook into a styled standalone HTML document."""

from __future__ import annotations

import html
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docs" / "RUNBOOK.md"
OUTPUT = ROOT / "docs" / "RUNBOOK.html"


def inline_format(text: str) -> str:
    """Apply inline markdown-like formatting and HTML escaping."""
    text = html.escape(text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', text)
    return text


def flush_paragraph(paragraph_lines: list[str], out: list[str]) -> None:
    """Render and clear buffered paragraph lines."""
    if not paragraph_lines:
        return
    text = " ".join(line.strip() for line in paragraph_lines)
    out.append(f"<p>{inline_format(text)}</p>")
    paragraph_lines.clear()


def flush_list(list_items: list[str], ordered: bool, out: list[str]) -> None:
    """Render and clear buffered list items as HTML list markup."""
    if not list_items:
        return
    tag = "ol" if ordered else "ul"
    out.append(f"<{tag}>")
    for item in list_items:
        out.append(f"<li>{inline_format(item)}</li>")
    out.append(f"</{tag}>")
    list_items.clear()


def flush_table(table_rows: list[list[str]], out: list[str]) -> None:
    """Render and clear a buffered markdown table as HTML."""
    if not table_rows:
        return
    header = table_rows[0]
    body = table_rows[1:]
    out.append('<table class="runbook-table">')
    out.append(
        "<thead><tr>"
        + "".join(f"<th>{inline_format(cell)}</th>" for cell in header)
        + "</tr></thead>"
    )
    out.append("<tbody>")
    for row in body:
        out.append(
            "<tr>"
            + "".join(f"<td>{inline_format(cell)}</td>" for cell in row)
            + "</tr>"
        )
    out.append("</tbody></table>")
    table_rows.clear()


def is_table_delimiter(line: str) -> bool:
    """Return True when a line is a markdown table delimiter row."""
    stripped = line.strip()
    return (
        stripped.startswith("|")
        and set(
            stripped.replace("|", "").replace("-", "").replace(":", "").replace(" ", "")
        )
        == set()
    )


def parse_markdown(md_text: str) -> str:
    """Convert the supported markdown subset into HTML fragments."""
    lines = md_text.splitlines()
    out: list[str] = []
    paragraph_lines: list[str] = []
    list_items: list[str] = []
    list_ordered = False
    table_rows: list[list[str]] = []
    in_code = False
    code_lang = ""
    code_lines: list[str] = []

    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()

        if stripped.startswith("```"):
            flush_paragraph(paragraph_lines, out)
            flush_list(list_items, list_ordered, out)
            flush_table(table_rows, out)
            if not in_code:
                in_code = True
                code_lang = stripped[3:].strip()
                code_lines = []
            else:
                code_html = html.escape("\n".join(code_lines))
                class_attr = f' class="language-{code_lang}"' if code_lang else ""
                out.append(f"<pre><code{class_attr}>{code_html}</code></pre>")
                in_code = False
                code_lang = ""
                code_lines = []
            i += 1
            continue

        if in_code:
            code_lines.append(line)
            i += 1
            continue

        if not stripped:
            flush_paragraph(paragraph_lines, out)
            flush_list(list_items, list_ordered, out)
            flush_table(table_rows, out)
            i += 1
            continue

        if stripped.startswith("#"):
            flush_paragraph(paragraph_lines, out)
            flush_list(list_items, list_ordered, out)
            flush_table(table_rows, out)
            level = len(stripped) - len(stripped.lstrip("#"))
            title = stripped[level:].strip()
            anchor = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
            out.append(f'<h{level} id="{anchor}">{inline_format(title)}</h{level}>')
            i += 1
            continue

        unordered = re.match(r"^[-*]\s+(.*)$", stripped)
        ordered = re.match(r"^\d+\.\s+(.*)$", stripped)
        if unordered or ordered:
            flush_paragraph(paragraph_lines, out)
            flush_table(table_rows, out)
            current_ordered = bool(ordered)
            item_text = (ordered or unordered).group(1)
            if list_items and list_ordered != current_ordered:
                flush_list(list_items, list_ordered, out)
            list_ordered = current_ordered
            list_items.append(item_text)
            i += 1
            continue

        if stripped.startswith("|") and "|" in stripped[1:]:
            flush_paragraph(paragraph_lines, out)
            flush_list(list_items, list_ordered, out)
            if i + 1 < len(lines) and is_table_delimiter(lines[i + 1]):
                table_rows.append(
                    [cell.strip() for cell in stripped.strip("|").split("|")]
                )
                i += 2
                while i < len(lines):
                    row_line = lines[i].strip()
                    if not row_line.startswith("|"):
                        break
                    table_rows.append(
                        [cell.strip() for cell in row_line.strip("|").split("|")]
                    )
                    i += 1
                flush_table(table_rows, out)
                continue

        paragraph_lines.append(line)
        i += 1

    flush_paragraph(paragraph_lines, out)
    flush_list(list_items, list_ordered, out)
    flush_table(table_rows, out)

    return "\n".join(out)


def build_html(body: str) -> str:
    """Wrap rendered body markup in the runbook HTML template."""
    css = """
body {
  font-family: Segoe UI, Arial, sans-serif;
  background: #f6f8fb;
  color: #16202a;
  margin: 0;
  padding: 0;
}
main {
  max-width: 980px;
  margin: 0 auto;
  padding: 32px 24px 48px;
}
h1, h2, h3 {
  color: #0f3b57;
}
h1 {
  border-bottom: 3px solid #0f3b57;
  padding-bottom: 10px;
}
h2 {
  margin-top: 32px;
  border-bottom: 1px solid #cfd8e3;
  padding-bottom: 8px;
}
p, li {
  line-height: 1.6;
}
code {
  background: #e8eef5;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: Consolas, monospace;
}
pre {
  background: #12202b;
  color: #eaf2f7;
  padding: 14px 16px;
  border-radius: 8px;
  overflow-x: auto;
}
pre code {
  background: transparent;
  color: inherit;
  padding: 0;
}
.runbook-table {
  width: 100%;
  border-collapse: collapse;
  margin: 16px 0 24px;
  background: white;
}
.runbook-table th,
.runbook-table td {
  border: 1px solid #d7e0ea;
  padding: 10px 12px;
  text-align: left;
  vertical-align: top;
}
.runbook-table th {
  background: #edf3f8;
}
a {
  color: #0b5fa5;
}
.banner {
  background: #0f3b57;
  color: white;
  padding: 18px 24px;
}
.banner p {
  margin: 6px 0 0;
  color: #d5e3ee;
}
"""
    return f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\">
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
  <title>Cisco Compliance Audit Runbook</title>
  <style>{css}</style>
</head>
<body>
  <div class=\"banner\">
    <h1 style=\"margin:0;border:0;padding:0;color:white;\">\
Cisco Compliance Audit Runbook</h1>
    <p>\
  Rendered HTML copy of docs/RUNBOOK.md for operators who do not use \
  Markdown-capable viewers.</p>
  </div>
  <main>
{body}
  </main>
</body>
</html>
"""


def main() -> None:
    """Render docs/RUNBOOK.md into docs/RUNBOOK.html."""
    md_text = SOURCE.read_text(encoding="utf-8")
    body = parse_markdown(md_text)
    html_text = build_html(body)
    OUTPUT.write_text(html_text, encoding="utf-8")
    print(f"Wrote {OUTPUT}")


if __name__ == "__main__":
    main()
