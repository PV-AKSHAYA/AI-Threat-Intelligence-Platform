import json
import csv
from io import StringIO
from pathlib import Path

from PyPDF2 import PdfReader
from docx import Document


def extract_text_from_file(file_path: str) -> str:
    """
    Extract text from PDF, DOCX, TXT, CSV, JSON.
    """

    suffix = Path(file_path).suffix.lower()

    if suffix == ".pdf":
        return _extract_pdf(file_path)

    elif suffix == ".docx":
        return _extract_docx(file_path)

    elif suffix == ".txt":
        return Path(file_path).read_text(
            encoding="utf-8",
            errors="ignore"
        )

    elif suffix == ".json":
        data = json.loads(
            Path(file_path).read_text(
                encoding="utf-8",
                errors="ignore"
            )
        )

        return json.dumps(data, indent=2)

    elif suffix == ".csv":

        text = Path(file_path).read_text(
            encoding="utf-8",
            errors="ignore"
        )

        reader = csv.reader(StringIO(text))

        rows = []

        for row in reader:
            rows.append(" ".join(row))

        return "\n".join(rows)

    raise ValueError(
        f"Unsupported file type: {suffix}"
    )


def _extract_pdf(file_path: str) -> str:

    reader = PdfReader(file_path)

    text = ""

    for page in reader.pages:
        text += page.extract_text() or ""

    return text


def _extract_docx(file_path: str) -> str:

    doc = Document(file_path)

    return "\n".join(
        paragraph.text
        for paragraph in doc.paragraphs
    )