"""Build a normalized, text-only threat dataset from public corpora.

Usage from backend/: python scripts/prepare_datasets.py --download
Raw messages stay in backend/data/raw (git-ignored); only normalized text is used.
"""
from __future__ import annotations

import argparse
import csv
import json
import mailbox
import os
import re
import tarfile
import urllib.request
from email import policy
from email.parser import BytesParser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
OUTPUT = ROOT / "data" / "threat_training.csv"
SEED = ROOT / "data" / "threat_seed.csv"
PROJECT_ROOT = ROOT.parent
BEC_DIR = PROJECT_ROOT / "BECdatasets"
PHISHING_JSONL = PROJECT_ROOT / "phishing&legitimate_datasets" / "phishing and benign email dataset.jsonl"
SPAM_DATASET_FILES = (PROJECT_ROOT / "archive" / "email_spam.csv", PROJECT_ROOT / "spam_datasets" / "email_spam.csv")
SPAMASSASSIN = {
    "easy_ham": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
    "hard_ham": "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
    "spam": "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2",
}
NAZARIO = "https://monkey.org/~jose/phishing/phishing-2024"


def clean_text(value: str) -> str:
    value = re.sub(r"<[^>]+>", " ", value)
    return re.sub(r"\s+", " ", value).strip()[:12000]


def message_text(raw: bytes) -> tuple[str, str]:
    message = BytesParser(policy=policy.default).parsebytes(raw)
    subject = str(message.get("subject", ""))
    parts: list[str] = []
    for part in message.walk() if message.is_multipart() else [message]:
        if part.get_content_disposition() == "attachment":
            continue
        if part.get_content_type() == "text/plain":
            try:
                parts.append(part.get_content())
            except Exception:
                pass
    if not parts and message.get_content_type() == "text/html":
        try:
            parts.append(message.get_content())
        except Exception:
            pass
    return clean_text(subject), clean_text("\n".join(parts))


def download_corpus() -> None:
    RAW.mkdir(parents=True, exist_ok=True)
    spam_dir = RAW / "spamassassin"
    spam_dir.mkdir(exist_ok=True)
    for name, url in SPAMASSASSIN.items():
        archive = spam_dir / f"{name}.tar.bz2"
        if not archive.exists():
            print(f"downloading {url}")
            urllib.request.urlretrieve(url, archive)
        target = spam_dir / name
        if not target.exists():
            target.mkdir()
            with tarfile.open(archive, "r:bz2") as bundle:
                for member in bundle.getmembers():
                    destination = (target / member.name).resolve()
                    if os.path.commonpath((str(target.resolve()), str(destination))) != str(target.resolve()):
                        raise ValueError(f"unsafe archive member: {member.name}")
                    bundle.extract(member, target)
    phishing = RAW / "phishing-2024"
    if not phishing.exists():
        print(f"downloading {NAZARIO}")
        urllib.request.urlretrieve(NAZARIO, phishing)


def rows_from_corpus() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    if SEED.exists():
        with SEED.open(encoding="utf-8-sig", newline="") as source:
            rows.extend(
                {
                    "label": row["label"],
                    "subject": row["subject"],
                    "body": row["body"],
                }
                for row in csv.DictReader(source)
            )
    seen_spam_files: set[Path] = set()
    for archive_csv in SPAM_DATASET_FILES:
        archive_csv = archive_csv.resolve()
        if not archive_csv.exists() or archive_csv in seen_spam_files:
            continue
        seen_spam_files.add(archive_csv)
        with archive_csv.open(encoding="utf-8-sig", newline="") as source:
            for row in csv.DictReader(source):
                label = "SPAM" if row.get("type", "").strip().lower() == "spam" else "BENIGN"
                rows.append({"label": label, "subject": row.get("title", ""), "body": row.get("text", "")})

    # User-provided BEC corpus: include clean and adversarial variants. Empty
    # padding rows are ignored; the poisoned copy teaches robustness to text
    # obfuscation without executing or storing attachments.
    for bec_file in (BEC_DIR / "synthetic_emails.csv", BEC_DIR / "synthetic_emails_poisoned.csv"):
        if not bec_file.exists():
            continue
        with bec_file.open(encoding="utf-8-sig", newline="") as source:
            for row in csv.DictReader(source):
                subject = row.get("subject", "").strip()
                body = row.get("body", "").strip()
                if subject or body:
                    rows.append({"label": "BEC", "subject": subject, "body": body})

    if PHISHING_JSONL.exists():
        with PHISHING_JSONL.open(encoding="utf-8-sig") as source:
            for line in source:
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                label = item.get("label", "").strip().lower()
                normalized_label = {"phishing": "PHISHING", "benign": "BENIGN"}.get(label)
                if not normalized_label:
                    continue
                intent = str(item.get("intent", "")).strip().lower()
                technique = str(item.get("technique", "")).strip().lower()
                if "malware delivery" in intent or "malicious payload" in technique:
                    normalized_label = "MALWARE"
                elif "business email compromise" in technique:
                    normalized_label = "BEC"
                metadata = " ".join(
                    str(item.get(key, ""))
                    for key in ("intent", "technique", "target", "spoofed_sender")
                    if item.get(key)
                )
                rows.append(
                    {
                        "label": normalized_label,
                        "subject": str(item.get("subject", "")),
                        "body": f"{item.get('body', '')} {metadata}".strip(),
                    }
                )

    for directory_name in ("easy_ham", "hard_ham", "spam"):
        directory = RAW / "spamassassin" / directory_name
        if not directory.exists():
            continue
        label = "SPAM" if directory_name == "spam" else "BENIGN"
        for path in directory.rglob("*"):
            if path.is_file() and not path.name.endswith((".tar.bz2", ".md5")):
                subject, body = message_text(path.read_bytes())
                if subject or body:
                    rows.append({"label": label, "subject": subject, "body": body})

    phishing = RAW / "phishing-2024"
    if phishing.exists():
        try:
            source = mailbox.mbox(phishing)
            for message in source:
                subject, body = message_text(message.as_bytes())
                if subject or body:
                    rows.append({"label": "PHISHING", "subject": subject, "body": body})
        except Exception as exc:
            print(f"warning: could not parse phishing corpus: {exc}")
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--download", action="store_true", help="download official public corpora")
    args = parser.parse_args()
    if args.download:
        download_corpus()
    rows = rows_from_corpus()
    if not rows:
        raise SystemExit("no source rows found; run with --download or provide archive/email_spam.csv")
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    with OUTPUT.open("w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=["label", "subject", "body"])
        writer.writeheader()
        writer.writerows(rows)
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["label"]] = counts.get(row["label"], 0) + 1
    print(f"wrote {len(rows)} rows to {OUTPUT}")
    print(counts)


if __name__ == "__main__":
    main()
