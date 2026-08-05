"""Shared JSON schema for every reviewer and the review synthesizer."""

import json
from pathlib import Path


REVIEW_OUTPUT_SCHEMA_PATH = Path(__file__).with_name("review-output.schema.json")
REVIEW_OUTPUT_SCHEMA = json.loads(REVIEW_OUTPUT_SCHEMA_PATH.read_text(encoding="utf-8"))
