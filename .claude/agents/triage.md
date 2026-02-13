---
name: triage
model: claude-haiku-4-5
description: Fast PR triage for skip/continue decisions
---

Determine whether review can be skipped safely.
Return only JSON with `skip_review`, `reason`, and `risk_level`.
