# Archived: pre-Phase-1 backend scaffold

This folder holds an earlier, never-run backend scaffold that was sitting untracked in
`backend/` (LangGraph/Groq dependencies, partial Monitor/Triage agent code, a separate set
of Pydantic schemas and an SQLite layer). It was moved here — not deleted — when the working
Phase-1 FastAPI backend was integrated into `backend/app/`.

Nothing imports this code and pytest does not collect it (`testpaths = tests`).
It is kept only as reference material for later phases (e.g. `tools/mitre/lookup.py`,
`tools/compliance/policy.py`, `agents/triage/rules.py`). Delete it once no longer useful.
