"""Canonical Workstream B schema and isolated fixture initialisation."""

from __future__ import annotations

import sqlite3
from pathlib import Path

DOLT_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schema" / "001_workstream_b.sql"


def dolt_schema() -> str:
    """Return the reviewed Dolt/MySQL DDL without applying it anywhere."""
    return DOLT_SCHEMA_PATH.read_text(encoding="utf-8")


# SQLite is used only as an isolated, dependency-free conformance fixture. The
# production DDL above remains authoritative for Dolt.
SQLITE_FIXTURE_SCHEMA = r"""
PRAGMA foreign_keys = ON;

CREATE TABLE beads_tasks (
  task_id TEXT PRIMARY KEY,
  task_type TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('open', 'assigned')),
  assignee TEXT,
  priority INTEGER NOT NULL CHECK (priority BETWEEN 0 AND 4),
  created_at TEXT NOT NULL,
  ready INTEGER NOT NULL CHECK (ready IN (0, 1)),
  blocked INTEGER NOT NULL CHECK (blocked IN (0, 1)),
  labels_json TEXT NOT NULL,
  CHECK ((status = 'open' AND assignee IS NULL) OR (status = 'assigned' AND assignee IS NOT NULL))
);

CREATE TABLE allocation_requests (
  request_id TEXT PRIMARY KEY,
  protocol_version TEXT NOT NULL CHECK (protocol_version = 'beads-allocation/v0.2'),
  request_type TEXT NOT NULL CHECK (request_type IN ('ALLOCATE_NEXT', 'ALLOCATE_TASK', 'RELEASE', 'INVALID')),
  payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'),
  source_repository TEXT NOT NULL,
  source_issue_number INTEGER NOT NULL CHECK (source_issue_number > 0),
  source_comment_id INTEGER NOT NULL CHECK (source_comment_id > 0),
  requested_by TEXT NOT NULL,
  agent_id TEXT,
  nominated_task_id TEXT,
  release_allocation_id TEXT REFERENCES allocations(allocation_id),
  status TEXT NOT NULL CHECK (status IN ('ALLOCATED', 'REJECTED', 'RELEASED')),
  result_code TEXT NOT NULL,
  terminal_reason_code TEXT,
  allocation_id TEXT UNIQUE REFERENCES allocations(allocation_id),
  processed_at TEXT NOT NULL,
  canonical_git_ref_sha TEXT CHECK (
    canonical_git_ref_sha IS NULL OR
    (length(canonical_git_ref_sha) = 40 AND canonical_git_ref_sha NOT GLOB '*[^0-9a-f]*')
  ),
  canonical_dolt_commit TEXT,
  anchor_status TEXT NOT NULL DEFAULT 'PENDING' CHECK (anchor_status IN ('PENDING', 'RECORDED')),
  projection_status TEXT NOT NULL DEFAULT 'PENDING' CHECK (projection_status IN ('PENDING', 'POSTED', 'MISSING', 'INVALID')),
  reconciliation_status TEXT NOT NULL DEFAULT 'NONE' CHECK (reconciliation_status IN ('NONE', 'REQUIRED', 'REPAIRED', 'ESCALATED')),
  UNIQUE (source_repository, source_issue_number, source_comment_id),
  CHECK (
    (anchor_status = 'PENDING' AND canonical_git_ref_sha IS NULL AND canonical_dolt_commit IS NULL)
    OR
    (anchor_status = 'RECORDED' AND canonical_git_ref_sha IS NOT NULL AND canonical_dolt_commit IS NOT NULL)
  ),
  CHECK (
    (request_type = 'INVALID' AND agent_id IS NULL AND nominated_task_id IS NULL
      AND release_allocation_id IS NULL AND allocation_id IS NULL)
    OR
    (request_type = 'ALLOCATE_NEXT' AND agent_id IS NOT NULL AND nominated_task_id IS NULL
      AND release_allocation_id IS NULL)
    OR
    (request_type = 'ALLOCATE_TASK' AND agent_id IS NOT NULL AND nominated_task_id IS NOT NULL
      AND release_allocation_id IS NULL)
    OR
    (request_type = 'RELEASE' AND agent_id IS NOT NULL AND nominated_task_id IS NULL
      AND release_allocation_id IS NOT NULL AND allocation_id IS NULL)
  ),
  CHECK ((status = 'ALLOCATED' AND allocation_id IS NOT NULL) OR status <> 'ALLOCATED')
);

CREATE TABLE allocations (
  allocation_id TEXT PRIMARY KEY CHECK (length(allocation_id) = 26),
  request_id TEXT NOT NULL UNIQUE REFERENCES allocation_requests(request_id),
  agent_id TEXT NOT NULL,
  task_id TEXT NOT NULL REFERENCES beads_tasks(task_id),
  state TEXT NOT NULL CHECK (state IN ('ACTIVE', 'RELEASED')),
  granted_at TEXT NOT NULL,
  released_at TEXT,
  release_actor TEXT,
  release_request_id TEXT UNIQUE REFERENCES allocation_requests(request_id),
  allocation_state_digest TEXT NOT NULL CHECK (
    length(allocation_state_digest) = 64 AND allocation_state_digest NOT GLOB '*[^0-9a-f]*'
  ),
  UNIQUE (allocation_id, task_id),
  CHECK (
    (state = 'ACTIVE' AND released_at IS NULL AND release_actor IS NULL AND release_request_id IS NULL)
    OR
    (state = 'RELEASED' AND released_at IS NOT NULL AND release_actor IS NOT NULL
      AND release_request_id IS NOT NULL)
  )
);

CREATE TABLE active_task_allocations (
  task_id TEXT PRIMARY KEY,
  allocation_id TEXT NOT NULL UNIQUE,
  FOREIGN KEY (allocation_id, task_id) REFERENCES allocations(allocation_id, task_id)
);

CREATE TABLE allocation_events (
  event_id TEXT PRIMARY KEY CHECK (length(event_id) = 26),
  allocation_id TEXT REFERENCES allocations(allocation_id),
  request_id TEXT REFERENCES allocation_requests(request_id),
  event_type TEXT NOT NULL CHECK (event_type IN (
    'REQUEST_TERMINAL', 'ALLOCATED', 'RELEASED', 'ANCHOR_RECORDED',
    'PROJECTION_POSTED', 'PROJECTION_REPAIRED', 'AUDIT_FINDING'
  )),
  audit_subject_type TEXT CHECK (
    audit_subject_type IS NULL OR audit_subject_type IN ('PROJECTION_COMMENT', 'STATE_REF')
  ),
  audit_subject_id TEXT,
  actor TEXT NOT NULL,
  event_at TEXT NOT NULL,
  reason_code TEXT,
  canonical_git_ref_sha TEXT CHECK (
    canonical_git_ref_sha IS NULL OR
    (length(canonical_git_ref_sha) = 40 AND canonical_git_ref_sha NOT GLOB '*[^0-9a-f]*')
  ),
  canonical_dolt_commit TEXT,
  details_json TEXT NOT NULL CHECK (json_valid(details_json)),
  CHECK (
    (event_type <> 'AUDIT_FINDING' AND request_id IS NOT NULL
      AND audit_subject_type IS NULL AND audit_subject_id IS NULL)
    OR
    (event_type = 'AUDIT_FINDING' AND (
      (request_id IS NOT NULL AND audit_subject_type IS NULL AND audit_subject_id IS NULL)
      OR
      (request_id IS NULL AND audit_subject_type IS NOT NULL AND audit_subject_id IS NOT NULL)
    ))
  )
);

CREATE TRIGGER allocation_events_no_update
BEFORE UPDATE ON allocation_events
BEGIN SELECT RAISE(ABORT, 'ALLOCATION_EVENTS_APPEND_ONLY'); END;

CREATE TRIGGER allocation_events_no_delete
BEFORE DELETE ON allocation_events
BEGIN SELECT RAISE(ABORT, 'ALLOCATION_EVENTS_APPEND_ONLY'); END;
"""


def initialise_sqlite_fixture(connection: sqlite3.Connection) -> None:
    """Initialise a fresh isolated canonical-state fixture."""
    connection.executescript(SQLITE_FIXTURE_SCHEMA)
    connection.execute("PRAGMA foreign_keys = ON")
