-- Workstream B canonical allocation schema for Dolt/MySQL.
-- Apply inside the same Dolt database as the Beads graph.

CREATE TABLE allocation_requests (
  request_id VARCHAR(160) NOT NULL,
  protocol_version VARCHAR(64) NOT NULL,
  request_type VARCHAR(32) NOT NULL,
  payload_sha256 CHAR(64) NOT NULL,
  source_repository VARCHAR(255) NOT NULL,
  source_issue_number BIGINT UNSIGNED NOT NULL,
  source_comment_id BIGINT UNSIGNED NOT NULL,
  requested_by VARCHAR(512) NOT NULL,
  agent_id VARCHAR(255) NULL,
  nominated_task_id VARCHAR(255) NULL,
  release_allocation_id CHAR(26) NULL,
  status VARCHAR(16) NOT NULL,
  result_code VARCHAR(64) NOT NULL,
  terminal_reason_code VARCHAR(64) NULL,
  allocation_id CHAR(26) NULL,
  processed_at VARCHAR(32) NOT NULL,
  canonical_git_ref_sha CHAR(40) NULL,
  canonical_dolt_commit VARCHAR(128) NULL,
  anchor_status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
  projection_status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
  reconciliation_status VARCHAR(16) NOT NULL DEFAULT 'NONE',
  PRIMARY KEY (request_id),
  UNIQUE KEY uq_allocation_requests_source
    (source_repository, source_issue_number, source_comment_id),
  UNIQUE KEY uq_allocation_requests_allocation (allocation_id),
  CONSTRAINT ck_allocation_requests_protocol
    CHECK (protocol_version = 'beads-allocation/v0.2'),
  CONSTRAINT ck_allocation_requests_type
    CHECK (request_type IN ('ALLOCATE_NEXT', 'ALLOCATE_TASK', 'RELEASE', 'INVALID')),
  CONSTRAINT ck_allocation_requests_hash
    CHECK (payload_sha256 REGEXP '^[0-9a-f]{64}$'),
  CONSTRAINT ck_allocation_requests_status
    CHECK (status IN ('ALLOCATED', 'REJECTED', 'RELEASED')),
  CONSTRAINT ck_allocation_requests_anchor
    CHECK (anchor_status IN ('PENDING', 'RECORDED')),
  CONSTRAINT ck_allocation_requests_projection
    CHECK (projection_status IN ('PENDING', 'POSTED', 'MISSING', 'INVALID')),
  CONSTRAINT ck_allocation_requests_reconciliation
    CHECK (reconciliation_status IN ('NONE', 'REQUIRED', 'REPAIRED', 'ESCALATED')),
  CONSTRAINT ck_allocation_requests_git_sha
    CHECK (canonical_git_ref_sha IS NULL OR canonical_git_ref_sha REGEXP '^[0-9a-f]{40}$'),
  CONSTRAINT ck_allocation_requests_anchor_metadata
    CHECK (
      (anchor_status = 'PENDING' AND canonical_git_ref_sha IS NULL AND canonical_dolt_commit IS NULL)
      OR
      (anchor_status = 'RECORDED' AND canonical_git_ref_sha IS NOT NULL AND canonical_dolt_commit IS NOT NULL)
    ),
  CONSTRAINT ck_allocation_requests_shape
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
  CONSTRAINT ck_allocation_requests_grant
    CHECK ((status = 'ALLOCATED' AND allocation_id IS NOT NULL) OR status <> 'ALLOCATED')
);

CREATE TABLE allocations (
  allocation_id CHAR(26) NOT NULL,
  request_id VARCHAR(160) NOT NULL,
  agent_id VARCHAR(255) NOT NULL,
  task_id VARCHAR(255) NOT NULL,
  state VARCHAR(16) NOT NULL,
  granted_at VARCHAR(32) NOT NULL,
  released_at VARCHAR(32) NULL,
  release_actor VARCHAR(512) NULL,
  release_request_id VARCHAR(160) NULL,
  allocation_state_digest CHAR(64) NOT NULL,
  PRIMARY KEY (allocation_id),
  UNIQUE KEY uq_allocations_request (request_id),
  UNIQUE KEY uq_allocations_release_request (release_request_id),
  UNIQUE KEY uq_allocations_identity_task (allocation_id, task_id),
  CONSTRAINT fk_allocations_request FOREIGN KEY (request_id)
    REFERENCES allocation_requests (request_id),
  CONSTRAINT fk_allocations_release_request FOREIGN KEY (release_request_id)
    REFERENCES allocation_requests (request_id),
  CONSTRAINT ck_allocations_state CHECK (state IN ('ACTIVE', 'RELEASED')),
  CONSTRAINT ck_allocations_digest
    CHECK (allocation_state_digest REGEXP '^[0-9a-f]{64}$'),
  CONSTRAINT ck_allocations_release_shape CHECK (
    (state = 'ACTIVE' AND released_at IS NULL AND release_actor IS NULL AND release_request_id IS NULL)
    OR
    (state = 'RELEASED' AND released_at IS NOT NULL AND release_actor IS NOT NULL
      AND release_request_id IS NOT NULL)
  )
);

-- Dolt does not provide a portable partial unique index. This table is the
-- database-enforced one-active-allocation-per-task structure.
CREATE TABLE active_task_allocations (
  task_id VARCHAR(255) NOT NULL,
  allocation_id CHAR(26) NOT NULL,
  PRIMARY KEY (task_id),
  UNIQUE KEY uq_active_task_allocations_allocation (allocation_id),
  CONSTRAINT fk_active_task_allocation_pair FOREIGN KEY (allocation_id, task_id)
    REFERENCES allocations (allocation_id, task_id)
);

ALTER TABLE allocation_requests
  ADD CONSTRAINT fk_allocation_requests_allocation FOREIGN KEY (allocation_id)
    REFERENCES allocations (allocation_id),
  ADD CONSTRAINT fk_allocation_requests_release_allocation FOREIGN KEY (release_allocation_id)
    REFERENCES allocations (allocation_id);

CREATE TABLE allocation_events (
  event_id CHAR(26) NOT NULL,
  allocation_id CHAR(26) NULL,
  request_id VARCHAR(160) NULL,
  event_type VARCHAR(32) NOT NULL,
  audit_subject_type VARCHAR(64) NULL,
  audit_subject_id VARCHAR(512) NULL,
  actor VARCHAR(512) NOT NULL,
  event_at VARCHAR(32) NOT NULL,
  reason_code VARCHAR(64) NULL,
  canonical_git_ref_sha CHAR(40) NULL,
  canonical_dolt_commit VARCHAR(128) NULL,
  details_json JSON NOT NULL,
  PRIMARY KEY (event_id),
  CONSTRAINT fk_allocation_events_allocation FOREIGN KEY (allocation_id)
    REFERENCES allocations (allocation_id),
  CONSTRAINT fk_allocation_events_request FOREIGN KEY (request_id)
    REFERENCES allocation_requests (request_id),
  CONSTRAINT ck_allocation_events_type CHECK (event_type IN (
    'REQUEST_TERMINAL', 'ALLOCATED', 'RELEASED', 'ANCHOR_RECORDED',
    'PROJECTION_POSTED', 'PROJECTION_REPAIRED', 'AUDIT_FINDING'
  )),
  CONSTRAINT ck_allocation_events_git_sha
    CHECK (canonical_git_ref_sha IS NULL OR canonical_git_ref_sha REGEXP '^[0-9a-f]{40}$'),
  CONSTRAINT ck_allocation_events_subject CHECK (
    (event_type <> 'AUDIT_FINDING' AND request_id IS NOT NULL
      AND audit_subject_type IS NULL AND audit_subject_id IS NULL)
    OR
    (event_type = 'AUDIT_FINDING' AND (
      (request_id IS NOT NULL AND audit_subject_type IS NULL AND audit_subject_id IS NULL)
      OR
      (request_id IS NULL AND audit_subject_type IS NOT NULL AND audit_subject_id IS NOT NULL)
    ))
  ),
  CONSTRAINT ck_allocation_events_audit_subject_type CHECK (
    audit_subject_type IS NULL OR audit_subject_type IN ('PROJECTION_COMMENT', 'STATE_REF')
  )
);

-- Dolt persists these triggers with the schema so canonical audit history cannot
-- be rewritten through ordinary SQL.
DELIMITER //
CREATE TRIGGER allocation_events_no_update
BEFORE UPDATE ON allocation_events FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'ALLOCATION_EVENTS_APPEND_ONLY';
END//
CREATE TRIGGER allocation_events_no_delete
BEFORE DELETE ON allocation_events FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'ALLOCATION_EVENTS_APPEND_ONLY';
END//
DELIMITER ;
