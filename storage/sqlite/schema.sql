/* NanoMDM SQLite schema: the pgsql schema in SQLite's dialect.
 * Applied by New on every start, so every statement is IF NOT EXISTS.
 * Timestamps are CURRENT_TIMESTAMP (whole seconds); the queue view breaks
 * ties by insertion order (rowid), so commands queued in the same second
 * are delivered in the order they were queued.
 */

CREATE TABLE IF NOT EXISTS devices
(
    id                  VARCHAR(255) NOT NULL,
    identity_cert       TEXT         NULL,
    serial_number       VARCHAR(127) NULL,
    unlock_token        BLOB         NULL,
    unlock_token_at     TIMESTAMP    NULL,
    authenticate        TEXT         NOT NULL,
    authenticate_at     TIMESTAMP    NOT NULL,
    token_update        TEXT         NULL,
    token_update_at     TIMESTAMP    NULL,
    bootstrap_token_b64 TEXT         NULL,
    bootstrap_token_at  TIMESTAMP    NULL,
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CHECK (identity_cert IS NULL OR substr(identity_cert, 1, 27) = '-----BEGIN CERTIFICATE-----'),
    CHECK (serial_number IS NULL OR serial_number != ''),
    CHECK (unlock_token IS NULL OR length(unlock_token) > 0),
    CHECK (authenticate != ''),
    CHECK (token_update IS NULL OR token_update != ''),
    CHECK (bootstrap_token_b64 IS NULL OR bootstrap_token_b64 != '')
);

CREATE INDEX IF NOT EXISTS serial_number ON devices (serial_number);

CREATE TABLE IF NOT EXISTS users
(
    id                          VARCHAR(255) NOT NULL,
    device_id                   VARCHAR(255) NOT NULL,
    user_short_name             VARCHAR(255) NULL,
    user_long_name              VARCHAR(255) NULL,
    token_update                TEXT         NULL,
    token_update_at             TIMESTAMP    NULL,
    user_authenticate           TEXT         NULL,
    user_authenticate_at        TIMESTAMP    NULL,
    user_authenticate_digest    TEXT         NULL,
    user_authenticate_digest_at TIMESTAMP    NULL,
    created_at                  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at                  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, device_id),
    UNIQUE (id),
    FOREIGN KEY (device_id)
        REFERENCES devices (id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CHECK (user_short_name IS NULL OR user_short_name != ''),
    CHECK (user_long_name IS NULL OR user_long_name != ''),
    CHECK (token_update IS NULL OR token_update != ''),
    CHECK (user_authenticate IS NULL OR user_authenticate != ''),
    CHECK (user_authenticate_digest IS NULL OR user_authenticate_digest != '')
);

CREATE TABLE IF NOT EXISTS enrollments
(
    id                 VARCHAR(255) NOT NULL,
    device_id          VARCHAR(255) NOT NULL,
    user_id            VARCHAR(255) NULL,
    type               VARCHAR(31)  NOT NULL,
    topic              VARCHAR(255) NOT NULL,
    push_magic         VARCHAR(127) NOT NULL,
    token_hex          VARCHAR(255) NOT NULL,
    enabled            BOOLEAN      NOT NULL DEFAULT TRUE,
    token_update_tally INTEGER      NOT NULL DEFAULT 1,
    last_seen_at       TIMESTAMP    NOT NULL,
    created_at         TIMESTAMP             DEFAULT CURRENT_TIMESTAMP,
    updated_at         TIMESTAMP             DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CHECK (id != ''),
    FOREIGN KEY (device_id)
        REFERENCES devices (id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (user_id)
        REFERENCES users (id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    UNIQUE (user_id),
    CHECK (type != ''),
    CHECK (topic != ''),
    CHECK (push_magic != ''),
    CHECK (token_hex != '')
);

CREATE INDEX IF NOT EXISTS idx_type ON enrollments (type);

CREATE TABLE IF NOT EXISTS commands
(
    command_uuid VARCHAR(127) NOT NULL,
    request_type VARCHAR(63)  NOT NULL,
    command      TEXT         NOT NULL,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (command_uuid),
    CHECK (command_uuid != ''),
    CHECK (request_type != ''),
    CHECK (substr(command, 1, 5) = '<?xml')
);

CREATE TABLE IF NOT EXISTS command_results
(
    id            VARCHAR(255) NOT NULL,
    command_uuid  VARCHAR(127) NOT NULL,
    status        VARCHAR(31)  NOT NULL,
    result        TEXT         NOT NULL,
    not_now_at    TIMESTAMP    NULL,
    not_now_tally INTEGER      NOT NULL DEFAULT 0,
    created_at    TIMESTAMP             DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMP             DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, command_uuid),
    FOREIGN KEY (id)
        REFERENCES enrollments (id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (command_uuid)
        REFERENCES commands (command_uuid)
        ON DELETE CASCADE ON UPDATE CASCADE,
    CHECK (status != ''),
    CHECK (substr(result, 1, 5) = '<?xml')
);

CREATE INDEX IF NOT EXISTS idx_status ON command_results (status);

CREATE TABLE IF NOT EXISTS enrollment_queue
(
    id           VARCHAR(255) NOT NULL,
    command_uuid VARCHAR(127) NOT NULL,
    active       BOOLEAN      NOT NULL DEFAULT TRUE,
    priority     SMALLINT     NOT NULL DEFAULT 0,
    created_at   TIMESTAMP             DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP             DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, command_uuid),
    FOREIGN KEY (id)
        REFERENCES enrollments (id)
        ON DELETE CASCADE ON UPDATE CASCADE,
    FOREIGN KEY (command_uuid)
        REFERENCES commands (command_uuid)
        ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_queue_command ON enrollment_queue (command_uuid);

/* Outstanding items (no result yet) have a NULL status (LEFT JOIN).
 * q.rowid breaks created_at ties: same-second commands keep queue order. */
CREATE VIEW IF NOT EXISTS view_queue AS
SELECT q.id,
       q.created_at,
       q.active,
       q.priority,
       c.command_uuid,
       c.request_type,
       c.command,
       r.updated_at AS result_updated_at,
       r.status,
       r.result
FROM enrollment_queue AS q
         INNER JOIN commands AS c
                    ON q.command_uuid = c.command_uuid
         LEFT JOIN command_results r
                   ON r.command_uuid = q.command_uuid AND r.id = q.id
ORDER BY q.priority DESC,
         q.created_at,
         q.rowid;

CREATE TABLE IF NOT EXISTS push_certs
(
    topic       VARCHAR(255) NOT NULL,
    cert_pem    TEXT         NOT NULL,
    key_pem     TEXT         NOT NULL,
    stale_token INTEGER      NOT NULL,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (topic),
    CHECK (topic != ''),
    CHECK (substr(cert_pem, 1, 27) = '-----BEGIN CERTIFICATE-----'),
    CHECK (substr(key_pem, 1, 5) = '-----')
);

CREATE TABLE IF NOT EXISTS cert_auth_associations
(
    id         VARCHAR(255) NOT NULL,
    sha256     CHAR(64)     NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, sha256),
    CHECK (id != ''),
    CHECK (sha256 != '')
);

/* updated_at on every UPDATE (MySQL's ON UPDATE CURRENT_TIMESTAMP).
 * recursive_triggers is off by default, so the inner UPDATE does not refire. */
CREATE TRIGGER IF NOT EXISTS devices_updated_at AFTER UPDATE ON devices FOR EACH ROW
BEGIN UPDATE devices SET updated_at = CURRENT_TIMESTAMP WHERE rowid = NEW.rowid; END;
CREATE TRIGGER IF NOT EXISTS users_updated_at AFTER UPDATE ON users FOR EACH ROW
BEGIN UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE rowid = NEW.rowid; END;
CREATE TRIGGER IF NOT EXISTS enrollments_updated_at AFTER UPDATE ON enrollments FOR EACH ROW
BEGIN UPDATE enrollments SET updated_at = CURRENT_TIMESTAMP WHERE rowid = NEW.rowid; END;
CREATE TRIGGER IF NOT EXISTS commands_updated_at AFTER UPDATE ON commands FOR EACH ROW
BEGIN UPDATE commands SET updated_at = CURRENT_TIMESTAMP WHERE rowid = NEW.rowid; END;
CREATE TRIGGER IF NOT EXISTS command_results_updated_at AFTER UPDATE ON command_results FOR EACH ROW
BEGIN UPDATE command_results SET updated_at = CURRENT_TIMESTAMP WHERE rowid = NEW.rowid; END;
CREATE TRIGGER IF NOT EXISTS enrollment_queue_updated_at AFTER UPDATE ON enrollment_queue FOR EACH ROW
BEGIN UPDATE enrollment_queue SET updated_at = CURRENT_TIMESTAMP WHERE rowid = NEW.rowid; END;
CREATE TRIGGER IF NOT EXISTS push_certs_updated_at AFTER UPDATE ON push_certs FOR EACH ROW
BEGIN UPDATE push_certs SET updated_at = CURRENT_TIMESTAMP WHERE rowid = NEW.rowid; END;
CREATE TRIGGER IF NOT EXISTS cert_auth_associations_updated_at AFTER UPDATE ON cert_auth_associations FOR EACH ROW
BEGIN UPDATE cert_auth_associations SET updated_at = CURRENT_TIMESTAMP WHERE rowid = NEW.rowid; END;
