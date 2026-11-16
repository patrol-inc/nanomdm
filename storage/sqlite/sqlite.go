// Package sqlite stores and retrieves MDM data in SQLite (WAL mode).
// It is a port of the pgsql backend; the queue and every multi-statement
// change run in transactions, so commands added while a device fetches
// its next one cannot be lost (unlike filekv's on-disk linked list).
package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/micromdm/nanomdm/cryptoutil"
	"github.com/micromdm/nanomdm/mdm"

	"github.com/micromdm/nanolib/log"
	"github.com/micromdm/nanolib/log/ctxlog"

	_ "modernc.org/sqlite" // pure Go, registers the "sqlite" driver
)

// Schema holds the schema for the NanoMDM SQLite storage. New applies it
// (every statement is IF NOT EXISTS).
//
//go:embed schema.sql
var Schema string

var ErrNoCert = errors.New("no certificate in MDM Request")

type SQLiteStorage struct {
	logger log.Logger
	db     *sql.DB
	rm     bool
}

type config struct {
	driver string
	dsn    string
	db     *sql.DB
	logger log.Logger
	rm     bool
}

type Option func(*config)

func WithLogger(logger log.Logger) Option {
	return func(c *config) {
		c.logger = logger
	}
}

func WithDSN(dsn string) Option {
	return func(c *config) {
		c.dsn = dsn
	}
}

func WithDriver(driver string) Option {
	return func(c *config) {
		c.driver = driver
	}
}

func WithDB(db *sql.DB) Option {
	return func(c *config) {
		c.db = db
	}
}

func WithDeleteCommands() Option {
	return func(c *config) {
		c.rm = true
	}
}

// pragmas set on every connection: WAL (readers never block the writer),
// wait up to 10 s for the write lock instead of failing with SQLITE_BUSY,
// enforce foreign keys (the schema relies on ON DELETE CASCADE), and take
// the write lock when a transaction starts so two transactions never both
// read and then deadlock upgrading to write.
const pragmas = "_pragma=journal_mode(WAL)&_pragma=busy_timeout(10000)&_pragma=foreign_keys(1)&_pragma=synchronous(NORMAL)&_txlock=immediate"

// DSN turns a file path (or a "file:" URI) into a DSN with the pragmas.
func DSN(dsn string) string {
	if dsn == "" {
		dsn = "nanomdm.db"
	}
	if !strings.HasPrefix(dsn, "file:") {
		dsn = "file:" + dsn
	}
	if strings.Contains(dsn, "?") {
		return dsn + "&" + pragmas
	}
	return dsn + "?" + pragmas
}

func New(opts ...Option) (*SQLiteStorage, error) {
	cfg := &config{logger: log.NopLogger, driver: "sqlite"}
	for _, opt := range opts {
		opt(cfg)
	}
	var err error
	if cfg.db == nil {
		cfg.db, err = sql.Open(cfg.driver, DSN(cfg.dsn))
		if err != nil {
			return nil, err
		}
	}
	if err = cfg.db.Ping(); err != nil {
		return nil, err
	}
	if _, err = cfg.db.Exec(Schema); err != nil {
		return nil, fmt.Errorf("applying schema: %w", err)
	}
	return &SQLiteStorage{db: cfg.db, logger: cfg.logger, rm: cfg.rm}, nil
}

// nullEmptyString returns a NULL string if s is empty.
func nullEmptyString(s string) sql.NullString {
	return sql.NullString{
		String: s,
		Valid:  s != "",
	}
}

func (s *SQLiteStorage) StoreAuthenticate(r *mdm.Request, msg *mdm.Authenticate) error {
	var pemCert []byte
	if r.Certificate != nil {
		pemCert = cryptoutil.PEMCertificate(r.Certificate.Raw)
	}
	_, err := s.db.ExecContext(
		r.Context(), `
INSERT INTO devices
    (id, identity_cert, serial_number, authenticate, authenticate_at)
VALUES
    (?1, ?2, ?3, ?4, CURRENT_TIMESTAMP)
ON CONFLICT (id) DO
UPDATE SET
    identity_cert = EXCLUDED.identity_cert,
    serial_number = EXCLUDED.serial_number,
    bootstrap_token_b64 = NULL,
    bootstrap_token_at = NULL,
    authenticate = EXCLUDED.authenticate,
    authenticate_at = CURRENT_TIMESTAMP;`,
		r.ID, nullEmptyString(string(pemCert)), nullEmptyString(msg.SerialNumber), string(msg.Raw),
	)
	return err
}

func (s *SQLiteStorage) storeDeviceTokenUpdate(r *mdm.Request, msg *mdm.TokenUpdate) error {
	query := `UPDATE devices SET token_update = ?1, token_update_at = CURRENT_TIMESTAMP`
	where := ` WHERE id = ?2;`
	args := []interface{}{string(msg.Raw)}
	// separately store the Unlock Token per MDM spec
	if len(msg.UnlockToken) > 0 {
		query += `, unlock_token = ?2, unlock_token_at = CURRENT_TIMESTAMP `
		args = append(args, msg.UnlockToken)
		where = ` WHERE id = ?3;`
	}
	args = append(args, r.ID)
	_, err := s.db.ExecContext(r.Context(), query+where, args...)
	return err
}

func (s *SQLiteStorage) storeUserTokenUpdate(r *mdm.Request, msg *mdm.TokenUpdate) error {
	// there shouldn't be an Unlock Token on the user channel, but
	// complain if there is to warn an admin
	if len(msg.UnlockToken) > 0 {
		ctxlog.Logger(r.Context(), s.logger).Info(
			"msg", "Unlock Token on user channel not stored",
		)
	}
	_, err := s.db.ExecContext(
		r.Context(), `
INSERT INTO users
    (id, device_id, user_short_name, user_long_name, token_update, token_update_at)
VALUES
    (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)
ON CONFLICT (id, device_id) DO UPDATE 
SET 
    device_id = EXCLUDED.device_id,
    user_short_name = EXCLUDED.user_short_name,
    user_long_name = EXCLUDED.user_long_name,
    token_update = EXCLUDED.token_update,
    token_update_at = CURRENT_TIMESTAMP;`,
		r.ID,
		r.ParentID,
		nullEmptyString(msg.UserShortName),
		nullEmptyString(msg.UserLongName),
		string(msg.Raw),
	)
	return err
}

func (s *SQLiteStorage) StoreTokenUpdate(r *mdm.Request, msg *mdm.TokenUpdate) error {
	var err error
	var deviceId, userId string
	resolved := (&msg.Enrollment).Resolved()
	if err = resolved.Validate(); err != nil {
		return err
	}
	if resolved.IsUserChannel {
		deviceId = r.ParentID
		userId = r.ID
		err = s.storeUserTokenUpdate(r, msg)
	} else {
		deviceId = r.ID
		err = s.storeDeviceTokenUpdate(r, msg)
	}
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(
		r.Context(), `
INSERT INTO enrollments
	(id, device_id, user_id, type, topic, push_magic, token_hex, last_seen_at, token_update_tally)
VALUES
	(?1, ?2, ?3, ?4, ?5, ?6, ?7, CURRENT_TIMESTAMP, 1)
ON CONFLICT (id) DO UPDATE 
SET
    device_id = EXCLUDED.device_id,
    user_id = EXCLUDED.user_id,
    type = EXCLUDED.type,
    topic = EXCLUDED.topic,
    push_magic = EXCLUDED.push_magic,
    token_hex = EXCLUDED.token_hex,
	enabled = TRUE,
	last_seen_at = CURRENT_TIMESTAMP,
	token_update_tally = enrollments.token_update_tally + 1;`,
		r.ID,
		deviceId,
		nullEmptyString(userId),
		r.Type.String(),
		msg.Topic,
		msg.PushMagic,
		msg.Token.String(),
	)
	return err
}

func (s *SQLiteStorage) RetrieveTokenUpdateTally(ctx context.Context, id string) (int, error) {
	var tally int
	err := s.db.QueryRowContext(
		ctx,
		`SELECT token_update_tally FROM enrollments WHERE id = ?1;`,
		id,
	).Scan(&tally)
	return tally, err
}

func (s *SQLiteStorage) StoreUserAuthenticate(r *mdm.Request, msg *mdm.UserAuthenticate) error {
	colName := "user_authenticate"
	colAtName := "user_authenticate_at"
	// if the DigestResponse is empty then this is the first (of two)
	// UserAuthenticate messages depending on our response
	if msg.DigestResponse != "" {
		colName = "user_authenticate_digest"
		colAtName = "user_authenticate_digest_at"
	}
	_, err := s.db.ExecContext(
		r.Context(), `
INSERT INTO users
    (id, device_id, user_short_name, user_long_name, `+colName+`, `+colAtName+`)
VALUES
    (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)
ON CONFLICT (id, device_id) DO UPDATE 
SET
    device_id = EXCLUDED.device_id,
    user_short_name = EXCLUDED.user_short_name,
    user_long_name = EXCLUDED.user_long_name,
    `+colName+` = EXCLUDED.`+colName+`,
    `+colAtName+` = EXCLUDED.`+colAtName+`;`,
		r.ID,
		r.ParentID,
		nullEmptyString(msg.UserShortName),
		nullEmptyString(msg.UserLongName),
		string(msg.Raw),
	)
	if err != nil {
		return err
	}
	return s.updateLastSeen(r)
}

// Disable can be called for an Authenticate or CheckOut message
func (s *SQLiteStorage) Disable(r *mdm.Request) error {
	if r.ParentID != "" {
		return errors.New("can only disable a device channel")
	}
	_, err := s.db.ExecContext(
		r.Context(),
		`UPDATE enrollments SET enabled = FALSE, token_update_tally = 0, last_seen_at = CURRENT_TIMESTAMP WHERE device_id = ?1 AND enabled = TRUE;`,
		r.ID,
	)
	return err
}

func (s *SQLiteStorage) updateLastSeen(r *mdm.Request) (err error) {
	_, err = s.db.ExecContext(
		r.Context(),
		`UPDATE enrollments SET last_seen_at = CURRENT_TIMESTAMP WHERE id = ?1`,
		r.ID,
	)
	if err != nil {
		err = fmt.Errorf("updating last seen: %w", err)
	}
	return
}
