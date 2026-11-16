package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/micromdm/nanomdm/mdm"
)

// Executes SQL statements that return a single COUNT(*) of rows.
func (s *SQLiteStorage) queryRowContextRowExists(ctx context.Context, query string, args ...interface{}) (bool, error) {
	var ct int
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&ct)
	return ct > 0, err
}

func (s *SQLiteStorage) EnrollmentHasCertHash(r *mdm.Request, _ string) (bool, error) {
	return s.queryRowContextRowExists(
		r.Context(),
		`SELECT COUNT(*) FROM cert_auth_associations WHERE id = ?1;`,
		r.ID,
	)
}

func (s *SQLiteStorage) HasCertHash(r *mdm.Request, hash string) (bool, error) {
	return s.queryRowContextRowExists(
		r.Context(),
		`SELECT COUNT(*) FROM cert_auth_associations WHERE sha256 = ?1;`,
		strings.ToLower(hash),
	)
}

func (s *SQLiteStorage) IsCertHashAssociated(r *mdm.Request, hash string) (bool, error) {
	return s.queryRowContextRowExists(
		r.Context(),
		`SELECT COUNT(*) FROM cert_auth_associations WHERE id = ?1 AND sha256 = ?2;`,
		r.ID, strings.ToLower(hash),
	)
}

// AssociateCertHash "DO NOTHING" on duplicated keys
func (s *SQLiteStorage) AssociateCertHash(r *mdm.Request, hash string) error {
	_, err := s.db.ExecContext(
		r.Context(), `
INSERT INTO cert_auth_associations (id, sha256) 
VALUES (?1, ?2)
ON CONFLICT (id, sha256) DO UPDATE SET updated_at=CURRENT_TIMESTAMP;`,
		r.ID,
		strings.ToLower(hash),
	)
	return err
}

func (s *SQLiteStorage) EnrollmentFromHash(ctx context.Context, hash string) (string, error) {
	var id string
	err := s.db.QueryRowContext(
		ctx,
		`SELECT id FROM cert_auth_associations WHERE sha256 = ?1 LIMIT 1;`,
		hash,
	).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return id, err
}
