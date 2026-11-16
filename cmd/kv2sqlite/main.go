// Command kv2sqlite copies a NanoMDM filekv store into a new SQLite store:
// enrollments (Authenticate, TokenUpdate, bootstrap and unlock tokens,
// device identity certificates), certificate-auth associations and push
// certificates. Command queues and results are not copied: the SQLite store
// starts with empty queues. Run it with NanoMDM stopped.
//
//	kv2sqlite -from /data/db -to /data/nanomdm.db
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	stdlog "log"
	"os"
	"strings"

	nlkv "github.com/micromdm/nanolib/storage/kv"
	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/storage/diskv"
	"github.com/micromdm/nanomdm/storage/sqlite"
)

func main() {
	from := flag.String("from", "", "filekv directory (NanoMDM -storage-dsn for filekv)")
	to := flag.String("to", "", "SQLite database file to create (must not exist)")
	flag.Parse()
	if *from == "" || *to == "" {
		stdlog.Fatal("usage: kv2sqlite -from <filekv dir> -to <new.db>")
	}
	if _, err := os.Stat(*to); err == nil {
		stdlog.Fatalf("%s already exists; refusing to overwrite", *to)
	}
	n, err := convert(context.Background(), *from, *to)
	if err != nil {
		stdlog.Fatal(err)
	}
	fmt.Printf("copied %d enrollments, %d certificate associations, %d push certificates\n", n.enrollments, n.certAuth, n.pushCerts)
}

type counts struct{ enrollments, certAuth, pushCerts int }

func normalize(e *mdm.Enrollment) *mdm.EnrollID {
	r := e.Resolved()
	if r == nil {
		return nil
	}
	eid := &mdm.EnrollID{Type: r.Type, ID: r.DeviceChannelID}
	if r.IsUserChannel {
		eid.ID += ":" + r.UserChannelID
		eid.ParentID = r.DeviceChannelID
	}
	return eid
}

func get(ctx context.Context, b nlkv.TxnBucketWithCRUD, key string) ([]byte, error) {
	v, err := b.Get(ctx, key)
	if errors.Is(err, nlkv.ErrKeyNotFound) {
		return nil, nil
	}
	return v, err
}

func convert(ctx context.Context, from, to string) (n counts, err error) {
	src := diskv.OpenBuckets(from)
	dst, err := sqlite.New(sqlite.WithDSN(to))
	if err != nil {
		return n, err
	}

	// Push certificates first: enrollments reference their topics.
	for _, key := range nlkv.AllKeys(ctx, src.PushCert) {
		topic, ok := strings.CutSuffix(key, ".pem")
		if !ok {
			continue
		}
		certPEM, err := get(ctx, src.PushCert, topic+".pem")
		if err != nil {
			return n, err
		}
		keyPEM, err := get(ctx, src.PushCert, topic+".key")
		if err != nil {
			return n, err
		}
		if certPEM == nil || keyPEM == nil {
			return n, fmt.Errorf("push certificate %s is incomplete", topic)
		}
		if err := dst.StorePushCert(ctx, certPEM, keyPEM); err != nil {
			return n, fmt.Errorf("push certificate %s: %w", topic, err)
		}
		n.pushCerts++
	}

	// Enrollments, in the order NanoMDM's own migration uses (Authenticate,
	// then TokenUpdate, then bootstrap token; device before user channels).
	checkins := make(chan interface{})
	go func() {
		if err := src.RetrieveMigrationCheckins(ctx, checkins); err != nil {
			checkins <- err
		}
		close(checkins)
	}()
	for c := range checkins {
		var e *mdm.Enrollment
		switch v := c.(type) {
		case *mdm.Authenticate:
			e = &v.Enrollment
		case *mdm.TokenUpdate:
			e = &v.Enrollment
		case *mdm.SetBootstrapToken:
			e = &v.Enrollment
		case error:
			return n, v
		default:
			return n, fmt.Errorf("unexpected check-in %T", c)
		}
		eid := normalize(e)
		if eid == nil {
			return n, errors.New("check-in without an enrollment")
		}
		r := mdm.NewRequestWithContext(ctx, nil)
		r.EnrollID = eid
		switch v := c.(type) {
		case *mdm.Authenticate:
			der, err := get(ctx, src.Devices, eid.ID+".cert")
			if err != nil {
				return n, err
			}
			if der != nil {
				if r.Certificate, err = x509.ParseCertificate(der); err != nil {
					return n, fmt.Errorf("%s identity certificate: %w", eid.ID, err)
				}
			}
			err = dst.StoreAuthenticate(r, v)
			if err == nil {
				err = dst.Disable(r) // as the service does after Authenticate
			}
			if err != nil {
				return n, fmt.Errorf("%s Authenticate: %w", eid.ID, err)
			}
		case *mdm.TokenUpdate:
			if v.UnlockToken == nil {
				// the unlock token comes in the first TokenUpdate only;
				// filekv keeps it separately
				if v.UnlockToken, err = get(ctx, src.Enrollments, eid.ID+".unl_tok"); err != nil {
					return n, err
				}
			}
			if err := dst.StoreTokenUpdate(r, v); err != nil {
				return n, fmt.Errorf("%s TokenUpdate: %w", eid.ID, err)
			}
			n.enrollments++
		case *mdm.SetBootstrapToken:
			if err := dst.StoreBootstrapToken(r, v); err != nil {
				return n, fmt.Errorf("%s bootstrap token: %w", eid.ID, err)
			}
		}
	}

	// Certificate-auth associations: without them every Mac's next request
	// would be refused.
	for _, key := range nlkv.AllKeys(ctx, src.CertAuth) {
		id, ok := strings.CutSuffix(key, ".cert_hash")
		if !ok {
			continue
		}
		hash, err := get(ctx, src.CertAuth, key)
		if err != nil {
			return n, err
		}
		r := mdm.NewRequestWithContext(ctx, nil)
		r.EnrollID = &mdm.EnrollID{ID: id}
		if err := dst.AssociateCertHash(r, string(hash)); err != nil {
			return n, fmt.Errorf("%s certificate association: %w", id, err)
		}
		n.certAuth++
	}
	return n, nil
}
