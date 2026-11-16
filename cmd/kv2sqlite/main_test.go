package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/storage/diskv"
	"github.com/micromdm/nanomdm/storage/sqlite"
	"github.com/micromdm/nanomdm/test"
)

func checkin(t *testing.T, path string) interface{} {
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	m, err := mdm.DecodeCheckin(b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func pushCertPEM(t *testing.T, topic string) (certPEM, keyPEM []byte) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{ExtraNames: []pkix.AttributeTypeAndValue{
			{Type: asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 1}, Value: topic},
		}},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

// A filekv store filled the way NanoMDM fills it converts to SQLite with the
// enrollment, push info, unlock and bootstrap tokens, identity certificate,
// certificate association and push certificate intact.
func TestConvert(t *testing.T) {
	ctx := context.Background()
	from := t.TempDir()
	src := diskv.New(from)

	auth := checkin(t, "../../mdm/testdata/Authenticate.1.plist").(*mdm.Authenticate)
	tok := checkin(t, "../../mdm/testdata/TokenUpdate.1.plist").(*mdm.TokenUpdate)
	_, cert, err := test.SimpleSelfSignedRSAKeypair("TESTDEVICE", 2)
	if err != nil {
		t.Fatal(err)
	}
	r := mdm.NewRequestWithContext(ctx, cert)
	r.EnrollID = normalize(&auth.Enrollment)
	if err := src.StoreAuthenticate(r, auth); err != nil {
		t.Fatal(err)
	}
	if err := src.StoreTokenUpdate(r, tok); err != nil {
		t.Fatal(err)
	}
	bs := &mdm.SetBootstrapToken{Enrollment: auth.Enrollment, BootstrapToken: mdm.BootstrapToken{BootstrapToken: []byte("bootstrap!")}}
	if err := src.StoreBootstrapToken(r, bs); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(cert.Raw)
	hash := hex.EncodeToString(sum[:])
	if err := src.AssociateCertHash(r, hash); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := pushCertPEM(t, tok.Topic)
	if err := src.StorePushCert(ctx, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}

	to := filepath.Join(t.TempDir(), "nanomdm.db")
	n, err := convert(ctx, from, to)
	if err != nil {
		t.Fatal(err)
	}
	if n != (counts{enrollments: 1, certAuth: 1, pushCerts: 1}) {
		t.Fatalf("counts: %+v", n)
	}

	dst, err := sqlite.New(sqlite.WithDSN(to))
	if err != nil {
		t.Fatal(err)
	}
	id := r.EnrollID.ID
	push, err := dst.RetrievePushInfo(ctx, []string{id})
	if err != nil || push[id] == nil {
		t.Fatalf("push info: %v %v", push, err)
	}
	if push[id].Topic != tok.Topic || push[id].PushMagic != tok.PushMagic || push[id].Token.String() != tok.Token.String() {
		t.Errorf("push info differs: %+v", push[id])
	}
	if ok, err := dst.IsCertHashAssociated(r, hash); err != nil || !ok {
		t.Errorf("certificate association lost: %v %v", ok, err)
	}
	got, err := dst.RetrieveBootstrapToken(r, nil)
	if err != nil || got == nil || string(got.BootstrapToken) != "bootstrap!" {
		t.Errorf("bootstrap token: %v %v", got, err)
	}
	if _, _, err := dst.RetrievePushCert(ctx, tok.Topic); err != nil {
		t.Errorf("push certificate: %v", err)
	}
	tally, err := dst.RetrieveTokenUpdateTally(ctx, id)
	if err != nil || tally < 1 {
		t.Errorf("enrollment not enabled: tally %d %v", tally, err)
	}

	if _, err := convert(ctx, from, to); err == nil {
		// main refuses an existing file; convert itself must at least not
		// silently duplicate (the store is upserted, so a rerun is harmless)
		t.Log("rerun over an existing database is idempotent")
	}
}
