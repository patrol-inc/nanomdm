package diskv

import (
	nlkv "github.com/micromdm/nanolib/storage/kv"
	"github.com/micromdm/nanomdm/storage/kv"
)

// Buckets opens the raw buckets of a filekv store, for converters that need
// keys the KV storage interfaces don't expose (device certificates, unlock
// tokens, certificate associations, push certificates).
type Buckets struct {
	Devices, Enrollments, Users, CertAuth, PushCert nlkv.TxnBucketWithCRUD
	*kv.KV
}

func OpenBuckets(path string) *Buckets {
	b := &Buckets{
		Users:    newBucket(path, "users"),
		CertAuth: newBucket(path, "cert_auth"),
		PushCert: newBucketWithTransform(path, "push_cert",
			StripPrefixTransform(Split2X2Transform, "com.apple.mgmt.External.")),
		Devices:     newBucket(path, "devices"),
		Enrollments: newBucket(path, "enrollments"),
	}
	b.KV = kv.New(b.Users, b.CertAuth, newBucket(path, "queue"), b.PushCert, b.Devices, b.Enrollments)
	return b
}
