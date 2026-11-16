package sqlite

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/micromdm/nanomdm/mdm"
	"github.com/micromdm/nanomdm/storage"
	"github.com/micromdm/nanomdm/storage/diskv"
)

// What broke Patrol's minis on filekv: right after enrollment the server
// queues a run of setup commands one by one while the Mac is already
// fetching and acknowledging them. Every command must arrive exactly once,
// in the order queued.
const setupCommands = 17

func commandPlist(uuid, requestType string) []byte {
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CommandUUID</key><string>%s</string><key>Command</key><dict><key>RequestType</key><string>%s</string></dict></dict></plist>`, uuid, requestType))
}

func resultPlist(uuid string) []byte {
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CommandUUID</key><string>%s</string><key>Status</key><string>Acknowledged</string></dict></plist>`, uuid))
}

// runSetupRace returns the command UUIDs the device received, in order.
func runSetupRace(t *testing.T, s storage.AllStorage, id string) []string {
	ctx := context.Background()
	r := mdm.NewRequestWithContext(ctx, nil)
	r.EnrollID = &mdm.EnrollID{Type: mdm.Device, ID: id}

	var wg sync.WaitGroup
	done := make(chan struct{})
	wg.Add(1)
	go func() { // the server queuing setup
		defer wg.Done()
		defer close(done)
		for i := 0; i < setupCommands; i++ {
			uuid := fmt.Sprintf("%s-cmd-%02d", id, i)
			cmd := &mdm.Command{CommandUUID: uuid, Raw: commandPlist(uuid, "InstallProfile")}
			cmd.Command.RequestType = "InstallProfile"
			if _, err := s.EnqueueCommand(ctx, []string{id}, cmd); err != nil {
				t.Errorf("enqueue %s: %v", uuid, err)
				return
			}
		}
	}()

	var got []string
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) { // the Mac fetching and acknowledging
		cmd, err := s.RetrieveNextCommand(r, true)
		if err != nil {
			t.Fatalf("retrieve: %v", err)
		}
		if cmd == nil {
			select {
			case <-done:
				// queuing finished; one more look so nothing queued last is missed
				if cmd, err = s.RetrieveNextCommand(r, true); err != nil || cmd == nil {
					wg.Wait()
					return got
				}
			default:
				continue
			}
		}
		got = append(got, cmd.CommandUUID)
		res := &mdm.CommandResults{CommandUUID: cmd.CommandUUID, Status: "Acknowledged", Raw: resultPlist(cmd.CommandUUID)}
		if err := s.StoreCommandReport(r, res); err != nil {
			t.Fatalf("report: %v", err)
		}
	}
	t.Fatal("timed out")
	return nil
}

func inOrderOnce(id string, got []string) bool {
	if len(got) != setupCommands {
		return false
	}
	for i, uuid := range got {
		if uuid != fmt.Sprintf("%s-cmd-%02d", id, i) {
			return false
		}
	}
	return true
}

func TestSetupRaceSQLite(t *testing.T) {
	s, err := New(WithDSN(filepath.Join(t.TempDir(), "race.db")))
	if err != nil {
		t.Fatal(err)
	}
	for trial := 0; trial < 50; trial++ {
		id := fmt.Sprintf("DEVICE-%02d", trial)
		// the enrollment row the queue's foreign keys need
		if _, err := s.db.Exec(`INSERT INTO devices (id, authenticate, authenticate_at) VALUES (?1, 'x', CURRENT_TIMESTAMP)`, id); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`INSERT INTO enrollments (id, device_id, type, topic, push_magic, token_hex, last_seen_at) VALUES (?1, ?1, 'Device', 't', 'm', 'aa', CURRENT_TIMESTAMP)`, id); err != nil {
			t.Fatal(err)
		}
		if got := runSetupRace(t, s, id); !inOrderOnce(id, got) {
			t.Fatalf("trial %d: device got %d commands, want all %d once and in order: %v", trial, len(got), setupCommands, got)
		}
	}
}

// Not an assertion on filekv's behaviour, which depends on timing: it logs how
// often the same race loses or repeats commands there, for comparison.
func TestSetupRaceFilekvForComparison(t *testing.T) {
	s := diskv.New(t.TempDir())
	broken := 0
	for trial := 0; trial < 50; trial++ {
		id := fmt.Sprintf("DEVICE-%02d", trial)
		if got := runSetupRace(t, s, id); !inOrderOnce(id, got) {
			broken++
		}
	}
	t.Logf("filekv: %d of 50 setups lost, repeated or reordered commands", broken)
}

// Closer to what the minis saw (one command acknowledged twice, then the
// queue looked empty): two overlapping fetch-and-acknowledge loops for the
// same Mac while the server queues. A command may be delivered twice; none
// may be lost, and the queue must end empty.
func runOverlapRace(t *testing.T, s storage.AllStorage, id string) (acked map[string]bool, leftover bool) {
	ctx := context.Background()
	acked = map[string]bool{}
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < setupCommands; i++ {
			uuid := fmt.Sprintf("%s-cmd-%02d", id, i)
			cmd := &mdm.Command{CommandUUID: uuid, Raw: commandPlist(uuid, "InstallProfile")}
			cmd.Command.RequestType = "InstallProfile"
			if _, err := s.EnqueueCommand(ctx, []string{id}, cmd); err != nil {
				t.Errorf("enqueue %s: %v", uuid, err)
				return
			}
		}
	}()
	var wg sync.WaitGroup
	for f := 0; f < 2; f++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := mdm.NewRequestWithContext(ctx, nil)
			r.EnrollID = &mdm.EnrollID{Type: mdm.Device, ID: id}
			deadline := time.Now().Add(20 * time.Second)
			for time.Now().Before(deadline) {
				cmd, err := s.RetrieveNextCommand(r, true)
				if err != nil {
					t.Errorf("retrieve: %v", err)
					return
				}
				if cmd == nil {
					select {
					case <-done:
						return
					default:
						continue
					}
				}
				res := &mdm.CommandResults{CommandUUID: cmd.CommandUUID, Status: "Acknowledged", Raw: resultPlist(cmd.CommandUUID)}
				if err := s.StoreCommandReport(r, res); err != nil {
					t.Errorf("report: %v", err)
					return
				}
				mu.Lock()
				acked[cmd.CommandUUID] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	<-done
	// drain: anything still reachable gets acknowledged now
	r := mdm.NewRequestWithContext(ctx, nil)
	r.EnrollID = &mdm.EnrollID{Type: mdm.Device, ID: id}
	for {
		cmd, err := s.RetrieveNextCommand(r, true)
		if err != nil || cmd == nil {
			break
		}
		acked[cmd.CommandUUID] = true
		leftover = true
		_ = s.StoreCommandReport(r, &mdm.CommandResults{CommandUUID: cmd.CommandUUID, Status: "Acknowledged", Raw: resultPlist(cmd.CommandUUID)})
	}
	return acked, leftover
}

func TestOverlapRaceSQLite(t *testing.T) {
	s, err := New(WithDSN(filepath.Join(t.TempDir(), "overlap.db")))
	if err != nil {
		t.Fatal(err)
	}
	for trial := 0; trial < 50; trial++ {
		id := fmt.Sprintf("DEVICE-%02d", trial)
		if _, err := s.db.Exec(`INSERT INTO devices (id, authenticate, authenticate_at) VALUES (?1, 'x', CURRENT_TIMESTAMP)`, id); err != nil {
			t.Fatal(err)
		}
		if _, err := s.db.Exec(`INSERT INTO enrollments (id, device_id, type, topic, push_magic, token_hex, last_seen_at) VALUES (?1, ?1, 'Device', 't', 'm', 'aa', CURRENT_TIMESTAMP)`, id); err != nil {
			t.Fatal(err)
		}
		if acked, _ := runOverlapRace(t, s, id); len(acked) != setupCommands {
			t.Fatalf("trial %d: %d of %d commands reached the device", trial, len(acked), setupCommands)
		}
	}
}

func TestOverlapRaceFilekvForComparison(t *testing.T) {
	s := diskv.New(t.TempDir())
	lost := 0
	for trial := 0; trial < 50; trial++ {
		id := fmt.Sprintf("DEVICE-%02d", trial)
		if acked, _ := runOverlapRace(t, s, id); len(acked) != setupCommands {
			lost++
		}
	}
	t.Logf("filekv: %d of 50 setups lost commands", lost)
}
