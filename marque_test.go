package cloudflare

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
)

// --- Caddyfile parsing tests ---

func TestMarqueSingleLine(t *testing.T) {
	handle := "user.bsky.social"
	password := "abcd-efgh-ijkl-mnop"
	config := fmt.Sprintf("marque %s %s", handle, password)

	dispenser := caddyfile.NewTestDispenser(config)
	p := MarqueProvider{}

	err := p.UnmarshalCaddyfile(dispenser)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	if p.Handle != handle {
		t.Errorf("Expected Handle=%q got %q", handle, p.Handle)
	}
	if p.AppPassword != password {
		t.Errorf("Expected AppPassword=%q got %q", password, p.AppPassword)
	}
}

func TestMarqueBlockSyntax(t *testing.T) {
	handle := "did:plc:abc123"
	password := "secret-password"
	config := fmt.Sprintf(`marque {
	handle %s
	app_password %s
}`, handle, password)

	dispenser := caddyfile.NewTestDispenser(config)
	p := MarqueProvider{}

	err := p.UnmarshalCaddyfile(dispenser)
	if err != nil {
		t.Fatalf("UnmarshalCaddyfile failed: %v", err)
	}

	if p.Handle != handle {
		t.Errorf("Expected Handle=%q got %q", handle, p.Handle)
	}
	if p.AppPassword != password {
		t.Errorf("Expected AppPassword=%q got %q", password, p.AppPassword)
	}
}

func TestMarqueEmptyConfig(t *testing.T) {
	config := "marque"

	dispenser := caddyfile.NewTestDispenser(config)
	p := MarqueProvider{}

	err := p.UnmarshalCaddyfile(dispenser)
	if err == nil {
		t.Error("Expected error for empty config, got nil")
	}
}

func TestMarqueMissingPassword(t *testing.T) {
	config := "marque user.bsky.social"

	dispenser := caddyfile.NewTestDispenser(config)
	p := MarqueProvider{}

	err := p.UnmarshalCaddyfile(dispenser)
	if err == nil {
		t.Error("Expected error for missing password, got nil")
	}
}

func TestMarqueMissingHandle(t *testing.T) {
	config := `marque {
	app_password secret
}`

	dispenser := caddyfile.NewTestDispenser(config)
	p := MarqueProvider{}

	err := p.UnmarshalCaddyfile(dispenser)
	if err == nil {
		t.Error("Expected error for missing handle, got nil")
	}
}

func TestMarqueTooManyArgs(t *testing.T) {
	config := "marque a b c"

	dispenser := caddyfile.NewTestDispenser(config)
	p := MarqueProvider{}

	err := p.UnmarshalCaddyfile(dispenser)
	if err == nil {
		t.Error("Expected error for too many args, got nil")
	}
}

func TestMarqueUnknownDirective(t *testing.T) {
	config := `marque {
	handle user.bsky.social
	app_password secret
	foobar baz
}`

	dispenser := caddyfile.NewTestDispenser(config)
	p := MarqueProvider{}

	err := p.UnmarshalCaddyfile(dispenser)
	if err == nil {
		t.Error("Expected error for unknown subdirective, got nil")
	}
}

// --- Provision tests ---

func TestMarqueProvisionPlaceholders(t *testing.T) {
	p := &MarqueProvider{
		Handle:      "{env.HANDLE}",
		AppPassword: "{env.APP_PASSWORD}",
	}

	// Provision with a context — placeholders that can't resolve will be replaced with empty string
	err := p.Provision(caddy.Context{})
	// Should fail because placeholders resolve to empty
	if err == nil {
		t.Error("Expected error for empty handle after placeholder resolution, got nil")
	}
}

func TestMarqueProvisionValid(t *testing.T) {
	p := &MarqueProvider{
		Handle:      "user.bsky.social",
		AppPassword: "secret-password",
	}

	err := p.Provision(caddy.Context{})
	if err != nil {
		t.Errorf("Provision failed: %v", err)
	}
}

// --- Record conversion round-trip tests ---

func TestEntryToRecordA(t *testing.T) {
	entry := RecordEntry{
		Name:       "@",
		RecordType: "A",
		Value:      "192.0.2.1",
		TTL:        3600,
	}

	rec, err := entryToRecord(entry)
	if err != nil {
		t.Fatalf("entryToRecord failed: %v", err)
	}

	rr := rec.RR()
	if rr.Name != "@" {
		t.Errorf("expected Name=@ got %q", rr.Name)
	}
	if rr.Type != "A" {
		t.Errorf("expected Type=A got %q", rr.Type)
	}
	if rr.Data != "192.0.2.1" {
		t.Errorf("expected Data=192.0.2.1 got %q", rr.Data)
	}
	if rr.TTL != 3600*time.Second {
		t.Errorf("expected TTL=3600s got %v", rr.TTL)
	}
}

func TestEntryToRecordAAAA(t *testing.T) {
	entry := RecordEntry{
		Name:       "www",
		RecordType: "AAAA",
		Value:      "2001:db8::1",
		TTL:        300,
	}

	rec, err := entryToRecord(entry)
	if err != nil {
		t.Fatalf("entryToRecord failed: %v", err)
	}

	rr := rec.RR()
	if rr.Type != "AAAA" {
		t.Errorf("expected Type=AAAA got %q", rr.Type)
	}
	if rr.Data != "2001:db8::1" {
		t.Errorf("expected Data=2001:db8::1 got %q", rr.Data)
	}
}

func TestEntryToRecordCNAME(t *testing.T) {
	entry := RecordEntry{
		Name:       "blog",
		RecordType: "CNAME",
		Value:      "example.com",
		TTL:        600,
	}

	rec, err := entryToRecord(entry)
	if err != nil {
		t.Fatalf("entryToRecord failed: %v", err)
	}

	rr := rec.RR()
	if rr.Type != "CNAME" {
		t.Errorf("expected Type=CNAME got %q", rr.Type)
	}
	if rr.Data != "example.com" {
		t.Errorf("expected Data=example.com got %q", rr.Data)
	}
}

func TestEntryToRecordMX(t *testing.T) {
	entry := RecordEntry{
		Name:       "@",
		RecordType: "MX",
		Value:      "mail.example.com",
		TTL:        3600,
		Priority:   10,
	}

	rec, err := entryToRecord(entry)
	if err != nil {
		t.Fatalf("entryToRecord failed: %v", err)
	}

	rr := rec.RR()
	if rr.Type != "MX" {
		t.Errorf("expected Type=MX got %q", rr.Type)
	}
	if rr.Data != "10 mail.example.com" {
		t.Errorf("expected Data='10 mail.example.com' got %q", rr.Data)
	}
}

func TestEntryToRecordSRV(t *testing.T) {
	entry := RecordEntry{
		Name:       "_sip._tcp",
		RecordType: "SRV",
		Value:      "5 5060 sip.example.com",
		TTL:        86400,
		Priority:   10,
	}

	rec, err := entryToRecord(entry)
	if err != nil {
		t.Fatalf("entryToRecord failed: %v", err)
	}

	rr := rec.RR()
	if rr.Type != "SRV" {
		t.Errorf("expected Type=SRV got %q", rr.Type)
	}
	if rr.Data != "10 5 5060 sip.example.com" {
		t.Errorf("expected Data='10 5 5060 sip.example.com' got %q", rr.Data)
	}
}

func TestEntryToRecordTXT(t *testing.T) {
	entry := RecordEntry{
		Name:       "@",
		RecordType: "TXT",
		Value:      "v=spf1 include:_spf.example.com ~all",
		TTL:        3600,
	}

	rec, err := entryToRecord(entry)
	if err != nil {
		t.Fatalf("entryToRecord failed: %v", err)
	}

	rr := rec.RR()
	if rr.Type != "TXT" {
		t.Errorf("expected Type=TXT got %q", rr.Type)
	}
	if rr.Data != "v=spf1 include:_spf.example.com ~all" {
		t.Errorf("expected SPF data, got %q", rr.Data)
	}
}

func TestEntryToRecordCAA(t *testing.T) {
	entry := RecordEntry{
		Name:       "@",
		RecordType: "CAA",
		Value:      `0 issue "letsencrypt.org"`,
		TTL:        3600,
	}

	rec, err := entryToRecord(entry)
	if err != nil {
		t.Fatalf("entryToRecord failed: %v", err)
	}

	rr := rec.RR()
	if rr.Type != "CAA" {
		t.Errorf("expected Type=CAA got %q", rr.Type)
	}
}

func TestRoundTripA(t *testing.T) {
	original := &libdns.Address{
		Name: "api",
		TTL:  300 * time.Second,
		IP:   netip.MustParseAddr("203.0.113.1"),
	}

	entry := recordToEntry(original)
	reconstructed, err := entryToRecord(entry)
	if err != nil {
		t.Fatalf("entryToRecord failed: %v", err)
	}

	origRR := original.RR()
	reconRR := reconstructed.RR()

	if origRR.Name != reconRR.Name {
		t.Errorf("Name mismatch: %q vs %q", origRR.Name, reconRR.Name)
	}
	if origRR.Type != reconRR.Type {
		t.Errorf("Type mismatch: %q vs %q", origRR.Type, reconRR.Type)
	}
	if origRR.Data != reconRR.Data {
		t.Errorf("Data mismatch: %q vs %q", origRR.Data, reconRR.Data)
	}
	if origRR.TTL != reconRR.TTL {
		t.Errorf("TTL mismatch: %v vs %v", origRR.TTL, reconRR.TTL)
	}
}

func TestRoundTripMX(t *testing.T) {
	original := &libdns.MX{
		Name:       "@",
		TTL:        3600 * time.Second,
		Preference: 20,
		Target:     "mx2.example.com",
	}

	entry := recordToEntry(original)
	reconstructed, err := entryToRecord(entry)
	if err != nil {
		t.Fatalf("entryToRecord failed: %v", err)
	}

	origRR := original.RR()
	reconRR := reconstructed.RR()

	if origRR.Type != "MX" {
		t.Fatalf("original type mismatch")
	}
	if origRR.Name != reconRR.Name {
		t.Errorf("Name mismatch: %q vs %q", origRR.Name, reconRR.Name)
	}
	if origRR.Type != reconRR.Type {
		t.Errorf("Type mismatch: %q vs %q", origRR.Type, reconRR.Type)
	}
	if origRR.Data != reconRR.Data {
		t.Errorf("Data mismatch: %q vs %q", origRR.Data, reconRR.Data)
	}
}

func TestRoundTripTXT(t *testing.T) {
	txtValue := "_acme-challenge.example.com"
	original := &libdns.TXT{
		Name: "_acme-challenge",
		TTL:  120 * time.Second,
		Text: txtValue,
	}

	entry := recordToEntry(original)
	reconstructed, err := entryToRecord(entry)
	if err != nil {
		t.Fatalf("entryToRecord failed: %v", err)
	}

	origRR := original.RR()
	reconRR := reconstructed.RR()

	if origRR.Type != "TXT" {
		t.Fatalf("original type mismatch")
	}
	if origRR.Name != reconRR.Name {
		t.Errorf("Name mismatch: %q vs %q", origRR.Name, reconRR.Name)
	}
	if origRR.Type != reconRR.Type {
		t.Errorf("Type mismatch: %q vs %q", origRR.Type, reconRR.Type)
	}
	if origRR.Data != reconRR.Data {
		t.Errorf("Data mismatch: %q vs %q", origRR.Data, reconRR.Data)
	}
}

func TestRecordEntryNameNormalization(t *testing.T) {
	// Names with trailing dots should be stripped in recordToEntry
	rec := &libdns.TXT{
		Name: "sub.example.com.",
		TTL:  300 * time.Second,
		Text: "normalized",
	}

	entry := recordToEntry(rec)
	if entry.Name != "sub.example.com" {
		t.Errorf("Expected normalized name 'sub.example.com' got %q", entry.Name)
	}
}

