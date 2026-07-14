// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bluesky-social/indigo/api/agnostic"
	"github.com/bluesky-social/indigo/atproto/atclient"
	"github.com/bluesky-social/indigo/atproto/identity"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/libdns/libdns"
)

const (
	dnsCollection    = "at.marque.dns"
	domainCollection = "at.marque.domain"
)

// MarqueProvider manages DNS records via ATProto PDS repo records
// (at.marque.dns and at.marque.domain lexicons). It authenticates
// to the user's PDS with an ATProto handle and app password, then
// reads and writes DNS zone entries stored as ATProto repo records.
type MarqueProvider struct {
	// ATProto handle (e.g. "user.bsky.social") or DID.
	Handle string `json:"handle,omitempty"`

	// ATProto app password for authentication.
	AppPassword string `json:"app_password,omitempty"`

	client *atclient.APIClient // authenticated client, lazy-initialized
	did    string              // resolved DID from login
	mu     sync.Mutex          // protects lazy login
}

// DNSRecord is the at.marque.dns lexicon record body stored in the PDS repo.
type DNSRecord struct {
	LexiconTypeID string        `json:"$type,omitempty"`
	Domain        string        `json:"domain"`
	Subject       StrongRef     `json:"subject"`
	Records       []RecordEntry `json:"records"`
	CreatedAt     string        `json:"createdAt"`
}

// RecordEntry is a single DNS resource record in the at.marque.dns records array.
type RecordEntry struct {
	Name       string `json:"name"`
	RecordType string `json:"recordType"`
	Value      string `json:"value"`
	TTL        int    `json:"ttl"`
	Priority   int    `json:"priority,omitempty"`
}

// StrongRef references an at.marque.domain record via com.atproto.repo.strongRef.
type StrongRef struct {
	LexiconTypeID string `json:"$type,omitempty"`
	URI           string `json:"uri"`
	CID           string `json:"cid"`
}

// recordInfo bundles a fetched DNS record with its AT URI and CID for updates.
type recordInfo struct {
	uri    string
	cid    string
	record *DNSRecord
}

func init() {
	caddy.RegisterModule(&MarqueProvider{})
}

// CaddyModule returns the Caddy module information.
func (*MarqueProvider) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dns.providers.marque",
		New: func() caddy.Module { return &MarqueProvider{} },
	}
}

// Provision validates the config and resolves placeholders.
// ATProto login is deferred to the first DNS operation.
func (p *MarqueProvider) Provision(ctx caddy.Context) error {
	repl := caddy.NewReplacer()
	p.Handle = repl.ReplaceAll(p.Handle, "")
	p.AppPassword = repl.ReplaceAll(p.AppPassword, "")

	if p.Handle == "" {
		return fmt.Errorf("handle is required")
	}
	if p.AppPassword == "" {
		return fmt.Errorf("app_password is required")
	}
	return nil
}

// UnmarshalCaddyfile parses the Caddyfile. Two syntaxes are supported:
//
//	marque <handle> <app_password>
//
//	marque {
//	    handle <handle>
//	    app_password <app_password>
//	}
func (p *MarqueProvider) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name

	if d.NextArg() {
		p.Handle = d.Val()
		if d.NextArg() {
			p.AppPassword = d.Val()
		} else {
			return d.ArgErr()
		}
	} else {
		for nesting := d.Nesting(); d.NextBlock(nesting); {
			switch d.Val() {
			case "handle":
				if d.NextArg() {
					p.Handle = d.Val()
				} else {
					return d.ArgErr()
				}
			case "app_password":
				if d.NextArg() {
					p.AppPassword = d.Val()
				} else {
					return d.ArgErr()
				}
			default:
				return d.Errf("unrecognized subdirective '%s'", d.Val())
			}
		}
	}

	if d.NextArg() {
		return d.Errf("unexpected argument '%s'", d.Val())
	}
	if p.Handle == "" {
		return d.Err("missing handle")
	}
	if p.AppPassword == "" {
		return d.Err("missing app_password")
	}
	return nil
}

// login performs lazy ATProto authentication. Thread-safe.
func (p *MarqueProvider) login(ctx context.Context) (*atclient.APIClient, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.client != nil {
		return p.client, nil
	}

	atid, err := syntax.ParseAtIdentifier(p.Handle)
	if err != nil {
		return nil, fmt.Errorf("invalid handle %q: %w", p.Handle, err)
	}

	client, err := atclient.LoginWithPassword(ctx, identity.DefaultDirectory(), atid, p.AppPassword, "", nil)
	if err != nil {
		return nil, fmt.Errorf("atproto login failed: %w", err)
	}

	p.client = client
	if client.AccountDID != nil {
		p.did = client.AccountDID.String()
	}
	return client, nil
}

// --- PDS record operations ---

// getDNSRecord fetches the at.marque.dns record for zone.
// Returns nil, nil if not found.
func (p *MarqueProvider) getDNSRecord(ctx context.Context, client *atclient.APIClient, zone string) (*recordInfo, error) {
	zone = strings.TrimSuffix(zone, ".")

	out, err := agnostic.RepoGetRecord(ctx, client, "", dnsCollection, p.did, zone)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("get dns record zone=%s: %w", zone, err)
	}

	if out.Value == nil {
		return nil, nil
	}

	var dns DNSRecord
	if err := json.Unmarshal(*out.Value, &dns); err != nil {
		return nil, fmt.Errorf("unmarshal dns record zone=%s: %w", zone, err)
	}

	return &recordInfo{
		uri:    out.Uri,
		cid:    derefString(out.Cid),
		record: &dns,
	}, nil
}

// getOrCreateDNSRecord gets the DNS record for zone, creating it if not found.
// Creation requires a corresponding at.marque.domain record to exist.
func (p *MarqueProvider) getOrCreateDNSRecord(ctx context.Context, client *atclient.APIClient, zone string) (*recordInfo, error) {
	info, err := p.getDNSRecord(ctx, client, zone)
	if err != nil {
		return nil, err
	}
	if info != nil {
		return info, nil
	}
	return p.createDNSRecord(ctx, client, zone)
}

// createDNSRecord creates a new at.marque.dns record for zone.
// Requires a corresponding at.marque.domain record to exist.
func (p *MarqueProvider) createDNSRecord(ctx context.Context, client *atclient.APIClient, zone string) (*recordInfo, error) {
	zone = strings.TrimSuffix(zone, ".")

	domainRef, err := p.getDomainRef(ctx, client, zone)
	if err != nil {
		return nil, fmt.Errorf("domain ref for zone=%s: %w", zone, err)
	}

	dns := DNSRecord{
		LexiconTypeID: dnsCollection,
		Domain:        zone,
		Subject:       *domainRef,
		Records:       []RecordEntry{},
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}

	recordMap, err := structToMap(dns)
	if err != nil {
		return nil, fmt.Errorf("marshal dns record: %w", err)
	}

	rkey := zone
	input := &agnostic.RepoCreateRecord_Input{
		Collection: dnsCollection,
		Record:     recordMap,
		Repo:       p.did,
		Rkey:       &rkey,
	}

	out, err := agnostic.RepoCreateRecord(ctx, client, input)
	if err != nil {
		return nil, fmt.Errorf("create dns record zone=%s: %w", zone, err)
	}

	return &recordInfo{
		uri:    out.Uri,
		cid:    out.Cid,
		record: &dns,
	}, nil
}

// getDomainRef returns a StrongRef for the at.marque.domain record for zone.
func (p *MarqueProvider) getDomainRef(ctx context.Context, client *atclient.APIClient, zone string) (*StrongRef, error) {
	zone = strings.TrimSuffix(zone, ".")

	out, err := agnostic.RepoGetRecord(ctx, client, "", domainCollection, p.did, zone)
	if err != nil {
		return nil, fmt.Errorf("get domain record zone=%s: %w", zone, err)
	}

	return &StrongRef{
		LexiconTypeID: "com.atproto.repo.strongRef",
		URI:           out.Uri,
		CID:           derefString(out.Cid),
	}, nil
}

// saveDNSRecord writes the DNS record back to the PDS via putRecord
// with optimistic concurrency (SwapRecord).
func (p *MarqueProvider) saveDNSRecord(ctx context.Context, client *atclient.APIClient, info *recordInfo) error {
	info.record.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	info.record.LexiconTypeID = dnsCollection

	recordMap, err := structToMap(*info.record)
	if err != nil {
		return fmt.Errorf("marshal dns record: %w", err)
	}

	aturi, err := syntax.ParseATURI(info.uri)
	if err != nil {
		return fmt.Errorf("parse aturi %q: %w", info.uri, err)
	}
	rkey := aturi.RecordKey().String()

	input := &agnostic.RepoPutRecord_Input{
		Collection: dnsCollection,
		Record:     recordMap,
		Repo:       p.did,
		Rkey:       rkey,
		SwapRecord: &info.cid,
	}

	out, err := agnostic.RepoPutRecord(ctx, client, input)
	if err != nil {
		return fmt.Errorf("put dns record zone=%s: %w", info.record.Domain, err)
	}

	info.uri = out.Uri
	info.cid = out.Cid
	return nil
}

// --- libdns interface implementations ---

// GetRecords returns all DNS records for the zone from the at.marque.dns record.
func (p *MarqueProvider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	client, err := p.login(ctx)
	if err != nil {
		return nil, err
	}

	info, err := p.getDNSRecord(ctx, client, zone)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, nil
	}

	records := make([]libdns.Record, 0, len(info.record.Records))
	for _, entry := range info.record.Records {
		rec, err := entryToRecord(entry)
		if err != nil {
			return nil, fmt.Errorf("convert entry name=%s type=%s: %w", entry.Name, entry.RecordType, err)
		}
		records = append(records, rec)
	}
	return records, nil
}

// AppendRecords adds records to the zone. Creates the DNS record if it doesn't exist.
func (p *MarqueProvider) AppendRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	client, err := p.login(ctx)
	if err != nil {
		return nil, err
	}

	info, err := p.getOrCreateDNSRecord(ctx, client, zone)
	if err != nil {
		return nil, err
	}

	var created []libdns.Record
	for _, rec := range recs {
		entry := recordToEntry(rec)
		info.record.Records = append(info.record.Records, entry)
		created = append(created, rec)
	}

	if err := p.saveDNSRecord(ctx, client, info); err != nil {
		return nil, err
	}
	return created, nil
}

// SetRecords replaces matching name:type records in the zone.
func (p *MarqueProvider) SetRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	client, err := p.login(ctx)
	if err != nil {
		return nil, err
	}

	info, err := p.getOrCreateDNSRecord(ctx, client, zone)
	if err != nil {
		return nil, err
	}

	// Build set of replacement keys
	replaceKeys := make(map[string]bool)
	for _, rec := range recs {
		rr := rec.RR()
		replaceKeys[rr.Name+":"+rr.Type] = true
	}

	// Keep entries not being replaced
	var kept []RecordEntry
	for _, entry := range info.record.Records {
		key := entry.Name + ":" + entry.RecordType
		if !replaceKeys[key] {
			kept = append(kept, entry)
		}
	}

	// Add new entries
	for _, rec := range recs {
		kept = append(kept, recordToEntry(rec))
	}

	info.record.Records = kept
	if err := p.saveDNSRecord(ctx, client, info); err != nil {
		return nil, err
	}
	return recs, nil
}

// DeleteRecords removes matching records from the zone.
// An empty Name, Type, or Data field in any deletion criteria
// matches any value (wildcard match per libdns convention).
func (p *MarqueProvider) DeleteRecords(ctx context.Context, zone string, recs []libdns.Record) ([]libdns.Record, error) {
	client, err := p.login(ctx)
	if err != nil {
		return nil, err
	}

	info, err := p.getDNSRecord(ctx, client, zone)
	if err != nil {
		return nil, err
	}
	if info == nil {
		return nil, nil
	}

	// Build deletion criteria
	type criteria struct {
		name, rtype, value string
	}
	var crits []criteria
	for _, rec := range recs {
		rr := rec.RR()
		crits = append(crits, criteria{rr.Name, rr.Type, rr.Data})
	}

	var kept []RecordEntry
	var deleted []libdns.Record
	for _, entry := range info.record.Records {
		matched := false
		for _, c := range crits {
			nameMatch := c.name == "" || c.name == entry.Name
			typeMatch := c.rtype == "" || c.rtype == entry.RecordType
			valueMatch := c.value == "" || c.value == entry.Value
			if nameMatch && typeMatch && valueMatch {
				matched = true
				break
			}
		}
		if matched {
			rec, err := entryToRecord(entry)
			if err != nil {
				return nil, fmt.Errorf("convert deleted entry: %w", err)
			}
			deleted = append(deleted, rec)
		} else {
			kept = append(kept, entry)
		}
	}

	if len(deleted) == 0 {
		return nil, nil
	}

	info.record.Records = kept
	if err := p.saveDNSRecord(ctx, client, info); err != nil {
		return nil, err
	}
	return deleted, nil
}

// --- Record conversion ---

// recordToEntry converts a libdns Record to an at.marque.dns RecordEntry.
// MX and SRV records split their priority out of the RDATA string.
func recordToEntry(r libdns.Record) RecordEntry {
	rr := r.RR()
	// Strip trailing dot for relative names (libdns convention: relative to zone)
	name := strings.TrimSuffix(rr.Name, ".")

	entry := RecordEntry{
		Name:       name,
		RecordType: rr.Type,
		TTL:        int(rr.TTL.Seconds()),
	}

	switch rr.Type {
	case "MX":
		parts := strings.SplitN(rr.Data, " ", 2)
		if len(parts) == 2 {
			entry.Priority, _ = strconv.Atoi(parts[0])
			entry.Value = parts[1]
		} else {
			entry.Value = rr.Data
		}
	case "SRV":
		fields := strings.Fields(rr.Data)
		if len(fields) >= 4 {
			entry.Priority, _ = strconv.Atoi(fields[0])
			// value stores "weight port target"
			entry.Value = strings.Join(fields[1:], " ")
		} else {
			entry.Value = rr.Data
		}
	default:
		entry.Value = rr.Data
	}

	return entry
}

// entryToRecord converts an at.marque.dns RecordEntry to a libdns Record.
// Uses libdns.RR.Parse() to produce typed records (Address, TXT, MX, etc.).
func entryToRecord(e RecordEntry) (libdns.Record, error) {
	ttl := time.Duration(e.TTL) * time.Second
	rr := libdns.RR{
		Name: e.Name,
		Type: e.RecordType,
		TTL:  ttl,
	}

	switch e.RecordType {
	case "MX":
		rr.Data = fmt.Sprintf("%d %s", e.Priority, e.Value)
	case "SRV":
		rr.Data = fmt.Sprintf("%d %s", e.Priority, e.Value)
	default:
		rr.Data = e.Value
	}

	return rr.Parse()
}

// --- Helpers ---

// structToMap converts a struct to map[string]any via JSON round-trip.
func structToMap(v any) (map[string]any, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// isNotFound checks whether err is an ATProto RecordNotFound API error.
func isNotFound(err error) bool {
	if apiErr, ok := err.(*atclient.APIError); ok {
		return apiErr.Name == "RecordNotFound"
	}
	return false
}

// derefString returns the dereferenced string or "" if nil.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*MarqueProvider)(nil)
	_ libdns.RecordAppender = (*MarqueProvider)(nil)
	_ libdns.RecordSetter   = (*MarqueProvider)(nil)
	_ libdns.RecordDeleter  = (*MarqueProvider)(nil)
	_ caddyfile.Unmarshaler = (*MarqueProvider)(nil)
	_ caddy.Provisioner     = (*MarqueProvider)(nil)
)
