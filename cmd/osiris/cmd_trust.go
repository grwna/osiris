package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/grwna/osiris/internal/apperr"
	"github.com/grwna/osiris/internal/manifest"
	"github.com/grwna/osiris/internal/trust"
)

const trustUsage = `usage: osiris trust <add|list|remove> [options]

  add     --store <trust.json> --key <public.pem> --package <name> [--package <name> ...]
          [--expect-keyid <hex>]
          Trust a public key for the given packages. Creates the store if needed;
          adding a key that is already present merges the packages (idempotent).
  list    --store <trust.json> [--json]
  remove  --store <trust.json> --keyid <hex> [--package <name> ...]
          Remove the key (or only the given packages of that key).

The trust store is never modified by verify; check the printed fingerprint
(keyid) out-of-band before trusting a key.
`

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func errExit(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "error: %v\n", err)
	if apperr.IsFormat(err) {
		return exitRejected
	}
	return exitInput
}

func cmdTrust(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, trustUsage)
		return exitInput
	}
	switch args[0] {
	case "-help", "--help", "-h":
		fmt.Fprint(stdout, trustUsage)
		return exitOK
	case "add":
		return cmdTrustAdd(args[1:], stdout, stderr)
	case "list":
		return cmdTrustList(args[1:], stdout, stderr)
	case "remove":
		return cmdTrustRemove(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "error: unknown trust command %q\n\n%s", args[0], trustUsage)
		return exitInput
	}
}

func cmdTrustAdd(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("trust add", stderr)
	keyPath := fs.String("key", "", "public key PEM (SPKI, label PUBLIC KEY) (required)")
	store := fs.String("store", "", "trust store path (required)")
	expect := fs.String("expect-keyid", "", "refuse unless the key fingerprint equals this keyid")
	var pkgs multiFlag
	fs.Var(&pkgs, "package", "package the key may sign (required, repeatable)")
	if code, done := parseFlags(fs, args); done {
		return code
	}
	if *keyPath == "" || *store == "" || len(pkgs) == 0 {
		return errExit(stderr, apperr.Input("trust add requires --key, --store and at least one --package"))
	}
	pubPEM, err := readSmall(*keyPath, 64*1024)
	if err != nil {
		return errExit(stderr, apperr.Input("read public key: %v", err))
	}
	s, existed, err := trust.LoadOrEmpty(*store)
	if err != nil {
		return errExit(stderr, err)
	}
	res, err := s.Add(pubPEM, pkgs)
	if err != nil {
		return errExit(stderr, err)
	}
	if *expect != "" && strings.ToLower(*expect) != res.Entry.KeyID {
		return errExit(stderr, apperr.Input("key fingerprint %s does not match --expect-keyid %s; trust store not changed", res.Entry.KeyID, *expect))
	}
	state := "unchanged (already trusted)"
	if res.Changed() || !existed {
		if err := trust.Save(*store, s); err != nil {
			return errExit(stderr, err)
		}
		switch {
		case res.Created:
			state = "added"
		case res.Changed():
			state = "updated (packages added: " + strings.Join(res.AddedPackages, ", ") + ")"
		}
	}
	e := res.Entry
	fmt.Fprintf(stdout, "keyid:     %s\nalgorithm: %s\npackages:  %s\nstatus:    %s\n",
		e.KeyID, e.Algorithm, strings.Join(e.Packages, ", "), state)
	fmt.Fprintf(stderr, "trust store: %s\nverify this fingerprint with the key owner out-of-band.\n", *store)
	return exitOK
}

func cmdTrustList(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("trust list", stderr)
	store := fs.String("store", "", "trust store path (required)")
	asJSON := fs.Bool("json", false, "print entries as JSON")
	if code, done := parseFlags(fs, args); done {
		return code
	}
	if *store == "" {
		return errExit(stderr, apperr.Input("trust list requires --store"))
	}
	s, err := trust.Load(*store)
	if err != nil {
		return errExit(stderr, err)
	}
	if *asJSON {
		type item struct {
			KeyID     string   `json:"keyid"`
			Algorithm string   `json:"algorithm"`
			Packages  []string `json:"packages"`
		}
		items := []item{}
		for _, e := range s.Keys {
			items = append(items, item{e.KeyID, string(e.Algorithm), e.Packages})
		}
		out, _ := json.Marshal(map[string]any{"keys": items})
		fmt.Fprintf(stdout, "%s\n", out)
		return exitOK
	}
	if len(s.Keys) == 0 {
		fmt.Fprintln(stderr, "trust store is empty")
		return exitOK
	}
	for _, e := range s.Keys {
		fmt.Fprintf(stdout, "%s  %-17s  %s\n", e.KeyID, e.Algorithm, strings.Join(e.Packages, ","))
	}
	return exitOK
}

func cmdTrustRemove(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("trust remove", stderr)
	keyid := fs.String("keyid", "", "keyid (fingerprint) to remove (required)")
	store := fs.String("store", "", "trust store path (required)")
	var pkgs multiFlag
	fs.Var(&pkgs, "package", "only revoke this package (repeatable)")
	if code, done := parseFlags(fs, args); done {
		return code
	}
	if *keyid == "" || *store == "" {
		return errExit(stderr, apperr.Input("trust remove requires --keyid and --store"))
	}
	id := strings.ToLower(*keyid)
	if !manifest.HexPattern.MatchString(id) {
		return errExit(stderr, apperr.Input("--keyid must be 64 hex characters"))
	}
	s, err := trust.Load(*store)
	if err != nil {
		return errExit(stderr, err)
	}
	removed, err := s.Remove(id, pkgs)
	if err != nil {
		return errExit(stderr, err)
	}
	if err := trust.Save(*store, s); err != nil {
		return errExit(stderr, err)
	}
	if removed {
		fmt.Fprintf(stdout, "removed key %s\n", id)
	} else {
		fmt.Fprintf(stdout, "revoked packages %s for key %s\n", strings.Join(pkgs, ", "), id)
	}
	return exitOK
}

func readSmall(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%s is too large to be a key file", path)
	}
	return data, nil
}
