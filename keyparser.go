package main

import (
	"errors"
	"io/ioutil"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type byDate []Signature

func (s byDate) Len() int {
	return len(s)
}
func (s byDate) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s byDate) Less(i, j int) bool {
	return s[i].Created.After(s[j].Created)
}

// Given a string representing either a Unix timestamp or GnuPG's
// botched ISO8601-alike, convert to a proper Golang timestamp.
//
// We recognize GnuPG's botched ISO8601-alike by the presence of
// the letter T.
//
// In case of error, drop in the year 1900 as a placeholder.
func parseTime(seq string) (rv time.Time) {
	if seq == "" {
		rv, _ = time.Parse("2006-Jan-02", "3000-Jan-01")
	} else if strings.Contains(seq, "T") {
		var ok error
		rv, ok = time.Parse("20060102T150405", seq)
		if ok != nil {
			rv = badtime
		}
	} else {
		secs, ok := strconv.ParseInt(seq, 10, 64)
		if ok != nil {
			rv = badtime
		} else {
			rv = time.Unix(secs, 0)
		}
	}
	return rv
}

// This monstrosity parses GnuPG's baroque machine-readable output
// and constructs a slice of public certificates in no particular order.
// It's implemented as essentially a really gross state machine.
func makeKeys(keydump string) (rv []Certificate) {
	rv = make([]Certificate, 0)

	// Regular expressions we'll be using to recognize different stanzas
	// of output.
	pubrx, _ := regexp.Compile("^(pub|sec):")
	subrx, _ := regexp.Compile("^(sub|ssb):")
	uidrx, _ := regexp.Compile("^uid:")
	sigrx, _ := regexp.Compile("^(sig|rev):")
	fprrx, _ := regexp.Compile("^fpr:")
	sigclsrx, _ := regexp.Compile("^([A-Fa-f0-9]+)([xl])(,\\d\\d)?$")

	cert := Certificate{}
	lastSeen := 0 // 0 for subkeys, 1 for user IDs

	for _, row := range strings.Split(keydump, "\n") {
		cols := strings.Split(row, ":")

		// Begin a new stanza
		if pubrx.MatchString(row) {
			// If we have a properly populated cert, append it to our
			// output after preparing it appropriately.
			if len(cert.Subkeys) > 0 && len(cert.Uids) > 0 {
				// Signatures are annoying in that there can be many
				// from a single cert, and only the most recently
				// created one is used.  By sorting in reverse order
				// of creation date, the relevant sig for a given
				// signer is always in head position.
				for index := range cert.Subkeys {
					for k := range cert.Subkeys[index].Signatures {
						sort.Sort(byDate(cert.Subkeys[index].Signatures[k]))
					}
				}
				for index := range cert.Uids {
					for k := range cert.Uids[index].Signatures {
						sort.Sort(byDate(cert.Uids[index].Signatures[k]))
					}
				}
				rv = append(rv, cert)
			}

			// And get ready for a new one to be read in.
			cert = Certificate{
				Subkeys: make([]Subkey, 0),
				Uids:    make([]Uid, 0),
			}
			// do NOT continue, as we need to fall through to the
			// next block
			//
			// continue
		}

		// Every pub row *is* a subkey row.  The pub line turns into
		// the subkey in head position.
		if pubrx.MatchString(row) || subrx.MatchString(row) {
			// subsequent sigs will attach to the most recent subkey
			lastSeen = 0

			algo, _ := strconv.Atoi(cols[3])
			length, _ := strconv.Atoi(cols[2])
			created := parseTime(cols[5])
			expires := parseTime(cols[6])

			// ECC algos also use a "curve" field to describe the
			// field on which they operate.
			curve := ""
			if algo == 18 || algo == 19 || algo == 22 {
				curve = cols[16]
			}

			cert.Subkeys = append(cert.Subkeys, Subkey{
				Algorithm:   CryptographicAlgorithm{id: algo},
				Signatures:  make(map[string][]Signature),
				Length:      length,
				Created:     created,
				Expires:     expires,
				Validity:    Validity{id: cols[1]},
				Id:          cols[4],
				Fingerprint: "",
				Curve:       curve,
				CanEncrypt:  strings.Contains(cols[11], "e"),
				CanSign:     strings.Contains(cols[11], "s"),
				CanCertify:  strings.Contains(cols[11], "c"),
				IsKeypair:   false,
			})
			continue
		}

		// User IDs are comparatively simple.
		if uidrx.MatchString(row) {
			lastSeen = 1
			created := parseTime(cols[5])
			expires := parseTime(cols[6])
			cert.Uids = append(cert.Uids, Uid{
				Signatures: make(map[string][]Signature),
				Name:       strings.Replace(cols[9], "\\x3a", ":", -1),
				Created:    created,
				Expires:    expires,
				Validity:   Validity{id: cols[1]},
			})
			continue
		}

		// An fpr row always occurs after a pub/sub row.  Attach this
		// to the most recently added subkey.
		if fprrx.MatchString(row) {
			fpr := cols[9]
			cert.Subkeys[len(cert.Subkeys)-1].Fingerprint = fpr
			continue
		}

		// Signatures are annoying.
		if sigrx.MatchString(row) {
			algo, _ := strconv.Atoi(cols[3])
			dig, _ := strconv.Atoi(cols[15])
			groups := sigclsrx.FindStringSubmatch(cols[10])
			class64, _ := strconv.ParseInt(groups[1], 16, 32)
			class := SignatureClass{id: int(class64)}
			created := parseTime(cols[5])
			expires := parseTime(cols[6])
			sig := Signature{
				SigningAlgorithm: CryptographicAlgorithm{id: algo},
				Id:               cols[4],
				Created:          created,
				Expires:          expires,
				DigestAlgorithm:  DigestAlgorithm{id: dig},
				Name:             strings.Replace(cols[9], "\\x3a", ":", -1),
				Exportable:       groups[2] == "x",
				Local:            groups[2] == "l",
				Class:            class,
				IsRevocation:     cols[0] == "rev",
				Revocation:       RevocationClasses.Unspecified,
				RevocationReason: "",
			}

			// Revocation signatures have extra data in the row
			if cols[0] == "rev" {
				rev, _ := strconv.ParseInt(groups[3], 16, 32)
				sig.Revocation = RevocationClass{id: int(rev)}
				if len(cols) >= 21 {
					sig.RevocationReason = cols[20]
				} else {
					sig.RevocationReason = "unspecified"
				}
			}

			// Use our state variable to figure out whether this gets
			// added to our last subkey or our last userID.
			if lastSeen == 0 {
				cert.Subkeys[len(cert.Subkeys)-1].Signatures[cols[4]] = append(cert.Subkeys[len(cert.Subkeys)-1].Signatures[cols[4]], sig)
			} else {
				cert.Uids[len(cert.Uids)-1].Signatures[cols[4]] = append(cert.Uids[len(cert.Uids)-1].Signatures[cols[4]], sig)
			}
		}
	}

	// At the end of it all we will probably have a complete cert
	// yet to added.
	if len(cert.Subkeys) > 0 && len(cert.Uids) > 0 {
		rv = append(rv, cert)
	}

	return rv
}

// Synchronously populate a complete keyring and return a dict
// that maps key IDs to certificates.
func getKeyring(filter string) (map[string]Certificate, error) {
	rv := make(map[string]Certificate)
	var gpg *exec.Cmd

	gpgpath, ok := FindExecutable()
	if ok != nil {
		return nil, errors.New("gpg not found")
	}

	if filter == "" {
		gpg = exec.Command(gpgpath, "--fixed-list-mode",
			"--no-tty", "--with-colons", "--with-colons",
			"--fingerprint", "--keyid-format", "long", "--list-sig")
	} else {
		gpg = exec.Command(gpgpath, "--fixed-list-mode",
			"--no-tty", "--with-colons", "--with-colons",
			"--fingerprint", "--keyid-format", "long", "--list-sig",
			filter)
	}

	stdout, ok := gpg.StdoutPipe()
	if ok != nil {
		return nil, errors.New("gpg internal error")
	}

	if gpg.Start() != nil {
		return nil, errors.New("gpg internal error")
	}
	outputBytes, ok := ioutil.ReadAll(stdout)
	gpg.Wait()
	if ok != nil {
		return nil, errors.New("gpg read error")
	}
	for _, cert := range makeKeys(string(outputBytes)) {
		rv[cert.Subkeys[0].Id] = cert
	}

	// Repeat the process looking for secret keys, so we can
	// populate the .IsKeypair field of each subkey properly.
	if filter == "" {
		gpg = exec.Command(gpgpath, "--fixed-list-mode",
			"--no-tty", "--with-colons", "--with-colons",
			"--fingerprint", "--list-secret")
	} else {
		gpg = exec.Command(gpgpath, "--fixed-list-mode",
			"--no-tty", "--with-colons", "--with-colons",
			"--fingerprint", "--list-secret", filter)
	}
	stdout, ok = gpg.StdoutPipe()
	if ok != nil || gpg.Start() != nil {
		return nil, errors.New("gpg internal error")
	}
	outputBytes, ok = ioutil.ReadAll(stdout)
	if ok != nil {
		return nil, errors.New("gpg read error")
	}
	gpg.Wait()

	keyId := ""
	for _, line := range strings.Split(string(outputBytes), "\n") {
		cols := strings.Split(line, ":")
		if cols[0] == "sec" {
			keyId = cols[4]
			rv[keyId].Subkeys[0].IsKeypair = true
		}
		if cols[0] == "ssb" {
			skid := cols[4]
			for index, sk := range rv[keyId].Subkeys {
				if sk.Id == skid {
					rv[keyId].Subkeys[index].IsKeypair = true
				}
			}
		}
	}

	return rv, nil
}
