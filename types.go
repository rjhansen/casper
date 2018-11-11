package main

import (
	"fmt"
	"time"
)

type CryptographicAlgorithm struct {
	id int
}

type CryptographicStruct struct {
	RSA               CryptographicAlgorithm
	RSAEncryptOnly    CryptographicAlgorithm
	RSASignOnly       CryptographicAlgorithm
	Elgamal           CryptographicAlgorithm
	DSA               CryptographicAlgorithm
	ECDH              CryptographicAlgorithm
	ECDSA             CryptographicAlgorithm
	VulnerableElgamal CryptographicAlgorithm
	EDDSA             CryptographicAlgorithm
}

type DigestAlgorithm struct {
	id int
}

type DigestStruct struct {
	MD5       DigestAlgorithm
	SHA1      DigestAlgorithm
	RIPEMD160 DigestAlgorithm
	SHA224    DigestAlgorithm
	SHA256    DigestAlgorithm
	SHA384    DigestAlgorithm
	SHA512    DigestAlgorithm
}

type SignatureClass struct {
	id int
}

type RevocationClass struct {
	id int
}

type RevocationStruct struct {
	Unspecified RevocationClass
	Superseded  RevocationClass
	Compromised RevocationClass
	Retired     RevocationClass
	UidInvalid  RevocationClass
}

type SignatureStruct struct {
	Binary                  SignatureClass
	Canonical               SignatureClass
	Standalone              SignatureClass
	Generic                 SignatureClass
	Persona                 SignatureClass
	Casual                  SignatureClass
	Positive                SignatureClass
	SubkeyBinding           SignatureClass
	PrimaryKeyBinding       SignatureClass
	OnKey                   SignatureClass
	KeyRevocation           SignatureClass
	SubkeyRevocation        SignatureClass
	CertificationRevocation SignatureClass
	Timestamp               SignatureClass
	ThirdParty              SignatureClass
}

type Validity struct {
	id string
}

type ValidityStruct struct {
	Unknown    Validity
	Invalid    Validity
	Disabled   Validity
	Revoked    Validity
	Expired    Validity
	Unassigned Validity
	Undefined  Validity
	NotValid   Validity
	Marginal   Validity
	Valid      Validity
	Implicit   Validity
	WellKnown  Validity
	Special    Validity
}

type Signature struct {
	SigningAlgorithm CryptographicAlgorithm
	Id               string
	Created          time.Time
	Expires          time.Time
	DigestAlgorithm  DigestAlgorithm
	Name             string
	Exportable       bool
	Local            bool
	Class            SignatureClass
	IsRevocation     bool
	Revocation       RevocationClass
	RevocationReason string
}

type Subkey struct {
	Algorithm   CryptographicAlgorithm
	Signatures  map[string][]*Signature
	Length      int
	Created     time.Time
	Expires     time.Time
	Validity    Validity
	Id          string
	Fingerprint string
	Curve       string
	CanEncrypt  bool
	CanSign     bool
	CanCertify  bool
	IsKeypair   bool
}

type Uid struct {
	Signatures map[string][]*Signature
	Name       string
	Created    time.Time
	Expires    time.Time
	Validity   Validity
}

type Certificate struct {
	Subkeys []*Subkey
	Uids    []*Uid
}

func (ca CryptographicAlgorithm) String() string {
	switch ca.id {
	case 1:
		return "RSA"
	case 2:
		return "RSA encrypt-only"
	case 3:
		return "RSA sign-only"
	case 16:
		return "Elgamal"
	case 17:
		return "DSA"
	case 18:
		return "ECDH"
	case 19:
		return "ECDSA"
	case 20:
		return "Vulnerable Elgamal"
	case 22:
		return "EDDSA"
	default:
		return "Unknown"
	}
}

func (da DigestAlgorithm) String() string {
	switch da.id {
	case 1:
		return "MD5"
	case 2:
		return "SHA1"
	case 3:
		return "RIPEMD160"
	case 8:
		return "SHA256"
	case 9:
		return "SHA384"
	case 10:
		return "SHA512"
	case 11:
		return "SHA224"
	default:
		return "Unknown"
	}
}

func (sc SignatureClass) String() string {
	switch sc.id {
	case 0x00:
		return "binary document"
	case 0x01:
		return "canonical text"
	case 0x02:
		return "standalone"
	case 0x10:
		return "generic"
	case 0x11:
		return "persona"
	case 0x12:
		return "casual"
	case 0x13:
		return "positive"
	case 0x18:
		return "subkey binding"
	case 0x19:
		return "primary key binding"
	case 0x1f:
		return "on-key"
	case 0x20:
		return "key revocation"
	case 0x28:
		return "subkey revocation"
	case 0x30:
		return "certification revocation"
	case 0x40:
		return "timestamp"
	case 0x50:
		return "third party"
	default:
		return "unknown"
	}
}

func (v Validity) String() string {
	switch v.id {
	case "o":
		return "unknown"
	case "i":
		return "invalid"
	case "d":
		return "disabled"
	case "r":
		return "revoked"
	case "e":
		return "expired"
	case "-":
		return "unassigned"
	case "q":
		return "undefined"
	case "n":
		return "invalid"
	case "m":
		return "marginal"
	case "f":
		return "valid"
	case "u":
		return "implicit"
	case "w":
		return "well-known private part"
	case "s":
		return "special"
	default:
		return "unknown"
	}
}

func (rc RevocationClass) String() string {
	switch rc.id {
	case 0:
		return "unspecified"
	case 1:
		return "superseded"
	case 2:
		return "compromised"
	case 3:
		return "retired"
	case 32:
		return "uid invalid"
	default:
		return "unknown"
	}
}

func (c Certificate) String() string {
	return fmt.Sprintf("%s (%s)", c.Subkeys[0].Id, c.Uids[0].Name)
}

func (s Subkey) String() (rv string) {
	future, _ := time.Parse("Jan 02 2006", "Jan 01 2100")

	if s.Curve == "" {
		rv = fmt.Sprintf("%s-%d", s.Algorithm, s.Length)
	} else {
		rv = fmt.Sprintf("%s-%d (curve %s)",
			s.Algorithm, s.Length, s.Curve)
	}

	if s.IsKeypair {
		rv += " keypair"
	}

	rv += fmt.Sprintf(" subkey %s, created %s, expires ",
		s.Id, s.Created.Format("Jan 02, 2006 3:04pm"))

	if s.Expires.After(future) {
		rv += "never"
	} else {
		rv += s.Expires.Format("Jan 02, 2006 3:04pm")
	}

	fmtstr := ", %s validity, sign?: %t certify?: %t encrypt?: %t"
	rv += fmt.Sprintf(fmtstr, s.Validity, s.CanSign, s.CanCertify,
		s.CanEncrypt)

	rv += fmt.Sprintf(", fpr %s", s.Fingerprint)

	return rv
}

func (s Signature) String() (rv string) {
	future, _ := time.Parse("Jan 02 2006", "Jan 01 2100")

	rv = fmt.Sprintf("%s (%s/%s) by %s, created %s, expires ",
		s.Id, s.SigningAlgorithm, s.DigestAlgorithm, s.Name,
		s.Created.Format("Jan 02, 2006 3:04pm"))
	if s.Expires.After(future) {
		rv += "never"
	} else {
		rv += s.Expires.Format("Jan 02, 2006 3:04pm")
	}
	if s.Exportable {
		rv += ", exportable, "
	} else {
		rv += ", local, "
	}
	rv += s.Class.String()
	if s.IsRevocation {
		rv += fmt.Sprintf(", REVOCATION (%s, %s)",
			s.Revocation, s.RevocationReason)
	}
	return rv
}

func (u Uid) String() (rv string) {
	future, _ := time.Parse("Jan 02 2006", "Jan 01 2100")
	rv = fmt.Sprintf("%s, created %s, expires ",
		u.Name, u.Created.Format("Jan 02, 2006 3:04pm"))
	if u.Expires.After(future) {
		rv += "never"
	} else {
		rv += u.Expires.Format("Jan 02, 2006 3:04pm")
	}
	rv += fmt.Sprintf(", %s validity", u.Validity)
	return rv
}
