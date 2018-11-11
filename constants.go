package main

import "time"

var RevocationClasses = RevocationStruct{
	Unspecified: RevocationClass{id: 0},
	Superseded:  RevocationClass{id: 1},
	Compromised: RevocationClass{id: 2},
	Retired:     RevocationClass{id: 3},
	UidInvalid:  RevocationClass{id: 32},
}

var Digests = DigestStruct{
	MD5:       DigestAlgorithm{id: 1},
	RIPEMD160: DigestAlgorithm{id: 3},
	SHA1:      DigestAlgorithm{id: 2},
	SHA224:    DigestAlgorithm{id: 11},
	SHA256:    DigestAlgorithm{id: 8},
	SHA384:    DigestAlgorithm{id: 9},
	SHA512:    DigestAlgorithm{id: 10},
}

var CryptographicAlgorithms = CryptographicStruct{
	RSA:               CryptographicAlgorithm{id: 1},
	RSAEncryptOnly:    CryptographicAlgorithm{id: 2},
	RSASignOnly:       CryptographicAlgorithm{id: 3},
	Elgamal:           CryptographicAlgorithm{id: 16},
	DSA:               CryptographicAlgorithm{id: 17},
	ECDH:              CryptographicAlgorithm{id: 18},
	ECDSA:             CryptographicAlgorithm{id: 19},
	VulnerableElgamal: CryptographicAlgorithm{id: 20},
	EDDSA:             CryptographicAlgorithm{id: 22},
}

var Signatures = SignatureStruct{
	Binary:                  SignatureClass{id: 0x00},
	Canonical:               SignatureClass{id: 0x01},
	Standalone:              SignatureClass{id: 0x02},
	Generic:                 SignatureClass{id: 0x10},
	Persona:                 SignatureClass{id: 0x11},
	Casual:                  SignatureClass{id: 0x12},
	Positive:                SignatureClass{id: 0x13},
	SubkeyBinding:           SignatureClass{id: 0x18},
	PrimaryKeyBinding:       SignatureClass{id: 0x19},
	OnKey:                   SignatureClass{id: 0x1F},
	KeyRevocation:           SignatureClass{id: 0x20},
	SubkeyRevocation:        SignatureClass{id: 0x28},
	CertificationRevocation: SignatureClass{id: 0x30},
	Timestamp:               SignatureClass{id: 0x40},
	ThirdParty:              SignatureClass{id: 0x50},
}

var Validities = ValidityStruct{
	Unknown:    Validity{id: "o"},
	Invalid:    Validity{id: "i"},
	Disabled:   Validity{id: "d"},
	Revoked:    Validity{id: "r"},
	Expired:    Validity{id: "e"},
	Unassigned: Validity{id: "-"},
	Undefined:  Validity{id: "q"},
	NotValid:   Validity{id: "n"},
	Marginal:   Validity{id: "m"},
	Valid:      Validity{id: "f"},
	Implicit:   Validity{id: "u"},
	WellKnown:  Validity{id: "w"},
	Special:    Validity{id: "s"},
}

var badtime time.Time
var future time.Time

func init() {
	badtime, _ = time.Parse("2006-Jan-02", "1900-Jan-01")
	future, _ = time.Parse("2006-Jan-02", "3000-Jan-01")
}
