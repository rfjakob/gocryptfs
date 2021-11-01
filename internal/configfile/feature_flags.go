package configfile

type flagIota int

const (
	// FlagPlaintextNames indicates that filenames are unencrypted.
	FlagPlaintextNames flagIota = iota
	// FlagDirIV indicates that a per-directory IV file is used.
	FlagDirIV
	// FlagEMENames indicates EME (ECB-Mix-ECB) filename encryption.
	// This flag is mandatory since gocryptfs v1.0.
	FlagEMENames
	// FlagGCMIV128 indicates 128-bit GCM IVs.
	// This flag is mandatory since gocryptfs v1.0,
	// except when XChaCha20Poly1305 is used.
	FlagGCMIV128
	// FlagLongNames allows file names longer than 175 bytes.
	FlagLongNames
	// FlagLongNameMax sets a custom name length limit, names longer than that
	// will be hashed.
	FlagLongNameMax
	// FlagAESSIV selects an AES-SIV based crypto backend.
	FlagAESSIV
	// FlagRaw64 enables raw (unpadded) base64 encoding for file names
	FlagRaw64
	// FlagHKDF enables HKDF-derived keys for use with GCM, EME and SIV
	// instead of directly using the master key (GCM and EME) or the SHA-512
	// hashed master key (SIV).
	// Note that this flag does not change the password hashing algorithm
	// which always is scrypt.
	FlagHKDF
	// FlagFIDO2 means that "-fido2" was used when creating the filesystem.
	// The masterkey is protected using a FIDO2 token instead of a password.
	FlagFIDO2
	// FlagXChaCha20Poly1305 means we use XChaCha20-Poly1305 file content encryption
	FlagXChaCha20Poly1305
)

// knownFlags stores the known feature flags and their string representation
var knownFlags = map[flagIota]string{
	FlagPlaintextNames:    "PlaintextNames",
	FlagDirIV:             "DirIV",
	FlagEMENames:          "EMENames",
	FlagGCMIV128:          "GCMIV128",
	FlagLongNames:         "LongNames",
	FlagLongNameMax:       "LongNameMax",
	FlagAESSIV:            "AESSIV",
	FlagRaw64:             "Raw64",
	FlagHKDF:              "HKDF",
	FlagFIDO2:             "FIDO2",
	FlagXChaCha20Poly1305: "XChaCha20Poly1305",
}

// isFeatureFlagKnown verifies that we understand a feature flag.
func isFeatureFlagKnown(flag string) bool {
	for _, knownFlag := range knownFlags {
		if knownFlag == flag {
			return true
		}
	}
	return false
}

// IsFeatureFlagSet returns true if the feature flag "flagWant" is enabled.
func (cf *ConfFile) IsFeatureFlagSet(flagWant flagIota) bool {
	flagString := knownFlags[flagWant]
	for _, flag := range cf.FeatureFlags {
		if flag == flagString {
			return true
		}
	}
	return false
}
