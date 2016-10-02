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
	// This flag is mandatory since gocryptfs v1.0.
	FlagGCMIV128
	// FlagLongNames allows file names longer than 176 bytes.
	FlagLongNames
	// FlagAESSIV selects an AES-SIV based crypto backend.
	FlagAESSIV
)

// knownFlags stores the known feature flags and their string representation
var knownFlags = map[flagIota]string{
	FlagPlaintextNames: "PlaintextNames",
	FlagDirIV:          "DirIV",
	FlagEMENames:       "EMENames",
	FlagGCMIV128:       "GCMIV128",
	FlagLongNames:      "LongNames",
	FlagAESSIV:         "AESSIV",
}

// Filesystems that do not have these feature flags set are deprecated.
var requiredFlagsNormal = []flagIota{
	FlagDirIV,
	FlagEMENames,
	FlagGCMIV128,
}

// Filesystems without filename encryption obviously don't have or need the
// filename related feature flags.
var requiredFlagsPlaintextNames = []flagIota{
	FlagGCMIV128,
}

// isFeatureFlagKnown verifies that we understand a feature flag.
func (cf *ConfFile) isFeatureFlagKnown(flag string) bool {
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
