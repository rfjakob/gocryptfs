package configfile

type flagIota int

const (
	FlagPlaintextNames flagIota = iota
	FlagDirIV
	FlagEMENames
	FlagGCMIV128
	FlagLongNames
	FlagAESSIV
)

// knownFlags stores the known feature flags and their string representation
var knownFlags map[flagIota]string = map[flagIota]string{
	FlagPlaintextNames: "PlaintextNames",
	FlagDirIV:          "DirIV",
	FlagEMENames:       "EMENames",
	FlagGCMIV128:       "GCMIV128",
	FlagLongNames:      "LongNames",
	FlagAESSIV:         "AESSIV",
}

// Filesystems that do not have these feature flags set are deprecated.
var requiredFlagsNormal []flagIota = []flagIota{
	FlagDirIV,
	FlagEMENames,
	FlagGCMIV128,
}

// Filesystems without filename encryption obviously don't have or need the
// filename related feature flags.
var requiredFlagsPlaintextNames []flagIota = []flagIota{
	FlagGCMIV128,
}

// isFeatureFlagKnown verifies that we understand a feature flag
func (cf *ConfFile) isFeatureFlagKnown(flag string) bool {
	for _, knownFlag := range knownFlags {
		if knownFlag == flag {
			return true
		}
	}
	return false
}

// isFeatureFlagSet - is the feature flag "flagWant" enabled?
func (cf *ConfFile) IsFeatureFlagSet(flagWant flagIota) bool {
	flagString := knownFlags[flagWant]
	for _, flag := range cf.FeatureFlags {
		if flag == flagString {
			return true
		}
	}
	return false
}
