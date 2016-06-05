package configfile

type flagIota int

const (
	FlagPlaintextNames flagIota = iota
	FlagDirIV
	FlagEMENames
	FlagGCMIV128
	FlagLongNames
)

// knownFlags stores the known feature flags and their string representation
var knownFlags map[flagIota]string = map[flagIota]string{
	FlagPlaintextNames: "PlaintextNames",
	FlagDirIV:          "DirIV",
	FlagEMENames:       "EMENames",
	FlagGCMIV128:       "GCMIV128",
	FlagLongNames:      "LongNames",
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
