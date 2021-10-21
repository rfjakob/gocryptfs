package configfile

import (
	"fmt"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

var testPw = []byte("test")

func TestLoadV1(t *testing.T) {
	_, _, err := LoadAndDecrypt("config_test/v1.conf", testPw)
	if err == nil {
		t.Errorf("Outdated v1 config file must fail to load but it didn't")
	} else if testing.Verbose() {
		fmt.Println(err)
	}
}

// Load a known-good config file and verify that it takes at least 100ms
// (brute-force protection)
func TestLoadV2(t *testing.T) {
	t1 := time.Now()

	_, _, err := LoadAndDecrypt("config_test/v2.conf", testPw)
	if err != nil {
		t.Errorf("Could not load v2 config file: %v", err)
	}

	elapsed := time.Since(t1)
	if elapsed < 100*time.Millisecond {
		t.Errorf("scrypt calculation runs too fast: %d ms", elapsed/time.Millisecond)
	}
}

func TestLoadV2PwdError(t *testing.T) {
	if !testing.Verbose() {
		tlog.Warn.Enabled = false
	}
	_, _, err := LoadAndDecrypt("config_test/v2.conf", []byte("wrongpassword"))
	if err == nil {
		t.Errorf("Loading with wrong password must fail but it didn't")
	}
}

func TestLoadV2Feature(t *testing.T) {
	_, _, err := LoadAndDecrypt("config_test/PlaintextNames.conf", testPw)
	if err != nil {
		t.Errorf("Could not load v2 PlaintextNames config file: %v", err)
	}
}

func TestLoadV2StrangeFeature(t *testing.T) {
	_, _, err := LoadAndDecrypt("config_test/StrangeFeature.conf", testPw)
	if err == nil {
		t.Errorf("Loading unknown feature must fail but it didn't")
	} else if testing.Verbose() {
		fmt.Println(err)
	}
}

func TestCreateConfDefault(t *testing.T) {
	err := Create(&CreateArgs{
		Filename: "config_test/tmp.conf",
		Password: testPw,
		LogN:     10,
		Creator:  "test"})
	if err != nil {
		t.Fatal(err)
	}
	_, c, err := LoadAndDecrypt("config_test/tmp.conf", testPw)
	if err != nil {
		t.Fatal(err)
	}
	// Check that all expected feature flags are set
	want := []flagIota{
		FlagGCMIV128, FlagDirIV, FlagEMENames, FlagLongNames,
		FlagRaw64, FlagHKDF,
	}
	for _, f := range want {
		if !c.IsFeatureFlagSet(f) {
			t.Errorf("Feature flag %q should be set but is not", knownFlags[f])
		}
	}
}

func TestCreateConfPlaintextnames(t *testing.T) {
	err := Create(&CreateArgs{
		Filename:       "config_test/tmp.conf",
		Password:       testPw,
		PlaintextNames: true,
		LogN:           10,
		Creator:        "test"})
	if err != nil {
		t.Fatal(err)
	}
	_, c, err := LoadAndDecrypt("config_test/tmp.conf", testPw)
	if err != nil {
		t.Fatal(err)
	}
	// Check that all expected feature flags are set
	want := []flagIota{
		FlagGCMIV128, FlagHKDF,
	}
	for _, f := range want {
		if !c.IsFeatureFlagSet(f) {
			t.Errorf("Feature flag %q should be set but is not", knownFlags[f])
		}
	}
}

// Reverse mode uses AESSIV
func TestCreateConfFileAESSIV(t *testing.T) {
	err := Create(&CreateArgs{
		Filename: "config_test/tmp.conf",
		Password: testPw,
		LogN:     10,
		Creator:  "test",
		AESSIV:   true})
	if err != nil {
		t.Fatal(err)
	}
	_, c, err := LoadAndDecrypt("config_test/tmp.conf", testPw)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsFeatureFlagSet(FlagAESSIV) {
		t.Error("AESSIV flag should be set but is not")
	}
}

func TestCreateConfLongNameMax(t *testing.T) {
	args := &CreateArgs{
		Filename:    "config_test/tmp.conf",
		Password:    testPw,
		LogN:        10,
		Creator:     "test",
		LongNameMax: 100,
	}
	err := Create(args)
	if err != nil {
		t.Fatal(err)
	}
	_, c, err := LoadAndDecrypt("config_test/tmp.conf", testPw)
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsFeatureFlagSet(FlagLongNameMax) {
		t.Error("FlagLongNameMax should be set but is not")
	}
	if c.LongNameMax != args.LongNameMax {
		t.Errorf("wrong LongNameMax value: want=%d have=%d", args.LongNameMax, c.LongNameMax)
	}
}

func TestIsFeatureFlagKnown(t *testing.T) {
	// Test a few hardcoded values
	testKnownFlags := []string{"DirIV", "PlaintextNames", "EMENames", "GCMIV128", "LongNames", "AESSIV"}
	// And also everything in knownFlags (yes, it is likely that we end up with
	// some duplicates. Does not matter.)
	for _, f := range knownFlags {
		testKnownFlags = append(testKnownFlags, f)
	}

	for _, f := range testKnownFlags {
		if !isFeatureFlagKnown(f) {
			t.Errorf("flag %q should be known", f)
		}
	}

	f := "StrangeFeatureFlag"
	if isFeatureFlagKnown(f) {
		t.Errorf("flag %q should be NOT known", f)
	}
}
