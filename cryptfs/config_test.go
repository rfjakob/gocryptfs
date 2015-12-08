package cryptfs

import (
	"fmt"
	"testing"
	"time"
)

func TestLoadV1(t *testing.T) {
	_, _, err := LoadConfFile("config_test/v1.conf", "test")
	if err == nil {
		t.Errorf("Outdated v1 config file must fail to load but it didn't")
	} else if testing.Verbose() {
		fmt.Print(err)
	}
}

// Load a known-good config file and verify that it takes at least 100ms
// (brute-force protection)
func TestLoadV2(t *testing.T) {
	t1 := time.Now()

	_, _, err := LoadConfFile("config_test/v2.conf", "foo")
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
		Warn.Disable()
	}
	_, _, err := LoadConfFile("config_test/v2.conf", "wrongpassword")
	Warn.Enable()
	if err == nil {
		t.Errorf("Loading with wrong password must fail but it didn't")
	}
}

func TestLoadV2Feature(t *testing.T) {
	_, _, err := LoadConfFile("config_test/PlaintextNames.conf", "test")
	if err != nil {
		t.Errorf("Could not load v2 PlaintextNames config file: %v", err)
	}
}

func TestLoadV2StrangeFeature(t *testing.T) {
	_, _, err := LoadConfFile("config_test/StrangeFeature.conf", "test")
	if err == nil {
		t.Errorf("Loading unknown feature must fail but it didn't")
	} else if testing.Verbose() {
		fmt.Print(err)
	}
}

func TestCreateConfFile(t *testing.T) {
	err := CreateConfFile("config_test/tmp.conf", "test", false, 10, true)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = LoadConfFile("config_test/tmp.conf", "test")
	if err != nil {
		t.Fatal(err)
	}

}

func TestIsFeatureFlagKnown(t *testing.T) {
	var cf ConfFile
	if !cf.isFeatureFlagKnown(FlagDirIV) {
		t.Errorf("This flag should be known")
	}
	if !cf.isFeatureFlagKnown(FlagPlaintextNames) {
		t.Errorf("This flag should be known")
	}
	if cf.isFeatureFlagKnown("StrangeFeatureFlag") {
		t.Errorf("This flag should be NOT known")
	}
}
