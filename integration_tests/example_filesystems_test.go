package integration_tests

// Mount example filesystems and check that the file "status.txt" is there

import (
	"io/ioutil"
	"os"
	"testing"
)

const statusTxtContent = "It works!\n"

// checkStatusTxt - read file "filename" and verify that it contains
// "It works!\n"
func checkStatusTxt(t *testing.T, filename string) {
	contentBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	content := string(contentBytes)
	if content != statusTxtContent {
		t.Errorf("Unexpected content: %s\n", content)
	}
}

// Test example_filesystems/normal
// with password mount and -masterkey mount
func TestExampleFsNormal(t *testing.T) {
	pDir := tmpDir + "TestExampleFsNormal/"
	cDir := "example_filesystems/normal"
	err := os.Mkdir(pDir, 0777)
	if err != nil {
		t.Fatal(err)
	}
	mount(cDir, pDir, "-extpass", "echo test")
	checkStatusTxt(t, pDir+"status.txt")
	unmount(pDir)
	mount(cDir, pDir, "-masterkey", "74676e34-0b47c145-00dac61a-17a92316-"+
		"bb57044c-e205b71f-65f4fdca-7cabd4b3")
	checkStatusTxt(t, pDir+"status.txt")
	unmount(pDir)
	err = os.Remove(pDir)
	if err != nil {
		t.Error(err)
	}
}
