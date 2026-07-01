package netconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/kylelemons/godebug/diff"
)

// Check interface list against expected results in the results directory.
func testVerifyInterfaces(interfaces []*Interface, resultsDir string, check int) error {
	// Get what we expect.
	expectedFile := filepath.Join(resultsDir, "interfaces", fmt.Sprintf("%d.expected", check))
	expected, err := os.ReadFile(expectedFile)
	if err != nil {
		return err
	}

	// Build a test of the current state.
	var builder strings.Builder
	for _, iface := range interfaces {
		fmt.Fprintln(&builder, iface)
	}

	// Verify the current state matches what we expect.
	diffErr := diff.Diff(builder.String(), string(expected))
	if diffErr != "" {
		fmt.Printf("Interface check %d failed with the following difference:\n%s\n\n%s\n\n", check, expectedFile, diffErr)
		return fmt.Errorf("Interface check %d has difference.", check)
	}
	return nil
}

// Function to check an directory and its sub directory for differences.
func testVerifyResultsDir(checkDir, tmpDir string, check int) error {
	// Read the provided check directory.
	files, err := os.ReadDir(checkDir)
	if err != nil {
		return err
	}

	// Check each file in the directory.
	for _, file := range files {
		// If is an sub directory, test it as well.
		if file.IsDir() {
			subDir := filepath.Join(checkDir, file.Name())
			subTmpDir := filepath.Join(tmpDir, file.Name())
			return testVerifyResultsDir(subDir, subTmpDir, check)
		} else {
			// Read the temporary file.
			tmpPath := filepath.Join(tmpDir, file.Name())
			tmpFile, err := os.ReadFile(tmpPath)
			if err != nil {
				return err
			}

			// Read the expected results.
			checkPath := filepath.Join(checkDir, file.Name())
			checkFile, err := os.ReadFile(checkPath)
			if err != nil {
				return err
			}

			// If difference, error.
			diffErr := diff.Diff(string(tmpFile), string(checkFile))
			if diffErr != "" {
				fmt.Printf("Result check %d failed with the following difference:\n%s\n\n%s\n\n", check, checkPath, diffErr)
				return fmt.Errorf("Result check %d has difference.", check)
			}
		}
	}
	return nil
}

// Cech the results directory fro differences from the temporary directory.
func testVerifyResults(resultsDir, tmpDir string, check int) error {
	// Try to read the directory files.
	checkDir := filepath.Join(resultsDir, strconv.Itoa(check))
	return testVerifyResultsDir(checkDir, tmpDir, check)
}
