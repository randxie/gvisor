// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mitigate

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	meltdown        = "cpu_meltdown"
	l1tf            = "l1tf"
	mds             = "mds"
	swapgs          = "swapgs"
	taa             = "taa"
	specterv1       = "spectre_v1"
	specterv2       = "spectre_v2"
	specStoreBypass = "spec_store_bypass"
)

var processorRegex = regexp.MustCompile(`processor\s*:\s*(\d+)\n`)

// getCPUSet returns cpu structs from reading /proc/cpuinfo.
func getCPUSet(data string) ([]*cpu, error) {
	indices := processorRegex.FindAllStringIndex(data, -1)
	if len(indices) > 0 {
		// add the ending index for last entry.
		indices = append(indices, []int{len(data), -1})
	}

	var cpus = make([]*cpu, 0, len(indices)-1)
	// the last entry should not be a valid entry.
	for i := 1; i < len(indices); i++ {
		start := indices[i-1][0]
		end := indices[i][0]
		c, err := getCPU(data[start:end])
		if err != nil {
			return nil, err
		}
		cpus = append(cpus, c)
	}
	return cpus, nil
}

// type cpu represents pertinent info about a cpu.
type cpu struct {
	processor int64               // the processor number of this CPU.
	vendorID  string              // the vendorID of CPU (e.g. AuthenticAMD).
	cpuFamily int64               // CPU family number (e.g. 6 for CascadeLake/Skylake).
	model     int64               // CPU model number (e.g. 85 for CascadeLake/Skylake).
	bugs      map[string]struct{} // map of vulnerabilities parsed from the 'bugs' field.
}

// getCPU parses a CPU from a single cpu entry from /proc/cpuinfo.
func getCPU(data string) (*cpu, error) {
	processor, err := parseProcessor(data)
	if err != nil {
		return nil, err
	}

	vendorID, err := parseVendorID(data)
	if err != nil {
		return nil, err
	}

	cpuFamily, err := parseCPUFamily(data)
	if err != nil {
		return nil, err
	}

	model, err := parseModel(data)
	if err != nil {
		return nil, err
	}

	bugs, err := parseBugs(data)
	if err != nil {
		return nil, err
	}

	return &cpu{
		processor: processor,
		vendorID:  vendorID,
		cpuFamily: cpuFamily,
		model:     model,
		bugs:      bugs,
	}, nil
}

// isVulnerable checks if a CPU is vulnerable to a set of bugs of interest.
// isVulnerable takes a function which should return true if this CPU should
// be excluded from vulnerability checks.
func (c *cpu) isVulnerable(excluded func(*cpu) bool) bool {
	// If a excluded is true, then the CPU is not vulnerable.
	if excluded != nil && excluded(c) {
		return false
	}

	return c.hasBug()
}

// List of pertinent side channel vulnerablilites.
// For mds, see: https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/mds.html.
var vulnerabilities = map[string]struct{}{
	meltdown: struct{}{},
	l1tf:     struct{}{},
	mds:      struct{}{},
	swapgs:   struct{}{},
	taa:      struct{}{},
}

// hasBug checks if a given cpu has a pertinent vulnerablity.
func (c *cpu) hasBug() bool {
	for bug := range vulnerabilities {
		if _, ok := c.bugs[bug]; ok {
			return true
		}
	}
	return false
}

// similarTo checks family/model/bugs fields for equality of two
// processors.
func (c *cpu) similarTo(other *cpu) bool {
	if c.vendorID != other.vendorID {
		return false
	}

	if other.cpuFamily != c.cpuFamily {
		return false
	}

	if other.model != c.model {
		return false
	}

	if len(other.bugs) != len(c.bugs) {
		return false
	}

	for bug := range c.bugs {
		if _, ok := other.bugs[bug]; !ok {
			return false
		}
	}
	return true
}

// parseProcessor grabs the processor field from /proc/cpuinfo output.
func parseProcessor(data string) (int64, error) {
	matches := processorRegex.FindStringSubmatch(data)
	if len(matches) < 2 {
		return 0, fmt.Errorf("failed to parse processor number: %s", data)
	}
	return strconv.ParseInt(matches[1], 0, 64)
}

var vendorIDRegex = regexp.MustCompile(`\nvendor_id\s+:\s+(\w+)\n`)

// parseVendorID grabs the vendor_id field from /proc/cpuinfo output.
func parseVendorID(data string) (string, error) {
	result, err := parseRegex(data, "vendor_id")
	if err != nil {
		return "", fmt.Errorf("failed to parse vendor_id: %v", err)
	}
	return result, nil
}

// parseCPUFamily grabs the cpu family field from /proc/cpuinfo output.
func parseCPUFamily(data string) (int64, error) {
	result, err := parseRegex(data, "cpu family")
	if err != nil {
		return 0, fmt.Errorf("failed to parse cpu family: %v", err)
	}
	return strconv.ParseInt(result, 0, 64)
}

// parseModel grabs the model field from /proc/cpuinfo output.
func parseModel(data string) (int64, error) {
	result, err := parseRegex(data, "model")
	if err != nil {
		return 0, fmt.Errorf("failed to parse model: %v", err)
	}
	return strconv.ParseInt(result, 0, 64)
}

// parseBugs grabs the bugs field from /proc/cpuinfo output.
func parseBugs(data string) (map[string]struct{}, error) {
	result, err := parseRegex(data, "bugs")
	if err != nil {
		return nil, fmt.Errorf("failed to parse bugs: %v", err)
	}
	bugs := strings.Split(result, " ")
	ret := make(map[string]struct{}, len(bugs))
	for _, bug := range bugs {
		ret[bug] = struct{}{}
	}
	return ret, nil
}

// parseRegex parses data wtih key inserted into a standard regex template.
func parseRegex(data, key string) (string, error) {
	reg := fmt.Sprintf(`\n%s\s*:\s*(.*)\n`, key)
	r := regexp.MustCompile(reg)
	matches := r.FindStringSubmatch(data)
	if len(matches) < 2 {
		return "", fmt.Errorf("failed to match key %s: %s", key, data)
	}
	return matches[1], nil
}
