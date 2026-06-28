// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cfgplugins

import (
	"fmt"
	"testing"

	"github.com/openconfig/featureprofiles/internal/helpers"
	"github.com/openconfig/ondatra"
)

// MACsecCfg holds parameters for configuring a MACsec security profile.
type MACsecCfg struct {
	IntfName    string // interface to apply the MACsec profile to
	ProfileName string // MACsec profile name (defaults to "sampleProfile")
	CKN         string // primary MKA key name (CKN)
	CAK         string // primary MKA key (type-7 encrypted CAK)
	FallbackCKN string
	FallbackCAK string
}

// ConfigureMACsec configures a MACsec security profile and applies it to the given interface
func ConfigureMACsec(t *testing.T, dut *ondatra.DUTDevice, cfg MACsecCfg) {
	t.Helper()
	// TODO: Add deviation and OC command
	macSecCLI := fmt.Sprintf(`mac security
   profile %[1]s
      key %[2]s 0 %[3]s
      key %[4]s 0 %[5]s fallback
      mka key-server priority 10
      mka session rekey-period 3600
      sci
   !
   interface %[6]s
   mac security profile %[1]s
!`, cfg.ProfileName, cfg.CKN, cfg.CAK, cfg.FallbackCKN, cfg.FallbackCAK, cfg.IntfName)
	helpers.GnmiCLIConfig(t, dut, macSecCLI)
}
