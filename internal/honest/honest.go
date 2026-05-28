// Package honest implements the cohort R143 LOUD-ONCE-WARNING-FLAG
// discipline for limitless-audit-chain-demo.
//
// Canonical advisories — three Warn (the demo is a showcase, not a
// production-runtime gate; advisories are framed as cohort discipline
// reminders, not as regulator-strict-liability surfaces):
//
//  1. CROSS_INFRA_DEMO_NOT_PRODUCTION_RUNTIME — Warn. The demo
//     orchestrates five upstream-emitter stand-ins. Production
//     runtimes MUST replace the stand-ins with the real SDKs.
//  2. UPSTREAM_SDK_STAND_INS_IN_USE — Warn. The internal/emitters
//     package contains stand-in implementations of the five upstream
//     SDKs (delve / grounded / recall / echo / parallax). When the
//     real SDKs ship (I3-I7 marathon agents), the stand-ins must be
//     swapped out in a follow-up M-slot.
//  3. SIGNATURE_VERIFIER_USES_MIRROR_MARK_TODAY — Warn. The chain
//     verifier at I20 ship-time uses the Mirror-Mark HMAC primitive
//     as a unified placeholder for all five upstream signature
//     surfaces. A future M-slot will introduce a dispatch verifier
//     that selects the per-emitter signature surface based on
//     Receipt.SignerID.
package honest

import (
	"fmt"
	"io"
	"sync"
)

const LoudOncePrefix = "[LOUD-ONCE-WARNING]"

type Severity string

const (
	SeverityInfo  Severity = "INFO"
	SeverityWarn  Severity = "WARN"
	SeverityError Severity = "ERROR"
)

type Advisory struct {
	Code     string
	Severity Severity
	Message  string
	DocLink  string
}

var canonicalAdvisories = []Advisory{
	{
		Code:     "CROSS_INFRA_DEMO_NOT_PRODUCTION_RUNTIME",
		Severity: SeverityWarn,
		Message:  "limitless-audit-chain-demo is the canonical 1st saturator of R-CROSS-INFRA-AUDIT-CHAIN-EMIT — it demonstrates the chain composition + verification primitive. Production runtimes MUST use the real upstream emitter SDKs (delve / grounded / recall / echo / parallax) once those flagships ship.",
		DocLink:  "README.md",
	},
	{
		Code:     "UPSTREAM_SDK_STAND_INS_IN_USE",
		Severity: SeverityWarn,
		Message:  "The five emitter stand-ins in internal/emitters/ are I20 ship-time placeholders for delve / grounded / recall / echo / parallax. When the upstream SDKs land their EmitXReceipt surfaces, replace the stand-in calls in cmd/audit-chain-demo/main.go in a follow-up M-slot.",
		DocLink:  "CONTEXT.md",
	},
	{
		Code:     "SIGNATURE_VERIFIER_USES_MIRROR_MARK_TODAY",
		Severity: SeverityWarn,
		Message:  "The chain.VerifierFunc supplied at I20 ship-time uses Mirror-Mark HMAC-SHA256 as a unified signature surface for all five emitters. A future M-slot will introduce a dispatch verifier that selects the per-emitter signature primitive based on Receipt.SignerID once the upstream SDKs land their signature surfaces.",
		DocLink:  "CONTEXT.md",
	},
}

var (
	registryMu sync.RWMutex
	registry   = map[string]*sync.Once{}
)

func LoudOnce(adv Advisory, w io.Writer) {
	registryMu.RLock()
	once, ok := registry[adv.Code]
	registryMu.RUnlock()
	if !ok {
		registryMu.Lock()
		once, ok = registry[adv.Code]
		if !ok {
			once = &sync.Once{}
			registry[adv.Code] = once
		}
		registryMu.Unlock()
	}
	once.Do(func() {
		_, _ = fmt.Fprintf(w, "%s %s %s: %s (see %s)\n",
			LoudOncePrefix, adv.Severity, adv.Code, adv.Message, adv.DocLink)
	})
}

func Reset() {
	registryMu.Lock()
	registry = map[string]*sync.Once{}
	registryMu.Unlock()
}

func CanonicalAdvisories() []Advisory {
	out := make([]Advisory, len(canonicalAdvisories))
	copy(out, canonicalAdvisories)
	return out
}

func FindAdvisory(code string) (Advisory, bool) {
	for _, a := range canonicalAdvisories {
		if a.Code == code {
			return a, true
		}
	}
	return Advisory{}, false
}
