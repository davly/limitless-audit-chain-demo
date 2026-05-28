// Package manifest implements the R150 cohort-canonical schematised-
// knowledge envelope for limitless-audit-chain-demo's regulatory +
// cohort-rule content surfaces.
package manifest

import (
	"sort"
	"time"
)

const SchemaVersion = 1

var FreshAtUnknown = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)

const (
	SourceRCrossInfraAuditChainEmit       = "R-CROSS-INFRA-AUDIT-CHAIN-EMIT — limitless-audit-chain-demo is the 1st saturator (1/3 promotion gate)"
	SourceR151KAT1Cohort                  = "R151 KAT-1 cohort canonical hex (HMAC-SHA256 0x01||32×0x00 with empty key)"
	SourceR175MirrorMarkLoadBearingCohort = "R175 R-MIRROR-MARK-LOAD-BEARING-IN-PRODUCTION cohort wire posture"
	SourceR174CohortMaturity              = "R174 R-COHORT-5-OF-5-MATURITY new-flagship discipline (5 internal packages from inception)"
	SourceR166FounderDraftedLegalCohort   = "R166 R-LIABILITY-FOOTER-CONST founder-drafted legal-document cohort"
	SourceDelveExpectedSurface            = "github.com/davly/delve — Step 1 schema-card emitter (I3, in-flight at I20 ship)"
	SourceGroundedExpectedSurface         = "github.com/davly/grounded — Step 2 citation retrieval emitter (I4, in-flight at I20 ship)"
	SourceRecallExpectedSurface           = "github.com/davly/recall — Step 3 cache emitter (I5, in-flight at I20 ship)"
	SourceEchoExpectedSurface             = "github.com/davly/echo — Step 4 event emitter (I6, in-flight at I20 ship)"
	SourceParallaxExpectedSurface         = "github.com/davly/parallax — Step 5 job dispatch emitter (I7, in-flight at I20 ship)"
	SourceContextDoc                      = "limitless-audit-chain-demo CONTEXT.md"
	SourceR85ParityMarker                 = "R85 CLEAN-PARITY between code + CONTEXT.md"
)

type Confidence int

const (
	ConfidenceHigh   Confidence = 3
	ConfidenceMedium Confidence = 2
	ConfidenceLow    Confidence = 1
)

type ReviewerClass string

const (
	ReviewerClassCohortMaintainer ReviewerClass = "cohort_maintainer"
	ReviewerClassEmitterAuthor    ReviewerClass = "emitter_author"
	ReviewerClassFounder          ReviewerClass = "founder_draft"
)

type Entry struct {
	Key               string
	Description       string
	FreshAt           time.Time
	Source            string
	SchemaVersion     int
	Confidence        Confidence
	ReviewerClass     ReviewerClass
	ReviewedByCounsel bool
	Jurisdiction      string
	StatuteVersion    string
}

func (e Entry) IsStale(now time.Time, maxAge time.Duration) bool {
	if e.FreshAt.Equal(FreshAtUnknown) {
		return true
	}
	return now.Sub(e.FreshAt) > maxAge
}

type Manifest []Entry

func (m Manifest) SortedKeys() []string {
	keys := make([]string, 0, len(m))
	for _, e := range m {
		keys = append(keys, e.Key)
	}
	sort.Strings(keys)
	return keys
}

func (m Manifest) StaleEntries(now time.Time, maxAge time.Duration) []Entry {
	var out []Entry
	for _, e := range m {
		if e.IsStale(now, maxAge) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

func AllSources() []string {
	return []string{
		SourceRCrossInfraAuditChainEmit,
		SourceR151KAT1Cohort,
		SourceR175MirrorMarkLoadBearingCohort,
		SourceR174CohortMaturity,
		SourceR166FounderDraftedLegalCohort,
		SourceDelveExpectedSurface,
		SourceGroundedExpectedSurface,
		SourceRecallExpectedSurface,
		SourceEchoExpectedSurface,
		SourceParallaxExpectedSurface,
		SourceContextDoc,
		SourceR85ParityMarker,
	}
}

func AllReviewerClasses() []ReviewerClass {
	return []ReviewerClass{
		ReviewerClassCohortMaintainer,
		ReviewerClassEmitterAuthor,
		ReviewerClassFounder,
	}
}

// Seed returns the canonical R150 manifest for limitless-audit-chain-demo.
//
// 11 entries: 5 cohort-rule pins + 5 upstream-emitter expected-surface
// references + 1 parity marker.
func Seed() Manifest {
	t := time.Date(2026, 5, 28, 0, 0, 0, 0, time.UTC)

	return Manifest{
		{
			Key:               "cohort.r_cross_infra_audit_chain_emit.first_saturator",
			Description:       "R-CROSS-INFRA-AUDIT-CHAIN-EMIT — limitless-audit-chain-demo is the 1st saturator. Status: 1/3 (this demo). 2nd + 3rd cohort siblings are deferred to a follow-up M-slot once the upstream SDKs land their per-emitter signature surfaces.",
			FreshAt:           t,
			Source:            SourceRCrossInfraAuditChainEmit,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewerClass:     ReviewerClassFounder,
			ReviewedByCounsel: false,
			Jurisdiction:      "GLOBAL",
			StatuteVersion:    "R-CROSS-INFRA-AUDIT-CHAIN-EMIT (promoted batch 6 candidate, 2026-05-28)",
		},
		{
			Key:               "cohort.r151.kat1_pin",
			Description:       "R151 KAT-1 HMAC-SHA256 cohort canonical hex 239a7d0d3f1bbe3a98aede01e2ad818c2db60b7177c02e2f015035b2b5b7dbca — pinned in internal/lore/lore.go and verified by lore_test.go.",
			FreshAt:           t,
			Source:            SourceR151KAT1Cohort,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewerClass:     ReviewerClassCohortMaintainer,
			ReviewedByCounsel: false,
			Jurisdiction:      "GLOBAL",
			StatuteVersion:    "R151 catalogue (promoted 2026-05-22)",
		},
		{
			Key:               "cohort.r175.mirrormark_load_bearing",
			Description:       "R175 R-MIRROR-MARK-LOAD-BEARING-IN-PRODUCTION — every chain receipt in this demo is Mirror-Mark-signed under the demo's KAT-1 keying via internal/mirrormark.Sign. Verifier dispatch on SignerID is a deferred uplift.",
			FreshAt:           t,
			Source:            SourceR175MirrorMarkLoadBearingCohort,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewerClass:     ReviewerClassCohortMaintainer,
			ReviewedByCounsel: false,
			Jurisdiction:      "GLOBAL",
			StatuteVersion:    "R175 catalogue (promoted 2026-05-27)",
		},
		{
			Key:               "cohort.r174.five_of_five",
			Description:       "R174 R-COHORT-5-OF-5-MATURITY — this demo ships the 5 canonical cohort packages (lore + mirrormark + manifest + honest + firewall) from inception alongside the load-bearing chain composition library + the founder-drafted legal cohort.",
			FreshAt:           t,
			Source:            SourceR174CohortMaturity,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewerClass:     ReviewerClassCohortMaintainer,
			ReviewedByCounsel: false,
			Jurisdiction:      "GLOBAL",
			StatuteVersion:    "R174 catalogue (promoted 2026-05-27)",
		},
		{
			Key:               "cohort.r166.founder_drafted_legal_cohort",
			Description:       "R166 R-LIABILITY-FOOTER-CONST + REVIEWED-BY-COUNSEL-FALSE — limitless-audit-chain-demo joins the 11+/3 cohort with a single founder-drafted DemoLiabilityFooter constant + ReviewedByCounsel = false honest baseline.",
			FreshAt:           t,
			Source:            SourceR166FounderDraftedLegalCohort,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewerClass:     ReviewerClassFounder,
			ReviewedByCounsel: false,
			Jurisdiction:      "GLOBAL",
			StatuteVersion:    "R166 catalogue (promoted 2026-05-27)",
		},
		{
			Key:               "emitter.delve.expected_surface",
			Description:       "Step 1 — delve emits a schema-card receipt at a database-schema boundary. Expected surface: emitters.EmitDelveReceipt(payload, prev, ts) -> chain.Receipt. I3 marathon agent uplift in-flight at I20 ship.",
			FreshAt:           t,
			Source:            SourceDelveExpectedSurface,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceMedium,
			ReviewerClass:     ReviewerClassEmitterAuthor,
			ReviewedByCounsel: false,
			Jurisdiction:      "GLOBAL",
			StatuteVersion:    "I20 expected-surface stand-in",
		},
		{
			Key:               "emitter.grounded.expected_surface",
			Description:       "Step 2 — grounded emits a citation-retrieval receipt over an authoritative corpus lookup. Expected surface: emitters.EmitGroundedReceipt(payload, prev, ts) -> chain.Receipt. I4 marathon agent uplift in-flight at I20 ship.",
			FreshAt:           t,
			Source:            SourceGroundedExpectedSurface,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceMedium,
			ReviewerClass:     ReviewerClassEmitterAuthor,
			ReviewedByCounsel: false,
			Jurisdiction:      "GLOBAL",
			StatuteVersion:    "I20 expected-surface stand-in",
		},
		{
			Key:               "emitter.recall.expected_surface",
			Description:       "Step 3 — recall emits a cache receipt for a citation lookup. Expected surface: emitters.EmitRecallReceipt(payload, prev, ts) -> chain.Receipt. I5 marathon agent uplift in-flight at I20 ship.",
			FreshAt:           t,
			Source:            SourceRecallExpectedSurface,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceMedium,
			ReviewerClass:     ReviewerClassEmitterAuthor,
			ReviewedByCounsel: false,
			Jurisdiction:      "GLOBAL",
			StatuteVersion:    "I20 expected-surface stand-in",
		},
		{
			Key:               "emitter.echo.expected_surface",
			Description:       "Step 4 — echo emits an event-publication receipt. Expected surface: emitters.EmitEchoReceipt(payload, prev, ts) -> chain.Receipt. I6 marathon agent uplift in-flight at I20 ship.",
			FreshAt:           t,
			Source:            SourceEchoExpectedSurface,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceMedium,
			ReviewerClass:     ReviewerClassEmitterAuthor,
			ReviewedByCounsel: false,
			Jurisdiction:      "GLOBAL",
			StatuteVersion:    "I20 expected-surface stand-in",
		},
		{
			Key:               "emitter.parallax.expected_surface",
			Description:       "Step 5 — parallax emits a job-dispatch receipt. Expected surface: emitters.EmitParallaxReceipt(payload, prev, ts) -> chain.Receipt. I7 marathon agent uplift in-flight at I20 ship.",
			FreshAt:           t,
			Source:            SourceParallaxExpectedSurface,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceMedium,
			ReviewerClass:     ReviewerClassEmitterAuthor,
			ReviewedByCounsel: false,
			Jurisdiction:      "GLOBAL",
			StatuteVersion:    "I20 expected-surface stand-in",
		},
		{
			Key:               "r85.parity.code_vs_context",
			Description:       "R85 CLEAN-PARITY anchor — CONTEXT.md status row vs runtime ground truth.",
			FreshAt:           t,
			Source:            SourceR85ParityMarker,
			SchemaVersion:     SchemaVersion,
			Confidence:        ConfidenceHigh,
			ReviewerClass:     ReviewerClassCohortMaintainer,
			ReviewedByCounsel: false,
			Jurisdiction:      "GLOBAL",
			StatuteVersion:    "R85 (internal)",
		},
	}
}
