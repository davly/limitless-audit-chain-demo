package legal

import (
	"strings"
	"testing"
)

func TestReviewedByCounsel_FalseHonestDefault(t *testing.T) {
	if ReviewedByCounsel {
		t.Fatalf("ReviewedByCounsel = true (R166 honest-default violation)")
	}
}

func TestDemoLiabilityFooter_NonEmpty(t *testing.T) {
	if len(DemoLiabilityFooter) == 0 {
		t.Fatalf("DemoLiabilityFooter is empty")
	}
}

func TestDemoLiabilityFooter_NamesShowcaseDiscipline(t *testing.T) {
	if !strings.Contains(DemoLiabilityFooter, "R-CROSS-INFRA-AUDIT-CHAIN-EMIT") {
		t.Fatalf("DemoLiabilityFooter does not name R-CROSS-INFRA-AUDIT-CHAIN-EMIT")
	}
}

func TestDemoLiabilityFooter_NamesShowcaseNotProduction(t *testing.T) {
	if !strings.Contains(DemoLiabilityFooter, "SHOWCASE DEMO") {
		t.Fatalf("DemoLiabilityFooter does not name SHOWCASE DEMO")
	}
}

func TestDemoLiabilityFooter_NotLegalAdvice(t *testing.T) {
	if !strings.Contains(DemoLiabilityFooter, "not legal advice") {
		t.Fatalf("DemoLiabilityFooter does not contain 'not legal advice' disclaimer")
	}
}

func TestLegalDocumentVersion_NonEmpty(t *testing.T) {
	if LegalDocumentVersion == "" {
		t.Fatalf("LegalDocumentVersion empty")
	}
}

func TestEffectiveDate_NonEmpty(t *testing.T) {
	if EffectiveDate == "" {
		t.Fatalf("EffectiveDate empty")
	}
}
