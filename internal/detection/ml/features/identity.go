package features

import (
	"math"
)

const IdentityFeatureCount = 24

// IdentityFeatureExtractor extracts features for detecting identity-layer
// attacks: credential theft, Kerberoasting, golden tickets, MFA bypass.
type IdentityFeatureExtractor struct{}

// Extract produces a 24-dim feature vector from authentication event data.
func (e *IdentityFeatureExtractor) Extract(evt interface{}) []float32 {
	feats := make([]float32, IdentityFeatureCount)

	type hasAuthVelocity interface {
		GetLoginRate() float64
		GetGeoDistanceKm() float64
		GetTimeBetweenLoginsSec() float64
		GetFailedAttempts() int
	}
	type hasPrivEsc interface {
		GetPrivilegeLevel() int
		GetLateralMoveCount() int
		GetEscalationChainLen() int
	}
	type hasKerberos interface {
		GetServiceTicketCount() int
		GetEncryptionType() int
		GetTicketLifetimeHours() float64
		GetSPNQueryRate() float64
	}
	type hasMFA interface {
		GetMFAChallengeCount() int
		GetMFABypassAttempts() int
		GetChallengeTiming() float64
		GetDeviceTrustScore() float64
	}
	type hasSession interface {
		GetTokenReuseCount() int
		GetSessionDurationHours() float64
		GetIPReputationScore() float64
	}

	if av, ok := evt.(hasAuthVelocity); ok {
		feats[0] = float32(math.Min(av.GetLoginRate()/100.0, 1.0))
		feats[1] = float32(math.Min(av.GetGeoDistanceKm()/20000.0, 1.0))
		feats[2] = 1.0 - float32(math.Min(av.GetTimeBetweenLoginsSec()/3600.0, 1.0))
		feats[3] = float32(math.Min(float64(av.GetFailedAttempts())/20.0, 1.0))
	}

	if pe, ok := evt.(hasPrivEsc); ok {
		feats[4] = float32(math.Min(float64(pe.GetPrivilegeLevel())/4.0, 1.0))
		feats[5] = float32(math.Min(float64(pe.GetLateralMoveCount())/10.0, 1.0))
		feats[6] = float32(math.Min(float64(pe.GetEscalationChainLen())/5.0, 1.0))
	}

	if k, ok := evt.(hasKerberos); ok {
		feats[8] = float32(math.Min(float64(k.GetServiceTicketCount())/50.0, 1.0))
		feats[9] = float32(k.GetEncryptionType()) / 23.0 // RC4=23 is suspicious
		feats[10] = float32(math.Min(k.GetTicketLifetimeHours()/720.0, 1.0))
		feats[11] = float32(math.Min(k.GetSPNQueryRate()/100.0, 1.0))
	}

	if m, ok := evt.(hasMFA); ok {
		feats[12] = float32(math.Min(float64(m.GetMFAChallengeCount())/10.0, 1.0))
		feats[13] = float32(math.Min(float64(m.GetMFABypassAttempts())/5.0, 1.0))
		feats[14] = float32(math.Min(m.GetChallengeTiming()/60.0, 1.0))
		feats[15] = float32(m.GetDeviceTrustScore())
	}

	if s, ok := evt.(hasSession); ok {
		feats[16] = float32(math.Min(float64(s.GetTokenReuseCount())/10.0, 1.0))
		feats[17] = float32(math.Min(s.GetSessionDurationHours()/168.0, 1.0))
		feats[18] = float32(s.GetIPReputationScore())
	}

	return feats
}
