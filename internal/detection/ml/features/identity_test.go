package features

import (
	"testing"
)

type mockIdentityEvent struct {
	loginRate         float64
	geoDistanceKm     float64
	timeBetweenLogins float64
	failedAttempts    int
	privilegeLevel    int
	lateralMoveCount  int
	escalationChain   int
	serviceTicketCt   int
	encryptionType    int
	ticketLifetime    float64
	spnQueryRate      float64
	mfaChallenges     int
	mfaBypassAttempts int
	challengeTiming   float64
	deviceTrustScore  float64
	tokenReuseCount   int
	sessionDuration   float64
	ipReputationScore float64
}

func (m mockIdentityEvent) GetLoginRate() float64            { return m.loginRate }
func (m mockIdentityEvent) GetGeoDistanceKm() float64        { return m.geoDistanceKm }
func (m mockIdentityEvent) GetTimeBetweenLoginsSec() float64 { return m.timeBetweenLogins }
func (m mockIdentityEvent) GetFailedAttempts() int           { return m.failedAttempts }
func (m mockIdentityEvent) GetPrivilegeLevel() int           { return m.privilegeLevel }
func (m mockIdentityEvent) GetLateralMoveCount() int         { return m.lateralMoveCount }
func (m mockIdentityEvent) GetEscalationChainLen() int       { return m.escalationChain }
func (m mockIdentityEvent) GetServiceTicketCount() int       { return m.serviceTicketCt }
func (m mockIdentityEvent) GetEncryptionType() int           { return m.encryptionType }
func (m mockIdentityEvent) GetTicketLifetimeHours() float64  { return m.ticketLifetime }
func (m mockIdentityEvent) GetSPNQueryRate() float64         { return m.spnQueryRate }
func (m mockIdentityEvent) GetMFAChallengeCount() int        { return m.mfaChallenges }
func (m mockIdentityEvent) GetMFABypassAttempts() int        { return m.mfaBypassAttempts }
func (m mockIdentityEvent) GetChallengeTiming() float64      { return m.challengeTiming }
func (m mockIdentityEvent) GetDeviceTrustScore() float64     { return m.deviceTrustScore }
func (m mockIdentityEvent) GetTokenReuseCount() int          { return m.tokenReuseCount }
func (m mockIdentityEvent) GetSessionDurationHours() float64 { return m.sessionDuration }
func (m mockIdentityEvent) GetIPReputationScore() float64    { return m.ipReputationScore }

func TestIdentityExtractor_FeatureCount(t *testing.T) {
	ext := &IdentityFeatureExtractor{}
	feats := ext.Extract(mockIdentityEvent{})
	if len(feats) != IdentityFeatureCount {
		t.Fatalf("expected %d features, got %d", IdentityFeatureCount, len(feats))
	}
}

func TestIdentityExtractor_AuthVelocity(t *testing.T) {
	ext := &IdentityFeatureExtractor{}
	feats := ext.Extract(mockIdentityEvent{
		loginRate:         50.0,
		geoDistanceKm:     10000.0,
		timeBetweenLogins: 1800.0,
		failedAttempts:    10,
	})

	if feats[0] != float32(50.0/100.0) {
		t.Errorf("login rate expected %f, got %f", float32(50.0/100.0), feats[0])
	}
	if feats[1] != float32(10000.0/20000.0) {
		t.Errorf("geo distance expected %f, got %f", float32(10000.0/20000.0), feats[1])
	}
	if feats[2] != float32(1.0-1800.0/3600.0) {
		t.Errorf("time between logins expected %f, got %f", float32(1.0-1800.0/3600.0), feats[2])
	}
	if feats[3] != float32(10.0/20.0) {
		t.Errorf("failed attempts expected %f, got %f", float32(10.0/20.0), feats[3])
	}
}

func TestIdentityExtractor_PrivilegeEscalation(t *testing.T) {
	ext := &IdentityFeatureExtractor{}
	feats := ext.Extract(mockIdentityEvent{
		privilegeLevel:   3,
		lateralMoveCount: 5,
		escalationChain:  2,
	})

	if feats[4] != float32(3.0/4.0) {
		t.Errorf("privilege level expected %f, got %f", float32(3.0/4.0), feats[4])
	}
	if feats[5] != float32(5.0/10.0) {
		t.Errorf("lateral move count expected %f, got %f", float32(5.0/10.0), feats[5])
	}
	if feats[6] != float32(2.0/5.0) {
		t.Errorf("escalation chain expected %f, got %f", float32(2.0/5.0), feats[6])
	}
}

func TestIdentityExtractor_KerberosFeatures(t *testing.T) {
	ext := &IdentityFeatureExtractor{}
	feats := ext.Extract(mockIdentityEvent{
		serviceTicketCt: 25,
		encryptionType:  23,
		ticketLifetime:  360.0,
		spnQueryRate:    50.0,
	})

	if feats[8] != float32(25.0/50.0) {
		t.Errorf("service ticket count expected %f, got %f", float32(25.0/50.0), feats[8])
	}
	if feats[9] != float32(23.0/23.0) {
		t.Errorf("encryption type RC4=23 should be 1.0, got %f", feats[9])
	}
	if feats[10] != float32(360.0/720.0) {
		t.Errorf("ticket lifetime expected %f, got %f", float32(360.0/720.0), feats[10])
	}
	if feats[11] != float32(50.0/100.0) {
		t.Errorf("SPN query rate expected %f, got %f", float32(50.0/100.0), feats[11])
	}
}

func TestIdentityExtractor_MFAFeatures(t *testing.T) {
	ext := &IdentityFeatureExtractor{}
	feats := ext.Extract(mockIdentityEvent{
		mfaChallenges:     5,
		mfaBypassAttempts: 2,
		challengeTiming:   30.0,
		deviceTrustScore:  0.8,
	})

	if feats[12] != float32(5.0/10.0) {
		t.Errorf("MFA challenge count expected %f, got %f", float32(5.0/10.0), feats[12])
	}
	if feats[13] != float32(2.0/5.0) {
		t.Errorf("MFA bypass attempts expected %f, got %f", float32(2.0/5.0), feats[13])
	}
	if feats[14] != float32(30.0/60.0) {
		t.Errorf("challenge timing expected %f, got %f", float32(30.0/60.0), feats[14])
	}
	if feats[15] != 0.8 {
		t.Errorf("device trust score expected 0.8, got %f", feats[15])
	}
}

func TestIdentityExtractor_SessionFeatures(t *testing.T) {
	ext := &IdentityFeatureExtractor{}
	feats := ext.Extract(mockIdentityEvent{
		tokenReuseCount:   5,
		sessionDuration:   84.0,
		ipReputationScore: 0.3,
	})

	if feats[16] != float32(5.0/10.0) {
		t.Errorf("token reuse count expected %f, got %f", float32(5.0/10.0), feats[16])
	}
	if feats[17] != float32(84.0/168.0) {
		t.Errorf("session duration expected %f, got %f", float32(84.0/168.0), feats[17])
	}
	if feats[18] != 0.3 {
		t.Errorf("IP reputation score expected 0.3, got %f", feats[18])
	}
}

func TestIdentityExtractor_EmptyEvent(t *testing.T) {
	ext := &IdentityFeatureExtractor{}
	feats := ext.Extract("not-a-real-event")
	for i, v := range feats {
		if v != 0 {
			t.Fatalf("expected all zeros, got non-zero at [%d]=%f", i, v)
		}
	}
}
