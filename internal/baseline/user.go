package baseline

import (
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
)

const (
	catUserLoginHour   = "user.login_hour"
	catUserApp         = "user.app"
	catUserNetDest     = "user.net_dest"
	catUserFileAccess  = "user.file_access"
	catUserWorkingHour = "user.working_hour"
)

// UserObservation captures a single user-activity data point.
type UserObservation struct {
	Username    string
	Application string
	NetDest     string
	FilePath    string
	LoginTime   time.Time
}

// UserBaseline tracks normal user behaviour including login times, typical
// applications, network destinations, file access patterns, and working hours.
type UserBaseline struct {
	engine *BaselineEngine
	logger *zap.Logger

	mu           sync.RWMutex
	userApps     map[string]map[string]int // user -> app -> count
	userNetDests map[string]map[string]int // user -> dest -> count
	userFiles    map[string]map[string]int // user -> file_prefix -> count
}

// NewUserBaseline creates a user baseline analyser backed by the given engine.
func NewUserBaseline(engine *BaselineEngine, logger *zap.Logger) *UserBaseline {
	return &UserBaseline{
		engine:       engine,
		logger:       logger,
		userApps:     make(map[string]map[string]int),
		userNetDests: make(map[string]map[string]int),
		userFiles:    make(map[string]map[string]int),
	}
}

// Observe records a user-activity data-point for baseline learning.
func (ub *UserBaseline) Observe(obs UserObservation) {
	if obs.Username == "" {
		return
	}

	if !obs.LoginTime.IsZero() {
		hour := float64(obs.LoginTime.Hour())
		ub.engine.AddObservation(catUserLoginHour, obs.Username, hour)
		ub.engine.AddObservation(catUserWorkingHour, obs.Username, hour)
	}

	if obs.Application != "" {
		ub.trackApp(obs.Username, obs.Application)
	}
	if obs.NetDest != "" {
		ub.trackNetDest(obs.Username, obs.NetDest)
	}
	if obs.FilePath != "" {
		ub.trackFileAccess(obs.Username, obs.FilePath)
	}
}

// CheckLoginTime returns true if the login hour is anomalous for this user.
func (ub *UserBaseline) CheckLoginTime(username string, loginTime time.Time) (bool, float64) {
	return ub.engine.IsAnomaly(catUserLoginHour, username, float64(loginTime.Hour()))
}

// CheckApplication returns true if the user has never been seen running this app.
func (ub *UserBaseline) CheckApplication(username, app string) bool {
	if ub.engine.IsLearning() {
		return false
	}

	ub.mu.RLock()
	defer ub.mu.RUnlock()

	apps, ok := ub.userApps[username]
	if !ok {
		return true
	}
	_, seen := apps[app]
	return !seen
}

// CheckNetDestination returns true if the user has never connected to this destination.
func (ub *UserBaseline) CheckNetDestination(username, dest string) bool {
	if ub.engine.IsLearning() {
		return false
	}

	ub.mu.RLock()
	defer ub.mu.RUnlock()

	dests, ok := ub.userNetDests[username]
	if !ok {
		return true
	}
	_, seen := dests[dest]
	return !seen
}

// CheckFileAccess returns true if the user has never accessed files in this path.
func (ub *UserBaseline) CheckFileAccess(username, filePath string) bool {
	if ub.engine.IsLearning() {
		return false
	}

	prefix := filePrefix(filePath)
	ub.mu.RLock()
	defer ub.mu.RUnlock()

	files, ok := ub.userFiles[username]
	if !ok {
		return true
	}
	_, seen := files[prefix]
	return !seen
}

func (ub *UserBaseline) trackApp(user, app string) {
	ub.mu.Lock()
	defer ub.mu.Unlock()

	apps, ok := ub.userApps[user]
	if !ok {
		apps = make(map[string]int)
		ub.userApps[user] = apps
	}
	apps[app]++
	ub.engine.AddObservation(catUserApp, fmt.Sprintf("%s:%s", user, app), 1)
}

func (ub *UserBaseline) trackNetDest(user, dest string) {
	ub.mu.Lock()
	defer ub.mu.Unlock()

	dests, ok := ub.userNetDests[user]
	if !ok {
		dests = make(map[string]int)
		ub.userNetDests[user] = dests
	}
	dests[dest]++
	ub.engine.AddObservation(catUserNetDest, fmt.Sprintf("%s:%s", user, dest), 1)
}

func (ub *UserBaseline) trackFileAccess(user, filePath string) {
	prefix := filePrefix(filePath)
	ub.mu.Lock()
	defer ub.mu.Unlock()

	files, ok := ub.userFiles[user]
	if !ok {
		files = make(map[string]int)
		ub.userFiles[user] = files
	}
	files[prefix]++
	ub.engine.AddObservation(catUserFileAccess, fmt.Sprintf("%s:%s", user, prefix), 1)
}

func filePrefix(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' || path[i] == '\\' {
			return path[:i]
		}
	}
	return path
}
