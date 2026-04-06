//go:build darwin

package kernel

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Foundation -framework EndpointSecurity

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <stdlib.h>
#include <string.h>

extern void goESFEventCallback(int eventType, int pid, int ppid, int uid, int gid,
    const char *comm, const char *path, const char *args);
extern int goESFAuthCallback(int eventType, int pid, const char *comm, const char *path);

static es_client_t *_esf_client = NULL;

static char* esf_copy_string(es_string_token_t tok) {
    if (tok.length == 0 || tok.data == NULL) {
        return strdup("");
    }
    char *s = (char *)malloc(tok.length + 1);
    if (s == NULL) return strdup("");
    memcpy(s, tok.data, tok.length);
    s[tok.length] = '\0';
    return s;
}

static char* esf_event_path(const es_message_t *msg) {
    switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_EXEC:
        return esf_copy_string(msg->event.exec.target->executable->path);
    case ES_EVENT_TYPE_AUTH_OPEN:
        return esf_copy_string(msg->event.open.file->path);
    case ES_EVENT_TYPE_AUTH_CREATE:
        if (msg->event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
            return esf_copy_string(msg->event.create.destination.existing_file->path);
        }
        return esf_copy_string(msg->event.create.destination.new_path.dir->path);
    case ES_EVENT_TYPE_AUTH_RENAME:
        return esf_copy_string(msg->event.rename.source->path);
    case ES_EVENT_TYPE_AUTH_UNLINK:
        return esf_copy_string(msg->event.unlink.target->path);
    case ES_EVENT_TYPE_AUTH_KEXTLOAD:
        return esf_copy_string(msg->event.kextload.identifier);
    case ES_EVENT_TYPE_AUTH_MOUNT:
        return strdup(msg->event.mount.statfs->f_mntonname);
    case ES_EVENT_TYPE_AUTH_SIGNAL:
        return esf_copy_string(msg->event.signal.target->executable->path);
    case ES_EVENT_TYPE_NOTIFY_WRITE:
        return esf_copy_string(msg->event.write.target->path);
    case ES_EVENT_TYPE_NOTIFY_MMAP:
        return esf_copy_string(msg->event.mmap.source->path);
    default:
        return strdup("");
    }
}

static void esf_handle_message(es_client_t *client, const es_message_t *msg) {
    audit_token_t tok = msg->process->audit_token;
    pid_t pid = audit_token_to_pid(tok);
    pid_t ppid = msg->process->ppid;
    uid_t uid = audit_token_to_euid(tok);
    gid_t gid = audit_token_to_egid(tok);

    char *comm = esf_copy_string(msg->process->executable->path);
    char *path = esf_event_path(msg);

    if (msg->action_type == ES_ACTION_TYPE_AUTH) {
        int decision = goESFAuthCallback((int)msg->event_type, (int)pid, comm, path);
        if (decision == 0) {
            es_respond_auth_result(client, msg, ES_AUTH_RESULT_ALLOW, false);
        } else {
            es_respond_auth_result(client, msg, ES_AUTH_RESULT_DENY, false);
        }
    }

    goESFEventCallback((int)msg->event_type, (int)pid, (int)ppid,
        (int)uid, (int)gid, comm, path, "");

    free(comm);
    free(path);
}

static int esf_create_client(void) {
    if (_esf_client != NULL) return -1;
    es_new_client_result_t result = es_new_client(&_esf_client,
        ^(es_client_t *c, const es_message_t *msg) {
            esf_handle_message(c, msg);
        });
    return (int)result;
}

static void esf_delete_client(void) {
    if (_esf_client != NULL) {
        es_delete_client(_esf_client);
        _esf_client = NULL;
    }
}

static int esf_subscribe_all(void) {
    if (_esf_client == NULL) return -1;
    es_event_type_t evts[] = {
        ES_EVENT_TYPE_AUTH_EXEC,
        ES_EVENT_TYPE_AUTH_OPEN,
        ES_EVENT_TYPE_AUTH_CREATE,
        ES_EVENT_TYPE_AUTH_RENAME,
        ES_EVENT_TYPE_AUTH_UNLINK,
        ES_EVENT_TYPE_AUTH_KEXTLOAD,
        ES_EVENT_TYPE_AUTH_MOUNT,
        ES_EVENT_TYPE_AUTH_SIGNAL,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_MMAP,
        ES_EVENT_TYPE_NOTIFY_MPROTECT,
    };
    es_return_t ret = es_subscribe(_esf_client, evts, sizeof(evts)/sizeof(evts[0]));
    return (ret == ES_RETURN_SUCCESS) ? 0 : -1;
}

static int esf_unsubscribe_all(void) {
    if (_esf_client == NULL) return -1;
    es_return_t ret = es_unsubscribe_all(_esf_client);
    return (ret == ES_RETURN_SUCCESS) ? 0 : -1;
}

static int esf_mute_path_prefix(const char *path) {
    if (_esf_client == NULL) return -1;
    es_return_t ret = es_mute_path(_esf_client, path, ES_MUTE_PATH_TYPE_PREFIX);
    return (ret == ES_RETURN_SUCCESS) ? 0 : -1;
}

static int esf_clear_cache(void) {
    if (_esf_client == NULL) return -1;
    es_clear_cache_result_t ret = es_clear_cache(_esf_client);
    return (ret == ES_CLEAR_CACHE_RESULT_SUCCESS) ? 0 : -1;
}
*/
import "C"

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/razatechofficial/edr/pkg/events"
)

var defaultMutePaths = []string{
	"/usr/libexec/",
	"/System/",
	"/Library/Apple/",
	"/usr/sbin/syslogd",
	"/usr/libexec/amfid",
}

const (
	defaultAuthCacheTTL = 5 * time.Minute
	defaultAuthTimeout  = 30 * time.Second
)

// globalESF holds the active ESFDriver instance for C callback routing.
// Only one ESF client is supported per process.
var globalESF atomic.Pointer[ESFDriver]

type authCacheEntry struct {
	decision  AuthDecision
	expiresAt time.Time
}

type authCache struct {
	mu      sync.RWMutex
	entries map[string]authCacheEntry
	ttl     time.Duration
}

func newAuthCache(ttl time.Duration) *authCache {
	return &authCache{
		entries: make(map[string]authCacheEntry),
		ttl:     ttl,
	}
}

func (c *authCache) get(key string) (AuthDecision, bool) {
	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(e.expiresAt) {
		return AuthAllow, false
	}
	return e.decision, true
}

func (c *authCache) set(key string, decision AuthDecision) {
	c.mu.Lock()
	c.entries[key] = authCacheEntry{
		decision:  decision,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}

func (c *authCache) cleanupLoop(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(c.ttl / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			now := time.Now()
			for k, v := range c.entries {
				if now.After(v.expiresAt) {
					delete(c.entries, k)
				}
			}
			c.mu.Unlock()
		}
	}
}

// ESFDriver implements Driver using the macOS Endpoint Security Framework.
type ESFDriver struct {
	agentID     string
	mu          sync.RWMutex
	policy      EventPolicy
	startTime   time.Time
	running     atomic.Bool
	buf         *RingBuffer
	cancel      context.CancelFunc
	wg          sync.WaitGroup
	authMu      sync.RWMutex
	authHandler AuthHandler
	cache       *authCache
	authTimeout time.Duration

	received  atomic.Uint64
	dropped   atomic.Uint64
	processed atomic.Uint64
	errors    atomic.Uint64
}

// NewESFDriver creates a new Endpoint Security Framework driver.
// Requires root privileges and the com.apple.developer.endpoint-security.client entitlement.
func NewESFDriver(agentID string) (*ESFDriver, error) {
	if os.Getuid() != 0 {
		return nil, fmt.Errorf("esf driver requires root privileges")
	}
	return &ESFDriver{
		agentID:     agentID,
		policy:      DefaultPolicy(),
		cache:       newAuthCache(defaultAuthCacheTTL),
		authTimeout: defaultAuthTimeout,
	}, nil
}

// Name returns the driver identifier.
func (d *ESFDriver) Name() string { return "esf" }

// Capabilities reports which event types this driver can collect.
func (d *ESFDriver) Capabilities() []events.EventType {
	return []events.EventType{
		events.EventProcess,
		events.EventFile,
		events.EventMemory,
		events.EventAuth,
		events.EventModule,
		events.EventMount,
		events.EventSignal,
	}
}

// Start creates the ESF client, subscribes to events, and begins collection.
func (d *ESFDriver) Start(ctx context.Context, buf *RingBuffer) error {
	if d.running.Load() {
		return fmt.Errorf("esf driver already running")
	}

	d.buf = buf

	if !globalESF.CompareAndSwap(nil, d) {
		return fmt.Errorf("another esf driver instance is already active")
	}

	result := int(C.esf_create_client())
	if result != 0 {
		globalESF.Store(nil)
		return d.clientCreateError(result)
	}

	if ret := C.esf_subscribe_all(); ret != 0 {
		C.esf_delete_client()
		globalESF.Store(nil)
		return fmt.Errorf("failed to subscribe to ESF events")
	}

	d.mu.RLock()
	mutePaths := defaultMutePaths
	if len(d.policy.MutePaths) > 0 {
		mutePaths = d.policy.MutePaths
	}
	d.mu.RUnlock()

	for _, p := range mutePaths {
		cs := C.CString(p)
		C.esf_mute_path_prefix(cs)
		C.free(unsafe.Pointer(cs))
	}

	var child context.Context
	child, d.cancel = context.WithCancel(ctx)
	d.startTime = time.Now()
	d.running.Store(true)

	d.wg.Add(1)
	go d.cache.cleanupLoop(child, &d.wg)

	return nil
}

// Stop unsubscribes from all events, deletes the ESF client, and releases resources.
func (d *ESFDriver) Stop() error {
	if !d.running.CompareAndSwap(true, false) {
		return nil
	}
	d.cancel()

	C.esf_unsubscribe_all()
	C.esf_delete_client()

	globalESF.Store(nil)
	d.wg.Wait()
	return nil
}

// SetPolicy updates the event collection policy. Mute paths are applied to the ESF client.
func (d *ESFDriver) SetPolicy(policy EventPolicy) error {
	d.mu.Lock()
	d.policy = policy
	d.mu.Unlock()

	if d.running.Load() {
		for _, p := range policy.MutePaths {
			cs := C.CString(p)
			C.esf_mute_path_prefix(cs)
			C.free(unsafe.Pointer(cs))
		}
		C.esf_clear_cache()
	}
	return nil
}

// SetAuthHandler registers a handler for authorization events. The handler is
// called with a timeout to ensure ESF deadlines are met.
func (d *ESFDriver) SetAuthHandler(h AuthHandler) {
	d.authMu.Lock()
	d.authHandler = h
	d.authMu.Unlock()
}

// Stats returns current driver metrics.
func (d *ESFDriver) Stats() DriverStats {
	var uptime float64
	if !d.startTime.IsZero() {
		uptime = time.Since(d.startTime).Seconds()
	}
	return DriverStats{
		EventsReceived:  d.received.Load(),
		EventsDropped:   d.dropped.Load(),
		EventsProcessed: d.processed.Load(),
		UptimeSeconds:   uptime,
		ErrorCount:      d.errors.Load(),
	}
}

// mapESFEventType maps raw ESF event type integers to internal EventType categories.
func mapESFEventType(raw int) events.EventType {
	switch raw {
	case int(C.ES_EVENT_TYPE_AUTH_EXEC),
		int(C.ES_EVENT_TYPE_NOTIFY_FORK),
		int(C.ES_EVENT_TYPE_NOTIFY_EXIT):
		return events.EventProcess
	case int(C.ES_EVENT_TYPE_AUTH_OPEN),
		int(C.ES_EVENT_TYPE_AUTH_CREATE),
		int(C.ES_EVENT_TYPE_AUTH_RENAME),
		int(C.ES_EVENT_TYPE_AUTH_UNLINK),
		int(C.ES_EVENT_TYPE_NOTIFY_WRITE):
		return events.EventFile
	case int(C.ES_EVENT_TYPE_NOTIFY_MMAP),
		int(C.ES_EVENT_TYPE_NOTIFY_MPROTECT):
		return events.EventMemory
	case int(C.ES_EVENT_TYPE_AUTH_KEXTLOAD):
		return events.EventModule
	case int(C.ES_EVENT_TYPE_AUTH_MOUNT):
		return events.EventMount
	case int(C.ES_EVENT_TYPE_AUTH_SIGNAL):
		return events.EventSignal
	default:
		return events.EventProcess
	}
}

func (d *ESFDriver) clientCreateError(result int) error {
	switch result {
	case 1:
		return fmt.Errorf("esf: invalid argument")
	case 2:
		return fmt.Errorf("esf: internal error")
	case 3:
		return fmt.Errorf("esf: missing com.apple.developer.endpoint-security.client entitlement")
	case 4:
		return fmt.Errorf("esf: not permitted (full disk access required)")
	case 5:
		return fmt.Errorf("esf: not privileged (must run as root)")
	case 6:
		return fmt.Errorf("esf: too many clients")
	default:
		return fmt.Errorf("esf: client creation failed with code %d", result)
	}
}
