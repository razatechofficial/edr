//go:build darwin && cgo && !nosec

package kernel

/*
#cgo CFLAGS: -x objective-c
// Newer macOS SDKs (e.g. Xcode 26) ship ESF as /usr/lib/libEndpointSecurity.tbd only;
// -framework EndpointSecurity no longer resolves for the linker.
#cgo LDFLAGS: -framework Foundation -lEndpointSecurity -lbsm

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <mach/mach_time.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

extern void goESFEventCallback(int eventType, int pid, int ppid, int uid, int gid,
    const char *comm, const char *path, const char *exec_args, const char *exec_env,
    int extra_int, const char *detail);
extern int goESFAuthCallback(int eventType, int pid, const char *comm, const char *path, int budget_ms);

// esf_auth_budget_ms converts ESF message deadline to remaining milliseconds (best-effort).
static int esf_auth_budget_ms(const es_message_t *msg) {
    if (msg == NULL) {
        return -1;
    }
    uint64_t dl = msg->deadline;
    if (dl == 0ULL) {
        return -1;
    }
    uint64_t now = mach_absolute_time();
    if (dl <= now) {
        return 0;
    }
    mach_timebase_info_data_t tb;
    if (mach_timebase_info(&tb) != KERN_SUCCESS) {
        return -1;
    }
    uint64_t delta = dl - now;
    uint64_t ns = delta * (uint64_t)tb.numer / (uint64_t)tb.denom;
    uint64_t ms = ns / 1000000ULL;
    if (ms > (uint64_t)INT_MAX) {
        return INT_MAX;
    }
    return (int)ms;
}

static es_client_t *_esf_client = NULL;

#define ESF_ARG_SEP ((char)0x1e)

static char *esf_join_exec_args(const es_message_t *msg) {
    if (msg == NULL) return strdup("");
    if (msg->event_type != ES_EVENT_TYPE_AUTH_EXEC && msg->event_type != ES_EVENT_TYPE_NOTIFY_EXEC) {
        return strdup("");
    }
    const es_event_exec_t *ex = &msg->event.exec;
    size_t cap = 512;
    size_t len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) {
        return strdup("");
    }
    buf[0] = '\0';
    size_t n = es_exec_arg_count(ex);
    for (size_t i = 0; i < n; i++) {
        es_string_token_t t = es_exec_arg(ex, i);
        if (t.data == NULL || t.length == 0) {
            continue;
        }
        size_t add = t.length + (len > 0 ? 1u : 0u);
        if (len + add + 1 > cap) {
            while (len + add + 1 > cap) {
                cap *= 2;
            }
            char *nb = (char *)realloc(buf, cap);
            if (!nb) {
                free(buf);
                return strdup("");
            }
            buf = nb;
        }
        if (len > 0) {
            buf[len++] = ESF_ARG_SEP;
        }
        memcpy(buf + len, t.data, t.length);
        len += t.length;
        buf[len] = '\0';
    }
    return buf;
}

static char *esf_join_exec_env(const es_message_t *msg) {
    if (msg == NULL) return strdup("");
    if (msg->event_type != ES_EVENT_TYPE_AUTH_EXEC && msg->event_type != ES_EVENT_TYPE_NOTIFY_EXEC) {
        return strdup("");
    }
    const es_event_exec_t *ex = &msg->event.exec;
    size_t cap = 1024;
    size_t len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) {
        return strdup("");
    }
    buf[0] = '\0';
    size_t n = es_exec_env_count(ex);
    for (size_t i = 0; i < n; i++) {
        es_string_token_t t = es_exec_env(ex, i);
        if (t.data == NULL || t.length == 0) {
            continue;
        }
        size_t add = t.length + (len > 0 ? 1u : 0u);
        if (len + add + 1 > cap) {
            while (len + add + 1 > cap) {
                cap *= 2;
            }
            char *nb = (char *)realloc(buf, cap);
            if (!nb) {
                free(buf);
                return strdup("");
            }
            buf = nb;
        }
        if (len > 0) {
            buf[len++] = ESF_ARG_SEP;
        }
        memcpy(buf + len, t.data, t.length);
        len += t.length;
        buf[len] = '\0';
    }
    return buf;
}

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

// NULL-safe ESF accessors (P0-7).
//
// EndpointSecurity guarantees msg is non-NULL inside the handler, but every
// nested pointer (msg->process, msg->process->executable, msg->event.*) can
// be NULL in practice on certain event types or transient states. Direct
// dereferences here previously crashed the agent under load. Every accessor
// below tolerates a NULL chain and returns a heap-allocated empty string
// (or 0 for numeric IDs) so callers do not need to NULL-check.

// Returns the file path as a malloc'd C-string ("" if any link is NULL).
static char* safe_file_path_copy(const es_file_t *f) {
    if (f == NULL) return strdup("");
    return esf_copy_string(f->path);
}

// Returns the process executable path as a malloc'd C-string.
static char* safe_proc_exec_path_copy(const es_process_t *p) {
    if (p == NULL) return strdup("");
    if (p->executable == NULL) return strdup("");
    return esf_copy_string(p->executable->path);
}

// Returns the process pid (0 if process is NULL).
static pid_t safe_pid(const es_process_t *p) {
    if (p == NULL) return 0;
    return audit_token_to_pid(p->audit_token);
}

// Returns the parent pid (0 if process is NULL).
static pid_t safe_ppid(const es_process_t *p) {
    if (p == NULL) return 0;
    return p->ppid;
}

// Returns the euid of the process (0 if process is NULL).
static uid_t safe_euid(const es_process_t *p) {
    if (p == NULL) return 0;
    return audit_token_to_euid(p->audit_token);
}

// Returns the egid of the process (0 if process is NULL).
static gid_t safe_egid(const es_process_t *p) {
    if (p == NULL) return 0;
    return audit_token_to_egid(p->audit_token);
}

static char* esf_event_path(const es_message_t *msg) {
    if (msg == NULL) return strdup("");
    switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_EXEC:
        return safe_proc_exec_path_copy(msg->event.exec.target);
    case ES_EVENT_TYPE_AUTH_OPEN:
        return safe_file_path_copy(msg->event.open.file);
    case ES_EVENT_TYPE_AUTH_CREATE:
        if (msg->event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
            return safe_file_path_copy(msg->event.create.destination.existing_file);
        }
        return safe_file_path_copy(msg->event.create.destination.new_path.dir);
    case ES_EVENT_TYPE_AUTH_RENAME:
        return safe_file_path_copy(msg->event.rename.source);
    case ES_EVENT_TYPE_AUTH_UNLINK:
        return safe_file_path_copy(msg->event.unlink.target);
    case ES_EVENT_TYPE_AUTH_KEXTLOAD:
        return esf_copy_string(msg->event.kextload.identifier);
    case ES_EVENT_TYPE_AUTH_MOUNT:
        if (msg->event.mount.statfs == NULL) return strdup("");
        return strdup(msg->event.mount.statfs->f_mntonname);
    case ES_EVENT_TYPE_AUTH_SIGNAL:
        return safe_proc_exec_path_copy(msg->event.signal.target);
    case ES_EVENT_TYPE_NOTIFY_WRITE:
        return safe_file_path_copy(msg->event.write.target);
    case ES_EVENT_TYPE_NOTIFY_MMAP:
    case ES_EVENT_TYPE_AUTH_MMAP:
        return safe_file_path_copy(msg->event.mmap.source);
    case ES_EVENT_TYPE_NOTIFY_MPROTECT:
        return safe_proc_exec_path_copy(msg->process);
    case ES_EVENT_TYPE_NOTIFY_EXEC:
        return safe_proc_exec_path_copy(msg->event.exec.target);
    case ES_EVENT_TYPE_NOTIFY_UNLINK:
        return safe_file_path_copy(msg->event.unlink.target);
    case ES_EVENT_TYPE_NOTIFY_TRUNCATE:
        return safe_file_path_copy(msg->event.truncate.target);
    case ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA:
        return safe_file_path_copy(msg->event.exchangedata.file1);
    case ES_EVENT_TYPE_NOTIFY_FCNTL:
        return safe_file_path_copy(msg->event.fcntl.target);
    case ES_EVENT_TYPE_NOTIFY_RENAME:
        return safe_file_path_copy(msg->event.rename.source);
    case ES_EVENT_TYPE_AUTH_COPYFILE:
        return safe_file_path_copy(msg->event.copyfile.source);
    case ES_EVENT_TYPE_AUTH_GET_TASK:
        return safe_proc_exec_path_copy(msg->event.get_task.target);
    case ES_EVENT_TYPE_NOTIFY_SIGNAL:
        return safe_proc_exec_path_copy(msg->event.signal.target);
    case ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE:
        return safe_proc_exec_path_copy(msg->event.remote_thread_create.target);
#ifdef ES_EVENT_TYPE_NOTIFY_BIND
    case ES_EVENT_TYPE_NOTIFY_BIND:
        return safe_proc_exec_path_copy(msg->process);
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_CONNECT
    case ES_EVENT_TYPE_NOTIFY_CONNECT:
        return safe_proc_exec_path_copy(msg->process);
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR
    case ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR:
        return safe_file_path_copy(msg->event.deleteextattr.target);
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD
    case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD:
        return safe_proc_exec_path_copy(msg->process);
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE
    case ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE:
        return safe_proc_exec_path_copy(msg->process);
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_XPC_CONNECT
    case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT:
        return esf_copy_string(msg->event.xpc_connect.service_name);
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED
    case ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED:
        return safe_proc_exec_path_copy(msg->process);
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_TCC_MODIFY
    case ES_EVENT_TYPE_NOTIFY_TCC_MODIFY:
        return safe_proc_exec_path_copy(msg->process);
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE
    case ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE:
        return safe_file_path_copy(msg->event.gatekeeper_user_override.file);
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED
    case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED:
        return safe_file_path_copy(msg->event.xp_malware_detected.file);
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED
    case ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED:
        return safe_file_path_copy(msg->event.xp_malware_remediated.file);
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_PROFILE_ADD
    case ES_EVENT_TYPE_NOTIFY_PROFILE_ADD:
        return esf_copy_string(msg->event.profile_add.profile_path);
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE
    case ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE:
        return esf_copy_string(msg->event.profile_remove.profile_path);
#endif
    default:
        return strdup("");
    }
}

static void esf_extra_fields(const es_message_t *msg, int *extra_int, char **detail_out) {
    *extra_int = 0;
    *detail_out = strdup("");
    if (msg == NULL || detail_out == NULL) {
        return;
    }
    switch (msg->event_type) {
    case ES_EVENT_TYPE_AUTH_SIGNAL:
        *extra_int = (int)msg->event.signal.sig;
        break;
    case ES_EVENT_TYPE_NOTIFY_SIGNAL:
        *extra_int = (int)msg->event.signal.sig;
        break;
#ifdef ES_EVENT_TYPE_NOTIFY_XPC_CONNECT
    case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT:
        free(*detail_out);
        *detail_out = esf_copy_string(msg->event.xpc_connect.service_name);
        break;
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_TCC_MODIFY
    case ES_EVENT_TYPE_NOTIFY_TCC_MODIFY:
        free(*detail_out);
        *detail_out = esf_copy_string(msg->event.tcc_modify.service);
        *extra_int = (int)msg->event.tcc_modify.auth_value;
        break;
#endif
    default:
        break;
    }
}

static void esf_handle_message(es_client_t *client, const es_message_t *msg) {
    // msg is guaranteed non-NULL by EndpointSecurity but we defend anyway —
    // a crash here would unsubscribe the agent. msg->process *can* be NULL
    // for certain notify-only event paths; every nested chain below goes
    // through the safe_* helpers above.
    if (msg == NULL) return;

    pid_t pid = safe_pid(msg->process);
    pid_t ppid = safe_ppid(msg->process);
    uid_t uid = safe_euid(msg->process);
    gid_t gid = safe_egid(msg->process);

    char *comm = safe_proc_exec_path_copy(msg->process);
    char *path = esf_event_path(msg);

    if (msg->action_type == ES_ACTION_TYPE_AUTH) {
        int decision = goESFAuthCallback((int)msg->event_type, (int)pid,
            comm ? comm : "",
            path ? path : "",
            esf_auth_budget_ms(msg));
        if (client != NULL) {
            es_auth_result_t r = (decision == 0) ? ES_AUTH_RESULT_ALLOW
                                                 : ES_AUTH_RESULT_DENY;
            es_respond_auth_result(client, msg, r, false);
        }
    }

    char *exec_args = esf_join_exec_args(msg);
    char *exec_env = esf_join_exec_env(msg);
    if (!exec_args) {
        exec_args = strdup("");
    }
    if (!exec_env) {
        exec_env = strdup("");
    }
    int extra_int = 0;
    char *detail = NULL;
    esf_extra_fields(msg, &extra_int, &detail);
    if (!detail) {
        detail = strdup("");
    }
    goESFEventCallback((int)msg->event_type, (int)pid, (int)ppid,
        (int)uid, (int)gid,
        comm ? comm : "",
        path ? path : "",
        exec_args, exec_env,
        extra_int, detail ? detail : "");
    free(detail);
    free(exec_args);
    free(exec_env);

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
        ES_EVENT_TYPE_AUTH_COPYFILE,
        ES_EVENT_TYPE_AUTH_MMAP,
        ES_EVENT_TYPE_AUTH_GET_TASK,
        ES_EVENT_TYPE_AUTH_KEXTLOAD,
        ES_EVENT_TYPE_AUTH_MOUNT,
        ES_EVENT_TYPE_AUTH_SIGNAL,
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_UNLINK,
        ES_EVENT_TYPE_NOTIFY_TRUNCATE,
        ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA,
        ES_EVENT_TYPE_NOTIFY_FCNTL,
        ES_EVENT_TYPE_NOTIFY_RENAME,
        ES_EVENT_TYPE_NOTIFY_SIGNAL,
        ES_EVENT_TYPE_NOTIFY_MMAP,
        ES_EVENT_TYPE_NOTIFY_MPROTECT,
        ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE,
#ifdef ES_EVENT_TYPE_NOTIFY_BIND
        ES_EVENT_TYPE_NOTIFY_BIND,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_CONNECT
        ES_EVENT_TYPE_NOTIFY_CONNECT,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR
        ES_EVENT_TYPE_NOTIFY_DELETEEXTATTR,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD
        ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE
        ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_REMOVE,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN
        ES_EVENT_TYPE_NOTIFY_LOGIN_LOGIN,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT
        ES_EVENT_TYPE_NOTIFY_LOGIN_LOGOUT,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK
        ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK
        ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_XPC_CONNECT
        ES_EVENT_TYPE_NOTIFY_XPC_CONNECT,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_AUTHENTICATION
        ES_EVENT_TYPE_NOTIFY_AUTHENTICATION,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_PROFILE_ADD
        ES_EVENT_TYPE_NOTIFY_PROFILE_ADD,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE
        ES_EVENT_TYPE_NOTIFY_PROFILE_REMOVE,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD
        ES_EVENT_TYPE_NOTIFY_OD_GROUP_ADD,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED
        ES_EVENT_TYPE_NOTIFY_CS_INVALIDATED,
#endif
#ifdef ES_EVENT_TYPE_AUTH_SETUID
        ES_EVENT_TYPE_AUTH_SETUID,
#endif
#ifdef ES_EVENT_TYPE_AUTH_SETGID
        ES_EVENT_TYPE_AUTH_SETGID,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_SETUID
        ES_EVENT_TYPE_NOTIFY_SETUID,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_SETGID
        ES_EVENT_TYPE_NOTIFY_SETGID,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_TCC_MODIFY
        ES_EVENT_TYPE_NOTIFY_TCC_MODIFY,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE
        ES_EVENT_TYPE_NOTIFY_GATEKEEPER_USER_OVERRIDE,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED
        ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED
        ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH
        ES_EVENT_TYPE_NOTIFY_SCREENSHARING_ATTACH,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH
        ES_EVENT_TYPE_NOTIFY_SCREENSHARING_DETACH,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_OD_USER_ADD
        ES_EVENT_TYPE_NOTIFY_OD_USER_ADD,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_OD_USER_REMOVE
        ES_EVENT_TYPE_NOTIFY_OD_USER_REMOVE,
#endif
#ifdef ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE
        ES_EVENT_TYPE_NOTIFY_OD_GROUP_REMOVE,
#endif
    };
    es_return_t ret = es_subscribe(_esf_client, evts, sizeof(evts)/sizeof(evts[0]));
    return (ret == ES_RETURN_SUCCESS) ? 0 : -1;
}

static int esf_unsubscribe_all(void) {
    if (_esf_client == NULL) return -1;
    es_return_t ret = es_unsubscribe_all(_esf_client);
    return (ret == ES_RETURN_SUCCESS) ? 0 : -1;
}

// esf_mute_path_notify mutes the given path prefix only for NOTIFY-shaped
// event types. AUTH events from the same paths still flow through to the
// handler so the agent retains policy-relevant visibility (e.g. it sees an
// exec auth request from /usr/libexec even when it skips emitting the
// associated NOTIFY_EXEC telemetry). On macOS 12+ this is enforced in the
// kernel via es_mute_path_events; on older releases the kernel-side fast
// path is unavailable and Go-side gating in shouldMuteNotify() is the only
// suppressor (the mute call below will simply return -1 there).
static int esf_mute_path_notify(const char *path) {
    if (_esf_client == NULL) return -1;
#if defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && \
    __MAC_OS_X_VERSION_MAX_ALLOWED >= 120000
    es_event_type_t notify_only[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_WRITE,
        ES_EVENT_TYPE_NOTIFY_UNLINK,
        ES_EVENT_TYPE_NOTIFY_TRUNCATE,
        ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA,
        ES_EVENT_TYPE_NOTIFY_FCNTL,
        ES_EVENT_TYPE_NOTIFY_RENAME,
        ES_EVENT_TYPE_NOTIFY_SIGNAL,
        ES_EVENT_TYPE_NOTIFY_MMAP,
        ES_EVENT_TYPE_NOTIFY_MPROTECT,
        ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE,
    };
    es_return_t ret = es_mute_path_events(_esf_client, path,
        ES_MUTE_PATH_TYPE_PREFIX, notify_only,
        sizeof(notify_only)/sizeof(notify_only[0]));
    return (ret == ES_RETURN_SUCCESS) ? 0 : -1;
#else
    (void)path;
    return -1;
#endif
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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
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

// DefaultESFMutePathPrefixes returns a copy of built-in ESF path mute prefixes.
func DefaultESFMutePathPrefixes() []string {
	out := make([]string, len(defaultMutePaths))
	copy(out, defaultMutePaths)
	return out
}

const (
	defaultAuthCacheTTL = 5 * time.Minute
	defaultAuthTimeout  = 750 * time.Millisecond
	esfNotifyQueueDepth = 4096
)

// ESFNotifyPayload carries a notify/auth-adjacent ES event off the ESF callback thread.
type ESFNotifyPayload struct {
	EventType    int
	PID          int
	PPID         int
	UID          int
	GID          int
	Comm         string
	Path         string
	Args         string
	Env          string
	SignalNumber int
	Detail       string
}

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

// trustedTeamEntry caches a path → "is this signed by a trusted team
// id?" verdict for a bounded TTL. Stored positive (trusted=true) and
// negative (trusted=false) so an unsigned binary is not re-evaluated on
// every AUTH event in a fork-bomb.
type trustedTeamEntry struct {
	trusted   bool
	expiresAt time.Time
}

const trustedTeamCacheTTL = 60 * time.Second
const trustedTeamCacheMax = 4096

// isTrustedTeamPath returns true when the binary at execPath is signed
// by one of the team identifiers in d.policy.TrustedTeamIDs. The
// verdict is cached for trustedTeamCacheTTL to avoid invoking the
// signing-info pipeline on every AUTH event for hot paths (e.g.
// /System/Library/Frameworks/...). Returns false for unsigned, ad-hoc
// signed, or unknown-team binaries — those flow through full analysis.
func (d *ESFDriver) isTrustedTeamPath(execPath string) bool {
	d.mu.RLock()
	trusted := d.policy.TrustedTeamIDs
	d.mu.RUnlock()
	if len(trusted) == 0 || execPath == "" {
		return false
	}

	now := time.Now()
	d.trustedTeamMu.RLock()
	e, ok := d.trustedTeamCache[execPath]
	d.trustedTeamMu.RUnlock()
	if ok && now.Before(e.expiresAt) {
		return e.trusted
	}

	teamID, _, _, valid := esfExecSigningInfoFull(execPath)
	verdict := false
	// P1-11 hardening: only auto-allow when the signature actually
	// verifies. A tampered binary that retains the embedded team
	// identifier must not be silently fast-pathed.
	if teamID != "" && valid {
		for _, t := range trusted {
			if teamID == t {
				verdict = true
				break
			}
		}
	}

	d.trustedTeamMu.Lock()
	if d.trustedTeamCache == nil {
		d.trustedTeamCache = make(map[string]trustedTeamEntry)
	}
	if len(d.trustedTeamCache) >= trustedTeamCacheMax {
		// Evict ~1/4 of expired/old entries to bound memory. Simple
		// linear scan is fine at 4 KiB-class map sizes.
		evicted := 0
		for k, v := range d.trustedTeamCache {
			if now.After(v.expiresAt) || evicted < trustedTeamCacheMax/4 {
				delete(d.trustedTeamCache, k)
				evicted++
				if evicted >= trustedTeamCacheMax/4 {
					break
				}
			}
		}
	}
	d.trustedTeamCache[execPath] = trustedTeamEntry{
		trusted:   verdict,
		expiresAt: now.Add(trustedTeamCacheTTL),
	}
	d.trustedTeamMu.Unlock()
	return verdict
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
	esfSeq    atomic.Uint64

	authCacheHits atomic.Uint64
	authTimeouts  atomic.Uint64
	authDenials   atomic.Uint64

	// trustedTeamCache stores positive AND negative results of a
	// path's team-id lookup. We cap entries so a fork-bombing
	// adversary cannot blow the map up, and TTL them so a binary
	// that gets re-signed eventually re-evaluates.
	trustedTeamMu     sync.RWMutex
	trustedTeamCache  map[string]trustedTeamEntry

	notifyCh               chan ESFNotifyPayload
	notifyDropped          atomic.Uint64
	authBudgetSumMs        atomic.Uint64
	authBudgetCount        atomic.Uint64
	authDeadlineViolations atomic.Uint64
	authBudgetDenyLow      atomic.Uint64

	authSampleMu   sync.Mutex
	authSamples    []uint32
	authSampleRing int // next slot when ring is full (1024)

	// mutePrefixes is the userspace mirror of the ESF NOTIFY-event mute
	// list. AUTH callbacks always run; only NOTIFY emission is suppressed
	// for matching paths. See applyMutePaths and shouldMuteNotify.
	mutePrefixMu sync.RWMutex
	mutePrefixes []string
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
		events.EventPtrace,
	}
}

// Start creates the ESF client, subscribes to events, and begins collection.
func (d *ESFDriver) Start(ctx context.Context, buf *RingBuffer) error {
	if d.running.Load() {
		return fmt.Errorf("esf driver already running")
	}

	d.buf = buf

	var child context.Context
	child, d.cancel = context.WithCancel(ctx)

	d.notifyCh = make(chan ESFNotifyPayload, esfNotifyQueueDepth)
	d.wg.Add(2)
	go d.cache.cleanupLoop(child, &d.wg)
	go d.notifyWorker(child)

	if !globalESF.CompareAndSwap(nil, d) {
		d.cancel()
		d.wg.Wait()
		d.notifyCh = nil
		return fmt.Errorf("another esf driver instance is already active")
	}

	result := int(C.esf_create_client())
	if result != 0 {
		globalESF.Store(nil)
		d.cancel()
		d.wg.Wait()
		d.notifyCh = nil
		return d.clientCreateError(result)
	}

	if ret := C.esf_subscribe_all(); ret != 0 {
		C.esf_delete_client()
		globalESF.Store(nil)
		d.cancel()
		d.wg.Wait()
		d.notifyCh = nil
		return fmt.Errorf("failed to subscribe to ESF events")
	}

	d.mu.RLock()
	mutePaths := d.policy.MutePaths
	if len(mutePaths) == 0 {
		mutePaths = defaultMutePaths
	}
	d.mu.RUnlock()

	d.applyMutePaths(mutePaths)

	d.startTime = time.Now()
	d.running.Store(true)
	_ = d.emitFeatureStatusEvent()

	return nil
}

func (d *ESFDriver) notifyWorker(ctx context.Context) {
	defer d.wg.Done()
	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case p := <-d.notifyCh:
					d.dispatchNotify(&p)
				default:
					return
				}
			}
		case p := <-d.notifyCh:
			d.dispatchNotify(&p)
		}
	}
}

// dispatchNotify gates NOTIFY telemetry emission on the per-event-type mute
// list. On macOS 12+ the same prefixes are also muted kernel-side via
// es_mute_path_events so this is a fast no-op; on older releases this is
// the only path that suppresses NOTIFY telemetry for trusted system
// prefixes. AUTH messages are not routed through notifyCh and are never
// affected by this gate.
func (d *ESFDriver) dispatchNotify(p *ESFNotifyPayload) {
	if d.shouldMuteNotify(p.Path) {
		// Mark drop in telemetry counters so muted-noise volume is
		// observable in monitoring_health.json.
		d.notifyDropped.Add(1)
		return
	}
	processESFNotifyPayload(d, p)
}

func (d *ESFDriver) observeAuthBudgetMs(ms int) {
	if ms < 0 {
		return
	}
	d.authBudgetSumMs.Add(uint64(ms))
	d.authBudgetCount.Add(1)
	const capSamples = 1024
	v := uint32(ms)
	if ms > 0x7fffffff {
		v = 0x7fffffff
	}
	d.authSampleMu.Lock()
	if len(d.authSamples) < capSamples {
		d.authSamples = append(d.authSamples, v)
	} else {
		idx := d.authSampleRing % capSamples
		d.authSamples[idx] = v
		d.authSampleRing++
	}
	d.authSampleMu.Unlock()
}

// ESFNotifyIngestMetrics reports notify-path queue telemetry (C2 offload).
func (d *ESFDriver) ESFNotifyIngestMetrics() map[string]any {
	if d == nil {
		return nil
	}
	if d.notifyCh == nil {
		return map[string]any{
			"esf_ingest_queue_depth": 0,
			"esf_ingest_queue_cap":   0,
			"esf_ingest_dropped":     d.notifyDropped.Load(),
		}
	}
	return map[string]any{
		"esf_ingest_queue_depth": len(d.notifyCh),
		"esf_ingest_queue_cap":   cap(d.notifyCh),
		"esf_ingest_dropped":     d.notifyDropped.Load(),
	}
}

func (d *ESFDriver) emitFeatureStatusEvent() error {
	major, minor := detectMacVersion()
	hasBTM := major >= 14
	hasTCCModify := major >= 15
	env := map[string]interface{}{
		"type":           "feature_status",
		"timestamp":      time.Now().UTC(),
		"agent_id":       d.agentID,
		"platform":       "darwin",
		"macos_version":  fmt.Sprintf("%d.%d", major, minor),
		"has_btm":        hasBTM,
		"has_tcc_modify": hasTCCModify,
	}
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return d.buf.Write(b)
}

func detectMacVersion() (int, int) {
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return 0, 0
	}
	parts := strings.Split(strings.TrimSpace(string(out)), ".")
	if len(parts) == 0 {
		return 0, 0
	}
	major, _ := strconv.Atoi(parts[0])
	minor := 0
	if len(parts) > 1 {
		minor, _ = strconv.Atoi(parts[1])
	}
	return major, minor
}

// Stop unsubscribes from all events, deletes the ESF client, and releases resources.
//
// P1-10: es_delete_client is known to deadlock on macOS 14 when the
// client has in-flight AUTH messages without a response. We bound the
// teardown with a 5s timeout — if cleanup does not return in time we
// surface an error to the caller, mark the driver stopped, and let the
// abandoned C-side resources leak rather than hang the process forever.
// The follow-on agent restart path closes the file descriptor on exit
// which forces ESF to drop the dangling client.
func (d *ESFDriver) Stop() error {
	if !d.running.CompareAndSwap(true, false) {
		return nil
	}
	globalESF.Store(nil)
	d.cancel()

	C.esf_unsubscribe_all()

	deleteDone := make(chan struct{})
	go func() {
		C.esf_delete_client()
		close(deleteDone)
	}()

	const esfStopTimeout = 5 * time.Second
	var deleteErr error
	select {
	case <-deleteDone:
	case <-time.After(esfStopTimeout):
		deleteErr = fmt.Errorf("ESF stop timeout after %s (es_delete_client deadlock)", esfStopTimeout)
	}

	waitDone := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(waitDone)
	}()
	select {
	case <-waitDone:
	case <-time.After(esfStopTimeout):
		if deleteErr == nil {
			deleteErr = fmt.Errorf("ESF stop timeout after %s waiting for goroutines", esfStopTimeout)
		}
	}

	d.notifyCh = nil
	return deleteErr
}

// SetPolicy updates the event collection policy. Mute paths are applied to the ESF client.
func (d *ESFDriver) SetPolicy(policy EventPolicy) error {
	d.mu.Lock()
	d.policy = policy
	d.mu.Unlock()

	if d.running.Load() {
		d.applyMutePaths(policy.MutePaths)
		C.esf_clear_cache()
	}
	return nil
}

// applyMutePaths registers each prefix with ESF using NOTIFY-only muting
// (P0-8). Both the kernel-side mute (when available) and the Go-side cache
// of mutePrefixes are updated; AUTH events for these prefixes continue to
// be processed so the agent retains the ability to deny known-bad behavior
// even within otherwise-trusted system directories.
func (d *ESFDriver) applyMutePaths(paths []string) {
	for _, p := range paths {
		cs := C.CString(p)
		C.esf_mute_path_notify(cs)
		C.free(unsafe.Pointer(cs))
	}
	d.mutePrefixMu.Lock()
	d.mutePrefixes = append(d.mutePrefixes[:0], paths...)
	d.mutePrefixMu.Unlock()
}

// shouldMuteNotify reports whether NOTIFY-shaped telemetry for the given
// path should be suppressed. Used as a userspace fallback on macOS <12
// (where the kernel-side per-event mute is unavailable) and as defense in
// depth on newer releases.
//
// P2-5: also mute NOTIFY emission for processes signed by a trusted
// team identifier. This complements the P1-9 AUTH fast path — AUTH
// auto-allows, NOTIFY suppresses telemetry — so trusted Apple/EDR
// binaries do not generate noise in the event stream while
// adhoc-signed / unsigned / unverifiable binaries continue to emit
// for security visibility.
func (d *ESFDriver) shouldMuteNotify(path string) bool {
	if path == "" {
		return false
	}
	d.mutePrefixMu.RLock()
	for _, prefix := range d.mutePrefixes {
		if strings.HasPrefix(path, prefix) {
			d.mutePrefixMu.RUnlock()
			return true
		}
	}
	d.mutePrefixMu.RUnlock()
	if d.isTrustedTeamPath(path) {
		return true
	}
	return false
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

// AuthHealth exposes authorization callback behavior for monitoring_health.json.
func (d *ESFDriver) AuthHealth() map[string]any {
	if d == nil {
		return nil
	}
	m := map[string]any{
		"auth_timeout_ms":        int(d.authTimeout / time.Millisecond),
		"auth_cache_hits":        d.authCacheHits.Load(),
		"auth_timeout_fallbacks": d.authTimeouts.Load(),
		"auth_denials":           d.authDenials.Load(),
	}
	if c := d.authBudgetCount.Load(); c > 0 {
		m["auth_deadline_avg_ms"] = int(d.authBudgetSumMs.Load() / c)
	}
	m["auth_deadline_violations"] = d.authDeadlineViolations.Load()

	d.authSampleMu.Lock()
	samples := append([]uint32(nil), d.authSamples...)
	d.authSampleMu.Unlock()
	if len(samples) > 0 {
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		m["auth_deadline_p50_ms"] = int(samples[len(samples)/2])
		m["auth_deadline_p95_ms"] = sortedUint32Percentile(samples, 95)
	}
	m["auth_budget_deny_low_deadline"] = d.authBudgetDenyLow.Load()
	return m
}

// mapESFEventType maps raw ESF event type integers to internal EventType
// categories. Each raw type is listed explicitly so future ESF additions
// fall into the default branch and surface as needing manual handling.
//
// The split also gives image-load (NOTIFY_MMAP / NOTIFY_KEXTLOAD) its own
// EventModule category, separate from generic memory mapping (MPROTECT) and
// auth-time pre-execution mmap denials.
func mapESFEventType(raw int) events.EventType {
	switch raw {
	// Process lifecycle.
	case int(C.ES_EVENT_TYPE_AUTH_EXEC),
		int(C.ES_EVENT_TYPE_NOTIFY_EXEC),
		int(C.ES_EVENT_TYPE_NOTIFY_FORK),
		int(C.ES_EVENT_TYPE_NOTIFY_EXIT),
		int(C.ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE):
		return events.EventProcess

	// File operations.
	case int(C.ES_EVENT_TYPE_AUTH_OPEN),
		int(C.ES_EVENT_TYPE_AUTH_CREATE),
		int(C.ES_EVENT_TYPE_AUTH_RENAME),
		int(C.ES_EVENT_TYPE_AUTH_UNLINK),
		int(C.ES_EVENT_TYPE_AUTH_COPYFILE),
		int(C.ES_EVENT_TYPE_NOTIFY_WRITE),
		int(C.ES_EVENT_TYPE_NOTIFY_UNLINK),
		int(C.ES_EVENT_TYPE_NOTIFY_TRUNCATE),
		int(C.ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA),
		int(C.ES_EVENT_TYPE_NOTIFY_FCNTL),
		int(C.ES_EVENT_TYPE_NOTIFY_RENAME):
		return events.EventFile

	// Image / module loads. NOTIFY_MMAP fires for every dylib mmap; we treat
	// it as EventModule so detection rules can scope to image-load only and
	// ignore page-protection changes.
	case int(C.ES_EVENT_TYPE_NOTIFY_MMAP),
		int(C.ES_EVENT_TYPE_AUTH_MMAP),
		int(C.ES_EVENT_TYPE_AUTH_KEXTLOAD):
		return events.EventModule

	// Memory protection changes (no image load implication).
	case int(C.ES_EVENT_TYPE_NOTIFY_MPROTECT):
		return events.EventMemory

	// Cross-process control.
	case int(C.ES_EVENT_TYPE_AUTH_GET_TASK):
		return events.EventPtrace
	case int(C.ES_EVENT_TYPE_AUTH_SIGNAL),
		int(C.ES_EVENT_TYPE_NOTIFY_SIGNAL):
		return events.EventSignal

	// Mount.
	case int(C.ES_EVENT_TYPE_AUTH_MOUNT):
		return events.EventMount

	default:
		return events.EventProcess
	}
}

func esfIsSignalType(raw int) bool {
	switch raw {
	case int(C.ES_EVENT_TYPE_AUTH_SIGNAL), int(C.ES_EVENT_TYPE_NOTIFY_SIGNAL):
		return true
	default:
		return false
	}
}

// esfOperationName returns the lowercase operation name for a raw ESF event
// type. It is used by the userland mapper to populate FileEvent.Operation
// and ProcessEvent.ProcessName so detection rules see explicit op names
// rather than a generic category alone.
func esfOperationName(raw int) string {
	switch raw {
	case int(C.ES_EVENT_TYPE_AUTH_EXEC), int(C.ES_EVENT_TYPE_NOTIFY_EXEC):
		return "exec"
	case int(C.ES_EVENT_TYPE_NOTIFY_FORK):
		return "fork"
	case int(C.ES_EVENT_TYPE_NOTIFY_EXIT):
		return "exit"
	case int(C.ES_EVENT_TYPE_NOTIFY_REMOTE_THREAD_CREATE):
		return "remote_thread_create"
	case int(C.ES_EVENT_TYPE_AUTH_OPEN):
		return "open"
	case int(C.ES_EVENT_TYPE_AUTH_CREATE):
		return "create"
	case int(C.ES_EVENT_TYPE_AUTH_RENAME), int(C.ES_EVENT_TYPE_NOTIFY_RENAME):
		return "rename"
	case int(C.ES_EVENT_TYPE_AUTH_UNLINK), int(C.ES_EVENT_TYPE_NOTIFY_UNLINK):
		return "unlink"
	case int(C.ES_EVENT_TYPE_AUTH_COPYFILE):
		return "copyfile"
	case int(C.ES_EVENT_TYPE_NOTIFY_WRITE):
		return "write"
	case int(C.ES_EVENT_TYPE_NOTIFY_TRUNCATE):
		return "truncate"
	case int(C.ES_EVENT_TYPE_NOTIFY_EXCHANGEDATA):
		return "exchangedata"
	case int(C.ES_EVENT_TYPE_NOTIFY_FCNTL):
		return "fcntl"
	case int(C.ES_EVENT_TYPE_NOTIFY_MMAP), int(C.ES_EVENT_TYPE_AUTH_MMAP):
		return "image_load"
	case int(C.ES_EVENT_TYPE_AUTH_KEXTLOAD):
		return "kextload"
	case int(C.ES_EVENT_TYPE_NOTIFY_MPROTECT):
		return "mprotect"
	case int(C.ES_EVENT_TYPE_AUTH_GET_TASK):
		return "get_task"
	case int(C.ES_EVENT_TYPE_AUTH_SIGNAL), int(C.ES_EVENT_TYPE_NOTIFY_SIGNAL):
		return "signal"
	case int(C.ES_EVENT_TYPE_AUTH_MOUNT):
		return "mount"
	}
	return esfOperationNameFallback(raw)
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
