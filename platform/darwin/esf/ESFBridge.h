/* SPDX-License-Identifier: Apache-2.0 */
/*
 * C bridge header for macOS Endpoint Security Framework.
 * Provides a thin C interface consumed by Go via cgo, isolating the
 * Objective-C/Swift ESF API behind a stable ABI boundary.
 */
#ifndef ESF_BRIDGE_H
#define ESF_BRIDGE_H

#include <stdint.h>

typedef enum {
	ESF_EVENT_AUTH_EXEC      = 0,
	ESF_EVENT_AUTH_OPEN      = 1,
	ESF_EVENT_AUTH_CREATE    = 2,
	ESF_EVENT_AUTH_RENAME    = 3,
	ESF_EVENT_AUTH_UNLINK    = 4,
	ESF_EVENT_AUTH_KEXTLOAD  = 5,
	ESF_EVENT_AUTH_MOUNT     = 6,
	ESF_EVENT_AUTH_SIGNAL    = 7,
	ESF_EVENT_NOTIFY_FORK    = 100,
	ESF_EVENT_NOTIFY_EXIT    = 101,
	ESF_EVENT_NOTIFY_WRITE   = 102,
	ESF_EVENT_NOTIFY_MMAP    = 103,
	ESF_EVENT_NOTIFY_MPROTECT = 104,
} esf_event_type_t;

typedef struct {
	esf_event_type_t type;
	int32_t  pid;
	int32_t  ppid;
	uint32_t uid;
	uint32_t gid;
	char     comm[16];
	char     path[1024];
	char     args[2048];
	int32_t  exit_code;
	uint32_t child_pid;
} esf_event_t;

/* Initialize ESF client. Returns 0 on success, negative errno on failure. */
int esf_init(void);

/* Start subscribing to all configured event types. */
int esf_start(void);

/* Stop event delivery and release the ESF client. */
void esf_stop(void);

/* Add a path to the mute set so events from that binary are suppressed. */
int esf_mute_path(const char *path);

/* Respond to an AUTH event. allow=1 permits the operation, allow=0 denies. */
void esf_auth_respond(uint64_t msg_id, int allow);

#endif /* ESF_BRIDGE_H */
