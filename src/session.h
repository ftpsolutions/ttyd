#ifndef TTYD_SESSION_H
#define TTYD_SESSION_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include <libwebsockets.h>
#include <uv.h>

#include "pty.h"

// client -> server command bytes (same as the legacy WS protocol)
#define INPUT '0'
#define RESIZE_TERMINAL '1'
#define PAUSE '2'
#define RESUME '3'
#define JSON_DATA '{'

// server -> client command bytes
#define OUTPUT '0'
#define SET_WINDOW_TITLE '1'
#define SET_PREFERENCES '2'

#define SID_HEX_LEN 32

// Single queued server->client message, already prefixed with its 4-byte
// big-endian length + command byte. We pre-frame so the /poll writer just
// concatenates buffers.
typedef struct msg_chunk {
  char *data;
  size_t len;
  struct msg_chunk *next;
} msg_chunk;

typedef struct ttyd_session {
  char sid[SID_HEX_LEN + 1];
  bool authenticated;
  int initial_sent;  // counter into initial_cmds in session.c

  char user[30];
  char address[50];
  char path[128];
  char **args;
  int argc;

  pty_process *process;

  msg_chunk *out_head;
  msg_chunk *out_tail;
  size_t out_bytes;
  bool pty_paused_for_backpressure;

  int close_code;  // 0 while alive; 1000/1006 once the pty is gone

  struct lws *poll_wsi;
  uv_timer_t poll_timer;
  bool poll_timer_active;

  uv_timer_t idle_timer;
  bool idle_timer_active;

  bool destroying;

  struct ttyd_session *next;
} ttyd_session;

typedef struct {
  ttyd_session *session;
  bool http_closed;
} session_pty_ctx;

// Lifecycle
ttyd_session *session_create(const char *address, const char *path);
ttyd_session *session_find(const char *sid);
void session_destroy(ttyd_session *s);
void session_destroy_all(void);

// Spawn the child pty for this session.
bool session_spawn(ttyd_session *s, uint16_t columns, uint16_t rows);

// Enqueue a server->client message; wakes the parked poll if any.
void session_enqueue(ttyd_session *s, char cmd, const void *data, size_t len);

// Handle an /input POST body (same framing as the old WS frames).
// Returns true on success.
bool session_handle_input(ttyd_session *s, const char *buf, size_t len);

// Park or wake long-poll.
void session_park_poll(ttyd_session *s, struct lws *wsi);
void session_clear_poll(ttyd_session *s, struct lws *wsi);

// Called by the http WRITEABLE callback to drain queued messages into the
// response body. Returns a newly-allocated buffer (caller frees) and size.
// If *close_out is non-zero after the call, the session has exited and
// the client should stop polling (HTTP header X-Ttyd-Close carries code).
void session_drain(ttyd_session *s, char **out, size_t *out_len, int *close_out);

// Bump the idle timer (client activity).
void session_touch(ttyd_session *s);

#endif  // TTYD_SESSION_H
