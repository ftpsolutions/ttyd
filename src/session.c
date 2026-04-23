#include "session.h"

#include <errno.h>
#include <json.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "server.h"
#include "utils.h"

// Long-poll hold timeout (ms). After this the server replies with a
// (possibly empty) body so intermediaries don't kill the connection.
#define POLL_HOLD_MS 25000

// If no poll or input is seen for this long, the session is torn down.
#define IDLE_TIMEOUT_MS 120000

// Server-side output buffer highwater: pause the pty if we exceed this
// before the client drains it.
#define OUTPUT_HIGHWATER (1u << 20)  // 1 MiB

static ttyd_session *sessions_head = NULL;

// Order matches the legacy WS protocol.
static const char initial_cmds[] = {SET_WINDOW_TITLE, SET_PREFERENCES};

static void session_kick_idle(ttyd_session *s);
static void session_enqueue_initials(ttyd_session *s);
static void process_read_cb(pty_process *process, pty_buf_t *buf, bool eof);
static void process_exit_cb(pty_process *process);

static void hex_encode(const uint8_t *in, size_t len, char *out) {
  static const char hex[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[i * 2] = hex[(in[i] >> 4) & 0xf];
    out[i * 2 + 1] = hex[in[i] & 0xf];
  }
  out[len * 2] = '\0';
}

static void gen_sid(char *out) {
  uint8_t bytes[SID_HEX_LEN / 2];
  if (lws_get_random(context, bytes, sizeof(bytes)) != sizeof(bytes)) {
    // fall back to something — this should basically never fire
    for (size_t i = 0; i < sizeof(bytes); i++) bytes[i] = (uint8_t)rand();
  }
  hex_encode(bytes, sizeof(bytes), out);
}

static void write_be32(char *p, uint32_t v) {
  p[0] = (char)((v >> 24) & 0xff);
  p[1] = (char)((v >> 16) & 0xff);
  p[2] = (char)((v >> 8) & 0xff);
  p[3] = (char)(v & 0xff);
}

ttyd_session *session_find(const char *sid) {
  if (sid == NULL) return NULL;
  for (ttyd_session *s = sessions_head; s != NULL; s = s->next) {
    if (strcmp(s->sid, sid) == 0) return s;
  }
  return NULL;
}

static void idle_timer_cb(uv_timer_t *t) {
  ttyd_session *s = (ttyd_session *)t->data;
  lwsl_notice("session %s idle timeout, destroying\n", s->sid);
  session_destroy(s);
}

static void poll_timer_cb(uv_timer_t *t) {
  ttyd_session *s = (ttyd_session *)t->data;
  s->poll_timer_active = false;
  if (s->poll_wsi != NULL) {
    // Wake the parked poll; drain path will notice empty queue and reply 200
    // with no body so the client re-polls.
    lws_callback_on_writable(s->poll_wsi);
  }
}

ttyd_session *session_create(const char *address, const char *path) {
  ttyd_session *s = xmalloc(sizeof(*s));
  memset(s, 0, sizeof(*s));
  gen_sid(s->sid);

  if (address != NULL) snprintf(s->address, sizeof(s->address), "%s", address);
  if (path != NULL) snprintf(s->path, sizeof(s->path), "%s", path);

  uv_timer_init(server->loop, &s->poll_timer);
  s->poll_timer.data = s;

  uv_timer_init(server->loop, &s->idle_timer);
  s->idle_timer.data = s;

  session_kick_idle(s);

  // Enqueue the two initial messages so the first /poll immediately returns
  // title + prefs, matching the legacy WS startup.
  session_enqueue_initials(s);

  s->next = sessions_head;
  sessions_head = s;

  server->client_count++;
  lwsl_notice("HTTP session %s created for %s, clients: %d\n", s->sid, s->address, server->client_count);
  return s;
}

// Separate "closer" handle counter: we need to wait for both embedded timers
// to finish closing before freeing the session that embeds them.
typedef struct {
  ttyd_session *s;
  int pending;
} session_closer;

static void session_handle_closed(uv_handle_t *h) {
  session_closer *c = (session_closer *)h->data;
  if (--c->pending > 0) return;

  ttyd_session *s = c->s;
  free(c);

  if (s->args != NULL) {
    for (int i = 0; i < s->argc; i++) free(s->args[i]);
    free(s->args);
  }
  msg_chunk *m = s->out_head;
  while (m != NULL) {
    msg_chunk *n = m->next;
    free(m->data);
    free(m);
    m = n;
  }
  free(s);
}

void session_destroy(ttyd_session *s) {
  if (s == NULL || s->destroying) return;
  s->destroying = true;

  // Remove from global list.
  if (sessions_head == s) {
    sessions_head = s->next;
  } else {
    for (ttyd_session *p = sessions_head; p != NULL; p = p->next) {
      if (p->next == s) {
        p->next = s->next;
        break;
      }
    }
  }

  if (s->poll_timer_active) {
    uv_timer_stop(&s->poll_timer);
    s->poll_timer_active = false;
  }
  if (s->idle_timer_active) {
    uv_timer_stop(&s->idle_timer);
    s->idle_timer_active = false;
  }

  // If a poll is parked, wake it so it sends an empty/close reply and
  // releases the wsi.
  if (s->poll_wsi != NULL) {
    struct lws *w = s->poll_wsi;
    // mark session as closed so drain emits the close header
    if (s->close_code == 0) s->close_code = 1006;
    lws_callback_on_writable(w);
    s->poll_wsi = NULL;
  }

  // Kill the pty if still running. The exit_cb will run later and see
  // session_dead via its ctx; it frees the ctx itself.
  bool pty_was_alive = false;
  if (s->process != NULL) {
    session_pty_ctx *ctx = (session_pty_ctx *)s->process->ctx;
    if (ctx != NULL) ctx->session = NULL;  // orphan
    if (process_running(s->process)) {
      pty_pause(s->process);
      lwsl_notice("killing process, pid: %d\n", s->process->pid);
      pty_kill(s->process, server->sig_code);
      pty_was_alive = true;
    }
    s->process = NULL;
  }

  server->client_count--;
  lwsl_notice("session %s destroyed, clients: %d\n", s->sid, server->client_count);

  if ((server->once || server->exit_no_conn) && server->client_count == 0) {
    lwsl_notice("exiting due to the --once/--exit-no-conn option.\n");
    lws_cancel_service(context);
    force_exit = true;
    // If the pty had already exited there's no exit_cb coming to exit(0).
    if (!pty_was_alive) uv_stop(server->loop);
  }

  session_closer *c = xmalloc(sizeof(*c));
  c->s = s;
  c->pending = 2;
  s->poll_timer.data = c;
  s->idle_timer.data = c;
  uv_close((uv_handle_t *)&s->poll_timer, session_handle_closed);
  uv_close((uv_handle_t *)&s->idle_timer, session_handle_closed);
}

void session_destroy_all(void) {
  while (sessions_head != NULL) session_destroy(sessions_head);
}

static void session_kick_idle(ttyd_session *s) {
  uv_timer_start(&s->idle_timer, idle_timer_cb, IDLE_TIMEOUT_MS, 0);
  s->idle_timer_active = true;
}

void session_touch(ttyd_session *s) { session_kick_idle(s); }

static void append_chunk(ttyd_session *s, msg_chunk *m) {
  m->next = NULL;
  if (s->out_tail == NULL) {
    s->out_head = s->out_tail = m;
  } else {
    s->out_tail->next = m;
    s->out_tail = m;
  }
  s->out_bytes += m->len;
}

void session_enqueue(ttyd_session *s, char cmd, const void *data, size_t len) {
  if (s == NULL || s->destroying) return;

  size_t payload_len = 1 + len;  // cmd + data
  msg_chunk *m = xmalloc(sizeof(*m));
  m->len = 4 + payload_len;
  m->data = xmalloc(m->len);
  write_be32(m->data, (uint32_t)payload_len);
  m->data[4] = cmd;
  if (len > 0 && data != NULL) memcpy(m->data + 5, data, len);
  append_chunk(s, m);

  // Server-side backpressure: if we've buffered past highwater and the pty
  // is still streaming, pause it until a poll drains us.
  if (s->out_bytes > OUTPUT_HIGHWATER && !s->pty_paused_for_backpressure && s->process != NULL) {
    pty_pause(s->process);
    s->pty_paused_for_backpressure = true;
  }

  if (s->poll_wsi != NULL) {
    lws_callback_on_writable(s->poll_wsi);
  }
}

static void session_enqueue_initials(ttyd_session *s) {
  char hostname[128];
  gethostname(hostname, sizeof(hostname) - 1);
  hostname[sizeof(hostname) - 1] = '\0';

  for (size_t i = 0; i < sizeof(initial_cmds); i++) {
    char cmd = initial_cmds[i];
    char buf[4096];
    int n = 0;
    switch (cmd) {
      case SET_WINDOW_TITLE:
        n = snprintf(buf, sizeof(buf), "%s (%s)", server->command, hostname);
        break;
      case SET_PREFERENCES:
        n = snprintf(buf, sizeof(buf), "%s", server->prefs_json);
        break;
      default:
        break;
    }
    if (n > 0) session_enqueue(s, cmd, buf, (size_t)n);
  }
}

void session_drain(ttyd_session *s, char **out, size_t *out_len, int *close_out) {
  *out = NULL;
  *out_len = 0;
  *close_out = s->close_code;

  if (s->out_head == NULL) {
    // Resume pty if we had paused for server-side backpressure and queue is now empty.
    if (s->pty_paused_for_backpressure && s->process != NULL) {
      pty_resume(s->process);
      s->pty_paused_for_backpressure = false;
    }
    return;
  }

  char *buf = xmalloc(s->out_bytes);
  size_t off = 0;
  msg_chunk *m = s->out_head;
  while (m != NULL) {
    memcpy(buf + off, m->data, m->len);
    off += m->len;
    msg_chunk *n = m->next;
    free(m->data);
    free(m);
    m = n;
  }
  s->out_head = s->out_tail = NULL;
  s->out_bytes = 0;

  *out = buf;
  *out_len = off;

  if (s->pty_paused_for_backpressure && s->process != NULL) {
    pty_resume(s->process);
    s->pty_paused_for_backpressure = false;
  }
}

void session_park_poll(ttyd_session *s, struct lws *wsi) {
  // If a previous poll is still parked (shouldn't normally happen), wake it
  // so it flushes/completes, then take over.
  if (s->poll_wsi != NULL && s->poll_wsi != wsi) {
    struct lws *prev = s->poll_wsi;
    s->poll_wsi = NULL;
    lws_callback_on_writable(prev);
  }
  s->poll_wsi = wsi;

  // Disable lws's own per-wsi timeout while we hold the connection.
  lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);

  if (s->poll_timer_active) uv_timer_stop(&s->poll_timer);
  uv_timer_start(&s->poll_timer, poll_timer_cb, POLL_HOLD_MS, 0);
  s->poll_timer_active = true;

  session_kick_idle(s);

  // If we already have queued output, wake immediately.
  if (s->out_head != NULL || s->close_code != 0) {
    lws_callback_on_writable(wsi);
  }
}

void session_clear_poll(ttyd_session *s, struct lws *wsi) {
  if (s->poll_wsi == wsi) s->poll_wsi = NULL;
  if (s->poll_timer_active) {
    uv_timer_stop(&s->poll_timer);
    s->poll_timer_active = false;
  }
}

static int parse_size(const char *buf, size_t len, uint16_t *cols, uint16_t *rows) {
  json_tokener *tok = json_tokener_new();
  json_object *obj = json_tokener_parse_ex(tok, buf, (int)len);
  int found = 0;
  if (obj != NULL) {
    struct json_object *o = NULL;
    if (json_object_object_get_ex(obj, "columns", &o)) {
      *cols = (uint16_t)json_object_get_int(o);
      found++;
    }
    if (json_object_object_get_ex(obj, "rows", &o)) {
      *rows = (uint16_t)json_object_get_int(o);
      found++;
    }
    json_object_put(obj);
  }
  json_tokener_free(tok);
  return found;
}

static char **build_args(ttyd_session *s) {
  int n = 0;
  char **argv = xmalloc((server->argc + s->argc + 1) * sizeof(char *));
  for (int i = 0; i < server->argc; i++) argv[n++] = server->argv[i];
  for (int i = 0; i < s->argc; i++) argv[n++] = s->args[i];
  argv[n] = NULL;
  return argv;
}

static char **build_env(ttyd_session *s) {
  int i = 0, n = 2;
  char **envp = xmalloc(n * sizeof(char *));
  envp[i] = xmalloc(36);
  snprintf(envp[i], 36, "TERM=%s", server->terminal_type);
  i++;
  if (strlen(s->user) > 0) {
    envp = xrealloc(envp, (++n) * sizeof(char *));
    envp[i] = xmalloc(40);
    snprintf(envp[i], 40, "TTYD_USER=%s", s->user);
    i++;
  }
  envp[i] = NULL;
  return envp;
}

bool session_spawn(ttyd_session *s, uint16_t columns, uint16_t rows) {
  if (s->process != NULL) return true;

  session_pty_ctx *ctx = xmalloc(sizeof(*ctx));
  ctx->session = s;
  ctx->http_closed = false;

  pty_process *process = process_init((void *)ctx, server->loop, build_args(s), build_env(s));
  if (server->cwd != NULL) process->cwd = strdup(server->cwd);
  if (columns > 0) process->columns = columns;
  if (rows > 0) process->rows = rows;
  if (pty_spawn(process, process_read_cb, process_exit_cb) != 0) {
    lwsl_err("pty_spawn: %d (%s)\n", errno, strerror(errno));
    free(ctx);
    process_free(process);
    return false;
  }
  lwsl_notice("started process, pid: %d\n", process->pid);
  s->process = process;
  pty_resume(process);
  return true;
}

static void process_read_cb(pty_process *process, pty_buf_t *buf, bool eof) {
  session_pty_ctx *ctx = (session_pty_ctx *)process->ctx;
  if (ctx->session == NULL || ctx->http_closed) {
    pty_buf_free(buf);
    return;
  }
  ttyd_session *s = ctx->session;
  if (eof && !process_running(process)) {
    if (s->close_code == 0) s->close_code = process->exit_code == 0 ? 1000 : 1006;
    if (s->poll_wsi != NULL) lws_callback_on_writable(s->poll_wsi);
  } else if (buf != NULL) {
    session_enqueue(s, OUTPUT, buf->base, buf->len);
    pty_buf_free(buf);
    // pty.c read_cb self-stops after each chunk; resume unless we paused
    // ourselves for server-side backpressure.
    if (!s->pty_paused_for_backpressure) pty_resume(process);
  }
}

static void process_exit_cb(pty_process *process) {
  session_pty_ctx *ctx = (session_pty_ctx *)process->ctx;
  if (ctx->session == NULL) {
    lwsl_notice("process killed with signal %d, pid: %d (orphan)\n", process->exit_signal, process->pid);
    free(ctx);
    if (force_exit) exit(0);
    return;
  }

  lwsl_notice("process exited with code %d, pid: %d\n", process->exit_code, process->pid);
  ttyd_session *s = ctx->session;
  s->process = NULL;
  if (s->close_code == 0) s->close_code = process->exit_code == 0 ? 1000 : 1006;
  if (s->poll_wsi != NULL) lws_callback_on_writable(s->poll_wsi);
  free(ctx);

  if (force_exit) exit(0);
}

bool session_handle_input(ttyd_session *s, const char *buf, size_t len) {
  if (s == NULL || len == 0) return false;
  session_touch(s);

  char command = buf[0];

  // Enforce credential auth for non-JSON_DATA frames, same as legacy WS.
  if (server->credential != NULL && !s->authenticated && command != JSON_DATA) {
    lwsl_warn("input before auth on session %s\n", s->sid);
    return false;
  }

  switch (command) {
    case INPUT:
      if (!server->writable) return true;  // silently drop in readonly mode
      if (s->process == NULL) return false;
      {
        int err = pty_write(s->process, pty_buf_init((char *)buf + 1, len - 1));
        if (err) {
          lwsl_err("uv_write: %s (%s)\n", uv_err_name(err), uv_strerror(err));
          return false;
        }
      }
      break;
    case RESIZE_TERMINAL:
      if (s->process == NULL) break;
      {
        uint16_t cols = s->process->columns, rows = s->process->rows;
        parse_size(buf + 1, len - 1, &cols, &rows);
        s->process->columns = cols;
        s->process->rows = rows;
        pty_resize(s->process);
      }
      break;
    case PAUSE:
      if (s->process != NULL) pty_pause(s->process);
      break;
    case RESUME:
      if (s->process != NULL) pty_resume(s->process);
      break;
    case JSON_DATA: {
      // initial handshake frame: AuthToken + initial size
      uint16_t cols = 0, rows = 0;
      json_tokener *tok = json_tokener_new();
      json_object *obj = json_tokener_parse_ex(tok, buf, (int)len);
      if (obj != NULL) {
        struct json_object *o = NULL;
        if (json_object_object_get_ex(obj, "columns", &o)) cols = (uint16_t)json_object_get_int(o);
        if (json_object_object_get_ex(obj, "rows", &o)) rows = (uint16_t)json_object_get_int(o);
        if (server->credential != NULL) {
          if (json_object_object_get_ex(obj, "AuthToken", &o)) {
            const char *token = json_object_get_string(o);
            if (token != NULL && strcmp(token, server->credential) == 0) {
              s->authenticated = true;
            } else {
              lwsl_warn("auth failed for session %s\n", s->sid);
            }
          }
        } else {
          s->authenticated = true;
        }
        json_object_put(obj);
      }
      json_tokener_free(tok);
      if (server->credential != NULL && !s->authenticated) return false;
      if (!session_spawn(s, cols, rows)) return false;
      break;
    }
    default:
      lwsl_warn("ignored unknown input command: %c\n", command);
      break;
  }
  return true;
}
