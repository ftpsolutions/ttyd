#include <libwebsockets.h>
#include <stdbool.h>
#include <uv.h>

#include "pty.h"

// url paths
struct endpoints {
  char *index;
  char *token;
  char *session;
  char *poll;
  char *input;
  char *close;
  char *parent;
};

extern volatile bool force_exit;
extern struct lws_context *context;
extern struct server *server;
extern struct endpoints endpoints;

enum http_handler_kind {
  HH_NONE = 0,
  HH_STATIC,   // serve pre-built buffer then complete
  HH_POLL,     // long-poll: body written when session has data
  HH_INPUT,    // accept POST body, dispatch to session, respond 204
  HH_SESSION,  // create new session from POST body, respond {"sid":...}
  HH_CLOSE,    // destroy session, respond 204
};

struct pss_http {
  char path[128];
  char query[256];

  enum http_handler_kind kind;
  char sid[64];

  // response body staging (for HH_STATIC and once HH_SESSION completes)
  char *buffer;
  char *ptr;
  size_t len;
  bool owns_buffer;

  // accumulated POST body
  char *body;
  size_t body_len;
  size_t body_cap;
};

struct server {
  int client_count;        // client count
  char *prefs_json;        // client preferences
  char *credential;        // encoded basic auth credential
  char *auth_header;       // header name used for auth proxy
  char *index;             // custom index.html
  char *command;           // full command line
  char **argv;             // command with arguments
  int argc;                // command + arguments count
  char *cwd;               // working directory
  int sig_code;            // close signal
  char sig_name[20];       // human readable signal string
  bool url_arg;            // allow client to send cli arguments in URL
  bool writable;           // whether clients can write to the TTY
  int max_clients;         // maximum concurrent sessions (0 = no limit)
  bool once;               // accept one session, exit after it ends
  bool exit_no_conn;       // exit when all sessions are closed
  char socket_path[255];   // UNIX domain socket path
  char terminal_type[30];  // terminal type to report

  uv_loop_t *loop;         // the libuv event loop
};
