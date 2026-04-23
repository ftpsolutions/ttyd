#include <libwebsockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "html.h"
#include "server.h"
#include "session.h"
#include "utils.h"

enum { AUTH_OK, AUTH_FAIL, AUTH_ERROR };

static char *html_cache = NULL;
static size_t html_cache_len = 0;

static int send_unauthorized(struct lws *wsi, unsigned int code, enum lws_token_indexes header) {
  unsigned char buffer[1024 + LWS_PRE], *p, *end;
  p = buffer + LWS_PRE;
  end = p + sizeof(buffer) - LWS_PRE;

  if (lws_add_http_header_status(wsi, code, &p, end) ||
      lws_add_http_header_by_token(wsi, header, (unsigned char *)"Basic realm=\"ttyd\"", 18, &p, end) ||
      lws_add_http_header_content_length(wsi, 0, &p, end) || lws_finalize_http_header(wsi, &p, end) ||
      lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
    return AUTH_FAIL;

  return lws_http_transaction_completed(wsi) ? AUTH_FAIL : AUTH_ERROR;
}

static int check_auth(struct lws *wsi, char *user_out, size_t user_cap) {
  if (server->auth_header != NULL) {
    int n = lws_hdr_custom_copy(wsi, user_out, (int)user_cap, server->auth_header, (int)strlen(server->auth_header));
    if (n > 0) return AUTH_OK;
    return send_unauthorized(wsi, HTTP_STATUS_PROXY_AUTH_REQUIRED, WSI_TOKEN_HTTP_PROXY_AUTHENTICATE);
  }

  if (server->credential != NULL) {
    char buf[256];
    int len = lws_hdr_copy(wsi, buf, sizeof(buf), WSI_TOKEN_HTTP_AUTHORIZATION);
    if (len >= 7 && strstr(buf, "Basic ") && !strcmp(buf + 6, server->credential)) return AUTH_OK;
    return send_unauthorized(wsi, HTTP_STATUS_UNAUTHORIZED, WSI_TOKEN_HTTP_WWW_AUTHENTICATE);
  }

  return AUTH_OK;
}

static bool accept_gzip(struct lws *wsi) {
  char buf[256];
  int len = lws_hdr_copy(wsi, buf, sizeof(buf), WSI_TOKEN_HTTP_ACCEPT_ENCODING);
  return len > 0 && strstr(buf, "gzip") != NULL;
}

static bool uncompress_html(char **output, size_t *output_len) {
  if (html_cache == NULL || html_cache_len == 0) {
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (inflateInit2(&stream, 16 + 15) != Z_OK) return false;

    html_cache_len = index_html_size;
    html_cache = xmalloc(html_cache_len);

    stream.avail_in = index_html_len;
    stream.avail_out = html_cache_len;
    stream.next_in = (void *)index_html;
    stream.next_out = (void *)html_cache;

    int ret = inflate(&stream, Z_SYNC_FLUSH);
    inflateEnd(&stream);
    if (ret != Z_STREAM_END) {
      free(html_cache);
      html_cache = NULL;
      html_cache_len = 0;
      return false;
    }
  }

  *output = html_cache;
  *output_len = html_cache_len;

  return true;
}

static void pss_reset(struct pss_http *pss) {
  if (pss->owns_buffer && pss->buffer != NULL) free(pss->buffer);
  pss->buffer = NULL;
  pss->ptr = NULL;
  pss->len = 0;
  pss->owns_buffer = false;
  if (pss->body != NULL) {
    free(pss->body);
    pss->body = NULL;
  }
  pss->body_len = 0;
  pss->body_cap = 0;
}

static void access_log(struct lws *wsi, const char *path) {
  char rip[50];
  lws_get_peer_simple(lws_get_network_wsi(wsi), rip, sizeof(rip));
  lwsl_notice("HTTP %s - %s\n", path, rip);
}

// Extract "sid" query parameter from stored query string.
static bool extract_sid(const char *query, char *out, size_t cap) {
  if (query == NULL || query[0] == '\0') return false;
  const char *p = query;
  while (*p) {
    const char *amp = strchr(p, '&');
    size_t seg_len = amp ? (size_t)(amp - p) : strlen(p);
    if (seg_len >= 4 && strncmp(p, "sid=", 4) == 0) {
      size_t vlen = seg_len - 4;
      if (vlen >= cap) vlen = cap - 1;
      memcpy(out, p + 4, vlen);
      out[vlen] = '\0';
      return true;
    }
    if (!amp) break;
    p = amp + 1;
  }
  return false;
}

// Copy URL query string from the wsi for later parsing.
static void copy_query(struct lws *wsi, char *out, size_t cap) {
  out[0] = '\0';
  int idx = 0;
  char buf[256];
  int offset = 0;
  while (lws_hdr_copy_fragment(wsi, buf, sizeof(buf), WSI_TOKEN_HTTP_URI_ARGS, idx++) > 0) {
    size_t blen = strlen(buf);
    if ((size_t)offset + blen + 2 >= cap) break;
    if (offset > 0) out[offset++] = '&';
    memcpy(out + offset, buf, blen);
    offset += (int)blen;
    out[offset] = '\0';
  }
}

// Collect args from query string for --url-arg sessions.
static void collect_args_from_query(const char *query, char ***args_out, int *argc_out) {
  *args_out = NULL;
  *argc_out = 0;
  if (query == NULL || query[0] == '\0') return;

  const char *p = query;
  while (*p) {
    const char *amp = strchr(p, '&');
    size_t seg_len = amp ? (size_t)(amp - p) : strlen(p);
    if (seg_len > 4 && strncmp(p, "arg=", 4) == 0) {
      size_t vlen = seg_len - 4;
      char *val = xmalloc(vlen + 1);
      memcpy(val, p + 4, vlen);
      val[vlen] = '\0';
      *args_out = xrealloc(*args_out, sizeof(char *) * (*argc_out + 1));
      (*args_out)[*argc_out] = val;
      (*argc_out)++;
    }
    if (!amp) break;
    p = amp + 1;
  }
}

static int get_method_uri(struct lws *wsi, char *path, size_t pathlen, enum lws_token_indexes *method_token) {
  int n;
  static const enum lws_token_indexes tokens[] = {
      WSI_TOKEN_GET_URI, WSI_TOKEN_POST_URI, WSI_TOKEN_DELETE_URI, WSI_TOKEN_PUT_URI,
  };
  for (size_t i = 0; i < sizeof(tokens) / sizeof(tokens[0]); i++) {
    n = lws_hdr_copy(wsi, path, (int)pathlen, tokens[i]);
    if (n > 0) {
      *method_token = tokens[i];
      return n;
    }
  }
  return -1;
}

static int simple_status(struct lws *wsi, unsigned int code) {
  unsigned char buffer[512 + LWS_PRE], *p = buffer + LWS_PRE, *end = p + sizeof(buffer) - LWS_PRE;
  if (lws_add_http_header_status(wsi, code, &p, end) || lws_add_http_header_content_length(wsi, 0, &p, end) ||
      lws_finalize_http_header(wsi, &p, end) ||
      lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
    return 1;
  return lws_http_transaction_completed(wsi) ? -1 : 0;
}

static int write_response_headers(struct lws *wsi, unsigned int code, const char *content_type, size_t content_len) {
  unsigned char buffer[1024 + LWS_PRE], *p = buffer + LWS_PRE, *end = p + sizeof(buffer) - LWS_PRE;
  if (lws_add_http_header_status(wsi, code, &p, end)) return 1;
  if (content_type != NULL) {
    if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE, (const unsigned char *)content_type,
                                     (int)strlen(content_type), &p, end))
      return 1;
  }
  if (lws_add_http_header_content_length(wsi, (unsigned long)content_len, &p, end)) return 1;
  if (lws_finalize_http_header(wsi, &p, end)) return 1;
  if (lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0) return 1;
  return 0;
}

// Prime pss to stream an owned buffer as HTTP body.
static void prime_body(struct pss_http *pss, char *buf, size_t len, bool own) {
  pss->buffer = buf;
  pss->ptr = buf;
  pss->len = len;
  pss->owns_buffer = own;
}

// Called when a /poll wsi becomes writable: drain session output and reply.
static int poll_writeable(struct lws *wsi, struct pss_http *pss) {
  ttyd_session *s = session_find(pss->sid);
  if (s == NULL) {
    return simple_status(wsi, HTTP_STATUS_GONE);
  }
  session_clear_poll(s, wsi);

  char *buf = NULL;
  size_t buf_len = 0;
  int close_code = 0;
  session_drain(s, &buf, &buf_len, &close_code);

  if (buf_len == 0 && close_code != 0) {
    if (buf != NULL) free(buf);
    session_destroy(s);  // nothing more to read; reap session
    return simple_status(wsi, HTTP_STATUS_GONE);
  }

  if (buf_len == 0) {
    // Timeout with nothing to send: 204 so the client loops.
    return simple_status(wsi, HTTP_STATUS_NO_CONTENT);
  }

  if (write_response_headers(wsi, HTTP_STATUS_OK, "application/octet-stream", buf_len)) {
    free(buf);
    return 1;
  }
  prime_body(pss, buf, buf_len, true);
  lws_callback_on_writable(wsi);
  return 0;
}

// Build and send {"sid":"..."} response for /session; returns 0 on success.
static int respond_session_created(struct lws *wsi, struct pss_http *pss, const char *sid) {
  char body[96];
  int n = snprintf(body, sizeof(body), "{\"sid\":\"%s\"}", sid);
  if (write_response_headers(wsi, HTTP_STATUS_OK, "application/json;charset=utf-8", (size_t)n)) return 1;
  char *buf = xmalloc(n);
  memcpy(buf, body, n);
  prime_body(pss, buf, n, true);
  lws_callback_on_writable(wsi);
  return 0;
}

static int handle_static_index(struct lws *wsi, struct pss_http *pss) {
  unsigned char buffer[1024 + LWS_PRE], *p = buffer + LWS_PRE, *end = p + sizeof(buffer) - LWS_PRE;
  const char *content_type = "text/html";

  if (server->index != NULL) {
    int n = lws_serve_http_file(wsi, server->index, content_type, NULL, 0);
    if (n < 0 || (n > 0 && lws_http_transaction_completed(wsi))) return 1;
    return 0;
  }

  char *output = (char *)index_html;
  size_t output_len = index_html_len;
  if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end) ||
      lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE, (const unsigned char *)content_type, 9, &p, end))
    return 1;

#ifdef LWS_WITH_HTTP_STREAM_COMPRESSION
  if (!uncompress_html(&output, &output_len)) return 1;
#else
  if (accept_gzip(wsi)) {
    if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_ENCODING, (unsigned char *)"gzip", 4, &p, end))
      return 1;
  } else {
    if (!uncompress_html(&output, &output_len)) return 1;
  }
#endif

  if (lws_add_http_header_content_length(wsi, (unsigned long)output_len, &p, end) ||
      lws_finalize_http_header(wsi, &p, end) ||
      lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
    return 1;

  pss->kind = HH_STATIC;
  prime_body(pss, output, output_len, false);
  lws_callback_on_writable(wsi);
  return 0;
}

static int handle_token(struct lws *wsi, struct pss_http *pss) {
  char body[256];
  const char *credential = server->credential != NULL ? server->credential : "";
  int n = snprintf(body, sizeof(body), "{\"token\": \"%s\"}", credential);
  if (write_response_headers(wsi, HTTP_STATUS_OK, "application/json;charset=utf-8", (size_t)n)) return 1;
  char *buf = xmalloc(n);
  memcpy(buf, body, n);
  pss->kind = HH_STATIC;
  prime_body(pss, buf, n, true);
  lws_callback_on_writable(wsi);
  return 0;
}

int callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
  struct pss_http *pss = (struct pss_http *)user;

  switch (reason) {
    case LWS_CALLBACK_HTTP: {
      char path_uri[256];
      enum lws_token_indexes method_tok = WSI_TOKEN_GET_URI;
      int pn = get_method_uri(wsi, path_uri, sizeof(path_uri), &method_tok);
      if (pn <= 0) {
        snprintf(path_uri, sizeof(path_uri), "%s", (const char *)in);
      }

      // Strip query from path for endpoint matching.
      char *q = strchr(path_uri, '?');
      if (q != NULL) *q = '\0';

      access_log(wsi, path_uri);
      snprintf(pss->path, sizeof(pss->path), "%s", path_uri);
      copy_query(wsi, pss->query, sizeof(pss->query));

      char user_buf[30] = "";
      switch (check_auth(wsi, user_buf, sizeof(user_buf))) {
        case AUTH_OK:
          break;
        case AUTH_FAIL:
          return 0;
        case AUTH_ERROR:
        default:
          return 1;
      }

      if (strcmp(pss->path, endpoints.token) == 0 && method_tok == WSI_TOKEN_GET_URI) {
        pss->kind = HH_STATIC;
        return handle_token(wsi, pss);
      }

      if (strcmp(pss->path, endpoints.session) == 0 && method_tok == WSI_TOKEN_POST_URI) {
        if (server->once && server->client_count > 0) {
          return simple_status(wsi, HTTP_STATUS_SERVICE_UNAVAILABLE);
        }
        if (server->max_clients > 0 && server->client_count >= server->max_clients) {
          return simple_status(wsi, HTTP_STATUS_SERVICE_UNAVAILABLE);
        }
        pss->kind = HH_SESSION;
        snprintf(pss->sid, sizeof(pss->sid), "%s", user_buf);  // stash user temporarily in sid
        return 0;  // wait for body
      }

      if (strcmp(pss->path, endpoints.poll) == 0 && method_tok == WSI_TOKEN_GET_URI) {
        if (!extract_sid(pss->query, pss->sid, sizeof(pss->sid))) {
          return simple_status(wsi, HTTP_STATUS_BAD_REQUEST);
        }
        ttyd_session *s = session_find(pss->sid);
        if (s == NULL) return simple_status(wsi, HTTP_STATUS_NOT_FOUND);
        // If credential auth is on, require handshake completion before polling.
        if (server->credential != NULL && !s->authenticated) return simple_status(wsi, HTTP_STATUS_UNAUTHORIZED);
        pss->kind = HH_POLL;
        session_park_poll(s, wsi);
        return 0;  // will write response when writable fires
      }

      if (strcmp(pss->path, endpoints.input) == 0 && method_tok == WSI_TOKEN_POST_URI) {
        if (!extract_sid(pss->query, pss->sid, sizeof(pss->sid))) {
          return simple_status(wsi, HTTP_STATUS_BAD_REQUEST);
        }
        if (session_find(pss->sid) == NULL) return simple_status(wsi, HTTP_STATUS_NOT_FOUND);
        pss->kind = HH_INPUT;
        return 0;  // wait for body
      }

      if (strcmp(pss->path, endpoints.close) == 0 && method_tok == WSI_TOKEN_POST_URI) {
        if (!extract_sid(pss->query, pss->sid, sizeof(pss->sid))) {
          return simple_status(wsi, HTTP_STATUS_BAD_REQUEST);
        }
        ttyd_session *s = session_find(pss->sid);
        if (s != NULL) session_destroy(s);
        return simple_status(wsi, HTTP_STATUS_NO_CONTENT);
      }

      // Redirect /base-path -> /base-path/
      if (strcmp(pss->path, endpoints.parent) == 0) {
        unsigned char buffer[1024 + LWS_PRE], *p = buffer + LWS_PRE, *end = p + sizeof(buffer) - LWS_PRE;
        if (lws_add_http_header_status(wsi, HTTP_STATUS_FOUND, &p, end) ||
            lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION, (unsigned char *)endpoints.index,
                                         (int)strlen(endpoints.index), &p, end) ||
            lws_add_http_header_content_length(wsi, 0, &p, end) || lws_finalize_http_header(wsi, &p, end) ||
            lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
          return 1;
        return lws_http_transaction_completed(wsi) ? -1 : 0;
      }

      if (strcmp(pss->path, endpoints.index) != 0) {
        lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
        return lws_http_transaction_completed(wsi) ? -1 : 0;
      }

      pss->kind = HH_STATIC;
      return handle_static_index(wsi, pss);
    }

    case LWS_CALLBACK_HTTP_BODY:
      if (pss->kind != HH_SESSION && pss->kind != HH_INPUT) break;
      if (pss->body_len + len > pss->body_cap) {
        size_t cap = pss->body_cap == 0 ? 1024 : pss->body_cap;
        while (cap < pss->body_len + len) cap *= 2;
        pss->body = xrealloc(pss->body, cap);
        pss->body_cap = cap;
      }
      memcpy(pss->body + pss->body_len, in, len);
      pss->body_len += len;
      break;

    case LWS_CALLBACK_HTTP_BODY_COMPLETION:
      if (pss->kind == HH_SESSION) {
        char stash_user[30];
        snprintf(stash_user, sizeof(stash_user), "%s", pss->sid);

        char addr[50];
        lws_get_peer_simple(lws_get_network_wsi(wsi), addr, sizeof(addr));
        ttyd_session *s = session_create(addr, pss->path);
        snprintf(s->user, sizeof(s->user), "%s", stash_user);
        if (server->url_arg) collect_args_from_query(pss->query, &s->args, &s->argc);

        bool ok = session_handle_input(s, pss->body, pss->body_len);
        if (!ok) {
          session_destroy(s);
          return simple_status(wsi, HTTP_STATUS_UNAUTHORIZED);
        }

        snprintf(pss->sid, sizeof(pss->sid), "%s", s->sid);
        return respond_session_created(wsi, pss, s->sid);
      }

      if (pss->kind == HH_INPUT) {
        ttyd_session *s = session_find(pss->sid);
        if (s == NULL) return simple_status(wsi, HTTP_STATUS_NOT_FOUND);
        if (!session_handle_input(s, pss->body, pss->body_len)) {
          return simple_status(wsi, HTTP_STATUS_BAD_REQUEST);
        }
        return simple_status(wsi, HTTP_STATUS_NO_CONTENT);
      }
      break;

    case LWS_CALLBACK_HTTP_WRITEABLE: {
      if (pss->kind == HH_POLL && pss->buffer == NULL) {
        // Session woke us up with fresh data, or timed out; drain now.
        return poll_writeable(wsi, pss);
      }
      if (!pss->buffer || pss->len == 0) {
        return lws_http_transaction_completed(wsi) ? -1 : 0;
      }

      unsigned char buffer[4096 + LWS_PRE];
      bool done = false;
      do {
        int n = sizeof(buffer) - LWS_PRE;
        int m = lws_get_peer_write_allowance(wsi);
        if (m == 0) {
          lws_callback_on_writable(wsi);
          return 0;
        } else if (m != -1 && m < n) {
          n = m;
        }
        if (pss->ptr + n > pss->buffer + pss->len) {
          n = (int)(pss->len - (pss->ptr - pss->buffer));
          done = true;
        }
        memcpy(buffer + LWS_PRE, pss->ptr, n);
        pss->ptr += n;
        if (lws_write_http(wsi, buffer + LWS_PRE, (size_t)n) < n) {
          pss_reset(pss);
          return -1;
        }
      } while (!lws_send_pipe_choked(wsi) && !done);

      if (!done && pss->ptr < pss->buffer + pss->len) {
        lws_callback_on_writable(wsi);
        return 0;
      }

      pss_reset(pss);
      return lws_http_transaction_completed(wsi) ? -1 : 0;
    }

    case LWS_CALLBACK_HTTP_FILE_COMPLETION:
      return lws_http_transaction_completed(wsi) ? -1 : 0;

    case LWS_CALLBACK_CLOSED_HTTP:
      if (pss == NULL) break;
      if (pss->kind == HH_POLL && pss->sid[0] != '\0') {
        ttyd_session *s = session_find(pss->sid);
        if (s != NULL) session_clear_poll(s, wsi);
      }
      pss_reset(pss);
      break;

#if (defined(LWS_OPENSSL_SUPPORT) || defined(LWS_WITH_TLS)) && !defined(LWS_WITH_MBEDTLS)
    case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
      if (!len || (SSL_get_verify_result((SSL *)in) != X509_V_OK)) {
        int err = X509_STORE_CTX_get_error((X509_STORE_CTX *)user);
        int depth = X509_STORE_CTX_get_error_depth((X509_STORE_CTX *)user);
        const char *msg = X509_verify_cert_error_string(err);
        lwsl_err("client certificate verification error: %s (%d), depth: %d\n", msg, err, depth);
        return 1;
      }
      break;
#endif
    default:
      break;
  }

  return 0;
}
