/* CTAPHID (FIDO CTAP 2.x, section 11.2): 64-byte reports, channels, message
 * reassembly. Init packet: CID(4) CMD|0x80 BCNTH BCNTL DATA(57);
 * continuation: CID(4) SEQ DATA(59). */
#include <string.h>
#include "fido.h"

enum {
    CMD_PING = 0x81, CMD_MSG = 0x83, CMD_INIT = 0x86, CMD_WINK = 0x88, CMD_CBOR = 0x90, CMD_CANCEL = 0x91,
    CMD_ERROR = 0xBF,
};
enum { ERR_INVALID_CMD = 0x01, ERR_INVALID_PAR = 0x02, ERR_INVALID_LEN = 0x03, ERR_INVALID_SEQ = 0x04,
       ERR_CHANNEL_BUSY = 0x06, ERR_INVALID_CHANNEL = 0x0B };
#define BROADCAST 0xFFFFFFFFu
#define CAP_WINK 0x01
#define CAP_CBOR 0x04
#define CAP_NMSG 0x08 /* no CTAP1/U2F */

static uint32_t be32(const uint8_t *p) { return (uint32_t)p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]; }
static void put_be32(uint8_t *p, uint32_t v) { p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v; }

void ctaphid_init(ctaphid *h)
{
    memset(h, 0, sizeof *h);
    h->next_cid = 1;
}

static void send_msg(uint32_t cid, uint8_t cmd, const uint8_t *d, size_t n, ctaphid_send send, void *ctx)
{
    uint8_t r[64];
    size_t off = 0;
    uint8_t seq = 0;
    memset(r, 0, 64);
    put_be32(r, cid);
    r[4] = cmd;
    r[5] = (uint8_t)(n >> 8);
    r[6] = (uint8_t)n;
    size_t k = n < 57 ? n : 57;
    memcpy(r + 7, d, k);
    send(ctx, r);
    for (off = k; off < n; off += k) {
        memset(r, 0, 64);
        put_be32(r, cid);
        r[4] = seq++;
        k = n - off < 59 ? n - off : 59;
        memcpy(r + 5, d + off, k);
        send(ctx, r);
    }
}

static void send_err(uint32_t cid, uint8_t err, ctaphid_send send, void *ctx) { send_msg(cid, CMD_ERROR, &err, 1, send, ctx); }

static void dispatch(ctaphid *h, const fido_env *env, ctaphid_send send, void *ctx)
{
    h->busy = false;
    switch (h->cmd) {
    case CMD_INIT: {
        if (h->len != 8) { send_err(h->cid, ERR_INVALID_LEN, send, ctx); return; }
        uint8_t r[17];
        memcpy(r, h->msg, 8); /* nonce */
        uint32_t cid = h->cid;
        if (cid == BROADCAST) {
            cid = h->next_cid++;
            if (h->next_cid == BROADCAST || !h->next_cid) h->next_cid = 1;
        }
        put_be32(r + 8, cid);
        r[12] = 2;              /* CTAPHID protocol version */
        r[13] = 1; r[14] = 0; r[15] = 0; /* device version */
        r[16] = CAP_WINK | CAP_CBOR | CAP_NMSG;
        send_msg(h->cid, CMD_INIT, r, sizeof r, send, ctx);
        return;
    }
    case CMD_PING: send_msg(h->cid, CMD_PING, h->msg, h->len, send, ctx); return;
    case CMD_WINK: send_msg(h->cid, CMD_WINK, NULL, 0, send, ctx); return;
    case CMD_CBOR: {
        size_t n = ctap2_handle(env, h->msg, h->len, h->resp, sizeof h->resp);
        send_msg(h->cid, CMD_CBOR, h->resp, n, send, ctx);
        memset(h->resp, 0, n);
        memset(h->msg, 0, h->len);
        return;
    }
    default: send_err(h->cid, ERR_INVALID_CMD, send, ctx); /* includes MSG: no U2F */
    }
}

void ctaphid_report(ctaphid *h, const uint8_t in[64], const fido_env *env, ctaphid_send send, void *ctx)
{
    uint32_t cid = be32(in);
    uint8_t b = in[4];

    if (!cid) { send_err(cid, ERR_INVALID_CHANNEL, send, ctx); return; }
    if (b & 0x80) { /* initialization packet */
        if (b == CMD_CANCEL) return;                     /* nothing long-running to cancel here */
        if (h->busy && cid != h->cid) {
            if (b != CMD_INIT) { send_err(cid, ERR_CHANNEL_BUSY, send, ctx); return; }
        }
        if (cid == BROADCAST && b != CMD_INIT) { send_err(cid, ERR_INVALID_CHANNEL, send, ctx); return; }
        if (cid != BROADCAST && (cid >= h->next_cid)) { send_err(cid, ERR_INVALID_CHANNEL, send, ctx); return; }
        uint16_t len = (uint16_t)(in[5] << 8 | in[6]);
        if (len > sizeof h->msg) { send_err(cid, ERR_INVALID_LEN, send, ctx); return; }
        h->cid = cid;
        h->cmd = b;
        h->len = len;
        h->seq = 0;
        h->got = len < 57 ? len : 57;
        memcpy(h->msg, in + 7, h->got);
        h->busy = h->got < len;
        if (!h->busy) dispatch(h, env, send, ctx);
        return;
    }
    /* continuation packet */
    if (!h->busy || cid != h->cid) return;               /* spurious: ignore */
    if (b != h->seq++) {
        h->busy = false;
        send_err(cid, ERR_INVALID_SEQ, send, ctx);
        return;
    }
    uint16_t k = h->len - h->got < 59 ? h->len - h->got : 59;
    memcpy(h->msg + h->got, in + 5, k);
    h->got += k;
    if (h->got == h->len) dispatch(h, env, send, ctx);
}
