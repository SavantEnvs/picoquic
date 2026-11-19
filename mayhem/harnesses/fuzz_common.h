/* Shared setup for the picoquic harnesses: a throw-away QUIC context and connection per input,
 * so one input's result never depends on another's. */
#ifndef MAYHEM_FUZZ_COMMON_H
#define MAYHEM_FUZZ_COMMON_H

#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"

static int fuzz_stream_cb(picoquic_cnx_t* cnx, uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* stream_ctx)
{
    (void)cnx; (void)stream_id; (void)bytes; (void)length; (void)fin_or_event;
    (void)callback_ctx; (void)stream_ctx;
    return 0;
}

static picoquic_quic_t* fuzz_create_quic(uint64_t* simulated_time)
{
    return picoquic_create(8, NULL, NULL, NULL, NULL, fuzz_stream_cb, NULL, NULL, NULL, NULL,
        *simulated_time, simulated_time, NULL, NULL, 0);
}

#endif
