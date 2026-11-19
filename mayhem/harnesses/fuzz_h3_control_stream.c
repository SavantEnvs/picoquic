/* HTTP/3 peer-initiated streams on a server connection: the unidirectional stream type, the control
 * stream with its SETTINGS frame (h3zero_settings_components_decode) and the frames that may follow,
 * QPACK/push streams, and WebTransport stream headers on uni- and bidirectional streams.
 *
 * Input: a sequence of [stream selector][chunk length][chunk] records, so the parser sees stream data
 * split and interleaved across streams the way it arrives from a peer. The selector picks one of the
 * client's first four unidirectional (2, 6, 10, 14) or bidirectional (0, 4, 8, 12) stream IDs. A stream
 * whose parser reported an error (returned NULL) gets no more data, as h3zero resets it. */
#include "fuzz_common.h"
#include "h3zero_common.h"

#define FUZZ_NB_STREAMS 8

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    (void)argc; (void)argv;
    debug_printf_suspend();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    uint64_t simulated_time = 1000000;
    struct sockaddr_in saddr;
    picoquic_quic_t* quic;
    picoquic_cnx_t* cnx;
    h3zero_callback_ctx_t* h3_ctx;
    int stream_failed[FUZZ_NB_STREAMS] = { 0 };

    if (size < 3) {
        return -1;
    }
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    quic = fuzz_create_quic(&simulated_time);
    if (quic == NULL) {
        return -1;
    }
    cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
        (struct sockaddr*)&saddr, simulated_time, 0, NULL, "h3", 0);
    h3_ctx = h3zero_callback_create_context(NULL);
    if (cnx != NULL && h3_ctx != NULL) {
        while (size >= 2) {
            unsigned int index = data[0] % FUZZ_NB_STREAMS;
            size_t length = data[1];
            uint64_t stream_id = (index < 4) ? (2 + 4 * (uint64_t)index) : (4 * (uint64_t)(index - 4));
            h3zero_stream_ctx_t* stream_ctx;
            uint64_t error_found = 0;

            data += 2;
            size -= 2;
            if (length > size) {
                length = size;
            }
            if (!stream_failed[index]) {
                stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, h3_ctx, 1, 1);
                if (stream_ctx == NULL ||
                    h3zero_parse_incoming_remote_stream_ex(data, data + length, stream_ctx, h3_ctx, cnx, &error_found) == NULL) {
                    stream_failed[index] = 1;
                }
            }
            data += length;
            size -= length;
        }
    }
    if (h3_ctx != NULL) {
        h3zero_callback_delete_context(cnx, h3_ctx);
    }
    picoquic_free(quic);
    return 0;
}
