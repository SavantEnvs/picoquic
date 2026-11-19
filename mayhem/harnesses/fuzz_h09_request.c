/* HTTP/0.9 (hq-interop) server request parsing: the request line ({GET|POST} <path> [HTTP/x.y]),
 * the header lines and the end of headers, fed incrementally as stream data from a client, then
 * the GET path parsed the way the demo server does (echo size or index; no web folder, no files).
 *
 * Input: a sequence of [2-byte big-endian length][chunk] records; the last record carries
 * picoquic_callback_stream_fin, the earlier ones picoquic_callback_stream_data. */
#include <stdlib.h>
#include <string.h>
#include "picoquic.h"
#include "h3zero_common.h"
#include "demoserver.h"

#define FUZZ_MAX_CHUNKS 64

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    h3zero_stream_ctx_t* stream_ctx = (h3zero_stream_ctx_t*)calloc(1, sizeof(h3zero_stream_ctx_t));
    size_t offset = 0;
    int ret = 0;

    if (stream_ctx == NULL) {
        return 0;
    }
    for (int n = 0; ret == 0 && n < FUZZ_MAX_CHUNKS && offset + 2 <= size; n++) {
        size_t chunk_length = ((size_t)data[offset] << 8) | data[offset + 1];
        size_t processed = 0;
        int is_last;
        uint8_t* chunk;

        offset += 2;
        if (chunk_length > size - offset) {
            chunk_length = size - offset;
        }
        is_last = (offset + chunk_length + 2 > size) || (n == FUZZ_MAX_CHUNKS - 1);
        /* An exact-size heap copy, so ASan sees any read past the chunk. */
        chunk = (uint8_t*)malloc(chunk_length ? chunk_length : 1);
        if (chunk == NULL) {
            break;
        }
        memcpy(chunk, data + offset, chunk_length);
        ret = picoquic_h09_server_process_data_header(chunk, chunk_length,
            is_last ? picoquic_callback_stream_fin : picoquic_callback_stream_data, stream_ctx, &processed);
        free(chunk);
        offset += chunk_length;
        if (is_last) {
            break;
        }
    }
    if (ret == 0 && stream_ctx->ps.hq.method == 0) {
        uint64_t echo_size = 0;
        char* file_path = NULL;
        int file_error = 0;

        (void)h3zero_server_parse_path(stream_ctx->ps.hq.path, stream_ctx->ps.hq.path_length,
            &echo_size, &file_path, NULL, &file_error);
        free(file_path);
    }
    free(stream_ctx->ps.hq.path);
    free(stream_ctx);
    return 0;
}
