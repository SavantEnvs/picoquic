/* HTTP/3 request/response stream parser: frame headers, HEADERS blocks and DATA lengths, parsed
 * incrementally in the same way as stream data arriving from a peer. */
#include <string.h>
#include "h3zero_common.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    uint8_t buffer[8192];
    h3zero_data_stream_state_t stream_state;
    uint8_t* p = buffer;
    uint8_t* p_max;
    uint64_t error_found = 0;

    if (size == 0 || size > sizeof(buffer)) {
        return -1;
    }
    memcpy(buffer, data, size);
    p_max = buffer + size;
    memset(&stream_state, 0, sizeof(stream_state));
    while (p != NULL && p < p_max) {
        size_t available_data = 0;

        p = h3zero_parse_data_stream(p, p_max, &stream_state, &available_data, &error_found);
        if (p != NULL) {
            p += available_data;
        }
    }
    h3zero_delete_data_stream_state(&stream_state);
    return 0;
}
