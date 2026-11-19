/* HTTP/3 header block (QPACK) parser: parses consecutive header blocks until the buffer ends. */
#include <string.h>
#include "h3zero.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    uint8_t buffer[4096];
    uint8_t* parsed = buffer;
    uint8_t* bytes_max;

    if (size == 0 || size > sizeof(buffer)) {
        return -1;
    }
    memcpy(buffer, data, size);
    bytes_max = buffer + size;
    while (parsed != NULL && parsed < bytes_max) {
        h3zero_header_parts_t parts;

        memset(&parts, 0, sizeof(parts));
        parsed = h3zero_parse_qpack_header_frame(parsed, bytes_max, &parts);
        h3zero_release_header_parts(&parts);
    }
    return 0;
}
