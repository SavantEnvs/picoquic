/* Frame skipper: walks a buffer frame by frame with picoquic_skip_frame, as the packet parser does to
 * classify a packet. Each call must consume at least one byte and stay inside the buffer. */
#include <stdlib.h>
#include "fuzz_common.h"

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    (void)argc; (void)argv;
    debug_printf_suspend();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    size_t index = 0;

    if (size == 0) {
        return -1;
    }
    while (index < size) {
        size_t consumed = 0;
        int pure_ack = 0;

        if (picoquic_skip_frame(data + index, size - index, &consumed, &pure_ack) != 0) {
            break;
        }
        if (consumed == 0 || consumed > size - index) {
            abort();
        }
        index += consumed;
    }
    return 0;
}
