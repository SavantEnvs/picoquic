/* WebTransport / extended-CONNECT capsule stream: picowt_receive_capsule accumulating capsules
 * (h3zero_accumulate_capsule: type and length varints, buffered values) and decoding the
 * close-session and drain-session capsules, with the bytes delivered in chunks.
 *
 * Input: a sequence of [chunk length][chunk] records, each handed to picowt_receive_capsule as one
 * delivery of stream data. Parsing stops at the first error, as the WebTransport session would. */
#include "fuzz_common.h"
#include "pico_webtransport.h"

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
    picowt_capsule_t capsule;

    if (size < 2) {
        return -1;
    }
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    quic = fuzz_create_quic(&simulated_time);
    if (quic == NULL) {
        return -1;
    }
    memset(&capsule, 0, sizeof(capsule));
    cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
        (struct sockaddr*)&saddr, simulated_time, 0, "fuzz-sni", "h3", 1);
    if (cnx != NULL) {
        while (size >= 1) {
            size_t length = data[0];

            data++;
            size--;
            if (length > size) {
                length = size;
            }
            if (picowt_receive_capsule(cnx, data, data + length, &capsule) != 0) {
                break;
            }
            data += length;
            size -= length;
        }
    }
    picowt_release_capsule(&capsule);
    picoquic_free(quic);
    return 0;
}
