/* TLS transport-parameters extension, as received from a peer. First byte: 0 = client hello
 * extension (parsed by a server), 1 = encrypted extensions (parsed by a client), and the QUIC
 * version in use. */
#include "fuzz_common.h"

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
    picoquic_connection_id_t initial_id = { { 1, 2, 3, 4, 5, 6, 7, 8 }, 8 };
    picoquic_connection_id_t remote_id = { { 8, 7, 6, 5, 4, 3, 2, 1 }, 8 };
    uint8_t buffer[1024];
    size_t decoded = 0;
    int mode;
    uint32_t version;

    if (size < 2 || size - 1 > sizeof(buffer)) {
        return -1;
    }
    mode = data[0] & 1;
    version = (data[0] & 2) ? picoquic_supported_versions[picoquic_nb_supported_versions - 1].version : 0;
    data++;
    size--;

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    quic = fuzz_create_quic(&simulated_time);
    if (quic == NULL) {
        return -1;
    }
    cnx = picoquic_create_cnx(quic, initial_id, remote_id, (struct sockaddr*)&saddr, simulated_time,
        version, "fuzz-sni", "fuzz-alpn", (mode == 0) ? 1 : 0);
    if (cnx != NULL) {
        memcpy(buffer, data, size);
        (void)picoquic_receive_transport_extensions(cnx, mode, buffer, size, &decoded);
        picoquic_delete_cnx(cnx);
    }
    picoquic_free(quic);
    return 0;
}
