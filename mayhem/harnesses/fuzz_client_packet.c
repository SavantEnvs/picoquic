/* A QUIC client that has just sent its first Initial, receiving up to four datagrams from the server:
 * version negotiation, Retry (integrity tag, token), server Initial (decryption, ServerHello),
 * Handshake/1-RTT headers and stateless reset checks, each followed by what the client sends back.
 *
 * Input: a sequence of [2-byte big-endian length][datagram] records. The client's connection IDs
 * are fixed (the initial DCID by picoquic_create_cnx, the local CID by picoquic's own cnx_id
 * callback hook, for the first local CID only), so seeds can address the connection; nothing in the input is rewritten. */
#include "fuzz_common.h"

#define FUZZ_MAX_DATAGRAMS 4

static const uint8_t fuzz_client_icid[8] = { 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c, 0x1c };
static const uint8_t fuzz_client_scid[8] = { 0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0xc1 };

static void fuzz_fixed_cnx_id(picoquic_quic_t* quic, picoquic_connection_id_t cnx_id_local,
    picoquic_connection_id_t cnx_id_remote, void* cnx_id_cb_data, picoquic_connection_id_t* cnx_id_returned)
{
    picoquic_connection_id_t fixed;

    (void)cnx_id_remote; (void)cnx_id_cb_data;
    (void)picoquic_parse_connection_id(fuzz_client_scid, sizeof(fuzz_client_scid), &fixed);
    /* Only the first local CID is fixed. Once it is in use, keep picoquic's random value, so later
     * CIDs (NEW_CONNECTION_ID) do not collide with it in picoquic_create_local_cnxid. */
    *cnx_id_returned = (picoquic_cnx_by_id(quic, fixed, NULL) == NULL) ? fixed : cnx_id_local;
}

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    (void)argc; (void)argv;
    debug_printf_suspend();
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    uint64_t simulated_time = 1000000;
    uint8_t packet[PICOQUIC_MAX_PACKET_SIZE];
    uint8_t send_buffer[PICOQUIC_MAX_PACKET_SIZE];
    struct sockaddr_in addr_server;
    struct sockaddr_in addr_client;
    struct sockaddr_storage reply_to;
    struct sockaddr_storage reply_from;
    picoquic_connection_id_t icid;
    picoquic_connection_id_t log_cid;
    picoquic_cnx_t* last_cnx = NULL;
    picoquic_quic_t* quic;
    picoquic_cnx_t* cnx;
    size_t send_length = 0;
    int if_index = 0;

    if (size < 3) {
        return -1;
    }

    memset(&addr_server, 0, sizeof(addr_server));
    addr_server.sin_family = AF_INET;
    addr_server.sin_port = htons(443);
    addr_server.sin_addr.s_addr = htonl(0x7f000001);
    memset(&addr_client, 0, sizeof(addr_client));
    addr_client.sin_family = AF_INET;
    addr_client.sin_port = htons(4433);
    addr_client.sin_addr.s_addr = htonl(0x7f000002);

    quic = picoquic_create(8, NULL, NULL, NULL, "picoquic-test", fuzz_stream_cb, NULL,
        fuzz_fixed_cnx_id, NULL, NULL, simulated_time, &simulated_time, NULL, NULL, 0);
    if (quic == NULL) {
        return -1;
    }
    picoquic_set_null_verifier(quic);
    (void)picoquic_parse_connection_id(fuzz_client_icid, sizeof(fuzz_client_icid), &icid);
    cnx = picoquic_create_cnx(quic, icid, picoquic_null_connection_id, (struct sockaddr*)&addr_server,
        simulated_time, 0, "test.example.com", "picoquic-test", 1);
    if (cnx != NULL && picoquic_start_client_cnx(cnx) == 0) {
        (void)picoquic_prepare_next_packet(quic, simulated_time, send_buffer, sizeof(send_buffer),
            &send_length, &reply_to, &reply_from, &if_index, &log_cid, &last_cnx);
        for (int i = 0; i < FUZZ_MAX_DATAGRAMS && size >= 2; i++) {
            size_t length = ((size_t)data[0] << 8) | data[1];

            data += 2;
            size -= 2;
            if (length > size) {
                length = size;
            }
            if (length > sizeof(packet)) {
                length = sizeof(packet);
            }
            memcpy(packet, data, length);
            data += length;
            size -= length;
            simulated_time += 10000;
            (void)picoquic_incoming_packet(quic, packet, length, (struct sockaddr*)&addr_server,
                (struct sockaddr*)&addr_client, 0, 0, simulated_time);
            (void)picoquic_prepare_next_packet(quic, simulated_time, send_buffer, sizeof(send_buffer),
                &send_length, &reply_to, &reply_from, &if_index, &log_cid, &last_cnx);
        }
    }
    picoquic_free(quic);
    return 0;
}
