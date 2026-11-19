/* QUIC frame decoder: the bytes after the selector are the plaintext payload of one packet, handed to
 * picoquic_decode_frames on a fresh connection. The first byte selects the packet epoch and which
 * negotiated extensions are on (frames of a disabled extension are a protocol violation, so each
 * decoder is only reached when its extension is enabled). */
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
    uint8_t selector;
    int epoch;
    int mpath;

    if (size < 2) {
        return -1;
    }
    selector = data[0];
    epoch = selector & 3;
    mpath = (selector >> 2) & 3;
    data++;
    size--;

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    quic = fuzz_create_quic(&simulated_time);
    if (quic == NULL) {
        return -1;
    }
    cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
        (struct sockaddr*)&saddr, simulated_time, 0, "fuzz-sni", "fuzz-alpn", (selector & 0x10) ? 0 : 1);
    if (cnx != NULL) {
        cnx->path[0]->first_tuple->p_remote_cnxid->cnx_id.id_len = 8;
        cnx->pkt_ctx[0].send_sequence = 0x0102030406;
        cnx->path[0]->pkt_ctx.send_sequence = 0x0102030406;
        (void)picoquic_create_local_cnxid(cnx, 0, NULL, simulated_time);
        cnx->is_time_stamp_enabled = 1;
        cnx->remote_parameters.ack_delay_exponent = 3;
        cnx->local_parameters.max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
        cnx->is_ack_frequency_negotiated = 1;
        cnx->remote_parameters.min_ack_delay = 1000;
        cnx->local_parameters.enable_bdp_frame = 3;
        cnx->is_reset_stream_at_enabled = 1;
        if (mpath != 0) {
            cnx->is_multipath_enabled = 1;
            cnx->max_path_id_local = 5;
            if (mpath >= 2) {
                cnx->is_address_discovery_provider = 1;
                cnx->is_address_discovery_receiver = 1;
            }
        }
        if (epoch == 3 && (selector & 0x20) == 0) {
            cnx->cnx_state = picoquic_state_ready;
        }
        (void)picoquic_decode_frames(cnx, cnx->path[0], data, size, NULL, epoch,
            NULL, NULL, 0, 0, NULL, simulated_time);
        picoquic_delete_cnx(cnx);
    }
    picoquic_free(quic);
    return 0;
}
