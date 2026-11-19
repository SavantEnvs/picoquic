/* A QUIC server (test certificate embedded, picoquic-test ALPN) with no connection yet, receiving one
 * UDP datagram: header parsing, the server's own replies to an unknown version (sending version
 * negotiation) or an unknown CID (sending a stateless reset), Initial decryption and the TLS
 * ClientHello, followed by whatever the server wants to send back. The client side (receiving VN,
 * Retry and the server's Initial) is fuzz_client_packet. */
#include "fuzz_common.h"
#include "fuzz_certs.h"
#include <picotls.h>
#include <picotls/openssl.h>
#include <openssl/x509.h>

/* picoquic takes ownership of the chain, the certificate bytes and the signer: all heap allocated. */
static int fuzz_install_server_identity(picoquic_quic_t* quic)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;
    const unsigned char* key_ptr = fuzz_key_der;
    ptls_iovec_t* chain = (ptls_iovec_t*)malloc(sizeof(ptls_iovec_t));
    uint8_t* cert = (uint8_t*)malloc(fuzz_cert_der_len);
    ptls_openssl_sign_certificate_t* signer = (ptls_openssl_sign_certificate_t*)malloc(sizeof(*signer));
    EVP_PKEY* pkey = d2i_AutoPrivateKey(NULL, &key_ptr, (long)fuzz_key_der_len);

    if (ctx == NULL || chain == NULL || cert == NULL || signer == NULL || pkey == NULL
        || ptls_openssl_init_sign_certificate(signer, pkey) != 0) {
        free(chain);
        free(cert);
        free(signer);
        EVP_PKEY_free(pkey);
        return -1;
    }
    EVP_PKEY_free(pkey);
    memcpy(cert, fuzz_cert_der, fuzz_cert_der_len);
    chain[0].base = cert;
    chain[0].len = fuzz_cert_der_len;
    picoquic_set_tls_certificate_chain(quic, chain, 1);
    ctx->sign_certificate = &signer->super;
    quic->enforce_client_only = 0;
    return 0;
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
    struct sockaddr_in addr_from;
    struct sockaddr_in addr_to;
    struct sockaddr_storage reply_to;
    struct sockaddr_storage reply_from;
    picoquic_quic_t* quic;
    picoquic_connection_id_t log_cid;
    picoquic_cnx_t* last_cnx = NULL;
    size_t send_length = 0;
    int if_index = 0;

    if (size < 8 || size > sizeof(packet)) {
        return -1;
    }
    memcpy(packet, data, size);

    memset(&addr_from, 0, sizeof(addr_from));
    addr_from.sin_family = AF_INET;
    addr_from.sin_port = htons(4433);
    addr_from.sin_addr.s_addr = htonl(0x7f000002);
    memset(&addr_to, 0, sizeof(addr_to));
    addr_to.sin_family = AF_INET;
    addr_to.sin_port = htons(443);
    addr_to.sin_addr.s_addr = htonl(0x7f000001);

    quic = picoquic_create(8, NULL, NULL, NULL, "picoquic-test", fuzz_stream_cb, NULL, NULL, NULL, NULL,
        simulated_time, &simulated_time, NULL, NULL, 0);
    if (quic == NULL) {
        return -1;
    }
    if (fuzz_install_server_identity(quic) == 0) {
        (void)picoquic_incoming_packet(quic, packet, size, (struct sockaddr*)&addr_from,
            (struct sockaddr*)&addr_to, 0, 0, simulated_time);
        (void)picoquic_prepare_next_packet(quic, simulated_time, send_buffer, sizeof(send_buffer),
            &send_length, &reply_to, &reply_from, &if_index, &log_cid, &last_cnx);
    }
    picoquic_free(quic);
    return 0;
}
