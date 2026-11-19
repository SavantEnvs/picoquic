/* :path query parsing as the HTTP/3 servers use it on a client's request: h3zero's query offset,
 * parameter lookup and percent-decoding into a string and a number, and the MASQUE CONNECT-UDP
 * path parser picomask_udp_path_params (?h=<address>&p=<port>, as the proxy reads it).
 *
 * Input: [1 byte: parameter id length, low 3 bits][parameter id][path]. */
#include <netdb.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include "picoquic.h"
#include "h3zero_uri.h"

/* Defined in picomask.c, not declared in a header. */
int picomask_udp_path_params(uint8_t* path, size_t path_length, struct sockaddr_storage* addr);

/* Environment mock: picoquic_get_server_address falls back to a DNS lookup for any host that is
 * not a literal address. A fuzz target must not query DNS (slow, network dependent, and the
 * answer would differ between runs), so name lookups fail here as they do on a host without DNS.
 * Literal IPv4/IPv6 addresses still go through inet_pton as in production. */
int getaddrinfo(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** res)
{
    (void)node; (void)service; (void)hints;
    *res = NULL;
    return EAI_NONAME;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    char parameter_id[8];
    size_t id_length;
    size_t path_length;
    uint8_t* path;
    size_t query_offset;
    uint8_t buffer[256];
    size_t parsed_length = 0;
    uint64_t number = 0;
    struct sockaddr_storage addr;

    if (size < 1) {
        return -1;
    }
    id_length = data[0] & 7;
    if (size < 1 + id_length) {
        return -1;
    }
    memcpy(parameter_id, data + 1, id_length);
    path_length = size - 1 - id_length;
    /* An exact-size heap copy, so ASan sees any read past the path. */
    path = (uint8_t*)malloc(path_length ? path_length : 1);
    if (path == NULL) {
        return 0;
    }
    memcpy(path, data + 1 + id_length, path_length);

    (void)h3zero_pathabempty_length(path, path_length);
    query_offset = h3zero_query_offset(path, path_length);
    if (query_offset < path_length) {
        const uint8_t* queries = path + query_offset;
        size_t queries_length = path_length - query_offset;

        (void)h3zero_query_parameter_string(queries, queries_length, parameter_id, id_length,
            buffer, sizeof(buffer), &parsed_length);
        (void)h3zero_query_parameter_number(queries, queries_length, parameter_id, id_length, &number, 0);
    }
    memset(&addr, 0, sizeof(addr));
    (void)picomask_udp_path_params(path, path_length, &addr);
    free(path);
    return 0;
}
