#pragma once

/**
 * @file ProgrammerSocks.h
 * @author w-AI-fu_DEV
 * @brief Simple wrapper over win32 WebSockets
 * @version 0.1
 * @date 2025-01-21
 * @license MIT
 * @copyright Copyright (c) 2025
 */

#if !defined(SOCKS_FLAG_DEBUG)
#define SOCKS_FLAG_DEBUG 0
#endif

#if !defined(SOCKS_FLAG_SILENT)
#define SOCKS_FLAG_SILENT 0
#endif

#if !defined(SOCKS_BUFFER_SIZE)
#define SOCKS_BUFFER_SIZE 2097152
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
// #include <websocket.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>

// #pragma comment(lib, "websocket.lib")
#pragma comment(lib, "Ws2_32.lib")

typedef uint8_t __SOCK_WS_OPCODE_TYPE;

#define __SOCK_WS_OPCODE_CONTINUATION (__SOCK_WS_OPCODE_TYPE)0x0
#define __SOCK_WS_OPCODE_TEXT (__SOCK_WS_OPCODE_TYPE)0x1
#define __SOCK_WS_OPCODE_BINARY (__SOCK_WS_OPCODE_TYPE)0x2
#define __SOCK_WS_OPCODE_CLOSE (__SOCK_WS_OPCODE_TYPE)0x8
#define __SOCK_WS_OPCODE_PING (__SOCK_WS_OPCODE_TYPE)0x9
#define __SOCK_WS_OPCODE_PONG (__SOCK_WS_OPCODE_TYPE)0xA

typedef enum __sock_err_type
{
    SOCK_ERR_SUCCESS,
    SOCK_ERR_FAILURE,
    SOCK_ERR_ARGUMENTS,
    SOCK_ERR_CONNECTION,
    SOCK_ERR_ALLOC,
} sock_err_t;

WSADATA __wsa_data;

typedef enum __sock_message_type
{
    SOCK_MESSAGE_NONE,
    SOCK_MESSAGE_CLOSE,
    SOCK_MESSAGE_TEXT,
    SOCK_MESSAGE_BINARY,

} SOCK_MESSAGE_TYPE;

typedef union __sock_message
{
    SOCK_MESSAGE_TYPE type;

    struct __sock_message_close
    {
        SOCK_MESSAGE_TYPE type;
        char *reason;
        uint64_t close_code;
    } message_close_frame;

    struct __sock_message_text
    {
        SOCK_MESSAGE_TYPE type;
        char *buffer;
        uint64_t length;
        int needs_freeing;
    } message_text;

    struct __sock_message_bin
    {
        SOCK_MESSAGE_TYPE type;
        BYTE *buffer;
        uint64_t length;
        int needs_freeing;
    } message_binary;

} SOCK_MESSAGE;

typedef struct __sock_ws_frame
{
    uint8_t fin;
    uint8_t rsv1;
    uint8_t rsv2;
    uint8_t rsv3;
    uint8_t opcode;
    uint8_t mask;
    uint64_t payload_length;
    uint8_t masking_key[4];
    unsigned char *payload;
} __WS_FRAME;

typedef struct __sock_websock
{
    SOCKET socket;
    char *recv_buffer;
    uint64_t recv_buff_count;
    SOCK_MESSAGE *messages_buffer;
    uint64_t messages_count;
    SOCK_MESSAGE *fragments_buffer;
    uint64_t fragments_count;
    int connected;
    __SOCK_WS_OPCODE_TYPE last_message_type;
} SOCK;

const char *__SOCK_B64_TABLE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const int __SOCK_B64_MOD_TABLE[3] = {0, 2, 1};

char *__strndup(const char *src, size_t n)
{
    if (!src)
        return NULL;

    size_t len = strnlen(src, n);
    char *dest = malloc(len + 1);

    if (!dest)
        return NULL;

    memcpy(dest, src, len);
    dest[len] = '\0';
    return dest;
}

void __sock_printerr(const char *format, ...)
{
    if (SOCKS_FLAG_SILENT)
        return;

    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
}

void __sock_debug(const char *line)
{
    if (SOCKS_FLAG_SILENT)
        return;
    if (!SOCKS_FLAG_DEBUG)
        return;
    printf("%s\n", line);
}

int __encode_text_frame(
    const char *message,   // Input string to encode
    unsigned char *output, // Output buffer
    size_t output_max_len, // Maximum output buffer size
    int should_mask        // Whether to apply client-side masking
)
{
    // Input validation
    if (!message || !output || output_max_len == 0)
    {
        return -1;
    }

    size_t message_len = strlen(message);
    size_t total_frame_len = 0;

    // First byte: FIN bit set (0x80) and text opcode (0x01)
    output[0] = 0x81; // 0x80 (FIN) | 0x01 (TEXT)
    total_frame_len++;

    // Payload length encoding
    if (message_len < 126)
    {
        // Short length
        output[1] = should_mask ? (message_len | 0x80) : message_len;
        total_frame_len++;
    }
    else if (message_len < 65536)
    {
        // Medium length (16-bit)
        output[1] = should_mask ? (126 | 0x80) : 126;
        output[2] = (message_len >> 8) & 0xFF;
        output[3] = message_len & 0xFF;
        total_frame_len += 3;
    }
    else
    {
        // Long length (64-bit)
        output[1] = should_mask ? (127 | 0x80) : 127;

        // 64-bit length (big-endian)
        for (int i = 0; i < 8; i++)
        {
            output[2 + i] = (message_len >> (56 - i * 8)) & 0xFF;
        }
        total_frame_len += 9;
    }

    // Masking (for client-side frames)
    if (should_mask)
    {
        // Generate random masking key
        uint8_t masking_key[4];
        for (int i = 0; i < 4; i++)
        {
            masking_key[i] = rand() & 0xFF;
            output[total_frame_len++] = masking_key[i];
        }

        // Copy and mask payload
        for (size_t i = 0; i < message_len; i++)
        {
            output[total_frame_len + i] =
                message[i] ^ masking_key[i % 4];
        }
    }
    else
    {
        // Directly copy payload
        memcpy(output + total_frame_len, message, message_len);
    }

    // Total frame length
    return total_frame_len + message_len;
}

int __encode_binary_frame(
    const char *buffer, // Input string to encode
    uint64_t buffer_length,
    unsigned char *output, // Output buffer
    size_t output_max_len, // Maximum output buffer size
    int should_mask        // Whether to apply client-side masking
)
{
    // Input validation
    if (!buffer || !output || output_max_len == 0)
    {
        return -1;
    }

    size_t total_frame_len = 0;

    // First byte: FIN bit set (0x80) and text opcode (0x02)
    output[0] = 0x82; // 0x80 (FIN) | 0x02 (BINARY)
    total_frame_len++;

    // Payload length encoding
    if (buffer_length < 126)
    {
        // Short length
        output[1] = should_mask ? (buffer_length | 0x80) : buffer_length;
        total_frame_len++;
    }
    else if (buffer_length < 65536)
    {
        // Medium length (16-bit)
        output[1] = should_mask ? (126 | 0x80) : 126;
        output[2] = (buffer_length >> 8) & 0xFF;
        output[3] = buffer_length & 0xFF;
        total_frame_len += 3;
    }
    else
    {
        // Long length (64-bit)
        output[1] = should_mask ? (127 | 0x80) : 127;

        // 64-bit length (big-endian)
        for (int i = 0; i < 8; i++)
        {
            output[2 + i] = (buffer_length >> (56 - i * 8)) & 0xFF;
        }
        total_frame_len += 9;
    }

    // Masking (for client-side frames)
    if (should_mask)
    {
        // Generate random masking key
        uint8_t masking_key[4];
        for (int i = 0; i < 4; i++)
        {
            masking_key[i] = rand() & 0xFF;
            output[total_frame_len++] = masking_key[i];
        }

        // Copy and mask payload
        for (size_t i = 0; i < buffer_length; i++)
        {
            output[total_frame_len + i] = buffer[i] ^ masking_key[i % 4];
        }
    }
    else
    {
        // Directly copy payload
        memcpy(output + total_frame_len, buffer, buffer_length);
    }

    // Total frame length
    return total_frame_len + buffer_length;
}

// Decode a WebSocket frame
int __decode_websocket_frame(
    unsigned char *input,
    size_t input_len,
    __WS_FRAME *frame)
{
    // Check if input is at least 2 bytes
    if (input_len < 2)
    {
        __sock_debug("Could not parse frame, size under 2 bytes.");
        return -1; // Insufficient data
    }

    // Parse first byte
    frame->fin = (input[0] & 0x80) >> 7;
    frame->rsv1 = (input[0] & 0x40) >> 6;
    frame->rsv2 = (input[0] & 0x20) >> 5;
    frame->rsv3 = (input[0] & 0x10) >> 4;
    frame->opcode = input[0] & 0x0F;

    // Parse second byte
    frame->mask = (input[1] & 0x80) >> 7;
    uint64_t payload_length = input[1] & 0x7F;

    // Track current position in input buffer
    size_t current_pos = 2;

    // Extended payload length
    if (payload_length == 126)
    {
        // 16-bit unsigned length
        if (input_len < 4)
        {
            __sock_debug("Could not parse frame, size under 4 bytes.");
            return -1; // Insufficient data
        }
        payload_length = (input[2] << 8) | input[3];
        current_pos += 2;
    }
    else if (payload_length == 127)
    {
        // 64-bit unsigned length
        if (input_len < 10)
        {
            __sock_debug("Could not parse frame, size under 10 bytes.");
            return -1; // Insufficient data
        }
        payload_length = 0;
        for (int i = 0; i < 8; i++)
        {
            payload_length = (payload_length << 8) | input[2 + i];
        }
        current_pos += 8;
    }

    frame->payload_length = payload_length;

    // Parse masking key if mask is set
    if (frame->mask)
    {
        if (input_len < current_pos + 4)
        {
            __sock_debug("Could not parse frame, could not parse masking key.");
            return -1; // Insufficient data
        }
        memcpy(frame->masking_key, input + current_pos, 4);
        current_pos += 4;
    }

    // Check if full payload is available
    if (input_len < current_pos + payload_length)
    {
        __sock_debug("Could not parse frame, payload is not fully available.\n");
        return -1; // Incomplete payload
    }

    // Allocate payload (caller must free)
    frame->payload = malloc(payload_length + 1);
    if (frame->payload == NULL)
    {
        __sock_debug("Could not parse frame, failed to allocate payload.");
        return -1; // Memory allocation failed
    }

    // Copy payload
    memcpy(frame->payload, input + current_pos, payload_length);

    // Unmask payload if masked
    if (frame->mask)
    {
        for (size_t i = 0; i < payload_length; i++)
        {
            frame->payload[i] ^= frame->masking_key[i % 4];
        }
    }

    // Null-terminate for string handling (optional)
    frame->payload[payload_length] = '\0';

    return current_pos + payload_length;
}

sock_err_t __resolve_ip(const char *hostname, char out_resolved_ip[INET_ADDRSTRLEN])
{
    __sock_debug("__resolve_ip");
    struct addrinfo hints, *res = NULL;
    char ip_address[INET_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(hostname, NULL, &hints, &res) != 0)
    {
        __sock_printerr("getaddrinfo failed with error: %d\n", WSAGetLastError());
        WSACleanup();
        return SOCK_ERR_FAILURE;
    }

    struct sockaddr_in *addr = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &addr->sin_addr, ip_address, sizeof(ip_address));

    memcpy(out_resolved_ip, ip_address, INET_ADDRSTRLEN);
    out_resolved_ip[INET_ADDRSTRLEN - 1] = '\0';

    freeaddrinfo(res);
    return SOCK_ERR_SUCCESS;
}

char *__encode_base64(const char *input)
{
    __sock_debug("encode_base64");
    size_t input_len = strlen(input);
    size_t output_len = 4 * ((input_len + 2) / 3);

    char *output = (char *)malloc(output_len + 1);
    if (output == NULL)
    {
        return NULL;
    }

    size_t i, j;
    for (i = 0, j = 0; i < input_len;)
    {
        uint32_t octet_a = i < input_len ? (unsigned char)input[i++] : 0;
        uint32_t octet_b = i < input_len ? (unsigned char)input[i++] : 0;
        uint32_t octet_c = i < input_len ? (unsigned char)input[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        output[j++] = __SOCK_B64_TABLE[(triple >> 18) & 0x3F];
        output[j++] = __SOCK_B64_TABLE[(triple >> 12) & 0x3F];
        output[j++] = __SOCK_B64_TABLE[(triple >> 6) & 0x3F];
        output[j++] = __SOCK_B64_TABLE[triple & 0x3F];
    }

    for (i = 0; i < __SOCK_B64_MOD_TABLE[input_len % 3]; i++)
    {
        output[output_len - 1 - i] = '=';
    }

    output[output_len] = '\0';
    return output;
}

sock_err_t __generate_b64_key(char out_buff[25])
{
    __sock_debug("__generate_b64_key");
    HCRYPTPROV crypt_prov;

    if (!CryptAcquireContext(&crypt_prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        __sock_printerr("Failed to acquire cryptographic provider context.\n");
        return SOCK_ERR_FAILURE;
    }

    const char *b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    BYTE random_bytes[22];

    if (!CryptGenRandom(crypt_prov, 22, random_bytes))
    {
        __sock_printerr("Failed to generate random numbers for b64 key.\n");
        CryptReleaseContext(crypt_prov, 0);
        return SOCK_ERR_FAILURE;
    }

    for (uint64_t i = 0; i < 22; ++i)
    {
        out_buff[i] = b[random_bytes[i] % 64];
    }

    out_buff[22] = '=';
    out_buff[23] = '=';
    out_buff[24] = '\0';

    CryptReleaseContext(crypt_prov, 0);
    return SOCK_ERR_SUCCESS;
}

sock_err_t socks_init()
{
    __sock_debug("socks_init");
    if (WSAStartup(MAKEWORD(2, 2), &__wsa_data) != 0)
    {
        __sock_printerr("WSAStartup failed with error: %d\n", WSAGetLastError());
        return SOCK_ERR_FAILURE;
    }
    return SOCK_ERR_SUCCESS;
}

void socks_end()
{
    __sock_debug("socks_end");
    WSACleanup();
}

sock_err_t sock_connect(
    const char *address,
    u_short port,
    const char *route,
    const char *username,
    const char *password,
    SOCK *out_socket)
{
    __sock_debug("sock_connect");

    (*out_socket) = (SOCK){
        .socket = (SOCKET)NULL,
        .recv_buffer = NULL,
        .recv_buff_count = 0,
        .messages_buffer = NULL,
        .messages_count = 0,
        .fragments_buffer = NULL,
        .fragments_count = 0,
        .connected = 1,
        .last_message_type = __SOCK_WS_OPCODE_TEXT,
    };

    if (address == NULL)
    {
        __sock_printerr("sock_connect failed, address is NULL.\n");
        return SOCK_ERR_ARGUMENTS;
    }

    __sock_debug("sock_connect:credentials");

    char *base64_credentials = NULL;
    if (username && password)
    {
        size_t cred_len = strlen(username) + strlen(password) + 2;
        char *credentials = malloc(cred_len);
        snprintf(credentials, cred_len, "%s:%s", username, password);

        base64_credentials = __encode_base64(credentials);
        free(credentials);
    }

    __sock_debug("sock_connect:socket");

    // Establish a connection using Winsock APIs
    out_socket->socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (out_socket->socket == INVALID_SOCKET)
    {
        __sock_printerr("sock_connect failed to create socket with error: %d\n", WSAGetLastError());
        return SOCK_ERR_FAILURE;
    }

    __sock_debug("sock_connect:addrinfo");
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    char ip_addr[INET_ADDRSTRLEN];
    __resolve_ip(address, ip_addr);
    inet_pton(AF_INET, ip_addr, &server_addr.sin_addr);

    __sock_debug("sock_connect:connect");
    if (connect(out_socket->socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
    {
        __sock_printerr("sock_connect failed to connect with error: %d\n", WSAGetLastError());
        closesocket(out_socket->socket);
        return SOCK_ERR_FAILURE;
    }

    // Generate key
    __sock_debug("sock_connect:generate key");
    char b64_key[25];
    sock_err_t err = __generate_b64_key(b64_key);
    if (err)
    {
        __sock_printerr("sock_connect failed to generate unique key.\n");
        closesocket(out_socket->socket);
        return SOCK_ERR_FAILURE;
    }

    // Create request
    __sock_debug("sock_connect:upgrade request");
    if (route == NULL)
    {
        route = "";
    }

    char auth_token[512];
    if (base64_credentials)
    {
        snprintf(auth_token, 512, "Authorization: %s\r\n", base64_credentials);
    }
    else
    {
        snprintf(auth_token, 2, "");
    }

    char request[1024];
    snprintf(request, 1024,
             "GET /%s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "%s"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Key: %s\r\n"
             "Sec-WebSocket-Version: 13\r\n\r\n",
             route, address, auth_token, b64_key);
    __sock_debug(request);

    // Send protocol switch request
    __sock_debug("sock_connect:send request");
    if (send(out_socket->socket, request, strlen(request), 0) == SOCKET_ERROR)
    {
        __sock_printerr("Send handshake failed with error: %d\n", WSAGetLastError());
        closesocket(out_socket->socket);
        return SOCK_ERR_FAILURE;
    }

    // Get response
    __sock_debug("sock_connect:recv request response");
    char response_buffer[1024];
    int bytes_read = recv(out_socket->socket, response_buffer, sizeof(response_buffer), 0);
    if (bytes_read == SOCKET_ERROR)
    {
        __sock_printerr("Handshake response receive failed with error: %d\n", WSAGetLastError());
        closesocket(out_socket->socket);
        return SOCK_ERR_FAILURE;
    }
    response_buffer[bytes_read] = '\0';

    // Check if protocol switch success
    __sock_debug("sock_connect:check request response");
    char *found = strstr(response_buffer, "101 Switching Protocols");
    if (found == NULL)
    {
        return SOCK_ERR_FAILURE;
    }

    // Set socket to non-blocking
    __sock_debug("sock_connect:set socket non-blocking");

    u_long mode = 1;
    ioctlsocket(out_socket->socket, FIONBIO, &mode);

    // Create recv buffer
    out_socket->recv_buffer = malloc(SOCKS_BUFFER_SIZE);

    out_socket->connected = 1;
    return SOCK_ERR_SUCCESS;
}

void sock_close(SOCK *s)
{
    __sock_debug("sock_close");

    if (s == NULL)
    {
        __sock_printerr("sock_close failed, SOCK is NULL.\n");
        return;
    }

    // Send close frame to server
    if (s->connected)
    {
        // TODO: Send close frame to server.
    }

    if (s->socket != (SOCKET)NULL)
    {
        closesocket(s->socket);
        s->socket = (SOCKET)NULL;
    }
    s->connected = 0;
}

int sock_has_data(SOCK *sock)
{
    return sock->messages_count > 0;
}

void __sock_make_message(
    SOCK *sock,
    __WS_FRAME *frame,
    __SOCK_WS_OPCODE_TYPE opcode,
    SOCK_MESSAGE *out_message)
{
    __sock_debug("__sock_make_message");

    __SOCK_WS_OPCODE_TYPE previous_type = sock->last_message_type;

    switch (opcode)
    {
    case __SOCK_WS_OPCODE_CONTINUATION:
        (*out_message) = (SOCK_MESSAGE){
            .message_binary = {
                .type = previous_type,
                .buffer = frame->payload,
                .length = frame->payload_length,
                .needs_freeing = 0,
            },
        };
        break;
    case __SOCK_WS_OPCODE_BINARY:
        (*out_message) = (SOCK_MESSAGE){
            .message_binary = {
                .type = SOCK_MESSAGE_BINARY,
                .buffer = frame->payload,
                .length = frame->payload_length,
                .needs_freeing = 0,
            },
        };
        break;
    case __SOCK_WS_OPCODE_TEXT:
        (*out_message) = (SOCK_MESSAGE){
            .message_text = {
                .type = SOCK_MESSAGE_TEXT,
                .buffer = (char *)frame->payload,
                .length = frame->payload_length,
                .needs_freeing = 0,
            },
        };
        break;
    case __SOCK_WS_OPCODE_CLOSE:
        // No close code nor reason
        if (frame->payload_length == 0)
        {
            (*out_message) = (SOCK_MESSAGE){
                .message_close_frame = {
                    .type = SOCK_MESSAGE_CLOSE,
                    .reason = NULL,
                    .close_code = 1005,
                },
            };
            break;
        }
        // Only close code
        else if (frame->payload_length == 2)
        {
            (*out_message) = (SOCK_MESSAGE){
                .message_close_frame = {
                    .type = SOCK_MESSAGE_CLOSE,
                    .reason = NULL,
                    .close_code = htons(*((uint16_t *)frame->payload)),
                },
            };
        }
        // Both close code and reason
        else
        {
            (*out_message) = (SOCK_MESSAGE){
                .message_close_frame = {
                    .type = SOCK_MESSAGE_CLOSE,
                    .reason = (char *)&frame->payload[2],
                    .close_code = htons(*((uint16_t *)frame->payload)),
                },
            };
        }
    default:
        __sock_printerr("Received message with opcode: %u\n", opcode);
        break;
    };
}

sock_err_t __sock_add_message(SOCK *s, __WS_FRAME *frame)
{
    __sock_debug("__sock_add_message");

    SOCK_MESSAGE msg = {
        .type = SOCK_MESSAGE_NONE,
    };

    if (frame->opcode != __SOCK_WS_OPCODE_CONTINUATION && (frame->opcode == __SOCK_WS_OPCODE_TEXT || frame->opcode == __SOCK_WS_OPCODE_BINARY))
    {
        s->last_message_type = frame->opcode;
    }

    __sock_make_message(s, frame, frame->opcode, &msg);

    if (msg.type == SOCK_MESSAGE_NONE)
    {
        __sock_printerr("Failed to create message of type %d.\n", frame->opcode);
        return SOCK_ERR_ARGUMENTS;
    }

    // Is fragment
    if (!frame->fin)
    {
        if (s->fragments_buffer == NULL)
        {
            s->fragments_buffer = malloc(sizeof(SOCK));

            if (s->fragments_buffer == NULL)
            {
                __sock_printerr("Failed to allocate space for message fragment buffer.\n");
                return SOCK_ERR_ALLOC;
            }

            s->fragments_count = 1;
            s->fragments_buffer[0] = msg;
        }
        else
        {
            s->fragments_count += 1;
            s->fragments_buffer = realloc(s->fragments_buffer,
                                          sizeof(SOCK) * s->fragments_count);

            if (s->fragments_buffer == NULL)
            {
                __sock_printerr("Failed to reallocate space for message fragment buffer.\n");
                return SOCK_ERR_ALLOC;
            }

            s->fragments_buffer[s->fragments_count - 1] = msg;
        }
    }
    else
    {
        PBYTE joined_fragments = NULL;
        uint64_t joined_fragments_len = 0;
        int is_utf8 = frame->opcode == __SOCK_WS_OPCODE_TEXT || (frame->opcode == __SOCK_WS_OPCODE_CONTINUATION && s->last_message_type == __SOCK_WS_OPCODE_TEXT);

        // Join message fragments
        if (s->fragments_count > 0)
        {
            for (uint64_t i = 0; i < s->fragments_count; ++i)
            {
                joined_fragments_len += s->fragments_buffer[i].message_binary.length;
            }

            uint64_t final_size = msg.message_binary.length + joined_fragments_len;
            joined_fragments = malloc(sizeof(BYTE) * final_size);

            if (joined_fragments == NULL)
            {
                __sock_printerr("Failed to allocate message from fragments.\n");
                return SOCK_ERR_ALLOC;
            }

            uint64_t write_ptr = 0;
            for (uint64_t i = 0; i < s->fragments_count; ++i)
            {
                uint64_t copy_size = s->fragments_buffer[i].message_binary.length;

                memcpy(&joined_fragments[write_ptr],
                       &s->fragments_buffer[i],
                       copy_size);

                write_ptr += copy_size;
            }

            memcpy(&joined_fragments[write_ptr],
                   msg.message_binary.buffer,
                   msg.message_binary.length);
            joined_fragments[final_size - 1] = '\0';

            msg.message_binary.buffer = joined_fragments;
            msg.message_binary.length = final_size;
            msg.message_binary.needs_freeing = 1;

            free(s->fragments_buffer);
            s->fragments_buffer = NULL;
            s->fragments_count = 0;
        }

        // First alloc
        if (s->messages_buffer == NULL)
        {
            s->messages_buffer = malloc(sizeof(SOCK));

            if (s->messages_buffer == NULL)
            {
                __sock_printerr("Failed to allocate space for message fragment buffer.\n");
                return SOCK_ERR_ALLOC;
            }

            s->messages_count = 1;
            s->messages_buffer[0] = msg;
        }
        // Subsequent allocs
        else
        {
            s->messages_count += 1;
            s->messages_buffer = realloc(s->messages_buffer,
                                         sizeof(SOCK) * s->messages_count);

            if (s->messages_buffer == NULL)
            {
                __sock_printerr("Failed to reallocate space for message fragment buffer.\n");
                return SOCK_ERR_ALLOC;
            }

            s->messages_buffer[s->messages_count - 1] = msg;
        }
    }
    return SOCK_ERR_SUCCESS;
}

sock_err_t __sock_get_message(SOCK *sock, SOCK_MESSAGE *out_message)
{
    __sock_debug("__sock_get_message");

    if (sock->messages_count == 0)
    {
        __sock_printerr("Failed to get message from empty buffer in __sock_get_message.\n");
        return SOCK_ERR_FAILURE;
    }

    // Assumes the message buffer is not empty
    (*out_message) = sock->messages_buffer[0];

    /*
        VISUALIZATION
        0, 1, 2, 3, 4, 5, END

        ITER 1
        1, 1, 2, 3, 4, 5, END

        ITER N
        1, 2, 3, 4, 5, 5, END
    */

    if (sock->messages_count == 1)
    {
        sock->messages_count = 0;
        free(sock->messages_buffer);
        sock->messages_buffer = NULL;
        return SOCK_ERR_SUCCESS;
    }

    // Shift all messages by 1 to the left
    for (uint64_t i = 0; i < sock->messages_count - 1; ++i)
    {
        SOCK_MESSAGE next = sock->messages_buffer[i + 1];
        sock->messages_buffer[i] = next;
    }

    // Realloc with new size
    sock->messages_count -= 1;
    sock->messages_buffer = realloc(sock->messages_buffer,
                                    sizeof(SOCK_MESSAGE) * sock->messages_count);

    if (sock->messages_buffer == NULL)
    {
        __sock_printerr("Failed to reallocate message buffer in __sock_get_message.\n");
        return SOCK_ERR_ALLOC;
    }
    return SOCK_ERR_SUCCESS;
}

sock_err_t sock_get_message(SOCK *sock, SOCK_MESSAGE *out_message)
{
    __sock_debug("sock_get_message");

    (*out_message) = (SOCK_MESSAGE){
        .type = SOCK_MESSAGE_NONE,
    };

    if (sock == NULL)
    {
        __sock_printerr("sock_get_message failed, SOCK is NULL.\n");
        return SOCK_ERR_ARGUMENTS;
    }

    if (!sock->connected)
    {
        __sock_printerr("sock_get_message failed, socket closed.\n");
        return SOCK_ERR_CONNECTION;
    }

    if (sock->messages_count == 0)
    {
        return SOCK_ERR_SUCCESS;
    }

    return __sock_get_message(sock, out_message);
}

void sock_free_message(SOCK_MESSAGE *message)
{
    __sock_debug("sock_free_message");

    if (message->type == SOCK_MESSAGE_TEXT || message->type == SOCK_MESSAGE_BINARY)
    {
        if (message->message_text.needs_freeing)
        {
            free(message->message_text.buffer);
            message->message_text.buffer = NULL;
            message->message_text.length = 0;
            message->message_text.needs_freeing = 0;
        }
    }
    else if (message->type == SOCK_MESSAGE_CLOSE)
    {
        free(&message->message_close_frame.reason[-2]);
        message->message_close_frame.close_code = 0;
    }
}

sock_err_t sock_send_text(SOCK *sock, const char *message)
{
    __sock_debug("sock_send_text");

    if (sock == NULL)
    {
        __sock_printerr("sock_send_text failed, SOCK is NULL.\n");
        return SOCK_ERR_ARGUMENTS;
    }

    if (!sock->connected)
    {
        __sock_printerr("sock_send_text failed, socket closed.\n");
        return SOCK_ERR_CONNECTION;
    }

    if (message == NULL)
    {
        __sock_printerr("sock_send_text failed, message is NULL.\n");
        return SOCK_ERR_ARGUMENTS;
    }

    uint64_t frame_len = strlen(message) + 15;
    char frame[frame_len];
    frame_len = __encode_text_frame(message, (unsigned char *)frame, frame_len, 1);

    if (send(sock->socket, (char *)frame, frame_len, 0) == SOCKET_ERROR)
    {
        int send_error = WSAGetLastError();

        if (send_error == WSAEWOULDBLOCK)
        {
            __sock_printerr("sock_send_text failed, error WSAEWOULDBLOCK, send buffer is full.\n");
        }
        else
        {
            __sock_printerr("sock_send_text failed, send returned error: %d\n", send_error);
        }
        return SOCK_ERR_FAILURE;
    }
    return SOCK_ERR_SUCCESS;
}

sock_err_t sock_send_binary(SOCK *sock, void *buffer, uint64_t buffer_size_bytes)
{
    __sock_debug("sock_send_binary");

    if (sock == NULL)
    {
        __sock_printerr("sock_send_binary failed, SOCK is NULL.\n");
        return SOCK_ERR_ARGUMENTS;
    }

    if (!sock->connected)
    {
        __sock_printerr("sock_send_binary failed, socket closed.\n");
        return SOCK_ERR_CONNECTION;
    }

    if (buffer == NULL)
    {
        __sock_printerr("sock_send_binary failed, message is NULL.\n");
        return SOCK_ERR_ARGUMENTS;
    }

    char frame[buffer_size_bytes + 15];
    uint64_t frame_len = __encode_text_frame((char *)buffer, (unsigned char *)frame, buffer_size_bytes, 1);

    if (send(sock->socket, (char *)frame, frame_len, 0) == SOCKET_ERROR)
    {
        int send_error = WSAGetLastError();

        if (send_error == WSAEWOULDBLOCK)
        {
            __sock_printerr("sock_send_binary failed, error WSAEWOULDBLOCK, send buffer is full.\n");
        }
        else
        {
            __sock_printerr("sock_send_binary failed, send returned error: %d\n", send_error);
        }
        return SOCK_ERR_FAILURE;
    }
    return SOCK_ERR_SUCCESS;
}

sock_err_t sock_poll(SOCK *sock)
{
    __sock_debug("sock_poll");

    if (sock == NULL)
    {
        __sock_printerr("sock_poll failed, SOCK is NULL.\n");
        return SOCK_ERR_ARGUMENTS;
    }

    if (!sock->connected)
    {
        __sock_printerr("sock_poll failed, socket closed.\n");
        return SOCK_ERR_CONNECTION;
    }

    int64_t available_buffer_count = SOCKS_BUFFER_SIZE - sock->recv_buff_count;

    if (available_buffer_count <= 0)
    {
        __sock_printerr("Failed to poll, not enough space in receive buffer.");
        return SOCK_ERR_FAILURE;
    }

    int64_t received_bytes_count = recv(sock->socket,
                                        &sock->recv_buffer[sock->recv_buff_count],
                                        available_buffer_count, 0);

    if (SOCKS_FLAG_DEBUG && !SOCKS_FLAG_SILENT)
    {
        printf("Available bytes: %llu\n", available_buffer_count);
        printf("Received bytes: %llu\n", received_bytes_count);
    }

    switch (received_bytes_count)
    {
    case SOCKET_ERROR:
        if (WSAGetLastError() == WSAEWOULDBLOCK)
        {
            __sock_debug("No data available.");
            return SOCK_ERR_SUCCESS;
        }
        else
        {
            __sock_printerr("Failed to poll with error: %d\n", WSAGetLastError());
            return SOCK_ERR_FAILURE;
        }

    case 0:
        __sock_printerr("Failed to poll, connection closed.\n");
        return SOCK_ERR_FAILURE;

    default:
        uint64_t previous_size = sock->recv_buff_count;
        sock->recv_buff_count += received_bytes_count;

        if (previous_size > sock->recv_buff_count)
        {
            __sock_printerr("Integer overflow in sock_poll\n");
            return SOCK_ERR_FAILURE;
        }

        while (sock->recv_buff_count > 0)
        {
            // Decode frame
            __WS_FRAME frame;
            int64_t decoded_bytes = __decode_websocket_frame((unsigned char *)sock->recv_buffer,
                                                             sock->recv_buff_count,
                                                             &frame);
            if (decoded_bytes == -1)
            {
                __sock_debug("Could not parse frame. This may indicate a buffer filed completely.\n");
                return SOCK_ERR_SUCCESS;
            }

            // Shift buffer left
            memmove(sock->recv_buffer,
                    &sock->recv_buffer[decoded_bytes],
                    sock->recv_buff_count - decoded_bytes);

            uint64_t previous_size = sock->recv_buff_count;
            sock->recv_buff_count -= decoded_bytes;

            if (previous_size < sock->recv_buff_count)
            {
                __sock_printerr("Integer underflow in sock_poll\n");
                return SOCK_ERR_FAILURE;
            }

            sock_err_t err = __sock_add_message(sock, &frame);
            if (err)
            {
                return SOCK_ERR_FAILURE;
            }
            __sock_debug("Added message to buffer.");
        }
        return SOCK_ERR_SUCCESS;
    }
    return SOCK_ERR_SUCCESS;
}