// Uncomment to print a stack trace
// #define SOCKS_FLAG_DEBUG 1

// Uncomment to remove all print statements
// #define SOCKS_FLAG_SILENT 1

// Sets the size in bytes of the receive buffer
// #define SOCKS_BUFFER_SIZE 2097152

#include "ProgrammerSocks.h"

int main()
{
    socks_init();

    // Connect to port 4263 of localhost
    SOCK sock;
    sock_err_t err = sock_connect("localhost", 4263, NULL, NULL, NULL, &sock);
    if (err)
    {
        printf("Failed to connect with error: %d\n", err);
        return 1;
    }

    sock_send_text(&sock, "This is a test text frame");
    sock_send_binary(&sock, "This is a test binary frame", sizeof("This is a test binary frame"));

    while (!sock_poll(&sock))
    {
        printf("Polled %llu messages.\n", sock.messages_count);
        while (sock_has_data(&sock))
        {
            SOCK_MESSAGE message;
            sock_err_t err = sock_get_message(&sock, &message);

            if (err)
            {
                printf("Failed to receive message with error: %d\n", err);
                return 1;
            }

            switch (message.type)
            {
            case SOCK_MESSAGE_NONE:
                printf("Received no messages.\n");
                break;
            case SOCK_MESSAGE_CLOSE:
                printf("Received close frame: %llu %s\n",
                       message.message_close_frame.close_code,
                       message.message_close_frame.reason);
                sock_close(&sock);
                socks_end();
                return 0;
            case SOCK_MESSAGE_TEXT:
                printf("Received: %s\n", message.message_text.buffer);
                sock_free_message(&message);
                break;
            case SOCK_MESSAGE_BINARY:
                printf("Received binary message.\n");
                break;

            default:
                break;
            }
        }
    }

    printf("Broke out of main loop.\n");
    sock_close(&sock);
    socks_end();
    return 0;
}
