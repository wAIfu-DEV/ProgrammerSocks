# ProgrammerSocks
## C Websocket client library for Windows

ProgrammerSocks is a wrapper around the winsocks2 standard Windows library, making it easier to use.

## Example
```c
#include "ProgrammerSocks.h"

int main()
{
    // Initialize the library
    socks_init();

    // Connect to port 4263 of localhost
    SOCK sock;
    sock_connect("localhost", 4263, "route/socket", "username", "password", &sock);

    // Send messages to server
    sock_send_text(&sock, "This is a test text frame");

    // Check for new messages (non-blocking)
    while (!sock_poll(&sock))
    {
        // Check if we have new messages
        while (sock_has_data(&sock))
        {
            // Get message at front of queue
            SOCK_MESSAGE message;
            sock_get_message(&sock, &message);

            if (message.type == SOCK_MESSAGE_TEXT)
            {
                printf("%s\n", message.message_text.buffer);
            }
            // Free the memory allocated for the message
            sock_free_message(&message);
        }
    }
    // Close the connection and free memory allocated for socket
    sock_close(&sock);
    // Cleanup the library
    socks_end();
    return 0;
}
// This is an example with little to no error handling, for real-world usage see example.c
```

## Important

Only works on Windows 8+  
You need the compiler flag `-ladvapi32` for the library to compile correctly.

## TODO

- [x] Feed greg.
- [x] Stress test under heavy load send/receive.
- [ ] Send close frames on sock_close for graceful closure.
- [ ] More extensive tests with non-localhost connections.