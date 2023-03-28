socks5-proxy-server
===================

This Perl code implements a SOCKS5 proxy server that listens for incoming connections and processes them in separate threads. The server takes four input parameters: `host`, `port`, `login`, and `password`.

When a client attempts to connect to the server, the server checks if the client supports any of the available authentication methods (no authentication or login/password authentication). If a suitable method is found, the server establishes a connection with the target server and begins forwarding data between the client and the target server.

The code uses the `IO::Select` module for working with sockets and the threads module for creating and managing threads. It includes several functions, including:

- `main`: the main function that creates threads for processing incoming connections.
- `replenish`: a function that creates additional threads if the number of free threads is less than the specified value.
- `new_client`: a function that handles incoming client connections and checks if the available authentication methods are supported by the client.
- `socks_auth`: a function that performs login and password authentication.
- `handle_client`: a function that establishes a connection with the target server and forwards data between the client and the target server.

This code includes the use of the following Perl modules: `IO::Select`, `Socket`, `threads`, `threads::shared`.

To run this code, enter the following command:
`perl socks5.pl host port login password`

Note that this code is designed for educational purposes and should not be used in production environments without proper modifications and security measures. 😊
