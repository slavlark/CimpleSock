#include "cimplesock_server.h"
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>



// ---------------- //
//                  //
// TCP SERVER BLOCK //
//                  //
// ---------------- //



int cimsock_listen_tcp(const char* ip_address, int port, int prevent_port_lockout) {

    // 1) Create a socket using a syscall
    int tcp_socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    /* FOR FUTURE REFERENCE:
     *
     * 1.A) int socket_fd:
     *      Integer, index of the file descriptor array where the OS will store a pointer
     *      for the underlying TCP Control Block (the actual network struct) in protected kernel memory.
     *
     * 1.B) socket():
     *      Initiates a syscall to the OS kernel to allocate a new TCP Control Block
     *      and to wire it to our file descriptor index stored in int listening.
     *
     * 1.C) Argument AF_: (PF_ deprecated)
     *      AF_INET      - Address Family Internet v4 - IPv4 Address
     *      AF_INET6     - Address Family Internet v6 - IPv6 Address
     *      AF_UNIX      - Within Unix InterProcess Com - Bind into a file
     *      AF_PACKET    - (Linux only) - Catch all packets
     *      AF_BLUETOOTH - Bluetooth communication (L2CAP, RFCOMM protocols).
     *      AF_NETLINK   - (Linux only) ask kernel to read/write routing tables, firewall rules or interfaces.
     *      AF_ROUTE     - (macOS/BSD) The Apple/Unix Netlink - read/write to the system's routing table.
     *
     * 1.D) Argument SOCK_: (The Socket Type)
     *      SOCK_STREAM    - TCP: Reliable, two-way, connection-based endless byte stream (no message boundaries).
     *      SOCK_DGRAM     - UDP: Unreliable, connectionless datagrams (bounded messages, but lost/misordered packets).
     *      SOCK_RDM       - TCP/UDP Hybrid: Guaranteed Delivery, Not order.
     *      SOCK_SEQPACKET - SCTP: Like TCP, Reliable and sequenced, but with message boundaries (4G/5G or Bluetooth).
     *      SOCK_RAW       - Raw IP Packets: Bypasses TCP/UDP completely (custom pings or packet sniffing).
     *
     *      In linux kernel 2.6+, SOCK_TYPE can be combined with hardware-level behaviors using OR(|):
     *      SOCK_NONBLOCK  - non-blocking socket (Saves a separate, messy fcntl() syscall later).
     *      SOCK_CLOEXEC   - "Close on Exec", crashes or new process spawns kill the current socket.
     *      Example        - ..., SOCK_STREAM | SOCK_NONBLOCK, 0)
     *
     * 1.E) Argument IPROTO_: (Protocol for SOCK_)
     *      0 - Default Protocol given SOCK_.
     *      Every protocol has a hardcoded ID number:
     *      1  / IPPROTO_ICMP - ICMP
     *      6  / IPPROTO_TCP  - TCP
     *      17 / IPPROTO_UDP  - UDP
     *      Passing 0 tells the kernel to map SOCK_STREAM to protocol 6.
     *      Equivalent Examples:
     *      int sock_explicit = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
     *      int sock_literal  = socket(AF_INET, SOCK_STREAM, 6);
     */



    // 2) Handle socket creation errors
    if (tcp_socket_fd == -1) {
        perror("Unable to create a socket!");
        exit(EXIT_FAILURE);
    }

    /* FOR FUTURE REFERENCE:
     *
     * 2.A) IF socket_file_descriptor_index == -1:
     *      When the socket creation fails, CLib turns the index to -1 to show failure.
     *
     * 2.B) perror():
     *      Grabs the `errno` integer, translates it to a string and appends it to the passed string.
     *
     * 2.C) exit(EXIT_FAILURE):
     *      Instantly terminates the C process, OS kernel cleans up any leftover open file descriptors.
     */



    // 3) Prevent kernel port lockout
    if (prevent_port_lockout == 1) {
        if (setsockopt(tcp_socket_fd, SOL_SOCKET, SO_REUSEADDR, &prevent_port_lockout, sizeof(prevent_port_lockout)) == -1) {
            perror("Setsockopt SO_REUSEADDR failed!");
            close(tcp_socket_fd);
            exit(EXIT_FAILURE);
        }
    }

        /* FOR FUTURE REFERENCE:
     *
     * 3.A) IF prevent_port_lockout == 1:
     *      Only when the user correctly passes int = 1, will this prevent port-lockout.
     *      Bullshit values not tolerated as a hardening step to force default more secure lockout.
     *
     * 3.B.0) setsockopt():
     *      Configuration syscall that asks the kernel to modify the params, buffers or rules of an active TCPctl Block.
     *
     * 3.B.1) Argument 1 - File Descriptor Array Index for the Socket:
     *      Integer which is the index in target file descriptor that's pointing to the kernel resource to modify.
     *
     * 3.B.2) Argument 2 - Level:
     *      Specifies which subsystem or protocol layer handles the passed instruction.
     *      SOL_SOCKET   - Generic Socket Wrapper: Abstracted, Socket layer on top of the transport layer.
     *      IPPROTO_TCP  - TCP Transport Layer: Direct modification of the TCP reliable packet transmission.
     *      IPPROTO_UDP  - UDP Transport Layer: Direct modification of the UDP conectionless datagram streams.
     *      IPPROTO_IP   - IP  Network Layer: Settings dictating how raw routing packets treat physical hardware hops.
     *      SOL_PACKET   - (Linux Only, requires SOCK_RAW privilege) Link/Ethernet Layer - abstract OS net stack bypass.
     *                          Low level networking for injection or sniffing of MAC addresses or Ethernet frames.
     *
     * 3.B.3) Argument 3 - Option Name:
     *      The specific structural flag, limit or behavior option to modify + argument data type.
     *
     *      3.B.3) SOL_SOCKET - Generic Socket Wrapper:
     *          SO_REUSEADDR  - [int] Bypasses kernel TIME_WAIT port lockouts for rapid service restarts.
     *          SO_KEEPALIVE  - [int] Generates periodic TCP background pings to detect dead connections.
     *          SO_REUSEPORT  - [int] (Linux/BSD) Allows multiple processes to bind to the exact same port.
     *          SO_RCVBUF     - [int] Sets the kernel's incoming packet buffer size in bytes. Limits max unread data.
     *          SO_SNDBUF     - [int] Sets the kernel's outgoing packet buffer size in bytes. Limits max outbound queue.
     *          SO_BROADCAST  - [int] Grants UDP sockets permission to blast packets to a subnet broadcast address.
     *          SO_LINGER     - [struct linger] Dictates if close() blocks to cleanly flush data or drops it instantly.
     *          SO_RCVTIMEO   - [struct timeval] Forces blocking read operations (recv/read) to timeout in X seconds.
     *          SO_SNDTIMEO   - [struct timeval] Forces blocking write operations (send/write) to timeout in X seconds.
     *
     *       3.B.3) IPPROTO_TCP - TCP Transport Layer:
     *          TCP_NODELAY     - [int] Disables Nagle's Algorithm. Forces small packets onto the wire instantly.
     *          TCP_QUICKACK    - [int] (Linux Only) Kills TCP delayed-ACK behavior to force instant packet receipts.
     *          TCP_CORK        - [int] (Linux Only) Glues packets together into a single max-size chunk before sending.
     *          TCP_MAXSEG      - [int] Directly alters the Maximum Segment Size (MSS) allowed for packets (VPN tuners).
     *          TCP_KEEPIDLE    - [int] Duration of connection inactivity (seconds) before first KEEPALIVE ping fires.
     *
     *       3.B.3) IPPROTO_UDP - UDP Transport Layer:
     *          UDP_NO_CHECKSUM - [int] Disables checksum logic to shave off microsecond latency (potentially risky).
     *          UDP_GRO         - [int] Glues incoming packets together at the NIC level to slash CPU processing load.
     *
     *       3.B.3) IPPROTO_IP  - IP Network Layer:
     *          IP_TTL        - [int] Time-To-Live. Sets max router hops a packet can survive (Traceroute/Ping tools).
     *          IP_HDRINCL    - [int] "Header Include". Code will manually write IP headers (SOCK_RAW packet crafting).
     *
     *       3.B.3) SOL_PACKET - Link/Ethernet Layer:
     *          PACKET_ADD_MEMBERSHIP - [struct packet_mreq] Interface card set to Promiscuous Mode (packet sniffing).
     *
     * 3.B.4) Argument 4: (Option Value Memory Address)
     *      Memory address stored in a void pointer, leading to the memory address where the configuration value lives.
     *
     * 3.B.5) Argument 5: (Pointer Size)
     *      Size of the stored option parameter to accomodate int and struct options.
     *
     * 3.C) IF setsockopt == -1:
     *      When the socket option setting fails, CLib turns the index to -1 to show failure.
     *
     * 3.D) perror():
     *      Grabs the errno integer, translates it to a string and appends it to the passed string.
     *
     * 3.E) close(socket_fd):
     *      Syscall to cleanly release the allocated file descriptor index from our process table.
     *      Prevents system-wide resource/memory leaks if the application subsequently aborts.
     *
     * 3.F) exit(EXIT_FAILURE):
     *      Instantly terminates the C process, OS kernel cleans up any leftover open file descriptors.
     */



    // 4) Package the network address details
    struct sockaddr_in addr = {0};

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // Parse the provided ip string, validate and assign it into the sockaddr_in structure, the validate the result
    if (inet_pton(AF_INET, ip_address, &addr.sin_addr) <= 0) {
        perror("Invalid IP address format!");
        close(tcp_socket_fd);
        exit(EXIT_FAILURE);
    }

    /* FOR FUTURE REFERENCE:
     *
     * 4.A) struct sockaddr_in = {0};
     *      Internet socket address structure holding IPv4 addresses and ports. Set as 0 to ensure no leftover padding.
     *      Other interfaces like bluetooth, cellular or ipc require different structs: e.g. sockaddr_rc or sockaddr_un.
     *
     * 4.B) addr.sin_family = AF_INET:
     *      Specifies the address type as AF_INET = Address Family Internet (... Protocol v4), so 32bit IPv4 addresses.
     *
     * 4.C) addr.sin_port = htons(port);
     *      htons = Host-to-Network-Short. Converts the 16-bit int from OS's Little-Endian order to internet Big-Endian.
     *
     * 4.D.0) inet_pton():
     *      pton = Presentation-to-Network. Validates, then parses the provided string into a raw binary IP address.
     *
     * 4.D.1) Argument 1 - AF_INET:
     *      Specifies the address family type, IPv4 in this case, to cast and validate the string to.
     *      Only accepts AF_INET and AF_INET6, not other AF_ types listed in 1.C.
     *
     * 4.D.2) Argument 2 - ip_address:
     *      String containing the IPv4 address, encoded in the decimal, 4-sequence, dot-separated form: e.g. 127.0.0.1.
     *
     * 4.D.3) Argument 3 - &addr.sin_addr:
     *      Memory address of the location where the parsed, validated IP cast to a big-endian int32 should be stored.
     *
     * 4.E) IF inet_pton <= 0:
     *      inet_pton Returns 1 on success, returns <= 0 if the string format is incorrect or corrupt.
     *
     * 4.F) perror():
     *      Grabs the errno integer, translates it to a string and appends it to the passed string.
     *
     * 4.G) close(socket_fd):
     *      Syscall to cleanly release the allocated file descriptor index from our process table.
     *      Prevents system-wide resource/memory leaks if the application subsequently aborts.
     *
     * 4.H) exit(EXIT_FAILURE):
     *      Instantly terminates the C process, OS kernel cleans up any leftover open file descriptors.
     */



    // 5) Bind the socket to the IP and Port
    if (bind(tcp_socket_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("Bind failed! Port might be occupied or privilege escalation required.");
        close(tcp_socket_fd);
        exit(EXIT_FAILURE);
    }

    /* FOR FUTURE REFERENCE:
     *
     * 5.A) bind():
     *      Syscall that binds the socket_fd to the ip address and port, registered in the system network routing table.
     *
     * 5.A.1) Argument 1 - socket_fd:
     *      The target file descriptor index identifying our socket.
     *
     * 5.A.2) Argument 2 - ((struct sockaddr *)&addr):
     *      Memory address to the beginning of the sockaddr_in struct (obtained by &addr), cast to a generic sockaddr
     *      pointer type rather than sockaddr_in since void* did not exist. So tl;dr: Pointer to the address struct.
     *
     * 5.A.3) Argument 3 - sizeof(addr):
     *      Explicit size of the address structure so that we know how many bytes of memory to read after the pointer.
     *
     * 5.B) IF bind == -1:
     *      When the socket binding fails, CLib turns the index to -1 to show failure.
     *
     * 5.C) perror():
     *      Grabs the errno integer, translates it to a string and appends it to the passed string.
     *
     * 5.D) close(socket_fd):
     *      Syscall to cleanly release the allocated file descriptor index from our process table.
     *      Prevents system-wide resource/memory leaks if the application subsequently aborts.
     *
     * 5.E) exit(EXIT_FAILURE):
     *      Instantly terminates the C process, OS kernel cleans up any leftover open file descriptors.
     */



    // 6) Put the socket into passive, listening mode
    if (listen(tcp_socket_fd, SOMAXCONN) == -1) {
        perror("Listen failed!");
        close(tcp_socket_fd);
        exit(EXIT_FAILURE);
    }

    /* FOR FUTURE REFERENCE:
     *
     * 6.A.0) listen():
     *      This syscall commands the kernel to start answering incoming hardware connection handshakes.
     *
     * 6.A.1) Argument 1 - socket_fd:
     *      The file descriptor index identifying our socket that we want to transition into listening mode.
     *
     * 6.A.2) Argument 2 - SOMAXCONN:
     *      The maximum connection limit for the kernel's internal connection backlog queues, either number or SOMAXCONN.
     *
     * 6.B) IF listen == -1:
     *      When the socket listen setting fails, CLib turns the index to -1 to show failure.
     *
     * 6.C) perror():
     *      Grabs the errno integer, translates it to a string and appends it to the passed string.
     *
     * 6.D) close(socket_fd):
     *      Syscall to cleanly release the allocated file descriptor index from our process table.
     *      Prevents system-wide resource/memory leaks if the application subsequently aborts.
     *
     * 6.E) exit(EXIT_FAILURE):
     *      Instantly terminates the C process, OS kernel cleans up any leftover open file descriptors.
     */

    return tcp_socket_fd; // Return the fully configured listening TCP socket!
}



// ---------------- //
//                  //
// UDP SERVER BLOCK //
//                  //
// ---------------- //



int cimsock_bind_udp(const char* ip_address, int port, int prevent_port_lockout) {

    // 1) Create a socket using a syscall
    int udp_socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    /* FOR FUTURE REFERENCE:
     *
     * 1.A) int socket_fd:
     *      Integer, index of the file descriptor array where the OS will store a pointer
     *      for the underlying UDP Control Block (the actual network struct) in protected kernel memory.
     *
     * 1.B) socket():
     *      Initiates a syscall to the OS kernel to allocate a new UDP Control Block
     *      and to wire it to our file descriptor index stored in int listening.
     *
     * 1.C) Argument AF_: (PF_ deprecated)
     *      AF_INET      - Address Family Internet v4 - IPv4 Address
     *      AF_INET6     - Address Family Internet v6 - IPv6 Address
     *      AF_UNIX      - Within Unix InterProcess Com - Bind into a file
     *      AF_PACKET    - (Linux only) - Catch all packets
     *      AF_BLUETOOTH - Bluetooth communication (L2CAP, RFCOMM protocols).
     *      AF_NETLINK   - (Linux only) ask kernel to read/write routing tables, firewall rules or interfaces.
     *      AF_ROUTE     - (macOS/BSD) The Apple/Unix Netlink - read/write to the system's routing table.
     *
     * 1.D) Argument SOCK_: (The Socket Type)
     *      SOCK_STREAM    - TCP: Reliable, two-way, connection-based endless byte stream (no message boundaries).
     *      SOCK_DGRAM     - UDP: Unreliable, connectionless datagrams (bounded messages, but lost/misordered packets).
     *      SOCK_RDM       - TCP/UDP Hybrid: Guaranteed Delivery, Not order.
     *      SOCK_SEQPACKET - SCTP: Like TCP, Reliable and sequenced, but with message boundaries (4G/5G or Bluetooth).
     *      SOCK_RAW       - Raw IP Packets: Bypasses TCP/UDP completely (custom pings or packet sniffing).
     *
     *      In linux kernel 2.6+, SOCK_TYPE can be combined with hardware-level behaviors using OR(|):
     *      SOCK_NONBLOCK  - non-blocking socket (Saves a separate, messy fcntl() syscall later).
     *      SOCK_CLOEXEC   - "Close on Exec", crashes or new process spawns kill the current socket.
     *      Example        - ..., SOCK_DGRAM | SOCK_NONBLOCK, 0)
     *
     * 1.E) Argument IPROTO_: (Protocol for SOCK_)
     *      0 - Default Protocol given SOCK_.
     *      Every protocol has a hardcoded ID number:
     *      1  / IPPROTO_ICMP - ICMP
     *      6  / IPPROTO_TCP  - TCP
     *      17 / IPPROTO_UDP  - UDP
     *      Passing 0 tells the kernel to map SOCK_DGRAM to protocol 17.
     *      Equivalent Examples:
     *      int sock_explicit = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
     *      int sock_literal  = socket(AF_INET, SOCK_DGRAM, 17);
     */



    // 2) Handle socket creation errors
    if (udp_socket_fd == -1) {
        perror("Unable to create a socket!");
        exit(EXIT_FAILURE);
    }

    /* FOR FUTURE REFERENCE:
     *
     * 2.A) IF socket_file_descriptor_index == -1:
     *      When the socket creation fails, CLib turns the index to -1 to show failure.
     *
     * 2.B) perror():
     *      Grabs the `errno` integer, translates it to a string and appends it to the passed string.
     *
     * 2.C) exit(EXIT_FAILURE):
     *      Instantly terminates the C process, OS kernel cleans up any leftover open file descriptors.
     */



    // 3) Prevent kernel port lockout
    if (prevent_port_lockout == 1) {
        if (setsockopt(udp_socket_fd, SOL_SOCKET, SO_REUSEADDR, &prevent_port_lockout, sizeof(prevent_port_lockout)) == -1) {
            perror("Setsockopt SO_REUSEADDR failed!");
            close(udp_socket_fd);
            exit(EXIT_FAILURE);
        }
    }

    /* FOR FUTURE REFERENCE:
     *
     * 3.A) IF prevent_port_lockout == 1:
     *      Only when the user correctly passes int = 1, will this prevent port-lockout.
     *      Bullshit values not tolerated as a hardening step to force default more secure lockout.
     *
     * 3.B.0) setsockopt():
     *      Configuration syscall that asks the kernel to modify the params, buffers or rules of an active UDPctl Block.
     *
     * 3.B.1) Argument 1 - File Descriptor Array Index for the Socket:
     *      Integer which is the index in target file descriptor that's pointing to the kernel resource to modify.
     *
     * 3.B.2) Argument 2 - Level:
     *      Specifies which subsystem or protocol layer handles the passed instruction.
     *      SOL_SOCKET   - Generic Socket Wrapper: Abstracted, Socket layer on top of the transport layer.
     *      IPPROTO_TCP  - TCP Transport Layer: Direct modification of the TCP reliable packet transmission.
     *      IPPROTO_UDP  - UDP Transport Layer: Direct modification of the UDP conectionless datagram streams.
     *      IPPROTO_IP   - IP  Network Layer: Settings dictating how raw routing packets treat physical hardware hops.
     *      SOL_PACKET   - (Linux Only, requires SOCK_RAW privilege) Link/Ethernet Layer - abstract OS net stack bypass.
     *                          Low level networking for injection or sniffing of MAC addresses or Ethernet frames.
     *
     * 3.B.3) Argument 3 - Option Name:
     *      The specific structural flag, limit or behavior option to modify + argument data type.
     *
     *      3.B.3) SOL_SOCKET - Generic Socket Wrapper:
     *          SO_REUSEADDR  - [int] Bypasses kernel TIME_WAIT port lockouts for rapid service restarts.
     *          SO_KEEPALIVE  - [int] Generates periodic TCP background pings to detect dead connections.
     *          SO_REUSEPORT  - [int] (Linux/BSD) Allows multiple processes to bind to the exact same port.
     *          SO_RCVBUF     - [int] Sets the kernel's incoming packet buffer size in bytes. Limits max unread data.
     *          SO_SNDBUF     - [int] Sets the kernel's outgoing packet buffer size in bytes. Limits max outbound queue.
     *          SO_BROADCAST  - [int] Grants UDP sockets permission to blast packets to a subnet broadcast address.
     *          SO_LINGER     - [struct linger] Dictates if close() blocks to cleanly flush data or drops it instantly.
     *          SO_RCVTIMEO   - [struct timeval] Forces blocking read operations (recv/read) to timeout in X seconds.
     *          SO_SNDTIMEO   - [struct timeval] Forces blocking write operations (send/write) to timeout in X seconds.
     *
     *       3.B.3) IPPROTO_TCP - TCP Transport Layer:
     *          TCP_NODELAY     - [int] Disables Nagle's Algorithm. Forces small packets onto the wire instantly.
     *          TCP_QUICKACK    - [int] (Linux Only) Kills TCP delayed-ACK behavior to force instant packet receipts.
     *          TCP_CORK        - [int] (Linux Only) Glues packets together into a single max-size chunk before sending.
     *          TCP_MAXSEG      - [int] Directly alters the Maximum Segment Size (MSS) allowed for packets (VPN tuners).
     *          TCP_KEEPIDLE    - [int] Duration of connection inactivity (seconds) before first KEEPALIVE ping fires.
     *
     *       3.B.3) IPPROTO_UDP - UDP Transport Layer:
     *          UDP_NO_CHECKSUM - [int] Disables checksum logic to shave off microsecond latency (potentially risky).
     *          UDP_GRO         - [int] Glues incoming packets together at the NIC level to slash CPU processing load.
     *
     *       3.B.3) IPPROTO_IP  - IP Network Layer:
     *          IP_TTL        - [int] Time-To-Live. Sets max router hops a packet can survive (Traceroute/Ping tools).
     *          IP_HDRINCL    - [int] "Header Include". Code will manually write IP headers (SOCK_RAW packet crafting).
     *
     *       3.B.3) SOL_PACKET - Link/Ethernet Layer:
     *          PACKET_ADD_MEMBERSHIP - [struct packet_mreq] Interface card set to Promiscuous Mode (packet sniffing).
     *
     * 3.B.4) Argument 4: (Option Value Memory Address)
     *      Memory address stored in a void pointer, leading to the memory address where the configuration value lives.
     *
     * 3.B.5) Argument 5: (Pointer Size)
     *      Size of the stored option parameter to accomodate int and struct options.
     *
     * 3.C) IF setsockopt == -1:
     *      When the socket option setting fails, CLib turns the index to -1 to show failure.
     *
     * 3.D) perror():
     *      Grabs the errno integer, translates it to a string and appends it to the passed string.
     *
     * 3.E) close(socket_fd):
     *      Syscall to cleanly release the allocated file descriptor index from our process table.
     *      Prevents system-wide resource/memory leaks if the application subsequently aborts.
     *
     * 3.F) exit(EXIT_FAILURE):
     *      Instantly terminates the C process, OS kernel cleans up any leftover open file descriptors.
     */



    // 4) Package the network address details
    struct sockaddr_in addr = {0};

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // Parse the provided ip string, validate and assign it into the sockaddr_in structure, the validate the result
    if (inet_pton(AF_INET, ip_address, &addr.sin_addr) <= 0) {
        perror("Invalid IP address format!");
        close(udp_socket_fd);
        exit(EXIT_FAILURE);
    }

    /* FOR FUTURE REFERENCE:
     *
     * 4.A) struct sockaddr_in = {0};
     *      Internet socket address structure holding IPv4 addresses and ports. Set as 0 to ensure no leftover padding.
     *      Other interfaces like bluetooth, cellular or ipc require different structs: e.g. sockaddr_rc or sockaddr_un.
     *
     * 4.B) addr.sin_family = AF_INET:
     *      Specifies the address type as AF_INET = Address Family Internet (... Protocol v4), so 32bit IPv4 addresses.
     *
     * 4.C) addr.sin_port = htons(port);
     *      htons = Host-to-Network-Short. Converts the 16-bit int from OS's Little-Endian order to internet Big-Endian.
     *
     * 4.D.0) inet_pton():
     *      pton = Presentation-to-Network. Validates, then parses the provided string into a raw binary IP address.
     *
     * 4.D.1) Argument 1 - AF_INET:
     *      Specifies the address family type, IPv4 in this case, to cast and validate the string to.
     *      Only accepts AF_INET and AF_INET6, not other AF_ types listed in 1.C.
     *
     * 4.D.2) Argument 2 - ip_address:
     *      String containing the IPv4 address, encoded in the decimal, 4-sequence, dot-separated form: e.g. 127.0.0.1.
     *
     * 4.D.3) Argument 3 - &addr.sin_addr:
     *      Memory address of the location where the parsed, validated IP cast to a big-endian int32 should be stored.
     *
     * 4.E) IF inet_pton <= 0:
     *      inet_pton Returns 1 on success, returns <= 0 if the string format is incorrect or corrupt.
     *
     * 4.F) perror():
     *      Grabs the errno integer, translates it to a string and appends it to the passed string.
     *
     * 4.G) close(socket_fd):
     *      Syscall to cleanly release the allocated file descriptor index from our process table.
     *      Prevents system-wide resource/memory leaks if the application subsequently aborts.
     *
     * 4.H) exit(EXIT_FAILURE):
     *      Instantly terminates the C process, OS kernel cleans up any leftover open file descriptors.
     */



    // 5) Bind the socket to the IP and Port
    if (bind(udp_socket_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("Bind failed! Port might be occupied or privilege escalation required.");
        close(udp_socket_fd);
        exit(EXIT_FAILURE);
    }


    /* FOR FUTURE REFERENCE:
     *
     * 5.A) bind():
     *      Syscall that binds the socket_fd to the ip address and port, registered in the system network routing table.
     *
     * 5.A.1) Argument 1 - socket_fd:
     *      The target file descriptor index identifying our socket.
     *
     * 5.A.2) Argument 2 - ((struct sockaddr *)&addr):
     *      Memory address to the beginning of the sockaddr_in struct (obtained by &addr), cast to a generic sockaddr
     *      pointer type rather than sockaddr_in since void* did not exist. So tl;dr: Pointer to the address struct.
     *
     * 5.A.3) Argument 3 - sizeof(addr):
     *      Explicit size of the address structure so that we know how many bytes of memory to read after the pointer.
     *
     * 5.B) IF bind == -1:
     *      When the socket binding fails, CLib turns the index to -1 to show failure.
     *
     * 5.C) perror():
     *      Grabs the errno integer, translates it to a string and appends it to the passed string.
     *
     * 5.D) close(socket_fd):
     *      Syscall to cleanly release the allocated file descriptor index from our process table.
     *      Prevents system-wide resource/memory leaks if the application subsequently aborts.
     *
     * 5.E) exit(EXIT_FAILURE):
     *      Instantly terminates the C process, OS kernel cleans up any leftover open file descriptors.
     */



    /* FOR FUTURE REFERENCE:
     * There is no listening on UDP, recall that it's connectionless.
     */

    return udp_socket_fd; // Return the fully configured bound UDP socket!
}