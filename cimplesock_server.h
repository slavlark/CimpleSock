#ifndef CIMPLESOCK_SERVER_H
#define CIMPLESOCK_SERVER_H

/* Macros CAPITALISED with CIMSOCK_ prefix
 * Functions use snake_case, public have cimsock_ prefix
 * Variables use snake_case
 */

// If this is being read by a C++ compiler, flag that this is a pure C library.
#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* * =========================================================================
 * MACROS & DEFAULTS
 * =========================================================================
 */
#define CIMSOCK_DEFAULT_PORT 8080
#define CIMSOCK_DEFAULT_ADDRESS "127.0.0.1"

#define cimsock_listen_tcp_default(void) cimsock_listen_tcp(CIMSOCK_DEFAULT_ADDRESS, CIMSOCK_DEFAULT_PORT, 1)
#define cimsock_bind_udp_default(void) cimsock_bind_udp(CIMSOCK_DEFAULT_ADDRESS, CIMSOCK_DEFAULT_PORT, 1)

/* * =========================================================================
 * CORE ENGINE API
 * =========================================================================
 */

/**
 * @brief Create a listening TCP Socket ready to start accepting connections.
 *
 * @param ip_address            The target IPv4 string literal (e.g. "127.0.0.1").
 * @param port                  The target hardware port number (e.g. 8080).
 * @param prevent_port_lockout  Strict boolean flag (1 = Active, 0 = Port Locked).
 * @return int                  The allocated system file descriptor index
 *      or terminates the process entirely on a fatal syscall failure, haha.
 */

int cimsock_listen_tcp(const char* ip_address, int port, int prevent_port_lockout);



/**
 * @brief Create a bound UDP Socket ready to start processing datagrams.
 *
 * @param ip_address            The target IPv4 string literal (e.g. "127.0.0.1").
 * @param port                  The target hardware port number (e.g. 8080).
 * @param prevent_port_lockout  Strict boolean flag (1 = Active, 0 = Port Locked).
 * @return int                  The allocated system file descriptor index
 *      or terminates the process entirely on a fatal syscall failure, haha.
 */

int cimsock_bind_udp(const char* ip_address, int port, int prevent_port_lockout);


/* * =========================================================================
 * INLINES
 * =========================================================================
 */

/**
 * @brief [DEFAULT PARAMS] Create a listening TCP Socket ready to start accepting connections.
 * * Automatically binds to 127.0.0.1 on port 8080 with port-lockout prevention active.
 * * @return int The allocated system file descriptor index.
 */
static inline int cimsock_listen_tcp_defaults(void) {
 return cimsock_listen_tcp(CIMSOCK_DEFAULT_ADDRESS, CIMSOCK_DEFAULT_PORT, 1);
}

/**
 * @brief [DEFAULT PARAMS] Create a bound UDP Socket ready to start processing datagrams.
 * * Automatically binds to 127.0.0.1 on port 8080 with port-lockout prevention active.
 * * @return int The allocated system file descriptor index.
 */
static inline int cimsock_bind_udp_defaults(void) {
 return cimsock_bind_udp(CIMSOCK_DEFAULT_ADDRESS, CIMSOCK_DEFAULT_PORT, 1);
}

// If this is being read by a C++ compiler, close the compatibility gate
#ifdef __cplusplus
}
#endif// __cplusplus

#endif // CIMPLESOCK_SERVER_H