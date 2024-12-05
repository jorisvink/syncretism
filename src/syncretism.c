/*
 * Copyright (c) 2024 Joris Vink <joris@sanctorum.se>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include "syncretism.h"

/* The label used for KMAC256() when deriving keys. */
#define SYNCRETISM_LABEL		"SYNCRETISM.KDF"

static void		signal_trap(int);
static void		signal_hdlr(int);
static void		signal_memfault(int);

/* Last received signal. */
volatile sig_atomic_t	sig_recv = -1;

/* For server mode, we can daemonize if we want too. */
static int		foreground = 1;

/* The path to the key file that is to be used. */
static const char	*keypath = NULL;

int
main(int argc, char *argv[])
{
	const char		*ip;
	u_int16_t		port;
	int			ch, client;

	port = 0;
	ip = NULL;
	client = -1;

	while ((ch = getopt(argc, argv, "cdi:k:p:s")) != -1) {
		switch (ch) {
		case 'c':
			client = 1;
			break;
		case 'd':
			foreground = 0;
			break;
		case 'i':
			ip = optarg;
			break;
		case 'k':
			keypath = optarg;
			break;
		case 'p':
			/* XXX */
			port = atoi(optarg);
			break;
		case 's':
			client = 0;
			break;
		}
	}

	argc -= optind;
	argv += optind;

	if (client == -1)
		fatal("no server (-s) or client (-c) specified");

	if (keypath == NULL)
		fatal("no key path (-k) has been set");

	if (ip == NULL)
		fatal("no ip (-i) has been set");

	if (client == 0 && port == 0)
		fatal("no port (-p) has been set");

	if (client == 1 && argc != 2)
		fatal("please specify remote and local directories");

	if (client == 0 && argc != 1)
		fatal("server requires a single root directory");

	if (foreground == 0)
		openlog("syncretism", LOG_NDELAY | LOG_PID, LOG_DAEMON);

	signal_trap(SIGINT);
	signal_trap(SIGHUP);
	signal_trap(SIGCHLD);
	signal_trap(SIGQUIT);
	signal_trap(SIGTERM);
	signal_trap(SIGSEGV);

	nyfe_random_init();

	if (client) {
		syncretism_client(ip, port, argv[0], argv[1]);
	} else {
		syncretism_server(ip, port, argv[0]);
	}

	return (0);
}

/*
 * Derive the TX and RX keys used for our communication with the peer.
 */
int
syncretism_derive_keys(struct conn *c, struct key *rx, struct key *tx,
    struct nyfe_agelas *rx_encap, struct nyfe_agelas *tx_encap)
{
	int			fd;
	struct nyfe_kmac256	kdf;
	u_int16_t		len;
	u_int8_t		key[32], okm[256];

	PRECOND(c != NULL);
	PRECOND(rx != NULL);
	PRECOND(tx != NULL);
	PRECOND(rx_encap != NULL);
	PRECOND(tx_encap != NULL);

	if ((fd = open(keypath,  O_RDONLY)) == -1) {
		syncretism_log(LOG_NOTICE,
		    "failed to open syncretism key: %s", errno_s);
		return (-1);
	}

	nyfe_zeroize_register(key, sizeof(key));

	if (nyfe_file_read(fd, key, sizeof(key)) != sizeof(key)) {
		(void)close(fd);
		nyfe_zeroize(key, sizeof(key));
		syncretism_log(LOG_NOTICE, "failed read syncretism key");
		return (-1);
	}

	(void)close(fd);

	nyfe_zeroize_register(okm, sizeof(okm));
	nyfe_zeroize_register(&kdf, sizeof(kdf));

	nyfe_kmac256_init(&kdf, key, sizeof(key),
	    SYNCRETISM_LABEL, sizeof(SYNCRETISM_LABEL) - 1);
	nyfe_zeroize(key, sizeof(key));

	len = htobe16(sizeof(okm));

	nyfe_kmac256_update(&kdf, &len, sizeof(len));
	nyfe_kmac256_update(&kdf, c->server_random, sizeof(c->server_random));
	nyfe_kmac256_update(&kdf, c->client_random, sizeof(c->client_random));
	nyfe_kmac256_final(&kdf, okm, sizeof(okm));
	nyfe_zeroize(&kdf, sizeof(kdf));

	nyfe_memcpy(rx->key, okm, sizeof(rx->key));
	nyfe_memcpy(tx->key, &okm[sizeof(rx->key)], sizeof(tx->key));

	nyfe_agelas_init(rx_encap,
	    &okm[sizeof(rx->key) + sizeof(tx->key)], 64);
	nyfe_agelas_init(tx_encap,
	    &okm[sizeof(rx->key) + sizeof(tx->key) + 64], 64);

	nyfe_zeroize(okm, sizeof(okm));

	rx->nonce = 1;
	tx->nonce = 1;

	return (0);
}

/*
 * Write all data to the given socket.
 */
int
syncretism_write(int fd, const void *data, size_t len)
{
	size_t			off;
	ssize_t			ret;
	const u_int8_t		*ptr;

	PRECOND(fd >= 0);
	PRECOND(data != NULL);

	off = 0;
	ptr = data;

	while (off != len) {
		if ((ret = write(fd, ptr + off, len - off)) == -1) {
			if (errno == EINTR)
				continue;

			syncretism_log(LOG_INFO, "write: %s ", errno_s);
			return (-1);
		}

		off += ret;
	}

	return (0);
}

/*
 * Read the exact amount of bytes from the given socket.
 */
int
syncretism_read(int fd, void *data, size_t len)
{
	size_t		off;
	ssize_t		ret;
	u_int8_t	*ptr;

	PRECOND(fd >= 0);
	PRECOND(data != NULL);

	off = 0;
	ptr = data;

	while (off != len) {
		if ((ret = read(fd, ptr + off, len - off)) == -1) {
			if (errno == EINTR)
				continue;

			if (errno == EWOULDBLOCK || errno == EAGAIN) {
				syncretism_log(LOG_NOTICE, "read timeout");
			} else {
				syncretism_log(LOG_INFO, "read: %s", errno_s);
			}

			return (-1);
		}

		if (ret == 0) {
			syncretism_log(LOG_INFO, "read: eof");
			return (-1);
		}

		off += ret;
	}

	return (0);
}

/*
 * Strip any potential trailing slashes from given path.
 */
void
syncretism_slash_strip(char *path)
{
	size_t		len;

	PRECOND(path != NULL);

	len = strlen(path);

	while (len > 0 && path[len - 1] == '/') {
		len--;
		path[len] = '\0';
	}
}

/*
 * Log a thing to tty or syslog.
 */
void
syncretism_log(int prio, const char *fmt, ...)
{
	va_list		args;

	va_start(args, fmt);
	syncretism_logv(prio, fmt, args);
	va_end(args);
}

/*
 * Log a thing to tty or syslog.
 */
void
syncretism_logv(int prio, const char *fmt, va_list args)
{
	if (foreground) {
		vprintf(fmt, args);
		printf("\n");
	} else {
		vsyslog(prio, fmt, args);
	}
}

/*
 * Returns the last received signal to the caller and resets sig_recv.
 */
int
syncretism_last_signal(void)
{
	int	sig;

	sig = sig_recv;
	sig_recv = -1;

	return (sig);
}

/*
 * Something went very wrong and we need to abort.
 */
void
fatal(const char *fmt, ...)
{
	va_list		args;

	nyfe_zeroize_all();

	va_start(args, fmt);
	syncretism_logv(LOG_ERR, fmt, args);
	va_end(args);

	exit(1);
}

/*
 * Let the given signal be caught by our signal handler.
 */
static void
signal_trap(int sig)
{
	struct sigaction	sa;

	memset(&sa, 0, sizeof(sa));

	if (sig == SIGSEGV)
		sa.sa_handler = signal_memfault;
	else
		sa.sa_handler = signal_hdlr;

	if (sigfillset(&sa.sa_mask) == -1)
		fatal("sigfillset: %s", errno_s);

	if (sigaction(sig, &sa, NULL) == -1)
		fatal("sigaction: %s", errno_s);
}

/*
 * Our signal handler, doesn't do much more than set sig_recv so it can
 * be obtained by syncretism_last_signal().
 */
static void
signal_hdlr(int sig)
{
	sig_recv = sig;
}

/*
 * The signal handler for when a segmentation fault occurred, we are
 * catching this so we can just cleanup before dying.
 */
static void
signal_memfault(int sig)
{
	nyfe_zeroize_all();
	abort();
}
