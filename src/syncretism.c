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
#include <signal.h>
#include <unistd.h>

#include "syncretism.h"

/* The label used for KMAC256() when deriving keys. */
#define SYNCRETISM_LABEL		"SYNCRETISM.KDF"

static void	signal_trap(int);
static void	signal_hdlr(int);
static void	signal_memfault(int);
static void	usage(const char *) __attribute__((noreturn));

/* Last received signal. */
volatile sig_atomic_t	sig_recv = -1;

/* Running as client or server? */
static int		client = -1;

/* For server mode, we can daemonize if we want too. */
static int		foreground = 1;

/* The path to the key file that is to be used. */
static const char	*keypath = NULL;

/* Syncretism version info from obj/version.c. */
extern const char	*syncretism_build_rev;
extern const char	*syncretism_build_date;

static void
usage(const char *reason)
{
	if (reason != NULL)
		printf("%s\n", reason);

	printf("Usage:\n");
	printf("  syncretism -s [options] [ip:port] [remote]\n");
	printf("  syncretism -c [options] [ip:port] [remote] [local]\n");
	printf("\n");
	printf("Options\n");
	printf("  -c       Run as a client\n");
	printf("  -s       Run as a server\n");
	printf("  -d       Daemonize server\n");
	printf("  -k       Absolute path to the shared secret\n");
	printf("  -v       Print version information\n");
	printf("  -p       Pid file when running as daemonized server\n");

	printf("\n");
	printf("Key files are 32-byte files consisting of cryptographically\n");
	printf("strong random data and can be generated from /dev/urandom.\n");
	printf("\n");
	printf("On the client side specify both the remote and local\n");
	printf("directories. For example, syncing the remote directory\n");
	printf("/home/cathedral to a local directory called backup-231021:\n");
	printf("\n");
	printf("  $ syncretism -c [options] 1.1.1.1:9191 "
	    "/home/cathedral backup-231021\n");
	printf("\n");
	printf("On the server side specify the root directory for all\n");
	printf("requests. The server will restrict clients from requesting\n");
	printf("file paths outside of the given root directory. For example\n");
	printf("serving /home/cathedral to all clients:\n");
	printf("\n");
	printf("  $ syncretism -s [options] 1.1.1.1:9191 /home/cathedral\n");
	printf("\n");

	exit(0);
}

int
main(int argc, char *argv[])
{
	int			ch;
	const char		*ip;
	u_int16_t		port;
	char			*p, *ep;
	const char		*pidfile;

	pidfile = NULL;

	while ((ch = getopt(argc, argv, "cdhk:p:sv")) != -1) {
		switch (ch) {
		case 'c':
			client = 1;
			break;
		case 'd':
			foreground = 0;
			break;
		case 'k':
			keypath = optarg;
			break;
		case 'p':
			pidfile = optarg;
			break;
		case 's':
			client = 0;
			break;
		case 'v':
			printf("syncretism %s %s\n", syncretism_build_rev,
			     syncretism_build_date);
			exit(0);
		case 'h':
		default:
			usage(NULL);
		}
	}

	argc -= optind;
	argv += optind;

	if (client == -1)
		usage("no server (-s) or client (-c) specified");

	if (keypath == NULL)
		usage("no key path (-k) has been set");

	if (argc == 0)
		usage("please specify an ip:port");

	if ((client == 1 && pidfile != NULL) ||
	    (client == 0 && pidfile != NULL && foreground == 1))
		usage("pidfile (-p) only valid for server mode (-s) with -d");

	if (client == 1 && argc != 3)
		usage("please specify remote and local directories");

	if (client == 0 && argc != 2)
		usage("server requires a single root directory");

	if (foreground == 0)
		openlog("syncretism", LOG_NDELAY | LOG_PID, LOG_DAEMON);

	if ((p = strchr(argv[0], ':')) == NULL)
		fatal("address must be in ip:port format");

	*(p)++ = '\0';
	ip = argv[0];

	errno = 0;
	port = strtoull(p, &ep, 10);
	if (errno != 0 || *ep != '\0' || port == 0)
		fatal("port '%s' invalid", p);

	signal_trap(SIGINT);
	signal_trap(SIGHUP);
	signal_trap(SIGCHLD);
	signal_trap(SIGQUIT);
	signal_trap(SIGTERM);
	signal_trap(SIGSEGV);

	nyfe_random_init();

	if (client) {
		if (foreground == 0)
			printf("-d has no effect in client mode\n");
		syncretism_client(ip, port, argv[1], argv[2]);
	} else {
		if (foreground == 0) {
			if (daemon(1, 1) == -1)
				fatal("daemon: %s", errno_s);
		}
		syncretism_server(ip, port, argv[1], pidfile);
	}

	return (0);
}

/*
 * Derive the TX and RX keys used for our communication with the peer.
 */
void
syncretism_derive_keys(struct conn *c, struct key *rx, struct key *tx,
    struct nyfe_agelas *rx_encap, struct nyfe_agelas *tx_encap)
{
	int			fd;
	struct nyfe_kmac256	kdf;
	u_int16_t		len;
	u_int8_t		ss[32], okm[256];

	PRECOND(c != NULL);
	PRECOND(rx != NULL);
	PRECOND(tx != NULL);
	PRECOND(rx_encap != NULL);
	PRECOND(tx_encap != NULL);

	if ((fd = open(keypath,  O_RDONLY)) == -1)
		fatal("failed to open syncretism key: %s", errno_s);

	nyfe_zeroize_register(ss, sizeof(ss));

	if (nyfe_file_read(fd, ss, sizeof(ss)) != sizeof(ss)) {
		nyfe_zeroize(ss, sizeof(ss));
		fatal("failed read syncretism shared secret");
	}

	(void)close(fd);

	nyfe_zeroize_register(okm, sizeof(okm));
	nyfe_zeroize_register(&kdf, sizeof(kdf));

	nyfe_kmac256_init(&kdf, ss, sizeof(ss),
	    SYNCRETISM_LABEL, sizeof(SYNCRETISM_LABEL) - 1);
	nyfe_zeroize(ss, sizeof(ss));

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
}

/*
 * Write all data to the given socket.
 */
void
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
			fatal("write error: %s ", errno_s);
		}

		off += ret;
	}
}

/*
 * Read the exact amount of bytes from the given socket.
 */
void
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

			if (errno == EWOULDBLOCK || errno == EAGAIN)
				fatal("read timeout");

			fatal("read error: %s", errno_s);
		}

		if (ret == 0)
			fatal("unexpected eof");

		off += ret;
	}
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
		if (client == 0)
			printf("[%d] ", getpid());
		vprintf(fmt, args);
		printf("\n");
	} else {
		vsyslog(prio, fmt, args);
	}
}

/*
 * Kill syncretism if we got interrupted by a signal.
 */
void
syncretism_signal_check(void)
{
	if (sig_recv != -1)
		fatal("interrupted by signal %d", sig_recv);
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
