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
#include <sys/socket.h>
#include <sys/wait.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <unistd.h>

#include "syncretism.h"

static void	server_pidfile_write(const char *);
static void	server_pidfile_unlink(const char *);

static void	server_reap_children(void);
static int	server_wait_and_fork(int, char *);

static void	server_send_random(struct conn *);
static void	server_recv_random(struct conn *);
static void	server_client_auth(struct conn *);
static void	server_perform_handshake(struct conn *);

static void	server_client_handle(struct conn *, char *);

/*
 * Bind to the given ip:port and handle incoming connections from our peer.
 */
void
syncretism_server(const char *ip, u_int16_t port, char *root, const char *pid)
{
	struct sockaddr_in	sin;
	int			fd, on;

	PRECOND(ip != NULL);
	PRECOND(port > 0);
	PRECOND(root != NULL);
	PRECOND(pid != NULL);

	syncretism_slash_strip(root);

	if (root[0] != '/')
		fatal("root directory must be an absolute path");

	if (chdir(root) == -1)
		fatal("chdir(%s): %s", root, errno_s);

	if (pid != NULL)
		server_pidfile_write(pid);

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	on = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == -1)
		fatal("setsockopt(SO_REUSEADDR): %s", errno_s);

	memset(&sin, 0, sizeof(sin));

	sin.sin_family = AF_INET;
	sin.sin_port = htobe16(port);
	sin.sin_addr.s_addr = inet_addr(ip);

	if (bind(fd, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		fatal("failed to bind to %s:%u: %s", ip, port, errno_s);

	if (listen(fd, 1) == -1)
		fatal("listen: %s", errno_s);

	syncretism_log(LOG_INFO, "started");

	for (;;) {
		if (server_wait_and_fork(fd, root) == -1)
			break;
	}

	syncretism_log(LOG_INFO, "exiting");

	if (pid != NULL)
		server_pidfile_unlink(pid);
}

/*
 * Accept a new client connection and setup a new child process for it.
 * Handles any reaping of kids too.
 */
static int
server_wait_and_fork(int fd, char *root)
{
	struct timeval		tv;
	struct pollfd		pfd;
	struct sockaddr_in	sin;
	pid_t			pid;
	socklen_t		sinlen;
	struct conn		client;
	int			cfd, nfd, sig;

	PRECOND(fd >= 0);
	PRECOND(root != NULL);

	pfd.fd = fd;
	pfd.events = POLLIN;

	for (;;) {
		if ((sig = syncretism_last_signal()) != -1) {
			if (sig == SIGCHLD) {
				server_reap_children();
				continue;
			}

			syncretism_log(LOG_INFO,
			    "interrupted by signal %d", sig);
			return (-1);
		}

		if ((nfd = poll(&pfd, 1, 1000)) == -1) {
			if (errno == EINTR)
				continue;
			fatal("poll: %s", errno_s);
		}

		if (nfd == 0)
			continue;

		sinlen = sizeof(sin);
		cfd = accept(fd, (struct sockaddr *)&sin, &sinlen);
		if (cfd == -1) {
			if (errno == EINTR)
				continue;
			fatal("accept4: %s", errno_s);
		}

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		if (setsockopt(cfd,
		    SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1)
			fatal("setsockopt(SO_RCVTIMEO): %s", errno_s);

		break;
	}

	if ((pid = fork()) == -1)
		fatal("fork: %s", errno_s);

	if (pid == 0) {
		/* Clears any pending signals from the parent. */
		(void)syncretism_last_signal();

		nyfe_zeroize_register(&client, sizeof(client));

		client.fd = cfd;
		server_perform_handshake(&client);
		server_client_handle(&client, root);
		nyfe_zeroize(&client, sizeof(client));

		syncretism_log(LOG_INFO, "sync completed");
		exit(0);
	}

	syncretism_log(LOG_INFO, "connection from %s:%u, pid=%d",
	    inet_ntoa(sin.sin_addr), be16toh(sin.sin_port), pid);

	close(cfd);

	return (0);
}

/*
 * Reap any child processes that may have exited.
 */
static void
server_reap_children(void)
{
	pid_t		pid;
	int		status;

	for (;;) {
		if ((pid = waitpid(-1, &status, WNOHANG)) == -1) {
			if (errno == ECHILD)
				break;
			if (errno == EINTR)
				continue;
			fatal("waitpid: %s", errno_s);
		}

		syncretism_log(LOG_INFO,
		    "child %d exited with %d", pid, status);
	}
}

/*
 * Handle a handshake with a client and then incoming messages.
 */
static void
server_client_handle(struct conn *c, char *root)
{
	struct file_entry	ent;
	struct file		*file;
	char			*path;
	size_t			rootlen;
	struct file_list	ours, theirs, update;

	PRECOND(c != NULL);
	PRECOND(root != NULL);

	path = NULL;
	rootlen = strlen(root);

	TAILQ_INIT(&ours);
	TAILQ_INIT(&theirs);
	TAILQ_INIT(&update);

	if ((path = syncretism_msg_read_string(c)) == NULL)
		fatal("client disconnected unexpectedly");

	if (strncmp(path, root, rootlen) || strstr(path, "../"))
		fatal("client requested path outside of root");

	if (chdir(path) == -1)
		fatal("failed to chdir to %s: %s", path, errno_s);

	free(path);

	for (;;) {
		syncretism_signal_check();

		if ((path = syncretism_file_entry_recv(c, &ent)) == NULL)
			break;

		syncretism_file_list_add(&theirs, path, &ent);
		free(path);
	}

	syncretism_file_list(&ours);
	syncretism_file_list_diff(&ours, &theirs, &update);

	TAILQ_FOREACH(file, &ours, list) {
		syncretism_signal_check();
		syncretism_file_send(c, file);
	}

	TAILQ_FOREACH(file, &update, list) {
		syncretism_signal_check();
		syncretism_file_send(c, file);
	}

	syncretism_file_done(c);

	syncretism_file_list_free(&ours);
	syncretism_file_list_free(&theirs);
	syncretism_file_list_free(&update);
}

/*
 * Perform the handshake to derive keys and authenticate the client.
 */
static void
server_perform_handshake(struct conn *c)
{
	struct timeval		tv;

	PRECOND(c != NULL);

	server_recv_random(c);
	server_send_random(c);

	syncretism_derive_keys(c, &c->rx, &c->tx, &c->rx_encap, &c->tx_encap);
	server_client_auth(c);

	/* client is now fully authed and we are on a secure channel. */
	tv.tv_sec = 60;
	tv.tv_usec = 0;

	if (setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1)
		fatal("setsockopt(SO_RCVTIMEO): %s", errno_s);
}

/*
 * Receive the client random data.
 */
static void
server_recv_random(struct conn *c)
{
	PRECOND(c != NULL);

	syncretism_read(c->fd, c->client_random, sizeof(c->client_random));
}

/*
 * Send our random data and challenge token to the client.
 */
static void
server_send_random(struct conn *c)
{
	PRECOND(c != NULL);

	nyfe_random_bytes(c->token, sizeof(c->token));
	nyfe_random_bytes(c->server_random, sizeof(c->server_random));

	syncretism_write(c->fd, c->server_random, sizeof(c->server_random));
	syncretism_write(c->fd, c->token, sizeof(c->token));
}

/*
 * Authenticate the client by verifying and decrypting the first
 * packet it sent us and making sure it contains our challenge.
 */
static void
server_client_auth(struct conn *c)
{
	struct msg	 *msg;

	PRECOND(c != NULL);

	msg = syncretism_msg_read(c);

	if (msg->length != sizeof(c->token))
		fatal("unexpected auth message size (%u)", msg->length);

	if (nyfe_mem_cmp(c->token, msg->data, sizeof(c->token)))
		fatal("client auth failed, token invalid");

	syncretism_msg_free(msg);

	syncretism_log(LOG_INFO, "client authenticated");
}

/*
 * Write our pid to the pidfile that was given by the user.
 */
static void
server_pidfile_write(const char *pidfile)
{
	int		fd;
	FILE		*fp;

	PRECOND(pidfile != NULL);

	/* Don't call fatal() here, we don't want to try and remove it. */
	if (access(pidfile, R_OK) != -1 && errno != ENOENT) {
		fprintf(stderr, "pidfile '%s' exists\n", pidfile);
		exit(1);
	}

	fd = nyfe_file_open(pidfile, NYFE_FILE_CREATE);

	if ((fp = fdopen(fd, "w")) == NULL)
		fatal("fdopen: %s", strerror(errno));

	(void)fprintf(fp, "%d", getpid());

	if (fclose(fp) != 0) {
		syncretism_log(LOG_NOTICE,
		    "close on pidfile failed: %s", errno_s);
	}
}

/*
 * Remove our pidfile from disk by unlinking it.
 */
static void
server_pidfile_unlink(const char *pidfile)
{
	PRECOND(pidfile != NULL);

	if (unlink(pidfile) == -1 && errno != ENOENT) {
		syncretism_log(LOG_NOTICE, "failed to remove pidfile '%s' (%s)",
		    pidfile, errno_s);
	}
}
