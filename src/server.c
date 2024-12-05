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

#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>

#include "syncretism.h"

static int	server_send_random(struct conn *);
static int	server_recv_random(struct conn *);
static int	server_client_auth(struct conn *);
static int	server_perform_handshake(struct conn *);

static void	server_client_handle(struct conn *,
		    struct sockaddr_in *, char *);

/*
 * Bind to the given ip:port and handle incoming connections from our peer.
 */
void
syncretism_server(const char *ip, u_int16_t port, char *root)
{
	struct timeval		tv;
	struct sockaddr_in	sin;
	struct conn		client;
	socklen_t		sinlen;
	int			fd, on, sig;

	PRECOND(ip != NULL);
	PRECOND(port > 0);
	PRECOND(root != NULL);

	(void)signal(SIGPIPE, SIG_IGN);
	syncretism_slash_strip(root);

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

	for (;;) {
		if (chdir(root) == -1) {
			fatal("failed to change directory to %s: %s",
			    root, errno_s);
		}

		if ((sig = syncretism_last_signal()) != -1) {
			syncretism_log(LOG_NOTICE,
			    "interrupted by signal %d", sig);
			break;
		}

		sinlen = sizeof(sin);
		memset(&client, 0, sizeof(client));

		if ((client.fd = accept(fd,
		    (struct sockaddr *)&sin, &sinlen)) == -1)
			fatal("accept4: %s", errno_s);

		tv.tv_sec = 1;
		tv.tv_usec = 0;

		if (setsockopt(client.fd,
		    SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1)
			fatal("setsockopt(SO_RCVTIMEO): %s", errno_s);

		syncretism_log(LOG_INFO, "client from %s:%u",
		    inet_ntoa(sin.sin_addr), be16toh(sin.sin_port));

		nyfe_zeroize_register(&client, sizeof(client));

		if (server_perform_handshake(&client) == -1) {
			syncretism_log(LOG_INFO, "handshake failed with %s:%u",
			    inet_ntoa(sin.sin_addr), be16toh(sin.sin_port));
		} else {
			server_client_handle(&client, &sin, root);
		}

		nyfe_zeroize(&client, sizeof(client));
		close(client.fd);
	}
}

/*
 * Handle a handshake with a client and then incoming messages.
 */
static void
server_client_handle(struct conn *c, struct sockaddr_in *sin, char *root)
{
	int			sig;
	struct file		*file;
	size_t			rootlen;
	char			*path, *digest;
	struct file_list	ours, theirs, update;

	PRECOND(c != NULL);
	PRECOND(sin != NULL);
	PRECOND(root != NULL);

	path = NULL;
	digest = NULL;
	rootlen = strlen(root);

	TAILQ_INIT(&ours);
	TAILQ_INIT(&theirs);
	TAILQ_INIT(&update);

	if ((path = syncretism_msg_read_string(c)) == NULL) {
		syncretism_log(LOG_NOTICE,
		    "unexpected disconnect from %s:%u",
		    inet_ntoa(sin->sin_addr), be16toh(sin->sin_port));
		goto cleanup;
	}

	if (strncmp(path, root, rootlen) || strstr(path, "../")) {
		syncretism_log(LOG_NOTICE,
		    "requested path outside of root from %s:%u",
		    inet_ntoa(sin->sin_addr), be16toh(sin->sin_port));
		goto cleanup;
	}

	if (chdir(path) == -1) {
		syncretism_log(LOG_NOTICE,
		    "failed to chdir to %s for %s:%u (%s)", path,
		    inet_ntoa(sin->sin_addr), be16toh(sin->sin_port), errno_s);
		goto cleanup;
	}

	free(path);

	for (;;) {
		path = NULL;
		digest = NULL;

		if ((sig = syncretism_last_signal()) != -1) {
			syncretism_log(LOG_NOTICE,
			    "interrupted by signal %d", sig);
			goto cleanup;
		}

		if (syncretism_file_entry_recv(c, &path, &digest, NULL) == -1) {
			syncretism_log(LOG_NOTICE,
			    "unexpected disconnect from %s:%u",
			    inet_ntoa(sin->sin_addr), be16toh(sin->sin_port));
			goto cleanup;
		}

		if (!strcmp(path, "done") && !strcmp(digest, "-"))
			break;

		if (strstr(path, "../")) {
			syncretism_log(LOG_NOTICE, "malicous path from %s:%u",
			    inet_ntoa(sin->sin_addr), be16toh(sin->sin_port));
			goto cleanup;
		}

		syncretism_file_list_add(&theirs, path, digest);

		free(path);
		free(digest);
	}

	syncretism_file_list(&ours);
	syncretism_file_list_diff(&ours, &theirs, &update);

	TAILQ_FOREACH(file, &ours, list) {
		if ((sig = syncretism_last_signal()) != -1) {
			syncretism_log(LOG_NOTICE,
			    "interrupted by signal %d", sig);
			goto cleanup;
		}

		if (syncretism_file_send(c, file) == -1)
			goto cleanup;
	}

	TAILQ_FOREACH(file, &update, list) {
		if ((sig = syncretism_last_signal()) != -1) {
			syncretism_log(LOG_NOTICE,
			    "interrupted by signal %d", sig);
			goto cleanup;
		}

		if (syncretism_file_send(c, file) == -1)
			goto cleanup;
	}

	if (syncretism_file_done(c) == -1) {
		syncretism_log(LOG_NOTICE,
		    "failed to send done to %s:%u",
		    inet_ntoa(sin->sin_addr), be16toh(sin->sin_port));
		goto cleanup;
	}

cleanup:
	free(path);
	free(digest);

	syncretism_file_list_free(&ours);
	syncretism_file_list_free(&theirs);
	syncretism_file_list_free(&update);
}

/*
 * Perform the handshake to derive keys and authenticate the client.
 */
static int
server_perform_handshake(struct conn *c)
{
	struct timeval		tv;

	PRECOND(c != NULL);

	if (server_recv_random(c) == -1)
		return (-1);

	if (server_send_random(c) == -1)
		return (-1);

	if (syncretism_derive_keys(c, &c->rx, &c->tx,
	    &c->rx_encap, &c->tx_encap) == -1)
		return (-1);

	if (server_client_auth(c) == -1)
		return (-1);

	/* client is now fully authed and we are on a secure channel. */
	tv.tv_sec = 60;
	tv.tv_usec = 0;

	if (setsockopt(c->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1)
		fatal("setsockopt(SO_RCVTIMEO): %s", errno_s);

	return (0);
}

/*
 * Receive the client random data.
 */
static int
server_recv_random(struct conn *c)
{
	PRECOND(c != NULL);

	if (syncretism_read(c->fd,
	    c->client_random, sizeof(c->client_random)) == -1)
		return (-1);

	return (0);
}

/*
 * Send our random data and challenge token to the client.
 */
static int
server_send_random(struct conn *c)
{
	PRECOND(c != NULL);

	nyfe_random_bytes(c->token, sizeof(c->token));
	nyfe_random_bytes(c->server_random, sizeof(c->server_random));

	if (syncretism_write(c->fd,
	    c->server_random, sizeof(c->server_random)) == -1)
		return (-1);

	if (syncretism_write(c->fd, c->token, sizeof(c->token)) == -1)
		return (-1);

	return (0);
}

/*
 * Authenticate the client by verifying and decrypting the first
 * packet it sent us and making sure it contains our challenge.
 */
static int
server_client_auth(struct conn *c)
{
	struct msg	 *msg;

	PRECOND(c != NULL);

	if ((msg = syncretism_msg_read(c)) == NULL)
		return (-1);

	if (msg->length != sizeof(c->token)) {
		syncretism_msg_free(msg);
		return (-1);
	}

	if (nyfe_mem_cmp(c->token, msg->data, sizeof(c->token))) {
		syncretism_msg_free(msg);
		return (-1);
	}

	syncretism_msg_free(msg);

	return (0);
}
