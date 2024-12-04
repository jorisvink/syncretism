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
#include <time.h>

#include "syncretism.h"

static int	server_send_random(struct conn *);
static int	server_recv_random(struct conn *);
static int	server_client_auth(struct conn *);
static int	server_perform_handshake(struct conn *);

static void	server_client_handle(struct conn *,
		    struct sockaddr_in *, const char *, char **);

/*
 * Bind to the given ip:port and handle incoming connections from our peer.
 */
void
syncretism_server(const char *ip, u_int16_t port, const char *root, char **argv)
{
	struct timeval		tv;
	struct sockaddr_in	sin;
	struct conn		client;
	socklen_t		sinlen;
	int			fd, on;

	PRECOND(ip != NULL);
	PRECOND(port > 0);
	PRECOND(root != NULL);
	PRECOND(argv != NULL);

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

		syncretism_log(LOG_INFO, "client from %s",
		    inet_ntoa(sin.sin_addr));

		nyfe_zeroize_register(&client, sizeof(client));
		server_client_handle(&client, &sin, root, argv);
		nyfe_zeroize(&client, sizeof(client));

		close(client.fd);
	}
}

/*
 * Handle a handshake with a client and then incoming messages.
 */
static void
server_client_handle(struct conn *c, struct sockaddr_in *sin,
    const char *root, char **pathv)
{
	struct file		*file;
	size_t			rootlen;
	char			*path, *digest;
	struct file_list	ours, theirs, update, remove;

	PRECOND(c != NULL);
	PRECOND(sin != NULL);
	PRECOND(root != NULL);
	PRECOND(pathv != NULL);

	if (server_perform_handshake(c) == -1) {
		syncretism_log(LOG_INFO, "handshake failed with %s:%u",
		    inet_ntoa(sin->sin_addr), be16toh(sin->sin_port));
		return;
	}

	TAILQ_INIT(&ours);
	TAILQ_INIT(&theirs);
	TAILQ_INIT(&update);
	TAILQ_INIT(&remove);

	rootlen = strlen(root);

	for (;;) {
		path = NULL;
		digest = NULL;

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

		if (strncmp(path, root, rootlen)) {
			syncretism_log(LOG_NOTICE,
			    "path outside root from %s:%u",
			    inet_ntoa(sin->sin_addr), be16toh(sin->sin_port));
			goto cleanup;
		}

		syncretism_file_list_add(&theirs, path, digest);

		free(path);
		free(digest);
	}

	syncretism_file_list(&ours, pathv);
	syncretism_file_list_diff(&ours, &theirs, &update, &remove);

	TAILQ_FOREACH(file, &update, list)
		syncretism_file_send(c, file);

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
	syncretism_file_list_free(&remove);
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
