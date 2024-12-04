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

#include "syncretism.h"

static int	client_send_auth(struct conn *);
static int	client_send_random(struct conn *);
static int	client_recv_random(struct conn *);
static int	client_send_files(struct conn *, char **);
static int	client_recv_files(struct conn *, const char *);

/*
 * Perform the syncretism as the client.
 */
void
syncretism_client(const char *ip, u_int16_t port, const char *root, char **argv)
{
	struct sockaddr_in	sin;
	struct conn		client;

	PRECOND(ip != NULL);
	PRECOND(port > 0);
	PRECOND(root != NULL);
	PRECOND(argv != NULL);

	memset(&client, 0, sizeof(client));

	if ((client.fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
		fatal("socket: %s", errno_s);

	memset(&sin, 0, sizeof(sin));

	sin.sin_family = AF_INET;
	sin.sin_port = htobe16(port);
	sin.sin_addr.s_addr = inet_addr(ip);

	nyfe_zeroize_register(&client, sizeof(client));

	if (connect(client.fd, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		fatal("failed to connect to %s:%u: %s", ip, port, errno_s);

	if (client_send_random(&client) == -1)
		fatal("failed to send our random data");

	if (client_recv_random(&client) == -1)
		fatal("failed to receive server random data");

	if (syncretism_derive_keys(&client, &client.tx, &client.rx,
	    &client.tx_encap, &client.rx_encap) == -1)
		fatal("failed to derive keys");

	if (client_send_auth(&client) == -1)
		fatal("failed to authenticate");

	if (client_send_files(&client, argv) == -1)
		fatal("failed to send our list of files");

	if (client_recv_files(&client, root) == -1)
		fatal("failed to receive server files");

	nyfe_zeroize(&client, sizeof(client));
}

/*
 * Send our random data to the server node.
 */
static int
client_send_random(struct conn *c)
{
	PRECOND(c != NULL);

	nyfe_random_bytes(c->client_random, sizeof(c->client_random));

	if (syncretism_write(c->fd,
	    c->client_random, sizeof(c->client_random)) == -1)
		return (-1);

	return (0);
}

/*
 * Receive random data and challenge token from the server node.
 */
static int
client_recv_random(struct conn *c)
{
	PRECOND(c != NULL);

	if (syncretism_read(c->fd,
	    c->server_random, sizeof(c->server_random)) == -1)
		return (-1);

	if (syncretism_read(c->fd, c->token, sizeof(c->token)) == -1)
		return (-1);

	return (0);
}

/*
 * Encrypt the authentication token under the newly derived keys
 * and send it to the server as initial proof that we hold the
 * same shared secret.
 */
static int
client_send_auth(struct conn *c)
{
	PRECOND(c != NULL);

	return (syncretism_msg_send(c, c->token, sizeof(c->token)));
}

/*
 * Collect all files under the given paths and send information about
 * them over to the server side so it can tell us what we need to do.
 */
static int
client_send_files(struct conn *c, char **pathv)
{
	int			ret;
	struct file		*file;
	struct file_list	files;

	PRECOND(c != NULL);
	PRECOND(pathv != NULL);

	ret = -1;

	if (syncretism_file_list(&files, pathv) == -1) {
		syncretism_file_list_free(&files);
		return (-1);
	}

	TAILQ_FOREACH(file, &files, list) {
		if (syncretism_file_entry_send(c, file) == -1)
			break;
	}

	if (file == NULL) {
		if (syncretism_file_done(c) != -1)
			ret = 0;
	}

	syncretism_file_list_free(&files);

	return (ret);
}

/*
 * Receive files from the server that we shall store.
 */
static int
client_recv_files(struct conn *c, const char *root)
{
	int			ret;
	struct msg		*msg;
	size_t			rootlen;
	char			*path, *digest;

	PRECOND(c != NULL);
	PRECOND(root != NULL);

	ret = -1;
	msg = NULL;
	rootlen = strlen(root);

	for (;;) {
		msg = NULL;
		path = NULL;
		digest = NULL;

		if (syncretism_file_entry_recv(c, &path, &digest) == -1) {
			syncretism_log(LOG_NOTICE,
			    "unexpected disconnect from server");
			goto cleanup;
		}

		if (!strcmp(path, "done") && !strcmp(digest, "-"))
			break;

		if (strstr(path, "../")) {
			syncretism_log(LOG_NOTICE, "malicous path from server");
			goto cleanup;
		}

		if (strncmp(path, root, rootlen)) {
			syncretism_log(LOG_NOTICE,
			    "path outside root from server");
			goto cleanup;
		}

		if ((msg = syncretism_msg_read(c)) == NULL) {
			syncretism_log(LOG_NOTICE,
			    "unexpected disconnect from server");
			goto cleanup;
		}

		if (syncretism_file_save(path, msg->data, msg->length) == -1) {
			syncretism_log(LOG_NOTICE, "failed to save %s", path);
			goto cleanup;
		}

		free(path);
		free(digest);
		syncretism_msg_free(msg);
	}

	ret = 0;

cleanup:
	free(path);
	free(digest);

	if (msg != NULL)
		syncretism_msg_free(msg);

	return (ret);
}
