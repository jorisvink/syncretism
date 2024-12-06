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
#include <sys/stat.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "syncretism.h"

static void	client_send_auth(struct conn *);
static void	client_send_random(struct conn *);
static void	client_recv_random(struct conn *);
static void	client_send_files(struct conn *, const char *);
static void	client_recv_files(struct conn *, const char *);

/* How many files we received. */
static u_int64_t	file_count = 0;

/*
 * Perform the syncretism as the client.
 */
void
syncretism_client(const char *ip, u_int16_t port, char *remote, char *local)
{
	struct sockaddr_in	sin;
	struct conn		client;

	PRECOND(ip != NULL);
	PRECOND(port > 0);
	PRECOND(remote != NULL);
	PRECOND(local != NULL);

	syncretism_slash_strip(local);
	syncretism_slash_strip(remote);

	if (mkdir(local, 0700) == -1 && errno != EEXIST)
		fatal("failed to create %s: %s", local, errno_s);

	if (chdir(local) == -1)
		fatal("failed to change directory to %s: %s", local, errno_s);

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

	printf("syncretism %s:%u:%s -> %s\n", ip, port, remote, local);

	client_send_random(&client);
	client_recv_random(&client);

	syncretism_derive_keys(&client, &client.tx, &client.rx,
	    &client.tx_encap, &client.rx_encap);

	client_send_auth(&client);
	client_send_files(&client, remote);
	client_recv_files(&client, local);

	nyfe_zeroize(&client, sizeof(client));

	printf("syncretism ritual complete\n");
	printf("   %" PRIu64 " created/updated files\n", file_count);
}

/*
 * Send our random data to the server node.
 */
static void
client_send_random(struct conn *c)
{
	PRECOND(c != NULL);

	nyfe_random_bytes(c->client_random, sizeof(c->client_random));
	syncretism_write(c->fd, c->client_random, sizeof(c->client_random));
}

/*
 * Receive random data and challenge token from the server node.
 */
static void
client_recv_random(struct conn *c)
{
	PRECOND(c != NULL);

	syncretism_read(c->fd, c->server_random, sizeof(c->server_random));
	syncretism_read(c->fd, c->token, sizeof(c->token));
}

/*
 * Encrypt the authentication token under the newly derived keys
 * and send it to the server as initial proof that we hold the
 * same shared secret.
 */
static void
client_send_auth(struct conn *c)
{
	PRECOND(c != NULL);

	syncretism_msg_send(c, c->token, sizeof(c->token));
}

/*
 * Collect all files under the given paths and send information about
 * them over to the server side so it can tell us what we need to do.
 */
static void
client_send_files(struct conn *c, const char *remote)
{
	struct file		*file;
	struct file_list	files;

	PRECOND(c != NULL);

	syncretism_msg_send(c, remote, strlen(remote));
	syncretism_file_list(&files);

	TAILQ_FOREACH(file, &files, list) {
		syncretism_signal_check();
		syncretism_file_entry_send(c, file);
	}

	if (file == NULL)
		syncretism_file_done(c);

	syncretism_file_list_free(&files);
}

/*
 * Receive files from the server that we shall store.
 */
static void
client_recv_files(struct conn *c, const char *local)
{
	struct file_entry	ent;
	char			*path;

	PRECOND(c != NULL);

	for (;;) {
		syncretism_signal_check();

		if ((path = syncretism_file_entry_recv(c, &ent)) == NULL)
			break;

		file_count++;

		syncretism_file_recv(c, path, &ent);
		syncretism_log(LOG_NOTICE,
		    "%s/%s (%" PRIu64 ")", local, path, ent.size);

		free(path);
	}
}
