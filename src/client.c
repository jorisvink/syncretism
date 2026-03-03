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

static void	client_send_random(struct conn *);
static void	client_recv_random(struct conn *);

static void	client_send_challenge(struct conn *);

static void	client_handshake_init(struct conn *);
static void	client_handshake_final(struct conn *);

static void	client_send_files(struct conn *, const char *);
static void	client_recv_files(struct conn *, const char *);

/* How many files we received. */
static u_int64_t	file_update = 0;

/* How many files we have removed. */
static u_int64_t	file_remove = 0;

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

	nyfe_mem_zero(&client, sizeof(client));

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

	client_handshake_init(&client);
	client_handshake_final(&client);

	client_send_files(&client, remote);
	client_recv_files(&client, local);

	nyfe_zeroize(&client, sizeof(client));

	printf("syncretism ritual complete\n");

	if (file_remove > 0)
		printf("   %" PRIu64 " removed files\n", file_remove);

	if (file_update > 0)
		printf("   %" PRIu64 " created/updated files\n", file_update);
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
 * Perform the initial handshake and key derivation.
 */
static void
client_handshake_init(struct conn *c)
{
	PRECOND(c != NULL);

	client_send_random(c);
	client_recv_random(c);

	syncretism_derive_keys(c, &c->tx, &c->rx,
	    &c->tx_encap, &c->rx_encap, SYNCRETISM_HANDSHAKE_INIT);

	client_send_challenge(c);
}

/*
 * Perform the final handshake and key derivation.
 */
static void
client_handshake_final(struct conn *c)
{
	struct msg	*msg;
	u_int8_t	sk[3168];
	struct mlkem	*recv, send;

	PRECOND(c != NULL);

	nyfe_mem_zero(&send, sizeof(send));
	nyfe_zeroize_register(sk, sizeof(sk));

	pqcrystals_kyber1024_ref_keypair(send.pk_ct, sk);
	nyfe_random_bytes(c->client_random, sizeof(c->client_random));
	nyfe_memcpy(send.random, c->client_random, sizeof(c->client_random));

	syncretism_msg_send(c, &send, sizeof(send));

	msg = syncretism_msg_read(c);
	if (msg->length != sizeof(*recv))
		fatal("expected ml-kem-1024 exchange, got %zu", msg->length);

	recv = (struct mlkem *)msg->data;
	pqcrystals_kyber1024_ref_dec(c->kem_ss, recv->pk_ct, sk);
	nyfe_zeroize(sk, sizeof(sk));

	nyfe_memcpy(c->server_random, recv->random, sizeof(recv->random));

	syncretism_derive_keys(c, &c->tx, &c->rx,
	    &c->tx_encap, &c->rx_encap, SYNCRETISM_HANDSHAKE_FINAL);
}

/*
 * Encrypt the challenge token under the newly derived keys
 * and send it to the server as initial proof that we hold the
 * same shared secret.
 */
static void
client_send_challenge(struct conn *c)
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
	syncretism_file_list(&files, 0);

	TAILQ_FOREACH(file, &files, list) {
		syncretism_signal_check();
		syncretism_file_entry_send(c, file);
	}

	if (file == NULL)
		syncretism_file_done(c);

	syncretism_file_list_free(&files);
}

/*
 * Receive files from the server that we shall store and the files we
 * shall delete from our local copy.
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

		file_update++;

		syncretism_file_recv(c, path, &ent);
		syncretism_log(LOG_NOTICE,
		    "U %s/%s (%" PRIu64 ")", local, path, ent.size);

		free(path);
	}

	for (;;) {
		syncretism_signal_check();

		if ((path = syncretism_file_entry_recv(c, &ent)) == NULL)
			break;

		if (unlink(path) == -1) {
			syncretism_log(LOG_NOTICE,
			    "warning: failed to remove '%s' (%s)",
			    path, strerror(errno));
		}

		file_remove++;

		syncretism_log(LOG_NOTICE, "R %s/%s", local, path);
		free(path);
	}
}
