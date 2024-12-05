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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "syncretism.h"

/*
 * Authenticate and encrypt the given data under the tx key.
 */
struct msg *
syncretism_msg_pack(struct conn *c, const void *data, size_t len)
{
	struct msg		*msg;
	struct nyfe_agelas	cipher;
	u_int64_t		nonce;
	u_int8_t		block[136];
	u_int32_t		length, pktlen;

	PRECOND(data != NULL);
	PRECOND(len <= SYNCRETISM_MAX_MSG_LEN);

	if ((msg = calloc(1, sizeof(*msg))) == NULL)
		fatal("calloc: failed to allocate msg");

	length = htobe32(len);
	nonce = htobe64(c->tx.nonce);

	msg->length = sizeof(length) + len + SYNCRETISM_TAG_LEN;

	if ((msg->data = calloc(1, msg->length)) == NULL)
		fatal("calloc: failed to allocate msg data");

	pktlen = htobe32(len + SYNCRETISM_TAG_LEN);
	nyfe_agelas_encrypt(&c->tx_encap, &pktlen, msg->data, sizeof(pktlen));

	nyfe_mem_zero(block, sizeof(block));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	nyfe_agelas_init(&cipher, c->tx.key, sizeof(c->tx.key));
	nyfe_agelas_aad(&cipher, &nonce, sizeof(nonce));
	nyfe_agelas_aad(&cipher, &length, sizeof(length));

	nyfe_memcpy(block, &nonce, sizeof(nonce));
	nyfe_agelas_encrypt(&cipher, block, block, sizeof(block));

	if (len > 0) {
		nyfe_agelas_encrypt(&cipher,
		    data, &msg->data[sizeof(length)], len);
	}

	nyfe_agelas_authenticate(&cipher,
	    &msg->data[sizeof(length) + len], SYNCRETISM_TAG_LEN);
	nyfe_zeroize(&cipher, sizeof(cipher));

	c->tx.nonce++;

	return (msg);
}

/*
 * Authenticate and decrypt the given message under the rx key.
 */
void
syncretism_msg_unpack(struct conn *c, struct msg *msg)
{
	u_int8_t		*tag;
	u_int64_t		nonce;
	u_int32_t		length;
	struct nyfe_agelas	cipher;
	u_int8_t		block[136], calc[SYNCRETISM_TAG_LEN];

	PRECOND(c != NULL);
	PRECOND(msg != NULL);
	PRECOND(msg->length >= SYNCRETISM_TAG_LEN && msg->length <=
	    sizeof(length) + SYNCRETISM_MAX_MSG_LEN + sizeof(calc));

	msg->length -= sizeof(calc);
	tag = &msg->data[msg->length];

	nonce = htobe64(c->rx.nonce);
	length = htobe32(msg->length);

	nyfe_mem_zero(block, sizeof(block));
	nyfe_zeroize_register(&cipher, sizeof(cipher));

	nyfe_agelas_init(&cipher, c->rx.key, sizeof(c->rx.key));
	nyfe_agelas_aad(&cipher, &nonce, sizeof(nonce));
	nyfe_agelas_aad(&cipher, &length, sizeof(length));

	nyfe_memcpy(block, &nonce, sizeof(nonce));

	nyfe_agelas_encrypt(&cipher, block, block, sizeof(block));
	if (msg->length > 0)
		nyfe_agelas_decrypt(&cipher, msg->data, msg->data, msg->length);
	nyfe_agelas_authenticate(&cipher, calc, sizeof(calc));

	nyfe_zeroize(&cipher, sizeof(cipher));

	if (nyfe_mem_cmp(tag, calc, sizeof(calc)))
		fatal("failed to verify integrity on received message");

	c->rx.nonce++;
}

/*
 * Wipe and free a message.
 */
void
syncretism_msg_free(struct msg *msg)
{
	PRECOND(msg != NULL);

	if (msg->length > 0)
		nyfe_mem_zero(msg->data, msg->length);

	free(msg->data);
	free(msg);
}

/*
 * Authenticate and encrypt the given data and send it to our peer
 * as a single message.
 */
void
syncretism_msg_send(struct conn *c, const void *buf, size_t buflen)
{
	struct msg	*msg;

	PRECOND(c != NULL);
	PRECOND(buf != NULL);
	PRECOND(buflen <= SYNCRETISM_MAX_MSG_LEN);

	msg = syncretism_msg_pack(c, buf, buflen);
	syncretism_write(c->fd, msg->data, msg->length);
	syncretism_msg_free(msg);
}

/*
 * Receive an encrypted message from our peer.
 * Does validation of the message and then attempts to unpack it.
 */
struct msg *
syncretism_msg_read(struct conn *c)
{
	u_int32_t	len;
	struct msg	*msg;

	PRECOND(c != NULL);

	syncretism_read(c->fd, &len, sizeof(len));
	nyfe_agelas_decrypt(&c->rx_encap, &len, &len, sizeof(len));

	len = be32toh(len);
	if (len < SYNCRETISM_TAG_LEN ||
	    len > sizeof(len) + SYNCRETISM_MAX_MSG_LEN + SYNCRETISM_TAG_LEN)
		fatal("received weird length (%u)", len);

	if ((msg = calloc(1, sizeof(*msg))) == NULL)
		fatal("calloc: failed to allocate msg");

	msg->length = len;

	if ((msg->data = calloc(1, msg->length)) == NULL)
		fatal("calloc: failed to allocate msg data");

	syncretism_read(c->fd, msg->data, msg->length);
	syncretism_msg_unpack(c, msg);

	return (msg);
}

/*
 * Returns a received message as a C-string to the caller.
 */
char *
syncretism_msg_read_string(struct conn *c)
{
	size_t		idx;
	char		*str;
	struct msg	*msg;

	PRECOND(c != NULL);

	msg = syncretism_msg_read(c);

	if ((str = calloc(1, msg->length + 1)) == NULL)
		fatal("calloc");

	for (idx = 0; idx < msg->length; idx++) {
		if (msg->data[idx] == '\0')
			fatal("expected string has embedded NUL-byte");
		str[idx] = msg->data[idx];
	}

	str[idx] = '\0';
	syncretism_msg_free(msg);

	return (str);
}

/*
 * Returns a received message as a uint64 to the caller.
 */
void
syncretism_msg_read_uint64(struct conn *c, u_int64_t *res)
{
	struct msg	*msg;

	PRECOND(c != NULL);
	PRECOND(res != NULL);

	msg = syncretism_msg_read(c);

	if (msg->length != sizeof(*res)) {
		fatal("unexpected message length - wanted 8, got %u",
		    msg->length);
	}

	memcpy(res, msg->data, msg->length);
	syncretism_msg_free(msg);

	*res = be64toh(*res);
}
