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

#ifndef __H_SYNCRETISM_H
#define __H_SYNCRETISM_H

#include <sys/queue.h>

#include <errno.h>
#include <string.h>
#include <syslog.h>

/* Makes life easier. */
#define errno_s			strerror(errno)

/* You know what it's for. */
#define PRECOND(x)							\
	do {								\
		if (!(x)) {						\
			fatal("precondition failed in %s:%s:%d\n",	\
			    __FILE__, __func__, __LINE__);		\
		}							\
	} while (0)

/* File sync done indication. */
#define SYNCRETISM_FILES_DONE		"done"

/*
 * Represents a file on the server or client, its path and its SHA3-256 digest.
 */
struct file {
	char			*path;
	int			seen;
	int			differ;
	char			digest[65];
	TAILQ_ENTRY(file)	list;
};

TAILQ_HEAD(file_list, file);

/*
 * A key used for tx or rx and its implicit counter used as a nonce.
 */
struct key {
	u_int8_t	key[64];
	u_int64_t	nonce;
};

/*
 * Client or server connection state.
 */
struct conn {
	int		fd;

	struct key	rx;
	struct key	tx;

	u_int8_t	token[64];
	u_int8_t	client_random[32];
	u_int8_t	server_random[32];
};

/* Maximum length for an encrypted and authenticated message. */
#define SYNCRETISM_MAX_MSG_LEN		(1024 * 1024)

/* Tag length for an encrypted and authenticated message. */
#define SYNCRETISM_TAG_LEN		32

/*
 * An encrypted and authenticated message that is sent to or received
 * from a peer. These are capped at max 1 MB per message.
 */
struct msg {
	u_int32_t	length;
	u_int8_t	*data;
};

/* src/syncretism.c */
void	fatal(const char *, ...);
int	syncretism_read(int, void *, size_t);
void	syncretism_log(int, const char *, ...);
int	syncretism_write(int, const void *, size_t);
void	syncretism_logv(int, const char *, va_list);
int	syncretism_derive_keys(struct conn *, struct key *, struct key *);

/* src/client.c */
void	syncretism_client(const char *, u_int16_t, const char *, char **);

/* src/file.c */
void	syncretism_file_list_free(struct file_list *);
int	syncretism_file_list(struct file_list *, char **);
int	syncretism_file_send(struct conn *, struct file *);
int	syncretism_file_save(char *, const void *, size_t);
int	syncretism_file_entry_split(char *, const char **, const char **);
int	syncretism_file_list_add(struct file_list *,
	    const char *, const char *);
void	syncretism_file_list_diff(struct file_list *, struct file_list *,
	    struct file_list *, struct file_list *);

/* src/server.c */
void	syncretism_server(const char *, u_int16_t, const char *, char **);

/* src/msg.c */
void		syncretism_msg_free(struct msg *);
int		syncretism_msg_unpack(struct conn *, struct msg *);
int		syncretism_msg_send(struct conn *, const void *, size_t);

struct msg	*syncretism_msg_read(struct conn *);
struct msg	*syncretism_msg_pack(struct conn *, const void *, size_t);

#endif
