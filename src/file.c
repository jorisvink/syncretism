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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <ctype.h>
#include <fts.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "syncretism.h"

static int	file_sha3sum(struct file *);
static int	file_cmp(const FTSENT **, const FTSENT **);

/*
 * Load all files under the given paths into list.
 */
int
syncretism_file_list(struct file_list *list, char **pathv)
{
	FTS			*fts;
	FTSENT			*ent;
	struct file		*file;

	PRECOND(list != NULL);
	PRECOND(pathv != NULL);

	TAILQ_INIT(list);

	fts = fts_open(pathv, FTS_NOCHDIR | FTS_LOGICAL | FTS_XDEV, file_cmp);
	if (fts == NULL) {
		syncretism_log(LOG_NOTICE, "fts_open: %s", errno_s);
		return (-1);
	}

	while ((ent = fts_read(fts)) != NULL) {
		if (S_ISDIR(ent->fts_statp->st_mode))
			continue;

		if ((file = calloc(1, sizeof(*file))) == NULL)
			fatal("calloc failed");

		if ((file->path = strdup(ent->fts_accpath)) == NULL)
			fatal("strdup failed");

		if (file_sha3sum(file) == -1) {
			free(file->path);
			free(file);
			continue;
		}

		file->size = ent->fts_statp->st_size;
		TAILQ_INSERT_TAIL(list, file, list);
	}

	fts_close(fts);

	return (0);
}

/*
 * Free all entries on the given file list.
 */
void
syncretism_file_list_free(struct file_list *list)
{
	struct file		*file;

	PRECOND(list != NULL);

	while ((file = TAILQ_FIRST(list)) != NULL) {
		TAILQ_REMOVE(list, file, list);
		free(file->path);
		free(file);
	}
}

/*
 * Adds a new entry to the given file list.
 */
int
syncretism_file_list_add(struct file_list *list, const char *path,
    const char *digest)
{
	int			len;
	struct file		*file;

	PRECOND(list != NULL);
	PRECOND(path != NULL);
	PRECOND(digest != NULL);

	if ((file = calloc(1, sizeof(*file))) == NULL)
		fatal("calloc failed");

	if ((file->path = strdup(path)) == NULL)
		fatal("strdup failed");

	len = snprintf(file->digest, sizeof(file->digest), "%s", digest);
	if (len == -1 || (size_t)len >= sizeof(file->digest)) {
		free(file->path);
		free(file);
		syncretism_log(LOG_NOTICE,
		    "file entry: copy of file digest failed");
		return (-1);
	}

	TAILQ_INSERT_TAIL(list, file, list);

	return (0);
}

/*
 * Given two file lists, figure out what files need to be updated
 * on the client side and what files can be removed.
 *
 * Note that this is really the bare minimum approach to this and
 * is in no shape or form performant.
 */
void
syncretism_file_list_diff(struct file_list *ours, struct file_list *theirs,
    struct file_list *update)
{
	struct file		*a, *an, *b, *bn;

	PRECOND(ours != NULL);
	PRECOND(theirs != NULL);
	PRECOND(update != NULL);

	TAILQ_INIT(update);

	/*
	 * Determine status on items in the lists.
	 *
	 * When this is done the following holds:
	 *	- Remaining entries in theirs are to be removed client side.
	 *	- Remaining entries in ours need updating.
	 */
	for (a = TAILQ_FIRST(theirs); a != NULL; a = an) {
		an = TAILQ_NEXT(a, list);

		for (b = TAILQ_FIRST(ours); b != NULL; b = bn) {
			bn = TAILQ_NEXT(b, list);

			if (!strcmp(a->path, b->path)) {
				TAILQ_REMOVE(theirs, a, list);
				TAILQ_REMOVE(ours, b, list);

				if (strcmp(a->digest, b->digest)) {
					TAILQ_INSERT_TAIL(update, b, list);
				} else {
					free(b->path);
					free(b);
				}

				free(a->path);
				free(a);

				break;
			}
		}
	}
}

/*
 * Send an indication to our peer that we are done with sending files.
 */
int
syncretism_file_done(struct conn *c)
{
	u_int64_t	dummy;

	PRECOND(c != NULL);

	if (syncretism_msg_send(c, "done", 4) == -1) {
		syncretism_log(LOG_NOTICE,
		    "failed to send file done path indication");
		return (-1);
	}

	if (syncretism_msg_send(c, "-", 1) == -1) {
		syncretism_log(LOG_NOTICE,
		    "failed to send file done digest indication");
		return (-1);
	}

	nyfe_random_bytes(&dummy, sizeof(dummy));

	if (syncretism_msg_send(c, &dummy, sizeof(dummy)) == -1) {
		syncretism_log(LOG_NOTICE,
		    "failed to send file done size indication");
		return (-1);
	}

	return (0);
}

/*
 * Send a file entry to our peer.
 */
int
syncretism_file_entry_send(struct conn *c, struct file *file)
{
	u_int64_t	sz;

	PRECOND(c != NULL);
	PRECOND(file != NULL);

	if (syncretism_msg_send(c, file->path, strlen(file->path)) == -1) {
		syncretism_log(LOG_NOTICE,
		    "failed to send file entry path");
		return (-1);
	}

	if (syncretism_msg_send(c, file->digest, strlen(file->digest)) == -1) {
		syncretism_log(LOG_NOTICE,
		    "failed to send file entry digest");
		return (-1);
	}

	sz = htobe64(file->size);

	if (syncretism_msg_send(c, &sz, sizeof(sz)) == -1) {
		syncretism_log(LOG_NOTICE,
		    "failed to send file entry size");
		return (-1);
	}

	return (0);
}

/*
 * Receive a file entry from our peer and return path and digest to caller.
 */
int
syncretism_file_entry_recv(struct conn *c, char **path,
    char **digest, u_int64_t *sz)
{
	u_int64_t		tmp;
	int			ret;
	char			*p, *d;
	size_t			idx, len;

	PRECOND(c != NULL);
	PRECOND(path != NULL);
	PRECOND(digest != NULL);
	/* sz can be NULL. */

	p = NULL;
	d = NULL;
	ret = -1;

	*path = NULL;
	*digest = NULL;

	if (sz == NULL)
		sz = &tmp;

	if ((p = syncretism_msg_read_string(c)) == NULL)
		goto cleanup;

	if ((d = syncretism_msg_read_string(c)) == NULL)
		goto cleanup;

	if (syncretism_msg_read_uint64(c, sz) == -1)
		goto cleanup;

	if (!strcmp(p, "done") && !strcmp(d, "-")) {
		*path = p;
		*digest = d;
		return (0);
	}

#if 0
	if (p[0] == '\0' || p[0] == '/') {
		syncretism_log(LOG_NOTICE, "file entry: a path is invalid");
		goto cleanup;
	}
#endif

	len = strlen(p);
	for (idx = 0; idx < len; idx++) {
		if (!isprint((unsigned char)p[idx])) {
			syncretism_log(LOG_NOTICE,
			    "file entry: a path contains bad vibes");
			goto cleanup;
		}
	}

	len = strlen(d);
	if (len != 64) {
		syncretism_log(LOG_NOTICE,
		    "file entry: a digest is invalid (%zu) (%s)", len, d);
		goto cleanup;
	}

	for (idx = 0; idx < len; idx++) {
		if (!isxdigit((unsigned char)d[idx])) {
			syncretism_log(LOG_NOTICE,
			    "file entry: a digest contains a non-hex digit");
			return (-1);
		}
	}

	*path = p;
	*digest = d;

	ret = 0;

cleanup:
	if (ret == -1) {
		free(p);
		free(d);
	}

	return (ret);
}

/*
 * Send the given file and its contents to our peer.
 */
int
syncretism_file_send(struct conn *c, struct file *file)
{
	struct stat	st;
	u_int8_t	*buf;
	size_t		toread;
	int		fd, ret;

	PRECOND(c != NULL);
	PRECOND(file != NULL);

	ret = -1;
	buf = NULL;

	if ((fd = open(file->path, O_RDONLY)) == -1) {
		syncretism_log(LOG_NOTICE,
		    "failed to open %s: %s", file->path, errno_s);
		goto cleanup;
	}

	if (fstat(fd, &st) == -1) {
		syncretism_log(LOG_NOTICE,
		    "failed to fstat %s: %s", file->path, errno_s);
		goto cleanup;
	}

	if ((buf = calloc(1, SYNCRETISM_MAX_MSG_LEN)) == NULL) {
		syncretism_log(LOG_NOTICE,
		    "file data calloc failed (%zu)", (size_t)st.st_size);
		goto cleanup;
	}

	if (syncretism_file_entry_send(c, file) == -1) {
		syncretism_log(LOG_NOTICE,
		    "failed to send file entry for %s", file->path);
		goto cleanup;
	}

	while (st.st_size != 0) {
		toread = MIN(st.st_size, SYNCRETISM_MAX_MSG_LEN);
		if (syncretism_read(fd, buf, toread) == -1) {
			syncretism_log(LOG_NOTICE,
			    "failed to read chunk of %s", file->path);
			goto cleanup;
		}

		if (syncretism_msg_send(c, buf, toread) == -1) {
			syncretism_log(LOG_NOTICE,
			    "failed to send file chunk of %s", file->path);
			goto cleanup;
		}

		st.st_size -= toread;
	}

	ret = 0;

cleanup:
	free(buf);
	(void)close(fd);

	return (ret);
}

/*
 * Receive a file from our peer and write it to disk.
 */
int
syncretism_file_recv(struct conn *c, char *path, u_int64_t sz)
{
	struct msg	*msg;
	u_int64_t	total;
	int		ret, fd, len;
	char		*p, tmp[1024];

	PRECOND(c != NULL);
	PRECOND(path != NULL);

	fd = -1;
	ret = -1;
	p = path + 1;

	for (;;) {
		if ((p = strchr(p, '/')) == NULL)
			break;

		*p = '\0';

		if (mkdir(path, 0700) == -1 && errno != EEXIST) {
			syncretism_log(LOG_NOTICE, "failed to create %s: %s",
			    path, errno_s);
			goto cleanup;
		}

		*p = '/';
		p++;
	}

	len = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	if (len == -1 || (size_t)len >= sizeof(tmp)) {
		syncretism_log(LOG_NOTICE, "failed to create tmp path");
		goto cleanup;
	}

	if ((fd = open(tmp, O_CREAT | O_TRUNC | O_WRONLY, 0700)) == -1) {
		syncretism_log(LOG_NOTICE,
		    "failed to open %s: %s", tmp, errno_s);
		goto cleanup;
	}

	total = 0;

	while (sz != 0) {
		if ((msg = syncretism_msg_read(c)) == NULL) {
			syncretism_log(LOG_NOTICE,
			    "failed to receive chunk for %s", path);
			goto cleanup;
		}

		if (syncretism_write(fd, msg->data, msg->length) == -1) {
			syncretism_msg_free(msg);
			syncretism_log(LOG_NOTICE,
			    "failed to write chunk of %s: %s", path, errno_s);
			goto cleanup;
		}

		sz -= msg->length;
		total += msg->length;

		syncretism_msg_free(msg);
	}

	if (close(fd) == -1) {
		fd = -1;
		syncretism_log(LOG_NOTICE,
		    "write errors on %s: %s", tmp, errno_s);
		goto cleanup;
	}

	if (rename(tmp, path) == -1) {
		syncretism_log(LOG_NOTICE,
		    "rename %s to %s failed: %s", tmp, path, errno_s);
		goto cleanup;
	}

	ret = 0;
	syncretism_log(LOG_NOTICE, "%s (%zu)", path, total);

cleanup:
	if (fd != -1)
		(void)close(fd);

	if (ret == -1) {
		if (unlink(tmp) == -1 && errno != ENOENT)  {
			syncretism_log(LOG_NOTICE,
			    "unlink on %s failed: %s", tmp, errno_s);
		}
	}

	return (ret);
}

/*
 * Given a file, calculate its SHA3-256 digest.
 */
static int
file_sha3sum(struct file *file)
{
	ssize_t			ret;
	size_t			idx;
	struct nyfe_sha3	ctx;
	int			fd, len;
	u_int8_t		buf[512], digest[32];

	PRECOND(file != NULL);

	if ((fd = open(file->path, O_RDONLY)) == -1) {
		syncretism_log(LOG_NOTICE, "failed to open '%s' (%s)",
		    file->path, errno_s);
		return (-1);
	}

	nyfe_sha3_init256(&ctx);

	for (;;) {
		if ((ret = read(fd, buf, sizeof(buf))) == -1) {
			if (errno == EINTR)
				continue;
			syncretism_log(LOG_NOTICE, "failed to read '%s' (%s)",
			    file->path, errno_s);
			return (-1);
		}

		if (ret == 0)
			break;

		nyfe_sha3_update(&ctx, buf, ret);
	}

	(void)close(fd);

	nyfe_sha3_final(&ctx, digest, sizeof(digest));

	for (idx = 0; idx < sizeof(digest); idx++) {
		len = snprintf(file->digest + (idx * 2),
		    sizeof(file->digest) - (idx * 2), "%02x", digest[idx]);
		if (len == -1 || (size_t)len >= sizeof(file->digest))
			fatal("failed to convert digest to hex form");
	}

	return (0);
}

/*
 * Helper to sort the FTS lists.
 */
static int
file_cmp(const FTSENT **a1, const FTSENT **b1)
{
	const FTSENT	*a;
	const FTSENT	*b;

	PRECOND(a1 != NULL);
	PRECOND(b1 != NULL);

	a = *a1;
	b = *b1;

	return (strcmp(a->fts_name, b->fts_name));
}
