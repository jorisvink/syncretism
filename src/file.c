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
#include <sys/time.h>

#include <ctype.h>
#include <fts.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "syncretism.h"

static void	file_sha3sum(struct file *);
static int	file_cmp(const FTSENT **, const FTSENT **);

/*
 * Create a list of all files under the parent working directory (".").
 */
void
syncretism_file_list(struct file_list *list)
{
	FTS			*fts;
	FTSENT			*ent;
	struct file		*file;
	char			*pathv[2];

	PRECOND(list != NULL);
	PRECOND(pathv != NULL);

	pathv[0] = ".";
	pathv[1] = NULL;

	TAILQ_INIT(list);

	fts = fts_open(pathv, FTS_NOCHDIR | FTS_LOGICAL | FTS_XDEV, file_cmp);
	if (fts == NULL)
		fatal("fts_open: %s", errno_s);

	while ((ent = fts_read(fts)) != NULL) {
		syncretism_signal_check();

		if (S_ISDIR(ent->fts_statp->st_mode))
			continue;

		if ((file = calloc(1, sizeof(*file))) == NULL)
			fatal("calloc failed");

		/* XXX - are we sure its always ./ ? */
		if ((file->path = strdup(ent->fts_accpath + 2)) == NULL)
			fatal("strdup failed");

		file_sha3sum(file);

		file->entry.mode = ent->fts_statp->st_mode;
		file->entry.size = ent->fts_statp->st_size;
		file->entry.mtime = ent->fts_statp->st_mtime;

		TAILQ_INSERT_TAIL(list, file, list);
	}

	fts_close(fts);
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
void
syncretism_file_list_add(struct file_list *list, const char *path,
    struct file_entry *ent)
{
	struct file		*file;

	PRECOND(list != NULL);
	PRECOND(path != NULL);
	PRECOND(ent != NULL);

	if ((file = calloc(1, sizeof(*file))) == NULL)
		fatal("calloc failed");

	if ((file->path = strdup(path)) == NULL)
		fatal("strdup failed");

	memcpy(&file->entry, ent, sizeof(file->entry));

	TAILQ_INSERT_TAIL(list, file, list);
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

			if (strcmp(a->path, b->path))
				continue;

			TAILQ_REMOVE(theirs, a, list);
			TAILQ_REMOVE(ours, b, list);

			if (nyfe_mem_cmp(a->entry.digest,
			    b->entry.digest, sizeof(a->entry.digest))) {
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

/*
 * Send an indication to our peer that we are done with sending files.
 * We do this by sending a path with name "done" and a file_entry
 * containing only 0 bytes.
 */
void
syncretism_file_done(struct conn *c)
{
	struct file_entry	ent;

	PRECOND(c != NULL);

	nyfe_mem_zero(&ent, sizeof(ent));

	syncretism_msg_send(c, "done", 4);
	syncretism_msg_send(c, &ent, sizeof(ent));
}

/*
 * Send a file entry to our peer.
 */
void
syncretism_file_entry_send(struct conn *c, struct file *file)
{
	struct file_entry	ent;

	PRECOND(c != NULL);
	PRECOND(file != NULL);

	memcpy(&ent, &file->entry, sizeof(ent));

	ent.mode = htobe64(ent.mode);
	ent.size = htobe64(ent.size);
	ent.mtime = htobe64(ent.mtime);

	syncretism_msg_send(c, file->path, strlen(file->path));
	syncretism_msg_send(c, &ent, sizeof(ent));
}

/*
 * Receive a file entry from our peer and return info to caller.
 */
char *
syncretism_file_entry_recv(struct conn *c, struct file_entry *ent)
{
	struct msg		*msg;
	char			*path;
	size_t			idx, len;

	PRECOND(c != NULL);
	PRECOND(ent != NULL);

	path = syncretism_msg_read_string(c);
	msg = syncretism_msg_read(c);
	if (msg->length != sizeof(*ent))
		fatal("expected entry, got %zu bytes", sizeof(*ent));

	memcpy(ent, msg->data, sizeof(*ent));

	ent->size = be64toh(ent->size);
	ent->mode = be64toh(ent->mode);
	ent->mtime = be64toh(ent->mtime);

	if (!strcmp(path, "done")) {
		for (idx = 0; idx < msg->length; idx++) {
			if (msg->data[idx] != 0)
				break;
		}

		if (idx == msg->length) {
			free(path);
			syncretism_msg_free(msg);
			return (NULL);
		}
	}

	syncretism_msg_free(msg);

	if (path[0] == '\0' || path[0] == '/')
		fatal("file entry: path is potentially malicous");

	if (strstr(path, "../"))
		fatal("file entry: peer sent malicous path");

	len = strlen(path);
	for (idx = 0; idx < len; idx++) {
		if (!isprint((unsigned char)path[idx]))
			fatal("file entry: a path contains bad vibes");
	}

	return (path);
}

/*
 * Send the given file and its contents to our peer.
 */
void
syncretism_file_send(struct conn *c, struct file *file)
{
	struct stat	st;
	int		fd;
	u_int8_t	*buf;
	size_t		toread;

	PRECOND(c != NULL);
	PRECOND(file != NULL);

	buf = NULL;

	if ((fd = open(file->path, O_RDONLY)) == -1)
		fatal("failed to open %s: %s", file->path, errno_s);

	if (fstat(fd, &st) == -1)
		fatal("failed to fstat %s: %s", file->path, errno_s);

	if ((buf = calloc(1, SYNCRETISM_MAX_MSG_LEN)) == NULL)
		fatal("calloc");

	syncretism_file_entry_send(c, file);

	while (st.st_size != 0) {
		toread = MIN(st.st_size, SYNCRETISM_MAX_MSG_LEN);

		syncretism_read(fd, buf, toread);
		syncretism_msg_send(c, buf, toread);

		st.st_size -= toread;
	}

	free(buf);
	(void)close(fd);
}

/*
 * Receive a file from our peer and write it to disk.
 */
void
syncretism_file_recv(struct conn *c, char *path, struct file_entry *ent)
{
	struct msg		*msg;
	u_int64_t		remain;
	int			fd, len;
	struct timeval		times[2];
	char			*p, tmp[1024];

	PRECOND(c != NULL);
	PRECOND(path != NULL);
	PRECOND(ent != NULL);

	p = path + 1;

	for (;;) {
		if ((p = strchr(p, '/')) == NULL)
			break;

		*p = '\0';

		if (mkdir(path, 0700) == -1 && errno != EEXIST)
			fatal("failed to create %s: %s", path, errno_s);

		*p = '/';
		p++;
	}

	len = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	if (len == -1 || (size_t)len >= sizeof(tmp))
		fatal("failed to snprintf tmp path");

	if ((fd = open(tmp, O_CREAT | O_TRUNC | O_WRONLY, 0700)) == -1)
		fatal("open(%s): %s", tmp, errno_s);

	remain = ent->size;

	while (remain != 0) {
		msg = syncretism_msg_read(c);

		if (msg->length > remain) {
			fatal("received file chunk odd %zu/%" PRIu64 " left",
			    msg->length, remain);
		}

		syncretism_write(fd, msg->data, msg->length);
		remain -= msg->length;

		syncretism_msg_free(msg);
	}

	memset(&times, 0, sizeof(times));
	time(&times[0].tv_sec);
	times[1].tv_sec = ent->mtime;

	if (futimes(fd, times) == -1)
		fatal("futimes(%s): %s", tmp, errno_s);

	if (fchmod(fd, ent->mode) == -1)
		fatal("fchmod(%s): %s", tmp, errno_s);

	if (close(fd) == -1)
		fatal("write errors on %s: %s", tmp, errno_s);

	if (rename(tmp, path) == -1)
		fatal("rename %s to %s failed: %s", tmp, path, errno_s);

	(void)close(fd);
}

/*
 * Given a file, calculate its SHA3-256 digest.
 */
static void
file_sha3sum(struct file *file)
{
	int			fd;
	ssize_t			ret;
	struct nyfe_sha3	ctx;
	u_int8_t		buf[512];

	PRECOND(file != NULL);

	if ((fd = open(file->path, O_RDONLY)) == -1)
		fatal("failed to open '%s' (%s)", file->path, errno_s);

	nyfe_sha3_init256(&ctx);

	for (;;) {
		if ((ret = read(fd, buf, sizeof(buf))) == -1) {
			if (errno == EINTR)
				continue;
			fatal("failed to read '%s' (%s)", file->path, errno_s);
		}

		if (ret == 0)
			break;

		nyfe_sha3_update(&ctx, buf, ret);
	}

	(void)close(fd);

	nyfe_sha3_final(&ctx, file->entry.digest, sizeof(file->entry.digest));
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
