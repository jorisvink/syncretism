# syncretism Makefile

CC?=cc
OBJDIR?=obj
BIN=syncretism
LIBNYFE=nyfe/libnyfe.a
VERSION=$(OBJDIR)/version.c

DESTDIR?=
PREFIX?=/usr/local
INSTALL_DIR=$(PREFIX)/bin

CFLAGS+=-std=c99 -pedantic -Wall -Werror -Wstrict-prototypes
CFLAGS+=-Wmissing-prototypes -Wmissing-declarations -Wshadow
CFLAGS+=-Wpointer-arith -Wcast-qual -Wsign-compare -O2
CFLAGS+=-fstack-protector-all -Wtype-limits -fno-common -Iinclude
CFLAGS+=-Inyfe/include
CFLAGS+=-g

SRC=	src/syncretism.c \
	src/client.c \
	src/file.c \
	src/msg.c \
	src/server.c

ifeq ("$(SANITIZE)", "1")
	CFLAGS+=-fsanitize=address,undefined
	LDFLAGS+=-fsanitize=address,undefined
endif

LDFLAGS+=$(LIBNYFE)

INSTALL_TARGETS=install-bin

OSNAME=$(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
ifeq ("$(OSNAME)", "linux")
	CFLAGS+=-D_GNU_SOURCE=1 -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
else ifeq ("$(OSNAME)", "darwin")
else ifeq ("$(OSNAME)", "openbsd")
endif

OBJS=	$(SRC:src/%.c=$(OBJDIR)/%.o)
OBJS+=	$(OBJDIR)/version.o

all: $(BIN)

$(BIN): $(OBJDIR) $(LIBNYFE) $(OBJS) $(VERSION)
	$(CC) $(OBJS) $(LDFLAGS) -o $(BIN)

$(VERSION): $(OBJDIR) force
	@if [ -f RELEASE ]; then \
		printf "const char *syncretism_build_rev = \"%s\";\n" \
		    `cat RELEASE` > $(VERSION); \
	elif [ -d .git ]; then \
		GIT_REVISION=`git rev-parse --short=8 HEAD`; \
		GIT_BRANCH=`git rev-parse --abbrev-ref HEAD`; \
		rm -f $(VERSION); \
		printf "const char *syncretism_build_rev = \"%s-%s\";\n" \
		    $$GIT_BRANCH $$GIT_REVISION > $(VERSION); \
	else \
		echo "No version information found (no .git or RELEASE)"; \
		exit 1; \
	fi
	@printf "const char *syncretism_build_date = \"%s\";\n" \
	    `date +"%Y-%m-%d"` >> $(VERSION);

install: $(INSTALL_TARGETS)

install-bin: $(BIN)
	mkdir -p $(DESTDIR)$(INSTALL_DIR)
	install -m 555 $(BIN) $(DESTDIR)$(INSTALL_DIR)/$(BIN)

$(LIBNYFE):
	$(MAKE) -C nyfe

src/syncretism.c: $(VERSION)

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(VERSION)
	$(MAKE) -C nyfe clean
	rm -rf $(OBJDIR) $(BIN)

.PHONY: all clean force
