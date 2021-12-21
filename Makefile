SRC = asn1.c at_cmd.c msg.c uta.c xmmctl.c
OBJ = ${SRC:.c=.o}

PKG_CONFIG ?= pkg-config

CFLAGS ?= -Wall -O2 -g -D_GNU_SOURCE
LDFLAGS += `${PKG_CONFIG} --libs openssl`

all: xmmctl

.c.o:
	${CC} -c ${CFLAGS} $<

xmmctl: ${OBJ}
	${CC} -o $@ ${OBJ} ${LDFLAGS}

clean:
	rm -f xmmctl ${OBJ}

.PHONY: all clean 
