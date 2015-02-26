OTPROOT=/usr/lib/erlang
INCLUDES = -I/usr/lib/erlang/usr/include

# OS X flags.
#GCCFLAGS = -O3 -fPIC -bundle -flat_namespace -undefined suppress -fno-common -Wall

# Linux Flags
GCCFLAGS = -O3 -fPIC -shared -fno-common -Wall

CFLAGS = $(GCCFLAGS) $(INCLUDES)
CFLAGS_32=-m32
LDFLAGS = $(CFLAGS) $(LIBS)

#OBJECTS = curve25519-donna.o curve25519-donna-c64.o curve25519_donna_nif.c

DRIVER = curve25519_donna_nif.so curve25519_donna_c64_nif.so
BEAM = curve25519.beam

all: $(DRIVER) $(BEAM)

clean: 
	rm -f *.o *.beam *.so

curve25519_donna_nif.so: curve25519-donna.c curve25519_donna_nif.c
	gcc -o $@ $^ $(LDFLAGS) $(CFLAGS_32)

curve25519_donna_c64_nif.so: curve25519-donna-c64.c curve25519_donna_nif.c
	gcc -o $@ $^ $(LDFLAGS)

$(BEAM): curve25519.erl
	erlc $^

# EOF
