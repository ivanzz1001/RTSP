

OBJS = test.o rtsp_demo.o rtsp_msg.o rtp_enc.o
TAR = demo

CC ?= gcc
CFLAGS += -g -Wall

all: $(TAR)

$(TAR) : $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o : %.c
	$(CC) $(CFLAGS) -c $^

clean:
	rm -f $(OBJS) $(TAR)
