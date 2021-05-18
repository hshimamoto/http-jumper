// MIT License Copyright(c) 2021 Hiroshi Shimamoto
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

static inline void ldatetime(char *dt, int sz)
{
	time_t t = time(NULL);
	struct tm *tmp = localtime(&t);
	if (!tmp)
		strcpy(dt, "-");
	else
		strftime(dt, sz, "%F %T", tmp);
}

#define logf(...) \
	do { \
		char dt[80]; \
		ldatetime(dt, sizeof(dt)); \
		fprintf(stderr, "%s [%d] ", dt, getpid()); \
		fprintf(stderr, __VA_ARGS__); \
		fflush(stderr); \
	} while (0)

void get_duration(char *buf, int n, struct timeval *prev)
{
	struct timeval now;
	gettimeofday(&now, NULL);
	int duration = now.tv_sec - prev->tv_sec;
	if (duration < 600) {
		int ms = (now.tv_usec - prev->tv_usec) / 1000;
		if (ms < 0) {
			ms += 1000;
			duration++;
		}
		snprintf(buf, n, "%d.%03ds", duration, ms);
	} else if (duration < 3600) {
		snprintf(buf, n, "%dm", duration / 60);
	} else if (duration < 12 * 3600) {
		int h = duration / 3600;
		int m = (duration / 60) % 60;
		snprintf(buf, n, "%dh %dm", h, m);
	} else {
		snprintf(buf, n, "%dh", duration / 3600);
	}
}

#define BUFSZ	(65536)
const int defport = 8888;
const int bufsz = BUFSZ;
static char buf[BUFSZ];

static int listensocket(int port)
{
	struct sockaddr_in addr;
	int s, one = 1;

	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return -1;
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
		goto bad;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);
	if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) < 0)
		goto bad;
	if (listen(s, 5) < 0)
		goto bad;

	return s;
bad:
	close(s);
	return -1;
}

static void enable_tcpkeepalive(int s, int idle, int cnt, int intvl)
{
	int val = 1;
	socklen_t len = sizeof(val);

	// enable
	setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &val, len);
	// set params
	val = idle;
	setsockopt(s, SOL_TCP, TCP_KEEPIDLE, &val, len);
	val = cnt;
	setsockopt(s, SOL_TCP, TCP_KEEPCNT, &val, len);
	val = intvl;
	setsockopt(s, SOL_TCP, TCP_KEEPINTVL, &val, len);
}

static struct sockaddr_in *getaddr(char *hostport)
{
	struct sockaddr_in *addr = NULL;
	char *p = strdup(hostport);
	char *c = strchr(p, ':');
	if (c == NULL)
		goto out;
	*c++ = 0;
	logf("host = %s, port = %s\n", p, c);

	addr = calloc(1, sizeof(struct sockaddr_in));
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr(p);
	addr->sin_port = htons(atoi(c));

	if (addr->sin_port == 0) {
		free(addr);
		addr = NULL;
	}

out:
	free(p);
	return addr;
}

/* GLOBAL */
struct sockaddr_in *jump;
char *target;

static int jumpto(int timeout)
{
	int s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0) {
		logf("socket error %d\n", errno);
		return -1;
	}

	if (connect(s, (struct sockaddr *)jump, sizeof(*jump)) < 0) {
		logf("connect error %d\n", errno);
		close(s);
		return -1;
	}

	logf("connected to jumper\n");

	snprintf(buf, 256, "CONNECT %s HTTP/1.0\r\n\r\n", target);
	write(s, buf, strlen(buf));

	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(s, &fds);
	struct timeval tv;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;

	int ret = select(s+1, &fds, NULL, NULL, &tv);
	if (ret <= 0) {
		logf("select error\n");
		close(s);
		return -1;
	}
	/* read and discard RESP */
	ret = read(s, buf, BUFSZ);
	if (ret < 12) {
		logf("bad resp\n");
		close(s);
		return -1;
	}
	if (buf[9] != '2' || buf[10] != '0' || buf[11] != '0') {
		logf("bad status\n");
		close(s);
		return -1;
	}

	logf("established\n");

	return s;
}

static void child_readwrite(int s, int r)
{
	fd_set fds;
	int max;
	int ret;

	max = (r > s) ? r : s;
	max++;

	for (;;) {
		struct timeval tv;
		FD_ZERO(&fds);
		FD_SET(s, &fds);
		FD_SET(r, &fds);
		tv.tv_sec = 3600;
		tv.tv_usec = 0;
		ret = select(max, &fds, NULL, NULL, &tv);
		if (ret < 0)
			return;
		if (ret == 0) {
			logf("nothing happens in hour, disconnect\n");
			return;
		}
		if (FD_ISSET(s, &fds)) {
			ret = read(s, buf, bufsz);
			if (ret <= 0)
				return;
			if (write(r, buf, ret) <= 0)
				return;
		}
		if (FD_ISSET(r, &fds)) {
			ret = read(r, buf, bufsz);
			if (ret <= 0)
				return;
			if (write(s, buf, ret) <= 0)
				return;
		}
	}
}

static void child_work(char *from, int s)
{
	int r;
	struct timeval tv_start;
	char duration[32];

	gettimeofday(&tv_start, NULL);
	/* connect to target */
	r = jumpto(60);
	if (r < 0)
		return;

	child_readwrite(s, r);

	get_duration(duration, 32, &tv_start);
	logf("close %s %s [%s]\n", from, target, duration);
}

static void accept_and_run(int s)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int cli;
	pid_t pid;

	cli = accept(s, (struct sockaddr *)&addr, &len);
	if (cli == -1) {
		if (errno == EINTR)
			return;
		exit(1);
	}

	/* ok, fork it */
	pid = fork();
	if (pid) {
		/* no need client side socket */
		close(cli);
		return;
	}

	/* no need accept socket */
	close(s);

	enable_tcpkeepalive(cli, 120, 5, 5);
	child_work(inet_ntoa(addr.sin_addr), cli);
	_exit(0);
}

int main(int argc, char **argv)
{
	int port = defport;
	int s;

	if (argc < 3) {
		puts("usage: http-jumper <jump host> <target> [listen port]");
		puts(" jump host: address:port");
		puts(" target   : address:port");
		exit(1);
	}
	if (argc >= 4)
		port = atoi(argv[3]);

	jump = getaddr(argv[1]);
	if (jump == NULL) {
		logf("parse error jump: %s\n", argv[1]);
		exit(1);
	}

	target = argv[2];

	/* check jumper */
	s = jumpto(30);
	if (s < 0) {
		exit(1);
	}
	close(s);

	/* okay, jumphost and target work */

	/* don't care about child */
	signal(SIGCHLD, SIG_IGN);

	s = listensocket(port);
	if (s < 0)
		exit(1);

	/* accept loop */
	for (;;)
		accept_and_run(s);

	return 0;
}
