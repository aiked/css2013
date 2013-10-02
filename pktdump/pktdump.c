#define __USE_BSD 1
#include <sys/types.h>
#include <sys/socket.h>

#define __FAVOR_BSD 1
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#ifdef __linux__
#include <netinet/ether.h>
#endif

#include <err.h>
#include <fcntl.h>
#include <pcap.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

void	cleanup(int sig);
void	pkt_printer(u_char *user, const struct pcap_pkthdr *h, const u_char *p);
char *	copy_args(const int argc, char * const argv[]);
int	usage(const char *app);

char *iflag; /* Network interface */
char *rflag; /* Read from file */
char *wflag; /* Write to file */

int dumpfd;
#define DUMPFPATH "pktdump.bin"

pcap_t *p; /* NIC pointer */
pcap_dumper_t *savefile; /* Trace file pointer */
struct bpf_program filter; /* BPF filter */
unsigned int snaplen = 65535;

int
main(int argc, char *argv[])
{
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_handler printer;
	u_char *userdata;
	struct in_addr net, mask;
	char *expr; /* BPF filter expression */
	int ch;

	while ((ch = getopt(argc, argv, "i:r:w:")) != -1)
		switch (ch) {
		case 'i':
			iflag = optarg;
			break;
		case 'r':
			rflag = optarg;
			break;
		case 'w':
			wflag = optarg;
			break;
		default:
			usage(argv[0]);
			/* NOTREACHED */
		}
	argc -= optind;
	argv += optind;

	/* expr = (argc > 0) ? argv[0] : NULL; */
	expr = copy_args(argc, &argv[0]);

	if (iflag)
		fprintf(stderr, "iflag: %s\n", iflag);
	if (rflag)
		fprintf(stderr, "rflag: %s\n", rflag);
	if (wflag)
		fprintf(stderr, "wflag: %s\n", wflag);
	if (expr)
		fprintf(stderr, "expr: %s\n", expr);

	if (rflag) {
		if ((p = pcap_open_offline(rflag, errbuf)) == NULL)
			err(1, errbuf);
		net.s_addr = 0;
		mask.s_addr = 0;
	} else {
		if (iflag)
			dev = iflag;
		else {
			if ((dev = pcap_lookupdev(errbuf)) == NULL)
				err(1, errbuf);
		}
		fprintf(stderr, "dev: %s\n", dev);

		if (pcap_lookupnet(dev, &net.s_addr, &mask.s_addr,
		                   errbuf) == -1) {
			warn(errbuf);
			net.s_addr = 0;
			mask.s_addr = 0;
		}
		fprintf(stderr, "net: %s\n", inet_ntoa(net));
		fprintf(stderr, "mask: %s\n", inet_ntoa(mask));

		if ((p = pcap_open_live(dev, snaplen, 1, 0, errbuf)) == NULL)
			err(1, errbuf);
	}

	if (wflag) {
		if ((savefile = pcap_dump_open(p, wflag)) == NULL)
			errx(1, "%s", pcap_geterr(p));
		printer = pcap_dump;
		userdata = (u_char *)savefile;
	} else {
		printer = pkt_printer;
		userdata = 0;
	}

	if (pcap_compile(p, &filter, expr, 0, mask.s_addr) == -1)
		errx(1, "%s", pcap_geterr(p));
	if (pcap_setfilter(p, &filter) == -1)
		errx(1, "%s", pcap_geterr(p));

	/* Expect ^C */
	signal(SIGINT, cleanup);

	/* Open the dumpfile */
	dumpfd = open(DUMPFPATH, O_WRONLY | O_EXCL | O_CREAT);
	if (dumpfd == -1)
		err(1, "open");

	if (pcap_loop(p, 0, printer, userdata) == -1)
		errx(1, "%s", pcap_geterr(p));
	cleanup(0);

	return (0);
}

void
cleanup(int sig)
{
	struct pcap_stat stat;

	pcap_breakloop(p);
	pcap_freecode(&filter);
	if (wflag) {
		pcap_dump_flush(savefile);
		pcap_dump_close(savefile);
	}
	if (!rflag) {
		if (pcap_stats(p, &stat) == -1)
			errx(1, "%s", pcap_geterr(p));
		fprintf(stderr, "\n");
		fprintf(stderr, "recv: %d ", stat.ps_recv);
		fprintf(stderr, "drop: %d ", stat.ps_drop);
	}
	fprintf(stderr, "\ndone\n");
	pcap_close(p);
	fflush(stdout);
	exit(0);
}

void
pkt_printer(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
	struct ether_header *eth;
	struct ip *ip;
	struct tcphdr *tcp;
	u_int16_t ip_len;
	u_int8_t ip_hlen, tcp_hlen;
	struct timeval *tvp;
	struct tm *tsp;
#define MAXTS 32
	char tsbuf[MAXTS];
	char *data;
	unsigned int datalen;

	/* IP and TCP header lengths are in 4-byte words */
	eth = (struct ether_header *)p;
	ip = (struct ip *)((u_char *)eth + ETHER_HDR_LEN);
	ip_hlen = ip->ip_hl << 2;
	tcp = (struct tcphdr *)((u_char *)ip + ip_hlen);
	tcp_hlen = tcp->th_off << 2;
	ip_len = ntohs(ip->ip_len);
	data = (char *)((u_char *)tcp + tcp_hlen);
	datalen = ip_len - ip_hlen - tcp_hlen;

	/* Print some useful info */
	tvp = (struct timeval *) &h->ts;
	tsp = (struct tm *) localtime((time_t * ) &tvp->tv_sec);
	strftime(tsbuf, sizeof(tsbuf), "%F %T", tsp);
	printf("%s.%06li ", tsbuf, tvp->tv_usec);
	printf("eth_len: %d ", ETHER_HDR_LEN + ip_len + ETHER_CRC_LEN);
	printf("eth_hlen: %d ", ETHER_HDR_LEN);
	printf("eth_crc: %d ", ETHER_CRC_LEN);
	printf("%s > ", ether_ntoa((struct ether_addr *) eth->ether_shost));
	printf("%s ", ether_ntoa((struct ether_addr *) eth->ether_dhost));
	printf("ip_len: %d ", ip_len);
	printf("ip_hlen: %d ", ip_hlen);
	printf("pr_len: %d ", ip_len - ip_hlen);
	printf("pr: ");
	switch (ip->ip_p) {
	case IPPROTO_TCP:
		printf("tcp ");
		break;
	case IPPROTO_UDP:
		printf("udp ");
		break;
	case IPPROTO_ICMP:
		printf("icmp ");
		break;
	default:
		printf("other ");
	}
	/* TCP and UDP headers have port numbers in the same place */
	printf("%s", inet_ntoa(ip->ip_src));
	if (ip->ip_p == IPPROTO_TCP || ip->ip_p == IPPROTO_UDP)
		printf(":%d", ntohs(tcp->th_sport));
	printf(" > ");
	printf("%s", inet_ntoa(ip->ip_dst));
	if (ip->ip_p == IPPROTO_TCP || ip->ip_p == IPPROTO_UDP)
		printf(":%d", ntohs(tcp->th_dport));
	if (!(ip->ip_p == IPPROTO_TCP)) {
		printf("\n");
		return;
	} else
		printf(" ");
	/* TCP only */
	printf("tcp_hlen: %d ", tcp_hlen);
	printf("tcp_flags: ");
	if (tcp->th_flags & TH_FIN)
		printf("fin ");
	if (tcp->th_flags & TH_SYN)
		printf("syn ");
	if (tcp->th_flags & TH_RST)
		printf("rst ");
	if (tcp->th_flags & TH_PUSH)
		printf("push ");
	if (tcp->th_flags & TH_ACK)
		printf("ack ");
	if (tcp->th_flags & TH_URG)
		printf("urg ");
	printf("tcp_datalen: %d\n", datalen);

	/* Dump payload */
	if (datalen > 0) {
		int len = datalen, nb;

		while (len > 0) {
			nb = write(dumpfd, data, len);
			if (nb == -1)
				err(1, "write");
			len -= nb;
			data += nb;
		}
	}
}

char *
copy_args(const int argc, char * const argv[])
{
	size_t len = 0;
	char *buf;
	int n;

	for (n = 0; n < argc; n++)
		len += strlen(argv[n]) + 1;
	if (len == 0)
		return (NULL);

	if ((buf = (char *)malloc(len)) == NULL)
		err(1, NULL);

	strncpy(buf, argv[0], len - 1);
	for (n = 1; argv[n]; n++) {
		strncat(buf, " ", len - 1 - strlen(buf));
		strncat(buf, argv[n], len - 1 - strlen(buf));
	}
	return (buf);
}

int
usage(const char *app)
{
	fprintf(stderr,
		"usage: %s [-i interface] [-r file] [-w file] [expression]\n",
		app);
	exit(1);
}
