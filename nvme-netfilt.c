#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <sys/time.h>
#include <stdbool.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <linux/netfilter.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

// Added on 26th, May. Library for Wireshark epan.
#include "nvme_dissector.h"

#define TRUE 1
#define FALSE 0

void print_bits (u_char *data, int len) {
	u_char ptr = *data;
	int i = 0;
	printf("0b");

	for (i = (len - 1); i >= 0; i--) {
		printf("%d", (ptr & (1 << i)) >> i);
	}

	printf("\n");
}

void nvme_handle (void *payload, unsigned int dlen) {
	struct nvme_pdu_hdr *pduh;

	int i;

	u_char pdu_type;
	u_char *cur = (u_char *)payload;

	// Dissecting for identifying PDU_TYPE
	pduh = (struct nvme_pdu_hdr *)cur;
	pdu_type = pduh->pdu_type;

	if (pdu_type == CapsuleCmd) {
		struct nvme_rw_cmd *cmdh;
		struct nvme_cmd *sqe;

		cmdh = (struct nvme_rw_cmd *)cur;
		pduh = &cmdh->pduh;

		pdu_type = pduh->pdu_type;

		printf ("PDU Type : 0x%x\n", pdu_type);
		// printf ("Packet Length : %d\n", pduh->plen);

		sqe = &cmdh->cmd;

		u_char opc = sqe->cmd_dword0.cmd_opc;

		if (opc == NVME_OPC_WRITE) {
			printf ("CMD_OPC : 0x%x (Write)\n", opc);
			printf ("CMD_CID : 0x%x\n", sqe->cmd_dword0.cid);

			printf ("Write Data Length : %d\n", sqe->sgl_desc0.length);
		} 

		else if (opc == NVME_OPC_READ) {
			printf ("CMD_OPC : 0x%x (Read)\n", opc);
			printf ("CMD_CID : 0x%x\n", sqe->cmd_dword0.cid);
		}
		else if (opc == NVME_OPC_KEEP_ALIVE) {
			printf ("CMD_OPC : 0x%x (Keep Alive)\n", opc);
			printf ("CMD_CID : 0x%x\n", sqe->cmd_dword0.cid);
		}
	}
	else if (pdu_type == C2HData) {
		struct nvme_c2h_data *c2h_hdr;
		u_short cccid;

		c2h_hdr = (struct nvme_c2h_data *)cur;

		pduh = &c2h_hdr->pduh;
		pdu_type = pduh->pdu_type;

		printf ("PDU Type : 0x%x (C2HData)\n", pdu_type);
		printf ("Packet Length : %d\n", pduh->plen);

		printf ("RESP CMD_CID : 0x%x\n", c2h_hdr->cccid);
		// break;
	}
	else {
		u_char *old_ptr;

		// Check if there's Capsule Resp 
		int payload_end = dlen - 24;

		cur = cur + payload_end;
		old_ptr = cur;

		pduh = (struct nvme_pdu_hdr *) cur;
		pdu_type = pduh->pdu_type;

		if (pdu_type == CapsuleResp) {
			struct nvme_rw_resp *resph;
			
			resph = (struct nvme_rw_resp *) old_ptr;

			pduh = &resph->pduh;
			pdu_type = pduh->pdu_type;

			printf ("PDU Type : 0x%x (CapsuleResp)\n", pdu_type);
			printf ("Packet Length : %d\n", pduh->plen);

			printf ("CAPRESP_CID : 0x%x\n", resph->rccqe.cid);
		}	
	}

	printf("\n");
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
//	u_int32_t id = print_pkt(nfa);
	u_int32_t id;

	struct iphdr *ip;
	struct tcphdr *tcp;
	
	// Added on 26th, May.
	char *rawData;		// payload of packets (contains everything except ethhdr)
	void *payload;
	unsigned int dlen;

	struct timeval timestamp;

	int ret;
	int verdict = NF_ACCEPT;
	
	int length; 
	
	struct pkt_buff *pkbuff;
	// Added part end.

    struct nfqnl_msg_packet_hdr *ph;
	ph = nfq_get_msg_packet_hdr(nfa);

	// printf("packet callback\n");

	id = ntohl(ph->packet_id);		// Packet ID
	// Added on 26th May. get packet payload.
	
	length =  nfq_get_payload(nfa, &rawData);

	if (length < 0) {
		fprintf(stderr, "error in nfq_get_payload\n");
		goto ret;
	}
	
	pkbuff = pktb_alloc (AF_INET, rawData, length, 0x1000);

	if (pkbuff == NULL) {
		fprintf(stderr, "pktb_alloc error\n");
		goto ret;
	}

	// IP & TCP Header Dissecting.
	ip = nfq_ip_get_hdr(pkbuff);
	
	if (pkbuff == NULL) {
		fprintf(stderr, "no ip header\n");
		goto ret;
	}

	printf("New Packet Arrived\n");
	printf("Src: %s\n", inet_ntoa(*(struct in_addr *)&ip->saddr));
	printf("Dst: %s\n", inet_ntoa(*(struct in_addr *)&ip->daddr));

	if (nfq_ip_set_transport_header(pkbuff, ip) < 0) {
		fprintf(stderr, "no L4 header\n");
		goto ret;
	}

	if (ip->protocol == IPPROTO_TCP) {
		tcp = nfq_tcp_get_hdr (pkbuff);

		// printf("%d\n", nfq_ip_set_transport_header(pkbuff, ip));
		if (tcp == NULL) {
			fprintf(stderr, "no tcp header\n");
			goto ret;
		}
		
		payload = nfq_tcp_get_payload (tcp, pkbuff);
		dlen = nfq_tcp_get_payload_len(tcp, pkbuff);
	
		dlen -= 4 * tcp->th_off;

		printf("dlen : %d\n", dlen);
		
		if (tcp->th_flags & TH_ACK) {
			// If it is not piggybacking... (There NO PAYLOAD)
			if (dlen == 0) {
				goto ret;
			}
		}

		if (payload == NULL) {
			fprintf(stderr, "no payload\n");
			goto ret;
		}

		nvme_handle (payload, dlen);

		// nvme_get_cmd_opc (payload, dlen);
		// */
	}
ret:
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	int fd;
	int rv;
	char buf[4096] __attribute__ ((aligned));

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h,  0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	// para el tema del loss:   while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)

	while ((rv = recv(fd, buf, sizeof(buf), 0)))
	{
		// printf("pkt received\n");
		nfq_handle_packet(h, buf, rv);
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	 * it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}