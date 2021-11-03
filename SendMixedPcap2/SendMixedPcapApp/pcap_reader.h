/**
 * @file pcap_reader.h
 * @author elija
 * @date 15/09/21
 * @brief работа с pcap файлом в режиме чтения
 */

#pragma once

#define USE_PCAP_READ_LIBPCAP 1 // читать пакеты из pcap файла с помощью библиотеки Libpcap
#define USE_PCAP_READ_FREAD 2 // читать пакеты из pcap файла с помощью fread()
#define USE_PCAP_READ USE_PCAP_READ_FREAD // выбор средства чтения pcap файла

#include <pcap.h>
#if USE_PCAP_READ == USE_PCAP_READ_LIBPCAP
#include "pcap_reader_l.h"
#elif USE_PCAP_READ == USE_PCAP_READ_FREAD
#include "pcap_reader_f.h"
#else
illegal option USE_PCAP_READ
#endif

/* Ethernet адреса состоят из 6 байт */
#define ETHER_ADDR_LEN 6

/* Заголовки Ethernet всегда состоят из 14 байтов */
#define SIZE_ETHERNET 14

/* Заголовок Ethernet */
struct sniff_ethernet {
  u_char ether_dhost[ETHER_ADDR_LEN]; /* Адрес назначения */
  u_char ether_shost[ETHER_ADDR_LEN]; /* Адрес источника */
  u_short ether_type; /* IP? ARP? RARP? и т.д. */
};

#define ETHERTYPE_PUP         0x0200  /* PUP protocol */
#define ETHERTYPE_IP          0x0800  /* IP protocol */
#define ETHERTYPE_ARP         0x0806  /* Addr. resolution protocol */
#define ETHERTYPE_REVARP      0x8035  /* reverse Addr. resolution protocol */

// минимальный размер заголовка IP (для GTP будем использовать ровно этот размер)
#define SIZE_IP 20

/* IP header */
struct sniff_ip {
  u_char ip_vhl;  /* версия << 4 | длина заголовка >> 2 */
  u_char ip_tos;  /* тип службы */
  u_short ip_len;  /* общая длина */
  u_short ip_id;  /* идентефикатор */
  u_short ip_off;  /* поле фрагмента смещения */
  #define IP_RF 0x8000  /* reserved флаг фрагмента */
  #define IP_DF 0x4000  /* dont флаг фрагмента */
  #define IP_MF 0x2000  /* more флаг фрагмента */
  #define IP_OFFMASK 0x1fff /* маска для битов фрагмента */
  u_char ip_ttl;  /* время жизни */
  u_char ip_p;  /* протокол */
  u_short ip_sum;  /* контрольная сумма */
  struct in_addr ip_src,ip_dst; /* адрес источника и адрес назначения */
};
#define IP_HL(ip)  (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)  (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
  u_short th_sport; /* порт источника */
  u_short th_dport; /* порт назначения */
  tcp_seq th_seq;  /* номер последовательности */
  tcp_seq th_ack;  /* номер подтверждения */
  u_char th_offx2; /* смещение данных, rsvd */
  #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
  u_char th_flags;
  #define TH_FIN 0x01
  #define TH_SYN 0x02
  #define TH_RST 0x04
  #define TH_PUSH 0x08
  #define TH_ACK 0x10
  #define TH_URG 0x20
  #define TH_ECE 0x40
  #define TH_CWR 0x80
  #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;  /* окно */
  u_short th_sum;  /* контрольная сумма */
  u_short th_urp;  /* экстренный указатель */
};

/* length of UDP header */		
#define SIZE_UDP        8

struct sniff_udp {
  u_short uh_sport;       /* source port */
  u_short uh_dport;       /* destination port */
  u_short uh_ulen;        /* datagram length */
  u_short uh_sum;         /* datagram checksum */
};

// https://en.wikipedia.org/wiki/GPRS_Tunnelling_Protocol
// минимальный размер заголовка GTP (для GTP будем использовать ровно этот размер)
#define SIZE_GTP 8
// заголовок GTP
struct sniff_gtp1 {
	uint8_t flags;
	uint8_t msg_type;
	uint16_t length;
	uint32_t teid;
};

