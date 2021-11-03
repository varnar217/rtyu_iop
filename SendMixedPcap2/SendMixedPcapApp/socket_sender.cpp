#include "Global.h"
#include "Log.h"
#include "DateTime.h"
#include "common.h"
#include "socket_sender.h"

/*
 https://habr.com/ru/company/smart_soft/blog/184430/
 При отправке данных через raw сокет у программиста есть выбор – переложить
 задачу создания IP заголовков на ядро или создавать заголовки самому.
 Второе возможно при использовании сокетной опции IP_HDRINCL (плюс в Linux есть
 ситуация, когда данная опция будет включена автоматически, если в качестве
 третьего аргумента в вызове socket() использовать константу IPPROTO_RAW).
 Однако, даже в случае использования опции IP_HDRINCL ядро все равно будет
 “ассистировать” программисту. Так, поля заголовка дейтаграммы Total Length и
 Header Checksum всегда автоматически заполняются ядром, а поля Source Address и
 Identification будут заполнены ядром, если программист оставит их значения
 равными нулю. Возможность создать свой заголовок дейтаграммы используется в
 основном для отправки пакетов с «проспуфленным» source IP-адресом. 
 */

/* исходный код написан на основе примера по ссылке:
 https://gist.github.com/leonid-ed/909a883c114eb58ed49f
 */

#define USE_RAW_SOCKET 1 // использовать в RAW sockets
#define USE_DPDK 2 // использовать dpdk
#define USE_SENDER USE_RAW_SOCKET // что использовать для отправки пакетов в сеть

#define USE_PACKET_SOURCE_MUXER 1 // испоьзовать в качестве источника пакетов EpsBearerMuxer (основноый режим работы программы)
#define USE_PACKET_SOURCE_BEARER 2 // испоьзовать в качестве источника пакетов EpsBearer (тестовый режим работы программы)
#define USE_PACKET_SOURCE_READER 3 // испоьзовать в качестве источника пакетов PcapReader (тестовый режим работы программы)
#define USE_PACKET_SOURCE_OPTION USE_PACKET_SOURCE_MUXER

#define USE_SENDTO 1 // отправлять(=1) или нет(=0) пакеты по сети
#define USE_SEND_BY_TIMESTAMP 1 // отправка пакетв по временным меткам ВРОДЕ работает, но нужно провести больше тестов)

#define USE_PRINT_PACKET 0 // отладочный вывод на экран информации по каждому отправляемому пакету
#define USE_FAKE_PACKET 0// будем всегда использовать только один первый считанный из pcap файла пакет

#define USE_LOCAL_OR_REMOTE 0 // 0 = local host; 1 = remote host

#if USE_LOCAL_OR_REMOTE == 0
/*
    An example of using raw sockets.
    You can capture packets by tcpdump:
        tcpdump -X -s0 -i lo -p udp
 */
#elif USE_LOCAL_OR_REMOTE == 1
/*
    An example of using raw sockets.
    You can capture packets by tcpdump:
        tcpdump -X -s0 -i eth0 -p udp
 */
#endif

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#if USE_SENDER == USE_RAW_SOCKET
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#elif USE_SENDER == USE_DPDK
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#else
illegal option USE_SENDER
#endif

#if USE_PACKET_SOURCE_OPTION == USE_PACKET_SOURCE_MUXER
#elif USE_PACKET_SOURCE_OPTION == USE_PACKET_SOURCE_BEARER
not supported option USE_PACKET_SOURCE_BEARER
#elif USE_PACKET_SOURCE_OPTION == USE_PACKET_SOURCE_READER
std::shared_ptr<PcapReader_c> PcapReaderForSender;
#else
illegal option USE_PACKET_SOURCE_OPTION
#endif

#define PCKT_LEN 8192

//------------------------------------------------------------------------------
/* Function for checksum calculation. From the RFC, the checksum algorithm is:
  "The checksum field is the 16 bit one's complement of the one's
  complement sum of all 16 bit words in the header.  For purposes of
  computing the checksum, the value of the checksum field is zero." */
static unsigned short csum(unsigned short *buf, int nwords)
{
  unsigned long sum;
  for(sum=0; nwords>0; nwords--)
    sum += *buf++;
  sum = (sum >> 16) + (sum &0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

//------------------------------------------------------------------------------
PacketSender_c::PacketSender_c()
{
  PRINT_LOG(PRINT_LEVEL::HIGH, "PacketSender_c(%p)::USE_OWN_INTERNAL_SEND_THREAD=%i\n", this, USE_OWN_INTERNAL_SEND_THREAD);
  PRINT_LOG(PRINT_LEVEL::HIGH, "PacketSender_c(%p)::USE_SENDTO=%i\n", this, USE_SENDTO);
  PRINT_LOG(PRINT_LEVEL::HIGH, "PacketSender_c(%p)::USE_SEND_BY_TIMESTAMP=%i\n", this, USE_SEND_BY_TIMESTAMP);
  PRINT_LOG(PRINT_LEVEL::HIGH, "PacketSender_c(%p)::USE_LOCAL_OR_REMOTE=%i (%s)\n", this, USE_LOCAL_OR_REMOTE,
    USE_LOCAL_OR_REMOTE == 0 ? "Local" : USE_LOCAL_OR_REMOTE == 1 ? "Remote" : "Error");
  PRINT_LOG(PRINT_LEVEL::HIGH, "PacketSender_c(%p)::USE_SENDER=%i (%s)\n", this, USE_SENDER,
    USE_SENDER == USE_RAW_SOCKET ? "RAW socket" : USE_SENDER == USE_DPDK ? "DPDK" : "Error");
  PRINT_LOG(PRINT_LEVEL::HIGH, "PacketSender_c(%p)::USE_PACKET_SOURCE_OPTION=%i (%s)\n", this, USE_PACKET_SOURCE_OPTION,
    USE_PACKET_SOURCE_OPTION == USE_PACKET_SOURCE_MUXER ? "EpsBearerMuxer" : USE_SENDER == USE_PACKET_SOURCE_BEARER ? "EpsBearer" : USE_SENDER == USE_PACKET_SOURCE_READER ? "PcapReader" : "Error");
  PRINT_LOG(PRINT_LEVEL::HIGH, "PacketSender_c(%p)::USE_FAKE_PACKET=%i\n", this, USE_FAKE_PACKET);
  PRINT_LOG(PRINT_LEVEL::HIGH, "PacketSender_c(%p)::SYNCHRO_MODE_PS=%i (%s)\n", this, SYNCHRO_MODE_PS,
    SYNCHRO_MODE_PS == SYNCHRO_MODE_MUTEX ? "Mutex" : SYNCHRO_MODE_PS == SYNCHRO_MODE_ATOMIC ?
    "Atomic" : SYNCHRO_MODE_PS == SYNCHRO_MODE_SEMAPHORE ? "Semaphore" : "Error");
  //PRINT_TMP(PRINT_LEVEL::HIGH, "DEBUG: %p: Constructor\n", this);
}

//------------------------------------------------------------------------------
PacketSender_c::~PacketSender_c()
{
	Close();
}

//------------------------------------------------------------------------------
bool PacketSender_c::Open(GeneratorParams_s& gparams, std::function<std::shared_ptr<EpsBearerPacket_s>()> get_packet)
{
	// сохранить копию режима работы
	Mode = gparams.Mode;

	PcapWriter = std::make_unique<PcapWriter_c>(gparams.File.Path, gparams.File.Size);
	
	StopFlag = false;
	
	SendPacketThread = std::thread(&PacketSender_c::SendPacket, this, get_packet);
  return true;
}

//------------------------------------------------------------------------------
void PacketSender_c::Close()
{
  StopFlag = true;

  if(SendPacketThread.joinable())
    SendPacketThread.join();
}

//------------------------------------------------------------------------------
void PacketSender_c::SendPacket(std::function<std::shared_ptr<EpsBearerPacket_s>()> get_packet)
{
  // привязать этот поток к ядру процессора с индексом 2
  thread_to_core(2);

  // здесь происходит отправка пакета в сеть любым желаемым средством (RAW socket, dpdk, ...)
  // при желании здесь же можно сделать механизм объединения пакетов перед отправкой

#if USE_SENDER == USE_RAW_SOCKET
const int StrErrorBufSize = 512;
  char StrErrorBuf[StrErrorBufSize]; // буфер для хранения описания ошибки

#if USE_SENDTO
  /* https://beej.us/guide/bgnet/html/#socket:
   Oh well. So the correct thing to do is to use AF_INET in your struct
   sockaddr_in and PF_INET in your call to socket(). But practically speaking,
   you can use AF_INET everywhere.
   */
  // create a raw socket with raw protocol
  int Socket = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
  if (Socket < 0) {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "socket() error: %s\n", strerror_r(errno, StrErrorBuf, StrErrorBufSize));
    return;
  }
  PRINT_LOG(PRINT_LEVEL::MIDDLE, "OK: a raw socket is opened (sd = %d)\n", Socket);
  
#if 0  // привязка к кокнретному сетевому интерфейсу (если у нас их несколько на машине)
// https://stackoverflow.com/questions/1207746/problems-with-so-bindtodevice-linux-socket-option
// https://www.beej.us/guide/bgnet/html/index-wide.html
  // bind a socket to a device name (might not work on all systems):
  //char *optval2 = "eth1"; // 4 bytes long, so 4, below:
  //setsockopt(Socket, SOL_SOCKET, SO_BINDTODEVICE, optval2, 4);
  /*
   * https://stackoverflow.com/questions/12603096/how-to-make-a-tcp-socket-work-with-so-bindtodevice-against-routing-table
   * https://stackoverflow.com/questions/33917575/choosing-socket-output-interface-so-bindtodevice-vs-bind-before-connect?rq=1
   * https://stackoverflow.com/questions/26278882/manually-specify-which-network-interface-to-send-data
   * https://stackoverflow.com/questions/19495414/how-to-stop-behaviour-c-socket-sendto-changes-interface
   * https://www.linuxquestions.org/questions/linux-networking-3/linux-network-stack-behavior-with-so_bindtodevice-4175577509/?__cf_chl_jschl_tk__=pmd_nDNmjeQedL1WMQEFVnXMt0xg1MyzqUDvPOIx9DLri3Q-1635904489-0-gqNtZGzNArujcnBszQil
   */
  char *optval2 = "enp66s0f0"; // 9 bytes long, so 9, below:
  //char *optval2 = "enp66s0f1"; // 9 bytes long, so 9, below:
  if (setsockopt(Socket, SOL_SOCKET, SO_BINDTODEVICE, optval2, 9) != 0) {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "setsockopt() error: %s\n", strerror_r(errno, StrErrorBuf, StrErrorBufSize));
    return;
  }

#if 0
  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = 0; // Auto-determine port.
  sin.sin_addr.s_addr = inet_addr("192.168.1.111"); //Your IP address on same network as peer you want to connect to
  bind(Socket, (sockaddr*)&sin, sizeof(sin));
#endif
#endif
#else
#endif

#if USE_PRINT_PACKET // требуется только для отладочного вывода адресов пакета
  // адреса источника и назначения в виде строки
  std::string src_str, dst_str;
#endif
#elif USE_SENDER == USE_DPDK
  int argc;
  char *argv[2];

  /* Initializion the Environment Abstraction Layer (EAL). 8< */
  int ret = rte_eal_init(argc, argv);
  if (ret < 0)
      rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
  /* >8 End of initializion the Environment Abstraction Layer (EAL). */
#else
illegal option USE_SENDER
#endif

  uint64_t pkts_count = 0; // номер последнего отправленного пакета
  uint64_t pkts_size = 0; // размер всех отправленных пакетов

  PRINT_LOG(PRINT_LEVEL::MIDDLE, "Send thread started\n");
  
#if USE_TMP_DEBUG
  std::time_t t1, t_all, t_get=0, t_send=0, t_ts=0, t_sendto=0, t_cnt = 0;
  t1 = DateTime::GetAppTimeNanosecCount();
#endif

  std::time_t sender_start_time = DateTime::GetAppTimeMicrosecCount();

  while(StopFlag == false)
  {
#if USE_ONLY_READ
        std::this_thread::sleep_for(std::chrono::seconds(1));
        continue;
#endif        
		std::shared_ptr<EpsBearerPacket_s> pkt = get_packet();
#if USE_TMP_DEBUG
    std::time_t t2 = DateTime::GetAppTimeNanosecCount();
    t_get += t2 - t1;
#endif
		if(StopFlag)
			break;
		else if(pkt == nullptr)
		{
			PRINT_ERR(PRINT_LEVEL::MIDDLE, "PacketSender received a null packet\n");
			break;
		}
#if USE_GTP
    const ssize_t pkt_size = ntohs(pkt->IpHeader2->ip_len);
#else
    const ssize_t pkt_size = ntohs(pkt->IpHeader->ip_len);
#endif
		if(Mode == 1) // записывать все отправленные пакеты в файл только в режиме с накоплением и формированием массивов размеченных данных
    {
#if USE_GTP
			PcapWriter->WritePacket((unsigned char *)pkt->IpHeader2, pkt_size, pkt->Video, pkt->Timestamp);
#else
			PcapWriter->WritePacket((unsigned char *)pkt->IpHeader, pkt_size, pkt->Video, pkt->Timestamp);
#endif
    }
		else
    {
#if 0 // в текущий момент не используем запись пакетов и разметки в файл для режима работы в реальном времени, но пусть код останется
#if USE_GTP
			PcapWriter->WritePacket((unsigned char *)pkt->IpHeader2, pkt_size, pkt->Video, DateTime::GetAppTimeMicrosecCount());
#else
			PcapWriter->WritePacket((unsigned char *)pkt->IpHeader, pkt_size, pkt->Video, DateTime::GetAppTimeMicrosecCount());
#endif
#endif
#if USE_SEND_BY_TIMESTAMP
#if USE_TMP_DEBUG
    std::time_t t5 = DateTime::GetAppTimeNanosecCount();
#endif
      std::time_t time = DateTime::GetAppTimeMicrosecCount() - sender_start_time;
      while(time < pkt->Timestamp && StopFlag == false)
      {
        time = DateTime::GetAppTimeMicrosecCount() - sender_start_time;
      } 
#if USE_TMP_DEBUG
    std::time_t t6 = DateTime::GetAppTimeNanosecCount();
    t_ts += t6 - t5;
#endif
#endif

#if USE_SENDER == USE_RAW_SOCKET
#if USE_SENDTO
      struct sockaddr_in sin;
      sin.sin_family = AF_INET;
#if ELIJA_TODO 
      /*
      For instance, by using IPPROTO_RAW (which automatically implies IP_HDRINCL),
      you show your intention that you want to create the IP header on your own.
      Thus the last two arguments of sendto() are actually redundant information,
      because they're already included in the data buffer you pass to sendto() as
      the second argument.
      In addition, the dest_addr passed in sendto() will be used by kernel to
      determine which network interface to used.
      For example, if dest_addr has ip 127.0.0.1 and the raw packet has dest
      address 8.8.8.8, your packet will still be routed to the lo interface.
      */
      //sin.sin_port = htons(dst_port);
#if USE_LOCAL_OR_REMOTE == 0
      sin.sin_addr.s_addr = inet_addr("127.0.0.1");
#elif USE_LOCAL_OR_REMOTE == 1
#if USE_GTP
      sin.sin_addr = pkt->IpHeader2->ip_dst;
#else
      sin.sin_addr = pkt->IpHeader->ip_dst;
#endif
#endif
#endif

      ssize_t size = 0; // отправленная часть пакета в байтах
#if USE_GTP
      const char* ptr = (const char *)pkt->IpHeader2; // указатель на текущие отправляемые данные пакета
#else
      const char* ptr = (const char *)pkt->IpHeader; // указатель на текущие отправляемые данные пакета
#endif
#if USE_TMP_DEBUG
      std::time_t t3 = DateTime::GetAppTimeNanosecCount();
#endif
      while(size < pkt_size)
      {
        ssize_t sz = sendto(Socket, ptr, pkt_size - size, 0, (struct sockaddr *)&sin, sizeof(sin));
        if (sz < 0)
        {
          PRINT_ERR(PRINT_LEVEL::MIDDLE, "sendto() error: %s\n", strerror_r(errno, StrErrorBuf, StrErrorBufSize));
          break;
        }
        if(StopFlag)
          break;
        ptr += sz;
        size += sz;
      }
#if USE_TMP_DEBUG
      std::time_t t4 = DateTime::GetAppTimeNanosecCount();
      t_sendto += t4 - t3;
#endif
      if(StopFlag)
        break;
#endif
#if USE_PRINT_PACKET
#if USE_GTP
      src_str = inet_ntoa(pkt->IpHeader2->ip_src);
      dst_str = inet_ntoa(pkt->IpHeader2->ip_dst);
#else
      src_str = inet_ntoa(pkt->IpHeader->ip_src);
      dst_str = inet_ntoa(pkt->IpHeader->ip_dst);
#endif
      PRINT_LOG(PRINT_LEVEL::HIGH, "Packet[%6i]: ts[%8llu], len[%5i], src[%16s], dst[%16s]\n", 
      pkts_count, pkt->Timestamp, pkt_size, src_str.c_str(), dst_str.c_str());
#endif
#elif USE_SENDER == USE_DPDK
#else
illegal option USE_SENDER
#endif
    }
    // обновить статистику
//#if USE_TMP_DEBUG
//    pkts_size += 1378;
//#else
    pkts_size += pkt_size;
//#endif
    pkts_count++;
    
#if USE_TMP_DEBUG
    std::time_t t = DateTime::GetAppTimeNanosecCount();
    t_all += t - t1;
    t_send += t - t2;
    t1 = t;
    t_cnt++;
#endif
  }
  std::time_t sender_stop_time = DateTime::GetAppTimeMicrosecCount();
  uint64_t send_time = sender_stop_time - sender_start_time;
  PRINT_LOG(PRINT_LEVEL::HIGH, "Send thread stopped after %llu microseconds (bitrate = %llu bits per sec)\n", send_time, pkts_size * 8000000 / send_time);
#if USE_TMP_DEBUG
  if(t_cnt) PRINT_LOG(PRINT_LEVEL::HIGH, "Send thread cnt=%llu, all=%llu (get=%llu + send=%llu (ts=%llu + sendto=%llu))\n", t_cnt, t_all/t_cnt, t_get/t_cnt, t_send/t_cnt, t_ts/t_cnt, t_sendto/t_cnt);
#endif
#if USE_SENDER == USE_RAW_SOCKET
#if USE_SENDTO
  if(Socket != -1)
  {
    int s = Socket;
    close(Socket);
    PRINT_LOG(PRINT_LEVEL::MIDDLE, "OK: a raw socket is closed (sd = %d)\n", s);
  }
#else
#endif
#elif USE_SENDER == USE_DPDK
#else
illegal option USE_SENDER
#endif
}
