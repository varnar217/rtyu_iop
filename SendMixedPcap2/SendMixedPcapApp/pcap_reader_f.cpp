#include "Global.h"
#include "Log.h"
#include "DateTime.h"
#include "common.h"
#include "pcap_reader.h"

#if USE_PCAP_READ == USE_PCAP_READ_FREAD

#include <memory.h>

#define USE_TIMESTAMP_SCALING 0 // использовать (=1) или нет (=0) искусстенное масштабирование значений временных меток пакетов
#if USE_TIMESTAMP_SCALING
double TimestampScalingCoeff = 0.00113; // * (1378 IP packet bytes + 36 IP+UDP+GTP headers bytes) by 1 ms = about 10 Gbit/sec
#endif

std::map<int, pcap_mem_t> PcapReader_c::PcapMap;

//------------------------------------------------------------------------------
PcapReader_c::PcapReader_c(GeneratorParams_s& gparams, GeneratorParams_s::Pcap_s& pparams, GeneratorParams_s::EpsBearer_s& eparams) :
  GeneratorParams(gparams), PcapParams(pparams), EpsBearerParams(eparams)
{
  
}

//------------------------------------------------------------------------------
PcapReader_c::~PcapReader_c()
{
  Close();
}

//------------------------------------------------------------------------------
bool PcapReader_c::Open()
{
  if(PcapReader_c::PcapMap.count(PcapParams.Id) == 0)
  {
    FILE* Pcap = fopen(PcapParams.Path.c_str(), "rb");
    if(Pcap == NULL)
    {
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "PCAP file %s has not opened\n", PcapParams.Path.c_str());
      std::string msg = std::string("PCAP file ") + PcapParams.Path + std::string(" open error");
      HttpClient.SendErr(msg);
      return false;
    }
    PRINT_LOG(PRINT_LEVEL::MIDDLE, "PCAP file %s has been opened successfully\n", PcapParams.Path.c_str());

    // вычисляем и сохраняем конечную позицию ПАКЕТОВ в файле
    if(fseek(Pcap, 0, SEEK_END) != 0)
    {
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "PCAP file %s set end position error\n", PcapParams.Path.c_str());
      return false;
    }
    long int PcapEndPos = ftell(Pcap);
    if(PcapEndPos == -1)
    {
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "PCAP file %s get end position error\n", PcapParams.Path.c_str());
      return false;
    }
    
    // вычисляем начальную позицию ПАКЕТОВ в файле (то есть первый байт после заголовка файла)
    size_t PcapBeginPos = sizeof(pcap_hdr_t);
    // возвращаемся к началу файла
    if(fseek(Pcap, 0, SEEK_SET) != 0)
    {
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "PCAP file %s set begin position error\n", PcapParams.Path.c_str());
      return false;
    }
    
    // прочитать весь файл от начала до конца в буфер
    std::unique_ptr<unsigned char[]> Data = std::make_unique<unsigned char[]>(PcapEndPos);
    if(Data == nullptr)
    {
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "PCAP file %s memory allocation error\n", PcapParams.Path.c_str());
      return false;
    }
    
    if(fread(Data.get(), sizeof(unsigned char), PcapEndPos, Pcap) != PcapEndPos)
    {
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "PCAP file %s read data error\n", PcapParams.Path.c_str());
      return false;
    }
    
    pcap_hdr_t* file_hdr = (pcap_hdr_t*)Data.get();

    // сохраняем для дальнейшего использования
    PcapReader_c::PcapMap[PcapParams.Id].Pcap = Pcap;
    PcapReader_c::PcapMap[PcapParams.Id].PcapBeginPos = PcapBeginPos;
    PcapReader_c::PcapMap[PcapParams.Id].PcapEndPos = PcapEndPos;
    PcapReader_c::PcapMap[PcapParams.Id].Data = std::move(Data);
    PcapReader_c::PcapMap[PcapParams.Id].MicrosecFlag = file_hdr->magic_number == 0xA1B2C3D4 ? true : false;
    PRINT_TMP(PRINT_LEVEL::MIDDLE, "PCAP file %s has been inserted into the map\n", PcapParams.Path.c_str());
  }
  
  PcapReader_c::PcapMap[PcapParams.Id].OwnerCount += 1;;
  PcapCurPos = PcapReader_c::PcapMap[PcapParams.Id].PcapBeginPos;
  PacketCount = 0;
  
  pcaprec_hdr_t* pkt_hdr = (pcaprec_hdr_t*)(PcapReader_c::PcapMap[PcapParams.Id].Data.get() + PcapCurPos);
  // временная метка пакета в микросекундах
  uint64_t ts = pkt_hdr->ts_sec*1000000ULL + (PcapReader_c::PcapMap[PcapParams.Id].MicrosecFlag ? pkt_hdr->ts_usec : pkt_hdr->ts_usec / 1000ULL);
#if USE_TIMESTAMP_SCALING
	ts = ts * TimestampScalingCoeff;
#endif
  PacketLastTimestamp = PacketFirstTimestamp = ts;
  
#if USE_GTP
  if(GeneratorParams.Gtp.IpSrc.empty())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "There is no source IP address for GTP\n");
		return false;
	}
  if(GeneratorParams.Gtp.IpDst.empty())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "There is no destination IP address for GTP\n");
		return false;
	}
  inet_aton(GeneratorParams.Gtp.IpSrc.c_str(), &GtpIpSrc);
  inet_aton(GeneratorParams.Gtp.IpDst.c_str(), &GtpIpDst);
#endif

  // выделение памяти под буфера пакетов
  for(auto& ptr: PktBuf)
    ptr = std::make_shared<EpsBearerPacket_s>();
  PktBufCur = 0;

#if USE_TMP_DEBUG
  t_all=0, t_make=0, t_memcopy=0, t_pkt=0, t_gtp=0, t_ip=0, t_ts=0, t_cnt = 0;
#endif

  return true;
}

//------------------------------------------------------------------------------
void PcapReader_c::Close()
{
  PcapReader_c::PcapMap[PcapParams.Id].OwnerCount -= 1;;
  if(PcapReader_c::PcapMap[PcapParams.Id].OwnerCount == 0)
  {
    // если файл был открыт, то его требуется зкрыть
    if(PcapReader_c::PcapMap[PcapParams.Id].Pcap)
    {
      fclose(PcapReader_c::PcapMap[PcapParams.Id].Pcap);
      PcapReader_c::PcapMap[PcapParams.Id].Pcap = NULL;
      PRINT_LOG(PRINT_LEVEL::MIDDLE, "PCAP file %s has been closed\n", PcapParams.Path.c_str());
    }
    PcapReader_c::PcapMap.erase(PcapParams.Id);
    PRINT_TMP(PRINT_LEVEL::MIDDLE, "PCAP file %s has been erased from the map\n", PcapParams.Path.c_str());
  }
#if ELIJA_DEBUG
  else if(PcapReader_c::PcapMap[PcapParams.Id].OwnerCount < 0)
    PRINT_LOG(PRINT_LEVEL::MIDDLE, "PCAP file %s owber count(%i) < 0\n", PcapParams.Path.c_str(), PcapReader_c::PcapMap[PcapParams.Id].OwnerCount);
#endif
#if USE_TMP_DEBUG
  if(t_cnt) PRINT_LOG(PRINT_LEVEL::HIGH, "Pcap file(%s) cnt=%llu, all=%llu, make=%llu, memcopy=%llu, pkt=%llu (gtp=%llu, ip=%llu, ts=%llu))\n", PcapParams.Path.c_str(), t_cnt, t_all/t_cnt, t_make/t_cnt, t_memcopy/t_cnt, t_pkt/t_cnt, t_gtp/t_cnt, t_ip/t_cnt, t_ts/t_cnt);
#endif
}

//------------------------------------------------------------------------------
std::shared_ptr<EpsBearerPacket_s> PcapReader_c::GetPacket()
{
#if USE_TMP_DEBUG
  std::time_t t1 = DateTime::GetAppTimeNanosecCount();
#endif
  //std::shared_ptr<EpsBearerPacket_s> pkt = std::make_shared<EpsBearerPacket_s>();
  std::shared_ptr<EpsBearerPacket_s> pkt = PktBuf[PktBufCur];
  PktBufCur = (PktBufCur + 1) & 0x03;
#if USE_TMP_DEBUG
  std::time_t t2 = DateTime::GetAppTimeNanosecCount();
  t_make += t2 - t1;
#endif
  
  // если указатель на пакет за пределами всех пакетов, то передвинуть указатель на начало первого пакета
  if(PcapCurPos == PcapReader_c::PcapMap[PcapParams.Id].PcapEndPos)
  {
    PcapCurPos = PcapReader_c::PcapMap[PcapParams.Id].PcapBeginPos;
    PacketRestartTimestamp = PacketLastTimestamp;
  }
  // считать пакет
  pcaprec_hdr_t* pkt_hdr = (pcaprec_hdr_t*)(PcapReader_c::PcapMap[PcapParams.Id].Data.get() + PcapCurPos);
  uint32_t pkt_size = pkt_hdr->incl_len;
  unsigned char* pkt_data = PcapReader_c::PcapMap[PcapParams.Id].Data.get() + PcapCurPos + sizeof(pcaprec_hdr_t);

  const struct sniff_ethernet *ethernet; /* Заголовок Ethernet */
  struct sniff_ip *ip; /* Заголовок IP */
  struct sniff_gtp1 *gtp; /* Заголовок GTP поверх IP */
  struct sniff_udp *udp2; /* Заголовок UDP поверх GTP+IP */
  struct sniff_ip *ip2; /* Заголовок IP поверх UDP+GTP+IP */

  u_int size_ip_hdr; // размер только заголовка IP пакета

#if ELIJA_WARNING // у нас ВРОДЕ только чистые IP-пакеты, но если вдруг будет сверху обёртка, то под неё нужно писать парсер/анализатор
  /* define/compute ip header offset */
  ip = (struct sniff_ip*)pkt_data;
#else // если IP-пакеты оюёрнуты в Ethernet
  /* define ethernet header */
  ethernet = (struct sniff_ethernet*)(pkt_data);
  
  /* define/compute ip header offset */
  ip = (struct sniff_ip*)(pkt_data + SIZE_ETHERNET);
#endif
  size_ip_hdr = IP_HL(ip)*4;
  if (size_ip_hdr < SIZE_IP) {
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "Invalid IP header length: %u bytes (%s)\n", size_ip_hdr, PcapParams.Path.c_str());
      return nullptr;
  }

  size_t size_ip_pkt = ntohs(ip->ip_len); // размер всего IP пакета (заголовок + данные)
#if ELIJA_TODO
/* Почему-то некоторые IP пакеты в PCAP файлах нашей базы имеют неправильное(?) значение ip->ip_len, которое превышает
 * значение pkt_hdr->incl_len, а этого быть не должно. Даже Wireshark подсвечивает красным эту ситуацию.
 * Для решения этой проблемы мы будем назначать ip->ip_len = pkt_hdr->incl_len, что верно в случае работы с "голыми" IP пакетами. */
  if(size_ip_pkt > pkt_hdr->incl_len)
  {
    size_ip_pkt = pkt_hdr->incl_len;
    ip->ip_len = htons(size_ip_pkt);
  }
#endif
  if(size_ip_pkt > EpsBearerPacketMaxSize - (SIZE_GTP + SIZE_UDP + SIZE_IP))
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "IP packet size is too large (current=%llu, maximum=%llu)\n", size_ip_pkt, EpsBearerPacketMaxSize - (SIZE_GTP + SIZE_UDP + SIZE_IP));
    return nullptr;
  }

#if USE_TMP_DEBUG
  std::time_t t3 = DateTime::GetAppTimeNanosecCount();
#endif
  // копировать считанные данные в свой пакет
#if USE_GTP
  memcpy(pkt->Data + (SIZE_GTP + SIZE_UDP + SIZE_IP), ip, size_ip_pkt);
#else
  memcpy(pkt->Data, ip, size_ip_pkt);
#endif
#if USE_TMP_DEBUG
  std::time_t t4 = DateTime::GetAppTimeNanosecCount();
  t_memcopy += t4 - t3;
#endif

#if USE_GTP
  pkt->IpHeader2 = (struct sniff_ip*)pkt->Data;
  pkt->UdpHeader2 = (struct sniff_udp*)(pkt->Data + SIZE_IP);
  pkt->GtpHeader = (struct sniff_gtp1*)(pkt->Data + (SIZE_IP + SIZE_UDP));
  pkt->IpHeader = (struct sniff_ip*)(pkt->Data + (SIZE_IP + SIZE_UDP + SIZE_GTP));
	
	pkt->GtpHeader->length = size_ip_pkt;
	pkt->GtpHeader->flags = 0x30;
	pkt->GtpHeader->msg_type = 0xFF;
	pkt->GtpHeader->teid = htonl(GetTeid());
	
	pkt->UdpHeader2->uh_sport = htons(2152);
	pkt->UdpHeader2->uh_dport = htons(2152);
	pkt->UdpHeader2->uh_ulen = htons(size_ip_pkt + (SIZE_UDP + SIZE_GTP));
	pkt->UdpHeader2->uh_sum = 0;
	
	pkt->IpHeader2->ip_vhl = 0x45;
	pkt->IpHeader2->ip_tos = 0;
	pkt->IpHeader2->ip_len = htons(size_ip_pkt + (SIZE_IP + SIZE_UDP + SIZE_GTP));
	pkt->IpHeader2->ip_id = PacketCount & 0xFFFF;
	pkt->IpHeader2->ip_off = 0;
	pkt->IpHeader2->ip_ttl = 64;
	pkt->IpHeader2->ip_p = 17; // UDP
	pkt->IpHeader2->ip_sum = 0;
#else
  pkt->IpHeader = (struct sniff_ip*)pkt->Data;
#endif
#if USE_TMP_DEBUG
  std::time_t t5 = DateTime::GetAppTimeNanosecCount();
  t_gtp += t5 - t4;
#endif
#if ELIJA_TODO
// здесь нужно разобраться когда и где использовать GeneratorParams.Gtp.IpSrc и GeneratorParams.Gtp.IpDst, а когда и где GeneratorParams.IpSrc и GeneratorParams.IpDst
#endif
#if USE_GTP
  pkt->IpHeader2->ip_src = GtpIpSrc;
  pkt->IpHeader2->ip_dst = GtpIpDst;
#else
  pkt->IpHeader->ip_src = GtpIpSrc;
  pkt->IpHeader->ip_dst = GtpIpDst;
#endif
#if USE_TMP_DEBUG
  std::time_t t6 = DateTime::GetAppTimeNanosecCount();
  t_ip += t6 - t5;
#endif

  // вычислить относительную временную метку пакета в мискросекундах (первый пакет файла всегда имеет относительную временную метку равную 0)
  uint64_t ts = pkt_hdr->ts_sec*1000000ULL + (PcapReader_c::PcapMap[PcapParams.Id].MicrosecFlag ? pkt_hdr->ts_usec : pkt_hdr->ts_usec / 1000ULL);
#if USE_TIMESTAMP_SCALING
	ts = ts * TimestampScalingCoeff;
#endif
  PacketLastTimestamp = pkt->Timestamp = ts - PacketFirstTimestamp + PacketRestartTimestamp;
#if USE_TMP_DEBUG
  std::time_t t7 = DateTime::GetAppTimeNanosecCount();
  t_ts += t7 - t6;
#endif

  // тип сервиса пакета
	pkt->Video = IsVideo();
  
  // сохраняем указатель на экземпляр создателя этого пакета
  pkt->PcapReader = weak_from_this();
#if USE_TMP_DEBUG
  std::time_t t8 = DateTime::GetAppTimeNanosecCount();
  t_pkt += t8 - t4;
#endif

#if 0 // отладочный вывод
  /* print source and destination IP addresses */
  PRINT_LOG(PRINT_LEVEL::HIGH, "       From: %s\n", inet_ntoa(pkt->IpHeader->ip_src));
  PRINT_LOG(PRINT_LEVEL::HIGH, "         To: %s\n", inet_ntoa(pkt->IpHeader->ip_dst));
  PRINT_LOG(PRINT_LEVEL::HIGH, "        Len: %u (%u)\n", ntohs(pkt->IpHeader->ip_len), size_ip_pkt);
  PRINT_LOG(PRINT_LEVEL::HIGH, "  Timestamp: %llu\n", pkt->Timestamp);
#if USE_GTP
  PRINT_LOG(PRINT_LEVEL::HIGH, "GTP IP From: %s\n", inet_ntoa(pkt->IpHeader2->ip_src));
  PRINT_LOG(PRINT_LEVEL::HIGH, "GTP IP   To: %s\n", inet_ntoa(pkt->IpHeader2->ip_dst));
#endif
#endif

  // передвинуть указатель на начало следующего пакета
  PcapCurPos += sizeof(pcaprec_hdr_t) + pkt_size;
  // увеличить счётчик считанных пакетов
  ++PacketCount;
  
#if USE_TMP_DEBUG
  std::time_t t9 = DateTime::GetAppTimeNanosecCount();
  t_all += t9 - t1;
  ++t_cnt;
#endif
	return pkt;
}

//------------------------------------------------------------------------------
GeneratorParams_s::EpsBearer_s& PcapReader_c::GetEpsBearer()
{
	return EpsBearerParams;
}

//------------------------------------------------------------------------------
int PcapReader_c::GetTeid() const
{
	return EpsBearerParams.Id;
}

//------------------------------------------------------------------------------
bool PcapReader_c::IsVideo() const
{
	return PcapParams.Video;
}

#endif
