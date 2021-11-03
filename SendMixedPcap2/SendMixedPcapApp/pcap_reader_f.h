/**
 * @file pcap_reader_f.h
 * @author elija
 * @date 31/10/21
 * @brief работа с pcap файлом в режиме чтения
 */

#pragma once
#include "common.h"
#include <cstdio>
#include <memory>
#include <map>

typedef struct pcap_hdr_s {
        uint32_t magic_number;   /* magic number: 0xA1B2C3D4 - microseconds, 0xA1B23C4D - nanoseconds */
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;       /* GMT to local correction */
        uint32_t sigfigs;        /* accuracy of timestamps */
        uint32_t snaplen;        /* max length of captured packets, in octets */
        uint32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        uint32_t ts_sec;         /* timestamp seconds */
        uint32_t ts_usec;        /* timestamp microseconds OR nanoseconds */
        uint32_t incl_len;       /* number of octets of packet saved in file */
        uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef struct pcap_mem_s
{
  FILE* Pcap {NULL}; //!< указатель на pcap файл
  std::unique_ptr<unsigned char[]> Data; // все данные файла
  size_t PcapBeginPos {0}; //!< начальная позиция в файле (соответстует первому пакету файла)
  size_t PcapEndPos {0}; //!< конечная позиция в файле
  bool MicrosecFlag; //!< формат временной метки: true - в микросекундах, false - в наносекундах
  int OwnerCount{0}; //!< подсчёт количества активных пользователей файла
} pcap_mem_t;

/**
 * @class PcapReader_c
 * @brief класс для работы с открытым в режиме чтения pcap файлом через fopen, fclose, fread
 */
class PcapReader_c: public std::enable_shared_from_this<PcapReader_c>
{
public:
  PcapReader_c(GeneratorParams_s& gparams, GeneratorParams_s::Pcap_s& pparams, GeneratorParams_s::EpsBearer_s& eparams);
  ~PcapReader_c();
  
	// начать работу с файлом
	bool Open();
  
	// завершить работу с файлом
	void Close();
  
	// взять из очереди пакетов пакет с самой ранней временной меткой
  std::shared_ptr<EpsBearerPacket_s> GetPacket();
	
	// получить ссылку на параметры EpsBearer
	GeneratorParams_s::EpsBearer_s& GetEpsBearer();

private:
	// получить уникальный идентификатор EpsBearer
	int GetTeid() const;
	
	// узнать содержит ли PCAP файл сервис видео (true=да, false=нет)
	bool IsVideo() const;
  
  // все открытые PCAP файлы копируются в память
  static std::map<int, pcap_mem_t> PcapMap;
  
  // индекс следующего буфера пакета
  int PktBufCur{0};
  // массив буферов для пакетов
  std::array<std::shared_ptr<EpsBearerPacket_s>, 4> PktBuf;
  
	GeneratorParams_s& GeneratorParams;
	GeneratorParams_s::Pcap_s& PcapParams;
	GeneratorParams_s::EpsBearer_s& EpsBearerParams;
  size_t PcapCurPos {0}; //!< конечная позиция в файле
  uint64_t PacketCount {0}; // номер последнего считанного из файла пакета
  uint64_t PacketFirstTimestamp {0}; //!< временная метка первого пакета файла в миллисекундах
  uint64_t PacketLastTimestamp {0}; //!< временная метка последнего считанного пакета файла в миллисекундах
  uint64_t PacketRestartTimestamp {0}; //!< временная метка первого пакета файла после рестарта в миллисекундах
  
  struct in_addr GtpIpSrc;
  struct in_addr GtpIpDst;

#if USE_TMP_DEBUG
  std::time_t t_all=0, t_make=0, t_memcopy=0, t_pkt=0, t_gtp=0, t_ip=0, t_ts=0, t_cnt = 0;
#endif
};