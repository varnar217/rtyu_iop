/**
 * @file common.h
 * @author elija
 * @date 23/109/21
 * @brief общие для проекта типы, значения и т.д. и т.п.
 */
#pragma once
#include <map>
#include <list>
#include <memory>
#include "httplib.h"

bool thread_to_core(int coreID);

#define USE_TMP_DEBUG 0 // временно для отладочного вывода времён

#define USE_ONLY_READ 0 // только чтение пакетов юез отправки

#define USE_SYNCHRO_MUTEX 1
#define USE_SYNCHRO_ATOMIC 2
#define USE_SYNCHRO_SEMAPHORE 3
#define USE_SYNCHRO_OPTION USE_SYNCHRO_MUTEX

#define USE_GTP 1 // добавлять GTP = 1, не добавлять GTP = 0

class PcapReader_c;

#if ELIJA_TODO // нужно понять каким в реальной жизни должно быть значение EpsBearerPacketMaxSize
// максимальный размер пакета
#endif
const size_t EpsBearerPacketMaxSize = 30000;
// пакет
struct EpsBearerPacket_s
{
  std::weak_ptr<PcapReader_c> PcapReader;
	bool Video; // true = пакет содержит данные видео сервиса, false = НЕ содержит данные видео сервиса
  uint64_t Timestamp{0}; // временная метка пакета в микросекундах
  char Data[EpsBearerPacketMaxSize];
#if USE_GTP
  struct sniff_ip* IpHeader2{NULL}; // заголовок IP из стека GTP/UDP/IP
  struct sniff_udp* UdpHeader2{NULL}; // заголовок UDP из стека GTP/UDP/IP
  struct sniff_gtp1* GtpHeader{NULL}; // заголовок GTP из стека GTP/UDP/IP
#endif
  struct sniff_ip* IpHeader{NULL}; // заголовок IP считанный из PCAP файла
};

// состояние Генератора
struct GeneratorState_s
{
  bool Run{false}; // выполняется (=true) или остановлен (=false) Генератор
};

// параметры работы Генератора
struct GeneratorParams_s
{
#if ELIJA_TODO
	// в идеале здесь бы вместо 0 и 1 использовать именованные константы, например, enum
#endif
  int Mode{0}; // режим работы Генератора, "0" - в реальном времени с отправкиой в сеть или "1" - в режиме накопления с записью файла
  size_t Bitrate{10000000000}; // суммарный битрейт всех EPS-Bearer в битах в секунду
  std::string IpSrc;
  std::string IpDst;
  struct File_s { // описание использования файла записи выходного трафика
    std::string Path; // полный путь к папке в которой будет создаваться файл
    unsigned int Size{1024}; // размер файла в мегабайтах после которого он закрывается и автоматически создаётся следующий файл
  } File;
  struct Gtp_s {
    bool Use;
    std::string IpSrc;
    std::string IpDst;
    int MinTeid;
    int MaxTeid;
  } Gtp;
  struct Service_s {
    int Id;
    std::string Name;
  };
  std::map<int,Service_s> ServiceList;
  struct App_s {
    int Id;
    std::string Name;
  };
  std::map<int,App_s> AppList;
  struct Pcap_s {
    int Id;
    bool Video;
    Service_s Service;
    App_s App;
    int Bitrate;
    std::string Path;
		std::shared_ptr<PcapReader_c> PcapReader;
  };
  std::map<int, Pcap_s> PcapList;
  struct UserScenario_s {
    int Id;
    std::string Name;
    size_t Bitrate;
		std::map<int, Pcap_s> Pcap;
  };
  std::map<int, UserScenario_s> UserScenarioList;
  struct NetworkScenario_s {
    int Id;
    std::string Name;
    struct Jitter_s {
      int TimeUp;
      int TimeDown;
      int Value;
    } Jitter;
    struct Burst_s {
      int TimeUp;
      int TimeDown;
    } Burst;
  };
  std::map<int, NetworkScenario_s> NetworkScenarioList;
  struct EpsBearer_s {
    int Id;
    size_t Bitrate;
    UserScenario_s UserScenario;
    NetworkScenario_s NetworkScenario;
		// статистика
		std::time_t StatsTime; //время начала сбора статистики в миллисекундах
		size_t StatsVideoSize{0}; // размер в БАЙТАХ трафика с видео сервисами с момента времени Time
		size_t StatsNonVideoSize{0}; // размер в БАЙТАХ трафика с НЕ видео сервисами с момента времени Time
		size_t StatsPacketCount{0}; // количество пакетов с момента времени Time
  };
  std::map<int, EpsBearer_s> EpsBearerList;
	// статистика
	std::time_t StatsTime; //время начала сбора статистики в миллисекундах
	size_t StatsVideoSize{0}; // размер в БАЙТАХ трафика с видео сервисами с момента времени Time
	size_t StatsNonVideoSize{0}; // размер в БАЙТАХ трафика с НЕ видео сервисами с момента времени Time
	size_t StatsPacketCount{0}; // количество пакетов с момента времени Time
};

//------------------------------------------------------------------------------
// отправка сообщений от Генератора Интерфейсу по инициативе Генератора
class HttpClient_c
{
public:
	HttpClient_c() = default;
	~HttpClient_c() = default;
	
	void Open(const char* addr, int port);
	
	void SendErr(std::string& msg);
private:
  std::mutex ClientMutex;
	std::unique_ptr<httplib::Client> Client;
};

// HTTP-клиент для отправки сообщений с Генератора на Интерфейс по инициативе Генератора
extern HttpClient_c HttpClient;

