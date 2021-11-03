/**
 * @file eps_bearer.h
 * @author elija
 * @date 17/09/21
 * @brief формирование потока сетевых пакетов для одного EPS-Bearer
 */
#pragma once
#include "pcap_reader.h"
#include <list>
#include <map>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include "common.h"

//https://question-it.com/questions/824436/condition_variable-ne-poluchaet-uvedomlenija-o-probuzhdenii-dazhe-s-predikatom
#define SYNCHRO_MODE_MUTEX 1 // std::mutex + std::condition_variable
// Как работают wait и notify для std::atomic в C++20?
// https://ru.stackoverflow.com/questions/1333605/%d0%9a%d0%b0%d0%ba-%d1%80%d0%b0%d0%b1%d0%be%d1%82%d0%b0%d1%8e%d1%82-wait-%d0%b8-notify-%d0%b4%d0%bb%d1%8f-stdatomic-%d0%b2-c20
// https://stackoverflow.com/questions/69385119/how-do-wait-and-notify-work-for-stdatomic-in-c20
// РЕЗЮМЕ: Похоже, что в gcc-11.1 есть ошибка при работе с std::atomic wait/notify, а в gcc-11.2 она уже исправлена
#define SYNCHRO_MODE_ATOMIC 2 //  C++20 std::atomic с функциями ожидания/оповещения (wait/notify)
#define SYNCHRO_MODE_SEMAPHORE 3 // C++20 std::counting_semaphore
#define SYNCHRO_MODE_EB SYNCHRO_MODE_MUTEX // выбранный способ синхронизации для EpsBearer_c

#if SYNCHRO_MODE_EB == SYNCHRO_MODE_SEMAPHORE
#include <semaphore>
#endif

/**
 * @class EpsBearer_c
 * @brief класс для формирования потока сетевых пакетов для одного EPS-Bearer
 *
 * смешивает в один поток сетевые пакеты из разных PCAP файлов по их временным меткам
 */
class EpsBearer_c:  public std::enable_shared_from_this<EpsBearer_c>
{
public:
  EpsBearer_c(int id);
  ~EpsBearer_c();

	// настроить параметры работы перед использованием
	bool Open(GeneratorParams_s::EpsBearer_s& ebp, GeneratorParams_s& params);
	
	// завершить работу
	void Close();

	// взять из очереди пакетов пакет с самой ранней временной меткой
  std::shared_ptr<EpsBearerPacket_s> GetPacket();

	// функция потока по считыванию новых пакетов в очередь пакетов
  void ReadPacket();
	
	// получить уникальный идентификатор
	int GetId() const;
	
	// получить статистику
	void GetStats(std::time_t& time_prev, std::time_t& time_curr, size_t& video_size, size_t& non_video_size, size_t& packet_count);
	
private:
	// уникальный идентификатор 
	int Id{-1};
	
	// копия параметров Params.EpsBearerList[Id] из GeneratorApp_c
	GeneratorParams_s::EpsBearer_s Params;
	
	// временная метка последнего отданного пакета
	uint64_t PacketLastTimestamp{0};
	
  // список всех PcapReader_c
  std::multimap<int, std::shared_ptr<PcapReader_c>> PcapReaderList;

  std::atomic_bool StopFlag;
  // упорядоченные по времени пакеты от каждого из всех PcapReader_c
#if ELIJA_TODO // подумать и возможно поменять list на map или что-то подобное с упорядочиванием по key
  std::list<std::shared_ptr<EpsBearerPacket_s>> Packets;
#endif
#if SYNCHRO_MODE_EB == SYNCHRO_MODE_MUTEX
  bool GetPacketFlag{true};
  bool ReadPacketFlag{false};
  std::mutex PacketsMutex;
  std::condition_variable ReadPacketCv;
  std::condition_variable GetPacketCv;
#elif SYNCHRO_MODE_EB == SYNCHRO_MODE_ATOMIC
  std::atomic_flag GetCondAtomicFlag;
  std::atomic_flag ReadCondAtomicFlag;
#elif SYNCHRO_MODE_EB == SYNCHRO_MODE_SEMAPHORE
  std::counting_semaphore<1> GetSignal{1};
  std::counting_semaphore<1> ReadSignal{0};
#else
  illegal option
#endif
  // поток чтения пакетов из Pcap
  std::thread ReadPacketThread;
	
	// статистика
	std::mutex StatsMutex;
	std::time_t StatsTime; //время начала сбора статистики в миллисекундах
	size_t StatsVideoSize{0}; // размер в БАЙТАХ трафика с видео сервисами с момента времени Time
	size_t StatsNonVideoSize{0}; // размер в БАЙТАХ трафика с НЕ видео сервисами с момента времени Time
	size_t StatsPacketCount{0}; // количество пакетов с момента времени Time
	//int StatsVideoPercent{0}; // процент видео в трафике с момента времени Time
	//int StatsAveragePacketSize{0}; // средний размер одного пакета в БАЙТАХ с момента времени Time
};
