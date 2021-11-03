/**
 * @file mix_eps_bearers.h
 * @author elija
 * @date 18/09/21
 * @brief формирование потока сетевых пакетов смешанных от многих EPS-Bearer
 */
#pragma once
#include "eps_bearer.h"
#include <list>
#include <map>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include "common.h"

//#define SYNCHRO_MODE_MUTEX 1 // std::mutex + std::condition_variable
//#define SYNCHRO_MODE_ATOMIC 2 //  C++20 std::atomic с функциями ожидания/оповещения (wait/notify)
//#define SYNCHRO_MODE_SEMAPHORE 3 // C++20 std::counting_semaphore
#define SYNCHRO_MODE_EBM SYNCHRO_MODE_MUTEX // выбранный способ синхронизации для EpsBearerMuxer_c

#if SYNCHRO_MODE_EBM == SYNCHRO_MODE_SEMAPHORE
#include <semaphore>
#endif

/**
 * @class EpsBearerMuxer_c
 * @brief класс для мультиплексирования потоков сетевых пакетов для всех EPS-Bearer в один сетевой поток
 */
class EpsBearerMuxer_c:  public std::enable_shared_from_this<EpsBearerMuxer_c>
{
public:
  EpsBearerMuxer_c(int id);
  ~EpsBearerMuxer_c();

	// добавить все EpsBearer в EpsBearerList, выполняется при старте приложения после чтения файла параметров
	bool Open(GeneratorParams_s& params);
	// хавершить работу
	void Close();
	// добавить EpsBearer в EpsBearerList с id = ebp.Id во время работы приложения
	bool AddEpsBearer(GeneratorParams_s::EpsBearer_s& ebp, GeneratorParams_s& params);
	// изменить параметры работы EpsBearer из EpsBearerList с id = ebp.Id во время работы приложения
	bool UpdateEpsBearer(GeneratorParams_s::EpsBearer_s& ebp, GeneratorParams_s& params);
	// удалить EpsBearer с id = ebp.Id из EpsBearerList во время работы приложения
	bool DeleteEpsBearer(GeneratorParams_s::EpsBearer_s& ebp);
	
	// взять из очереди пакетов пакет с самой ранней временной меткой
  std::shared_ptr<EpsBearerPacket_s> GetPacket();
	
	// функция потока по считыванию новых пакетов в очередь пакетов
  void ReadPacket();

	// получить уникальный идентификатор
	int GetId() const;
	
	// получить EpsBearer_c по id
	std::shared_ptr<EpsBearer_c> GetEpsBearer(int id);
	
	// получить статистику
	void GetStats(std::time_t& time_prev, std::time_t& time_curr, size_t& video_size, size_t& non_video_size, size_t& packet_count);
	
private:
	// уникальный идентификатор
	int Id{-1};
	
	// разграничение доступа к списку EpsBearerList из разных потоков
	std::mutex EpsBearerListMutex;
  // список всех EpsBearer_c
  std::map<int, std::shared_ptr<EpsBearer_c>> EpsBearerList;

  std::atomic_bool StopFlag;
	
  //std::atomic_bool GetFlag{false};
  //std::atomic_bool HttpFlag{false};
	
  // упорядоченные по времени пакеты от каждого из всех EpsBearer_c
#if ELIJA_TODO // подумать и возможно поменять list на map или что-то подобное с упорядочиванием по key
  std::list<std::shared_ptr<EpsBearerPacket_s>> Packets;
#endif
#if SYNCHRO_MODE_EBM == SYNCHRO_MODE_MUTEX
  bool GetPacketFlag{true};
  bool ReadPacketFlag{false};
  std::mutex PacketsMutex;
  std::condition_variable ReadPacketCv;
  std::condition_variable GetPacketCv;
#elif SYNCHRO_MODE_EBM == SYNCHRO_MODE_ATOMIC
  std::atomic_flag GetCondAtomicFlag;
  std::atomic_flag ReadCondAtomicFlag;
  //std::atomic_flag HttpCondAtomicFlag;
#elif SYNCHRO_MODE_EBM == SYNCHRO_MODE_SEMAPHORE
  std::counting_semaphore<1> GetSignal{1};
  std::counting_semaphore<1> ReadSignal{0};
  //std::counting_semaphore<1> HttpSignal{0};
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