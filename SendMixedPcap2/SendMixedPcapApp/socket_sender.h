/**
 * @file socket_sender.h
 * @author elija
 * @date 16/09/21
 * @brief отправка сетевых пакетов с помощью RAW сокетов
 */

#pragma once

#include "eps_bearer_muxer.h"
#include  "pcap_writer.h"
#include <sys/socket.h>
#include <list>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

//#define SYNCHRO_MODE_MUTEX 1 // std::mutex + std::condition_variable
//#define SYNCHRO_MODE_ATOMIC 2 //  C++20 std::atomic с функциями ожидания/оповещения (wait/notify)
//#define SYNCHRO_MODE_SEMAPHORE 3 // C++20 std::counting_semaphore
#define SYNCHRO_MODE_PS SYNCHRO_MODE_MUTEX // выбранный способ синхронизации для PacketSender_c

#if SYNCHRO_MODE_PS == SYNCHRO_MODE_SEMAPHORE
#include <semaphore>
#endif

#define USE_OWN_INTERNAL_SEND_THREAD 1 // использовать(=1) или нет(=0) собственный внутренний поток отправки пакетов

/**
* @class PacketSender_c
 * @brief класс для отправки сетевых пакетов с помощью RAW сокета
 */
class PacketSender_c
{
public:
  PacketSender_c();
  ~PacketSender_c();
  
  ssize_t SendPacketIp(const struct sniff_ip *ip, ssize_t len);

	// настроить параметры работы перед использованием
	bool Open(GeneratorParams_s& gparams, std::function<std::shared_ptr<EpsBearerPacket_s>()> get_packet);
	
	// завершить работу
	void Close();
	
	// взять из очереди пакетов пакет с самой ранней временной меткой
	std::function<std::shared_ptr<EpsBearerPacket_s>()>GetPacket;

	// функция потока по отправке пакетов из очереди пакетов
  void SendPacket(std::function<std::shared_ptr<EpsBearerPacket_s>()> get_packet);

	// установить режим работы
	bool SetMode();
	
private:
	// режим работы (может изменяться только когда Ядро ГТО не работает):
	// 0 = в реальном времени с отправкой пакетов в сеть,
	// 1 = в режиме с накоплением и формированием массивов размеченных данных на жёстком диске)
	int Mode{-1};
	
	// сохранение отправляемых пакетов в PCAP файл
	std::unique_ptr<PcapWriter_c> PcapWriter;

  // признак завершения работы потока
	std::atomic_bool StopFlag;
	
	// поток отправки пакетов из очереди
  std::thread SendPacketThread;
};