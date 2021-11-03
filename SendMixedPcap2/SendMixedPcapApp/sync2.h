/**
 * @file sync.h
 * @author elija
 * @date 17/09/21
 * @brief формирование потока сетевых пакетов для одного EPS-Bearer
 */
#pragma once
#include "pcap_reader.h"
#include <list>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

#define USE_ATOMIC_WAIT 1 // использовать (=1) или нет (=0) C++20 std::atomic с функциями ожидания/оповещения (wait/notify) вместо std::condition_variable

/**
 * @class Sync2_c
 * @brief класс для формирования потока сетевых пакетов для одного EPS-Bearer
 * 
 * смешивает в один поток сетевые пакеты из разных PCAP файлов по их временным меткам
 */
class Sync2_c
{
public:
  Sync2_c();
  ~Sync2_c();
  
  //bool AddPcap(std::shared_ptr<PcapReader_c> pr);

  void GetPacket();
  void ReadPacket();

private:
  std::atomic_bool StopFlag;
  // упорядоченные по времени пакеты от каждого из всех Pcap
  //std::list<std::shared_ptr<EpsBearerPacket_s>> Packets;
  std::thread GetPacketThread;
  // поток чтения пакетов из Pcap
  std::thread ReadPacketThread;
#if USE_ATOMIC_WAIT
  std::atomic_flag CondAtomicFlag1{};
  std::atomic_flag CondAtomicFlag2{};
#else
  bool WaitPacket{false};
  std::mutex PacketsMutex;
  std::condition_variable ReadPacketCv;
  std::condition_variable GetPacketCv;
#endif
};