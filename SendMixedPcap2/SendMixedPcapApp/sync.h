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
 * @class Sync_c
 * @brief класс для формирования потока сетевых пакетов для одного EPS-Bearer
 * 
 * смешивает в один поток сетевые пакеты из разных PCAP файлов по их временным меткам
 */
class Sync_c:  public std::enable_shared_from_this<Sync_c>
{
public:
  Sync_c();
  ~Sync_c();
  
  bool AddPcap(std::shared_ptr<PcapReader_c> pr);

  std::shared_ptr<EpsBearerPacket_s> GetPacket();
  void ReadPacket();

private:
  std::atomic_bool StopFlag;
  // упорядоченные по времени пакеты от каждого из всех Pcap
  std::list<std::shared_ptr<EpsBearerPacket_s>> Packets;
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