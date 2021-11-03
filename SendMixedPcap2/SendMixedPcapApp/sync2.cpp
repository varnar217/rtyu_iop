#include "Global.h"
#include "Log.h"
#include "DateTime.h"
#include "sync2.h"

//------------------------------------------------------------------------------
Sync2_c::Sync2_c(): StopFlag(false), GetPacketThread(&Sync2_c::GetPacket, this), ReadPacketThread(&Sync2_c::ReadPacket, this)
{
#if USE_ATOMIC_WAIT
  CondAtomicFlag1.test_and_set();
  CondAtomicFlag1.notify_one();
#endif
}

//------------------------------------------------------------------------------
Sync2_c::~Sync2_c()
{
  StopFlag = true;
#if USE_ATOMIC_WAIT
  CondAtomicFlag1.test_and_set();
  CondAtomicFlag1.notify_one();
  CondAtomicFlag2.test_and_set();
  CondAtomicFlag2.notify_one();
#endif
  if(ReadPacketThread.joinable())
    ReadPacketThread.join();
  if(GetPacketThread.joinable())
    GetPacketThread.join();
}

/*
//------------------------------------------------------------------------------
bool Sync2_c::AddPcap(std::shared_ptr<PcapReader_c> pr)
{
  auto pkt = pr->GetPacket();
  if(pkt == nullptr)
    return false;
#if USE_ATOMIC_WAIT
#else
  std::unique_lock<std::mutex> lk(PacketsMutex);
#endif
  uint64_t pkt_ts = pkt->Timestamp;
  auto p = Packets.begin();
  while(p != Packets.end())
  {
    if(p->get()->Timestamp >= pkt_ts)
      break;
    p++;
  }
  Packets.insert(p, pkt);
#if USE_ATOMIC_WAIT
  CondAtomicFlag1.test_and_set();
  CondAtomicFlag1.notify_one();
#else
  WaitPacket = false;
  GetPacketCv.notify_one();
#endif
  return true;
}
*/

//------------------------------------------------------------------------------
void Sync2_c::GetPacket()
{
  uint64_t pkts_count = 0; // номер последнего отправленного пакета
  uint64_t pkts_size = 0; // размер всех отправленных пакетов

  PRINT_LOG(PRINT_LEVEL::MIDDLE, "fake_sender thread started\n");
  std::time_t sender_start_time = DateTime::GetAppTimeMicrosecCount();
  while(StopFlag == false)
  {
#if USE_ATOMIC_WAIT
    CondAtomicFlag1.wait(false);
    CondAtomicFlag1.clear();
    if(StopFlag == true)
      break;
#else
    std::unique_lock<std::mutex> lk(PacketsMutex);
    while(WaitPacket == true)
    {
      GetPacketCv.wait_for(lk, std::chrono::seconds(1));
      if(StopFlag == true)
        break;
    }
    if(StopFlag == true)
      break;
#endif
    //std::shared_ptr<EpsBearerPacket_s> pkt = Packets.front();
    //pkt->EpsBearer = weak_from_this();
#if USE_ATOMIC_WAIT
    CondAtomicFlag2.test_and_set();
    CondAtomicFlag2.notify_one();
#else
    WaitPacket = true;
    ReadPacketCv.notify_one();
#endif
    //return std::make_shared<EpsBearerPacket_s>();
    pkts_size += 1378;
    pkts_count++;
  }
  std::time_t sender_stop_time = DateTime::GetAppTimeMicrosecCount();
  uint64_t send_time = sender_stop_time - sender_start_time;
  PRINT_LOG(PRINT_LEVEL::HIGH, "fake_sender thread stopped after %llu microseconds (bitrate = %llu bits per sec)\n", send_time, pkts_size * 8000000 / send_time);
}

//------------------------------------------------------------------------------
void Sync2_c::ReadPacket()
{
  while(StopFlag == false)
  {
#if USE_ATOMIC_WAIT
    CondAtomicFlag2.wait(false);
    CondAtomicFlag2.clear();
#else
    std::unique_lock<std::mutex> lk(PacketsMutex);
    while(WaitPacket == false)
    {
      ReadPacketCv.wait_for(lk, std::chrono::seconds(1));
      if(StopFlag == true)
        break;
    }
#endif
    if(StopFlag == true)
      break;

/*
    std::shared_ptr<EpsBearerPacket_s> pkt_old = Packets.front();
    Packets.pop_front();
    auto pr = pkt_old->PcapReader.lock();
    if(pr == nullptr)
    {
#if USE_ATOMIC_WAIT
      CondAtomicFlag1.test_and_set();
      CondAtomicFlag1.notify_one();
#endif
      continue; // породивший пакет PcapReader уже не существует
    }
    std::shared_ptr<EpsBearerPacket_s> pkt = pr->GetPacket();
    if(pkt == nullptr)
      break;
    uint64_t pkt_ts = pkt->Timestamp;
    auto p = Packets.begin();
    while(p != Packets.end())
    {
      if(p->get()->Timestamp >= pkt_ts)
        break;
      p++;
    }
    Packets.insert(p, pkt);
*/
#if USE_ATOMIC_WAIT
    CondAtomicFlag1.test_and_set();
    CondAtomicFlag1.notify_one();
#else
    WaitPacket = false;
    GetPacketCv.notify_one();
#endif
  }
}
