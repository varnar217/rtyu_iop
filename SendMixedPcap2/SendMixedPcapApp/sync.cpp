#include "Global.h"
#include "Log.h"
#include "DateTime.h"
#include "sync.h"

//------------------------------------------------------------------------------
Sync_c::Sync_c(): StopFlag(false), ReadPacketThread(&Sync_c::ReadPacket, this)
{
//#if USE_ATOMIC_WAIT
//  CondAtomicFlag1.test_and_set();
//  CondAtomicFlag1.notify_one();
//#endif
}

//------------------------------------------------------------------------------
Sync_c::~Sync_c()
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
}

//------------------------------------------------------------------------------
bool Sync_c::AddPcap(std::shared_ptr<PcapReader_c> pr)
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

//------------------------------------------------------------------------------
std::shared_ptr<EpsBearerPacket_s> Sync_c::GetPacket()
{
#if USE_ATOMIC_WAIT
  CondAtomicFlag1.wait(false);
  CondAtomicFlag1.clear();
  if(StopFlag == true)
    return nullptr;
#else
  std::unique_lock<std::mutex> lk(PacketsMutex);
  while(WaitPacket == true)
  {
    GetPacketCv.wait_for(lk, std::chrono::seconds(1));
    if(StopFlag == true)
      return nullptr;
  }
#endif
  std::shared_ptr<EpsBearerPacket_s> pkt = Packets.front();
  //pkt->EpsBearer = weak_from_this();
#if USE_ATOMIC_WAIT
  CondAtomicFlag2.test_and_set();
  CondAtomicFlag2.notify_one();
#else
  WaitPacket = true;
  ReadPacketCv.notify_one();
#endif
  //return std::make_shared<EpsBearerPacket_s>();
  return pkt;
}

//------------------------------------------------------------------------------
void Sync_c::ReadPacket()
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
#if 0
    std::shared_ptr<EpsBearerPacket_s> pkt = pkt_old;
#else
    std::shared_ptr<EpsBearerPacket_s> pkt = pr->GetPacket();
#endif
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

#if USE_ATOMIC_WAIT
    CondAtomicFlag1.test_and_set();
    CondAtomicFlag1.notify_one();
#else
    WaitPacket = false;
    GetPacketCv.notify_one();
#endif
  }
}
