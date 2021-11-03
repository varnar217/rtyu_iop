#include "Global.h"
#include "Log.h"
#include "DateTime.h"
#include "eps_bearer_muxer.h"

#define USE_FAKE_PACKET 0 // будем всегда использовать только один первый считанный из pcap файла пакет

//------------------------------------------------------------------------------
EpsBearerMuxer_c::EpsBearerMuxer_c(int id): 
Id(id), StopFlag(false), StatsTime(DateTime::GetEpochTimeMicrosecCount()), ReadPacketThread(&EpsBearerMuxer_c::ReadPacket, this)
{
#if SYNCHRO_MODE_EBM == SYNCHRO_MODE_ATOMIC
  GetCondAtomicFlag.test_and_set();
#endif
  PRINT_LOG(PRINT_LEVEL::HIGH, "EpsBearerMuxer_c(%p)::USE_FAKE_PACKET=%i\n", this, USE_FAKE_PACKET);
  PRINT_LOG(PRINT_LEVEL::HIGH, "EpsBearerMuxer_c(%p)::SYNCHRO_MODE_EBM=%i (%s)\n", this, SYNCHRO_MODE_EBM,
    SYNCHRO_MODE_EBM == SYNCHRO_MODE_MUTEX ? "Mutex" : SYNCHRO_MODE_EBM == SYNCHRO_MODE_ATOMIC ?
    "Atomic" : SYNCHRO_MODE_EBM == SYNCHRO_MODE_SEMAPHORE ? "Semaphore" : "Error");
}

//------------------------------------------------------------------------------
EpsBearerMuxer_c::~EpsBearerMuxer_c()
{
	Close();
}

//------------------------------------------------------------------------------
bool EpsBearerMuxer_c::Open(GeneratorParams_s& params)
{
#if SYNCHRO_MODE_EBM == SYNCHRO_MODE_MUTEX
	std::lock_guard<std::mutex> lk(PacketsMutex);
#endif
	for(auto& ebp: params.EpsBearerList)
	{
		EpsBearerList[ebp.second.Id] = std::make_shared<EpsBearer_c>(ebp.second.Id);
		if(EpsBearerList[ebp.second.Id]->Open(ebp.second, params) == false)
		{
			PRINT_ERR(PRINT_LEVEL::MIDDLE, "EpsBearerMuxer cannot open EpsBearer with id=%i\n", ebp.second.Id);
      EpsBearerList[ebp.second.Id]->Close();
			return false;
		}
	}
	for(auto& eb: EpsBearerList)
	{
		// получить пакет от EpsBearer
		auto pkt = eb.second->GetPacket();
		if(pkt == nullptr)
		{
			PRINT_ERR(PRINT_LEVEL::MIDDLE, "EpsBearerMuxer received a null packet from EpsBearer (id=%i)\n", eb.first);
			return false;
		}
		// добавить полученный пакет в очередь пакетов EpsBearerMuxer в соответствии с его временной меткой
		uint64_t pkt_ts = pkt->Timestamp;
		auto p = Packets.begin();
		while(p != Packets.end())
		{
			if(p->get()->Timestamp >= pkt_ts)
				break;
			p++;
		}
		Packets.insert(p, pkt);
    //PRINT_TMP(PRINT_LEVEL::HIGH, "%p:%llu EpsBearerMuxer_c::Create() insert size=%i\n", this, DateTime::GetAppTimeMicrosecCount(), (int)Packets.size());
	}
	return true;
}

//------------------------------------------------------------------------------
void EpsBearerMuxer_c::Close()
{
  StopFlag = true;
#if SYNCHRO_MODE_EBM == SYNCHRO_MODE_MUTEX
  GetPacketCv.notify_one();
  ReadPacketCv.notify_one();
#elif SYNCHRO_MODE_EBM == SYNCHRO_MODE_ATOMIC
  GetCondAtomicFlag.test_and_set();
  GetCondAtomicFlag.notify_one();
  ReadCondAtomicFlag.test_and_set();
  ReadCondAtomicFlag.notify_one();
#elif SYNCHRO_MODE_EBM == SYNCHRO_MODE_SEMAPHORE
  GetSignal.release();
  ReadSignal.release();
#endif
  if(ReadPacketThread.joinable())
    ReadPacketThread.join();
}

//------------------------------------------------------------------------------
bool EpsBearerMuxer_c::AddEpsBearer(GeneratorParams_s::EpsBearer_s& ebp, GeneratorParams_s& params)
{
#if SYNCHRO_MODE_EBM == SYNCHRO_MODE_MUTEX
	std::lock_guard<std::mutex> lk(PacketsMutex);
#endif
  //PRINT_TMP(PRINT_LEVEL::HIGH, "TEST:: AddEpsBearer 0\n");
	EpsBearerList[ebp.Id] = std::make_shared<EpsBearer_c>(ebp.Id);
	if(EpsBearerList[ebp.Id]->Open(ebp, params) == false)
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "EpsBearerMuxer cannot open EpsBearer with id=%i\n", ebp.Id);
		EpsBearerList[ebp.Id]->Close();
		return false;
  }
	std::shared_ptr<EpsBearerPacket_s> pkt = EpsBearerList[ebp.Id]->GetPacket();
	if(pkt == nullptr)
	{
		PRINT_ERR(PRINT_LEVEL::MIDDLE, "HttpRequest(AddEpsBearer) received a null packet from EpsBearer (id=%i)\n", ebp.Id);
    //PRINT_TMP(PRINT_LEVEL::HIGH, "TEST:: EpsBeare->GetPacket failed\n");
		return false;
	}
	uint64_t pkt_ts = pkt->Timestamp;
	auto p = Packets.begin();
	while(p != Packets.end())
	{
		if(p->get()->Timestamp >= pkt_ts)
			break;
		p++;
	}
	Packets.insert(p, pkt);
  //PRINT_TMP(PRINT_LEVEL::HIGH, "TEST:: AddEpsBearer 1\n");
	return true;
}

//------------------------------------------------------------------------------
bool EpsBearerMuxer_c::UpdateEpsBearer(GeneratorParams_s::EpsBearer_s& ebp, GeneratorParams_s& params)
{
#if SYNCHRO_MODE_EBM == SYNCHRO_MODE_MUTEX
	std::unique_lock<std::mutex> lk(PacketsMutex);
#endif
  //PRINT_TMP(PRINT_LEVEL::HIGH, "TEST:: UpdateEpsBearer 0\n");
#if __cplusplus > 201703L // C++20
	if(EpsBearerList.contains(ebp.Id) == false)
#else
	if(EpsBearerList.count(ebp.Id) == 0)
#endif
  {
    //PRINT_TMP(PRINT_LEVEL::HIGH, "TEST:: UpdateEpsBearer Generator has NO EpsBearer with id = %i\n", ebp.Id);
		return false;
  }
#if SYNCHRO_MODE_EBM == SYNCHRO_MODE_MUTEX
  lk.unlock();
#endif

#if ELIJA_TODO // попробовать реализовать Update в котором поэлементно сверять параметры и при необходимости вносить изменения, не останавливая работу EpsBearer?
	if(DeleteEpsBearer(ebp) == false)
	{
		//PRINT_TMP(PRINT_LEVEL::HIGH, "TEST:: DeleteEpsBearer failed\n");
		return false;
	}
	if(AddEpsBearer(ebp, params) == false)
	{
		//PRINT_TMP(PRINT_LEVEL::HIGH, "TEST:: AddEpsBearer failed\n");
		return false;
	}
#else
	if(EpsBearerList[ebp.Id]->Update(ebp) == false)
  {
    //PRINT_TMP(PRINT_LEVEL::HIGH, "TEST:: EpsBearer->Update failed\n");
		return false;
  }
#endif
	
  PRINT_TMP(PRINT_LEVEL::HIGH, "TEST:: UpdateEpsBearer 1\n");
	return true;
}

//------------------------------------------------------------------------------
bool EpsBearerMuxer_c::DeleteEpsBearer(GeneratorParams_s::EpsBearer_s& ebp)
{
#if SYNCHRO_MODE_EBM == SYNCHRO_MODE_MUTEX
	std::lock_guard<std::mutex> lk(PacketsMutex);
#endif
  //PRINT_TMP(PRINT_LEVEL::HIGH, "TEST:: DeleteEpsBearer 0\n");
#if __cplusplus > 201703L // C++20
	if(EpsBearerList.contains(ebp.Id) == false)
#else
	if(EpsBearerList.count(ebp.Id) == 0)
#endif
  {
    //PRINT_TMP(PRINT_LEVEL::HIGH, "TEST:: DeleteEpsBearer Generator has NO EpsBearer with id = %i\n", ebp.Id);
		return false;
  }
	
	EpsBearerList.erase(ebp.Id);
  //PRINT_TMP(PRINT_LEVEL::HIGH, "TEST:: DeleteEpsBearer 1\n");
	return true;
}

//------------------------------------------------------------------------------
std::shared_ptr<EpsBearerPacket_s>  EpsBearerMuxer_c::GetPacket()
{
#if 0
  std::time_t start_time = DateTime::GetAppTimeMicrosecCount();
  PRINT_LOG(PRINT_LEVEL::MIDDLE, "%llu: EpsBearerMuxer_c(%p) get\n", start_time, this);
#endif
    //PRINT_TMP(PRINT_LEVEL::HIGH, "%p:%llu EpsBearerMuxer_c::GetPacket() before wait size=%i\n", this, DateTime::GetAppTimeMicrosecCount(), (int)Packets.size());
#if 1 // ELIJA_DEBUG
#if SYNCHRO_MODE_EBM == SYNCHRO_MODE_MUTEX
  std::unique_lock<std::mutex> lk(PacketsMutex);
  while(GetPacketFlag == false)
  {
    GetPacketCv.wait_for(lk, std::chrono::seconds(1));
    if(StopFlag == true)
      return nullptr;
  }
  GetPacketFlag = false;
#elif SYNCHRO_MODE_EBM == SYNCHRO_MODE_ATOMIC
  GetCondAtomicFlag.wait(false);
  GetCondAtomicFlag.clear();
#elif SYNCHRO_MODE_EBM == SYNCHRO_MODE_SEMAPHORE
  GetSignal.acquire();
#endif
#endif
	if(StopFlag == true)
		return nullptr;
    //PRINT_TMP(PRINT_LEVEL::HIGH, "%p:%llu EpsBearerMuxer_c::GetPacket() after wait size=%i\n", this, DateTime::GetAppTimeMicrosecCount(), (int)Packets.size());
  std::shared_ptr<EpsBearerPacket_s> pkt = Packets.front();
  pkt->EpsBearerMuxer = weak_from_this();
#if SYNCHRO_MODE_EBM == SYNCHRO_MODE_MUTEX
  ReadPacketFlag = true;
  ReadPacketCv.notify_one();
#elif SYNCHRO_MODE_EBM == SYNCHRO_MODE_ATOMIC
  ReadCondAtomicFlag.test_and_set();
  ReadCondAtomicFlag.notify_one();
#elif SYNCHRO_MODE_EBM == SYNCHRO_MODE_SEMAPHORE
  ReadSignal.release();
#endif
    //PRINT_TMP(PRINT_LEVEL::HIGH, "%p:%llu EpsBearerMuxer_c::GetPacket() notify size=%i\n", this, DateTime::GetAppTimeMicrosecCount(), (int)Packets.size());
#if 0
  std::time_t stop_time = DateTime::GetAppTimeMicrosecCount();
  PRINT_LOG(PRINT_LEVEL::MIDDLE, "%llu: EpsBearerMuxer_c(%p) get time %llu microseconds\n", stop_time, this, stop_time - start_time);
#endif
  return pkt;
}

//------------------------------------------------------------------------------
void EpsBearerMuxer_c::ReadPacket()
{
  while(StopFlag == false)
  {
    //PRINT_TMP(PRINT_LEVEL::HIGH, "%p:%llu EpsBearerMuxer_c::ReadPacket() before wait size=%i\n", this, DateTime::GetAppTimeMicrosecCount(), (int)Packets.size());
#if SYNCHRO_MODE_EBM == SYNCHRO_MODE_MUTEX
    std::unique_lock<std::mutex> lk(PacketsMutex);
    while(ReadPacketFlag == false)
    {
      ReadPacketCv.wait_for(lk, std::chrono::seconds(1));
      if(StopFlag == true)
        break;
    }
    ReadPacketFlag = false;
#elif SYNCHRO_MODE_EBM == SYNCHRO_MODE_ATOMIC
    ReadCondAtomicFlag.wait(false);
    ReadCondAtomicFlag.clear();
#elif SYNCHRO_MODE_EBM == SYNCHRO_MODE_SEMAPHORE
    ReadSignal.acquire();
#endif
    if(StopFlag == true)
      break;
    //PRINT_TMP(PRINT_LEVEL::HIGH, "%p:%llu EpsBearerMuxer_c::ReadPacket() after wait size=%i\n", this, DateTime::GetAppTimeMicrosecCount(), (int)Packets.size());
#if ! USE_FAKE_PACKET
    std::shared_ptr<EpsBearerPacket_s> pkt_old = Packets.front();
    Packets.pop_front();
    //PRINT_TMP(PRINT_LEVEL::HIGH, "%p:%llu EpsBearerMuxer_c::ReadPacket() pop size=%i\n", this, DateTime::GetAppTimeMicrosecCount(), (int)Packets.size());
		{ // перед удалением отправленного пакета вносим его в статистику,
			// делаем это здесь, чтобы не перегружать поток отправки пакетов
			std::lock_guard<std::mutex> lk(StatsMutex);
			const ssize_t pkt_size = ntohs(pkt_old->IpHeader->ip_len);
			if(pkt_old->Video)
				StatsVideoSize += pkt_size;
			else
				StatsNonVideoSize += pkt_size;
			++StatsPacketCount;
		}
    auto eb = pkt_old->EpsBearer.lock();
    if(eb == nullptr)
      continue; // породивший пакет EpsBearer уже не существует
    std::shared_ptr<EpsBearerPacket_s> pkt = eb->GetPacket();
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
    //PRINT_TMP(PRINT_LEVEL::HIGH, "%p:%llu EpsBearerMuxer_c::ReadPacket() insert size=%i\n", this, DateTime::GetAppTimeMicrosecCount(), (int)Packets.size());
#endif // USE_FAKE_PACKET
#if SYNCHRO_MODE_EBM ==  SYNCHRO_MODE_MUTEX
    GetPacketFlag = true;
    GetPacketCv.notify_one();
#elif SYNCHRO_MODE_EBM == SYNCHRO_MODE_ATOMIC
    GetCondAtomicFlag.test_and_set();
    GetCondAtomicFlag.notify_one();
#elif SYNCHRO_MODE_EBM == SYNCHRO_MODE_SEMAPHORE
    GetSignal.release();
#endif
    //PRINT_TMP(PRINT_LEVEL::HIGH, "%p:%llu EpsBearerMuxer_c::ReadPacket() notify size=%i\n", this, DateTime::GetAppTimeMicrosecCount(), (int)Packets.size());
  }
}


//------------------------------------------------------------------------------
int EpsBearerMuxer_c::GetId() const
{
	return Id;
}

//------------------------------------------------------------------------------
std::shared_ptr<EpsBearer_c> EpsBearerMuxer_c::GetEpsBearer(int id)
{
#if __cplusplus > 201703L // C++20
	if(EpsBearerList.contains(id))
#else
	if(EpsBearerList.count(id))
#endif
		return EpsBearerList[id];
	return nullptr;
}

//------------------------------------------------------------------------------
void EpsBearerMuxer_c::GetStats(std::time_t& time_prev, std::time_t& time_curr, size_t& video_size, size_t& non_video_size, size_t& packet_count)
{
	std::lock_guard<std::mutex> lk(StatsMutex);
	time_prev = StatsTime;
	StatsTime = DateTime::GetEpochTimeMicrosecCount();
	time_curr = StatsTime;
	video_size = StatsVideoSize;
  StatsVideoSize = 0;
	non_video_size = StatsNonVideoSize;
  StatsNonVideoSize = 0;
	packet_count = StatsPacketCount;
  StatsPacketCount = 0;
}
