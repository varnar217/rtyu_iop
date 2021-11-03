#include "Global.h"
#include "Log.h"
#include "DateTime.h"
#include "eps_bearer.h"
#include <experimental/random>


//PcapReader_c Pcap("/home/elija/Datasets/pcap/test/0130d_youtube.pcap");
//PcapReader_c Pcap("/home/elija/Datasets/pcap/test/0144d_instagram.pcap");
//PcapReader_c Pcap("/home/elija/Datasets/pcap/test/0146d_tiktok.pcap");

#define USE_FAKE_PACKET 0 // будем всегда использовать только один первый считанный из pcap файла пакет

//------------------------------------------------------------------------------
EpsBearer_c::EpsBearer_c(int id): 
Id(id), StopFlag(false), StatsTime(DateTime::GetEpochTimeMicrosecCount()), ReadPacketThread(&EpsBearer_c::ReadPacket, this)
{
#if SYNCHRO_MODE_EB == SYNCHRO_MODE_ATOMIC
  GetCondAtomicFlag.test_and_set();
#endif
  PRINT_TMP(PRINT_LEVEL::MIDDLE, "EpsBearer_c(%p)::USE_FAKE_PACKET=%i\n", this, USE_FAKE_PACKET);
  PRINT_TMP(PRINT_LEVEL::MIDDLE, "EpsBearer_c(%p)::SYNCHRO_MODE_EB=%i (%s)\n", this, SYNCHRO_MODE_EB,
    SYNCHRO_MODE_EB == SYNCHRO_MODE_MUTEX ? "Mutex" : SYNCHRO_MODE_EB == SYNCHRO_MODE_ATOMIC ?
    "Atomic" : SYNCHRO_MODE_EB == SYNCHRO_MODE_SEMAPHORE ? "Semaphore" : "Error");
}

//------------------------------------------------------------------------------
EpsBearer_c::~EpsBearer_c()
{
	Close();
}

//------------------------------------------------------------------------------
bool EpsBearer_c::Open(GeneratorParams_s::EpsBearer_s& ebp, GeneratorParams_s& params)
{
	// сохранить копию параметров себе и с ней потокобезопасно работать
	Params = ebp;
  // если это не настраиваемый пользовательский сценарий, а из списка
  if(Params.UserScenario.Id)
  {
    // проверить существует ли такой сценарий в списке
#if __cplusplus > 201703L // C++20
    if(params.UserScenarioList.contains(Params.UserScenario.Id) == false)
#else
    if(params.UserScenarioList.count(Params.UserScenario.Id) == 0)
#endif
    {
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "EpsBearer refers to a non-existing User scenario (id=%i)\n", Params.UserScenario.Id);
      return false;
    }
    Params.UserScenario = params.UserScenarioList[Params.UserScenario.Id];
  }
  // если это не настраиваемый сетевой сценарий, а из списка
  if(Params.NetworkScenario.Id)
  {
    // проверить существует ли такой сценарий в списке
#if __cplusplus > 201703L // C++20
    if(params.NetworkScenarioList.contains(Params.NetworkScenario.Id) == false)
#else
    if(params.NetworkScenarioList.count(Params.NetworkScenario.Id) == 0)
#endif
    {
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "EpsBearer refers to a non-existing Nrtwork scenario (id=%i)\n", Params.NetworkScenario.Id);
      return false;
    }
    Params.NetworkScenario = params.NetworkScenarioList[Params.NetworkScenario.Id];
  }
	// цикл по всем PCAP файла перечисленным в пользовательском сценарии для данного EpsBearer
	for(auto& id: Params.UserScenario.PcapId)
	{
		// PCAP файл должен быть перечислен в списке доступных PCAP файлов
#if __cplusplus > 201703L // C++20
		if(params.PcapList.contains(id) == false)
#else
		if(params.PcapList.count(id) == 0)
#endif
		{
			PRINT_ERR(PRINT_LEVEL::MIDDLE, "User scenario of EpsBearer refers to a non-existing PCAP file (id=%i)\n", id);
			return false;
		}
		// создать экземпляр PcapReader_c в качестве интерфейса для работы с данным PCAP файлом
		auto pr = std::make_shared<PcapReader_c>(id, params.PcapList[id].Video, Id, params.PcapList[id].Path.c_str(), params.IpSrc.c_str(), params.IpDst.c_str());
		if(pr->Open() == false)
		{
			PRINT_ERR(PRINT_LEVEL::MIDDLE, "EpsBearer cannot open the PCAP file %s\n", params.PcapList[id].Path.c_str());
      pr->Close();
			return false;
		}
		PcapReaderList.emplace(std::make_pair(id, pr));

		// получить пакет из PCAP файла
		auto pkt = pr->GetPacket();
		if(pkt == nullptr)
		{
			PRINT_ERR(PRINT_LEVEL::MIDDLE, "EpsBearer received a null packet from PCAP file %s\n",params.PcapList[id].Path.c_str());
			return false;
		}
		// добавить полученный пакет в очередь пакетов EpsBearer в соответствии с его временной меткой
		uint64_t pkt_ts = pkt->Timestamp;
		auto p = Packets.begin();
		while(p != Packets.end())
		{
			if(p->get()->Timestamp >= pkt_ts)
				break;
			p++;
		}
		Packets.insert(p, pkt);
    //PRINT_TMP(PRINT_LEVEL::HIGH, "%p:%llu EpsBearer_c::Create() insert size=%i\n", this, DateTime::GetAppTimeMicrosecCount(), (int)Packets.size());
	}
	return true;
}

//------------------------------------------------------------------------------
void EpsBearer_c::Close()
{
  StopFlag = true;
#if SYNCHRO_MODE_EB == SYNCHRO_MODE_MUTEX
	GetPacketCv.notify_one();
	ReadPacketCv.notify_one();
#elif SYNCHRO_MODE_EB == SYNCHRO_MODE_ATOMIC
  GetCondAtomicFlag.test_and_set();
  GetCondAtomicFlag.notify_one();
  ReadCondAtomicFlag.test_and_set();
  ReadCondAtomicFlag.notify_one();
#elif SYNCHRO_MODE_EB == SYNCHRO_MODE_SEMAPHORE
  GetSignal.release();
  ReadSignal.release();
#endif
  if(ReadPacketThread.joinable())
    ReadPacketThread.join();
}

//------------------------------------------------------------------------------
std::shared_ptr<EpsBearerPacket_s> EpsBearer_c::GetPacket()
{
#if 0
  std::time_t start_time = DateTime::GetAppTimeMicrosecCount();
  PRINT_LOG(PRINT_LEVEL::MIDDLE, "%llu: EpsBearer_c(%p) get\n", start_time, this);
#endif
#if SYNCHRO_MODE_EB == SYNCHRO_MODE_MUTEX
  std::unique_lock<std::mutex> lk(PacketsMutex);
  while(GetPacketFlag == false)
  {
    GetPacketCv.wait_for(lk, std::chrono::seconds(1));
    if(StopFlag == true)
      return nullptr;
  }
  GetPacketFlag = false;
#elif SYNCHRO_MODE_EB == SYNCHRO_MODE_ATOMIC
  GetCondAtomicFlag.wait(false);
  GetCondAtomicFlag.clear();
  if(StopFlag == true)
    return nullptr;
#elif SYNCHRO_MODE_EB == SYNCHRO_MODE_SEMAPHORE
  GetSignal.acquire();
    if(StopFlag == true)
      return nullptr;
#endif
	//PRINT_TMP(PRINT_LEVEL::HIGH, "%p:%llu EpsBearer_c::GetPacket() wait size=%i\n", this, DateTime::GetAppTimeMicrosecCount(), (int)Packets.size());
  std::shared_ptr<EpsBearerPacket_s> pkt = Packets.front();
#if ELIJA_TODO // а почему я добавляю this здесь, а не сразу после считывания пакета в очередь?
  pkt->EpsBearer = weak_from_this();
#endif
#if SYNCHRO_MODE_EB == SYNCHRO_MODE_MUTEX
  ReadPacketFlag = true;
  ReadPacketCv.notify_one();
#elif SYNCHRO_MODE_EB == SYNCHRO_MODE_ATOMIC
  ReadCondAtomicFlag.test_and_set();
  ReadCondAtomicFlag.notify_one();
#elif SYNCHRO_MODE_EB == SYNCHRO_MODE_SEMAPHORE
  ReadSignal.release();
#endif
#if 0
  std::time_t stop_time = DateTime::GetAppTimeMicrosecCount();
  PRINT_LOG(PRINT_LEVEL::MIDDLE, "%llu: EpsBearer_c(%p) get time %llu microseconds\n", stop_time, this, stop_time - start_time);
#endif
  return pkt;
}

//------------------------------------------------------------------------------
void EpsBearer_c::ReadPacket()
{
  while(StopFlag == false)
  {
#if SYNCHRO_MODE_EB == SYNCHRO_MODE_MUTEX
    std::unique_lock<std::mutex> lk(PacketsMutex);
    while(ReadPacketFlag == false)
    {
      ReadPacketCv.wait_for(lk, std::chrono::seconds(1));
      if(StopFlag == true)
        break;
    }
    ReadPacketFlag = false;
#elif SYNCHRO_MODE_EB == SYNCHRO_MODE_ATOMIC
    ReadCondAtomicFlag.wait(false);
    ReadCondAtomicFlag.clear();
#elif SYNCHRO_MODE_EB == SYNCHRO_MODE_SEMAPHORE
    ReadSignal.acquire();
		//while(ReadSignal.try_acquire_for(std::chrono::milliseconds(500)) == false)
#endif
    if(StopFlag == true)
      break;
    //PRINT_TMP(PRINT_LEVEL::HIGH, "%p:%llu EpsBearer_c::ReadPacket() wait size=%i\n", this, DateTime::GetAppTimeMicrosecCount(), (int)Packets.size());
//    PRINT_DBG(PRINT_LEVEL::MIDDLE, "%llu: EpsBearer_c(%p)::ReadPacket() size=%i\n", DateTime::GetAppTimeMicrosecCount(), this, (int)Packets.size());
#if ! USE_FAKE_PACKET
    std::shared_ptr<EpsBearerPacket_s> pkt_old = Packets.front();
    Packets.pop_front();
    //PRINT_TMP(PRINT_LEVEL::HIGH, "%p:%llu EpsBearer_c::ReadPacket() pop size=%i\n", this, DateTime::GetAppTimeMicrosecCount(), (int)Packets.size());
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
    auto pr = pkt_old->PcapReader.lock();
    if(pr == nullptr)
      continue; // породивший пакет PcapReader уже не существует
    std::shared_ptr<EpsBearerPacket_s> pkt = pr->GetPacket();
    if(pkt == nullptr)
      break;
		// изменить временную метку пакета в соответствии с настройками Jitter
		if(Params.NetworkScenario.Jitter.TimeUp)
		{
			int t = pkt->Timestamp % (Params.NetworkScenario.Jitter.TimeUp + Params.NetworkScenario.Jitter.TimeDown);
			if(t <= Params.NetworkScenario.Jitter.TimeUp)
				pkt->Timestamp += std::experimental::randint(0, Params.NetworkScenario.Jitter.Value);
		}
		// изменить временную метку пакета в соответствии с настройками Burst
		if(Params.NetworkScenario.Burst.TimeUp)
		{
			int t = pkt->Timestamp % (Params.NetworkScenario.Burst.TimeUp + Params.NetworkScenario.Burst.TimeDown);
			if(t <= Params.NetworkScenario.Burst.TimeUp)
				pkt->Timestamp = PacketLastTimestamp;
		}
		// сохранить временную метку последнего отданного пакета
		PacketLastTimestamp = pkt->Timestamp;
		// добавить пакет в очередь в соответствии с его временной меткой
    uint64_t pkt_ts = pkt->Timestamp;
    auto p = Packets.begin();
    while(p != Packets.end())
    {
      if(p->get()->Timestamp >= pkt_ts)
        break;
      p++;
    }
    Packets.insert(p, pkt);
    //PRINT_TMP(PRINT_LEVEL::HIGH, "%p:%llu EpsBearer_c::ReadPacket() insert size=%i\n", this, DateTime::GetAppTimeMicrosecCount(), (int)Packets.size());
#endif // USE_FAKE_PACKET
#if SYNCHRO_MODE_EB ==  SYNCHRO_MODE_MUTEX
    GetPacketFlag = true;
    GetPacketCv.notify_one();
#elif SYNCHRO_MODE_EB == SYNCHRO_MODE_ATOMIC
    GetCondAtomicFlag.test_and_set();
    GetCondAtomicFlag.notify_one();
#elif SYNCHRO_MODE_EB == SYNCHRO_MODE_SEMAPHORE
    GetSignal.release();
#endif
  }
}

//------------------------------------------------------------------------------
int EpsBearer_c::GetId() const
{
	return Id;
}

//------------------------------------------------------------------------------
void EpsBearer_c::GetStats(std::time_t& time_prev, std::time_t& time_curr, size_t& video_size, size_t& non_video_size, size_t& packet_count)
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
