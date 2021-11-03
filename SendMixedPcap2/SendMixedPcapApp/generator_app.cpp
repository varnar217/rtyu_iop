#include "Global.h"
#include "Log.h"
#include "DateTime.h"
#include "common.h"
#include "generator_app.h"
#include "pcap_reader.h"
#include "eps_bearer.h"
#include "eps_bearer_muxer.h"
#include "socket_sender.h"

#include <stdio.h>
#include <stdint.h>
#include <cstring>
#include <thread>
#include <memory>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <chrono>
#include <experimental/random>

#define APP_MODE_MAIN 1 // основной вариант программы
//#define APP_MODE_TEST 2 // экспериментальный вариант программы
//#define APP_MODE_SEND 3 // проверка скорости работы только по отправке пакетов
//#define APP_MODE_READ 4 // проверка скорости работы только по чтению пакетов
#define APP_MODE_OPTION APP_MODE_MAIN // выбор варианта программы для построения

#define USE_CONTROL_TIMER 1 // выполнение програмы в течении заданного времени и потом автоматическое завершение
#define USE_CONTROL_STDIN 2 // управление командами набранными на клавиатуре в консоли
#define USE_CONTROL_HTTP 3 // управление командами получеными от HTTP-сервера
#define USE_CONTROL_OPTION USE_CONTROL_HTTP

#include "http_server_api.h"
#define HTTP_SERVER_OPTION_HTTPLIB 1
//efine HTTP_SERVER_OPTION_RESTINO 2
#define HTTP_SERVER_OPTION HTTP_SERVER_OPTION_HTTPLIB
#if HTTP_SERVER_OPTION == HTTP_SERVER_OPTION_HTTPLIB
#include "http_server_httplib.h"
#endif

#define USE_FAKE_HTTP_RESPONSE 0 // использовать (=1) или нет (=0) чередующиеся заранее подготовленные успешный и ошибочный ответы

//------------------------------------------------------------------------------
GeneratorApp_c::GeneratorApp_c()
{
  PRINT_MSG(PRINT_LEVEL::MIDDLE, "The application started at %s\n", DateTime::GetEpochTimeStringHTP().c_str());
  if(ReadParams() == false)
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "Cannot read Generator parameters\n");
    return;
  }
#if USE_SYNCHRO_OPTION == USE_SYNCHRO_MUTEX
#elif USE_SYNCHRO_OPTION == USE_SYNCHRO_ATOMIC
    PacketsCondAtomicFlag.test_and_set();
#elif USE_SYNCHRO_OPTION == USE_SYNCHRO_SEMAPHORE
#endif
}

//------------------------------------------------------------------------------
GeneratorApp_c::~GeneratorApp_c()
{
  WriteParams();
  PRINT_MSG(PRINT_LEVEL::MIDDLE, "The application finished at %s\n", DateTime::GetEpochTimeStringHTP().c_str());
}

//------------------------------------------------------------------------------
std::shared_ptr<EpsBearerPacket_s> GeneratorApp_c::GetPacket()
{
#if USE_ONLY_READ
  std::shared_ptr<EpsBearerPacket_s> pkt;
#else
  //std::unique_lock<std::mutex> lk(PacketsMutex);
  while(GetPacketFlag == false)
  {
    //GetPacketCv.wait_for(lk, std::chrono::seconds(1));
    if(StopFlag == true)
      return nullptr;
  }
  GetPacketFlag = false;

	std::shared_ptr<EpsBearerPacket_s> pkt;
  {
    std::lock_guard<std::mutex> lk(PacketsMutex);
    pkt = Packets.front();
  }

  ReadPacketFlag = true;
  //ReadPacketCv.notify_one();
#endif

	return pkt;
}

//------------------------------------------------------------------------------
void GeneratorApp_c::ReadPacket(int thread_id)
{
  // привязать этот поток к ядру процессора с индексом 1
  thread_to_core(1+thread_id);
  
#if ELIJA_TODO
// здесь сделать что-то вроде семафоров с максимльным значением равным количеству потоков в пуле,
// увеличивать на единицу при каждом начале чтения нового пакета и уменьшать на единицу при каждой
// записи нового пакета в очередь, а позволять забирать в GetPacket только когда семаор = 0, то есть
// все потоки чтения отработали. ПРИЧЁМ такой механизм важен для режима с накоплением, чтобы в
// выходном файле временные метки щли по порядку. НО в режиме реального времени ВРОДЕ никаких
// меток нет, а есть только время отправки пакета и если несколько близких пакетов вдруг поменяются, то
// МОЖЕТ ну и бог с ними?
#endif

  GeneratorParams_s::NetworkScenario_s::Jitter_s jitter;
  GeneratorParams_s::NetworkScenario_s::Burst_s burst;

  uint64_t pkts_count = 0; // номер последнего отправленного пакета
  uint64_t pkts_size = 0; // размер всех отправленных пакетов
  
  PRINT_LOG(PRINT_LEVEL::HIGH, "Read thread(%i) started\n", thread_id);

#if USE_TMP_DEBUG
  std::time_t t_all=0, t_wait=0, t_read=0, t_mutex=0, t_scenario=0, t_queue=0, t_get=0, t_cnt = 0;
  std::time_t t1 = DateTime::GetAppTimeNanosecCount(), t2;
#endif
  std::time_t sender_start_time = DateTime::GetAppTimeMicrosecCount();

	while(StopFlag == false)
	{
    std::shared_ptr<EpsBearerPacket_s> pkt_old;
    { // работа с очередью пакетов с разделением доступа из разных потоков
#if USE_SYNCHRO_OPTION == USE_SYNCHRO_MUTEX
      //std::unique_lock<std::mutex> lk(PacketsMutex);
      while(ReadPacketFlag == false)
      {
        //ReadPacketCv.wait_for(lk, std::chrono::seconds(1));
        if(StopFlag == true)
          break; // завершить работу потока
      }
      ReadPacketFlag = false;
#elif USE_SYNCHRO_OPTION == USE_SYNCHRO_ATOMIC
      PacketsCondAtomicFlag.wait(false);
      PacketsCondAtomicFlag.clear();
#elif USE_SYNCHRO_OPTION == USE_SYNCHRO_SEMAPHORE
      PacketsSignal.acquire();
#endif
      if(StopFlag == true)
        break; // завершить работу потока
#if USE_TMP_DEBUG
      t2 = DateTime::GetAppTimeNanosecCount();
      t_wait += t2 - t1;
#endif

      {
        std::lock_guard<std::mutex> lk(PacketsMutex);
        pkt_old = Packets.front();
        Packets.pop_front();
      }
    }

#if USE_TMP_DEBUG
      std::time_t t5 = DateTime::GetAppTimeNanosecCount();
#endif
    ssize_t pkt_size = 0;
    { // работа с параметрами Генератора с разделением доступа из разных потоков
      std::lock_guard<std::mutex> lk(ParamsMutex);
      std::shared_ptr<PcapReader_c> pr = pkt_old->PcapReader.lock();
      // если породивший этот пакет PcapReader ещё существует, то и параметры EpsBearer ещё существуют
      if(pr) // работа с очередью пакетов с разделением доступа из разных потоков
      {
        GeneratorParams_s::EpsBearer_s& eparams = pr->GetEpsBearer();
        // статистика отправленного ранее пакета
//#if USE_TMP_DEBUG
//        pkt_size = 1378;
//#else
#if USE_GTP
        pkt_size = ntohs(pkt_old->IpHeader2->ip_len);
#else
        pkt_size = ntohs(pkt_old->IpHeader->ip_len);
#endif
//#endif
        bool video = pkt_old->Video;

        if(video)
        {
          eparams.StatsVideoSize += pkt_size;
          Params.StatsVideoSize += pkt_size;
        }
        else
        {
          eparams.StatsNonVideoSize += pkt_size;
          Params.StatsNonVideoSize += pkt_size;
        }
        ++eparams.StatsPacketCount;
        ++Params.StatsPacketCount;
        
        jitter = eparams.NetworkScenario.Jitter;
        burst = eparams.NetworkScenario.Burst;
      }
    }
#if USE_TMP_DEBUG
      std::time_t t6 = DateTime::GetAppTimeNanosecCount();
      t_mutex += t6 - t5;
#endif
    
    std::shared_ptr<PcapReader_c> pr = pkt_old->PcapReader.lock();
     // если породивший этот пакет PcapReader ещё существует
    if(pr) // работа с очередью пакетов с разделением доступа из разных потоков
    {
      //std::lock_guard<std::mutex> lk(PacketsMutex);
#if USE_TMP_DEBUG
      std::time_t t3 = DateTime::GetAppTimeNanosecCount();
#endif
      std::shared_ptr<EpsBearerPacket_s> pkt = pr->GetPacket();
#if USE_TMP_DEBUG
      std::time_t t4 = DateTime::GetAppTimeNanosecCount();
      t_get += t4 - t3;
#endif
      if(pkt == nullptr)
      {
        PRINT_ERR(PRINT_LEVEL::MIDDLE, "GeneratorApp(%p): Null packet received\n");
        break; // завершить работу потока
      }
      // изменить временную метку пакета в соответствии с настройками Jitter
      if(jitter.TimeUp)
      {
        int t = pkt->Timestamp % (jitter.TimeUp + jitter.TimeDown);
        if(t <= jitter.TimeUp)
          pkt->Timestamp += std::experimental::randint(0, jitter.Value*2-1);
#if ELIJA_TODO
        // альтернативы std::experimental::randint в C++11:
        // https://stackoverflow.com/questions/40275512/how-to-generate-random-numbers-between-2-values-inclusive
        // https://ravesli.com/urok-71-generatsiya-sluchajnyh-chisel-funktsii-srand-i-rand/#toc-7
#endif
      }
      // изменить временную метку пакета в соответствии с настройками Burst
      if(burst.TimeUp)
      {
        int t = pkt->Timestamp % (burst.TimeUp + burst.TimeDown);
        if(t <= burst.TimeUp)
          pkt->Timestamp = pkt_old->Timestamp;
#if ELIJA_TODO
// КАЖЕТСЯ что тут получается, что при включении режима Burstбудут ускоряться все пакеты только одного
// PcapReader, того который случайно попал на то самое начало, поскольку именно его пакеты будут
// помещаться в самое начало очереди пакетов и значит считывться первыми и значит опять читаться
// будут именно они и так по кругу

#endif
      }
#if USE_TMP_DEBUG
      std::time_t t7 = DateTime::GetAppTimeNanosecCount();
      t_scenario += t7 - t6;
#endif
      // добавить пакет в очередь в соответствии с его временной меткой
      uint64_t pkt_ts = pkt->Timestamp;
      {
        std::lock_guard<std::mutex> lk(PacketsMutex);
        auto p = Packets.begin();
        while(p != Packets.end())
        {
          if(p->get()->Timestamp >= pkt_ts)
            break;
          p++;
        }
        Packets.insert(p, pkt);
      }
#if USE_TMP_DEBUG
      std::time_t t8 = DateTime::GetAppTimeNanosecCount();
      t_queue += t8 - t7;
#endif

      // обновить статистику
      pkts_size += pkt_size;
      pkts_count++;
#if USE_SYNCHRO_OPTION == USE_SYNCHRO_MUTEX
#if USE_ONLY_READ
      ReadPacketFlag = true;
#endif
      GetPacketFlag = true;
      //GetPacketCv.notify_one();
#elif USE_SYNCHRO_OPTION == USE_SYNCHRO_ATOMIC
      PacketsCondAtomicFlag.test_and_set();
      PacketsCondAtomicFlag.notify_one();
#elif USE_SYNCHRO_OPTION == USE_SYNCHRO_SEMAPHORE
      PacketsSignal.release();
#endif
#if USE_TMP_DEBUG
      std::time_t t = DateTime::GetAppTimeNanosecCount();
      t_read += t - t2;
      t_all += t - t1;
      t1 = t;
      t_cnt++;
#endif
    }
  }
  std::time_t sender_stop_time = DateTime::GetAppTimeMicrosecCount();
  uint64_t send_time = sender_stop_time - sender_start_time;
  PRINT_LOG(PRINT_LEVEL::HIGH, "Read thread(%i) stopped after %llu microseconds (bitrate = %llu bits per sec)\n", thread_id, send_time, pkts_size * 8000000 / send_time);
#if USE_TMP_DEBUG
  if(t_cnt) PRINT_LOG(PRINT_LEVEL::HIGH, "Read thread(%i) cnt=%llu, all=%llu (wait=%llu + read=%llu (mutex=%llu + scenario=%llu + queue=%llu + get=%llu))\n", thread_id, t_cnt, t_all/t_cnt, t_wait/t_cnt, t_read/t_cnt, t_mutex/t_cnt, t_scenario/t_cnt, t_queue/t_cnt, t_get/t_cnt);
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponseDeleteExit(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_delete_exit_ok;
  }
  else
  {
    *code = 501;
    return json_response_delete_exit_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  // оповещение о завершении приложения Ядра ГТО
	nlohmann::json jres;
	jres["response"]["code"] = 0;
	jres["response"]["msg"] = "Request DELETE(/exit) Generator has closed";
	jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
	*code = 201;
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponseGetInit(const std::string& reqs, std::string& addr, std::string& port, int* code)
{
  if(addr.empty())
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: old GUI addr = %s\n", GuiAddr.c_str());
  else
  {
    GuiAddr = addr;
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: new GUI addr = %s\n", GuiAddr.c_str());
  }

  if(port.empty())
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: old GUI port = %i\n", GuiPort);
  else
  {
    GuiPort = std::stoi(port);
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: new GUI port = %i\n", GuiPort);
  }

#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_get_init_ok;
  }
  else
  {
    *code = 501;
    return json_response_get_init_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  int i;
  // состояние Ядра ГТО и список всех параметров работы Ядра ГТО
	nlohmann::json jres;
	jres["response"]["code"] = 0;
	jres["response"]["msg"] = "Request GET(/init) processed successfully";
	jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
	jres["state"]["run"] = State.Run;
	jres["params"]["mode"] = Params.Mode;
	jres["params"]["br"] = Params.Bitrate;
	jres["params"]["ipsrc"] = Params.IpSrc;
	jres["params"]["ipdst"] = Params.IpDst;
	jres["params"]["file"]["path"] = Params.File.Path;
	jres["params"]["file"]["size"] = Params.File.Size;
	jres["params"]["gtp"]["use"] = Params.Gtp.Use;
	jres["params"]["gtp"]["ipsrc"] = Params.Gtp.IpSrc;
	jres["params"]["gtp"]["ipdst"] = Params.Gtp.IpDst;
	jres["params"]["gtp"]["minteid"] = Params.Gtp.MinTeid;
	jres["params"]["gtp"]["maxteid"] = Params.Gtp.MaxTeid;
  jres["params"]["service"] = nlohmann::json::array();
  i = 0;
  for(auto& service: Params.ServiceList)
  {
    jres["params"]["service"][i]["id"] = service.second.Id;
    jres["params"]["service"][i]["name"] = service.second.Name;
    ++i;
  }
  jres["params"]["app"] = nlohmann::json::array();
  i = 0;
  for(auto& app: Params.AppList)
  {
    jres["params"]["app"][i]["id"] = app.second.Id;
    jres["params"]["app"][i]["name"] = app.second.Name;
    ++i;
  }
  jres["params"]["pcap"] = nlohmann::json::array();
  i = 0;
  for(auto& pcap: Params.PcapList)
  {
    jres["params"]["pcap"][i]["id"] = pcap.second.Id;
    jres["params"]["pcap"][i]["video"] = pcap.second.Video;
    jres["params"]["pcap"][i]["service"]["id"] = pcap.second.Service.Id;
    jres["params"]["pcap"][i]["app"]["id"] = pcap.second.App.Id;
    jres["params"]["pcap"][i]["br"] = pcap.second.Bitrate;
    jres["params"]["pcap"][i]["path"] = pcap.second.Path;
    ++i;
  }
  jres["params"]["user_scenario"] = nlohmann::json::array();
  i = 0;
  for(auto& us: Params.UserScenarioList)
  {
    jres["params"]["user_scenario"][i]["id"] = us.second.Id;
    jres["params"]["user_scenario"][i]["name"] = us.second.Name;
    jres["params"]["user_scenario"][i]["br"] = us.second.Bitrate;
    jres["params"]["user_scenario"][i]["pcap_id"] = nlohmann::json::array();
    int j = 0;
    for(auto& pcap_id: us.second.Pcap)
    {
      jres["params"]["user_scenario"][i]["pcap_id"][j] = pcap_id.first;
      ++j;
    }
    ++i;
  }
  jres["params"]["network_scenario"] = nlohmann::json::array();
  i = 0;
  for(auto& ns: Params.NetworkScenarioList)
  {
    jres["params"]["network_scenario"][i]["id"] = ns.second.Id;
    jres["params"]["network_scenario"][i]["name"] = ns.second.Name;
    jres["params"]["network_scenario"][i]["jitter"]["timeup"] = ns.second.Jitter.TimeUp;
    jres["params"]["network_scenario"][i]["jitter"]["timedown"] = ns.second.Jitter.TimeDown;
    jres["params"]["network_scenario"][i]["jitter"]["value"] = ns.second.Jitter.Value;
    jres["params"]["network_scenario"][i]["burst"]["timeup"] = ns.second.Burst.TimeUp;
    jres["params"]["network_scenario"][i]["burst"]["timedown"] = ns.second.Burst.TimeDown;
    ++i;
  }
  jres["params"]["eb"] = nlohmann::json::array();
  i = 0;
  for(auto& eb: Params.EpsBearerList)
  {
    jres["params"]["eb"][i]["id"] = eb.second.Id;
    jres["params"]["eb"][i]["br"] = eb.second.Bitrate;
    jres["params"]["eb"][i]["user_scenario"]["id"] = eb.second.UserScenario.Id;
    if(eb.second.UserScenario.Id == 0) // отправляем эти значения только для настраиваемого пользовательского сценария
    {
      jres["params"]["eb"][i]["user_scenario"]["name"] = eb.second.UserScenario.Name;
      jres["params"]["eb"][i]["user_scenario"]["br"] = eb.second.UserScenario.Bitrate;
      jres["params"]["eb"][i]["user_scenario"]["pcap_id"] = nlohmann::json::array();
      int j = 0;
      for(auto& pcap_id: eb.second.UserScenario.Pcap)
      {
        jres["params"]["eb"][i]["user_scenario"]["pcap_id"][j] = pcap_id.first;
        ++j;
      }
    }
    jres["params"]["eb"][i]["network_scenario"]["id"] = eb.second.NetworkScenario.Id;
    if(eb.second.NetworkScenario.Id == 0) // отправляем эти значения только для настраиваемого сетевого сценария
    {
      jres["params"]["eb"][i]["network_scenario"]["name"] = eb.second.NetworkScenario.Name;
      jres["params"]["eb"][i]["network_scenario"]["jitter"]["timeup"] = eb.second.NetworkScenario.Jitter.TimeUp;
      jres["params"]["eb"][i]["network_scenario"]["jitter"]["timedown"] = eb.second.NetworkScenario.Jitter.TimeDown;
      jres["params"]["eb"][i]["network_scenario"]["jitter"]["value"] = eb.second.NetworkScenario.Jitter.Value;
      jres["params"]["eb"][i]["network_scenario"]["burst"]["timeup"] = eb.second.NetworkScenario.Burst.TimeUp;
      jres["params"]["eb"][i]["network_scenario"]["burst"]["timedown"] = eb.second.NetworkScenario.Burst.TimeDown;
    }
    ++i;
  }
	*code = 201;
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponseGetAlive(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_get_alive_ok;
  }
  else
  {
    *code = 501;
    return json_response_get_alive_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  // состояние Ядра ГТО
	nlohmann::json jres;
	jres["response"]["code"] = 0;
	jres["response"]["msg"] = "Request GET(/alive) processed successfully";
	jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
	*code = 201;
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif

#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponseGetState(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_get_state_ok;
  }
  else
  {
    *code = 501;
    return json_response_get_state_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  // состояние Ядра ГТО
	nlohmann::json jres;
	jres["response"]["code"] = 0;
	jres["response"]["msg"] = "Request GET(/state) processed successfully";
	jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
	jres["state"]["run"] = State.Run;
	*code = 201;
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif

#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponsePutStateRun(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_put_state_run_ok;
  }
  else
  {
    *code = 501;
    return json_response_put_state_run_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  PRINT_TMP(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePutStateRun: %s\n", reqs.c_str());
  // проверка запроса
	if(nlohmann::json::accept(reqs) == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "NLOHMANN: RequestPutStateRun is NOT a valid JSON\n");
		nlohmann::json jres;
		jres["response"]["code"] = 1;
		jres["response"]["msg"] = "Request PUT(/state/run) is NOT a valid JSON";
		jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
		jres["state"]["run"] = State.Run;
		*code = 501;
		return jres.dump(2);
	}
  // разбор запроса
  nlohmann::json jreq = nlohmann::json::parse(reqs);
  // анализ запроса (включить в работу или остановить Ядро ГТО)
	bool run;
  if (jreq["state"]["run"].is_null())
  {
    PRINT_ERR(PRINT_LEVEL::HIGH, "NLOHMANN: RequestPutStateRun[state][run] is null\n");
		nlohmann::json jres;
		jres["response"]["code"] = 1;
		jres["response"]["msg"] = "Request PUT(/state/run) is null";
		jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
		jres["state"]["run"] = State.Run;
		*code = 501;
		return jres.dump(2);
  }
  else
  {
		if (jreq["state"]["run"].is_boolean() == false)
		{
			PRINT_ERR(PRINT_LEVEL::HIGH, "NLOHMANN: RequestPutStateRun[state][run] has a wrong type (must be boolean)\n");
			nlohmann::json jres;
			jres["response"]["code"] = 1;
			jres["response"]["msg"] = "Request PUT(/state/run) has a wrong type (must be boolean)";
			jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
			jres["state"]["run"] = State.Run;
			*code = 501;
			return jres.dump(2);
		}
    run = jreq["state"]["run"];
    PRINT_TMP(PRINT_LEVEL::HIGH, "NLOHMANN: RequestPutStateRun[state][run] = %i\n", run);
  }
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
  rapidjson::Document d;
  d.Parse(reqs);
  rapidjson::Value& run = d["state"]["run"];
#else
illegal option
#endif
	if(State.Run == run )
	{
    PRINT_LOG(PRINT_LEVEL::HIGH, "Generator is already %s\n", State.Run ? "running" : "stopped");
		nlohmann::json jres;
		jres["response"]["code"] = 1;
		if(State.Run)
			jres["response"]["msg"] = "Request PUT(/state/run) Generator is already running";
		else
			jres["response"]["msg"] = "Request PUT(/state/run) Generator is already stopped";
		jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
		jres["state"]["run"] = State.Run;
		*code = 501;
		return jres.dump(2);
	}
  // выполнение запроса
  if(State.Run == false) // Ядро ГТО сейчас остановлено
  {
    if(Start() == true)
    {
			// Ядро ГТО успешно стартовало
      PRINT_LOG(PRINT_LEVEL::HIGH, "GENERATOR has started\n");
      State.Run = true;

			nlohmann::json jres;
			jres["response"]["code"] = 0;
			jres["response"]["msg"] = "Request PUT(/state/run) processed successfully";
			jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
			jres["state"]["run"] = State.Run;
			*code = 201;
			return jres.dump(2);
    }
    else
    {
      PRINT_LOG(PRINT_LEVEL::HIGH, "GENERATOR start error\n");
			nlohmann::json jres;
			jres["response"]["code"] = 1;
			jres["response"]["msg"] = "Request PUT(/state/run) Generator start error";
			jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
			jres["state"]["run"] = State.Run;
			*code = 501;
			return jres.dump(2);
    }
  }
  else // Ядро ГТО сейчас работает
  {
    if(Stop() == true)
    {
			// Ядро ГТО успешно остановлено
      PRINT_LOG(PRINT_LEVEL::HIGH, "GENERATOR has stopped\n");
      State.Run = false;

			nlohmann::json jres;
			jres["response"]["code"] = 0;
			jres["response"]["msg"] = "Request PUT(/state/run) processed successfully";
			jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
			jres["state"]["run"] = State.Run;
			*code = 201;
			return jres.dump(2);
    }
    else
    {
      PRINT_LOG(PRINT_LEVEL::HIGH, "GENERATOR stop error\n");
			nlohmann::json jres;
			jres["response"]["code"] = 1;
			jres["response"]["msg"] = "Request PUT(/state/run) Generator stop error";
			jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
			jres["state"]["run"] = State.Run;
			*code = 501;
			return jres.dump(2);
    }
  }
  PRINT_ERR(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePutStateRun impossible situation\n");
	nlohmann::json jres;
	jres["response"]["code"] = 1;
	jres["response"]["msg"] = "Request PUT(/state/run) impossible situation";
	jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
	jres["state"]["run"] = State.Run;
	*code = 500;
	return jres.dump(2);
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponseGetStatsEb(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = true;//false;
  //tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return
R"({
  "stats": {
    "eb_id": 0,
    "time": "2021-10-06T04:34:21.1436",
    "period": 1000,
    "size": )" + std::to_string(std::experimental::randint(3000000, 4000000)) + R"(,
    "vpercent": )" + std::to_string(std::experimental::randint(0, 100)) + R"(,
    "avrpktsz": )" + std::to_string(std::experimental::randint(100, 1500)) + R"(,
    "pktcount": )" + std::to_string(std::experimental::randint(2000, 4000)) +
    R"(
  }
})";
  }
  else
  {
    *code = 501;
    return json_response_get_stats_eb_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  if(State.Run == false)
  {
		PRINT_ERR(PRINT_LEVEL::HIGH, "No Eps-Bearer Muxer statistics because Generator is not running\n");
		nlohmann::json jres;
		jres["response"]["code"] = 1;
		jres["response"]["msg"] = "Request GET(/stats/eb) No EpsBearerMuxer statistics because Generator is not running";
		jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
		*code = 501;
		return jres.dump(2);
  }
	std::time_t time_prev, time_curr;
	size_t full_size, full_time, video_size, non_video_size, packet_count;

	time_prev = Params.StatsTime;
	Params.StatsTime = DateTime::GetEpochTimeMicrosecCount();
	time_curr = Params.StatsTime;
	video_size = Params.StatsVideoSize;
  Params.StatsVideoSize = 0;
	non_video_size = Params.StatsNonVideoSize;
  Params.StatsNonVideoSize = 0;
	packet_count = Params.StatsPacketCount;
  Params.StatsPacketCount = 0;

  full_size = video_size + non_video_size;
  full_time = time_curr - time_prev;
  // статистика мультиплексора всех Eps-Bearer
	nlohmann::json jres;
	jres["response"]["code"] = 0;
	jres["response"]["msg"] = "Request GET(/stats/eb) processed successfully";
	jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
	jres["stats"]["eb_id"] = 0;
	jres["stats"]["time"] = DateTime::GetEpochTimeStringHTP(time_curr);
	jres["stats"]["period"] = full_time;
	jres["stats"]["size"] = full_size;
	jres["stats"]["vpercent"] = full_size ? 100 * video_size / full_size : 0;
	jres["stats"]["avrpktsz"] = packet_count ? full_size / packet_count : 0;
	jres["stats"]["pktcount"] = packet_count;
	*code = 201;
  if(full_time) PRINT_TMP(PRINT_LEVEL::HIGH, "EpsBearer Muxer statistics: br=%.2f bps, pr=%.2f pps\n", full_size*8000.0/full_time, packet_count*1000.0/full_time);
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponseGetStatsEbN(const std::string& reqs, int id, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = true;//false;
  //tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return
R"({
  "stats": {
    "eb_id": )" + std::to_string(id) + R"(,
    "time": "2021-10-06T04:34:21.1436",
    "period": 1000,
    "size": )" + std::to_string(std::experimental::randint(3000000, 4000000)) + R"(,
    "vpercent": )" + std::to_string(std::experimental::randint(0, 100)) + R"(,
    "avrpktsz": )" + std::to_string(std::experimental::randint(100, 1500)) + R"(,
    "pktcount": )" + std::to_string(std::experimental::randint(2000, 4000)) +
    R"(
  }
})";
  }
  else
  {
    *code = 501;
    return json_response_get_stats_eb_n_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  if(State.Run == false)
  {
		PRINT_ERR(PRINT_LEVEL::HIGH, "No Eps-Bearer statistics because Generator is not running\n");
		nlohmann::json jres;
		jres["response"]["code"] = 1;
		jres["response"]["msg"] = "Request GET(/stats/ebN) No EpsBearer statistics because Generator is not running";
		jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
		*code = 501;
		return jres.dump(2);
  }

	std::time_t time_prev, time_curr;
	size_t full_size, full_time, video_size, non_video_size, packet_count;

	time_prev = Params.EpsBearerList[id].StatsTime;
	Params.EpsBearerList[id].StatsTime = DateTime::GetEpochTimeMicrosecCount();
	time_curr = Params.EpsBearerList[id].StatsTime;
	video_size = Params.EpsBearerList[id].StatsVideoSize;
  Params.EpsBearerList[id].StatsVideoSize = 0;
	non_video_size = Params.EpsBearerList[id].StatsNonVideoSize;
  Params.EpsBearerList[id].StatsNonVideoSize = 0;
	packet_count = Params.EpsBearerList[id].StatsPacketCount;
  Params.EpsBearerList[id].StatsPacketCount = 0;

  full_size = video_size + non_video_size;
  full_time = time_curr - time_prev;
  // статистика по одному Eps-Bearer
	nlohmann::json jres;
	jres["response"]["code"] = id;
	jres["response"]["msg"] = "Request GET(/stats/ebN) processed successfully";
	jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
	jres["stats"]["eb_id"] = 0;
	jres["stats"]["time"] = DateTime::GetEpochTimeStringHTP(time_curr);
	jres["stats"]["period"] = full_time;
	jres["stats"]["size"] = full_size;
	jres["stats"]["vpercent"] = full_size ? 100 * video_size / full_size : 0;
	jres["stats"]["avrpktsz"] = packet_count ? full_size / packet_count : 0;
	jres["stats"]["pktcount"] = packet_count;
	*code = 201;
  if(full_time) PRINT_TMP(PRINT_LEVEL::HIGH, "EpsBearer[%i] statistics: br=%.2f bps, pr=%.2f pps\n", id, full_size*8000.0/full_time, packet_count*1000.0/full_time);
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponseGetParams(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_get_params_ok;
  }
  else
  {
    *code = 501;
    return json_response_get_params_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  int i;
  // все параметря работы Ядра ГТО
	nlohmann::json jres;
	jres["response"]["code"] = 0;
	jres["response"]["msg"] = "Request GET(/params) processed successfully";
	jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
	jres["params"]["mode"] = Params.Mode;
	jres["params"]["br"] = Params.Bitrate;
	jres["params"]["ipsrc"] = Params.IpSrc;
	jres["params"]["ipdst"] = Params.IpDst;
	jres["params"]["file"]["path"] = Params.File.Path;
	jres["params"]["file"]["size"] = Params.File.Size;
	jres["params"]["gtp"]["use"] = Params.Gtp.Use;
	jres["params"]["gtp"]["ipsrc"] = Params.Gtp.IpSrc;
	jres["params"]["gtp"]["ipdst"] = Params.Gtp.IpDst;
	jres["params"]["gtp"]["minteid"] = Params.Gtp.MinTeid;
	jres["params"]["gtp"]["maxteid"] = Params.Gtp.MaxTeid;
  jres["params"]["service"] = nlohmann::json::array();
  i = 0;
  for(auto& service: Params.ServiceList)
  {
    jres["params"]["service"][i]["id"] = service.second.Id;
    jres["params"]["service"][i]["name"] = service.second.Name;
    ++i;
  }
  jres["params"]["app"] = nlohmann::json::array();
  i = 0;
  for(auto& app: Params.AppList)
  {
    jres["params"]["app"][i]["id"] = app.second.Id;
    jres["params"]["app"][i]["name"] = app.second.Name;
    ++i;
  }
  jres["params"]["pcap"] = nlohmann::json::array();
  i = 0;
  for(auto& pcap: Params.PcapList)
  {
    jres["params"]["pcap"][i]["id"] = pcap.second.Id;
    jres["params"]["pcap"][i]["video"] = pcap.second.Video;
    jres["params"]["pcap"][i]["service"]["id"] = pcap.second.Service.Id;
    jres["params"]["pcap"][i]["app"]["id"] = pcap.second.App.Id;
    jres["params"]["pcap"][i]["br"] = pcap.second.Bitrate;
    jres["params"]["pcap"][i]["path"] = pcap.second.Path;
    ++i;
  }
  jres["params"]["user_scenario"] = nlohmann::json::array();
  i = 0;
  for(auto& us: Params.UserScenarioList)
  {
    jres["params"]["user_scenario"][i]["id"] = us.second.Id;
    jres["params"]["user_scenario"][i]["name"] = us.second.Name;
    jres["params"]["user_scenario"][i]["br"] = us.second.Bitrate;
    jres["params"]["user_scenario"][i]["pcap_id"] = nlohmann::json::array();
    int j = 0;
    for(auto& pcap_id: us.second.Pcap)
    {
      jres["params"]["user_scenario"][i]["pcap_id"][j] = pcap_id.first;
      ++j;
    }
    ++i;
  }
  jres["params"]["network_scenario"] = nlohmann::json::array();
  i = 0;
  for(auto& ns: Params.NetworkScenarioList)
  {
    jres["params"]["network_scenario"][i]["id"] = ns.second.Id;
    jres["params"]["network_scenario"][i]["name"] = ns.second.Name;
    jres["params"]["network_scenario"][i]["jitter"]["timeup"] = ns.second.Jitter.TimeUp;
    jres["params"]["network_scenario"][i]["jitter"]["timedown"] = ns.second.Jitter.TimeDown;
    jres["params"]["network_scenario"][i]["jitter"]["value"] = ns.second.Jitter.Value;
    jres["params"]["network_scenario"][i]["burst"]["timeup"] = ns.second.Burst.TimeUp;
    jres["params"]["network_scenario"][i]["burst"]["timedown"] = ns.second.Burst.TimeDown;
    ++i;
  }
  jres["params"]["eb"] = nlohmann::json::array();
  i = 0;
  for(auto& eb: Params.EpsBearerList)
  {
    jres["params"]["eb"][i]["id"] = eb.second.Id;
    jres["params"]["eb"][i]["br"] = eb.second.Bitrate;
    jres["params"]["eb"][i]["user_scenario"]["id"] = eb.second.UserScenario.Id;
    if( eb.second.UserScenario.Id == 0) // отправляем эти значения только для настраиваемого пользовательского сценария
    {
      jres["params"]["eb"][i]["user_scenario"]["name"] = eb.second.UserScenario.Name;
      jres["params"]["eb"][i]["user_scenario"]["br"] = eb.second.UserScenario.Bitrate;
      jres["params"]["eb"][i]["user_scenario"]["pcap_id"] = nlohmann::json::array();
      int j = 0;
      for(auto& pcap_id: eb.second.UserScenario.Pcap)
      {
        jres["params"]["eb"][i]["user_scenario"]["pcap_id"][j] = pcap_id.first;
        ++j;
      }
    }
    jres["params"]["eb"][i]["network_scenario"]["id"] = eb.second.NetworkScenario.Id;
    if(eb.second.NetworkScenario.Id == 0) // отправляем эти значения только для настраиваемого сетевого сценария
    {
      jres["params"]["eb"][i]["network_scenario"]["name"] = eb.second.NetworkScenario.Name;
      jres["params"]["eb"][i]["network_scenario"]["jitter"]["timeup"] = eb.second.NetworkScenario.Jitter.TimeUp;
      jres["params"]["eb"][i]["network_scenario"]["jitter"]["timedown"] = eb.second.NetworkScenario.Jitter.TimeDown;
      jres["params"]["eb"][i]["network_scenario"]["jitter"]["value"] = eb.second.NetworkScenario.Jitter.Value;
      jres["params"]["eb"][i]["network_scenario"]["burst"]["timeup"] = eb.second.NetworkScenario.Burst.TimeUp;
      jres["params"]["eb"][i]["network_scenario"]["burst"]["timedown"] = eb.second.NetworkScenario.Burst.TimeDown;
    }
    ++i;
  }
	*code = 201;
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponsePutParams(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_put_params_ok;
  }
  else
  {
    *code = 501;
    return json_response_put_params_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  int i, id;
	nlohmann::json jres;
  // формирование ответа (список всех параметров)
  auto make_response = [&](int response_code)
  {
    jres["response"]["code"] = response_code;
		if(response_code)
			jres["response"]["msg"] = "Request PUT(/params) error";
		else
			jres["response"]["msg"] = "Request PUT(/params) processed successfully";
    jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
    jres["params"]["mode"] = Params.Mode;
    jres["params"]["br"] = Params.Bitrate;
    jres["params"]["ipsrc"] = Params.IpSrc;
    jres["params"]["ipdst"] = Params.IpDst;
    jres["params"]["file"]["path"] = Params.File.Path;
    jres["params"]["file"]["size"] = Params.File.Size;
    jres["params"]["gtp"]["use"] = Params.Gtp.Use;
    jres["params"]["gtp"]["ipsrc"] = Params.Gtp.IpSrc;
    jres["params"]["gtp"]["ipdst"] = Params.Gtp.IpDst;
    jres["params"]["gtp"]["minteid"] = Params.Gtp.MinTeid;
    jres["params"]["gtp"]["maxteid"] = Params.Gtp.MaxTeid;
    jres["params"]["service"] = nlohmann::json::array();
    i = 0;
    for(auto& service: Params.ServiceList)
    {
      jres["params"]["service"][i]["id"] = service.second.Id;
      jres["params"]["service"][i]["name"] = service.second.Name;
      ++i;
    }
    jres["params"]["app"] = nlohmann::json::array();
    i = 0;
    for(auto& app: Params.AppList)
    {
      jres["params"]["app"][i]["id"] = app.second.Id;
      jres["params"]["app"][i]["name"] = app.second.Name;
      ++i;
    }
    jres["params"]["pcap"] = nlohmann::json::array();
    i = 0;
    for(auto& pcap: Params.PcapList)
    {
      jres["params"]["pcap"][i]["id"] = pcap.second.Id;
      jres["params"]["pcap"][i]["video"] = pcap.second.Video;
      jres["params"]["pcap"][i]["service"]["id"] = pcap.second.Service.Id;
      jres["params"]["pcap"][i]["app"]["id"] = pcap.second.App.Id;
      jres["params"]["pcap"][i]["br"] = pcap.second.Bitrate;
      jres["params"]["pcap"][i]["path"] = pcap.second.Path;
      ++i;
    }
    jres["params"]["user_scenario"] = nlohmann::json::array();
    i = 0;
    for(auto& us: Params.UserScenarioList)
    {
      jres["params"]["user_scenario"][i]["id"] = us.second.Id;
      jres["params"]["user_scenario"][i]["name"] = us.second.Name;
      jres["params"]["user_scenario"][i]["br"] = us.second.Bitrate;
      jres["params"]["user_scenario"][i]["pcap_id"] = nlohmann::json::array();
      int j = 0;
      for(auto& pcap_id: us.second.Pcap)
      {
        jres["params"]["user_scenario"][i]["pcap_id"][j] = pcap_id.first;
        ++j;
      }
      ++i;
    }
    jres["params"]["network_scenario"] = nlohmann::json::array();
    i = 0;
    for(auto& ns: Params.NetworkScenarioList)
    {
      jres["params"]["network_scenario"][i]["id"] = ns.second.Id;
      jres["params"]["network_scenario"][i]["name"] = ns.second.Name;
      jres["params"]["network_scenario"][i]["jitter"]["timeup"] = ns.second.Jitter.TimeUp;
      jres["params"]["network_scenario"][i]["jitter"]["timedown"] = ns.second.Jitter.TimeDown;
      jres["params"]["network_scenario"][i]["jitter"]["value"] = ns.second.Jitter.Value;
      jres["params"]["network_scenario"][i]["burst"]["timeup"] = ns.second.Burst.TimeUp;
      jres["params"]["network_scenario"][i]["burst"]["timedown"] = ns.second.Burst.TimeDown;
      ++i;
    }
    jres["params"]["eb"] = nlohmann::json::array();
    i = 0;
    for(auto& eb: Params.EpsBearerList)
    {
      jres["params"]["eb"][i]["id"] = eb.second.Id;
      jres["params"]["eb"][i]["br"] = eb.second.Bitrate;
      jres["params"]["eb"][i]["user_scenario"]["id"] = eb.second.UserScenario.Id;
      if(eb.second.UserScenario.Id == 0) // отправляем эти значения только для настраиваемого пользовательского сценария
      {
        jres["params"]["eb"][i]["user_scenario"]["name"] = eb.second.UserScenario.Name;
        jres["params"]["eb"][i]["user_scenario"]["br"] = eb.second.UserScenario.Bitrate;
        jres["params"]["eb"][i]["user_scenario"]["pcap_id"] = nlohmann::json::array();
        int j = 0;
        for(auto& pcap_id: eb.second.UserScenario.Pcap)
        {
          jres["params"]["eb"][i]["user_scenario"]["pcap_id"][j] = pcap_id.first;
          ++j;
        }
      }
      jres["params"]["eb"][i]["network_scenario"]["id"] = eb.second.NetworkScenario.Id;
      if(eb.second.NetworkScenario.Id == 0) // отправляем эти значения только для настраиваемого сетевого сценария
      {
        jres["params"]["eb"][i]["network_scenario"]["name"] = eb.second.NetworkScenario.Name;
        jres["params"]["eb"][i]["network_scenario"]["jitter"]["timeup"] = eb.second.NetworkScenario.Jitter.TimeUp;
        jres["params"]["eb"][i]["network_scenario"]["jitter"]["timedown"] = eb.second.NetworkScenario.Jitter.TimeDown;
        jres["params"]["eb"][i]["network_scenario"]["jitter"]["value"] = eb.second.NetworkScenario.Jitter.Value;
        jres["params"]["eb"][i]["network_scenario"]["burst"]["timeup"] = eb.second.NetworkScenario.Burst.TimeUp;
        jres["params"]["eb"][i]["network_scenario"]["burst"]["timedown"] = eb.second.NetworkScenario.Burst.TimeDown;
      }
      ++i;
    }
  };
  GeneratorParams_s params; // временный экземпляр параметров
  PRINT_TMP(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePutParams: %s\n", reqs.c_str());

#if ELIJA_TODO // в данный момет изменение параметров во время работы ЗАПРЕЩЕНО. в будущем можно переделать:
  // - быстрый вариант: остановить работу и запустить с новыми параметрами
  // - другой вариант: - искать изменения во всех параметрах и анализировать можно ли их изменить без перезапуска
  if(State.Run == true)
  {
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams: All parameters cannot be changed while Generator is running\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
  }
#endif
  // проверить запрос
	if(nlohmann::json::accept(reqs) == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePutParams is NOT a valid JSON\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  // разобрать запрос
  nlohmann::json jreq = nlohmann::json::parse(reqs);
  // анализ запроса )списо всех параметров среди которых какие-то могли измениться)
  // ResponsePutParams[params][mode]
  if(jreq["params"]["mode"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][mode] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["mode"].is_number() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][mode] has a wrong type (must be number)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  params.Mode = jreq["params"]["mode"];
  // ResponsePutParams[params][br]
  if(jreq["params"]["br"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][br] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["br"].is_number() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][br] has a wrong type (must be number)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  params.Bitrate = jreq["params"]["br"];
  // ResponsePutParams[params][ipsrc]
  if(jreq["params"]["ipsrc"].is_null() == false)
	{
    if(jreq["params"]["ipsrc"].is_string() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][ipsrc] has a wrong type (must be string)\n");
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.IpSrc = jreq["params"]["ipsrc"];
	}
  // ResponsePutParams[params][ipdst]
  if(jreq["params"]["ipdst"].is_null() == false)
	{
    if(jreq["params"]["ipdst"].is_string() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][ipdst] has a wrong type (must be string)\n");
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.IpDst = jreq["params"]["ipdst"];
	}
  // ResponsePutParams[params][file]
  if(jreq["params"]["file"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][file] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["file"].is_object() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][file] has a wrong type (must be object)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  // ResponsePutParams[params][file][path]
  if(jreq["params"]["file"]["path"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][file][path] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["file"]["path"].is_string() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][file][path] has a wrong type (must be string)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  params.File.Path = jreq["params"]["file"]["path"];
  // ResponsePutParams[params][file][size]
  if(jreq["params"]["file"]["size"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][file][size] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["file"]["size"].is_number() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][file][size] has a wrong type (must be number)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  params.File.Size = jreq["params"]["file"]["size"];
  // ResponsePutParams[params][gtp]
  if(jreq["params"]["gtp"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][gtp] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["gtp"].is_object() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][gtp] has a wrong type (must be object)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  // ResponsePutParams[params][gtp][use]
  if(jreq["params"]["gtp"]["use"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][gtp][use] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["gtp"]["use"].is_boolean() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][gtp][use] has a wrong type (must be boolean)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  params.Gtp.Use = jreq["params"]["gtp"]["use"];
  // ResponsePutParams[params][gtp][ipsrc]
  if(jreq["params"]["gtp"]["ipsrc"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][gtp][ipsrc] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["gtp"]["ipsrc"].is_string() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][gtp][ipsrc] has a wrong type (must be string)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  params.Gtp.IpSrc = jreq["params"]["gtp"]["ipsrc"];
  // ResponsePutParams[params][gtp][ipdst]
  if(jreq["params"]["gtp"]["ipdst"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][gtp][ipdst] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["gtp"]["ipdst"].is_string() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][gtp][ipdst] has a wrong type (must be string)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  params.Gtp.IpDst = jreq["params"]["gtp"]["ipdst"];
  // ResponsePutParams[params][gtp][minteid]
  if(jreq["params"]["gtp"]["minteid"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][gtp][minteid] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["gtp"]["minteid"].is_number() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][gtp][minteid] has a wrong type (must be number)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  params.Gtp.MinTeid = jreq["params"]["gtp"]["minteid"];
  // ResponsePutParams[params][gtp][maxteid]
  if(jreq["params"]["gtp"]["maxteid"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][gtp][maxteid] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["gtp"]["maxteid"].is_number() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][gtp][maxteid] has a wrong type (must be number)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  params.Gtp.MaxTeid = jreq["params"]["gtp"]["maxteid"];
  // ResponsePutParams[params][service]
  if(jreq["params"]["service"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][service] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["service"].is_array() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][service] has a wrong type (must be array)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  for(i=0; i<jreq["params"]["service"].size(); ++i)
  {
    // ResponsePutParams[params][service][i][id]
    if(jreq["params"]["service"][i]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][service][%i][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["service"][i]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][service][%i][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    id = jreq["params"]["service"][i]["id"];
    params.ServiceList[id].Id = id;
    // ResponsePutParams[params][service][i][name]
    if(jreq["params"]["service"][i]["name"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][service][%i][name] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["service"][i]["name"].is_string() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][service][%i][name] has a wrong type (must be string)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.ServiceList[id].Name = jreq["params"]["service"][i]["name"];
  }
  // ResponsePutParams[params][app]
  if(jreq["params"]["app"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][app] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["app"].is_array() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][app] has a wrong type (must be array)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  for(i=0; i<jreq["params"]["app"].size(); ++i)
  {
    // ResponsePutParams[params][app][i][id]
    if(jreq["params"]["app"][i]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][app][%i][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["app"][i]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][app][%i][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    id = jreq["params"]["app"][i]["id"];
    params.AppList[id].Id = id;
    // ResponsePutParams[params][app][i][name]
    if(jreq["params"]["app"][i]["name"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][app][%i][name] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["app"][i]["name"].is_string() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][app][%i][name] has a wrong type (must be string)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.AppList[id].Name = jreq["params"]["app"][i]["name"];
  }
  // ResponsePutParams[params][pcap]
  if(jreq["params"]["pcap"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][pcap] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["pcap"].is_array() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][pcap] has a wrong type (must be array)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  for(i=0; i<jreq["params"]["pcap"].size(); ++i)
  {
    // ResponsePutParams[params][pcap][i][id]
    if(jreq["params"]["pcap"][i]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][pcap][%i][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["pcap"][i]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][pcap][%i][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    id = jreq["params"]["pcap"][i]["id"];
    params.PcapList[id].Id = id;
    // ResponsePutParams[params][pcap][i][video]
    if(jreq["params"]["pcap"][i]["video"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][pcap][%i][video] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["pcap"][i]["video"].is_boolean() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][pcap][%i][video] has a wrong type (must be boolean)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.PcapList[id].Video = jreq["params"]["pcap"][i]["video"];
    // ResponsePutParams[params][pcap][i][service]
    if(jreq["params"]["pcap"][i]["service"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][pcap][%i][service] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["pcap"][i]["service"].is_object() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][pcap][%i][service] has a wrong type (must be object)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    // ResponsePutParams[params][pcap][i][service][id]
    if(jreq["params"]["pcap"][i]["service"]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][pcap][%i][service][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["pcap"][i]["service"]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][pcap][%i][service][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.PcapList[id].Service.Id = jreq["params"]["pcap"][i]["service"]["id"];
    // ResponsePutParams[params][pcap][i][app]
    if(jreq["params"]["pcap"][i]["app"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][pcap][%i][app] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["pcap"][i]["app"].is_object() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][pcap][%i][app] has a wrong type (must be object)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    // ResponsePutParams[params][pcap][i][app][id]
    if(jreq["params"]["pcap"][i]["app"]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][pcap][%i][app][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["pcap"][i]["app"]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][pcap][%i][app][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.PcapList[id].App.Id = jreq["params"]["pcap"][i]["app"]["id"];
    // ResponsePutParams[params][pcap][i][br]
    if(jreq["params"]["pcap"][i]["br"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][pcap][%i][br] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["pcap"][i]["br"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][pcap][%i][br] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.PcapList[id].Bitrate = jreq["params"]["pcap"][i]["br"];
    // ResponsePutParams[params][pcap][i][path]
    if(jreq["params"]["pcap"][i]["path"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][pcap][%i][path] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["pcap"][i]["path"].is_string() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][pcap][%i][path] has a wrong type (must be string)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.PcapList[id].Path = jreq["params"]["pcap"][i]["path"];
  }
  // ResponsePutParams[params][user_scenario]
  if(jreq["params"]["user_scenario"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][user_scenario] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["user_scenario"].is_array() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][user_scenario] has a wrong type (must be array)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  for(i=0; i<jreq["params"]["user_scenario"].size(); ++i)
  {
    // ResponsePutParams[params][user_scenario][i][id]
    if(jreq["params"]["user_scenario"][i]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][user_scenario][%i][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["user_scenario"][i]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][i][user_scenario][%i][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    id = jreq["params"]["user_scenario"][i]["id"];
    params.UserScenarioList[id].Id = id;
    // ResponsePutParams[params][user_scenario][i][name]
    if(jreq["params"]["user_scenario"][i]["name"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][user_scenario][%i][name] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["user_scenario"][i]["name"].is_string() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][user_scenario][%i][name] has a wrong type (must be string)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.UserScenarioList[id].Name = jreq["params"]["user_scenario"][i]["name"];
    // ResponsePutParams[params][eb][i][user_scenario][i][br]
    if(jreq["params"]["user_scenario"][i]["br"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][user_scenario][%i][br] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["user_scenario"][i]["br"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][user_scenario][%i][br] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.UserScenarioList[id].Bitrate = jreq["params"]["user_scenario"][i]["br"];
    // ResponsePutParams[params][user_scenario][i][pcap_id]
    if(jreq["params"]["user_scenario"][i]["pcap_id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][user_scenario][%i][pcap_id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["user_scenario"][i]["pcap_id"].is_array() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][user_scenario][%i][pcap_id] has a wrong type (must be array)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    for(int j=0; j<jreq["params"]["user_scenario"][i]["pcap_id"].size(); ++j)
    {
      // ResponsePutParams[params][user_scenario][i][pcap_id][j]
      if(jreq["params"]["user_scenario"][i]["pcap_id"][j].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][user_scenario][%i][pcap_id][%i] is null\n", i, j);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["user_scenario"][i]["pcap_id"][j].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][user_scenario][%i][pcap_id][%i] has a wrong type (must be number)\n", i, j);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
			int pid = jreq["params"]["user_scenario"][i]["pcap_id"][j];
      params.UserScenarioList[id].Pcap[pid] = {0};
    }
  }
  // ResponsePutParams[params][network_scenario]
  if(jreq["params"]["network_scenario"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["network_scenario"].is_array() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario] has a wrong type (must be array)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  for(i=0; i<jreq["params"]["network_scenario"].size(); ++i)
  {
    // ResponsePutParams[params][network_scenario][i][id]
    if(jreq["params"]["network_scenario"][i]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario][%i][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario][%i][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    id = jreq["params"]["network_scenario"][i]["id"];
    params.NetworkScenarioList[id].Id = id;
    // ResponsePutParams[params][network_scenario][i][name]
    if(jreq["params"]["network_scenario"][i]["name"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario][%i][name] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["name"].is_string() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario][%i][name] has a wrong type (must be string)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.NetworkScenarioList[id].Name = jreq["params"]["network_scenario"][i]["name"];
    // ResponsePutParams[params][network_scenario][i][jitter]
    if(jreq["params"]["network_scenario"][i]["jitter"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario][%i][jitter] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["jitter"].is_object() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario][%i][jitter] has a wrong type (must be object)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    // ResponsePutParams[params][network_scenario][i][jitter][timeup]
    if(jreq["params"]["network_scenario"][i]["jitter"]["timeup"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario][%i][jitter][timeup] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["jitter"]["timeup"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario][%i][jitter][timeup] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.NetworkScenarioList[id].Jitter.TimeUp = jreq["params"]["network_scenario"][i]["jitter"]["timeup"];
    // ResponsePutParams[params][network_scenario][i][jitter][timedown]
    if(jreq["params"]["network_scenario"][i]["jitter"]["timedown"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario][%i][jitter][timedown] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["jitter"]["timedown"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario][%i][jitter][timedown] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.NetworkScenarioList[id].Jitter.TimeDown = jreq["params"]["network_scenario"][i]["jitter"]["timedown"];
    // ResponsePutParams[params][network_scenario][i][jitter][value]
    if(jreq["params"]["network_scenario"][i]["jitter"]["value"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario][%i][jitter][value] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["jitter"]["value"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario][%i][jitter][value] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.NetworkScenarioList[id].Jitter.Value = jreq["params"]["network_scenario"][i]["jitter"]["value"];
    // ResponsePutParams[params][network_scenario][i][burst]
    if(jreq["params"]["network_scenario"][i]["burst"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario][%i][burst] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["burst"].is_object() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario][%i][burst] has a wrong type (must be object)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    // ResponsePutParams[params][network_scenario][i][burst][timeup]
    if(jreq["params"]["network_scenario"][i]["burst"]["timeup"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario][%i][burst][timeup] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["burst"]["timeup"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario][%i][burst][timeup] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.NetworkScenarioList[id].Burst.TimeUp = jreq["params"]["network_scenario"][i]["burst"]["timeup"];
    // ResponsePutParams[params][network_scenario][i][burst][timedown]
    if(jreq["params"]["network_scenario"][i]["burst"]["timedown"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario][%i][burst][timedown] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["burst"]["timedown"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario][%i][burst][timedown] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.NetworkScenarioList[id].Burst.TimeDown = jreq["params"]["network_scenario"][i]["burst"]["timedown"];
  }
  // ResponsePutParams[params][eb]
  if(jreq["params"]["eb"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["eb"].is_array() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb] has a wrong type (must be array)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  for(i=0; i<jreq["params"]["eb"].size(); ++i)
  {
    // ResponsePutParams[params][eb][i][id]
    if(jreq["params"]["eb"][i]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    id = jreq["params"]["eb"][i]["id"];
    params.EpsBearerList[id].Id = id;
    // ResponsePutParams[params][eb][i][br]
    if(jreq["params"]["eb"][i]["br"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][br] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["br"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][br] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.EpsBearerList[id].Bitrate = jreq["params"]["eb"][i]["br"];
    // ResponsePutParams[params][eb][i][user_scenario]
    if(jreq["params"]["eb"][i]["user_scenario"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][user_scenario] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["user_scenario"].is_object() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][user_scenario] has a wrong type (must be object)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    // ResponsePutParams[params][eb][i][user_scenario][id]
    if(jreq["params"]["eb"][i]["user_scenario"]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][user_scenario][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["user_scenario"]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][user_scenario][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.EpsBearerList[id].UserScenario.Id = jreq["params"]["eb"][i]["user_scenario"]["id"];
    if(params.EpsBearerList[id].UserScenario.Id == 0) // настраиваемый пользовательский сценарий, значит должны присутствовать все остальные элементы
    {
      // ResponsePutParams[params][eb][i][user_scenario][name]
      if(jreq["params"]["eb"][i]["user_scenario"]["name"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][user_scenario][name] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["user_scenario"]["name"].is_string() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][user_scenario][name] has a wrong type (must be string)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].UserScenario.Name = jreq["params"]["eb"][i]["user_scenario"]["name"];
      // ResponsePutParams[params][eb][i][user_scenario][br]
      if(jreq["params"]["eb"][i]["user_scenario"]["br"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][user_scenario][br] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["user_scenario"]["br"].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][user_scenario][br] has a wrong type (must be number)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].UserScenario.Bitrate = jreq["params"]["eb"][i]["user_scenario"]["br"];
      // ResponsePutParams[params][eb][i][user_scenario][pcap_id]
      if(jreq["params"]["eb"][i]["user_scenario"]["pcap_id"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][user_scenario][pcap_id] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["user_scenario"]["pcap_id"].is_array() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][user_scenario][pcap_id] has a wrong type (must be array)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      for(int j=0; j<jreq["params"]["eb"][i]["user_scenario"]["pcap_id"].size(); ++j)
      {
        // ResponsePutParams[params][eb][i][user_scenario][pcap_id][j]
        if(jreq["params"]["eb"][i]["user_scenario"]["pcap_id"][j].is_null())
        {
          PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][user_scenario][pcap_id][%i] is null\n", i, j);
          *code = 501;
          make_response(1);
          return jres.dump(2);
        }
        if(jreq["params"]["eb"][i]["user_scenario"]["pcap_id"][j].is_number() == false)
        {
          PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][user_scenario][pcap_id][%i] has a wrong type (must be number)\n", i, j);
          *code = 501;
          make_response(1);
          return jres.dump(2);
        }
				int pid = jreq["params"]["eb"][i]["user_scenario"]["pcap_id"][j];
        params.EpsBearerList[id].UserScenario.Pcap[pid] = {0};
      }
    }
    // ResponsePutParams[params][eb][i][network_scenario]
    if(jreq["params"]["eb"][i]["network_scenario"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][network_scenario] is null\n");
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["network_scenario"].is_object() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario] has a wrong type (must be object)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    // ResponsePutParams[params][eb][i][network_scenario][id]
    if(jreq["params"]["eb"][i]["network_scenario"]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["network_scenario"]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.EpsBearerList[id].NetworkScenario.Id = jreq["params"]["eb"][i]["network_scenario"]["id"];
    if(params.EpsBearerList[id].NetworkScenario.Id == 0) // настраиваемый сетевой сценарий, значит должны присутствовать все остальные элементы
    {
      // ResponsePutParams[params][eb][i][network_scenario][name]
      if(jreq["params"]["eb"][i]["network_scenario"]["name"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario][name] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["name"].is_string() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario][name] has a wrong type (must be string)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].NetworkScenario.Name = jreq["params"]["eb"][i]["network_scenario"]["name"];
      // ResponsePutParams[params][eb][i][network_scenario][jitter]
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario][jitter] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"].is_object() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario][jitter] has a wrong type (must be object)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      // ResponsePutParams[params][eb][i][network_scenario][jitter][timeup]
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"]["timeup"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario][jitter][timeup] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"]["timeup"].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario][jitter][timeup] has a wrong type (must be number)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].NetworkScenario.Jitter.TimeUp = jreq["params"]["eb"][i]["network_scenario"]["jitter"]["timeup"];
      // ResponsePutParams[params][eb][i][network_scenario][jitter][timedown]
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"]["timedown"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario][jitter][timedown] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"]["timedown"].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario][jitter][timedown] has a wrong type (must be number)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].NetworkScenario.Jitter.TimeDown = jreq["params"]["eb"][i]["network_scenario"]["jitter"]["timedown"];
      // ResponsePutParams[params][eb"[i][network_scenario][jitter][value]
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"]["value"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario][jitter][value] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"]["value"].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario][jitter][value] has a wrong type (must be number)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].NetworkScenario.Jitter.Value = jreq["params"]["eb"][i]["network_scenario"]["jitter"]["value"];
      // ResponsePutParams[params][eb][i][network_scenario][burst]
      if(jreq["params"]["eb"][i]["network_scenario"]["burst"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario][burst] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["burst"].is_object() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario][burst] has a wrong type (must be object)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      // ResponsePutParams[params][eb][i][network_scenario][burst][timeup]
      if(jreq["params"]["eb"][i]["network_scenario"]["burst"]["timeup"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario][burst][timeup] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["burst"]["timeup"].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario][burst][timeup] has a wrong type (must be number)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].NetworkScenario.Burst.TimeUp = jreq["params"]["eb"][i]["network_scenario"]["burst"]["timeup"];
      // ResponsePutParams[params][eb][i][network_scenario][burst][timedown]
      if(jreq["params"]["eb"][i]["network_scenario"]["burst"]["timedown"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario][burst][timedown] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["burst"]["timedown"].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParams[params][eb][%i][network_scenario][burst][timedown] has a wrong type (must be number)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].NetworkScenario.Burst.TimeDown = jreq["params"]["eb"][i]["network_scenario"]["burst"]["timedown"];
    }
}
  // успешное завершение анализа запроса
	*code = 201;
  {
    std::lock_guard<std::mutex> lk(ParamsMutex);
    Params = params;
  }
	WriteParams();
  make_response(0);
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponseGetParamsCommon(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_get_params_common_ok;
  }
  else
  {
    *code = 501;
    return json_response_get_params_common_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  // формирование ответа (список всех общих параметров)
	nlohmann::json jres;
	jres["response"]["code"] = 0;
	jres["response"]["msg"] = "Request GET(/params/common) processed successfully";
	jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
	jres["params"]["mode"] = Params.Mode;
	jres["params"]["br"] = Params.Bitrate;
	jres["params"]["ipsrc"] = Params.IpSrc;
	jres["params"]["ipdst"] = Params.IpDst;
	jres["params"]["file"]["path"] = Params.File.Path;
	jres["params"]["file"]["size"] = Params.File.Size;
	jres["params"]["gtp"]["use"] = Params.Gtp.Use;
	jres["params"]["gtp"]["ipsrc"] = Params.Gtp.IpSrc;
	jres["params"]["gtp"]["ipdst"] = Params.Gtp.IpDst;
	jres["params"]["gtp"]["minteid"] = Params.Gtp.MinTeid;
	jres["params"]["gtp"]["maxteid"] = Params.Gtp.MaxTeid;
	*code = 201;
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponsePutParamsCommon(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_put_params_common_ok;
  }
  else
  {
    *code = 501;
    return json_response_put_params_common_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
	nlohmann::json jres;
  // формирование ответа (список всех общих параметров)
  auto make_response = [&](int response_code)
  {
    jres["response"]["code"] = response_code;
		if(response_code)
			jres["response"]["msg"] = "Request PUT(/params/common) error";
		else
			jres["response"]["msg"] = "Request PUT(/params/common) processed successfully";
    jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
    jres["params"]["mode"] = Params.Mode;
    jres["params"]["br"] = Params.Bitrate;
    jres["params"]["ipsrc"] = Params.IpSrc;
    jres["params"]["ipdst"] = Params.IpDst;
    jres["params"]["file"]["path"] = Params.File.Path;
    jres["params"]["file"]["size"] = Params.File.Size;
    jres["params"]["gtp"]["use"] = Params.Gtp.Use;
    jres["params"]["gtp"]["ipsrc"] = Params.Gtp.IpSrc;
    jres["params"]["gtp"]["ipdst"] = Params.Gtp.IpDst;
    jres["params"]["gtp"]["minteid"] = Params.Gtp.MinTeid;
    jres["params"]["gtp"]["maxteid"] = Params.Gtp.MaxTeid;
  };
  GeneratorParams_s params; // временный экземпляр параметров
  PRINT_TMP(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePutParamsCommon: %s\n", reqs.c_str());
#if ELIJA_TODO // в данный момет изменение параметров во время работы ЗАПРЕЩЕНО. в будущем можно переделать:
  // - быстрый вариант: остановить работу и запустить с новыми параметрами
  // - другой вариант: - искать изменения во всех параметрах и анализировать можно ли их изменить без перезапуска
  if(State.Run == true)
  {
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon: All parameters cannot be changed while Generator is running\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
  }
#endif
  // проверить запрос
	if(nlohmann::json::accept(reqs) == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePutParamsCommon is NOT a valid JSON\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  // разобрать запрос
  nlohmann::json jreq = nlohmann::json::parse(reqs);
  // анализ запроса (список всех общих параметров среди которых какие-то могли измениться)
  // ResponsePutParamsCommon[params][mode]
  if(jreq["params"]["mode"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][mode] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["mode"].is_number() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][mode] has a wrong type (must be number)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  params.Mode = jreq["params"]["mode"];
  // ResponsePutParamsCommon[params][br]
  if(jreq["params"]["br"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][br] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["br"].is_number() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][br] has a wrong type (must be number)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  params.Bitrate = jreq["params"]["br"];
  // ResponsePutParamsCommon[params][ipsrc]
  if(jreq["params"]["ipsrc"].is_null() == false)
	{
    if(jreq["params"]["ipsrc"].is_string() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][ipsrc] has a wrong type (must be string)\n");
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.IpSrc = jreq["params"]["ipsrc"];
	}
  // ResponsePutParamsCommon[params][ipdst]
  if(jreq["params"]["ipdst"].is_null() == false)
	{
    if(jreq["params"]["ipdst"].is_string() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][ipdst] has a wrong type (must be string)\n");
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.IpDst = jreq["params"]["ipdst"];
	}
  // ResponsePutParamsCommon[params][file]
  if(jreq["params"]["file"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][file] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["file"].is_object() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][file] has a wrong type (must be object)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  // ResponsePutParamsCommon[params][file][path]
  if(jreq["params"]["file"]["path"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][file][path] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["file"]["path"].is_string() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][file][path] has a wrong type (must be string)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  params.File.Path = jreq["params"]["file"]["path"];
  // ResponsePutParamsCommon[params][file][size]
  if(jreq["params"]["file"]["size"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][file][size] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["file"]["size"].is_number() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][file][size] has a wrong type (must be number)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  params.File.Size = jreq["params"]["file"]["size"];
  // ResponsePutParamsCommon[params][gtp]
  if(jreq["params"]["gtp"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][gtp] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["gtp"].is_object() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][gtp] has a wrong type (must be object)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  // ResponsePutParamsCommon[params][gtp][use]
  if(jreq["params"]["gtp"]["use"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][gtp][use] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["gtp"]["use"].is_boolean() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][gtp][use] has a wrong type (must be boolean)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  params.Gtp.Use = jreq["params"]["gtp"]["use"];
  // ResponsePutParamsCommon[params][gtp][ipsrc]
  if(jreq["params"]["gtp"]["ipsrc"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][gtp][ipsrc] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["gtp"]["ipsrc"].is_string() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][gtp][ipsrc] has a wrong type (must be string)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  params.Gtp.IpSrc = jreq["params"]["gtp"]["ipsrc"];
  // ResponsePutParamsCommon[params][gtp][ipdst]
  if(jreq["params"]["gtp"]["ipdst"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][gtp][ipdst] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["gtp"]["ipdst"].is_string() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][gtp][ipdst] has a wrong type (must be string)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  params.Gtp.IpDst = jreq["params"]["gtp"]["ipdst"];
  // ResponsePutParamsCommon[params][gtp][minteid]
  if(jreq["params"]["gtp"]["minteid"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][gtp][minteid] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["gtp"]["minteid"].is_number() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][gtp][minteid] has a wrong type (must be number)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  params.Gtp.MinTeid = jreq["params"]["gtp"]["minteid"];
  // ResponsePutParamsCommon[params][gtp][maxteid]
  if(jreq["params"]["gtp"]["maxteid"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][gtp][maxteid] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["gtp"]["maxteid"].is_number() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsCommon[params][gtp][maxteid] has a wrong type (must be number)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  params.Gtp.MaxTeid = jreq["params"]["gtp"]["maxteid"];

  // успешное завершение анализа запроса
	*code = 201;
  {
    std::lock_guard<std::mutex> lk(ParamsMutex);
    // заменить старые общие параметры на новые
    Params.Mode = params.Mode;
    Params.Bitrate = params.Bitrate;
    Params.IpSrc = params.IpSrc;
    Params.IpDst = params.IpDst;
    Params.File = params.File;
    Params.Gtp = params.Gtp;
  }
	WriteParams();
  make_response(0);
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponseGetParamsService(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_get_params_service_ok;
  }
  else
  {
    *code = 501;
    return json_response_get_params_service_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  int i;
  // формирование ответа (список всех сервисов)
	nlohmann::json jres;
	jres["response"]["code"] = 0;
	jres["response"]["msg"] = "Request GET(/params/service) processed successfully";
	jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
  jres["params"]["service"] = nlohmann::json::array();
  i = 0;
  for(auto& service: Params.ServiceList)
  {
    jres["params"]["service"][i]["id"] = service.second.Id;
    jres["params"]["service"][i]["name"] = service.second.Name;
    ++i;
  }
	*code = 201;
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponseGetParamsApp(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_get_params_app_ok;
  }
  else
  {
    *code = 501;
    return json_response_get_params_app_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  int i;
  // формирование ответа (список всех приложений)
	nlohmann::json jres;
	jres["response"]["code"] = 0;
	jres["response"]["msg"] = "Request GET(/params/app) processed successfully";
	jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
  jres["params"]["app"] = nlohmann::json::array();
  i = 0;
  for(auto& app: Params.AppList)
  {
    jres["params"]["app"][i]["id"] = app.second.Id;
    jres["params"]["app"][i]["name"] = app.second.Name;
    ++i;
  }
	*code = 201;
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponseGetParamsPcap(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_get_params_pcap_ok;
  }
  else
  {
    *code = 501;
    return json_response_get_params_pcap_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  int i;
  // формирование ответа (список всех PCAP файлов)
	nlohmann::json jres;
	jres["response"]["code"] = 0;
	jres["response"]["msg"] = "Request GET(/params/pcap) processed successfully";
	jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
  jres["params"]["pcap"] = nlohmann::json::array();
  i = 0;
  for(auto& pcap: Params.PcapList)
  {
    jres["params"]["pcap"][i]["id"] = pcap.second.Id;
    jres["params"]["pcap"][i]["video"] = pcap.second.Video;
    jres["params"]["pcap"][i]["service"]["id"] = pcap.second.Service.Id;
    jres["params"]["pcap"][i]["app"]["id"] = pcap.second.App.Id;
    jres["params"]["pcap"][i]["br"] = pcap.second.Bitrate;
    jres["params"]["pcap"][i]["path"] = pcap.second.Path;
    ++i;
  }
	*code = 201;
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponseGetParamsUserScenario(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_get_params_user_scenario_ok;
  }
  else
  {
    *code = 501;
    return json_response_get_params_user_scenario_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  int i;
  // формирование ответа (список всех пользовательских сценариев)
	nlohmann::json jres;
	jres["response"]["code"] = 0;
	jres["response"]["msg"] = "Request GET(/params/user_scenario) processed successfully";
	jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
  jres["params"]["user_scenario"] = nlohmann::json::array();
  i = 0;
  for(auto& us: Params.UserScenarioList)
  {
    jres["params"]["user_scenario"][i]["id"] = us.second.Id;
    jres["params"]["user_scenario"][i]["name"] = us.second.Name;
    jres["params"]["user_scenario"][i]["br"] = us.second.Bitrate;
    jres["params"]["user_scenario"][i]["pcap_id"] = nlohmann::json::array();
    int j = 0;
    for(auto& pcap_id: us.second.Pcap)
    {
      jres["params"]["user_scenario"][i]["pcap_id"][j] = pcap_id.first;
      ++j;
    }
    ++i;
  }
	*code = 201;
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponsePostParamsUserScenario(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_post_params_user_scenario_ok;
  }
  else
  {
    *code = 501;
    return json_response_post_params_user_scenario_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  int i, id;
	nlohmann::json jres;
  // формирование ответа (возвращаем список всех пользовательских сценариев)
  auto make_response = [&](int response_code)
  {
    jres["response"]["code"] = response_code;
    jres["response"]["msg"] = "Request POST(/params/user_scenario) processed successfully";
    jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
    jres["params"]["user_scenario"] = nlohmann::json::array();
    i = 0;
    for(auto& us: Params.UserScenarioList)
    {
      jres["params"]["user_scenario"][i]["id"] = us.second.Id;
      jres["params"]["user_scenario"][i]["name"] = us.second.Name;
      jres["params"]["user_scenario"][i]["br"] = us.second.Bitrate;
      jres["params"]["user_scenario"][i]["pcap_id"] = nlohmann::json::array();
      int j = 0;
      for(auto& pcap_id: us.second.Pcap)
      {
        jres["params"]["user_scenario"][i]["pcap_id"][j] = pcap_id.first;
        ++j;
      }
      ++i;
    }
  };
  GeneratorParams_s params; // временный экземпляр параметров
  PRINT_TMP(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePostParamsUserScenario: %s\n", reqs.c_str());
  // проверить запрос
	if(nlohmann::json::accept(reqs) == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePostParamsUserScenario is NOT a valid JSON\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  // разобрать запрос
  nlohmann::json jreq = nlohmann::json::parse(reqs);
  // анализ запроса (список создаваемых пользовательских сценариев)
  // ResponsePostParamsUserScenario[params][user_scenario]
  if(jreq["params"]["user_scenario"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsUserScenario[params][user_scenario] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["user_scenario"].is_array() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsUserScenario[params][user_scenario] has a wrong type (must be array)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  for(i=0; i<jreq["params"]["user_scenario"].size(); ++i)
  {
    // ResponsePostParamsUserScenario[params][user_scenario][i][id]
    if(jreq["params"]["user_scenario"][i]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsUserScenario[params][user_scenario][%i][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["user_scenario"][i]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsUserScenario[params][eb][i][user_scenario][%i][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    id = jreq["params"]["user_scenario"][i]["id"];
    params.UserScenarioList[id].Id = id;
    // ResponsePostParamsUserScenario[params][user_scenario][i][name]
    if(jreq["params"]["user_scenario"][i]["name"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsUserScenario[params][user_scenario][%i][name] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["user_scenario"][i]["name"].is_string() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsUserScenario[params][user_scenario][%i][name] has a wrong type (must be string)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.UserScenarioList[id].Name = jreq["params"]["user_scenario"][i]["name"];
    // ResponsePostParamsUserScenario[params][eb][i][user_scenario][i][br]
    if(jreq["params"]["user_scenario"][i]["br"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsUserScenario[params][user_scenario][%i][br] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["user_scenario"][i]["br"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsUserScenario[params][user_scenario][%i][br] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.UserScenarioList[id].Bitrate = jreq["params"]["user_scenario"][i]["br"];
    // ResponsePostParamsUserScenario[params][user_scenario][i][pcap_id]
    if(jreq["params"]["user_scenario"][i]["pcap_id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsUserScenario[params][user_scenario][%i][pcap_id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["user_scenario"][i]["pcap_id"].is_array() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsUserScenario[params][user_scenario][%i][pcap_id] has a wrong type (must be array)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    for(int j=0; j<jreq["params"]["user_scenario"][i]["pcap_id"].size(); ++j)
    {
      // ResponsePostParamsUserScenario[params][user_scenario][i][pcap_id][j]
      if(jreq["params"]["user_scenario"][i]["pcap_id"][j].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsUserScenario[params][user_scenario][%i][pcap_id][%i] is null\n", i, j);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["user_scenario"][i]["pcap_id"][j].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsUserScenario[params][user_scenario][%i][pcap_id][%i] has a wrong type (must be number)\n", i, j);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
			int pid = jreq["params"]["user_scenario"][i]["pcap_id"][j];
      params.UserScenarioList[id].Pcap[pid] = {0};
    }
  }
  // успешное завершение анализа запроса
	*code = 201;
  {
    std::lock_guard<std::mutex> lk(ParamsMutex);
    // добавить к старым пользовательским сценариям новые
    Params.UserScenarioList.merge(params.UserScenarioList);
  }
	WriteParams();
  make_response(0);
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponsePutParamsUserScenario(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_put_params_user_scenario_ok;
  }
  else
  {
    *code = 501;
    return json_response_put_params_user_scenario_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  int i, id;
	nlohmann::json jres;
  // формирование ответа (список всех пользовательских сценариев)
  auto make_response = [&](int response_code)
  {
    jres["response"]["code"] = response_code;
		jres["response"]["msg"] = "Request PUT(/params/user_scenario) processed successfully";
    jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
    jres["params"]["user_scenario"] = nlohmann::json::array();
    i = 0;
    for(auto& us: Params.UserScenarioList)
    {
      jres["params"]["user_scenario"][i]["id"] = us.second.Id;
      jres["params"]["user_scenario"][i]["name"] = us.second.Name;
      jres["params"]["user_scenario"][i]["br"] = us.second.Bitrate;
      jres["params"]["user_scenario"][i]["pcap_id"] = nlohmann::json::array();
      int j = 0;
      for(auto& pcap_id: us.second.Pcap)
      {
        jres["params"]["user_scenario"][i]["pcap_id"][j] = pcap_id.first;
        ++j;
      }
      ++i;
    }
  };
  GeneratorParams_s params; // временный экземпляр параметров
  PRINT_TMP(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePutParamsUserScenario: %s\n", reqs.c_str());
#if ELIJA_TODO // в данный момет изменение во время работы ЗАПРЕЩЕНО. в будущем можно переделать
  if(State.Run == true)
  {
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsUserScenario: All parameters cannot be changed while Generator is running\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
  }
#endif
  // проверить запрос
	if(nlohmann::json::accept(reqs) == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePutParamsUserScenario is NOT a valid JSON\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  // разобрать запрос
  nlohmann::json jreq = nlohmann::json::parse(reqs);
  // анализ запроса (список изменяемых пользовательских сценариев)
  // ResponsePutParamsUserScenario[params][user_scenario]
  if(jreq["params"]["user_scenario"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsUserScenario[params][user_scenario] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["user_scenario"].is_array() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsUserScenario[params][user_scenario] has a wrong type (must be array)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  for(i=0; i<jreq["params"]["user_scenario"].size(); ++i)
  {
    // ResponsePutParamsUserScenario[params][user_scenario][i][id]
    if(jreq["params"]["user_scenario"][i]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsUserScenario[params][user_scenario][%i][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["user_scenario"][i]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsUserScenario[params][eb][i][user_scenario][%i][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    id = jreq["params"]["user_scenario"][i]["id"];
    params.UserScenarioList[id].Id = id;
    // ResponsePutParamsUserScenario[params][user_scenario][i][name]
    if(jreq["params"]["user_scenario"][i]["name"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsUserScenario[params][user_scenario][%i][name] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["user_scenario"][i]["name"].is_string() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsUserScenario[params][user_scenario][%i][name] has a wrong type (must be string)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.UserScenarioList[id].Name = jreq["params"]["user_scenario"][i]["name"];
    // ResponsePutParamsUserScenario[params][eb][i][user_scenario][i][br]
    if(jreq["params"]["user_scenario"][i]["br"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsUserScenario[params][user_scenario][%i][br] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["user_scenario"][i]["br"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsUserScenario[params][user_scenario][%i][br] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.UserScenarioList[id].Bitrate = jreq["params"]["user_scenario"][i]["br"];
    // ResponsePutParamsUserScenario[params][user_scenario][i][pcap_id]
    if(jreq["params"]["user_scenario"][i]["pcap_id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsUserScenario[params][user_scenario][%i][pcap_id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["user_scenario"][i]["pcap_id"].is_array() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsUserScenario[params][user_scenario][%i][pcap_id] has a wrong type (must be array)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    for(int j=0; j<jreq["params"]["user_scenario"][i]["pcap_id"].size(); ++j)
    {
      // ResponsePutParamsUserScenario[params][user_scenario][i][pcap_id][j]
      if(jreq["params"]["user_scenario"][i]["pcap_id"][j].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsUserScenario[params][user_scenario][%i][pcap_id][%i] is null\n", i, j);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["user_scenario"][i]["pcap_id"][j].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsUserScenario[params][user_scenario][%i][pcap_id][%i] has a wrong type (must be number)\n", i, j);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
			int pid = jreq["params"]["user_scenario"][i]["pcap_id"][j];
      params.UserScenarioList[id].Pcap[pid] = {0};
    }
  }
  // успешное завершение анализа запроса
	*code = 201;
  {
    std::lock_guard<std::mutex> lk(ParamsMutex);
    // заменить параметры обновлённых пользовательских сценариев
    for(auto& us: params.UserScenarioList)
    {
      Params.UserScenarioList[us.second.Id] = params.UserScenarioList[us.second.Id];
    }
  }
	WriteParams();
  make_response(0);
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponseDeleteParamsUserScenario(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_put_params_user_scenario_err;
  }
  else
  {
    *code = 501;
    return json_response_delete_params_user_scenario_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  int i, id;
	nlohmann::json jres;
  // формирование ответа (список всех пользовательских сценариев)
  auto make_response = [&](int response_code)
  {
    jres["response"]["code"] = response_code;
		jres["response"]["msg"] = "Request DELETE(/params/user_scenario) processed successfully";
    jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
    jres["params"]["user_scenario"] = nlohmann::json::array();
    i = 0;
    for(auto& us: Params.UserScenarioList)
    {
      jres["params"]["user_scenario"][i]["id"] = us.second.Id;
      jres["params"]["user_scenario"][i]["name"] = us.second.Name;
      jres["params"]["user_scenario"][i]["br"] = us.second.Bitrate;
      jres["params"]["user_scenario"][i]["pcap_id"] = nlohmann::json::array();
      int j = 0;
      for(auto& pcap_id: us.second.Pcap)
      {
        jres["params"]["user_scenario"][i]["pcap_id"][j] = pcap_id.first;
        ++j;
      }
      ++i;
    }
  };
  GeneratorParams_s params; // временный экземпляр параметров
  PRINT_TMP(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePutParamsUserScenario: %s\n", reqs.c_str());
#if ELIJA_TODO // в данный момет удаление во время работы ЗАПРЕЩЕНО. в будущем можно переделать
  if(State.Run == true)
  {
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsUserScenario: All parameters cannot be changed while Generator is running\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
  }
#endif
  // проверить запрос
	if(nlohmann::json::accept(reqs) == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePutParamsUserScenario is NOT a valid JSON\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  // разобрать запрос
  nlohmann::json jreq = nlohmann::json::parse(reqs);
  // анализ запроса (список удаляемых пользовательских сценариев)
  // ResponsePutParamsUserScenario[params][user_scenario]
  if(jreq["params"]["user_scenario"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsUserScenario[params][user_scenario] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["user_scenario"].is_array() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsUserScenario[params][user_scenario] has a wrong type (must be array)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  for(i=0; i<jreq["params"]["user_scenario"].size(); ++i)
  {
    // ResponsePutParamsUserScenario[params][user_scenario][i][id]
    if(jreq["params"]["user_scenario"][i]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsUserScenario[params][user_scenario][%i][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["user_scenario"][i]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsUserScenario[params][eb][i][user_scenario][%i][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    id = jreq["params"]["user_scenario"][i]["id"];
    params.UserScenarioList[id].Id = id;
#if __cplusplus > 201703L // C++20
		if(Params.UserScenarioList.contains(id) == false)
#else
		if(Params.UserScenarioList.count(id) == 0)
#endif
#if ELIJA_TODO // здесь сделать защиту от повторения id  в одном запросе? сейчас программа как-то плохо на это реагирует
#endif
		{
			PRINT_ERR(PRINT_LEVEL::HIGH, "UserScenario cannot be deleted because Generator has NO UserScenario with id=%i\n", id);
			*code = 501;
			make_response(1);
			return jres.dump(2);
		}
  }
  // успешное завершение анализа запроса
	*code = 201;
  {
    std::lock_guard<std::mutex> lk(ParamsMutex);
    // удалить пользовательские сценариии
    for(auto& us: params.UserScenarioList)
    {
      Params.UserScenarioList.erase(us.second.Id);
    }
  }
	WriteParams();
  make_response(0);
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponseGetParamsNetworkScenario(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_get_params_network_scenario_ok;
  }
  else
  {
    *code = 501;
    return json_response_get_params_network_scenario_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  int i;
  // формирование ответа (список всех сетевых сценариев)
	nlohmann::json jres;
	jres["response"]["code"] = 0;
	jres["response"]["msg"] = "Request GET(/params/network_scenario) processed successfully";
	jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
  jres["params"]["network_scenario"] = nlohmann::json::array();
  i = 0;
  for(auto& ns: Params.NetworkScenarioList)
  {
    jres["params"]["network_scenario"][i]["id"] = ns.second.Id;
    jres["params"]["network_scenario"][i]["name"] = ns.second.Name;
    jres["params"]["network_scenario"][i]["jitter"]["timeup"] = ns.second.Jitter.TimeUp;
    jres["params"]["network_scenario"][i]["jitter"]["timedown"] = ns.second.Jitter.TimeDown;
    jres["params"]["network_scenario"][i]["jitter"]["value"] = ns.second.Jitter.Value;
    jres["params"]["network_scenario"][i]["burst"]["timeup"] = ns.second.Burst.TimeUp;
    jres["params"]["network_scenario"][i]["burst"]["timedown"] = ns.second.Burst.TimeDown;
    ++i;
  }
	*code = 201;
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponsePostParamsNetworkScenario(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_post_params_network_scenario_ok;
  }
  else
  {
    *code = 501;
    return json_response_post_params_network_scenario_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  int i, id;
	nlohmann::json jres;
  // формирование ответа (список всех сетевых сценариев)
  auto make_response = [&](int response_code)
  {
    jres["response"]["code"] = response_code;
		jres["response"]["msg"] = "Request POST(/params/network_scenario) processed successfully";
    jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
    jres["params"]["network_scenario"] = nlohmann::json::array();
    i = 0;
    for(auto& ns: Params.NetworkScenarioList)
    {
      jres["params"]["network_scenario"][i]["id"] = ns.second.Id;
      jres["params"]["network_scenario"][i]["name"] = ns.second.Name;
      jres["params"]["network_scenario"][i]["jitter"]["timeup"] = ns.second.Jitter.TimeUp;
      jres["params"]["network_scenario"][i]["jitter"]["timedown"] = ns.second.Jitter.TimeDown;
      jres["params"]["network_scenario"][i]["jitter"]["value"] = ns.second.Jitter.Value;
      jres["params"]["network_scenario"][i]["burst"]["timeup"] = ns.second.Burst.TimeUp;
      jres["params"]["network_scenario"][i]["burst"]["timedown"] = ns.second.Burst.TimeDown;
      ++i;
    }
  };
  GeneratorParams_s params; // временный экземпляр параметров
  PRINT_TMP(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePostParamsNetworkScenario: %s\n", reqs.c_str());
  // проверить запрос
	if(nlohmann::json::accept(reqs) == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePostParamsNetworkScenario is NOT a valid JSON\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  // разобрать запрос
  nlohmann::json jreq = nlohmann::json::parse(reqs);
  // анализ запроса (список создаваемых сетевых сценариев)
  // ResponsePostParamsNetworkScenario[params][network_scenario]
  if(jreq["params"]["network_scenario"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["network_scenario"].is_array() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario] has a wrong type (must be array)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  for(i=0; i<jreq["params"]["network_scenario"].size(); ++i)
  {
    // ResponsePostParamsNetworkScenario[params][network_scenario][i][id]
    if(jreq["params"]["network_scenario"][i]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario][%i][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario][%i][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    id = jreq["params"]["network_scenario"][i]["id"];
    params.NetworkScenarioList[id].Id = id;
    // ResponsePostParamsNetworkScenario[params][network_scenario][i][name]
    if(jreq["params"]["network_scenario"][i]["name"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario][%i][name] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["name"].is_string() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario][%i][name] has a wrong type (must be string)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.NetworkScenarioList[id].Name = jreq["params"]["network_scenario"][i]["name"];
    // ResponsePostParamsNetworkScenario[params][network_scenario][i][jitter]
    if(jreq["params"]["network_scenario"][i]["jitter"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario][%i][jitter] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["jitter"].is_object() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario][%i][jitter] has a wrong type (must be object)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    // ResponsePostParamsNetworkScenario[params][network_scenario][i][jitter][timeup]
    if(jreq["params"]["network_scenario"][i]["jitter"]["timeup"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario][%i][jitter][timeup] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["jitter"]["timeup"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario][%i][jitter][timeup] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.NetworkScenarioList[id].Jitter.TimeUp = jreq["params"]["network_scenario"][i]["jitter"]["timeup"];
    // ResponsePostParamsNetworkScenario[params][network_scenario][i][jitter][timedown]
    if(jreq["params"]["network_scenario"][i]["jitter"]["timedown"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario][%i][jitter][timedown] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["jitter"]["timedown"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario][%i][jitter][timedown] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.NetworkScenarioList[id].Jitter.TimeDown = jreq["params"]["network_scenario"][i]["jitter"]["timedown"];
    // ResponsePostParamsNetworkScenario[params][network_scenario][i][jitter][value]
    if(jreq["params"]["network_scenario"][i]["jitter"]["value"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario][%i][jitter][value] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["jitter"]["value"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario][%i][jitter][value] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.NetworkScenarioList[id].Jitter.Value = jreq["params"]["network_scenario"][i]["jitter"]["value"];
    // ResponsePostParamsNetworkScenario[params][network_scenario][i][burst]
    if(jreq["params"]["network_scenario"][i]["burst"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario][%i][burst] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["burst"].is_object() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario][%i][burst] has a wrong type (must be object)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    // ResponsePostParamsNetworkScenario[params][network_scenario][i][burst][timeup]
    if(jreq["params"]["network_scenario"][i]["burst"]["timeup"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario][%i][burst][timeup] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["burst"]["timeup"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario][%i][burst][timeup] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.NetworkScenarioList[id].Burst.TimeUp = jreq["params"]["network_scenario"][i]["burst"]["timeup"];
    // ResponsePostParamsNetworkScenario[params][network_scenario][i][burst][timedown]
    if(jreq["params"]["network_scenario"][i]["burst"]["timedown"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario][%i][burst][timedown] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["burst"]["timedown"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParamsNetworkScenario[params][network_scenario][%i][burst][timedown] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.NetworkScenarioList[id].Burst.TimeDown = jreq["params"]["network_scenario"][i]["burst"]["timedown"];
  }
  // успешное завершение анализа запроса
	*code = 201;
  {
    std::lock_guard<std::mutex> lk(ParamsMutex);
    // добавить новые сетевые сценарии к старым
    Params.NetworkScenarioList.merge(params.NetworkScenarioList);
  }
	WriteParams();
  make_response(0);
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponsePutParamsNetworkScenario(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_put_params_network_scenario_ok;
  }
  else
  {
    *code = 501;
    return json_response_put_params_network_scenario_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  int i, id;
	nlohmann::json jres;
  // формирование ответа (список всех сетевых сценариев)
  auto make_response = [&](int response_code)
  {
    jres["response"]["code"] = response_code;
		jres["response"]["msg"] = "Request PUT(/params/network_scenario) processed successfully";
    jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
    jres["params"]["network_scenario"] = nlohmann::json::array();
    i = 0;
    for(auto& ns: Params.NetworkScenarioList)
    {
      jres["params"]["network_scenario"][i]["id"] = ns.second.Id;
      jres["params"]["network_scenario"][i]["name"] = ns.second.Name;
      jres["params"]["network_scenario"][i]["jitter"]["timeup"] = ns.second.Jitter.TimeUp;
      jres["params"]["network_scenario"][i]["jitter"]["timedown"] = ns.second.Jitter.TimeDown;
      jres["params"]["network_scenario"][i]["jitter"]["value"] = ns.second.Jitter.Value;
      jres["params"]["network_scenario"][i]["burst"]["timeup"] = ns.second.Burst.TimeUp;
      jres["params"]["network_scenario"][i]["burst"]["timedown"] = ns.second.Burst.TimeDown;
      ++i;
    }
  };
  GeneratorParams_s params; // временный экземпляр параметров
  PRINT_TMP(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePutParamsNetworkScenario: %s\n", reqs.c_str());
#if ELIJA_TODO // в данный момет изменение во время работы ЗАПРЕЩЕНО. в будущем можно переделать
  if(State.Run == true)
  {
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario: All parameters cannot be changed while Generator is running\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
  }
#endif
  // проверить запрос
	if(nlohmann::json::accept(reqs) == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePutParamsNetworkScenario is NOT a valid JSON\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  // разобрать запрос
  nlohmann::json jreq = nlohmann::json::parse(reqs);
  // анализ запроса (список изменяемых сетевых сценариев)
  // ResponsePutParamsNetworkScenario[params][network_scenario]
  if(jreq["params"]["network_scenario"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["network_scenario"].is_array() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario] has a wrong type (must be array)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  for(i=0; i<jreq["params"]["network_scenario"].size(); ++i)
  {
    // ResponsePutParamsNetworkScenario[params][network_scenario][i][id]
    if(jreq["params"]["network_scenario"][i]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario][%i][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario][%i][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    id = jreq["params"]["network_scenario"][i]["id"];
    params.NetworkScenarioList[id].Id = id;
    // ResponsePutParamsNetworkScenario[params][network_scenario][i][name]
    if(jreq["params"]["network_scenario"][i]["name"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario][%i][name] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["name"].is_string() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario][%i][name] has a wrong type (must be string)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.NetworkScenarioList[id].Name = jreq["params"]["network_scenario"][i]["name"];
    // ResponsePutParamsNetworkScenario[params][network_scenario][i][jitter]
    if(jreq["params"]["network_scenario"][i]["jitter"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario][%i][jitter] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["jitter"].is_object() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario][%i][jitter] has a wrong type (must be object)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    // ResponsePutParamsNetworkScenario[params][network_scenario][i][jitter][timeup]
    if(jreq["params"]["network_scenario"][i]["jitter"]["timeup"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario][%i][jitter][timeup] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["jitter"]["timeup"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario][%i][jitter][timeup] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.NetworkScenarioList[id].Jitter.TimeUp = jreq["params"]["network_scenario"][i]["jitter"]["timeup"];
    // ResponsePutParamsNetworkScenario[params][network_scenario][i][jitter][timedown]
    if(jreq["params"]["network_scenario"][i]["jitter"]["timedown"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario][%i][jitter][timedown] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["jitter"]["timedown"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario][%i][jitter][timedown] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.NetworkScenarioList[id].Jitter.TimeDown = jreq["params"]["network_scenario"][i]["jitter"]["timedown"];
    // ResponsePutParamsNetworkScenario[params][network_scenario][i][jitter][value]
    if(jreq["params"]["network_scenario"][i]["jitter"]["value"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario][%i][jitter][value] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["jitter"]["value"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario][%i][jitter][value] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.NetworkScenarioList[id].Jitter.Value = jreq["params"]["network_scenario"][i]["jitter"]["value"];
    // ResponsePutParamsNetworkScenario[params][network_scenario][i][burst]
    if(jreq["params"]["network_scenario"][i]["burst"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario][%i][burst] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["burst"].is_object() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario][%i][burst] has a wrong type (must be object)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    // ResponsePutParamsNetworkScenario[params][network_scenario][i][burst][timeup]
    if(jreq["params"]["network_scenario"][i]["burst"]["timeup"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario][%i][burst][timeup] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["burst"]["timeup"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario][%i][burst][timeup] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.NetworkScenarioList[id].Burst.TimeUp = jreq["params"]["network_scenario"][i]["burst"]["timeup"];
    // ResponsePutParamsNetworkScenario[params][network_scenario][i][burst][timedown]
    if(jreq["params"]["network_scenario"][i]["burst"]["timedown"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario][%i][burst][timedown] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["burst"]["timedown"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsNetworkScenario[params][network_scenario][%i][burst][timedown] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.NetworkScenarioList[id].Burst.TimeDown = jreq["params"]["network_scenario"][i]["burst"]["timedown"];
  }
  // успешное завершение анализа запроса
	*code = 201;
  {
    std::lock_guard<std::mutex> lk(ParamsMutex);
    // заменить параметры обновлённых пользовательских сценариев
    for(auto& ns: params.NetworkScenarioList)
    {
      Params.NetworkScenarioList[ns.second.Id] = params.NetworkScenarioList[ns.second.Id];
    }
  }
	WriteParams();
  make_response(0);
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponseDeleteParamsNetworkScenario(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_delete_params_network_scenario_ok;
  }
  else
  {
    *code = 501;
    return json_response_delete_params_network_scenario_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  int i, id;
	nlohmann::json jres;
  // формирование ответа (список всех сетевых сценариев)
  auto make_response = [&](int response_code)
  {
    jres["response"]["code"] = response_code;
		jres["response"]["msg"] = "Request DELETE(/params/network_scenario) processed successfully";
    jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
    jres["params"]["network_scenario"] = nlohmann::json::array();
    i = 0;
    for(auto& ns: Params.NetworkScenarioList)
    {
      jres["params"]["network_scenario"][i]["id"] = ns.second.Id;
      jres["params"]["network_scenario"][i]["name"] = ns.second.Name;
      jres["params"]["network_scenario"][i]["jitter"]["timeup"] = ns.second.Jitter.TimeUp;
      jres["params"]["network_scenario"][i]["jitter"]["timedown"] = ns.second.Jitter.TimeDown;
      jres["params"]["network_scenario"][i]["jitter"]["value"] = ns.second.Jitter.Value;
      jres["params"]["network_scenario"][i]["burst"]["timeup"] = ns.second.Burst.TimeUp;
      jres["params"]["network_scenario"][i]["burst"]["timedown"] = ns.second.Burst.TimeDown;
      ++i;
    }
  };
  GeneratorParams_s params; // временный экземпляр параметров
  PRINT_TMP(PRINT_LEVEL::HIGH, "NLOHMANN: ResponseDeleteParamsNetworkScenario: %s\n", reqs.c_str());
#if ELIJA_TODO // в данный момет изменение во время работы ЗАПРЕЩЕНО. в будущем можно переделать
  if(State.Run == true)
  {
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponseDeleteParamsNetworkScenario: All parameters cannot be changed while Generator is running\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
  }
#endif
  // проверить запрос
	if(nlohmann::json::accept(reqs) == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "NLOHMANN: ResponseDeleteParamsNetworkScenario is NOT a valid JSON\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  // разобрать запрос
  nlohmann::json jreq = nlohmann::json::parse(reqs);
  // анализ запроса (список удаляемых сетевых сценариев)
  // ResponseDeleteParamsNetworkScenario[params][network_scenario]
  if(jreq["params"]["network_scenario"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponseDeleteParamsNetworkScenario[params][network_scenario] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["network_scenario"].is_array() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponseDeleteParamsNetworkScenario[params][network_scenario] has a wrong type (must be array)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  for(i=0; i<jreq["params"]["network_scenario"].size(); ++i)
  {
    // ResponseDeleteParamsNetworkScenario[params][network_scenario][i][id]
    if(jreq["params"]["network_scenario"][i]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponseDeleteParamsNetworkScenario[params][network_scenario][%i][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["network_scenario"][i]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponseDeleteParamsNetworkScenario[params][network_scenario][%i][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    id = jreq["params"]["network_scenario"][i]["id"];
    params.NetworkScenarioList[id].Id = id;
#if __cplusplus > 201703L // C++20
		if(Params.NetworkScenarioList.contains(id) == false)
#else
		if(Params.NetworkScenarioList.count(id) == 0)
#endif
#if ELIJA_TODO // здесь сделать защиту от повторения id  в одном запросе? сейчас программа как-то плохо на это реагирует
#endif
		{
			PRINT_ERR(PRINT_LEVEL::HIGH, "NetworkScenario cannot be deleted because Generator has NO NetworkScenario with id=%i\n", id);
			*code = 501;
			make_response(1);
			return jres.dump(2);
		}
  }
  // успешное завершение анализа запроса
	*code = 201;
  {
    std::lock_guard<std::mutex> lk(ParamsMutex);
    // удалить пользовательские сценариии
    for(auto& ns: params.NetworkScenarioList)
    {
      Params.NetworkScenarioList.erase(ns.second.Id);
    }
  }
	WriteParams();
  make_response(0);
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponseGetParamsEb(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_get_params_eb_ok;
  }
  else
  {
    *code = 501;
    return json_response_get_params_eb_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  int i;
	nlohmann::json jres;
	jres["response"]["code"] = 0;
	jres["response"]["msg"] = "Request GET(/params/eb) processed successfully";
	jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
  jres["params"]["eb"] = nlohmann::json::array();
  i = 0;
  for(auto& eb: Params.EpsBearerList)
  {
    jres["params"]["eb"][i]["id"] = eb.second.Id;
    jres["params"]["eb"][i]["br"] = eb.second.Bitrate;
    jres["params"]["eb"][i]["user_scenario"]["id"] = eb.second.UserScenario.Id;
    if(eb.second.UserScenario.Id == 0) // отправляем эти значения только для настраиваемого пользовательского сценария
    {
      jres["params"]["eb"][i]["user_scenario"]["name"] = eb.second.UserScenario.Name;
      jres["params"]["eb"][i]["user_scenario"]["br"] = eb.second.UserScenario.Bitrate;
      jres["params"]["eb"][i]["user_scenario"]["pcap_id"] = nlohmann::json::array();
      int j = 0;
      for(auto& pcap_id: eb.second.UserScenario.Pcap)
      {
        jres["params"]["eb"][i]["user_scenario"]["pcap_id"][j] = pcap_id.first;
        ++j;
      }
    }
    jres["params"]["eb"][i]["network_scenario"]["id"] = eb.second.NetworkScenario.Id;
    if(eb.second.NetworkScenario.Id == 0) // отправляем эти значения только для настраиваемого сетевого сценария
    {
      jres["params"]["eb"][i]["network_scenario"]["name"] = eb.second.NetworkScenario.Name;
      jres["params"]["eb"][i]["network_scenario"]["jitter"]["timeup"] = eb.second.NetworkScenario.Jitter.TimeUp;
      jres["params"]["eb"][i]["network_scenario"]["jitter"]["timedown"] = eb.second.NetworkScenario.Jitter.TimeDown;
      jres["params"]["eb"][i]["network_scenario"]["jitter"]["value"] = eb.second.NetworkScenario.Jitter.Value;
      jres["params"]["eb"][i]["network_scenario"]["burst"]["timeup"] = eb.second.NetworkScenario.Burst.TimeUp;
      jres["params"]["eb"][i]["network_scenario"]["burst"]["timedown"] = eb.second.NetworkScenario.Burst.TimeDown;
    }
    ++i;
  }
	*code = 201;
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponseGetParamsEb1(const std::string& reqs, int id, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_get_params_eb_1_ok;
  }
  else
  {
    *code = 501;
    return json_response_get_params_eb_1_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
	// формирование ответа (параметры работы EpsBearer с идентификатором = id)
	nlohmann::json jres;
  jres["params"]["eb"] = nlohmann::json::array();
	int res = 1;
#if __cplusplus > 201703L // C++20
  if(Params.EpsBearerList.contains(id) == false)
#else
  if(Params.EpsBearerList.count(id) == 0)
#endif
  {
    PRINT_ERR(PRINT_LEVEL::HIGH, "ResponseGetParamsEb1[params][eb] has NO EpsBearer with id=%i (use PUT request)\n", id);
    *code = 501;
  }
  else
  {
    auto& eb = Params.EpsBearerList[id]; // EpsBearer с идентификатором = id)
    jres["params"]["eb"][0]["id"] = eb.Id;
    jres["params"]["eb"][0]["br"] = eb.Bitrate;
    jres["params"]["eb"][0]["user_scenario"]["id"] = eb.UserScenario.Id;
    if(eb.UserScenario.Id == 0) // отправляем эти значения только для настраиваемого пользовательского сценария
    {
      jres["params"]["eb"][0]["user_scenario"]["name"] = eb.UserScenario.Name;
      jres["params"]["eb"][0]["user_scenario"]["br"] = eb.UserScenario.Bitrate;
      jres["params"]["eb"][0]["user_scenario"]["pcap_id"] = nlohmann::json::array();
      int j = 0;
      for(auto& pcap_id: eb.UserScenario.Pcap)
      {
        jres["params"]["eb"][0]["user_scenario"]["pcap_id"][j] = pcap_id.first;
        ++j;
      }
    }
    jres["params"]["eb"][0]["network_scenario"]["id"] = eb.NetworkScenario.Id;
    if(eb.NetworkScenario.Id) // отправляем эти значения только для настраиваемого сетевого сценария
    {
      jres["params"]["eb"][0]["network_scenario"]["name"] = eb.NetworkScenario.Name;
      jres["params"]["eb"][0]["network_scenario"]["jitter"]["timeup"] = eb.NetworkScenario.Jitter.TimeUp;
      jres["params"]["eb"][0]["network_scenario"]["jitter"]["timedown"] = eb.NetworkScenario.Jitter.TimeDown;
      jres["params"]["eb"][0]["network_scenario"]["jitter"]["value"] = eb.NetworkScenario.Jitter.Value;
      jres["params"]["eb"][0]["network_scenario"]["burst"]["timeup"] = eb.NetworkScenario.Burst.TimeUp;
      jres["params"]["eb"][0]["network_scenario"]["burst"]["timedown"] = eb.NetworkScenario.Burst.TimeDown;
    }
    res = 0;
    *code = 201;
  }

	jres["response"]["code"] = res;
	if(res)
		jres["response"]["msg"] = "Request GET(/params/ebN) error";
	else
		jres["response"]["msg"] = "Request GET(/params/ebN) processed successfully";
	jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponsePostParamsEb(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_post_params_eb_ok;
  }
  else
  {
    *code = 501;
    return json_response_post_params_eb_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  int i, id;
	nlohmann::json jres;
  // формирование ответа
  auto make_response = [&](int response_code)
  {
    jres["response"]["code"] = response_code;
    if(response_code == 0)
      jres["response"]["msg"] = "Request POST(/params/eb) processed successfully";
    else
      jres["response"]["msg"] = "Request POST(/params/eb) error";
    jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
    jres["params"]["eb"] = nlohmann::json::array();
    i = 0;
    for(auto& eb: Params.EpsBearerList)
    {
      jres["params"]["eb"][i]["id"] = eb.second.Id;
      jres["params"]["eb"][i]["br"] = eb.second.Bitrate;
      jres["params"]["eb"][i]["user_scenario"]["id"] = eb.second.UserScenario.Id;
      if(eb.second.UserScenario.Id == 0) // отправляем эти значения только для настраиваемого пользовательского сценария
      {
        jres["params"]["eb"][i]["user_scenario"]["name"] = eb.second.UserScenario.Name;
        jres["params"]["eb"][i]["user_scenario"]["br"] = eb.second.UserScenario.Bitrate;
        jres["params"]["eb"][i]["user_scenario"]["pcap_id"] = nlohmann::json::array();
        int j = 0;
        for(auto& pcap_id: eb.second.UserScenario.Pcap)
        {
          jres["params"]["eb"][i]["user_scenario"]["pcap_id"][j] = pcap_id.first;
          ++j;
        }
      }
      jres["params"]["eb"][i]["network_scenario"]["id"] = eb.second.NetworkScenario.Id;
      if(eb.second.NetworkScenario.Id == 0) // отправляем эти значения только для настраиваемого сетевого сценария
      {
        jres["params"]["eb"][i]["network_scenario"]["name"] = eb.second.NetworkScenario.Name;
        jres["params"]["eb"][i]["network_scenario"]["jitter"]["timeup"] = eb.second.NetworkScenario.Jitter.TimeUp;
        jres["params"]["eb"][i]["network_scenario"]["jitter"]["timedown"] = eb.second.NetworkScenario.Jitter.TimeDown;
        jres["params"]["eb"][i]["network_scenario"]["jitter"]["value"] = eb.second.NetworkScenario.Jitter.Value;
        jres["params"]["eb"][i]["network_scenario"]["burst"]["timeup"] = eb.second.NetworkScenario.Burst.TimeUp;
        jres["params"]["eb"][i]["network_scenario"]["burst"]["timedown"] = eb.second.NetworkScenario.Burst.TimeDown;
      }
      ++i;
    }
  };
  GeneratorParams_s params; // временный экземпляр параметров
  PRINT_TMP(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePostParamsEb: %s\n", reqs.c_str());
	//PRINT_TMP(PRINT_LEVEL::HIGH, "NLOHMANN: %s\n", reqs.c_str());
  // проверить запрос
	if(nlohmann::json::accept(reqs) == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePostParamsEb is NOT a valid JSON\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  // разобрать запрос
  nlohmann::json jreq = nlohmann::json::parse(reqs);
  // анализ запроса
  // ResponsePostParams[params][eb]
  if(jreq["params"]["eb"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["eb"].is_array() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb] has a wrong type (must be array)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  for(i=0; i<jreq["params"]["eb"].size(); ++i)
  {
    // ResponsePostParams[params][eb][i][id]
    if(jreq["params"]["eb"][i]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    id = jreq["params"]["eb"][i]["id"];
#if __cplusplus > 201703L // C++20
		if(Params.EpsBearerList.contains(id))
#else
		if(Params.EpsBearerList.count(id))
#endif
#if ELIJA_TODO // здесь сделать защиту от повторения id  в одном запросе? сейчас программа как-то плохо на это реагирует
#endif
		{
			PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb] already has EpsBearer with id=%i (use PUT request)\n", id);
			*code = 501;
			make_response(1);
			return jres.dump(2);
		}
    params.EpsBearerList[id].Id = id;
    // ResponsePostParams[params][eb][i][br]
    if(jreq["params"]["eb"][i]["br"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][br] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["br"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][br] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.EpsBearerList[id].Bitrate = jreq["params"]["eb"][i]["br"];
    // ResponsePostParams[params][eb][i][user_scenario]
    if(jreq["params"]["eb"][i]["user_scenario"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][user_scenario] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["user_scenario"].is_object() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][user_scenario] has a wrong type (must be object)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    // ResponsePostParams[params][eb][i][user_scenario][id]
    if(jreq["params"]["eb"][i]["user_scenario"]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][user_scenario][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["user_scenario"]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][user_scenario][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.EpsBearerList[id].UserScenario.Id = jreq["params"]["eb"][i]["user_scenario"]["id"];
    if(params.EpsBearerList[id].UserScenario.Id == 0) // настраиваемый пользовательский сценарий, значит должны присутствовать все остальные элементы
    {
      // ResponsePostParams[params][eb][i][user_scenario][name]
      if(jreq["params"]["eb"][i]["user_scenario"]["name"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][user_scenario][name] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["user_scenario"]["name"].is_string() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][user_scenario][name] has a wrong type (must be string)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].UserScenario.Name = jreq["params"]["eb"][i]["user_scenario"]["name"];
      // ResponsePostParams[params][eb][i][user_scenario][br]
      if(jreq["params"]["eb"][i]["user_scenario"]["br"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][user_scenario][br] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["user_scenario"]["br"].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][user_scenario][br] has a wrong type (must be number)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].UserScenario.Bitrate = jreq["params"]["eb"][i]["user_scenario"]["br"];
      // ResponsePostParams[params][eb][i][user_scenario][pcap_id]
      if(jreq["params"]["eb"][i]["user_scenario"]["pcap_id"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][user_scenario][pcap_id] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["user_scenario"]["pcap_id"].is_array() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][user_scenario][pcap_id] has a wrong type (must be array)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      for(int j=0; j<jreq["params"]["eb"][i]["user_scenario"]["pcap_id"].size(); ++j)
      {
        // ResponsePostParams[params][eb][i][user_scenario][pcap_id][j]
        if(jreq["params"]["eb"][i]["user_scenario"]["pcap_id"][j].is_null())
        {
          PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][user_scenario][pcap_id][%i] is null\n", i, j);
          *code = 501;
          make_response(1);
          return jres.dump(2);
        }
        if(jreq["params"]["eb"][i]["user_scenario"]["pcap_id"][j].is_number() == false)
        {
          PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][user_scenario][pcap_id][%i] has a wrong type (must be number)\n", i, j);
          *code = 501;
          make_response(1);
          return jres.dump(2);
        }
				int pid = jreq["params"]["eb"][i]["user_scenario"]["pcap_id"][j];
        params.EpsBearerList[id].UserScenario.Pcap[pid] = {0};
      }
    }
    // ResponsePostParams[params][eb][i][network_scenario]
    if(jreq["params"]["eb"][i]["network_scenario"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][network_scenario] is null\n");
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["network_scenario"].is_object() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][network_scenario] has a wrong type (must be object)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    // ResponsePostParams[params][eb][i][network_scenario][id]
    if(jreq["params"]["eb"][i]["network_scenario"]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][network_scenario][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["network_scenario"]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][network_scenario][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.EpsBearerList[id].NetworkScenario.Id = jreq["params"]["eb"][i]["network_scenario"]["id"];
    if(params.EpsBearerList[id].NetworkScenario.Id == 0) // настраиваемый сетевой сценарий, значит должны присутствовать все остальные элементы
    {
      // ResponsePostParams[params][eb][i][network_scenario][name]
      if(jreq["params"]["eb"][i]["network_scenario"]["name"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][network_scenario][name] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["name"].is_string() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][network_scenario][name] has a wrong type (must be string)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].NetworkScenario.Name = jreq["params"]["eb"][i]["network_scenario"]["name"];
      // ResponsePostParams[params][eb][i][network_scenario][jitter]
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "v[params][eb][%i][network_scenario][jitter] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"].is_object() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][network_scenario][jitter] has a wrong type (must be object)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      // ResponsePostParams[params][eb][i][network_scenario][jitter][timeup]
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"]["timeup"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][network_scenario][jitter][timeup] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"]["timeup"].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][network_scenario][jitter][timeup] has a wrong type (must be number)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].NetworkScenario.Jitter.TimeUp = jreq["params"]["eb"][i]["network_scenario"]["jitter"]["timeup"];
      // ResponsePostParams[params][eb][i][network_scenario][jitter][timedown]
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"]["timedown"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][network_scenario][jitter][timedown] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"]["timedown"].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][network_scenario][jitter][timedown] has a wrong type (must be number)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].NetworkScenario.Jitter.TimeDown = jreq["params"]["eb"][i]["network_scenario"]["jitter"]["timedown"];
      // ResponsePostParams[params][eb"[i][network_scenario][jitter][value]
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"]["value"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][network_scenario][jitter][value] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"]["value"].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][network_scenario][jitter][value] has a wrong type (must be number)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].NetworkScenario.Jitter.Value = jreq["params"]["eb"][i]["network_scenario"]["jitter"]["value"];
      // ResponsePostParams[params][eb][i][network_scenario][burst]
      if(jreq["params"]["eb"][i]["network_scenario"]["burst"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][network_scenario][burst] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["burst"].is_object() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][network_scenario][burst] has a wrong type (must be object)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      // ResponsePostParams[params][eb][i][network_scenario][burst][timeup]
      if(jreq["params"]["eb"][i]["network_scenario"]["burst"]["timeup"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][network_scenario][burst][timeup] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["burst"]["timeup"].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][network_scenario][burst][timeup] has a wrong type (must be number)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].NetworkScenario.Burst.TimeUp = jreq["params"]["eb"][i]["network_scenario"]["burst"]["timeup"];
      // ResponsePostParams[params][eb][i][network_scenario][burst][timedown]
      if(jreq["params"]["eb"][i]["network_scenario"]["burst"]["timedown"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][network_scenario][burst][timedown] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["burst"]["timedown"].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePostParams[params][eb][%i][network_scenario][burst][timedown] has a wrong type (must be number)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].NetworkScenario.Burst.TimeDown = jreq["params"]["eb"][i]["network_scenario"]["burst"]["timedown"];
    }
}
  // успешное завершение анализа запроса
	*code = 201;
	// если Ядро ГТО работает, то добавляем новые EpsBearer в работу,
	// если же Ядро ГТО остановлено, то это нелать не нужно, поскольку это выполнится при запуске в работу
	if(State.Run == true)
	{
		if(AddEpsBearer(params.EpsBearerList) == false)
		{
			PRINT_ERR(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePostParamsEb Generator cannot add EpsBearer\n");
			*code = 501;
			make_response(1);
			return jres.dump(2);
		}
	}
  {
    std::lock_guard<std::mutex> lk(ParamsMutex);
    // добавить параметры работы новых EpsBearer ко всем остальным EpsBearer
    Params.EpsBearerList.merge(params.EpsBearerList);
  }
	WriteParams();
  make_response(0);
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponsePutParamsEb(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_put_params_eb_ok;
  }
  else
  {
    *code = 501;
    return json_response_put_params_eb_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  int i, id;
	nlohmann::json jres;
  // формирование ответа (список всех Eps-Bearer)
  auto make_response = [&](int response_code)
  {
    jres["response"]["code"] = response_code;
		jres["response"]["msg"] = "Request PUT(/params/eb) processed successfully";
    jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
    jres["params"]["eb"] = nlohmann::json::array();
    i = 0;
    for(auto& eb: Params.EpsBearerList)
    {
      jres["params"]["eb"][i]["id"] = eb.second.Id;
      jres["params"]["eb"][i]["br"] = eb.second.Bitrate;
      jres["params"]["eb"][i]["user_scenario"]["id"] = eb.second.UserScenario.Id;
      if(eb.second.UserScenario.Id == 0) // отправляем эти значения только для настраиваемого пользовательского сценария
      {
        jres["params"]["eb"][i]["user_scenario"]["name"] = eb.second.UserScenario.Name;
        jres["params"]["eb"][i]["user_scenario"]["br"] = eb.second.UserScenario.Bitrate;
        jres["params"]["eb"][i]["user_scenario"]["pcap_id"] = nlohmann::json::array();
        int j = 0;
        for(auto& pcap_id: eb.second.UserScenario.Pcap)
        {
          jres["params"]["eb"][i]["user_scenario"]["pcap_id"][j] = pcap_id.first;
          ++j;
        }
      }
      jres["params"]["eb"][i]["network_scenario"]["id"] = eb.second.NetworkScenario.Id;
      if(eb.second.NetworkScenario.Id == 0) // отправляем эти значения только для настраиваемого сетевого сценария
      {
        jres["params"]["eb"][i]["network_scenario"]["name"] = eb.second.NetworkScenario.Name;
        jres["params"]["eb"][i]["network_scenario"]["jitter"]["timeup"] = eb.second.NetworkScenario.Jitter.TimeUp;
        jres["params"]["eb"][i]["network_scenario"]["jitter"]["timedown"] = eb.second.NetworkScenario.Jitter.TimeDown;
        jres["params"]["eb"][i]["network_scenario"]["jitter"]["value"] = eb.second.NetworkScenario.Jitter.Value;
        jres["params"]["eb"][i]["network_scenario"]["burst"]["timeup"] = eb.second.NetworkScenario.Burst.TimeUp;
        jres["params"]["eb"][i]["network_scenario"]["burst"]["timedown"] = eb.second.NetworkScenario.Burst.TimeDown;
      }
      ++i;
    }
  };
  GeneratorParams_s params; // временный экземпляр параметров
  PRINT_TMP(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePutParamsEb: %s\n", reqs.c_str());
  // проверить запрос
	if(nlohmann::json::accept(reqs) == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePutParamsEb is NOT a valid JSON\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  // разобрать запрос
  nlohmann::json jreq = nlohmann::json::parse(reqs);
  // анализ запроса (список создаваемых Eps-Bearer)
  // ResponsePutParamsEb[params][eb]
  if(jreq["params"]["eb"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["eb"].is_array() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb] has a wrong type (must be array)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  for(i=0; i<jreq["params"]["eb"].size(); ++i)
  {
    // ResponsePutParamsEb[params][eb][i][id]
    if(jreq["params"]["eb"][i]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    id = jreq["params"]["eb"][i]["id"];
#if __cplusplus > 201703L // C++20
		if(Params.EpsBearerList.contains(id) == false)
#else
		if(Params.EpsBearerList.count(id) == 0)
#endif
#if ELIJA_TODO // здесь сделать защиту от повторения id  в одном запросе? сейчас программа как-то плохо на это реагирует
#endif
		{
			PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb] has NO EpsBearer with id=%i (use POST request)\n", id);
			*code = 501;
			make_response(1);
			return jres.dump(2);
		}
    params.EpsBearerList[id].Id = id;
    // ResponsePutParamsEb[params][eb][i][br]
    if(jreq["params"]["eb"][i]["br"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][br] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["br"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][br] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.EpsBearerList[id].Bitrate = jreq["params"]["eb"][i]["br"];
    // ResponsePutParamsEb[params][eb][i][user_scenario]
    if(jreq["params"]["eb"][i]["user_scenario"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][user_scenario] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["user_scenario"].is_object() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][user_scenario] has a wrong type (must be object)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    // ResponsePutParamsEb[params][eb][i][user_scenario][id]
    if(jreq["params"]["eb"][i]["user_scenario"]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][user_scenario][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["user_scenario"]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][user_scenario][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.EpsBearerList[id].UserScenario.Id = jreq["params"]["eb"][i]["user_scenario"]["id"];
    if(params.EpsBearerList[id].UserScenario.Id == 0) // настраиваемый пользовательский сценарий, значит должны присутствовать все остальные элементы
    {
      // ResponsePutParamsEb[params][eb][i][user_scenario][name]
      if(jreq["params"]["eb"][i]["user_scenario"]["name"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][user_scenario][name] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["user_scenario"]["name"].is_string() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][user_scenario][name] has a wrong type (must be string)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].UserScenario.Name = jreq["params"]["eb"][i]["user_scenario"]["name"];
      // ResponsePutParamsEb[params][eb][i][user_scenario][br]
      if(jreq["params"]["eb"][i]["user_scenario"]["br"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][user_scenario][br] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["user_scenario"]["br"].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][user_scenario][br] has a wrong type (must be number)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].UserScenario.Bitrate = jreq["params"]["eb"][i]["user_scenario"]["br"];
      // ResponsePutParamsEb[params][eb][i][user_scenario][pcap_id]
      if(jreq["params"]["eb"][i]["user_scenario"]["pcap_id"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][user_scenario][pcap_id] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["user_scenario"]["pcap_id"].is_array() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][user_scenario][pcap_id] has a wrong type (must be array)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      for(int j=0; j<jreq["params"]["eb"][i]["user_scenario"]["pcap_id"].size(); ++j)
      {
        // ResponsePutParamsEb[params][eb][i][user_scenario][pcap_id][j]
        if(jreq["params"]["eb"][i]["user_scenario"]["pcap_id"][j].is_null())
        {
          PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][user_scenario][pcap_id][%i] is null\n", i, j);
          *code = 501;
          make_response(1);
          return jres.dump(2);
        }
        if(jreq["params"]["eb"][i]["user_scenario"]["pcap_id"][j].is_number() == false)
        {
          PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][user_scenario][pcap_id][%i] has a wrong type (must be number)\n", i, j);
          *code = 501;
          make_response(1);
          return jres.dump(2);
        }
				int pid = jreq["params"]["eb"][i]["user_scenario"]["pcap_id"][j];
        params.EpsBearerList[id].UserScenario.Pcap[pid] = {0};
      }
    }
    // ResponsePutParamsEb[params][eb][i][network_scenario]
    if(jreq["params"]["eb"][i]["network_scenario"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][network_scenario] is null\n");
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["network_scenario"].is_object() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario] has a wrong type (must be object)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    // ResponsePutParamsEb[params][eb][i][network_scenario][id]
    if(jreq["params"]["eb"][i]["network_scenario"]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["network_scenario"]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    params.EpsBearerList[id].NetworkScenario.Id = jreq["params"]["eb"][i]["network_scenario"]["id"];
    if(params.EpsBearerList[id].NetworkScenario.Id == 0) // настраиваемый сетевой сценарий, значит должны присутствовать все остальные элементы
    {
      // ResponsePutParamsEb[params][eb][i][network_scenario][name]
      if(jreq["params"]["eb"][i]["network_scenario"]["name"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario][name] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["name"].is_string() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario][name] has a wrong type (must be string)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].NetworkScenario.Name = jreq["params"]["eb"][i]["network_scenario"]["name"];
      // ResponsePutParamsEb[params][eb][i][network_scenario][jitter]
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario][jitter] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"].is_object() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario][jitter] has a wrong type (must be object)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      // ResponsePutParamsEb[params][eb][i][network_scenario][jitter][timeup]
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"]["timeup"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario][jitter][timeup] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"]["timeup"].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario][jitter][timeup] has a wrong type (must be number)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].NetworkScenario.Jitter.TimeUp = jreq["params"]["eb"][i]["network_scenario"]["jitter"]["timeup"];
      // ResponsePutParamsEb[params][eb][i][network_scenario][jitter][timedown]
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"]["timedown"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario][jitter][timedown] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"]["timedown"].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario][jitter][timedown] has a wrong type (must be number)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].NetworkScenario.Jitter.TimeDown = jreq["params"]["eb"][i]["network_scenario"]["jitter"]["timedown"];
      // ResponsePutParamsEb[params][eb"[i][network_scenario][jitter][value]
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"]["value"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario][jitter][value] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["jitter"]["value"].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario][jitter][value] has a wrong type (must be number)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].NetworkScenario.Jitter.Value = jreq["params"]["eb"][i]["network_scenario"]["jitter"]["value"];
      // ResponsePutParamsEb[params][eb][i][network_scenario][burst]
      if(jreq["params"]["eb"][i]["network_scenario"]["burst"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario][burst] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["burst"].is_object() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario][burst] has a wrong type (must be object)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      // ResponsePutParamsEb[params][eb][i][network_scenario][burst][timeup]
      if(jreq["params"]["eb"][i]["network_scenario"]["burst"]["timeup"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario][burst][timeup] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["burst"]["timeup"].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario][burst][timeup] has a wrong type (must be number)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].NetworkScenario.Burst.TimeUp = jreq["params"]["eb"][i]["network_scenario"]["burst"]["timeup"];
      // ResponsePutParamsEb[params][eb][i][network_scenario][burst][timedown]
      if(jreq["params"]["eb"][i]["network_scenario"]["burst"]["timedown"].is_null())
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario][burst][timedown] is null\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      if(jreq["params"]["eb"][i]["network_scenario"]["burst"]["timedown"].is_number() == false)
      {
        PRINT_ERR(PRINT_LEVEL::HIGH, "ResponsePutParamsEb[params][eb][%i][network_scenario][burst][timedown] has a wrong type (must be number)\n", i);
        *code = 501;
        make_response(1);
        return jres.dump(2);
      }
      params.EpsBearerList[id].NetworkScenario.Burst.TimeDown = jreq["params"]["eb"][i]["network_scenario"]["burst"]["timedown"];
    }
  }
  // успешное завершение анализа запроса
	*code = 201;
	// если Ядро ГТО работает, то изменяем EpsBearer в процессе работы,
	// если же Ядро ГТО остановлено, то это делать не нужно, поскольку это выполнится при запуске в работу
	//PRINT_TMP(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePutParamsEb before State.Run = %i\n", State.Run);
	if(State.Run == true)
	{
		if(AddEpsBearer(params.EpsBearerList) == false)
		{
			PRINT_ERR(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePutParamsEb Generator cannot add EpsBearer\n");
			*code = 501;
			make_response(1);
			return jres.dump(2);
		}
	}
	//PRINT_TMP(PRINT_LEVEL::HIGH, "NLOHMANN: ResponsePutParamsEb after State.Run = %i\n", State.Run);
  {
    std::lock_guard<std::mutex> lk(ParamsMutex);
    // заменить параметры работы обновлённых EpsBearer
    for(auto& ebp: params.EpsBearerList)
    {
      Params.EpsBearerList[ebp.second.Id] = params.EpsBearerList[ebp.second.Id];
    }
  }
	WriteParams();
  make_response(0);
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
std::string GeneratorApp_c::ResponseDeleteParamsEb(const std::string& reqs, int* code)
{
#if USE_FAKE_HTTP_RESPONSE
  static bool tmp = false;
  tmp = !tmp;
  if(tmp)
  {
    *code = 201;
    return json_response_delete_params_eb_ok;
  }
  else
  {
    *code = 501;
    return json_response_delete_params_eb_err;
  }
#else
#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  int i, id;
	nlohmann::json jres;
  // формирование ответа (список всех Eps-Bearer)
  auto make_response = [&](int response_code)
  {
    jres["response"]["code"] = response_code;
		jres["response"]["msg"] = "Request DELETE(/params/eb) processed successfully";
    jres["response"]["time"] = DateTime::GetEpochTimeStringHTP();
    jres["params"]["eb"] = nlohmann::json::array();
    i = 0;
    for(auto& eb: Params.EpsBearerList)
    {
      jres["params"]["eb"][i]["id"] = eb.second.Id;
      jres["params"]["eb"][i]["br"] = eb.second.Bitrate;
      jres["params"]["eb"][i]["user_scenario"]["id"] = eb.second.UserScenario.Id;
      if(eb.second.UserScenario.Id == 0) // отправляем эти значения только для настраиваемого пользовательского сценария
      {
        jres["params"]["eb"][i]["user_scenario"]["name"] = eb.second.UserScenario.Name;
        jres["params"]["eb"][i]["user_scenario"]["br"] = eb.second.UserScenario.Bitrate;
        jres["params"]["eb"][i]["user_scenario"]["pcap_id"] = nlohmann::json::array();
        int j = 0;
        for(auto& pcap_id: eb.second.UserScenario.Pcap)
        {
          jres["params"]["eb"][i]["user_scenario"]["pcap_id"][j] = pcap_id.first;
          ++j;
        }
      }
      jres["params"]["eb"][i]["network_scenario"]["id"] = eb.second.NetworkScenario.Id;
      if(eb.second.NetworkScenario.Id == 0) // отправляем эти значения только для настраиваемого сетевого сценария
      {
        jres["params"]["eb"][i]["network_scenario"]["name"] = eb.second.NetworkScenario.Name;
        jres["params"]["eb"][i]["network_scenario"]["jitter"]["timeup"] = eb.second.NetworkScenario.Jitter.TimeUp;
        jres["params"]["eb"][i]["network_scenario"]["jitter"]["timedown"] = eb.second.NetworkScenario.Jitter.TimeDown;
        jres["params"]["eb"][i]["network_scenario"]["jitter"]["value"] = eb.second.NetworkScenario.Jitter.Value;
        jres["params"]["eb"][i]["network_scenario"]["burst"]["timeup"] = eb.second.NetworkScenario.Burst.TimeUp;
        jres["params"]["eb"][i]["network_scenario"]["burst"]["timedown"] = eb.second.NetworkScenario.Burst.TimeDown;
      }
      ++i;
    }
  };
  GeneratorParams_s params; // временный экземпляр параметров
  PRINT_TMP(PRINT_LEVEL::HIGH, "NLOHMANN: ResponseDeleteParamsEb: %s\n", reqs.c_str());
  // проверить запрос
	if(nlohmann::json::accept(reqs) == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "NLOHMANN: ResponseDeleteParamsEb is NOT a valid JSON\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  // разобрать запрос
  nlohmann::json jreq = nlohmann::json::parse(reqs);
  // анализ запроса (список удаляемых Eps-Bearer)
  // ResponseDeleteParamsEb[params][eb]
  if(jreq["params"]["eb"].is_null())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponseDeleteParamsEb[params][eb] is null\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  if(jreq["params"]["eb"].is_array() == false)
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "ResponseDeleteParamsEb[params][eb] has a wrong type (must be array)\n");
		*code = 501;
    make_response(1);
		return jres.dump(2);
	}
  for(i=0; i<jreq["params"]["eb"].size(); ++i)
  {
    // ResponseDeleteParamsEb[params][eb][i][id]
    if(jreq["params"]["eb"][i]["id"].is_null())
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponseDeleteParamsEb[params][eb][%i][id] is null\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    if(jreq["params"]["eb"][i]["id"].is_number() == false)
    {
      PRINT_ERR(PRINT_LEVEL::HIGH, "ResponseDeleteParamsEb[params][eb][%i][id] has a wrong type (must be number)\n", i);
      *code = 501;
      make_response(1);
      return jres.dump(2);
    }
    id = jreq["params"]["eb"][i]["id"];
    params.EpsBearerList[id].Id = id;
#if __cplusplus > 201703L // C++20
		if(Params.EpsBearerList.contains(id) == false)
#else
		if(Params.EpsBearerList.count(id) == 0)
#endif
#if ELIJA_TODO // здесь сделать защиту от повторения id  в одном запросе? сейчас программа как-то плохо на это реагирует
#endif
		{
			PRINT_ERR(PRINT_LEVEL::HIGH, "EpsBearer cannot be deleted because Generator has NO EpsBearer with id=%i\n", id);
			*code = 501;
			make_response(1);
			return jres.dump(2);
		}
  }
  // успешное завершение анализа запроса
	*code = 201;
  {
    std::lock_guard<std::mutex> lk(ParamsMutex);
    // удалить параметры работы EpsBearer
    // цикл по всем EpsBearer
    for(auto& epair: params.EpsBearerList)
    {
      int eid = epair.first;
      GeneratorParams_s::EpsBearer_s& eparams = epair.second;

      Params.EpsBearerList.erase(eid);
    }
  }
	WriteParams();
  make_response(0);
	return jres.dump(2);
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif
#endif
}

//------------------------------------------------------------------------------
bool GeneratorApp_c::AddEpsBearer(std::map<int, GeneratorParams_s::EpsBearer_s>& elist)
{
	// цикл по всем EpsBearer
	for(auto& epair: elist)
	{
		int eid = epair.first;
		GeneratorParams_s::EpsBearer_s& eparams = epair.second;

		// если это не настраиваемый пользовательский сценарий, а из списка
		if(eparams.UserScenario.Id)
		{
			// проверить существует ли такой сценарий в списке
#if __cplusplus > 201703L // C++20
			if(Params.UserScenarioList.contains(eparams.UserScenario.Id) == false)
#else
			if(Params.UserScenarioList.count(eparams.UserScenario.Id) == 0)
#endif
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "EpsBearer refers to a non-existing User scenario (id=%i)\n", eparams.UserScenario.Id);
				return false;
			}
			eparams.UserScenario = Params.UserScenarioList[eparams.UserScenario.Id];
		}
		// если это не настраиваемый сетевой сценарий, а из списка
		if(eparams.NetworkScenario.Id)
		{
			// проверить существует ли такой сценарий в списке
#if __cplusplus > 201703L // C++20
			if(Params.NetworkScenarioList.contains(eparams.NetworkScenario.Id) == false)
#else
			if(Params.NetworkScenarioList.count(eparams.NetworkScenario.Id) == 0)
#endif
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "EpsBearer refers to a non-existing Network scenario (id=%i)\n", eparams.NetworkScenario.Id);
				return false;
			}
			eparams.NetworkScenario = Params.NetworkScenarioList[eparams.NetworkScenario.Id];
		}
		// цикл по всем PCAP файла перечисленным в пользовательском сценарии для данного EpsBearer
		for(auto& ppair: eparams.UserScenario.Pcap)
		{
			int pid = ppair.first;
			GeneratorParams_s::Pcap_s& pparams = ppair.second;

			// PCAP файл должен быть перечислен в списке доступных PCAP файлов
#if __cplusplus > 201703L // C++20
			if(Params.PcapList.contains(pid) == false)
#else
			if(Params.PcapList.count(pid) == 0)
#endif
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "User scenario of EpsBearer refers to a non-existing PCAP file (id=%i)\n", pid);
				return false;
			}
      pparams = Params.PcapList[pid];
			// создать экземпляр PcapReader_c в качестве интерфейса для работы с данным PCAP файлом
			pparams.PcapReader = std::make_shared<PcapReader_c>(Params, pparams, eparams);
			if(pparams.PcapReader->Open() == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "EpsBearer cannot open the PCAP file %s\n", pparams.Path.c_str());
				pparams.PcapReader->Close();
				return false;
			}

			// получить пакет из PCAP файла
			auto pkt = pparams.PcapReader->GetPacket();
			if(pkt == nullptr)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "EpsBearer received a null packet from PCAP file %s\n",pparams.Path.c_str());
				return false;
			}
			// добавить полученный пакет в очередь пакетов EpsBearer в соответствии с его временной меткой
			uint64_t pkt_ts = pkt->Timestamp;
      {
        std::lock_guard<std::mutex> lk(PacketsMutex);
        auto p = Packets.begin();
        while(p != Packets.end())
        {
          if(p->get()->Timestamp >= pkt_ts)
            break;
          p++;
        }
        Packets.insert(p, pkt);
      }
			//PRINT_TMP(PRINT_LEVEL::HIGH, "%p:%llu EpsBearer_c::Create() insert size=%i\n", this, DateTime::GetAppTimeMicrosecCount(), (int)Packets.size());
		}
	}
  return true;
}

//------------------------------------------------------------------------------
bool GeneratorApp_c::Start()
{
	StopFlag = false;

	if(AddEpsBearer(Params.EpsBearerList) == false)
		return false;

#if ELIJA_TODO // нужно подумать как вычислять правильно: параметр интерфейса или вычисляемое значение или std::thread::hardware_concurrency()
	ReadPacketThreadsNum = std::thread::hardware_concurrency() - 4;
  ReadPacketThreadsNum = ReadPacketThreadsNum < 2 ? 2 : ReadPacketThreadsNum;
  ReadPacketThreadsNum = 1;
  PRINT_TMP(PRINT_LEVEL::MIDDLE, "ReadPacketThreadsNum = %i\n", ReadPacketThreadsNum);
	for(int i=0; i<ReadPacketThreadsNum; ++i)
#endif
	{
		ReadPacketThreads.emplace_back(std::thread(&GeneratorApp_c::ReadPacket, this, i));
	}
	///////////////////////////
  // создать отправку пакетов для всех EPS-Bearer
  Sender = std::make_shared<PacketSender_c>();
  // настроить отправку пакетов для всех EPS-Bearer
  if(Sender->Open(Params, [this]() { return GetPacket(); }) == false)
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "GeneratorApp cannot open PacketSender \n");
    Sender->Close();
    Sender.reset();
		return false;
  }
#if USE_SYNCHRO_OPTION == USE_SYNCHRO_MUTEX
#if USE_ONLY_READ
  ReadPacketFlag = true;
#endif
  GetPacketFlag = true;
  //GetPacketCv.notify_one();
#elif USE_SYNCHRO_OPTION == USE_SYNCHRO_ATOMIC
#elif USE_SYNCHRO_OPTION == USE_SYNCHRO_SEMAPHORE
#endif
	return true;
}

//------------------------------------------------------------------------------
bool GeneratorApp_c::Stop()
{
	StopFlag = true;
  ReadPacketFlag = true;
	//ReadPacketCv.notify_all();
  GetPacketFlag = true;
	//GetPacketCv.notify_all();

  Sender.reset();

	for(auto& thr: ReadPacketThreads)
	{
		if(thr.joinable())
			thr.join();
	}

  return true;
}

//------------------------------------------------------------------------------
bool GeneratorApp_c::ReadParams()
{
  std::lock_guard<std::mutex> lk(ParamsFileMutex);

#if USE_JSON_OPTION == USE_JSON_NLOHMANN
  std::ifstream ifs(ParamsFilePath);
  if(ifs.is_open() == false)
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "Cannot open for reading the parameters file %s\n", ParamsFilePath.c_str());
    return false;
  }
  PRINT_TMP(PRINT_LEVEL::MIDDLE, "The parameters file %s has been opened for reading\n", ParamsFilePath.c_str());

	if(!nlohmann::json::accept(ifs))
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s is NOT a valid JSON\n", ParamsFilePath.c_str());
    return false;
  }
	ifs.seekg(0);
  PRINT_TMP(PRINT_LEVEL::MIDDLE, "The parameters file %s is a valid JSON \n", ParamsFilePath.c_str());

	// разобрать JSON файл с параметрами работы Генератора
  nlohmann::json jf = nlohmann::json::parse(ifs);
  PRINT_TMP(PRINT_LEVEL::MIDDLE, "The parameters file %s has been parsed\n", ParamsFilePath.c_str());

	// проверить наличие элемента params
  if (jf.contains("params") == false)
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params\" key\n", ParamsFilePath.c_str());
    return false;
  }

	// элемент params
  auto jparams = jf["params"];
	// проверить соответствие типа
	if(jparams.is_object() == false)
	{
		PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params\" has a wrong type (required = object)\n");
		return false;
	}
	PRINT_TMP(PRINT_LEVEL::MIDDLE, "key: params, type: object\n");
	// проверить наличие всех обязательных элементов внутри params
  if (jparams.contains("mode") == false)
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.mode\" key\n", ParamsFilePath.c_str());
    return false;
  }
  if (jparams.contains("br") == false)
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.br\" key\n", ParamsFilePath.c_str());
    return false;
  }
  if (jparams.contains("file") == false)
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.file\" key\n", ParamsFilePath.c_str());
    return false;
  }
  if (jparams.contains("gtp") == false)
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.gtp\" key\n", ParamsFilePath.c_str());
    return false;
  }
  if (jparams.contains("service") == false)
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.service\" key\n", ParamsFilePath.c_str());
    return false;
  }
  if (jparams.contains("app") == false)
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.app\" key\n", ParamsFilePath.c_str());
    return false;
  }
  if (jparams.contains("pcap") == false)
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.pcap\" key\n", ParamsFilePath.c_str());
    return false;
  }
  if (jparams.contains("user_scenario") == false)
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.user_scenario\" key\n", ParamsFilePath.c_str());
    return false;
  }
  if (jparams.contains("network_scenario") == false)
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.network_scenario\" key\n", ParamsFilePath.c_str());
    return false;
  }

	// цикл по всем элементам params
  for(auto& jparams1 : jparams.items())
  {
		if(jparams1.key() == "mode") // элемент params.mode
		{
			auto jmode = jparams["mode"];
			// проверить соответствие типа
			if(jmode.is_number() == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.mode\" has a wrong type (required = number)\n");
				return false;
			}
			Params.Mode = jmode.get<int>();
			PRINT_TMP(PRINT_LEVEL::MIDDLE, "  key: %s, type: number, value: %i\n", jparams1.key().c_str(), Params.Mode);
			// проверить корректность считанного значения
			if(Params.Mode < 0 ||Params.Mode > 1)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.mode\" is out of range (current = %i, required = [0, 1])\n", Params.Mode);
				return false;
			}
		}
		else if(jparams1.key() == "br") // элемент params.br
		{
			auto jbr = jparams["br"];
			// проверить соответствие типа
			if(jbr.is_number() == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.br\" has a wrong type (required = number)\n");
				return false;
			}
			Params.Bitrate = jbr.get<size_t>();
			PRINT_TMP(PRINT_LEVEL::MIDDLE, "  key: %s, type: number, value: %llu\n", jparams1.key().c_str(), Params.Bitrate);
			// проверить корректность считанного значения
			if(Params.Bitrate < 0 ||Params.Bitrate > 50000000000)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.br\" is out of range (current = %llu, required = [0, 50000000000])\n", Params.Bitrate);
				return false;
			}
		}
		else if(jparams1.key() == "ipsrc") // элемент params.ipsrc
		{
			auto jipsrc = jparams["ipsrc"];
			// проверить соответствие типа
			if(jipsrc.is_string() == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.ipsrc\" has a wrong type (required = string)\n");
				return false;
			}
			Params.IpSrc = jipsrc.get<std::string>();
			PRINT_TMP(PRINT_LEVEL::MIDDLE, "  key: %s, type: string, value: %s\n", jparams1.key().c_str(), Params.IpSrc.c_str());
#if ! ELIJA_TODO // какую проверку здесь выполнять?
			if(Params.IpSrc ?)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.ipsrc\" is ? (current = %s)\n", Params.IpSrc.c_str());
				return false;
			}
#endif
		}
		else if(jparams1.key() == "ipdst") // элемент params.ipdst
		{
			auto jipdst = jparams["ipdst"];
			// проверить соответствие типа
			if(jipdst.is_string() == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.ipdst\" has a wrong type (required = string)\n");
				return false;
			}
			Params.IpDst = jipdst.get<std::string>();
			PRINT_TMP(PRINT_LEVEL::MIDDLE, "  key: %s, type: string, value: %s\n", jparams1.key().c_str(), Params.IpDst.c_str());
#if ! ELIJA_TODO // какую проверку здесь выполнять?
			if(Params.IpDst ?)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.ipdst\" is ? (current = %s)\n", Params.IpDst.c_str());
				return false;
			}
#endif
		}
		else if(jparams1.key() == "file") // элемент params.file
		{
			auto jfile = jparams["file"];
			// проверить соответствие типа
			if(jfile.is_object() == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.file\" has a wrong type (required = object)\n");
				return false;
			}
			PRINT_TMP(PRINT_LEVEL::MIDDLE, "  key: %s, type: object\n", jparams1.key().c_str());
			// проверить наличие всех обязательных элементов внутри params.file
			if (jfile.contains("path") == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.file.path\" key\n", ParamsFilePath.c_str());
				return false;
			}
			if (jfile.contains("size") == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.file.size\" key\n", ParamsFilePath.c_str());
				return false;
			}
			// цикл по всем элементам params.file
			for(auto& jfile1 : jfile.items())
			{
				if(jfile1.key() == "path") // элемент params.file.path
				{
					auto jpath = jfile["path"];
					// проверить соответствие типа
					if(jpath.is_string() == false)
					{
						PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.file.path\" has a wrong type (required = string)\n");
						return false;
					}
					Params.File.Path = jpath.get<std::string>();
					PRINT_TMP(PRINT_LEVEL::MIDDLE, "    key: %s, type: string, value: %s\n", jfile1.key().c_str(), Params.File.Path.c_str());
#if ! ELIJA_TODO // какую проверку здесь выполнять? может проверять открытие файла по указанному пути?
					// проверить корректность считанного значения
					if(Params.File.Path ?)
					{
						PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.file.path\" is ? (current = %s\n", Params.File.Path);
						return false;
					}
#endif
				}
				else if(jfile1.key() == "size") // элемент params.file.size
				{
					auto jsize = jfile["size"];
					// проверить соответствие типа
					if(jsize.is_number() == false)
					{
						PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.file.size\" has a wrong type (required = number)\n");
						return false;
					}
					Params.File.Size = jsize.get<unsigned int>();
					PRINT_TMP(PRINT_LEVEL::MIDDLE, "    key: %s, type: number, value: %i\n", jfile1.key().c_str(), Params.File.Size);
					if(Params.File.Size < 10 ||Params.File.Size > 10000)
					{
						PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.file.size\" is out of range (current = %llu, required = [10, 10000])\n", Params.Bitrate);
						return false;
					}
				}
			}
		}
		else if(jparams1.key() == "gtp") // элемент params.gtp
		{
			auto jgtp = jparams["gtp"];
			// проверить соответствие типа
			if(jgtp.is_object() == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.gtp\" has a wrong type (required = object)\n");
				return false;
			}
			PRINT_TMP(PRINT_LEVEL::MIDDLE, "  key: %s, type: object\n", jparams1.key().c_str());
			// проверить наличие всех обязательных элементов внутри params.file
			if (jgtp.contains("use") == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.gtp.use\" key\n", ParamsFilePath.c_str());
				return false;
			}
			if (jgtp.contains("ipsrc") == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.gtp.ipsrc\" key\n", ParamsFilePath.c_str());
				return false;
			}
			if (jgtp.contains("ipdst") == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.gtp.ipdst\" key\n", ParamsFilePath.c_str());
				return false;
			}
			if (jgtp.contains("minteid") == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.gtp.minteid\" key\n", ParamsFilePath.c_str());
				return false;
			}
			if (jgtp.contains("maxteid") == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.gtp.maxteid\" key\n", ParamsFilePath.c_str());
				return false;
			}
			// цикл по всем элементам params.gtp
			for(auto& jgtp1 : jgtp.items())
			{
				if(jgtp1.key() == "use") // элемент params.gtp.use
				{
					auto juse = jgtp["use"];
					// проверить соответствие типа
					if(juse.is_boolean() == false)
					{
						PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.gtp.use\" has a wrong type (required = boolean)\n");
						return false;
					}
					Params.Gtp.Use = juse.get<bool>();
					PRINT_TMP(PRINT_LEVEL::MIDDLE, "    key: %s, type: boolean, value: %i\n", jgtp1.key().c_str(), Params.Gtp.Use);
#if ! ELIJA_TODO // какую проверку здесь выполнять?
					// проверить корректность считанного значения
					if(Params.Gtp.Use ?)
					{
						PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.gtp.use\" is ? (current = %s\n", Params.Gtp.Use);
						return false;
					}
#endif
				}
				else if(jgtp1.key() == "ipsrc") // элемент params.gtp.ipsrc
				{
					auto jipsrc = jgtp["ipsrc"];
					// проверить соответствие типа
					if(jipsrc.is_string() == false)
					{
						PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.gtp.ipsrc\" has a wrong type (required = string)\n");
						return false;
					}
					Params.Gtp.IpSrc = jipsrc.get<std::string>();
					PRINT_TMP(PRINT_LEVEL::MIDDLE, "    key: %s, type: string, value: %s\n", jgtp1.key().c_str(), Params.Gtp.IpSrc.c_str());
#if ! ELIJA_TODO // какую проверку здесь выполнять?
					// проверить корректность считанного значения
					if(Params.Gtp.IpSrc ?)
					{
						PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.gtp.use\" is ? (current = %s\n", Params.Gtp.IpSrc.c_str());
						return false;
					}
#endif
				}
				else if(jgtp1.key() == "ipdst") // элемент params.gtp.ipdst
				{
					auto jipdst = jgtp["ipdst"];
					// проверить соответствие типа
					if(jipdst.is_string() == false)
					{
						PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.gtp.ipdst\" has a wrong type (required = string)\n");
						return false;
					}
					Params.Gtp.IpDst = jipdst.get<std::string>();
					PRINT_TMP(PRINT_LEVEL::MIDDLE, "    key: %s, type: string, value: %s\n", jgtp1.key().c_str(), Params.Gtp.IpDst.c_str());
#if ! ELIJA_TODO // какую проверку здесь выполнять?
					// проверить корректность считанного значения
					if(Params.Gtp.IpDst ?)
					{
						PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.gtp.ipdst\" is ? (current = %s\n", Params.Gtp.IpDst.c_str();
						return false;
					}
#endif
				}
				else if(jgtp1.key() == "minteid") // элемент params.gtp.minteid
				{
					auto jminteid = jgtp["minteid"];
					// проверить соответствие типа
					if(jminteid.is_number() == false)
					{
						PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.gtp.minteid\" has a wrong type (required = number)\n");
						return false;
					}
					Params.Gtp.MinTeid = jminteid.get<int>();
					PRINT_TMP(PRINT_LEVEL::MIDDLE, "    key: %s, type: string, value: %i\n", jgtp1.key().c_str(), Params.Gtp.MinTeid);
					// проверить корректность считанного значения
					if(Params.Gtp.MinTeid < 0 || Params.Gtp.MinTeid > 50000)
					{
						PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.gtp.minteid\" is out of range (current = %s, required = [0, 50000])\n", Params.Gtp.MinTeid);
						return false;
					}
				}
				else if(jgtp1.key() == "maxteid") // элемент params.gtp.maxteid
				{
					auto jmaxteid = jgtp["maxteid"];
					// проверить соответствие типа
					if(jmaxteid.is_number() == false)
					{
						PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.gtp.maxteid\" has a wrong type (required = number)\n");
						return false;
					}
					Params.Gtp.MaxTeid = jmaxteid.get<int>();
					PRINT_TMP(PRINT_LEVEL::MIDDLE, "    key: %s, type: string, value: %i\n", jgtp1.key().c_str(), Params.Gtp.MaxTeid);
					// проверить корректность считанного значения
					if(Params.Gtp.MaxTeid < 0 || Params.Gtp.MaxTeid > 50000)
					{
						PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.gtp.maxteid\" is out of range (current = %s, required = [0, 50000])\n", Params.Gtp.MaxTeid);
						return false;
					}
				}
			}
      if(Params.Gtp.MaxTeid <= Params.Gtp.MinTeid)
      {
        PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.gtp.maxteid\" must be greater than  \"params.gtp.minteid\" (current = %i <= %i\n", Params.Gtp.MaxTeid, Params.Gtp.MinTeid);
        return false;
      }
		}
		else if(jparams1.key() == "service") // элемент params.service
		{
			auto jservice = jparams["service"];
			// проверить соответствие типа
			if(jservice.is_array() == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.service\" has a wrong type (required = array)\n");
				return false;
			}
			PRINT_TMP(PRINT_LEVEL::MIDDLE, "  key: %s, type: array\n", jparams1.key().c_str());
			// цикл по всем элементам params.service
			for (int i=0; i<jservice.size(); ++i)
			{
				auto jservice0 = jservice[i];
				// проверить соответствие типа
				if(jservice0.is_object() == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.service[%i]\" has a wrong type (required = object)\n", i);
					return false;
				}
				PRINT_TMP(PRINT_LEVEL::MIDDLE, "    ind: %i, type: object\n", i);
				// проверить наличие всех обязательных элементов внутри params.service[i]
				if (jservice0.contains("id") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.service[%i].id\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
				if (jservice0.contains("name") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.service[%i].name\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
        int id;
        { // элемент params.service[i].id
          auto jid = jservice0["id"];
          // проверить соответствие типа
          if(jid.is_number() == false)
          {
            PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.service[%i].id\" has a wrong type (required = number)\n", i);
            return false;
          }
          id = jid.get<int>();
          Params.ServiceList[id].Id = id;
          PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: id, type: number, value: %i\n", Params.ServiceList[id].Id);
          // проверить корректность считанного значения
          if(Params.ServiceList[id].Id < 0)
          {
            PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.service[%i].id\" must be a positive value (current = %i)\n", i, Params.ServiceList[id].Id);
            return false;
          }
        }
				// цикл по всем элементам params.service[i]
				for(auto& jservice1 : jservice0.items())
				{
					if(jservice1.key() == "id") // элемент params.service[i].id
            continue; // мы его уже обработали
					else if(jservice1.key() == "name") // элемент params.service[i].name
					{
						auto jname = jservice0["name"];
						// проверить соответствие типа
						if(jname.is_string() == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.service[%i].name\" has a wrong type (required = string)\n", i);
							return false;
						}
						Params.ServiceList[id].Name = jname.get<std::string>();
						PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: %s, type: string, value: %s\n", jservice1.key().c_str(), Params.ServiceList[id].Name.c_str());
#if ! ELIJA_TODO // какую проверку здесь выполнять?
						// проверить корректность считанного значения
						if(Params.ServiceList[id].Name ?)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.service[%i].name\" is ? (current = %s)\n", i, Params.ServiceList[id].Name.c_str());
							return false;
						}
#endif
					}
				}
			}
		}
		else if(jparams1.key() == "app") // элемент params.app
		{
			auto japp = jparams["app"];
			// проверить соответствие типа
			if(japp.is_array() == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.app\" has a wrong type (required = array)\n");
				return false;
			}
			PRINT_TMP(PRINT_LEVEL::MIDDLE, "  key: %s, type: array\n", jparams1.key().c_str());
			// цикл по всем элементам params.app
			for (int i=0; i<japp.size(); ++i)
			{
				auto japp0 = japp[i];
				// проверить соответствие типа
				if(japp0.is_object() == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.app[%i]\" has a wrong type (required = object)\n", i);
					return false;
				}
				PRINT_TMP(PRINT_LEVEL::MIDDLE, "    ind: %i, type: object\n", i);
				// проверить наличие всех обязательных элементов внутри params.app[i]
				if (japp0.contains("id") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.app[%i].id\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
				if (japp0.contains("name") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.app[%i].name\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
        int id;
        { // элемент params.app[i].name
          auto jid = japp0["id"];
          // проверить соответствие типа
          if(jid.is_number() == false)
          {
            PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.app[%i].id\" has a wrong type (required = number)\n", i);
            return false;
          }
          id = jid.get<int>();
          Params.AppList[id].Id = id;
          PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: id, type: number, value: %i\n", Params.AppList[id].Id);
          // проверить корректность считанного значения
          if(Params.AppList[id].Id < 0)
          {
            PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.app[%i].id\" must be a positive value (current = %i)\n", i, Params.AppList[id].Id);
            return false;
          }
        }
				// цикл по всем элементам params.app[i]
				for(auto& japp1 : japp0.items())
				{
					if(japp1.key() == "id") // элемент params.app[i].id
            continue; // мы его уже обработали
					else if(japp1.key() == "name") // элемент params.app[i].name
					{
						auto jname = japp0["name"];
						// проверить соответствие типа
						if(jname.is_string() == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.app[%i].name\" has a wrong type (required = string)\n", i);
							return false;
						}
						Params.AppList[id].Name = jname.get<std::string>();
						PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: %s, type: string, value: %s\n", japp1.key().c_str(), Params.AppList[id].Name.c_str());
#if ! ELIJA_TODO // какую проверку здесь выполнять?
						// проверить корректность считанного значения
						if(Params.AppList[id].Name ?)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.app[i%].name\" is ? (current = %s)\n", i, Params.AppList[id].Name.c_str());
							return false;
						}
#endif
					}
				}
			}
		}
		else if(jparams1.key() == "pcap") // элемент params.pcap
		{
			auto jpcap = jparams["pcap"];
			// проверить соответствие типа
			if(jpcap.is_array() == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.pcap\" has a wrong type (required = array)\n");
				return false;
			}
			PRINT_TMP(PRINT_LEVEL::MIDDLE, "  key: %s, type: array\n", jparams1.key().c_str());
			// цикл по всем элементам params.pcap
			for (int i=0; i<jpcap.size(); ++i)
			{
				auto jpcap0 = jpcap[i];
				// проверить соответствие типа
				if(jpcap0.is_object() == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.pcap[%i]\" has a wrong type (required = object)\n", i);
					return false;
				}
				PRINT_TMP(PRINT_LEVEL::MIDDLE, "    ind: %i, type: object\n", i);
				// проверить наличие всех обязательных элементов внутри params.pcap[i]
				if (jpcap0.contains("id") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.pcap[%i].id\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
				if (jpcap0.contains("video") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.pcap[%i].video\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
				if (jpcap0.contains("service") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.pcap[%i].service\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
				if (jpcap0.contains("app") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.pcap[%i].app\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
				if (jpcap0.contains("br") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.pcap[%i].br\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
				if (jpcap0.contains("path") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.pcap[%i].path\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
        int id;
        { // элемент params.pcap[i].id
          auto jid = jpcap0["id"];
          // проверить соответствие типа
          if(jid.is_number() == false)
          {
            PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.pcap[%i].id\" has a wrong type (required = number)\n", i);
            return false;
          }
          id = jid.get<int>();
          Params.PcapList[id].Id = id;
          PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: id, type: number, value: %i\n", Params.PcapList[id].Id);
          // проверить корректность считанного значения
          if(Params.PcapList[id].Id < 0)
          {
            PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.pcap[%i].id\" must be a positive value (current = %i)\n", i, Params.PcapList[id].Id);
            return false;
          }
        }
				// цикл по всем элементам params.pcap[i]
				for(auto& jpcap1 : jpcap0.items())
				{
					if(jpcap1.key() == "id") // элемент params.pcap[i].id
            continue; // мы его уже обработали
					else if(jpcap1.key() == "video") // элемент params.pcap[i].video
					{
						auto jvideo = jpcap0["video"];
						// проверить соответствие типа
						if(jvideo.is_boolean() == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.pcap[%i].video\" has a wrong type (required = boolean)\n", i);
							return false;
						}
						Params.PcapList[id].Video = jvideo.get<bool>();
						PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: %s, type: bool, value: %i\n", jpcap1.key().c_str(), Params.PcapList[id].Video);
#if ! ELIJA_TODO // какую проверку здесь выполнять?
						// проверить корректность считанного значения
						if(Params.PcapList[id].Video ?)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.pcap[%i].video\" must be a positive value (current = %i)\n", i, Params.PcapList[id].Video);
							return false;
						}
#endif
					}
					else if(jpcap1.key() == "service") // элемент params.pcap[i].service
					{
						auto jservice = jpcap0["service"];
						// проверить соответствие типа
						if(jservice.is_object() == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.pcap[%i].service\" has a wrong type (required = object)\n", i);
							return false;
						}
						PRINT_TMP(PRINT_LEVEL::MIDDLE, "        key: %s, type: object\n", jpcap1.key().c_str());
						// проверить наличие всех обязательных элементов внутри params.pcap[i].service
						if (jservice.contains("id") == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.pcap[%i].service.id\" key\n", ParamsFilePath.c_str(), i);
							return false;
						}
						// цикл по всем элементам params.pcap[i].service
						for(auto& jservice1 : jservice.items())
						{
							if(jservice1.key() == "id") // элемент params.pcap[i].service.id
							{
								auto jid = jservice["id"];
								// проверить соответствие типа
								if(jid.is_number() == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.pcap[%i].service.id\" has a wrong type (required = number)\n", i);
									return false;
								}
								Params.PcapList[id].Service.Id = jid.get<int>();
								PRINT_TMP(PRINT_LEVEL::MIDDLE, "          key: %s, type: number, value: %i\n", jservice1.key().c_str(), Params.PcapList[id].Id);
#if ! ELIJA_TODO // какую проверку здесь выполнять? может проверять есть ли значение в ранее считанном списке params.service?
								// проверить корректность считанного значения
								if(Params.PcapList[id].Service.Id ?)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.pcap[%i].service.id\" is ? (current = %i)\n", i, Params.PcapList[id].Service.Id);
									return false;
								}
#endif
							}
						}
					}
					else if(jpcap1.key() == "app") // элемент params.pcap[i].app
					{
						auto japp = jpcap0["app"];
						// проверить соответствие типа
						if(japp.is_object() == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.pcap[%i].app\" has a wrong type (required = object)\n", i);
							return false;
						}
						PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: %s, type: object\n", jpcap1.key().c_str());
						// проверить наличие всех обязательных элементов внутри params.pcap[i].app
						if (japp.contains("id") == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.pcap[%i].app.id\" key\n", ParamsFilePath.c_str(), i);
							return false;
						}
						// цикл по всем элементам params.pcap[i].app
						for(auto& japp1 : japp.items())
						{
							if(japp1.key() == "id") // элемент params.pcap[i].app.id
							{
								auto jid = japp["id"];
								// проверить соответствие типа
								if(jid.is_number() == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.pcap[%i].app.id\" has a wrong type (required = number)\n", i);
									return false;
								}
								Params.PcapList[id].App.Id = jid.get<int>();
								PRINT_TMP(PRINT_LEVEL::MIDDLE, "        key: %s, type: number, value: %i\n", japp1.key().c_str(), Params.PcapList[id].Id);
#if ! ELIJA_TODO // какую проверку здесь выполнять? может проверять есть ли значение в ранее считанном списке params.app?
								// проверить корректность считанного значения
								if(Params.PcapList[id].App.Id ?)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.pcap[%i].app.id\" is ? (current = %i)\n", i, Params.PcapList[id].App.Id);
									return false;
								}
#endif
							}
						}
					}
					else if(jpcap1.key() == "br") // элемент params.pcap[i].br
					{
						auto jbr = jpcap0["br"];
						// проверить соответствие типа
						if(jbr.is_number() == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.pcap[%i].br\" has a wrong type (required = number)\n", i);
							return false;
						}
						Params.PcapList[id].Bitrate = jbr.get<int>();
						PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: %s, type: number, value: %i\n", jpcap1.key().c_str(), Params.PcapList[id].Bitrate);
						// проверить корректность считанного значения
						if(Params.PcapList[id].Bitrate < 0)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.pcap[%i].br\" must be a positive value (current = %i)\n", i, Params.PcapList[id].Bitrate);
							return false;
						}
					}
					else if(jpcap1.key() == "path") // элемент params.pcap[i].path
					{
						auto jpath = jpcap0["path"];
						// проверить соответствие типа
						if(jpath.is_string() == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.pcap[%i].path\" has a wrong type (required = string)\n", i);
							return false;
						}
						Params.PcapList[id].Path = jpath.get<std::string>();
						PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: %s, type: string, value: %s\n", jpcap1.key().c_str(), Params.PcapList[id].Path.c_str());
#if ! ELIJA_TODO // какую проверку здесь выполнять?
						// проверить корректность считанного значения
						if(Params.PcapList[id].Path ?)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.pcap[%i].path\" is ? (current = %s)\n", i, Params.PcapList[id].Path.c_str();
							return false;
						}
#endif
					}
				}
			}
		}
		else if(jparams1.key() == "user_scenario") // элемент params.user_scenario
		{
			auto jus = jparams["user_scenario"];
			// проверить соответствие типа
			if(jus.is_array() == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.user_scenario\" has a wrong type (required = array)\n");
				return false;
			}
			PRINT_TMP(PRINT_LEVEL::MIDDLE, "  key: %s, type: array\n", jparams1.key().c_str());
			// цикл по всем элементам params.user_scenario
			for (int i=0; i<jus.size(); ++i)
			{
				auto jus0 = jus[i];
				// проверить соответствие типа
				if(jus0.is_object() == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.user_scenario[%i]\" has a wrong type (required = object)\n", i);
					return false;
				}
				PRINT_TMP(PRINT_LEVEL::MIDDLE, "    ind: %i, type: object\n", i);
				// проверить наличие всех обязательных элементов внутри params.user_scenario[i]
				if (jus0.contains("id") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.user_scenario[%i].id\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
				if (jus0.contains("name") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.user_scenario[%i].name\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
				if (jus0.contains("br") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.user_scenario[%i].br\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
				if (jus0.contains("pcap_id") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.user_scenario[%i].pcap_id\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
        int id;
        { // элемент params.user_scenario[i].id
          auto jid = jus0["id"];
          // проверить соответствие типа
          if(jid.is_number() == false)
          {
            PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.user_scenario[%i].id\" has a wrong type (required = number)\n", i);
            return false;
          }
          id = jid.get<int>();
          Params.UserScenarioList[id].Id = id;
          PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: id, type: number, value: %i\n", Params.UserScenarioList[id].Id);
          // проверить корректность считанного значения
          if(Params.UserScenarioList[id].Id < 0)
          {
            PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.user_scenario[%i].id\" must be a positive value (current = %i)\n", i, Params.UserScenarioList[id].Id);
            return false;
          }
        }
				// цикл по всем элементам params.user_scenario[i]
				for(auto& jus1 : jus0.items())
				{
					if(jus1.key() == "id") // элемент params.user_scenario[i].id
            continue; // мы его уже обработали
					else if(jus1.key() == "name") // элемент params.user_scenario[i].name
					{
						auto jname = jus0["name"];
						// проверить соответствие типа
						if(jname.is_string() == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.user_scenario[%i].name\" has a wrong type (required = string)\n", i);
							return false;
						}
						Params.UserScenarioList[id].Name = jname.get<std::string>();
						PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: %s, type: string, value: %s\n", jus1.key().c_str(), Params.UserScenarioList[id].Name.c_str());
#if ! ELIJA_TODO // какую проверку здесь выполнять?
						// проверить корректность считанного значения
						if(Params.UserScenarioList[id].Name ?)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.user_scenario[%i].name\" is ? (current = %s)\n", i, Params.UserScenarioList[id].Name.c_str());
							return false;
						}
#endif
					}
					else if(jus1.key() == "br") // элемент params.user_scenario[i].br
					{
						auto jbr = jus0["br"];
						// проверить соответствие типа
						if(jbr.is_number() == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.user_scenario[%i].br\" has a wrong type (required = number)\n", i);
							return false;
						}
						Params.UserScenarioList[id].Bitrate = jbr.get<size_t>();
						PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: %s, type: number, value: %llu\n", jus1.key().c_str(), Params.UserScenarioList[id].Bitrate);
						// проверить корректность считанного значения
						if(Params.UserScenarioList[id].Bitrate < 0 || Params.UserScenarioList[id].Bitrate > 50000000)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.user_scenario[%i].br\" is out of range (current = %llu, required = [0, 50000000])\n", i, Params.UserScenarioList[id].Bitrate);
							return false;
						}
					}
					else if(jus1.key() == "pcap_id") // элемент params.user_scenario[i].pcap_id
					{
						auto jpcapid0 = jus0["pcap_id"];
						// проверить соответствие типа
						if(jpcapid0.is_array() == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.user_scenario[%i].pcap_id\" has a wrong type (required = array)\n", i);
							return false;
						}
						PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: %s, type: array\n", jus1.key().c_str());
						for(int j = 0; j < jpcapid0.size(); ++j)
						{
							auto jpcapid1 = jpcapid0[j];
							// проверить соответствие типа
							if(jpcapid1.is_number() == false)
							{
								PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.user_scenario[%i].pcap_id[%i]\" has a wrong type (required = number)\n", i, j);
								return false;
							}
							int pid = jpcapid1.get<int>();
							Params.UserScenarioList[id].Pcap[pid] = {0};
							PRINT_TMP(PRINT_LEVEL::MIDDLE, "        ind: %i, type: number, value: %i\n", j, pid);
#if ! ELIJA_TODO // какую проверку здесь выполнять?
							// проверить корректность считанного значения
							if(pid ?)
							{
								PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.user_scenario[%i].pcap_id[%i]\" is ?)\n", i, pid);
								return false;
							}
#endif
						}
					}
				}
			}
		}
		else if(jparams1.key() == "network_scenario") // элемент params.network_scenario
		{
			auto jns = jparams["network_scenario"];
			// проверить соответствие типа
			if(jns.is_array() == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario\" has a wrong type (required = array)\n");
				return false;
			}
			PRINT_TMP(PRINT_LEVEL::MIDDLE, "  key: %s, type: array\n", jparams1.key().c_str());
			// цикл по всем элементам params.network_scenario
			for (int i=0; i<jns.size(); ++i)
			{
				auto jns0 = jns[i];
				// проверить соответствие типа
				if(jns0.is_object() == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i]\" has a wrong type (required = object)\n", i);
					return false;
				}
				PRINT_TMP(PRINT_LEVEL::MIDDLE, "    ind: %i, type: object\n", i);
				// проверить наличие всех обязательных элементов внутри params.network_scenario[i]
				if (jns0.contains("id") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.network_scenario[%i].id\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
				if (jns0.contains("name") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "1 The parameters file %s has NO \"params.network_scenario[%i].name\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
				if (jns0.contains("jitter") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.network_scenario[%i].jitter\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
				if (jns0.contains("burst") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.network_scenario[%i].burst\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
        int id;
        { // элемент params.network_scenario[i].id
          auto jid = jns0["id"];
          // проверить соответствие типа
          if(jid.is_number() == false)
          {
            PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i].id\" has a wrong type (required = number)\n", i);
            return false;
          }
          id = jid.get<int>();
          Params.NetworkScenarioList[id].Id = id;
          PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: id, type: number, value: %i\n", Params.NetworkScenarioList[id].Id);
          // проверить корректность считанного значения
          if(Params.NetworkScenarioList[id].Id < 0)
          {
            PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i].id\" must be a positive value (current = %i)\n", i, Params.NetworkScenarioList[id].Id);
            return false;
          }
        }
				// цикл по всем элементам params.network_scenario[i]
				for(auto& jns1 : jns0.items())
				{
					if(jns1.key() == "id") // элемент params.network_scenario[i].id
            continue; // мы его уже обработали
					else if(jns1.key() == "name") // элемент params.network_scenario[i].name
					{
						auto jname = jns0["name"];
						// проверить соответствие типа
						if(jname.is_string() == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i].name\" has a wrong type (required = string)\n", i);
							return false;
						}
						Params.NetworkScenarioList[id].Name = jname.get<std::string>();
						PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: %s, type: string, value: %s\n", jns1.key().c_str(), Params.NetworkScenarioList[id].Name.c_str());
#if ! ELIJA_TODO // какую проверку здесь выполнять?
						// проверить корректность считанного значения
						if(Params.UserScenatioList[i].Name ?)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i].name\" is ? (current = %s)\n", i, Params.UserScenatioList[i].Name.c_str();
							return false;
						}
#endif
					}
					else if(jns1.key() == "jitter") // элемент params.network_scenario[i].jitter
					{
						auto jjitter = jns0["jitter"];
						// проверить соответствие типа
						if(jjitter.is_object() == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i].jitter\" has a wrong type (required = object)\n", i);
							return false;
						}
						PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: %s, type: object\n", jns1.key().c_str());
						// проверить наличие всех обязательных элементов внутри params.network_scenario[i].jitter
						if (jjitter.contains("timeup") == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.network_scenario[%i].jitter.timeup\" key\n", ParamsFilePath.c_str(), i);
							return false;
						}
						if (jjitter.contains("timedown") == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.network_scenario[%i].jitter.timedown\" key\n", ParamsFilePath.c_str(), i);
							return false;
						}
						if (jjitter.contains("value") == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.network_scenario[%i].jitter.value\" key\n", ParamsFilePath.c_str(), i);
							return false;
						}
						// цикл по всем элементам params.network_scenario[i].jitter
						for(auto& jjitter1 : jjitter.items())
						{
							if(jjitter1.key() == "timeup") // элемент params.network_scenario[i].jitter.timeup
							{
								auto jtimeup = jjitter["timeup"];
								// проверить соответствие типа
								if(jtimeup.is_number() == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i].jitter.timeup\" has a wrong type (required = number)\n", i);
									return false;
								}
								Params.NetworkScenarioList[id].Jitter.TimeUp = jtimeup.get<int>();
								PRINT_TMP(PRINT_LEVEL::MIDDLE, "        key: %s, type: number, value: %i\n", jjitter1.key().c_str(), Params.NetworkScenarioList[id].Jitter.TimeUp);
								// проверить корректность считанного значения
								if(Params.NetworkScenarioList[id].Jitter.TimeUp < 0)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i].jitter.timeup\" must be a positiva value (current = %i)\n", i, Params.NetworkScenarioList[id].Jitter.TimeUp);
									return false;
								}
							}
							else if(jjitter1.key() == "timedown") // элемент params.network_scenario[i].jitter.timedown
							{
								auto jtimedown = jjitter["timedown"];
								// проверить соответствие типа
								if(jtimedown.is_number() == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i].jitter.timedown\" has a wrong type (required = number)\n", i);
									return false;
								}
								Params.NetworkScenarioList[id].Jitter.TimeDown = jtimedown.get<int>();
								PRINT_TMP(PRINT_LEVEL::MIDDLE, "        key: %s, type: number, value: %i\n", jjitter1.key().c_str(), Params.NetworkScenarioList[id].Jitter.TimeDown);
								// проверить корректность считанного значения
								if(Params.NetworkScenarioList[id].Jitter.TimeDown < 0)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i].jitter.timedown\" must be a positiva value (current = %i)\n", i, Params.NetworkScenarioList[id].Jitter.TimeDown);
									return false;
								}
							}
							else if(jjitter1.key() == "value") // элемент params.network_scenario[i].jitter.value
							{
								auto jvalue = jjitter["value"];
								// проверить соответствие типа
								if(jvalue.is_number() == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i].jitter.value\" has a wrong type (required = number)\n", i);
									return false;
								}
								Params.NetworkScenarioList[id].Jitter.Value = jvalue.get<int>();
								PRINT_TMP(PRINT_LEVEL::MIDDLE, "        key: %s, type: number, value: %i\n", jjitter1.key().c_str(), Params.NetworkScenarioList[id].Jitter.Value);
								// проверить корректность считанного значения
								if(Params.NetworkScenarioList[id].Jitter.Value < 0)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i].jitter.timedown\" must be a positiva value (current = %i)\n", i, Params.NetworkScenarioList[id].Jitter.Value);
									return false;
								}
							}
						}
					}
					else if(jns1.key() == "burst") // элемент params.network_scenario[i].burst
					{
						auto jburst = jns0["burst"];
						// проверить соответствие типа
						if(jburst.is_object() == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i].burst\" has a wrong type (required = object)\n", i);
							return false;
						}
						PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: %s, type: object\n", jns1.key().c_str());
						// проверить наличие всех обязательных элементов внутри params.network_scenario[i].burst
						if (jburst.contains("timeup") == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.network_scenario[%i].burst.timeup\" key\n", ParamsFilePath.c_str(), i);
							return false;
						}
						if (jburst.contains("timedown") == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.network_scenario[%i].burst.timedown\" key\n", ParamsFilePath.c_str(), i);
							return false;
						}
						// цикл по всем элементам params.network_scenario[i].burst
						for(auto& jburst1 : jburst.items())
						{
							if(jburst1.key() == "timeup") // элемент params.network_scenario[i].burst.timeup
							{
								auto jtimeup = jburst["timeup"];
								// проверить соответствие типа
								if(jtimeup.is_number() == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i].burst.timeup\" has a wrong type (required = number)\n", i);
									return false;
								}
								Params.NetworkScenarioList[id].Burst.TimeUp = jtimeup.get<int>();
								PRINT_TMP(PRINT_LEVEL::MIDDLE, "        key: %s, type: number, value: %i\n", jburst1.key().c_str(), Params.NetworkScenarioList[id].Burst.TimeUp);
								// проверить корректность считанного значения
								if(Params.NetworkScenarioList[id].Burst.TimeUp < 0)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i].burst.timeup\" must be a positiva value (current = %i)\n", i, Params.NetworkScenarioList[id].Burst.TimeUp);
									return false;
								}
							}
							else if(jburst1.key() == "timedown") // элемент params.network_scenario[i].burst.timedown
							{
								auto jtimedown = jburst["timedown"];
								// проверить соответствие типа
								if(jtimedown.is_number() == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i].burst.timedown\" has a wrong type (required = number)\n", i);
									return false;
								}
								Params.NetworkScenarioList[id].Burst.TimeDown = jtimedown.get<int>();
								PRINT_TMP(PRINT_LEVEL::MIDDLE, "        key: %s, type: number, value: %i\n", jburst1.key().c_str(), Params.NetworkScenarioList[id].Burst.TimeDown);
								// проверить корректность считанного значения
								if(Params.NetworkScenarioList[id].Burst.TimeDown < 0)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i].burst.timedown\" must be a positiva value (current = %i)\n", i, Params.NetworkScenarioList[id].Burst.TimeDown);
									return false;
								}
							}
						}
					}
				}
			}
		}
		else if(jparams1.key() == "eb") // элемент params.eb
		{
			auto jeb = jparams["eb"];
			// проверить соответствие типа
			if(jeb.is_array() == false)
			{
				PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb\" has a wrong type (required = array)\n");
				return false;
			}
			PRINT_TMP(PRINT_LEVEL::MIDDLE, "  key: %s, type: array\n", jparams1.key().c_str());
			// цикл по всем элементам params.eb
			for (int i=0; i<jeb.size(); ++i)
			{
				auto jeb0 = jeb[i];
				// проверить соответствие типа
				if(jeb0.is_object() == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i]\" has a wrong type (required = object)\n", i);
					return false;
				}
				PRINT_TMP(PRINT_LEVEL::MIDDLE, "    ind: %i, type: object\n", i);
				// проверить наличие всех обязательных элементов внутри params.eb[i]
				if (jeb0.contains("id") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.eb[%i].id\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
				if (jeb0.contains("br") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.eb[%i].br\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
				if (jeb0.contains("user_scenario") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.eb[%i].user_scenario\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
				if (jeb0.contains("network_scenario") == false)
				{
					PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.network_scenario[%i].burst\" key\n", ParamsFilePath.c_str(), i);
					return false;
				}
        int id;
        { // элемент params.eb[i].id
          auto jid = jeb0["id"];
          // проверить соответствие типа
          if(jid.is_number() == false)
          {
            PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].id\" has a wrong type (required = number)\n", i);
            return false;
          }
          id = jid.get<int>();
          Params.EpsBearerList[id].Id = id;
          PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: id, type: number, value: %i\n", Params.EpsBearerList[id].Id);
          // проверить корректность считанного значения
          if(Params.EpsBearerList[id].Id < 0)
          {
            PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].id\" must be a positive value (current = %i)\n", i, Params.EpsBearerList[id].Id);
            return false;
          }
        }
				// цикл по всем элементам params.eb[i]
				for(auto& jeb1 : jeb0.items())
				{
					if(jeb1.key() == "id") // элемент params.eb[i].id
            continue; // мы его уже обработали
					else if(jeb1.key() == "br") // элемент params.eb[i].name
					{
						auto jbr = jeb0["br"];
						// проверить соответствие типа
						if(jbr.is_number() == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].br\" has a wrong type (required = number)\n", i);
							return false;
						}
						Params.EpsBearerList[id].Bitrate = jbr.get<size_t>();
						PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: %s, type: string, value: %llu\n", jeb1.key().c_str(), Params.EpsBearerList[id].Bitrate);
						// проверить корректность считанного значения
						if(Params.EpsBearerList[id].Bitrate < 0 || Params.EpsBearerList[id].Bitrate > 50000000)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].br\" is out of range (current = %llu, required = [0, 50000000])\n", i, Params.EpsBearerList[id].Bitrate);
							return false;
						}
					}
					else if(jeb1.key() == "user_scenario") // элемент params.eb[i].user_scenario
					{
						auto jus = jeb0["user_scenario"];
						// проверить соответствие типа
						if(jus.is_object() == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].user_scenario\" has a wrong type (required = object)\n", i);
							return false;
						}
						PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: %s, type: object\n", jeb1.key().c_str());
						// проверить наличие всех обязательных элементов внутри params.eb[i].user_scenario
						if (jus.contains("id") == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.eb[%i].user_scenario.id\" key\n", ParamsFilePath.c_str(), i);
							return false;
						}
						// цикл по всем элементам params.eb[i].user_scenario
						for(auto& jus1 : jus.items())
						{
							if(jus1.key() == "id") // элемент params.eb[i].user_scenario.id
							{
								auto jid = jus["id"];
								// проверить соответствие типа
								if(jid.is_number() == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].user_scenario.id\" has a wrong type (required = number)\n", i);
									return false;
								}
								Params.EpsBearerList[id].UserScenario.Id = jid.get<int>();
								PRINT_TMP(PRINT_LEVEL::MIDDLE, "        key: %s, type: number, value: %i\n", jus1.key().c_str(), Params.EpsBearerList[id].UserScenario.Id);
								// проверить корректность считанного значения
								if(Params.EpsBearerList[id].UserScenario.Id < 0)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].user_scenario.id\" must be a positive value (current = %i)\n", i, Params.NetworkScenarioList[id].Id);
									return false;
								}
								// ЕСЛИ это настраиваемый пользовательский сценарий, то проверить наличие всех обязательных элементов внутри params.eb[i].user_scenario
								if(Params.EpsBearerList[id].UserScenario.Id == 0)
								{
									if (jus.contains("name") == false)
									{
										PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.eb[%i].user_scenario.name\" key\n", ParamsFilePath.c_str(), i);
										return false;
									}
									if (jus.contains("br") == false)
									{
										PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.eb[%i].user_scenario.br\" key\n", ParamsFilePath.c_str(), i);
										return false;
									}
									if (jus.contains("pcap_id") == false)
									{
										PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.eb[%i].user_scenario.pcap_id\" key\n", ParamsFilePath.c_str(), i);
										return false;
									}
								}
							}
							else if(jus1.key() == "name") // элемент params.eb[i].user_scenario.name
							{
								auto jname = jus["name"];
								// проверить соответствие типа
								if(jname.is_string() == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].user_scenario.name\" has a wrong type (required = string)\n", i);
									return false;
								}
								Params.EpsBearerList[id].UserScenario.Name = jname.get<std::string>();
								PRINT_TMP(PRINT_LEVEL::MIDDLE, "        key: %s, type: string, value: %s\n", jus1.key().c_str(), Params.EpsBearerList[id].UserScenario.Name.c_str());
#if ! ELIJA_TODO // какую проверку здесь выполнять?
								// проверить корректность считанного значения
								if(Params.EpsBearerList[id].UserScenario.Name ?)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].user_scenario.name\" is ? (current = %s)\n", i, Params.EpsBearerList[id].UserScenario.Name.c_str());
									return false;
								}
#endif
							}
							else if(jus1.key() == "br") // элемент params.eb[i].user_scenario.br
							{
								auto jbr = jus["br"];
								// проверить соответствие типа
								if(jbr.is_number() == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].user_scenario.br\" has a wrong type (required = number)\n", i);
									return false;
								}
								Params.EpsBearerList[id].UserScenario.Bitrate = jbr.get<size_t>();
								PRINT_TMP(PRINT_LEVEL::MIDDLE, "        key: %s, type: number, value: %llu\n", jus1.key().c_str(), Params.EpsBearerList[id].UserScenario.Bitrate);
								// проверить корректность считанного значения
								if(Params.EpsBearerList[id].UserScenario.Bitrate < 0 || Params.EpsBearerList[id].UserScenario.Bitrate > 50000000)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].user_scenario.br\" is out of range (current = %llu, required = [0, 50000000])\n", i, Params.UserScenarioList[id].Bitrate);
									return false;
								}
							}
							else if(jus1.key() == "pcap_id") // элемент params.eb[i].user_scenario.pcap_id
							{
								auto jpcapid0 = jus["pcap_id"];
								// проверить соответствие типа
								if(jpcapid0.is_array() == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].user_scenario.pcap_id\" has a wrong type (required = array)\n", i);
									return false;
								}
								PRINT_TMP(PRINT_LEVEL::MIDDLE, "        key: %s, type: array\n", jus1.key().c_str());
								for(int j = 0; j < jpcapid0.size(); ++j)
								{
									auto jpcapid1 = jpcapid0[j];
									// проверить соответствие типа
									if(jpcapid1.is_number() == false)
									{
										PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].user_scenario.pcap_id[%i]\" has a wrong type (required = number)\n", i, j);
										return false;
									}
									int pid = jpcapid1.get<int>();
									Params.EpsBearerList[id].UserScenario.Pcap[pid] = {0};
									PRINT_TMP(PRINT_LEVEL::MIDDLE, "          ind: %i, type: number, value: %i\n", j, pid);
#if ! ELIJA_TODO // какую проверку здесь выполнять?
									// проверить корректность считанного значения
									if(pid ?)
									{
										PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].user_scenario.pcap_id[%i]\" is ?)\n", i, j, pid);
										return false;
									}
#endif
								}
							}
						}
					}
					else if(jeb1.key() == "network_scenario") // элемент params.eb[i].network_scenario
					{
						auto jns = jeb0["network_scenario"];
						// проверить соответствие типа
						if(jns.is_object() == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].network_scenario\" has a wrong type (required = object)\n", i);
							return false;
						}
						PRINT_TMP(PRINT_LEVEL::MIDDLE, "      key: %s, type: object\n", jeb1.key().c_str());
						// проверить наличие всех обязательных элементов внутри params.eb[i].network_scenario
						if (jns.contains("id") == false)
						{
							PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.network_scenario[%i].id\" key\n", ParamsFilePath.c_str(), i);
							return false;
						}
						// цикл по всем элементам params.network_scenario[i]
						for(auto& jns1 : jns.items())
						{
							if(jns1.key() == "id") // элемент params.network_scenario[i].id
							{
								auto jid = jns["id"];
								// проверить соответствие типа
								if(jid.is_number() == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i].id\" has a wrong type (required = number)\n", i);
									return false;
								}
								Params.EpsBearerList[id].NetworkScenario.Id = jid.get<int>();
								PRINT_TMP(PRINT_LEVEL::MIDDLE, "        key: %s, type: number, value: %i\n", jns1.key().c_str(), Params.EpsBearerList[id].NetworkScenario.Id);
								// проверить корректность считанного значения
								if(Params.EpsBearerList[id].NetworkScenario.Id < 0)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].network_scenario.id\" must be a positive value (current = %i)\n", i, Params.EpsBearerList[id].NetworkScenario.Id);
									return false;
								}
								// ЕСЛИ это настраиваемый пользовательский сценарий, то проверить наличие всех обязательных элементов внутри params.eb[i].network_scenario
								if(Params.EpsBearerList[id].NetworkScenario.Id == 0)
								{
									if (jns.contains("name") == false)
									{
										PRINT_ERR(PRINT_LEVEL::MIDDLE, "2 The parameters file %s has NO \"params.network_scenario[%i].name\" key\n", ParamsFilePath.c_str(), i);
										return false;
									}
									if (jns.contains("jitter") == false)
									{
										PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.network_scenario[%i].jitter\" key\n", ParamsFilePath.c_str(), i);
										return false;
									}
									if (jns.contains("burst") == false)
									{
										PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.network_scenario[%i].burst\" key\n", ParamsFilePath.c_str(), i);
										return false;
									}
								}
							}
							else if(jns1.key() == "name") // элемент params.eb[i].network_scenario.name
							{
								auto jname = jns["name"];
								// проверить соответствие типа
								if(jname.is_string() == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].network_scenario.name\" has a wrong type (required = string)\n", i);
									return false;
								}
								Params.EpsBearerList[id].NetworkScenario.Name = jname.get<std::string>();
								PRINT_TMP(PRINT_LEVEL::MIDDLE, "        key: %s, type: string, value: %s\n", jns1.key().c_str(), Params.EpsBearerList[id].NetworkScenario.Name.c_str());
		#if ! ELIJA_TODO // какую проверку здесь выполнять?
								// проверить корректность считанного значения
								if(Params.UserScenatioList[i].Name ?)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.network_scenario[%i].name\" is ? (current = %s)\n", i, Params.UserScenatioList[i].Name.c_str();
									return false;
								}
		#endif
							}
							else if(jns1.key() == "jitter") // элемент params.eb[i].network_scenario.jitter
							{
								auto jjitter = jns["jitter"];
								// проверить соответствие типа
								if(jjitter.is_object() == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].network_scenario.jitter\" has a wrong type (required = object)\n", i);
									return false;
								}
								PRINT_TMP(PRINT_LEVEL::MIDDLE, "        key: %s, type: object\n", jns1.key().c_str());
								// проверить наличие всех обязательных элементов внутри params.network_scenario[i].jitter
								if (jjitter.contains("timeup") == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.eb[%i].network_scenario.jitter.timeup\" key\n", ParamsFilePath.c_str(), i);
									return false;
								}
								if (jjitter.contains("timedown") == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.eb[%i].network_scenario.jitter.timedown\" key\n", ParamsFilePath.c_str(), i);
									return false;
								}
								if (jjitter.contains("value") == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.eb[%i].network_scenario.jitter.value\" key\n", ParamsFilePath.c_str(), i);
									return false;
								}
								// цикл по всем элементам params.eb[i].network_scenario.jitter
								for(auto& jjitter1 : jjitter.items())
								{
									if(jjitter1.key() == "timeup") // элемент params.eb[i].network_scenario.jitter.timeup
									{
										auto jtimeup = jjitter["timeup"];
										// проверить соответствие типа
										if(jtimeup.is_number() == false)
										{
											PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].network_scenario.jitter.timeup\" has a wrong type (required = number)\n", i);
											return false;
										}
										Params.EpsBearerList[id].NetworkScenario.Jitter.TimeUp = jtimeup.get<int>();
										PRINT_TMP(PRINT_LEVEL::MIDDLE, "          key: %s, type: number, value: %i\n", jjitter1.key().c_str(), Params.EpsBearerList[id].NetworkScenario.Jitter.TimeUp);
										// проверить корректность считанного значения
										if(Params.EpsBearerList[id].NetworkScenario.Jitter.TimeUp < 0)
										{
											PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].network_scenario.jitter.timeup\" must be a positiva value (current = %i)\n", i, Params.EpsBearerList[id].NetworkScenario.Jitter.TimeUp);
											return false;
										}
									}
									else if(jjitter1.key() == "timedown") // элемент params.eb[i].network_scenario.jitter.timedown
									{
										auto jtimedown = jjitter["timedown"];
										// проверить соответствие типа
										if(jtimedown.is_number() == false)
										{
											PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].network_scenario.jitter.timedown\" has a wrong type (required = number)\n", i);
											return false;
										}
										Params.EpsBearerList[id].NetworkScenario.Jitter.TimeDown = jtimedown.get<int>();
										PRINT_TMP(PRINT_LEVEL::MIDDLE, "          key: %s, type: number, value: %i\n", jjitter1.key().c_str(), Params.EpsBearerList[id].NetworkScenario.Jitter.TimeDown);
										// проверить корректность считанного значения
										if(Params.EpsBearerList[id].NetworkScenario.Jitter.TimeDown < 0)
										{
											PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].network_scenario.jitter.timedown\" must be a positiva value (current = %i)\n", i, Params.EpsBearerList[id].NetworkScenario.Jitter.TimeDown);
											return false;
										}
									}
									else if(jjitter1.key() == "value") // элемент params.eb[i].network_scenario.jitter.value
									{
										auto jvalue = jjitter["value"];
										// проверить соответствие типа
										if(jvalue.is_number() == false)
										{
											PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].network_scenario.jitter.value\" has a wrong type (required = number)\n", i);
											return false;
										}
										Params.EpsBearerList[id].NetworkScenario.Jitter.Value = jvalue.get<int>();
										PRINT_TMP(PRINT_LEVEL::MIDDLE, "          key: %s, type: number, value: %i\n", jjitter1.key().c_str(), Params.EpsBearerList[id].NetworkScenario.Jitter.Value);
										// проверить корректность считанного значения
										if(Params.EpsBearerList[id].NetworkScenario.Jitter.Value < 0)
										{
											PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].network_scenario.jitter.timedown\" must be a positiva value (current = %i)\n", i, Params.EpsBearerList[id].NetworkScenario.Jitter.Value);
											return false;
										}
									}
								}
							}
							else if(jns1.key() == "burst") // элемент params.eb[i].network_scenario.burst
							{
								auto jburst = jns["burst"];
								// проверить соответствие типа
								if(jburst.is_object() == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].network_scenario.burst\" has a wrong type (required = object)\n", i);
									return false;
								}
								PRINT_TMP(PRINT_LEVEL::MIDDLE, "        key: %s, type: object\n", jns1.key().c_str());
								// проверить наличие всех обязательных элементов внутри params.network_scenario[i].burst
								if (jburst.contains("timeup") == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.network_scenario[%i].burst.timeup\" key\n", ParamsFilePath.c_str(), i);
									return false;
								}
								if (jburst.contains("timedown") == false)
								{
									PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameters file %s has NO \"params.network_scenario[%i].burst.timedown\" key\n", ParamsFilePath.c_str(), i);
									return false;
								}
								// цикл по всем элементам params.network_scenario[i].burst
								for(auto& jburst1 : jburst.items())
								{
									if(jburst1.key() == "timeup") // элемент params.network_scenario[i].burst.timeup
									{
										auto jtimeup = jburst["timeup"];
										// проверить соответствие типа
										if(jtimeup.is_number() == false)
										{
											PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].network_scenario.burst.timeup\" has a wrong type (required = number)\n", i);
											return false;
										}
										Params.EpsBearerList[id].NetworkScenario.Burst.TimeUp = jtimeup.get<int>();
										PRINT_TMP(PRINT_LEVEL::MIDDLE, "          key: %s, type: number, value: %i\n", jburst1.key().c_str(), Params.EpsBearerList[id].NetworkScenario.Burst.TimeUp);
										// проверить корректность считанного значения
										if(Params.EpsBearerList[id].NetworkScenario.Burst.TimeUp < 0)
										{
											PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].network_scenario.burst.timeup\" must be a positiva value (current = %i)\n", i, Params.EpsBearerList[id].NetworkScenario.Burst.TimeUp);
											return false;
										}
									}
									else if(jburst1.key() == "timedown") // элемент params.eb[i].network_scenario.burst.timedown
									{
										auto jtimedown = jburst["timedown"];
										// проверить соответствие типа
										if(jtimedown.is_number() == false)
										{
											PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].network_scenario.burst.timedown\" has a wrong type (required = number)\n", i);
											return false;
										}
										Params.EpsBearerList[id].NetworkScenario.Burst.TimeDown = jtimedown.get<int>();
										PRINT_TMP(PRINT_LEVEL::MIDDLE, "          key: %s, type: number, value: %i\n", jburst1.key().c_str(), Params.EpsBearerList[id].NetworkScenario.Burst.TimeDown);
										// проверить корректность считанного значения
										if(Params.EpsBearerList[id].NetworkScenario.Burst.TimeDown < 0)
										{
											PRINT_ERR(PRINT_LEVEL::MIDDLE, "The parameter \"params.eb[%i].network_scenario.burst.timedown\" must be a positiva value (current = %i)\n", i, Params.EpsBearerList[id].NetworkScenario.Burst.TimeDown);
											return false;
										}
									}
								}
							}
						}
					}
				}
			}
		}
  }

#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif

  return true;
}

//------------------------------------------------------------------------------
bool GeneratorApp_c::WriteParams()
{
  std::ofstream ofs(ParamsFilePath);
  if(ofs.is_open() == false)
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "Cannot open for writing the parameters file %s\n", ParamsFilePath.c_str());
    return false;
  }
  PRINT_TMP(PRINT_LEVEL::MIDDLE, "The parameters file %s has been opened for writing\n", ParamsFilePath.c_str());

  std::lock_guard<std::mutex> lk(ParamsFileMutex);

#if USE_JSON_OPTION == USE_JSON_NLOHMANN
	int i;
	nlohmann::json jres;
  // подготовить параметры для записи в файл
	jres["params"]["mode"] = Params.Mode;
	jres["params"]["br"] = Params.Bitrate;
	jres["params"]["ipsrc"] = Params.IpSrc;
	jres["params"]["ipdst"] = Params.IpDst;
	jres["params"]["file"]["path"] = Params.File.Path;
	jres["params"]["file"]["size"] = Params.File.Size;
	jres["params"]["gtp"]["use"] = Params.Gtp.Use;
	jres["params"]["gtp"]["ipsrc"] = Params.Gtp.IpSrc;
	jres["params"]["gtp"]["ipdst"] = Params.Gtp.IpDst;
	jres["params"]["gtp"]["minteid"] = Params.Gtp.MinTeid;
	jres["params"]["gtp"]["maxteid"] = Params.Gtp.MaxTeid;
	jres["params"]["service"] = nlohmann::json::array();
	i = 0;
	for(auto& service: Params.ServiceList)
	{
		jres["params"]["service"][i]["id"] = service.second.Id;
		jres["params"]["service"][i]["name"] = service.second.Name;
		++i;
	}
	jres["params"]["app"] = nlohmann::json::array();
	i = 0;
	for(auto& app: Params.AppList)
	{
		jres["params"]["app"][i]["id"] = app.second.Id;
		jres["params"]["app"][i]["name"] = app.second.Name;
		++i;
	}
	jres["params"]["pcap"] = nlohmann::json::array();
	i = 0;
	for(auto& pcap: Params.PcapList)
	{
		jres["params"]["pcap"][i]["id"] = pcap.second.Id;
		jres["params"]["pcap"][i]["video"] = pcap.second.Video;
		jres["params"]["pcap"][i]["service"]["id"] = pcap.second.Service.Id;
		jres["params"]["pcap"][i]["app"]["id"] = pcap.second.App.Id;
		jres["params"]["pcap"][i]["br"] = pcap.second.Bitrate;
		jres["params"]["pcap"][i]["path"] = pcap.second.Path;
		++i;
	}
	jres["params"]["user_scenario"] = nlohmann::json::array();
	i = 0;
	for(auto& us: Params.UserScenarioList)
	{
		jres["params"]["user_scenario"][i]["id"] = us.second.Id;
		jres["params"]["user_scenario"][i]["name"] = us.second.Name;
		jres["params"]["user_scenario"][i]["br"] = us.second.Bitrate;
		jres["params"]["user_scenario"][i]["pcap_id"] = nlohmann::json::array();
		int j = 0;
		for(auto& pcap_id: us.second.Pcap)
		{
			jres["params"]["user_scenario"][i]["pcap_id"][j] = pcap_id.first;
			++j;
		}
		++i;
	}
	jres["params"]["network_scenario"] = nlohmann::json::array();
	i = 0;
	for(auto& ns: Params.NetworkScenarioList)
	{
		jres["params"]["network_scenario"][i]["id"] = ns.second.Id;
		jres["params"]["network_scenario"][i]["name"] = ns.second.Name;
		jres["params"]["network_scenario"][i]["jitter"]["timeup"] = ns.second.Jitter.TimeUp;
		jres["params"]["network_scenario"][i]["jitter"]["timedown"] = ns.second.Jitter.TimeDown;
		jres["params"]["network_scenario"][i]["jitter"]["value"] = ns.second.Jitter.Value;
		jres["params"]["network_scenario"][i]["burst"]["timeup"] = ns.second.Burst.TimeUp;
		jres["params"]["network_scenario"][i]["burst"]["timedown"] = ns.second.Burst.TimeDown;
		++i;
	}
	jres["params"]["eb"] = nlohmann::json::array();
	i = 0;
	for(auto& eb: Params.EpsBearerList)
	{
		jres["params"]["eb"][i]["id"] = eb.second.Id;
		jres["params"]["eb"][i]["br"] = eb.second.Bitrate;
		jres["params"]["eb"][i]["user_scenario"]["id"] = eb.second.UserScenario.Id;
		if(eb.second.UserScenario.Id == 0) // отправляем эти значения только для настраиваемого пользовательского сценария
		{
			jres["params"]["eb"][i]["user_scenario"]["name"] = eb.second.UserScenario.Name;
			jres["params"]["eb"][i]["user_scenario"]["br"] = eb.second.UserScenario.Bitrate;
			jres["params"]["eb"][i]["user_scenario"]["pcap_id"] = nlohmann::json::array();
			int j = 0;
			for(auto& pcap_id: eb.second.UserScenario.Pcap)
			{
				jres["params"]["eb"][i]["user_scenario"]["pcap_id"][j] = pcap_id.first;
				++j;
			}
		}
		jres["params"]["eb"][i]["network_scenario"]["id"] = eb.second.NetworkScenario.Id;
		if(eb.second.NetworkScenario.Id == 0) // отправляем эти значения только для настраиваемого сетевого сценария
		{
			jres["params"]["eb"][i]["network_scenario"]["name"] = eb.second.NetworkScenario.Name;
			jres["params"]["eb"][i]["network_scenario"]["jitter"]["timeup"] = eb.second.NetworkScenario.Jitter.TimeUp;
			jres["params"]["eb"][i]["network_scenario"]["jitter"]["timedown"] = eb.second.NetworkScenario.Jitter.TimeDown;
			jres["params"]["eb"][i]["network_scenario"]["jitter"]["value"] = eb.second.NetworkScenario.Jitter.Value;
			jres["params"]["eb"][i]["network_scenario"]["burst"]["timeup"] = eb.second.NetworkScenario.Burst.TimeUp;
			jres["params"]["eb"][i]["network_scenario"]["burst"]["timedown"] = eb.second.NetworkScenario.Burst.TimeDown;
		}
		++i;
	}
	// сохранить параметры в файле
	ofs << jres.dump(2) << std::endl;
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#else
illegal option
#endif

  return true;
}

//------------------------------------------------------------------------------
#if APP_MODE_OPTION == APP_MODE_MAIN // основной рабочий вариант программы
int GeneratorApp_c::Run(std::string http_srv_host, int http_srv_port)
{
  PRINT_LOG(PRINT_LEVEL::HIGH, "============================================================\n");
  PRINT_LOG(PRINT_LEVEL::HIGH, "the main version of Generator\n");

#if USE_CONTROL_OPTION == USE_CONTROL_TIMER // завершать программу через заданный интервал времени
    PRINT_MSG(PRINT_LEVEL::MIDDLE, "The application will run for 15 seconds. Wait...\n");
    std::this_thread::sleep_for(std::chrono::seconds(15));
#elif USE_CONTROL_OPTION == USE_CONTROL_STDIN // управление выполнением программы через команды с клавиатуры
  const int buffer_len = 512;
  std::unique_ptr<char[]> buffer = std::make_unique<char[]>(buffer_len);

  PRINT_MSG(PRINT_LEVEL::MIDDLE, "\nThe application is ready\n");
  PRINT_MSG(PRINT_LEVEL::MIDDLE, "\n"
    "Commands list:\n"
    "exit         - terminate the application\n"
    "list         - show commands list\n");

  while (std::fgets(buffer.get(), buffer_len, stdin))
  {
    if (std::strncmp(buffer.get(), "exit", strlen("exit")) == 0)
    {
      break;
    }
    else if (std::strncmp(buffer.get(), "list", strlen("list")) == 0)
    {
      PRINT_MSG(PRINT_LEVEL::MIDDLE, "\n"
        "Commands list:\n"
        "exit         - terminate application\n"
        "list         - show commands list\n");
    }
    else
    {
      PRINT_MSG(PRINT_LEVEL::MIDDLE, "\nUnknown command\n");
    }
  }
#elif USE_CONTROL_OPTION == USE_CONTROL_HTTP // HTTP-сервер управляет временем работы программы
  HttpServerHttplib_c http_server;
  http_server.Run(http_srv_host, http_srv_port,
    [this](const std::string& reqs, int* code) { return ResponseDeleteExit(reqs, code); },
    [this](const std::string& reqs, std::string& addr, std::string& port, int* code) { return ResponseGetInit(reqs, addr, port, code); },
    [this](const std::string& reqs, int* code) { return ResponseGetAlive(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponseGetState(reqs, code); },
		[this](const std::string& reqs, int* code) { return ResponsePutStateRun(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponseGetStatsEb(reqs, code); },
    [this](const std::string& reqs, int id, int* code) { return ResponseGetStatsEbN(reqs, id, code); },
    [this](const std::string& reqs, int* code) { return ResponseGetParams(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponsePutParams(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponseGetParamsCommon(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponsePutParamsCommon(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponseGetParamsService(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponseGetParamsApp(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponseGetParamsPcap(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponseGetParamsUserScenario(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponsePostParamsUserScenario(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponsePutParamsUserScenario(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponseDeleteParamsUserScenario(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponseGetParamsNetworkScenario(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponsePostParamsNetworkScenario(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponsePutParamsNetworkScenario(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponseDeleteParamsNetworkScenario(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponseGetParamsEb(reqs, code); },
    [this](const std::string& reqs, int id, int* code) { return ResponseGetParamsEb1(reqs, id, code); },
    [this](const std::string& reqs, int* code) { return ResponsePostParamsEb(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponsePutParamsEb(reqs, code); },
    [this](const std::string& reqs, int* code) { return ResponseDeleteParamsEb(reqs, code); }
    );
#else
illegal option
#endif

	return 0;
}
//******************************************************************************
#elif APP_MODE_OPTION == APP_MODE_TEST // экспериментальный вариант
int GeneratorApp_c::Run(std::string http_srv_host, int http_srv_port)
{
  PRINT_LOG(PRINT_LEVEL::HIGH, "============================================================\n");
  PRINT_LOG(PRINT_LEVEL::HIGH, "the experimental version of Generator\n");

	return 0;
}
//******************************************************************************
#elif APP_MODE_OPTION == APP_MODE_SEND // проверка скорости работы толькл по отправке пакетов
int GeneratorApp_c::Run(std::string http_srv_host, int http_srv_port)
{
  PRINT_LOG(PRINT_LEVEL::HIGH, "============================================================\n");
  PRINT_LOG(PRINT_LEVEL::HIGH, "testing the speed of packets sending\n");

	return 0;
}
//******************************************************************************
#elif APP_MODE_OPTION == APP_MODE_READ // проверка скорости работы по чтению пакетов
int GeneratorApp_c::Run(std::string http_srv_host, int http_srv_port)
{
  PRINT_LOG(PRINT_LEVEL::HIGH, "============================================================\n");
  PRINT_LOG(PRINT_LEVEL::HIGH, "testing the speed of packets reading\n");
  
	return 0;
}
#else
illegal option APP_MODE_OPTION
#endif