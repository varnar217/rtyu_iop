#include "Global.h"
#include "Log.h"
#include "DateTime.h"
#include "common.h"
#include <thread>
#include <iostream>
#include "http_server_api.h"

//==============================================================================
// HTTP-клиент для отправки сообщений с Генератора на Интерфейс по инициативе Генератора
HttpClient_c HttpClient;

//------------------------------------------------------------------------------
void HttpClient_c::Open(const char* addr, int port)
{
  std::lock_guard<std::mutex> lk(ClientMutex);
  Client = std::make_unique<httplib::Client>(addr, port);
}

//------------------------------------------------------------------------------
void HttpClient_c::SendErr(std::string& msg)
{
  std::lock_guard<std::mutex> lk(ClientMutex);
  if(Client)
  {
    nlohmann::json jres;
    jres["err"]["code"] = 1;
    jres["err"]["msg"] = msg.c_str();
    jres["err"]["time"] = DateTime::GetEpochTimeStringHTP();
    Client->Post("/err", jres.dump(2), "application/json");
  }
}

//==============================================================================
bool thread_to_core(int coreID)
{
  short status=0;
  int nThreads = std::thread::hardware_concurrency();
  cpu_set_t set;
  CPU_ZERO(&set);

  if(coreID < 0 || coreID >= nThreads)
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "Wrong core id number (current=%i, required=[0,%i])\n", coreID, nThreads);
    return false;
  }

  CPU_SET(coreID,&set);
  if(sched_setaffinity(0, sizeof(cpu_set_t), &set) < 0)
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "Unable to Set Affinity\n");
    return false;
  }
  return true;
}
