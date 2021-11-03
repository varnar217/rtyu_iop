/**
 * @file http_server_api.h
 * @author elija
 * @date 11/10/21
 * @brief приложение Ядра Генератора тестовых образцов (ГТО)
 */
#pragma once
#include "socket_sender.h"
#include "http_server_httplib.h"
#include <memory>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include "common.h"

#if __cplusplus > 201703L // C++20
#include <semaphore>
#endif

/**
 * @class GeneratorApp_c
 * @brief класс реализации приложения Ядра Генератора тестовых образцов (ГТО)
 */
class GeneratorApp_c
{
public:
  GeneratorApp_c();
  ~GeneratorApp_c();

  // функции для обработки HTTP-запросов от Интерфейса ГТО
  std::string ResponseDeleteExit(const std::string& reqs, int* code);
  std::string ResponseGetInit(const std::string& reqs, std::string& addr, std::string& port, int* code);
  std::string ResponseGetAlive(const std::string& reqs, int* code);
  std::string ResponseGetState(const std::string& reqs, int* code);
  std::string ResponsePutStateRun(const std::string& reqs, int* code);
  std::string ResponseGetStatsEb(const std::string& reqs, int* code);
  std::string ResponseGetStatsEbN(const std::string& reqs, int id, int* code);
  std::string ResponseGetParams(const std::string& reqs, int* code);
  std::string ResponsePutParams(const std::string& reqs, int* code);
  std::string ResponseGetParamsCommon(const std::string& reqs, int* code);
  std::string ResponsePutParamsCommon(const std::string& reqs, int* code);
  std::string ResponseGetParamsService(const std::string& reqs, int* code);
  std::string ResponseGetParamsApp(const std::string& reqs, int* code);
  std::string ResponseGetParamsPcap(const std::string& reqs, int* code);
  std::string ResponseGetParamsUserScenario(const std::string& reqs, int* code);
  std::string ResponsePostParamsUserScenario(const std::string& reqs, int* code);
  std::string ResponsePutParamsUserScenario(const std::string& reqs, int* code);
  std::string ResponseDeleteParamsUserScenario(const std::string& reqs, int* code);
  std::string ResponseGetParamsNetworkScenario(const std::string& reqs, int* code);
  std::string ResponsePostParamsNetworkScenario(const std::string& reqs, int* code);
  std::string ResponsePutParamsNetworkScenario(const std::string& reqs, int* code);
  std::string ResponseDeleteParamsNetworkScenario(const std::string& reqs, int* code);
  std::string ResponseGetParamsEb(const std::string& reqs, int* code);
  std::string ResponseGetParamsEb1(const std::string& reqs, int id, int* code);
  std::string ResponsePostParamsEb(const std::string& reqs, int* code);
  std::string ResponsePutParamsEb(const std::string& reqs, int* code);
  std::string ResponseDeleteParamsEb(const std::string& reqs, int* code);

	bool AddEpsBearer(std::map<int, GeneratorParams_s::EpsBearer_s>& elist);

  // запустить работу Ядра ГТО
  bool Start();

  // остановить работу Ядра ГТО
  bool Stop();

  // получить параметры работы Генератора из JSON файла и записать их в Params
  bool ReadParams();
  // сохранить параметры работы Генератора из Params в JSON файл
  bool WriteParams();

  // запустить цикл жизни Генератора
  int Run(std::string http_srv_host, int http_srv_port);
  
private:
	// требование завершения работы
	std::atomic_bool StopFlag;

  // упорядоченные по времени пакеты от каждого из всех PcapReader_c
  std::list<std::shared_ptr<EpsBearerPacket_s>> Packets;
  // разграничение доступа к очереди пакетов Packets из разных потоков
#if USE_TMP_DEBUG_SYNCHRO_OPTION == USE_TMP_DEBUG_SYNCHRO_MUTEX
  std::mutex PacketsMutex;
  // сигнализация между потоками
  //bool GetPacketFlag{true};
  //bool ReadPacketFlag{false};
  //std::condition_variable ReadPacketCv;
  //std::condition_variable GetPacketCv;
  std::atomic_bool GetPacketFlag{true};
  std::atomic_bool ReadPacketFlag{false};
#elif USE_TMP_DEBUG_SYNCHRO_OPTION == USE_TMP_DEBUG_SYNCHRO_ATOMIC
  std::atomic_flag PacketsCondAtomicFlag;
#elif USE_TMP_DEBUG_SYNCHRO_OPTION == USE_TMP_DEBUG_SYNCHRO_SEMAPHORE
  std::counting_semaphore<1> PacketsSignal{1};
#endif

	// взять из очереди пакетов пакет с самой ранней временной меткой
  std::shared_ptr<EpsBearerPacket_s> GetPacket();
	// функция потока получения нового пакета и помещения его в очередь пакетов в соовтветствии с его временной меткой
	void ReadPacket(int thread_id);
	// пул потоков для получения новых пакетов
	std::vector<std::thread> ReadPacketThreads;
	// количество потоков в пуле ReadPacketThreads
	int ReadPacketThreadsNum{0};

  // параметры работы Генератора
  GeneratorParams_s Params;
  // разграничение доступа к параметрам Генератора Params из разных потоков
  std::mutex ParamsMutex;

  // состояние Генератора
  GeneratorState_s State;

  // IP адрес Интерфейса (заполняется после получения приветственного запроса GET(/init?addr=&port=))
  std::string GuiAddr{"127.0.0.1"};
  // порт Интерфейса (заполняется после получения приветственного запроса GET(/init?addr=&port=))
  int GuiPort{8080};

  // JSON файл с параметрами работы
  std::string ParamsFilePath{"../../GeneratorParams.json"};
  // разграничение доступа к JSON файлу с параметрами работы из разных потоков
  std::mutex ParamsFileMutex;

  // единственный экземпляр PacketSender_c (забирает пакеты из Packets через GetPacket())
  std::shared_ptr<PacketSender_c> Sender;
};

