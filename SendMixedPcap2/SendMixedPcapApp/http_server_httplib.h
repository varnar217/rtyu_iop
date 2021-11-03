/**
 * @file http_server_httplib.h
 * @author elija
 * @date 06/10/21
 * @brief HTTP-сервер из библиотеки cpp-httplib для приёма и обработки команд от интерфейса через REST API (HTTP-запросы)
 * https://github.com/yhirose/cpp-httplib/tree/master
 */
#pragma once

//#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "httplib.h"
#include "http_server_api.h"
#include <functional>
#include <mutex>

//------------------------------------------------------------------------------
/**
 * @class HttpServerHttplib_c
 * @brief класс реализации HTTP-сервера из библиотеки cpp-httplib
 * 
 * HTTP-сервер принимает и обрабатывает запросы от Интерфейса ГТО в манере REST API
 */
class HttpServerHttplib_c {
public:
  HttpServerHttplib_c();
  ~HttpServerHttplib_c() = default;
  
  // запуск цикла жизни HTTP-сервера
  void Run(std::string http_srv_host, int http_srv_port,
    std::function<std::string(const std::string&,int*)> response_delete_exit,
    std::function<std::string(const std::string&,std::string&,std::string&,int*)> response_get_init,
    std::function<std::string(const std::string&,int*)> response_get_alive,
    std::function<std::string(const std::string&,int*)> response_get_state,
    std::function<std::string(const std::string&,int*)> response_put_state_run,
    std::function<std::string(const std::string&,int*)> response_get_stats_eb,
    std::function<std::string(const std::string&,int,int*)> response_get_stats_eb_n,
    std::function<std::string(const std::string&,int*)> response_get_params,
    std::function<std::string(const std::string&,int*)> response_put_params,
    std::function<std::string(const std::string&,int*)> response_get_params_common,
    std::function<std::string(const std::string&,int*)> response_put_params_common,
    std::function<std::string(const std::string&,int*)> response_get_params_service,
    std::function<std::string(const std::string&,int*)> response_get_params_app,
    std::function<std::string(const std::string&,int*)> response_get_params_pcap,
    std::function<std::string(const std::string&,int*)> response_get_params_user_scenario,
    std::function<std::string(const std::string&,int*)> response_post_params_user_scenario,
    std::function<std::string(const std::string&,int*)> response_put_params_user_scenario,
    std::function<std::string(const std::string&,int*)> response_delete_params_user_scenario,
    std::function<std::string(const std::string&,int*)> response_get_params_network_scenario,
    std::function<std::string(const std::string&,int*)> response_post_params_network_scenario,
    std::function<std::string(const std::string&,int*)> response_put_params_network_scenario,
    std::function<std::string(const std::string&,int*)> response_delete_params_network_scenario,
    std::function<std::string(const std::string&,int*)> response_get_params_eb,
    std::function<std::string(const std::string&,int,int*)> response_get_params_eb_1,
    std::function<std::string(const std::string&,int*)> response_post_params_eb,
    std::function<std::string(const std::string&,int*)> response_put_params_eb,
    std::function<std::string(const std::string&,int*)> response_delete_params_eb
    );
  
  // функции обратного вызова для обработки HTTP_запросов от Интерфейса ГТО
  std::function<std::string(const std::string&,int*)> ResponseDeleteExit;
  std::function<std::string(const std::string&,std::string&,std::string&,int*)> ResponseGetInit;
  std::function<std::string(const std::string&,int*)> ResponseGetAlive;
  std::function<std::string(const std::string&,int*)> ResponseGetState;
  std::function<std::string(const std::string&,int*)> ResponsePutStateRun;
  std::function<std::string(const std::string&,int*)> ResponseGetStatsEb;
  std::function<std::string(const std::string&,int,int*)> ResponseGetStatsEbN;
  std::function<std::string(const std::string&,int*)> ResponseGetParams;
  std::function<std::string(const std::string&,int*)> ResponsePutParams;
  std::function<std::string(const std::string&,int*)> ResponseGetParamsCommon;
  std::function<std::string(const std::string&,int*)> ResponsePutParamsCommon;
  std::function<std::string(const std::string&,int*)> ResponseGetParamsService;
  std::function<std::string(const std::string&,int*)> ResponseGetParamsApp;
  std::function<std::string(const std::string&,int*)> ResponseGetParamsPcap;
  std::function<std::string(const std::string&,int*)> ResponseGetParamsUserScenario;
  std::function<std::string(const std::string&,int*)> ResponsePostParamsUserScenario;
  std::function<std::string(const std::string&,int*)> ResponsePutParamsUserScenario;
  std::function<std::string(const std::string&,int*)> ResponseDeleteParamsUserScenario;
  std::function<std::string(const std::string&,int*)> ResponseGetParamsNetworkScenario;
  std::function<std::string(const std::string&,int*)> ResponsePostParamsNetworkScenario;
  std::function<std::string(const std::string&,int*)> ResponsePutParamsNetworkScenario;
  std::function<std::string(const std::string&,int*)> ResponseDeleteParamsNetworkScenario;
  std::function<std::string(const std::string&,int*)> ResponseGetParamsEb;
  std::function<std::string(const std::string&,int,int*)> ResponseGetParamsEb1;
  std::function<std::string(const std::string&,int*)> ResponsePostParamsEb;
  std::function<std::string(const std::string&,int*)> ResponsePutParamsEb;
  std::function<std::string(const std::string&,int*)> ResponseDeleteParamsEb;
};

