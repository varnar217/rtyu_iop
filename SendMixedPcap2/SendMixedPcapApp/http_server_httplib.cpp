#include "Global.h"
#include "Log.h"
#include "DateTime.h"
#include "common.h"
#include "http_server_httplib.h"
#include "http_server_api.h"

//------------------------------------------------------------------------------
HttpServerHttplib_c::HttpServerHttplib_c()
{
	
}

//------------------------------------------------------------------------------
void HttpServerHttplib_c::Run(std::string http_srv_host, int http_srv_port,
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
    )
{
  // инициализация функций обратного вызова для обработки HTTP-запросов
  ResponseDeleteExit = response_delete_exit;
  ResponseGetInit = response_get_init;
  ResponseGetAlive = response_get_alive;
  ResponseGetState = response_get_state;
  ResponsePutStateRun = response_put_state_run;
  ResponseGetStatsEb = response_get_stats_eb;
  ResponseGetStatsEbN = response_get_stats_eb_n;
  ResponseGetParams = response_get_params;
  ResponsePutParams = response_put_params;
  ResponseGetParamsCommon = response_get_params_common;
  ResponsePutParamsCommon = response_put_params_common;
  ResponseGetParamsService = response_get_params_service;
  ResponseGetParamsApp = response_get_params_app;
  ResponseGetParamsPcap = response_get_params_pcap;
  ResponseGetParamsUserScenario = response_get_params_user_scenario;
  ResponsePostParamsUserScenario = response_post_params_user_scenario;
  ResponsePutParamsUserScenario = response_put_params_user_scenario;
  ResponseDeleteParamsUserScenario = response_delete_params_user_scenario;
  ResponseGetParamsNetworkScenario = response_get_params_network_scenario;
  ResponsePostParamsNetworkScenario = response_post_params_network_scenario;
  ResponsePutParamsNetworkScenario = response_put_params_network_scenario;
  ResponseDeleteParamsNetworkScenario = response_delete_params_network_scenario;
  ResponseGetParamsEb = response_get_params_eb;
  ResponseGetParamsEb1 = response_get_params_eb_1;
  ResponsePostParamsEb = response_post_params_eb;
  ResponsePutParamsEb = response_put_params_eb;
  ResponseDeleteParamsEb = response_delete_params_eb;
  
  // HTTP
  httplib::Server svr;
  // HTTPS
  //httplib::SSLServer svr;
  
  svr.Delete("/exit", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: delete(/exit)\n");
    int code;
    std::string ress = ResponseDeleteExit(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
    svr.stop();
  });
  
  svr.Get("/init", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: get(/init)\n");
    std::string addr;
    std::string port;
    if(req.has_param("addr"))
      addr = req.get_param_value("addr");
    if(req.has_param("port"))
      port = req.get_param_value("port");
    int code;
    std::string ress = ResponseGetInit(req.body, addr, port, &code);
    res.status = code;
    res.set_content(ress, "application/json");
    //res.status = 201;
  });
  
  svr.Get("/state", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: get(/state)\n");
    int code;
    std::string ress = ResponseGetState(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Get("/alive", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: get(/alive)\n");
    int code;
    std::string ress = ResponseGetAlive(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Put("/state/run", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: put(/state/run)\n");
    int code;
    std::string ress = ResponsePutStateRun(req.body, &code);
    res.status = code;
    //PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: before set_content\n");
    res.set_content(ress, "application/json");
    //PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: after set_content\n");
    //auto j = nlohmann::json::parse(req.body);
    //rapidjson::Document d;
    //d.Parse(req.body.c_str());
    //rapidjson::Value& nob = d["nob"];
    //PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: post(num_of_bearers) nob = %i\n", nob.GetInt());
    
    // req.body - std::string
    // Params params - std::multimap<std::string, std::string>:
    //    bool has_param(const char *key) const;
    //    std::string get_param_value(const char *key, size_t id = 0) const;
    //    size_t get_param_value_count(const char *key) const;
    // Headers headers - std::multimap<std::string, std::string, detail::ci>
    //      bool has_header(const char *key) const;
    //      std::string get_header_value(const char *key, size_t id = 0) const;
    //      template <typename T>
    //      T get_header_value(const char *key, size_t id = 0) const;
    //      size_t get_header_value_count(const char *key) const;
  });

  svr.Get(R"(/stats/eb)", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: get(/stats/eb)\n");
    int code;
    std::string ress = ResponseGetStatsEb(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Get(R"(/stats/eb/(\d+))", [&](const httplib::Request& req, httplib::Response& res) {
    std::string ids = req.matches[1];
    int id = std::stoi(ids);
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: get(/stats/eb/%i)\n", id);
    int code;
    std::string ress = ResponseGetStatsEbN(req.body, id, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Get("/params", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: get(/params)\n");
    int code;
    std::string ress = ResponseGetParams(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Put("/params", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: put(/params)\n");
    int code;
    std::string ress = ResponsePutParams(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Get("/params/common", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: get(/params/common)\n");
    int code;
    std::string ress = ResponseGetParamsCommon(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Put("/params/common", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: put(/params/common)\n");
    int code;
    std::string ress = ResponsePutParamsCommon(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Get("/params/service", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: get(/params/service)\n");
    int code;
    std::string ress = ResponseGetParamsService(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Get("/params/app", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: get(/params/app)\n");
    int code;
    std::string ress = ResponseGetParamsApp(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Get("/params/pcap", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: get(/params/pcap)\n");
    int code;
    std::string ress = ResponseGetParamsPcap(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Get("/params/user_scenario", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: get(/params/user_scenario)\n");
    int code;
    std::string ress = ResponseGetParamsUserScenario(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Post("/params/user_scenario", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: post(/params/user_scenario)\n");
    int code;
    std::string ress = ResponsePostParamsUserScenario(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Put("/params/user_scenario", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: put(/params/user_scenario)\n");
    int code;
    std::string ress = ResponsePutParamsUserScenario(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Delete("/params/user_scenario", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: delete(/params/user_scenario)\n");
    int code;
    std::string ress = ResponseDeleteParamsUserScenario(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Get("/params/network_scenario", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: get(/params/network_scenario)\n");
    int code;
    std::string ress = ResponseGetParamsNetworkScenario(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Post("/params/network_scenario", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: post(/params/network_scenario)\n");
    int code;
    std::string ress = ResponsePostParamsNetworkScenario(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Put("/params/network_scenario", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: put(/params/network_scenario)\n");
    int code;
    std::string ress = ResponsePutParamsNetworkScenario(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Delete("/params/network_scenario", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: delete(/params/network_scenario)\n");
    int code;
    std::string ress = ResponseDeleteParamsNetworkScenario(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Get("/params/eb", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: get(/params/eb)\n");
    int code;
    std::string ress = ResponseGetParamsEb(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });

  svr.Get(R"(/params/eb/(\d+))", [&](const httplib::Request& req, httplib::Response& res) {
    std::string ids = req.matches[1];
    int id = std::stoi(ids);
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: get(/params/eb/%i)\n", id);
    int code;
    std::string ress = ResponseGetParamsEb1(req.body, id, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Post("/params/eb", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: post(/params/eb)\n");
    int code;
    std::string ress = ResponsePostParamsEb(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Put("/params/eb", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: put(/params/eb)\n");
    int code;
    std::string ress = ResponsePutParamsEb(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
  svr.Delete("/params/eb", [&](const httplib::Request& req, httplib::Response& res) {
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER: delete(/params/eb)\n");
    int code;
    std::string ress = ResponseDeleteParamsEb(req.body, &code);
    res.status = code;
    res.set_content(ress, "application/json");
  });
  
#if 0
  if(http_srv_port == 0)
  {
    svr.bind_to_port(http_srv_host.c_str(), http_srv_port);
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER is running on host=%s and any port\n", http_srv_host.c_str());
  }
  else
  {
    svr.bind_to_any_port(http_srv_host.c_str());
    PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER is running on host=%s and port=%i\n", http_srv_host.c_str(), http_srv_port);
  }
  svr.listen_after_bind();
#else
  PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER is running...\n");
  svr.listen("0.0.0.0", 8080);
#endif
  PRINT_LOG(PRINT_LEVEL::HIGH, "HTTP_SERVER shut down\n");
}