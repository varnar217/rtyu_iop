#include "Global.h"
#include "Log.h"
#include "DateTime.h"
#include "generator_app.h"
#include <string.h>

// дата построения пиррложения Ядра ГТО
const char* Version_Date = __DATE__;
// время построения пиррложения Ядра ГТО
const char* Version_Time = __TIME__;

int main(int argc, char **argv)
{
	// вывести версию приложения, если задан единственный параметр командной строки "-v"
  if(argc == 2 && strcmp(argv[1], "-v") == 0)
  {
		PRINT_MSG(PRINT_LEVEL::MIDDLE, "Version built on %s at %s\n", Version_Date, Version_Time);
    //PRINT_ERR(PRINT_LEVEL::MIDDLE, "Version built on %s\n", VERSION.c_str());
    return 0;
  }
#if ELIJA_TODO // разобраться с привязкой HTTP-сервер к адресу и порту и нужно ли это
  //if(argc != 3)
  //{
  //  PRINT_ERR(PRINT_LEVEL::MIDDLE, "Set required parameters: http_server_host (any=0.0.0.0), http_server_port (any=0)\n");
  //  return 1;
  //}
  std::string http_srv_host;// (argv[1]);
  int http_srv_port;// = std::stoi(argv[2]);
#endif
  //PRINT_MSG(PRINT_LEVEL::MIDDLE, "Used parameters: http_server_host=%s, http_server_port=%i\n", http_srv_host.c_str(), http_srv_port);
  GeneratorApp_c generator_app;
  return generator_app.Run(http_srv_host, http_srv_port);
}
