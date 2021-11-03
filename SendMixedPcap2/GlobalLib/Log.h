#pragma once
/*!
\file Log.h
\brief
\~russian Описания функций вывода сообщений с предупреждениями, ошибками, логами и просто информацией

\~russian ELIJA_TODO
*/
#include "Global.h"
#include <functional>
#include <mutex>

extern std::recursive_mutex PrintMutex; // разграничение доступа из разных потоков

#if ELIJA_WARNING // а что делать со случаями когда сообщение должно быть больше MAX_MSG_LEN char и как вообще отслеживать выход за границы MAX_MSG_LEN char?
const int MAX_MSG_LEN = 65536; // максимальная длина сообщения
#endif

enum PRINT_LEVEL
{
  MIN = 1, // почти ничего не выводить
  VERY_LOW = 5,
  LOW = 20,
  MIDDLE = 50,
  HIGH = 70,
  VERY_HIGH = 90,
  MAX = 99 // выводить почти всё
};

extern void (*PRINT_TMP)(const int level, const char *format, ...); //!< \~russian напечатать сообщение, которое должно быть удалено в релизной версии продукта \~english print debug
extern void (*PRINT_MSG)(const int level, const char *format, ...); //!< \~russian напечатать полезное информационное сообщение \~english print useful info
extern void (*PRINT_ERR)(const int level, const char *format, ...); //!< \~russian напечатать сообщение об ошибке \~english print error
extern void (*PRINT_WRN)(const int level, const char *format, ...); //!< \~russian напечатать сообщение о предупреждении \~english print warning
extern void (*PRINT_LOG)(const int level, const char *format, ...); //!< \~russian напечатать сопровождающее сообщение \~english print verbose info
extern void (*PRINT_DBG)(const int level, const char *format, ...); //!< \~russian напечатать отладочное сообщение \~english print debug
extern void (*PRINT_TO_FILE)(const int level, const char *format, ...);


/*
template <class ... Args>
void PRINT_MSG(const int level, const char *format, Args ... args)
{
  std::lock_guard<std::recursive_mutex> lck(PrintMutex);
  printf(format, args...);
}
*/

#if ! ELIJA_TMP
#include <mutex>
#include <iostream>
#include <utility>

extern std::recursive_mutex PrintMutex;

template<typename First, typename ...Rest>
void PRINT_MSG(First && first, Rest && ...rest)
{
  std::lock_guard<std::recursive_mutex> lck(PrintMutex);
  std::cout << std::forward<First>(first);
  PRINT_MSG(std::forward<Rest>(rest)...);
}

template<typename First, typename ...Rest>
void PRINT_ERR(First && first, Rest && ...rest)
{
  std::lock_guard<std::recursive_mutex> lck(PrintMutex);
  std::cout << std::forward<First>(first);
  PRINT_ERR(std::forward<Rest>(rest)...);
}

template<typename First, typename ...Rest>
void PRINT_WRN(First && first, Rest && ...rest)
{
  std::lock_guard<std::recursive_mutex> lck(PrintMutex);
  std::cout << std::forward<First>(first);
  PRINT_WRN(std::forward<Rest>(rest)...);
}

template<typename First, typename ...Rest>
void PRINT_LOG(First && first, Rest && ...rest)
{
  std::lock_guard<std::recursive_mutex> lck(PrintMutex);
  std::cout << std::forward<First>(first);
  PRINT_LOG(std::forward<Rest>(rest)...);
}

template<typename First, typename ...Rest>
void PRINT_DBG(First && first, Rest && ...rest)
{
  std::lock_guard<std::recursive_mutex> lck(PrintMutex);
  std::cout << std::forward<First>(first);
  PRINT_DBG(std::forward<Rest>(rest)...);
}
#endif

#if ! ELIJA_TMP
class Log
{
public:
  static Log& Instance()
  {
    static Log theSingleInstance;
    return theSingleInstance;
  }

  void(*PRINT_MSG)(const int level, const char *format, ...); //!< \~russian напечатать полезное информационное сообщение \~english print useful info
  void(*PRINT_ERR)(const int level, const char *format, ...); //!< \~russian напечатать сообщение об ошибке \~english print error
  void(*PRINT_WRN)(const int level, const char *format, ...); //!< \~russian напечатать сообщение о предупреждении \~english print warning
  void(*PRINT_LOG)(const int level, const char *format, ...); //!< \~russian напечатать сопровождающее сообщение \~english print verbose info
  void(*PRINT_DBG)(const int level, const char *format, ...); //!< \~russian напечатать отладочное сообщение \~english print debug

private:
  Log()
  {
    PRINT_MSG = PRINT_MSG_PRINTF;
    PRINT_ERR = PRINT_ERR_PRINTF;
    PRINT_WRN = PRINT_WRN_PRINTF;
    PRINT_LOG = PRINT_LOG_PRINTF;
    PRINT_DBG = PRINT_DBG_PRINTF;
  }
  ~Log() = default;
  Log(const Log& root) = delete;
  Log& operator=(const Log&) = delete;
};
#endif
