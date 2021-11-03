/*!
\file Log.cpp
\brief
\~russian Определения функций вывода сообщений с предупреждениями, ошибками, логами и просто информацией

\~russian ELIJA_TODO
*/

#include "Global.h"
#include "Log.h"
#include "DateTime.h"
#include <cstdarg> 
#include <cstdio>
#include <mutex>

void PRINT_TMP_PRINTF_DEFAULT(const int level, const char *format, ...); // вариант по умолчанию, который можно переопределить в программе
void PRINT_MSG_PRINTF_DEFAULT(const int level, const char *format, ...); // вариант по умолчанию, который можно переопределить в программе
void PRINT_ERR_PRINTF_DEFAULT(const int level, const char *format, ...); // вариант по умолчанию, который можно переопределить в программе
void PRINT_WRN_PRINTF_DEFAULT(const int level, const char *format, ...); // вариант по умолчанию, который можно переопределить в программе
void PRINT_LOG_PRINTF_DEFAULT(const int level, const char *format, ...); // вариант по умолчанию, который можно переопределить в программе
void PRINT_DBG_PRINTF_DEFAULT(const int level, const char *format, ...); // вариант по умолчанию, который можно переопределить в программе
void PRINT_TO_FILE_FPRINTF_DEFAULT(const int level, const char *format, ...); // вариант по умолчанию, который можно переопределить в программе

void(*PRINT_TMP)(const int level, const char *format, ...)=PRINT_TMP_PRINTF_DEFAULT; //!< \~russian напечатать полезное информационное сообщение \~english print temporary info
void(*PRINT_MSG)(const int level, const char *format, ...)=PRINT_MSG_PRINTF_DEFAULT; //!< \~russian напечатать полезное информационное сообщение \~english print useful info
void(*PRINT_ERR)(const int level, const char *format, ...)=PRINT_ERR_PRINTF_DEFAULT; //!< \~russian напечатать сообщение об ошибке \~english print error
void(*PRINT_WRN)(const int level, const char *format, ...)=PRINT_WRN_PRINTF_DEFAULT; //!< \~russian напечатать сообщение о предупреждении \~english print warning
void(*PRINT_LOG)(const int level, const char *format, ...)=PRINT_LOG_PRINTF_DEFAULT; //!< \~russian напечатать сопровождающее сообщение \~english print verbose info
void(*PRINT_DBG)(const int level, const char *format, ...)=PRINT_DBG_PRINTF_DEFAULT; //!< \~russian напечатать отладочное сообщение \~english print debug
void(*PRINT_TO_FILE)(const int level, const char *format, ...)=PRINT_TO_FILE_FPRINTF_DEFAULT;

#if OSID==OSID_WINDOWS || OSID==OSID_LINUX
#define LOGV(...) (printf(__VA_ARGS__))
#define LOGD(...) (printf(__VA_ARGS__))
#define LOGI(...) (printf(__VA_ARGS__))
#define LOGW(...) (printf(__VA_ARGS__))
#define LOGE(...) (printf(__VA_ARGS__))
#elif OSID==OSID_ANDROID
#include <android/log.h>
/*
Log.e: This is for when bad stuff happens. Use this tag in places like inside a catch statement. You know that an error has occurred and therefore you're logging an error.
Log.w: Use this when you suspect something shady is going on. You may not be completely in full on error mode, but maybe you recovered from some unexpected behavior. Basically, use this to log stuff you didn't expect to happen but isn't necessarily an error. Kind of like a "hey, this happened, and it's weird, we should look into it."
Log.i: Use this to post useful information to the log. For example: that you have successfully connected to a server. Basically use it to report successes.
Log.d: Use this for debugging purposes. If you want to print out a bunch of messages so you can log the exact flow of your program, use this. If you want to keep a log of variable values, use this.
Log.v: Use this when you want to go absolutely nuts with your logging. If for some reason you've decided to log every little thing in a particular part of your app, use the Log.v tag.
*/
#define LOGV(...) ((void)__android_log_print(ANDROID_LOG_VERBOSE, "Ravis", __VA_ARGS__))
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG  , "Ravis", __VA_ARGS__))
#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO   , "Ravis", __VA_ARGS__))
#define LOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN   , "Ravis", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR  , "Ravis", __VA_ARGS__))
#endif

// файл журнала сообщений
static FILE* LogFile = NULL;
// имя и местоположение файла журнала сообщений
static const char* LogFilePath = "./generator_log.txt";

std::recursive_mutex PrintMutex; // разграничение доступа из разных потоков

//-----------------------------------------------------------------------------
// продублировать сообщение в журнал
static void REPLICATE_TO_FILE(const char* msg)
{
  if(LogFile == NULL)
  {
    LogFile = fopen(LogFilePath, "at");
    if (LogFile)
    {
      fprintf(LogFile, "************************************************************\n");
      fprintf(LogFile, "%s: Session started\n", DateTime::GetEpochTimeStringHTP().c_str());
      fflush(LogFile);
    }
  }
  if (LogFile)
  {
    fprintf(LogFile, "%s: %s", DateTime::GetEpochTimeStringHTP().c_str(), msg);
    fflush(LogFile);
  }
}

//-----------------------------------------------------------------------------
// вариант по умолчанию, который можно переопределить в программе
// \~russian , которое должно быть удалено в релизной версии \~english print temporary info
void PRINT_TMP_PRINTF_DEFAULT(const int level, const char *format, ...)
{
  char msg[MAX_MSG_LEN];
  va_list vargs;
  va_start(vargs, format);
  vsnprintf(msg, MAX_MSG_LEN, format, vargs);
  va_end(vargs);
  std::lock_guard<std::recursive_mutex> lck(PrintMutex);
  LOGI("%s", msg);
}

//-----------------------------------------------------------------------------
// вариант по умолчанию, который можно переопределить в программе
// \~russian напечатать полезное информационное сообщение \~english print useful info
void PRINT_MSG_PRINTF_DEFAULT(const int level, const char *format, ...)
{
  char msg[MAX_MSG_LEN];
  va_list vargs;
  va_start(vargs, format);
  vsnprintf(msg, MAX_MSG_LEN, format, vargs);
  va_end(vargs);
  std::lock_guard<std::recursive_mutex> lck(PrintMutex);
  LOGI("%s", msg);
}

//-----------------------------------------------------------------------------
// вариант по умолчанию, который можно переопределить в программе
// \~russian напечатать сообщение об ошибке \~english print error
void PRINT_ERR_PRINTF_DEFAULT(const int level, const char *format, ...)
{
  char msg[MAX_MSG_LEN];
  va_list vargs;
  va_start(vargs, format);
  vsnprintf(msg, MAX_MSG_LEN, format, vargs);
  va_end(vargs);
  std::lock_guard<std::recursive_mutex> lck(PrintMutex);
  LOGE("%s", msg);
	REPLICATE_TO_FILE(msg);
}

//-----------------------------------------------------------------------------
// вариант по умолчанию, который можно переопределить в программе
// \~russian напечатать сообщение о предупреждении \~english print warning
void PRINT_WRN_PRINTF_DEFAULT(const int level, const char *format, ...)
{
  char msg[MAX_MSG_LEN];
  va_list vargs;
  va_start(vargs, format);
  vsnprintf(msg, MAX_MSG_LEN, format, vargs);
  va_end(vargs);
  std::lock_guard<std::recursive_mutex> lck(PrintMutex);
  LOGW("%s", msg);
}

//-----------------------------------------------------------------------------
// вариант по умолчанию, который можно переопределить в программе
// \~russian напечатать сопровождающее сообщение \~english print verbose info
void PRINT_LOG_PRINTF_DEFAULT(const int level, const char *format, ...)
{
#if 1
  if(level < PRINT_LEVEL::HIGH)
    return;
#endif
  char msg[MAX_MSG_LEN];
  va_list vargs;
  va_start(vargs, format);
  vsnprintf(msg, MAX_MSG_LEN, format, vargs);
  va_end(vargs);
  std::lock_guard<std::recursive_mutex> lck(PrintMutex);
  LOGV("%s", msg);
}

//-----------------------------------------------------------------------------
// вариант по умолчанию, который можно переопределить в программе
// \~russian напечатать отладочное сообщение \~english print debug
void PRINT_DBG_PRINTF_DEFAULT(const int level, const char *format, ...)
{
  char msg[MAX_MSG_LEN];
  va_list vargs;
  va_start(vargs, format);
  vsnprintf(msg, MAX_MSG_LEN, format, vargs);
  va_end(vargs);
  std::lock_guard<std::recursive_mutex> lck(PrintMutex);
  LOGD("%s", msg);
}

//-----------------------------------------------------------------------------
// вариант по умолчанию, который можно переопределить в программе
void PRINT_TO_FILE_FPRINTF_DEFAULT(const int level, const char *format, ...)
{
  char msg[MAX_MSG_LEN];
  va_list vargs;
  va_start(vargs, format);
  vsnprintf(msg, MAX_MSG_LEN, format, vargs);
  va_end(vargs);
  std::lock_guard<std::recursive_mutex> lck(PrintMutex);
  if(LogFile == NULL)
  {
    LogFile = fopen(LogFilePath, "at");
    if (LogFile)
    {
      fprintf(LogFile, "************************************************************\n");
      fprintf(LogFile, "Session started at %s\n", DateTime::GetEpochTimeStringHTP().c_str());
      fflush(LogFile);
    }
  }
  if (LogFile)
  {
    fprintf(LogFile, "%s", msg);
    fflush(LogFile);
  }
}
