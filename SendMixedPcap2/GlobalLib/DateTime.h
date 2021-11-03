#pragma once
/*!
\file DateTime.h
\brief
\~russian Описания 

\~russian ELIJA_TODO
*/

#include <string>
#include <chrono>
#include <ctime>

// choose the maximum resolution clock from std::chrono::steady_clock and std::chrono::system_clock
using maxres_sys_or_steady =
std::conditional<
  std::chrono::system_clock::period::den <= std::chrono::steady_clock::period::den,
  std::chrono::system_clock, std::chrono::steady_clock
>::type;

// choose the non-sleeping clock from std::chrono::high_resolution_clock and the maximum resolution clock
using maxres_nonsleeping_clock =
std::conditional<
  std::chrono::high_resolution_clock::is_steady,
  std::chrono::high_resolution_clock, maxres_sys_or_steady
>::type;

using app_clock = maxres_nonsleeping_clock; // clock for the application time
using epoch_clock = std::chrono::system_clock; // clock for the epoch time

//-----------------------------------------------------------------------------
/*!
\class DateTime
\brief
\~russian Класс для работы со временем в программе
*/
class DateTime
{
public:
  static std::chrono::nanoseconds GetAppTimeNanosec(); // the application time in nanoseconds (std::chrono::nanoseconds)
  static std::chrono::microseconds GetAppTimeMicrosec(); // the application time in microseconds (std::chrono::microseconds)
  static std::chrono::milliseconds GetAppTimeMillisec(); // the application time in milliseconds (std::chrono::milliseconds)
  static std::chrono::seconds GetAppTimeSeconds(); // the application time in seconds (std::chrono::seconds)
  static std::chrono::minutes GetAppTimeMinutes(); // the application time in minutes (std::chrono::minutes)
  static std::chrono::hours GetAppTimeHours(); // the application time in hours (std::chrono::hours)

  static std::time_t GetAppTimeNanosecCount(); // the application time in nanoseconds (std::time_t)
  static std::time_t GetAppTimeMicrosecCount(); // the application time in microseconds (std::time_t)
  static std::time_t GetAppTimeMillisecCount(); // the application time in milliseconds (std::time_t)
  static std::time_t GetAppTimeSecondsCount(); // the application time in seconds (std::time_t)
  static std::time_t GetAppTimeMinutesCount(); // the application time in minutes (std::time_t)
  static std::time_t GetAppTimeHoursCount(); // the application time in hours (std::time_t)

  static std::chrono::nanoseconds GetEpochTimeNanosec(); // the epoch time in nanoseconds (std::chrono::nanoseconds)
  static std::chrono::microseconds GetEpochTimeMicrosec(); // the epoch time in microseconds (std::chrono::microseconds)
  static std::chrono::milliseconds GetEpochTimeMillisec(); // the epoch time in milliseconds (std::chrono::milliseconds)
  static std::chrono::seconds GetEpochTimeSeconds(); // the epoch time in seconds (std::chrono::seconds)
  static std::chrono::minutes GetEpochTimeMinutes(); // the epoch time in minutes (std::chrono::minutes)
  static std::chrono::hours GetEpochTimeHours(); // the epoch time in hours (std::chrono::hours)

  static std::time_t GetEpochTimeNanosecCount(); // the epoch time in nanoseconds (std::time_t)
  static std::time_t GetEpochTimeMicrosecCount(); // the epoch time in microseconds (std::time_t)
  static std::time_t GetEpochTimeMillisecCount(); // the epoch time in milliseconds (std::time_t)
  static std::time_t GetEpochTimeSecondsCount(); // the epoch time in seconds (std::time_t)
  static std::time_t GetEpochTimeMinutesCount(); // the epoch time in minutes (std::time_t)
  static std::time_t GetEpochTimeHoursCount(); // the epoch time in hours (std::time_t)

  static std::string GetEpochTimeString(const char* format); // the epoch time as std::string (see format in std::strftime description, perhaps "%Y-%m-%d %H:%M:%S")
  static std::string EpochTimeToString(const char* format, const std::chrono::seconds& seconds); // convert the epoch time from seconds (std::chrono::seconds) to std::string (see format in std::strftime description, perhaps "%Y-%m-%d %H:%M:%S")
  static std::string EpochTimeToString(const char* format, const std::time_t& seconds); // convert the epoch time from seconds (std::time_t) to std::string (see format in std::strftime description, perhaps "%Y-%m-%d %H:%M:%S")

  static std::string GetEpochTimeStringHTP(); // the HTP project specific: the epoch time as std::string in format "%Y-%m-%dT%H:%M:%S.%microsec")
  static std::string GetEpochTimeStringHTP(std::time_t epoch_time_microsec); // the HTP project specific: the epoch time as std::string in format "%Y-%m-%dT%H:%M:%S.%microsec")

private:
  static app_clock::time_point TimePointStart; //!< \~russian Временная метка начала работы приложения
};
