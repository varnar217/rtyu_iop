/*!
\file DateTime.cpp
\brief
\~russian Определения 

\~russian ELIJA_TODO
*/

#include "Global.h"
#include "DateTime.h"

#if ELIJA_ERROR // здесь разбираюсь с тем как правильно работать с временем в программе
/*
https://stackoverflow.com/questions/14504870/convert-stdchronotime-point-to-unix-timestamp
A unix time stamp is defined as the number of seconds since January 1, 1970 UTC, except not counting all the seconds. This is somewhat ridiculous and one has to wonder what the point of it is, so I agree that this is a silly question.

Anyway, lets look at some platform documentation for time_t and time().

Linux:
time() returns the time as the number of seconds since the Epoch, 1970-01-01 00:00:00 +0000 (UTC).
POSIX.1 defines seconds since the Epoch using a formula that approximates the number of seconds between a specified time and the Epoch. This formula takes account of the facts that all years that are evenly divisible by 4 are leap years, but years that are evenly divisible by 100 are not leap years unless they are also evenly divisible by 400, in which case they are leap years. This value is not the same as the actual number of seconds between the time and the Epoch, because of leap seconds and because system clocks are not required to be synchronized to a standard reference. The intention is that the interpretation of seconds since the Epoch values be consistent; see POSIX.1-2008 Rationale A.4.15 for further rationale.

Windows:
The time function returns the number of seconds elapsed since midnight (00:00:00), January 1, 1970, Coordinated Universal Time (UTC), according to the system clock.

Mac OS X:
The functions ctime(), gmtime(), and localtime() all take as an argument a time value representing the time in seconds since the Epoch (00:00:00 UTC, January 1, 1970;

The asctime(), ctime(), difftime(), gmtime(), localtime(), and mktime() functions conform to ISO/IEC 9899:1990 (ISO C90''), and conform to
ISO/IEC 9945-1:1996 (POSIX.1'') provided the selected local timezone does not contain a leap-second table (see zic(8)).
Similar documentation can be found for other systems, such as AIX, HP-UX, Solaris, etc.

So although not specified in C++ there is an easy and widely portable way to get a Unix timestamp:
auto unix_timestamp = std::chrono::seconds(std::time(NULL));

And if you want a number of milliseconds since 1 Jan 1970 UTC (similarly not counting all of them) then you can do this:
int unix_timestamp_x_1000 = std::chrono::milliseconds(unix_timestamp).count();

Just remember that these values aren't real times, so you can't in general use unix timestamps in arithmetic. For example subtracting unix timestamps does not give you an accurate count of seconds between the times. Or if you did something like:
std::chrono::steady_clock::now() - unix_timestamp;
you would not get a time point actually corresponding to 1970-01-01 00:00:00+0000.

As Andy Prowl suggests you could do something silly like:
// 1 Jan 1970 (no time zone)
std::tm c = { 0, 0, 0, 1, 0, 70, 0, 0, -1};
// treat it as 1 Jan 1970 (your system's time zone) and get the
// number of seconds since your system's epoch (leap seconds may
// or may not be included)
std::time_t l = std::mktime(&c);
// get a calender time for that time_point in UTC. When interpreted
// as UTC this represents the same calendar date and time as the
// original, but if we change the timezone to the system TZ then it
// represents a time offset from the original calendar time by as
// much as UTC differs from the local timezone.
std::tm m = *std::gmtime(&l);
// Treat the new calendar time as offset time in the local TZ. Get
// the number of seconds since the system epoch (again, leap seconds
// may or may not be counted).
std::time_t n = std::mktime(&m);
l -= (n-l); // subtract the difference
l should now represent the (wrong) number of seconds since 1 Jan 1970 UTC. As long as there are no leap seconds between the system epoch and 1 Jan 1970 (system time zone), or within an equal amount of time in the other direction from the system epoch, then any counted leap seconds should cancel out and l will be wrong in just the way that unix timestamps are wrong.

Another option is to use a decent date library such as Howard Hinnant's chrono::date. (Howard Hinnant was one of the guys that worked on the C++11 <chrono> library.)

auto now = system_clock::now();
sys_days today = time_point_cast<days>(now);
system_clock::time_point this_morning = today;
sys_days unix_epoch = day(1)/jan/1970;
days days_since_epoch = today - unix_epoch;
auto s = now - this_morning;
auto tz_offset = hours(0);
int unix_timestamp = (days_since_epoch + s + tz_offset) / seconds(1);
If you want to handle leap seconds Howard Hinnant also provides a library (http://howardhinnant.github.io/date/tz.html) that includes facilities for handling them as well as for parsing time zone databases as the source for leap second data.
*/

//=============================================================================
/*
The C++11 chrono header file provides three standard clocks that could be used for timing one’s code:
system_clock - this is the real - time clock used by the system;
high_resolution_clock - this is a clock with the shortest tick period possible on the current system;
steady_clock - this is a monotonic clock that is guaranteed to never be adjusted.
*/

#if ELIJA_WARNING
/*
The standard specifies three different clocks:
- system_clock
- steady_clock
- high_resolution_clock

And the standard does not specify the epoch for any of these clocks.

Programmers (you) can also author their own clocks, which may or may not specify an epoch.

There is a de-facto (unofficial) standard that std::chrono::system_clock::time_point has an epoch consistent with Unix Time. This is defined as the time duration that has elapsed since 00:00:00 Coordinated Universal Time (UTC), Thursday, 1 January 1970, not counting leap seconds.

There is no de-facto standard for the other two std-specified clocks. Additionally high_resolution_clock is permitted to be a type alias for either system_clock or steady_clock.

On OS X, high_resolution_clock is a type alias for steady_clock, and steady_clock is a count of nanoseconds since the computer booted (no relationship whatsoever to UTC).

ТАКИМ ОБРАЗОМ:
high_resolution_clock::now().time_since_epoch(), steady_clock::now().time_since_epoch() - неизвестно от какого момента стартует, т.е. точкой начала отсчёта может быть любой момент
system_clock::now().time_since_epoch() и std::time - фактически (хотя и неофициально) стартует от 00:00, Jan 1 1970 UTC
*/
#endif

/*
The encoding of calendar time in std::time_t is unspecified, but most systems conform to POSIX specification and return a value of integral type holding
the number of seconds since the Epoch (00:00, Jan 1 1970 UTC). Implementations in which std::time_t is a 32-bit signed integer (many historical implementations)
fail in the year 2038.
*/

//-----------------------------------------------------------------------------
#if ELIJA_WARNING // никто не гарантирует, что инициализация данной статической переменной класса произойдёт раньше инициализации других глобальных объектов, а если они вдруг при инициализации используют функции времени, то каков будет результат?
app_clock::time_point DateTime::TimePointStart = app_clock::now();
#endif

//-----------------------------------------------------------------------------
// the application time in nanoseconds (std::chrono::nanoseconds)
std::chrono::nanoseconds DateTime::GetAppTimeNanosec()
{
  return std::chrono::duration_cast<std::chrono::nanoseconds>(app_clock::now() - TimePointStart);
}

//-----------------------------------------------------------------------------
// the application time in microseconds (std::chrono::microseconds)
std::chrono::microseconds DateTime::GetAppTimeMicrosec()
{
  return std::chrono::duration_cast<std::chrono::microseconds>(app_clock::now() - TimePointStart);
}

//-----------------------------------------------------------------------------
// the application time in milliseconds (std::chrono::milliseconds)
std::chrono::milliseconds DateTime::GetAppTimeMillisec()
{
  return std::chrono::duration_cast<std::chrono::milliseconds>(app_clock::now() - TimePointStart);
}

//-----------------------------------------------------------------------------
// the application time in seconds (std::chrono::seconds)
std::chrono::seconds DateTime::GetAppTimeSeconds()
{
  return std::chrono::duration_cast<std::chrono::seconds>(app_clock::now() - TimePointStart);
}

//-----------------------------------------------------------------------------
// the application time in minutes (std::chrono::minutes)
std::chrono::minutes DateTime::GetAppTimeMinutes()
{
  return std::chrono::duration_cast<std::chrono::minutes>(app_clock::now() - TimePointStart);
}

//-----------------------------------------------------------------------------
// the application time in hours (std::chrono::hours)
std::chrono::hours DateTime::GetAppTimeHours()
{
  return std::chrono::duration_cast<std::chrono::hours>(app_clock::now() - TimePointStart);
}

//-----------------------------------------------------------------------------
// the application time in nanoseconds (std::time_t)
std::time_t DateTime::GetAppTimeNanosecCount()
{
  return std::chrono::duration_cast<std::chrono::nanoseconds>(app_clock::now() - TimePointStart).count();
}

//-----------------------------------------------------------------------------
// the application time in microseconds (std::time_t)
std::time_t DateTime::GetAppTimeMicrosecCount()
{
  return std::chrono::duration_cast<std::chrono::microseconds>(app_clock::now() - TimePointStart).count();
}

//-----------------------------------------------------------------------------
// the application time in milliseconds (std::time_t)
std::time_t DateTime::GetAppTimeMillisecCount()
{
  return std::chrono::duration_cast<std::chrono::milliseconds>(app_clock::now() - TimePointStart).count();
}

//-----------------------------------------------------------------------------
// the application time in seconds (std::time_t)
std::time_t DateTime::GetAppTimeSecondsCount()
{
  return std::chrono::duration_cast<std::chrono::seconds>(app_clock::now() - TimePointStart).count();
}

//-----------------------------------------------------------------------------
// the application time in minutes (std::time_t)
std::time_t DateTime::GetAppTimeMinutesCount()
{
  return std::chrono::duration_cast<std::chrono::minutes>(app_clock::now() - TimePointStart).count();
}

//-----------------------------------------------------------------------------
// the application time in hours (std::time_t)
std::time_t DateTime::GetAppTimeHoursCount()
{
  return std::chrono::duration_cast<std::chrono::hours>(app_clock::now() - TimePointStart).count();
}

//-----------------------------------------------------------------------------
// the epoch time in nanoseconds (std::chrono::nanoseconds)
std::chrono::nanoseconds DateTime::GetEpochTimeNanosec()
{
  return std::chrono::duration_cast<std::chrono::nanoseconds>(epoch_clock::now().time_since_epoch());
}

//-----------------------------------------------------------------------------
// the epoch time in microseconds (std::chrono::microseconds)
std::chrono::microseconds DateTime::GetEpochTimeMicrosec()
{
  return std::chrono::duration_cast<std::chrono::microseconds>(epoch_clock::now().time_since_epoch());
}

//-----------------------------------------------------------------------------
// the epoch time in milliseconds (std::chrono::milliseconds)
std::chrono::milliseconds DateTime::GetEpochTimeMillisec()
{
  return std::chrono::duration_cast<std::chrono::milliseconds>(epoch_clock::now().time_since_epoch());
}

//-----------------------------------------------------------------------------
// the epoch time in seconds (std::chrono::seconds)
std::chrono::seconds DateTime::GetEpochTimeSeconds()
{
  return std::chrono::duration_cast<std::chrono::seconds>(epoch_clock::now().time_since_epoch());
}

//-----------------------------------------------------------------------------
// the epoch time in minutes (std::chrono::minutes)
std::chrono::minutes DateTime::GetEpochTimeMinutes()
{
  return std::chrono::duration_cast<std::chrono::minutes>(epoch_clock::now().time_since_epoch());
}

//-----------------------------------------------------------------------------
// the epoch time in hours (std::chrono::hours)
std::chrono::hours DateTime::GetEpochTimeHours()
{
  return std::chrono::duration_cast<std::chrono::hours>(epoch_clock::now().time_since_epoch());
}

//-----------------------------------------------------------------------------
// the epoch time in nanoseconds (std::time_t)
std::time_t DateTime::GetEpochTimeNanosecCount()
{
  return std::chrono::duration_cast<std::chrono::nanoseconds>(epoch_clock::now().time_since_epoch()).count();
}

//-----------------------------------------------------------------------------
// the epoch time in microseconds (std::time_t)
std::time_t DateTime::GetEpochTimeMicrosecCount()
{
  return std::chrono::duration_cast<std::chrono::microseconds>(epoch_clock::now().time_since_epoch()).count();
}

//-----------------------------------------------------------------------------
// the epoch time in milliseconds (std::time_t)
std::time_t DateTime::GetEpochTimeMillisecCount()
{
  return std::chrono::duration_cast<std::chrono::milliseconds>(epoch_clock::now().time_since_epoch()).count();
}

//-----------------------------------------------------------------------------
// the epoch time in seconds (std::time_t)
std::time_t DateTime::GetEpochTimeSecondsCount()
{
  return std::chrono::duration_cast<std::chrono::seconds>(epoch_clock::now().time_since_epoch()).count();
}

//-----------------------------------------------------------------------------
// the epoch time in minutes (std::time_t)
std::time_t DateTime::GetEpochTimeMinutesCount()
{
  return std::chrono::duration_cast<std::chrono::minutes>(epoch_clock::now().time_since_epoch()).count();
}

//-----------------------------------------------------------------------------
// the epoch time in hours (std::time_t)
std::time_t DateTime::GetEpochTimeHoursCount()
{
  return std::chrono::duration_cast<std::chrono::hours>(epoch_clock::now().time_since_epoch()).count();
}

//-----------------------------------------------------------------------------
// the epoch time as std::string (see format in std::strftime description, perhaps "%Y-%m-%d %H:%M:%S")
std::string DateTime::GetEpochTimeString(const char* format)
{
  return EpochTimeToString(format, GetEpochTimeSecondsCount());
};

//-----------------------------------------------------------------------------
// convert the epoch time from seconds (std::chrono::seconds) to std::string (see format in std::strftime description, perhaps "%Y-%m-%d %H:%M:%S")
std::string DateTime::EpochTimeToString(const char* format, const std::chrono::seconds& seconds)
{
  std::time_t t = seconds.count();
  char mbstr[100];
  std::strftime(mbstr, sizeof(mbstr), format, std::localtime(&t));
  return std::string(mbstr);
};

//-----------------------------------------------------------------------------
// convert the epoch time from seconds (std::time_t) to std::string (see format in std::strftime description, perhaps "%Y-%m-%d %H:%M:%S")
std::string DateTime::EpochTimeToString(const char* format, const std::time_t& seconds)
{
  const std::time_t& t = seconds;
  char mbstr[100];
  std::strftime(mbstr, sizeof(mbstr), format, std::localtime(&t));
  return std::string(mbstr);
};

//-----------------------------------------------------------------------------
// the HTP project specific: the epoch time as std::string in format "%Y-%m-%dT%H:%M:%S.%microsec")
std::string DateTime::GetEpochTimeStringHTP()
{
  std::time_t epoch_time_microsec = GetEpochTimeMicrosecCount();
  std::time_t microsec = epoch_time_microsec % 1000000;
  std::time_t sec = epoch_time_microsec / 1000000;
  char mbstr[100];
  std::strftime(mbstr, sizeof(mbstr), "%FT%T.", std::localtime(&sec));
  return std::string(mbstr) + std::to_string(microsec);
};

//-----------------------------------------------------------------------------
// the HTP project specific: the epoch time as std::string in format "%Y-%m-%dT%H:%M:%S.%microsec")
std::string DateTime::GetEpochTimeStringHTP(std::time_t epoch_time_microsec)
{
  std::time_t microsec = epoch_time_microsec % 1000000;
  std::time_t sec = epoch_time_microsec / 1000000;
  char mbstr[100];
  std::strftime(mbstr, sizeof(mbstr), "%FT%T.", std::localtime(&sec));
  return std::string(mbstr) + std::to_string(microsec);
};
#endif
