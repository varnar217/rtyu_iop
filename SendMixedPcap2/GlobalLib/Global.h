#pragma once
/*!
\file eCommon.h
\brief
\~english ELIJA_TODO
\~russian ELIJA_TODO

\~russian ELIJA_TODO
*/

#define ELIJA_TODO    1 // доделать / додумать
#define ELIJA_DEBUG   1 // фрагменты кода, которые обеспечивают дополнительную защиту от ошибок, но обычно не используются из-за накладных расходов (аналог assert)
#define ELIJA_LOG     1 // фрагменты кода с логгированием для тестирования/отладки
#define ELIJA_WARNING 1 // тут что-то возможно не так
#define ELIJA_ERROR   1 // тут точно что-то не так и нужно исправить
#define ELIJA_TMP     1 // временный фрагмент кода на время разработки/тестирования/отладки, который нужно не забыть убрать в финальной версии
#define ELIJA_NOTYET  ? // для формирования ошибки на этапе компиляции

#define OSID_WINDOWS 1 // операционная система Microsoft Windows
#define OSID_LINUX   2 // операционная система Linux/Unix
#define OSID_ANDROID 3 // операционная система Android

// определяем версию операционной системы для компиляции
#if defined(_WIN32) || defined(_WIN64)
#define OSID OSID_WINDOWS
#elif defined(__ANDROID__)
#define OSID OSID_ANDROID
#elif defined(__linux__)
#define OSID OSID_LINUX
#else
ELIJA_NOTYET
#endif

#if OSID == OSID_WINDOWS

// Including SDKDDKVer.h defines the highest available Windows platform.
// If you wish to build your application for a previous Windows platform, include WinSDKVer.h and
// set the _WIN32_WINNT macro to the platform you wish to support before including SDKDDKVer.h.
#include <SDKDDKVer.h>

#if ELIJA_TODO // разобраться где определять. требуется для того, чтобы не было ошибок из-за одновременного использования winsock2.h и winsock.h при работе с сокетами:
// This problem is caused when including <windows.h> before <winsock2.h>.Try arrange your include list that <windows.h> is included after <winsock2.h> or define _WINSOCKAPI_ first
#define _WINSOCKAPI_    // stops windows.h including winsock.h
#endif

#endif

#if ELIJA_TODO // пока сделано для того, чтобы потом было проще искать всё, что возможно потребует многоязычной поддержки
//#define LANG_RUS 0
//#define LANG_ENG 1
//#define LANG_USE LANG_RUS
//#define LANG_TXT(msg) (L ## msg) //!< \~russian текст с переводом на соответствующий язык \~english text translated into the appropriate language
#define LANG_TXT(msg) (msg) //!< \~russian текст с переводом на соответствующий язык \~english text translated into the appropriate language
#endif

//#include <inttypes.h>
#include <stdint.h>
#include <stddef.h>
