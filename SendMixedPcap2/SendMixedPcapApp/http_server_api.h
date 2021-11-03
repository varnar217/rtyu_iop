/**
 * @file http_server_api.h
 * @author elija
 * @date 07/10/21
 * @brief API для общения HTTP-сервера (ядро / back-end) с HTTP-клиентом (интерфейс пользователя / front-end)
 */
#pragma once

#define USE_JSON_NLOHMANN 1 // использовать библиотеку https://github.com/nlohmann/json
#define USE_JSON_RAPIDJSON 2 // использовать библиотеку https://rapidjson.org/
#define USE_JSON_OPTION USE_JSON_NLOHMANN

#if USE_JSON_OPTION == USE_JSON_NLOHMANN
#include "nlohmann/json.hpp"
#elif USE_JSON_OPTION == USE_JSON_RAPIDJSON
#include "rapidjson/rapidjson.h"
#include "rapidjson/document.h"
#else
illegal option
#endif

//#define USE_STATS_PUT 1 // после получения запроса PUT создаётся поток в котором статистика отправляется в бесконечном цикле запросом POST
//#define USE_STATS_GET 2 // статистика возвращается только в ответ на каждый запрос GET
//#define USE_STATS_OPTION USE_STATS_GET

// заготовленные запросы и ответы для примера и отладки:
// СЕРВЕР:
extern const char* json_response_delete_exit_ok; // ответ на DELETE(/exit) - успешно
extern const char* json_response_delete_exit_err; // ответ на DELETE(/exit) - ошибка
extern const char* json_response_get_init_ok; // ответ на GET(/init?addr=&port=) - успешно
extern const char* json_response_get_init_err; // ответ на GET(/init?addr=&port=) - ошибка
extern const char* json_response_get_state_ok; // ответ на GET(/state) - успешно
extern const char* json_response_get_state_err; // ответ на GET(/state) - ошибка
extern const char* json_request_put_state_run; // запрос PUT(/state/run)
extern const char* json_response_put_state_run_ok; // ответ на PUT(/state/run) - успешно
extern const char* json_response_put_state_run_err; // ответ на PUT(/state/run) - ошибка
extern const char* json_response_get_stats_eb_ok; // ответ на GET(/stats/eb) - успешно
extern const char* json_response_get_stats_eb_err; // ответ на GET(/stats/eb) - ошибка
extern const char* json_response_get_stats_eb_n_ok; // ответ на GET(/stats/eb/N) - успешно
extern const char* json_response_get_stats_eb_n_err; // ответ на GET(/stats/eb/N) - ошибка
extern const char* json_response_get_params_ok; // ответ на GET(/params) - успешно
extern const char* json_response_get_params_err; // ответ на GET(/params) - ошибка
extern const char* json_request_put_params; // запрос PUT(/params)
extern const char* json_response_put_params_ok; // ответ на PUT(/params) - успешно
extern const char* json_response_put_params_err; // ответ на PUT(/params) - ошибка
extern const char* json_response_get_params_common_ok; // ответ на GET(/params/common) - успешно
extern const char* json_response_get_params_common_err; // ответ на GET(/params/common) - ошибка
extern const char* json_request_put_params_common; // запрос PUT(/params/common)
extern const char* json_response_put_params_common_ok; // ответ на PUT(/params/common) - успешно
extern const char* json_response_put_params_common_err; // ответ на PUT(/params/common) - ошибка
extern const char* json_response_get_params_service_ok; // ответ на GET(/params/service) - успешно
extern const char* json_response_get_params_service_err; // ответ на GET(/params/service) - ошибка
extern const char* json_response_get_params_app_ok; // ответ на GET(/params/app) - успешно
extern const char* json_response_get_params_app_err; // ответ на GET(/params/app) - ошибка
extern const char* json_response_get_params_pcap_ok; // ответ на GET(/params/pcap) - успешно
extern const char* json_response_get_params_pcap_err; // ответ на GET(/params/pcap) - ошибка
extern const char* json_response_get_params_user_scenario_ok; // ответ на GET(/params/user_scenario) - успешно
extern const char* json_response_get_params_user_scenario_err; // ответ на GET(/params/user_scenario) - ошибка
extern const char* json_request_post_params_user_scenario; // запрос POST(/params/user_scenario)
extern const char* json_response_post_params_user_scenario_ok; // ответ на POST(/params/user_scenario) - успешно
extern const char* json_response_post_params_user_scenario_err; // ответ на POST(/params/user_scenario) - ошибка
extern const char* json_request_put_params_user_scenario; // запрос PUT(/params/user_scenario)
extern const char* json_response_put_params_user_scenario_ok; // ответ на PUT(/params/user_scenario) - успешно
extern const char* json_response_put_params_user_scenario_err; // ответ на PUT(/params/user_scenario) - ошибка
extern const char* json_request_delete_params_user_scenario; // запрос DELETE(/params/user_scenario)
extern const char* json_response_delete_params_user_scenario_ok; // ответ на DELETE(/params/user_scenario) - успешно
extern const char* json_response_delete_params_user_scenario_err; // ответ на DELETE(/params/user_scenario) - ошибка
extern const char* json_response_get_params_network_scenario_ok; // ответ на GET(/params/network_scenario) - успешно
extern const char* json_response_get_params_network_scenario_err; // ответ на GET(/params/network_scenario) - ошибка
extern const char* json_request_post_params_network_scenario; // запрос POST(/params/network_scenario)
extern const char* json_response_post_params_network_scenario_ok; // ответ на POST(/params/network_scenario) - успешно
extern const char* json_response_post_params_network_scenario_err; // ответ на POST(/params/network_scenario) - ошибка
extern const char* json_request_put_params_network_scenario; // запрос PUT(/params/network_scenario)
extern const char* json_response_put_params_network_scenario_ok; // ответ на PUT(/params/network_scenario) - успешно
extern const char* json_response_put_params_network_scenario_err; // ответ на PUT(/params/network_scenario) - ошибка
extern const char* json_request_delete_params_network_scenario; // запрос DELETE(/params/network_scenario)
extern const char* json_response_delete_params_network_scenario_ok; // ответ на DELETE(/params/network_scenario) - успешно
extern const char* json_response_delete_params_network_scenario_err; // ответ на DELETE(/params/network_scenario) - ошибка
extern const char* json_response_get_params_eb_ok; // ответ на GET(/params/eb) - успешно
extern const char* json_response_get_params_eb_err; // ответ на GET(/params/eb) - ошибка
extern const char* json_response_get_params_eb_1_ok; // ответ на GET(/params/eb/1?id=) - успешно
extern const char* json_response_get_params_eb_1_err; // ответ на GET(/params/eb/1?id=) - ошибка
extern const char* json_request_post_params_eb; // запрос POST(/params/eb)
extern const char* json_response_post_params_eb_ok; // ответ на POST(/params/eb) - успешно
extern const char* json_response_post_params_eb_err; // ответ на POST(/params/eb) - ошибка
extern const char* json_request_put_params_eb; // запрос PUT(/params/eb)
extern const char* json_response_put_params_eb_ok; // ответ на PUT(/params/eb) - успешно
extern const char* json_response_put_params_eb_err; // ответ на PUT(/params/eb) - ошибка
extern const char* json_request_delete_params_eb; // запрос DELETE(/params/eb)
extern const char* json_response_delete_params_eb_ok; // ответ на DELETE(/params/eb) - успешно
extern const char* json_response_delete_params_eb_err; // ответ на DELETE(/params/eb) - ошибка
// КЛИЕНТ:
extern const char* json_request_post_err; // отправка ИНТЕРФЕЙСУ сообщения о внутренней ошибке на ГЕНЕРАТОРЕ

/*
 * Протокол обмена сообщениями между интерфейсом пользователя (front-end) и ядром (back-end) а-ля REST API:
 * - В ответ на GET возвращаем либо код успешного завершения и запрошенный ресурс, либо код ошибки
 * - В ответ на POST возвращаем либо код успешного завершения и новый созданный ресурс, либо код ошибки
 * - В ответ на PUT возвращаем либо код успешного завершения и изменённый ресурс, либо код ошибки и текущее состояние ресурса
 * - В ответ на PATCH возвращаем либо код успешного завершения и изменённый ресурс, либо код ошибки и текущее состояние ресурса
 * - В ответ на DELETE возвращаем либо код успешного завершения, либо код ошибки
 * 
 * СЕРВЕР:
 * DELETE(/exit) - завершить работу приложения ядра
 * GET(/init?addr=&port=) - первоначальное подключение интерфейса к ядру и получение от ядра его параметров и состояния
 * GET(/state) - получить состояние работы ядра
 * PUT(/state/run) - изменить состояние (запустить или остановить) работы ядра
 * GET(/stats/eb) - получить статистику по всем EPS-Bearer
 * GET(/stats/eb/N) - получить статистику по EPS-Bearer с идентификатором N
 * GET(/params) - получить все параметры работы ядра
 * PUT(/params) - изменить параметры работы ядра
 * GET(/params/common) - получить "общие" параметры работы ядра (режим работы, суммарный битрейт, GTP, файл сохранения)
 * PUT(/params/common) - изменить "общие" параметры работы ядра (режим работы, суммарный битрейт, GTP, файл сохранения)
 * GET(/params/service) - получить список всех сервисов возможных в PCAP файле
 * GET(/params/app) - получить список всех приложений возможных в PCAP файле
 * GET(/params/pcap) - получить список всех PCAP файлов доступных ядру
 * GET(/params/user_scenario) - получить список всех сохранённых пользовательских сценариев доступных ядру
 * POST(/params/user_scenario) - создать один/несколько пользовательских сценариев доступных ядру
 * PUT(/params/user_scenario) - изменить один/несколько/все пользовательские сценарии доступные ядру
 * DELETE(/params/user_scenario) - удалить один/несколько/все пользовательские сценарии доступные ядру
 * GET(/params/network_scenario) - получить список всех сохранённых сетевых сценариев доступных ядру
 * POST(/params/network_scenario) - создать один/несколько сетевых сценариев доступных ядру
 * PUT(/params/network_scenario) - изменить один/несколько/все сетевые сценарии доступные ядру
 * DELETE(/params/network_scenario) - удалить один/несколько/все сетевые сценариии доступные ядру
 * GET(/params/eb) - получить параметры всех EPS-Bearer
 * GET(/params/eb/N) - получить параметры одного EPS-Bearer с идентификатором N
 * POST(/params/eb) - создать один/несколько EPS-Bearer с параметрами
 * PUT(/params/eb) - изменить параметры работы для одного/нескольких/всех EPS-Bearer
 * DELETE(/params/eb) - удалить один/несколько/все EPS-Bearer
 * 
 * КЛИЕНТ:
 * POST(/err) - отправка ИНТЕРФЕЙСУ сообщения о внутренней ошибке на ГЕНЕРАТОРЕ (выполняется при возникновении внутренней ошибки на ГЕНЕРАТОРЕ)
 * 
 * ***************************************************************************
 * GET(/init?addr=&port=) - первоначальное подключение интерфейса к ядру и получение от ядра его параметров и состояния
 * ЗАПРОС:
 * - body: -
 * 
 * ОТВЕТ:
 * - body: object
 *   - response: object
 *     - code: number (код ошибки, в текущий момент только два кода: 0 = успешно, 1 = ошибка)
 *     - msg: string (текстовое описание ошибки или констатация успешного завершения)
 *     - time: string (в абсолютном виде вроде "2012-04-23T18:25:43.511Z" или в относительном от старта приложения, например, в микросекундах "123456767")
 *   - state: object (состояние работы ядра)
 *     - run: bool (запущена или остановлена работа ядра, "true" или "false")
 *   - params: object (параметры работы ядра)
 *     - mode: number (режим работы ядра, "0" - в реальном времени с отправкиой в сеть или "1" - не в реальном с записью файла))
 *     - br: number (суммарный битрейт всех EPS-Bearer в битах в секунду, например, "10000000000"))
 *     - ipsrc: string (НЕОБЯЗАТЕЛЬНЫЙ параметр: IP адрес, который используется для подмены оригинального адреса источника во всех пакетах)
 *     - ipdst: string (НЕОБЯЗАТЕЛЬНЫЙ параметр: IP адрес, который используется для подмены оригинального адреса назначения во всех пакетах)
 *     - file: object (описание использования файла записи выходного трафика)
 *       - path: string (полный путь к папке в которой будет создаваться файл, например, "/home/user/saved")
 *       - size: number (размер файла в мегабайтах после которого он закрывается и автоматически создаётся следующий файл, например, "1024")
 *     - gtp: object (описание использования протокола GTP)
 *       - use: bool (использовать или нет, "true" - использовать, "1" - не использовать)
 *       - ipsrc: string (IP адрес источника, например, "192.168.1.110")
 *       - ipdst: string (IP адрес назначения, например, "192.168.1.220")
 *       - minteid: number (минимальное значение идентификатора EPS-Bearer (Tunnel End Point Identifier), например "120")
 *       - maxteid: number (максимальное значение идентификатора EPS-Bearer (Tunnel End Point Identifier), например "319")
 *     - service: array of objects (перечисление всех видов сервиса возможных в PCAP файле)
 *       - id: number (уникальный идентификатор сервиса)
 *       - name: string (название сервиса, например, "Видео хостинг", "Видео соцсеть", "Видео мессенджер", "Видео онлайн-кинотеатр", "Видео телевидение", Видео спортивная трансляция", "Видео трансляция игр", "Игра", "Обновление ПО", "Браузер", "Новостная лента", "Аудио", "Файл", "Торрент", "Покупки", "Фоновый шум", ...))
 *     - app: array of objects (перечисление всех приложений возможных в PCAP файле)
 *       - id: number (уникальный идентификатор приложения)
 *       - name: string (название приложения, например, "Youtube android app", "Youtube ios app", "Youtube android browser", "Youtube ios browser", "Youtube desktop browser", ,,,))
 *     - pcap: array of objects (перечисление всех PCAP файлов доступных ядру)
 *       - id: number (уникальный идентификатор PCAP файла)
 *       - video: bool (содержит сервис видео или нет, "true" или "false")
 *       - service: object (тип сервиса из списка)
 *         - id: number (уникальный идентификатор сервиса)
 *       - app: object (приложение из списка)
 *         - id: number (уникальный идентификатор приложения)
 *       - br: number (усреднённый или типа того битрейт в файле в битах в секунду, например, "10000000")
 *       - path: string (полный путь к имени файла, например, "/home/user/pcaps/video/youtube_40mbs.pcap")
 *     - user_scenario: array of objects (перечисление пользовательских сценариев формирования трафика)
 *       - id: number (уникальный идентификатор сценария, например, "0" настраиваемый и он же дефолтный, "1", "2", "3", ... для всех остальных)
 *       - name: string (название сценария, например, "social media user (10 mbps)" или "gamer (12 mbps)" или ...)
 *       - br: number (желаемый битрейт в битах в секунду, например, "10000000")
 *       - pcap_id: array of numbers
 *         - number (уникальный идентификатор PCAP файла)
 *     - network_scenario: array of objects (перечисление сетевых сценариев формирования трафика)
 *       - id: number (уникальный идентификатор сценария, например, "0" настраиваемый и он же дефолтный, "1", "2", "3", ... для всех остальных)
 *       - name: string (название сценария, например, "Мало задержек" или "Большой джиттер" или ...)
 *       - jitter: object (параметры колебания отправки пакетов)
 *         - timeup : number (время в миллисекундах в течение которого работает jitter)
 *         - timedown : number (время в миллисекундах в течение которого НЕ работает jitter)
 *         - value : number (в микросекундах максимальное случайное изменение временной метки пакета в любую сторону)
 *       - burst: object (параметры взрывного режима отправки пакетов)
 *         - timeup : number (время в миллисекундах в течение которого работает burst, в это время у всех пакетов временная метка меняется на "отсылать прямо сейчас")
 *         - timedown : number (время в миллисекундах в течение которого работает burst)
 *     - eb: array of objects (перечисление всех EPS-Bearer)
 *       - id: number (уникальный идентификатор EPS-Bearer (совпадает с порядковым номером), например, "0" для всех EPS-Bearer, "1", "2", "3", ... для всех остальных)
 *       - br: number (максимальная пропускная способность (битрейт) для EPS-Bearer в битах в секунду, например, "20000000")
 *       - user_scenario: object (пользовательский сценарий)
 *         - id: number (уникальный идентификатор сценария, например, "0" настраиваемый и он же дефолтный, "1", "2", "3", ... для всех остальных)
 *         ВНИМАНИЕ! ЕСЛИ id НЕ равен 0, то ВСЕ оставшиеся поля этого object НЕ ПЕРЕДАЮТСЯ, поскольку они известни из списка пользовательских сценариев
 *         - name: string (название сценария, например, "social media user (10 mbps)" или "gamer (12 mbps)" или ...)
 *         - br: number (желаемый битрейт в битах в секунду, например, "10000000")
 *         - pcap_id: array of numbers
 *           - number (уникальный идентификатор PCAP файла)
 *       - network_scenario: number (сетевой сценарий)
 *         - id: number (уникальный идентификатор сценария, например, "0" настраиваемый и он же дефолтный, "1", "2", "3", ... для всех остальных)
 *         ВНИМАНИЕ! ЕСЛИ id НЕ равен 0, то ВСЕ оставшиеся поля этого object НЕ ПЕРЕДАЮТСЯ, поскольку они известни из списка сетевых сценариев
 *         - name: string (название сценария, например, "Мало задержек" или "Большой джиттер" или ...)
 *         - jitter: object (параметры колебания отправки пакетов)
 *           - timeup : number (время в миллисекундах в течение которого работает jitter)
 *           - timedown : number (время в миллисекундах в течение которого НЕ работает jitter)
 *           - value : number (в микросекундах максимальное случайное изменение временной метки пакета в любую сторону)
 *         - burst: object (параметры взрывного режима отправки пакетов)
 *           - timeup : number (время в миллисекундах в течение которого работает burst, в это время у всех пакетов временная метка меняется на "отсылать прямо сейчас")
 *           - timedown : number (время в миллисекундах в течение которого работает burst)
 * ***************************************************************************
 * GET(/stats/eb) и GET(/stats/eb/N) - запросы на получение статистики по всем или конкретному EPS-Bearer соответственно
 * ЗАПРОС:
 * - body: -
 * 
 * ОТВЕТ:
 * - body: object
 *   - response: object
 *     - code: number (код ошибки, в текущий момент только два кода: 0 = успешно, 1 = ошибка)
 *     - msg: string (текстовое описание ошибки или констатация успешного завершения)
 *     - time: string (в абсолютном виде вроде "2012-04-23T18:25:43.511Z" или в относительном от старта приложения, например, в микросекундах "123456767")
 *   - stats: object (статистика по одному или всем EPS-Bearer)
 *     - eb_id: number (идентификатор EPS-Bearer для которого отправлена статистика, например, "0" для всех EPS-Bearer, "1", "2", "3", ... для отдельных EPS-Bearer)
 *     - time: string (абсолютно время к которому относится статистика, например, "2021-10-06T04:34:21.1436")
 *     - period: number (период времени за который накоплена статистика  в миллисекундах)
 *     - size: number (размер в БАЙТАХ трафика за период времени из поля "period")
 *     - vpercent: number (ПРОЦЕНТ видео в трафике за период времени из поля "period", допустимый диапазон значений от 0 до 100 включительно)
 *     - avrpktsz: number (средний размер одного пакета в БАЙТАХ за период времени из поля "period")
 *     - pktcount: number (количество пакетов за период времени из поля "period")
 * *****************************************************************************
 * В ответ на запрос GET(/stats/eb) и GET(/stats/eb/N) Генератор отправляет Интерфейсу статистику в виде ответа на запрос
 * - body: object
 *   - response: object
 *     - code: number (код ошибки, в текущий момент только два кода: 0 = успешно, 1 = ошибка)
 *     - msg: string (текстовое описание ошибки или констатация успешного завершения)
 *     - time: string (в абсолютном виде вроде "2012-04-23T18:25:43.511Z" или в относительном от старта приложения, например, в микросекундах "123456767")
 *   - stats: object (статистика)
 *     - eb_id: number (идентификатор EPS-Bearer для которого отправлена статистика, например, "0" для всех EPS-Bearer, "1", "2", "3", ... для отдельных EPS-Bearer)
 *     - time: string (абсолютно время к которому относится статистика, например, "2021-10-06T04:34:21.1436")
 *     - period: number (период времени за который накоплена статистика  в миллисекундах)
 *     - size: number (размер в БАЙТАХ трафика за период времени из поля "period")
 *     - vpercent: number (ПРОЦЕНТ видео в трафике за период времени из поля "period", допустимый диапазон значений от 0 до 100 включительно)
 *     - avrpktsz: number (средний размер одного пакета в БАЙТАХ за период времени из поля "period")
 *     - pktcount: number (количество пакетов за период времени из поля "period")
 * 
 * При возникновении внутренней ошибки Генератор отправляет Интерфейсу оповещение в виде POST(/err):
 * - body: object
 *   - err: object
 *     - code: number (код ошибки)
 *     - msg: string (описание ошибки)
 *     - time: string (время возникновения ошибки, например, "2021-10-06T04:34:21.1436")
 * 
 */
