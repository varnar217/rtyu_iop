1) не успевает 100 Eps-Bearer по 50 Мбит/сек - вместо 5 Гигибит/сек чут более 1 Гигабит/сек
2) либо большая нервномерность в некоторых PCAP файлах и битрейт получается больше возможного допуска,
либо я неправильно работаю именно  натуральными PCAP файлами, поскольку с синтетическими такой
проблемы нет и они точно держат битрейт
3) похоже при более чем первом старте сбоит или подсчёи битрейта или лействительно создаёт слишком
маленький битрейт. кажется при первом старте такого не происходит. что-то не обнуляется?
4) что-тосовсем не получилось с джиттером, все пакеты имели временую метку = 0

************************************************************
ТОЛЬКО ЧТЕНИЕ ПАКЕТОВ
независимо от своего реального размера ВСЕ пакеты прнимаются равными 1378 байт
битрейт выводится в значениях бит в секунду

на моём домашнем ноутбуке:
-    176'725'514'408 - 1 поток, единственный пакет создаётся заранее, ЯКОБЫ мьютекс
-    167'853'871'659 - 1 поток, единственный пакет создаётся заранее, семафор
-  2 x 7'952'888'609 - 2 потока, в каждом единственный фиктивный пакет создаётся заранее, мьютекс
-  2 x 9'031'213'253 - 2 потока, в каждом единственный фиктивный пакет создаётся заранее, семафор
-      5'852'810'222 - 1 поток, пакет реально считывается из файла, ЯКОБЫ мьютекс
-      6'065'050'194 - 1 поток, пакет реально считывается из файла но БЕЗ копирования из буфера libpcap, ЯКОБЫ мьютекс
-  2 x 1'444'260'805 - 2 потока, пакет реально считывается из файла, мьютекс
-  2 x 1'344'850'222 - 2 потока, пакет реально считывается из файла, у каждого потока своя независимая очередь пакетов, мьютекс
-  2 x 1'336'759'201 - 2 потока, пакет реально считывается из файла, у каждого потока своя независимая очередь пакетов, мьютекс только на время вызова PcapReader_c::GetPacket()


на 10.8.7.44 (файлы на HDD sda)
-     12'343'913'957 - 1 поток, пакет реально считывается из файла, ЯКОБЫ мьютекс

на 10.8.7.44 (файлы на SSD nvme0)
-     12'488'301'409 - 1 поток, пакет реально считывается из файла, ЯКОБЫ мьютекс
-  2 x 3'830'482'598 - 2 потока, пакет реально считывается из файла, мьютекс
-  3 x 1'497'786'275 - 3 потока, пакет реально считывается из файла, мьютекс
-  4 x 1'205'132'892 - 4 потока, пакет реально считывается из файла, мьютекс
-  6 x   680'574'229 - 6 потоков, пакет реально считывается из файла, мьютекс
-  8 x   486'850'470 - 8 потоков, пакет реально считывается из файла, мьютекс
- 10 x   398'021'072 - 10 потоков, пакет реально считывается из файла, мьютекс

ЧТЕНИЕ ПАКЕТОВ И ОТПРАВКА ПАКЕТОВ

на моём домашнем ноутбуке:
-      1'237'031'780 - 1 поток чтение и 1 поток отправка без отправки и учёта временной метки, пакет реально считывается из файла, мьютекс и ожидание событий
-      5'243'664'961 - 1 поток чтение и 1 поток отправка без отправки и учёта временной метки, пакет реально считывается из файла, УДАЛИЛ мьютекс и ожидание событий, ОСТАВИЛ только проверку атомарного флага в цикле
-      4'159'369'266 - 1 поток чтение и 1 поток отправка C отправкой на localhost и БЕЗ учёта временной метки, пакет реально считывается из файла, УДАЛИЛ мьютекс и ожидание событий, ОСТАВИЛ только проверку атомарного флага в цикле

на 10.8.7.44 (файлы на HDD sda)
-      4'479'219'844 - 1 поток чтение и 1 поток отправка без отправки и учёта временной метки, пакет реально считывается из файла, УДАЛИЛ мьютекс и ожидание событий, ОСТАВИЛ только проверку атомарного флага в цикле

на 10.8.7.44 (файлы на SSD nvme0)
-       4'759'128'928 - 1 поток чтение и 1 поток отправка без отправки и учёта временной метки, пакет реально считывается из файла, УДАЛИЛ мьютекс и ожидание событий, ОСТАВИЛ только проверку атомарного флага в цикле

------------------------------------------------------------
СТАТИСТИКА С НАНОСЕКУНДАМИ ПО ЭТАПАМ:

предположим, что размр каждого пакета = 1378 байт = 11024 бит, тогда для достижения потока в 10 Гигибит/сек нам нужно
обрабатывть один такой пакет 10000000000 / 11024 = 907112 раз в секунду, тогда на обработку одного пакетам можно
тратить не более 1000000000 / 907112 = 1102 наносекунды

на моём домашнем ноутбуке:
-      5'463'626'669 - 1 поток, пакет реально считывается из файла, ЯКОБЫ мьютекс
read: cnt=13077804, wait=110, read=1907, libpcap=1724
-      4'888'240'292 - 1 поток чтение и 1 поток отправка без отправки и учёта временной метки, пакет реально считывается из файла, УДАЛИЛ мьютекс и ожидание событий, ОСТАВИЛ только проверку атомарного флага в цикле
read: cnt=22420534, wait=188, read=2066, libpcap=1787
send: cnt=22420534, get=2142, send=113, sendto=0
-      3'847'116'060 - 1 поток чтение и 1 поток отправка C отправкой на localhost и БЕЗ учёта временной метки, пакет реально считывается из файла, УДАЛИЛ мьютекс и ожидание событий, ОСТАВИЛ только проверку атомарного флага в цикле
read: cnt=15223226, wait=653, read=2212, libpcap=1954
send: cnt=15223226, get=385, send=2480, sendto=2123

на 10.8.7.44 (файлы на HDD sda)
-     11'403'025'182 - 1 поток, пакет реально считывается из файла, ЯКОБЫ мьютекс
read: cnt=81415259, wait=70, read=896, libpcap=793
-      4'834'303'217 - 1 поток чтение и 1 поток отправка без отправки и учёта временной метки, пакет реально считывается из файла, УДАЛИЛ мьютекс и ожидание событий, ОСТАВИЛ только проверку атомарного флага в цикле
read: cnt=14059247, wait=770, read=1509, libpcap=967
send: cnt=14059248, get=2024, send=255, sendto=0
-      2'800'214'952 - 1 поток чтение и 1 поток отправка C отправкой на localhost и БЕЗ учёта временной метки, пакет реально считывается из файла, УДАЛИЛ мьютекс и ожидание событий, ОСТАВИЛ только проверку атомарного флага в цикле
read: cnt=14843451, wait=1851, read=2085, libpcap=1516
send: cnt=14843452, get=401, send=3535, sendto=2927

на 10.8.7.44 (файлы на SSD nvme0)
-     11'263'415'342 - 1 поток, пакет реально считывается из файла, ЯКОБЫ мьютекс
read: cnt=19649025, wait=70, read=908, libpcap=805
-      4'399'722'316 - 1 поток чтение и 1 поток отправка без отправки и учёта временной метки, пакет реально считывается из файла, УДАЛИЛ мьютекс и ожидание событий, ОСТАВИЛ только проверку атомарного флага в цикле
read: cnt=20364446, wait=858, read=1646, libpcap=962
send: cnt=20364446, get=2226, send=279, sendto=0
-      2'800'350'882 - 1 поток чтение и 1 поток отправка C отправкой на localhost и БЕЗ учёта временной метки, пакет реально считывается из файла, УДАЛИЛ мьютекс и ожидание событий, ОСТАВИЛ только проверку атомарного флага в цикле
read: cnt=13221891, wait=1803, read=2133, libpcap=1547
send: cnt=13221892, get=413, send=3523, sendto=2925

------------------------------------
ЭКСПЕРИМЕНТЫ С ЗАМЕНОЙ библиотеки iibpcap НА собственный fread

НА МОЁМ ДОМАШНЕМ КОМПЕ:
libpcap GeneratorParamsOnePcapEqualIntervals100msUDP5EB.json
read thread(0) stopped after 35171996 microseconds (bitrate = 5403506425 bits per sec)
read thread(0) cnt=17239850, wait=110, read=1929, libpcap=1745
send thread stopped after 36002872 microseconds (bitrate = 0 bits per sec)

libpcap GeneratorParamsGeneral.json
read thread(0) stopped after 33216303 microseconds (bitrate = 4879102354 bits per sec)
read thread(0) cnt=14701174, wait=111, read=2148, libpcap=1909
send thread stopped after 34002924 microseconds (bitrate = 0 bits per sec)

fread GeneratorParamsOnePcapEqualIntervals100msUDP5EB.json
read thread(0) stopped after 31192897 microseconds (bitrate = 7056745000 bits per sec)
read thread(0) cnt=19967373, wait=109, read=1452, libpcap=1270
send thread stopped after 32002708 microseconds (bitrate = 0 bits per sec)

fread GeneratorParamsGeneral.json
read thread(0) stopped after 27451663 microseconds (bitrate = 6472523169 bits per sec)
read thread(0) cnt=16117700, wait=109, read=1593, libpcap=1359
send thread stopped after 28002316 microseconds (bitrate = 0 bits per sec)

НА 10.8.7.44:

libpcap GeneratorParamsOnePcapEqualIntervals100msUDP5EB.json HDD
read thread(0) stopped after 22177841 microseconds (bitrate = 11345201439 bits per sec)
read thread(0) cnt=22824027, wait=70, read=900, libpcap=811
send thread stopped after 23002428 microseconds (bitrate = 0 bits per sec)

fread GeneratorParamsOnePcapEqualIntervals100msUDP5EB.json HDD
read thread(0) stopped after 28814254 microseconds (bitrate = 15664496474 bits per sec)
read thread(0) cnt=40943467, wait=69, read=634, libpcap=544
send thread stopped after 29002979 microseconds (bitrate = 0 bits per sec)

---

libpcap GeneratorParamsGeneral.json HDD
read thread(0) stopped after 18724083 microseconds (bitrate = 9081285901 bits per sec)
read thread(0) cnt=15424415, wait=71, read=1142, libpcap=1010
send thread stopped after 19001954 microseconds (bitrate = 0 bits per sec)

fread GeneratorParamsGeneral.json HDD
read thread(0) stopped after 27857663 microseconds (bitrate = 12665269397 bits per sec)
read thread(0) cnt=32005153, wait=71, read=799, libpcap=677
send thread stopped after 28002822 microseconds (bitrate = 0 bits per sec)

---

libpcap+send GeneratorParamsGeneral.json HDD
send thread stopped after 23973649 microseconds (bitrate = 4297808455 bits per sec)
read thread(0) stopped after 23973615 microseconds (bitrate = 4297814550 bits per sec)
read thread(0) cnt=9346349, wait=732, read=1832, libpcap=1151
send thread cnt=9346349, get=2311, send=253, sendto=0

fread+send GeneratorParamsGeneral.json HDD
send thread stopped after 26810419 microseconds (bitrate = 4865172899 bits per sec)
send thread cnt=11832123, get=2009, send=256, sendto=0
read thread(0) stopped after 26810346 microseconds (bitrate = 4865186146 bits per sec)
read thread(0) cnt=11832123, wait=870, read=1395, libpcap=800

---

НА МОЁМ КОМПЕ:
fread+send GeneratorParamsGeneral.json set_thread_affinity
send thread stopped after 13220716 microseconds (bitrate = 5738502580 bits per sec)
send thread cnt=6881995, get=1803, send=117, sendto=0
read thread(0) stopped after 13220520 microseconds (bitrate = 5738587656 bits per sec)
read thread(0) cnt=6881995, wait=191, read=1729, libpcap=1416

НА 10.8.7.44:
fread+send GeneratorParamsGeneral.json set_thread_affinity
send thread stopped after 26198175 microseconds (bitrate = 4677397083 bits per sec)
send thread cnt=11115681, get=2141, send=215, sendto=0
read thread(0) stopped after 26198070 microseconds (bitrate = 4677415830 bits per sec)
read thread(0) cnt=11115681, wait=831, read=1525, libpcap=862

=============================











************************************************************
ВОПРОСЫ ДЛЯ РАЗМЫШЛЕНИЯ:

1) не создавать каждый раз пакет в PcapReader_c, а сделать небольшой список пакетов и при чтении из
PCAP файла брать пакет из этого списка, а после отправки в Sender_c возвращать пакет в список
соответствующего PcapReader_c. но будет ли это реальным увеличением быстродействия Sender_c?

2) если быстродействия будет хватать, то в EpsBearerPacket_s поменять указатели на weak_ptr,
чтобы обезопасить себя от вызова функций уже удалённых модулей
UPDATE: уже так и сделал, поскольку именно наличие weak_ptr позволяет отслеживать "исчезновение"
модулей связанных с пакетами в очереди. то есть, если мы в интерфейсе пользователя во время работы
можем добавлять и УДАЛЯТЬ EpsBearer_c из EpsBearerMuxer_c, то может возникнуть ситуация, когда в
очереди пакетов на отправку находится пакет от модуля EpsBeare_c, который уже был удалён из
состава EpsBeareMuxer_c. а значит мы имеем право отправить такой пакет, но считать новый пакет
из данного EpsBeare_c уже не можем. так что скорее подумать есть ли возможность вернуть обычные
указатели, но при этом сохранить логику работы с удалением породивших пакеты модулей.

3) если с быстродействием будут проблемы, то подумать есть ли смысл и возможность
передавать пакет между модулями не в виде shared_ptr, а как простой указатель. хотя я сам
не верю, что это может реально повлиять на производительность, но чем чёрт не шутит...

4) возможно для ускорения работы с PCAP файлами сделать упреждающее чтение нескольких пакетов в память? 

5) вместо "200" потоков для каждого Eps-Bearer сделать "4" потока, которые будут считывать
данные в порядке очереди, дожидаясь на каждом этапе завершения данного этапа предыдущим
по порядку модулем (например, поток 2 будет считывать данные из PCAP файла, но записывать в
Eps-Bearer он сможет только после того как получил сигнал, что поток 1 записыал в Eps-Bearer и т.д.)

6) возможно для ускорения в модулях EpsBearer_c, EpsBearerMuxer_c и даже Sender_c иметь очередь
не по одному самому раннему пакету из каждого низлежащего модууля, но брать в эту очередь
из каждого низлежащего модуля по N пакетов?
ВНИМАНИЕ! если брать ровно по одному пакету, то мы фактически получаем только ДВА потока для
случая, когда на некотором промежутке времени берутся данные только из одного pcap файла: один
поток отправки пакетов ждёт пакеты, а другой для него читает пакеты. потому что несмотря на
количество EpsBearer (а соответственно и их потоков чтения) работает фактически только один из них,
потому что поток отправки пакетов не запрашивает ничего, пока ему в очередь не считают пакет 
вместо предыдущего отправленного пакета). поэтому очередь в каждом модуле из более чем одного
пакета позволит создать реальную многопоточность чтения, хотя и тоже в ограниченных пределах. поскольку
если чтение всегда идёт на интервале времени из одного и того же файла, то всё равно приходится ждать
считывания предыдущего пакета прежде чем укладывать в очередь новый. а если мы сделаем более одного
пакета в очереди, то это точно решает проблему? как мы будем определять можно ли брать очередной из
очереди или для одного из низлежащих модулей уже нет его пакетов в очереди и тогда мы может нарушить
упорядочение по времени, когда его пакеты потом придут (делать какой-то счётчик?)? может ещё
какие-то проблемы есть?

7) не забывать про Close() для PcapReader_c
UPDATE: в текущий момент PcapReader_c создаётся с шаблоном std::enable_shared_from_this, а значит
экземпляры этого класса могут создавться только как std::shared_ptr, а значит мы просто помещаем
Close() в деструктор и больше о нём не вспоминаем... пока вдруг не уберём std::enable_shared_from_this

8) В случае использования любой синхронизации C++20 нужно подумать как добавлять новые более
низкоуровневые экземпляры в очередь пакетов класса. Что происходит с условиями, если я добавляю новый
и оповещаю об этом в момент, когда выполняется запрос на чтение старого отправленного? И получается
добавлять новые элементы в очередь нужно под аналогом мьютекса, как это реализовать? сейчас нужно
сначала добавить все модули с помощью Add, а потом выполнить Start, то есть сейчас не предусмотрено
добавление новых модулей уже после начала работы модуля

9) Методы синхронизациии между потоками:
- spinlock
- std::mutex + std::condition_variable
- C++20 std::atomic с функциями ожидания/оповещения (wait/notify)
- C++20 std::counting_semaphore
- C++20 std:berrier или std::latch (для однократного выполнения)
ВНИМАНИЕ: Похоже, что в gcc-11.1 есть ошибка при работе с std::atomic wait/notify,
а в gcc-11.2 она уже исправлена

10) КАЖЕТСЯ для ускорения в модуле PacketSender_c нужно:
- убрать идею про работу с несколькими мультиплексорами EpsBearerMuxer_c и тогда пакеты внутри
PacketSender_c будут просто очередью, поскольку ВСЕГДА новый пакет поступающий от ОДНОГО
ЕДИНСТВЕННОГО мультиплексора будет пакетом с самой поздней временной меткой и тем самым можно
избавиться внутри PacketSender_c::GetPacket() от ожидания каждого while(WaitPacket == true), а
заменить это на проверку размера очереди и если в очереди есть хоть один пакет, то отдавать его
- и соответственно тогда сделать очередь пакетов внутри PacketSender_c достаточно большого
размера, чтобы иметь запас по времени для подчитывания новых пакетов. например, если первоначальная
буферизация этой очереди будет составлят 100 пакетов, то с момента начала работы у нас КАЖЕТСЯ будет
достаточно приличный запас по времени для подчитывния новых пакетов, поскольку маловероятно, что
все 100 пакетов очереди будет принадлежать одному и тому же PcapReader_c, а значит КАЖЕТСЯ будет
работать распаралеливание потоков подчитывания

11) По ссылке https://github.com/AMildner/MoonGen в разделе Rate Control вычитал такую интересную фразу:
"Intel 10 GbE NICs (82599 and X540) support rate control in hardware. This can be used to generate
CBR or bursty traffic with precise inter-departure times."
Авторы описывают это в документе https://www.net.in.tum.de/fileadmin/bibtex/publications/papers/MoonGen_IMC2015.pdf
в разделах "7. RATE CONTRO" и "8. CONTROLLING INTER-PACKET GAPS IN SOFTWARE".
Значит ли это, что мы можем реализовать частичный аналог traffic control на аппаратной платформе?

12) Поэкспериментировать с выравниванием памяти для хранения пакетов? С другой стороны, если я их
не копирую вплоть до отправки сетевому устройству, то нужно ли это?

13) Нужно будет для каждого EPS-Bearer завести уникальный id по которому его будут идентифицировать и Интерфейс и Ядро

14) Похоже приложение валится при работе с очередью пакетов Packets как минимум в
классе PacketSender_c и в функции GetPacket(которая вызывается из функции потока SendPacket)
и в функции потока ReadPacket. Воспроизвести это можно, посылая http-серверу несколько раз
команду PUT(/state/run), то есть запуская и останавливая работу Ядра ГТО. Хотя это
проявляется в классе PacketSender_c, но ВОЗМОЖНО это может случаться и в других классах,
поскольку в них алгоритм работы с очередью Packets абсолютно идентичный. А может и нет...
Причём эта ситуация встречается и для режима синхронизации SYNCHRO_MODE_SEMAPHORE (c++20) и
для "старого" режима SYNCHRO_MODE_MUTEX. Так что СКОРЕЕ ВСЕГО дело не в компиляторе и
плохой поддержке им c++20.
Результаты поисков ошибки 1:
Если перед использованием Packets поставить точку останова
  if(Packets.empty())
    int brk = 0; // точка останова
то при выполнении серии старт/остановка мы попадаем в неё... что НЕВОЗМОЖНО по тому алгоритму,
который нарисован в моей голове. Нужно копать где-то здесь.

15) Сделать обработку ситуации, когда приходит запрос на завершение приложений при
работающем потке отправки статистики. Сейчас это вызывает ошибку при завершении приложения.

16) Запретить работу с Ядром ГТО нескольких Интерфейсов ГТО одновременно

17) Если мы удаляем какой-то EpsBearer, но его пакеты в EpsBeareMuxer и в Sender остаются. А
если они имеют какую-то метку по которой они должны будут быть отправлены, например, минут
через 10. А за эти 10 минут мы создаём новый EpsBearer с таким же идентификатором, то
"старый" пакет отправится под видом нового EpsBearer? Это нормально?

18) Нужно разобраться может ли HTTP-сервер обрабатывать одновременно несколько запросов и
если может, то сделать защиту совместных ресурсов (например, Params из GeneratorApp_c)

19) Хорошо бы сделать передачу const, когда передаются параметры вглубь модулей. Но на скорую руку
это не сделать, поскольку вылезают ошибки. Поэтому на будущее

20) Как на первом этапе получить любой битрейт из PCAP-файла. Мы знаем битрейт в файле и
тогда просто при считыванни очередного пакета из файла умножаем его временную метку на
коэффициент пропорциональности = (br_required/br_file), который позволяет привести битрейт
к требуемому значению. Например, если в файле битрейт 1000000 бит/сек, а нам нужен 1500000 бит/сек,
то при считывании пакетов их временная метка получается как
timestamp = (timestamp_file * 1500000 / 1000000) = timestamp * 1.5

21) Поддержка работы на 2-х языках (русский и английский) для Ядра ГТО это фактически
только поддержка отправки сообщений через HTTP-сервер Интерфейсу ГТО на нужном языке. Это
вроде легко сделать, если иметь глобальный пареметр прилоения вроде int Language и все
сообщения для HTTP-сервера формировать из глобального списка сообщений как
MessageTxt[MessageId][Language]. Это же касается и названий в конфигурационных файлах, вот только
тогда их придётся хранить не в виде текстовых полей, а кодов ParamId. И тогда доступ к ним
будет выглядеть как ParamsTxt[ParamId][Language]

22) Разграничение доступа при работе с GeneratorApp_c.Params и c EpsBearerMuxer_c.Packets
реализовано только на уровне EpsBearerMuxer_c для варианта синхронизации
#if SYNCHRO_MODE_EBM == SYNCHRO_MODE_MUTEX
Нужно полумать над правильным механизмом для всех вариантов синхронизации

************************************************************
задачи:
+	сделать изменение времени
-	сделать создание http-сервера на заданном адресе и порте
+	сделать отправку статистики по GET(/state/graph) и GET(/state/graph/N)

+ сделать PacketWriter_c, он же PcapWriter_c
+ проект переделать в относительные ссылки и библиотеки и PCAP файлы
- убрать EpsBearer_c и EpsBearerMuxer_c, а оставить только PcapReader_c с
    указателем на параметры EpsBearer которому он приндлежит
+ сделать GTP
+ сделать версию
- сделать правильную обработку ошибок при работе с PCAP файлами
+ сделать jitter и burst
+ проверить работу jitter и  burst  с помощью PCAP файла с одинаковыми интервалами между пакетами
- управление выходными файлами, а может и входными
- сделать что-то с размерами лог-файлов. либо по дням разбивать, либо ограничение размера,
	  либо и то и другое, либо что-то ещё
- время временных меток при сохранении PCAP файла в режиме с накоплением сейчас берётся
    из текущего времени компьютера, а нужно из временной метки пакета?

************************************************************
текущая статистика (27 октября 2021):

************************************************************
ОБЩАЯ ЛОГИКА РАБОТЫ:

- PcapReader_c По запросу считывает из файла один пакет и отдаёт УКАЗАТЕЛЬ на него и дальше на
    всём тракте следования пакета он передаётся как указатель с добавлением в него информации
    о низлежащих модулях через которые он проходит (это нужно, чтобы потом знать для каких именно
    экземпляров модулей требуется считать новый пакет взамен отданного)
- EpsBearer_c Хранит в себе очередь пакетов, которая содержит ровно по одному пакету от каждого
    PcapReader_c входящего в данный EpsBearer_c. Причём этот пакет гарантировано является пакетом
    с самой ранней временной меткой в конкретном PcapReader_c. Все пакеты в очереди отсортированы
    по временной метке.
    Причём сортировка состоит в определении положения только одного добавляемого в очередь пакета
    и остальные пакеты очереди при этом не меняют своего положения.
    По запросу EpsBearer_c отдаёт пакет с самой ранней временной меткой, т.е. самый первый пакет
    из очереди пакетов, и после этого выставляет событие о необходимости считать новый пакет
    взамен отданного.
    Например, если EpsBearer_c состоит из трёх PcapReader_c, то сначала очередь пакетов
    может выглядеть так:
      [0] пакет 2-го PcapReader_c с временной меткой 10
      [1] пакет 3-го PcapReader_c с временной меткой 30
      [2] пакет 1-го PcapReader_c с временной меткой 40
    После того как EpsBearerMuxer_c забрал из очереди пакет с самой ранней временной меткой:
      [0] пакет 3-го PcapReader_c с временной меткой 30
      [1] пакет 1-го PcapReader_c с временной меткой 40
    Сразу же в отдельном потоке запускается считывание нового пакета именно из 2-го PcapReader_c,
      поскольку отдали именно его пакет:
      [ ] пакет 2-го PcapReader_c с временной меткой 35
    Этот новый пакет помещается в очередь пакетов в соответствии со своей временной меткой:
      [0] пакет 3-го PcapReader_c с временной меткой 30
      [1] пакет 2-го PcapReader_c с временной меткой 35
      [2] пакет 1-го PcapReader_c с временной меткой 40
    И так продолжается бесконечно.
- EpsBearerMuxer_c Хранит в себе очередь пакетов, которая содержит ровно по одному пакету от каждого
    EpsBearer_c входящего в данный EpsBearerMuxer_c. Логика работы этого модуля полностью совпадает
    с логикой работы модуля EpsBearer_c.
- Sender_c Забирает пакеты из EpsBearerMuxer_c и отправляет их в сеть или же записывает
    их в файл. Логика работы с пакетами у этого модуля совпадает с логикой модулей
    EpsBearer_c и EpsBearerMuxer_c. Только в конце этот модуль забирает пакет с самой ранней
    временной меткой из EpsBearerMuxer_c в собственном потоке и затем отправляет его в сеть
    (через любой доступный сетевой интерфейс) или записывает его в файл.

************************************************************
ПСЕВДО-КОД (вариант с синхронизацией std::mutex + std::condition_variable):

// пакет с сопроводительной информацией
struct EpsBearerPacket_s
{
  std::weak_ptr<PcapReader_c> pr; // из какого экземпляра PcapReader_c произошёл пакет
  std::weak_ptr<EpsBearer_c> eb; // через какой экземпляр EpsBearer_c прошёл пакет
  std::weak_ptr<EpsBearerMuxer_c> ebm; // через какой экземпляр EpsBearerMuxer_c прошёл пакет
  uint64_c timestamp; // временная метка пакета
  uint32_c service_id; // например, ВИДЕО: [0=YouTube, 1=Instagram, 2=TikTok, ...], НЕ ВИДЕО: []65536=Torrent, 65537=WWW, ...]
  char[] data; // данные пакета считанные из PCAP файла
  char* ip_header; // указатель на начало IP заголовка в данных считанного пакета data
  // в начале data можно резервировать место для заголовков стека GTP/UDP/IP и записывать
  //   данные из PCAP файла уже после них
  char* ip_header2; // указатель на начало IP заголовка в стеке GTP/UDP/IP
  char* udp_header2; // указатель на начало UDP заголовка в стеке GTP/UDP/IP
  char* gtp_header2; // указатель на начало GTP заголовка в стеке GTP/UDP/IP
}

// чтение пакетов из PCAP файла
PcapReader_c
{
  PcapPacket_s PcapPacket;
  
  std::shared_ptr<EpsBearerPacket_s> GetPacket()
  {
    PcapPacket = pcap_read_next();
    std::shared_ptr<EpsBearerPacket_s> pkt = std::make_unique<>();
    memcpy(pkt, PcapPacket);
    pkt->pr = this;
    return pkt;
  }
}

// формирование трафика для одного EPS-Bearer
EpsBearer_c
{
  // упорядоченные по времени пакеты от каждого из всех Pcap
  std::list<std::shared_ptr<EpsBearerPacket_s>> Packets;
  // true - Packets.front() ещё не заполнен новым пакетом и требуется ожидание, false - можно забирать Packets.front()
  bool WaitPacket;
  std::mutex PacketsMutex;
  std::cond_var ReadPacketCv;
  std::cond_var GetPacketCv;
  
  std::thread ReadPacket() // функция потока
  {
    // здесь можно реализовать свою логику изменения параметов трафика конкретного EPS-Bearer
    while(условие завершения)
    {
      std::unique_lock(PacketsMutex);
      while(WaitPacket == false) ReadPacketCv.wait();
      std::shared_ptr<EpsBearerPacket_s> pkt_old = Packets.front();
      Packets.pop_front();
      std::shared_ptr<EpsBearerPacket_s> pkt = pkt_old->pr.lock()->GetPacket();
      Packets.priority_push(pkt);
      WaitPacket = false;
      GetPacketCv.notify();
    }
  }
  std::shared_ptr<EpsBearerPacket_s> GetPacket()
  {
    // здесь можно было бы добавить любую логику а-ля traffic control для этого экземпляра EpsBearer_c
    std::unique_lock(PacketsMutex);
    while(WaitPacket == true) GetPacketCv.wait();
    std::shared_ptr<EpsBearerPacket_s> pkt = Packets.front();
    pkt->eb = this;
    WaitPacket = true;
    ReadPacketCv.notify();
    return pkt;
  }
  AddPcap(std::shared_ptr<PcapReader_c> pr)
  {
    std::shared_ptr<EpsBearerPacket_s> pkt = pr->GetPacket();
    std::unique_lock(PacketsMutex);
    Packets.priority_push(pkt);
    WaitPacket = false;
    GetPacketCv.notify();
  }
}

// формирование смешанного трафика от многих EPS-Bearer
EpsBearerMuxer_c
{
  // упорядоченные по времени пакеты от каждого из всех EpsBearer
  std::list<std::shared_ptr<EpsBearerPacket_s>> Packets;
  // true - Packets.front() ещё не заполнен новым пакетом и требуется ожидание, false - можно забирать Packets.front()
  bool WaitPacket;
  std::mutex PacketsMutex;
  std::cond_var ReadPacketCv;
  std::cond_var GetPacketCv;
  
  std::thread ReadPacket() // функция потока
  {
    // здесь можно реализовать свою логику изменения параметов трафика мультиплексора многих EPS-Bearer
    while(условие завершения)
    {
      std::unique_lock(PacketsMutex);
      while(WaitPacket == false) ReadPacketCv.wait();
      std::shared_ptr<EpsBearerPacket_s> pkt_old = Packets.front();
      Packets.pop_front();
      std::shared_ptr<EpsBearerPacket_s> pkt = pkt_old->eb.lock()->GetPacket();
      Packets.priority_push(pkt);
      WaitPacket = false;
      GetPacketCv.notify();
    }
  }
  std::shared_ptr<EpsBearerPacket_s> GetPacket()
  {
    // здесь можно было бы добавить любую логику а-ля traffic control для этого экземпляра EpsBearerMuxer_c
    std::unique_lock(PacketsMutex);
    while(WaitPacket == true) GetPacketCv.wait();
    std::shared_ptr<EpsBearerPacket_s> pkt = Packets.front();
    pkt->ebm = this;
    WaitPacket = true;
    ReadPacketCv.notify();
    return pkt;
  }
  AddEpsBearer(std::shared_ptr<EpsBearer_c> eb)
  {
    std::shared_ptr<EpsBearerPacket_s> pkt = eb->GetPacket();
    std::unique_lock(PacketsMutex);
    Packets.priority_push(pkt);
    WaitPacket = false;
    GetPacketCv.notify();
  }
}

// отправка в сеть от многих EpsBearerMuxer_c
Sender_c
{
  // упорядоченные по времени пакеты от каждого из всех EpsBearerMuxer_c
  std::list<std::shared_ptr<EpsBearerPacket_s>> Packets;
  // true - Packets.front() ещё не заполнен новым пакетом и требуется ожидание, false - можно забирать Packets.front()
  bool WaitPacket;
  std::mutex PacketsMutex;
  std::cond_var ReadPacketCv;
  std::cond_var GetPacketCv;
  
  std::thread SendPacket() // функция потока
  {
    while(условие завершения)
    {
      std::shared_ptr<EpsBearerPacket_s> pkt = GetPacket();
      // здесь происходит отправка пакета в сеть любым желаемым средством (RAW socket, dpdk, ...)
      // при желании здесь же можно сделать механизм объединения пакетов перед отправкой
      send(pkt);
      // после этого отправленный пакет уничтожается (а мог бы возвращаться породившему его PcapReader_c)
    }
  }
  std::thread ReadPacket() // функция потока
  {
    // здесь можно реализовать свою логику изменения параметов всего отправляемого в сеть трафика
    while(условие завершения)
    {
      std::unique_lock(PacketsMutex);
      while(WaitPacket == false) ReadPacketCv.wait();
      std::shared_ptr<EpsBearerPacket_s> pkt_old = Packets.front();
      Packets.pop_front();
      std::shared_ptr<EpsBearerPacket_s> pkt = pkt_old->ebm.lock()->GetPacket();
      Packets.priority_push(pkt);
      WaitPacket = false;
      GetPacketCv.notify();
    }
  }
  std::shared_ptr<EpsBearerPacket_s> GetPacket()
  {
    std::unique_lock(PacketsMutex);
    while(WaitPacket == true) GetPacketCv.wait();
    std::shared_ptr<EpsBearerPacket_s> pkt = Packets.front();
    WaitPacket = true;
    ReadPacketCv.notify();
    return pkt;
  }
  AddEpsBearerMuxer(std::shared_ptr<EpsBearerMuxer_c> ebm)
  {
    std::shared_ptr<EpsBearerPacket_s> pkt = ebm->GetPacket();
    std::unique_lock(PacketsMutex);
    Packets.priority_push(pkt);
    WaitPacket = false;
    GetPacketCv.notify();
  }
}