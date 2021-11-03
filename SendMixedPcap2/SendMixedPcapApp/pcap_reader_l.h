/**
 * @file pcap_reader_l.h
 * @author elija
 * @date 15/09/21
 * @brief работа с pcap файлом в режиме чтения с помощью библиотеки libpcap
 */

#pragma once

#include "common.h"
#include <memory>
#include <string>

/**
 * @class PcapReader_c
 * @brief класс для работы с открытым в режиме чтения pcap файлом с помощью библиотеки libpcap
 */
class PcapReader_c: public std::enable_shared_from_this<PcapReader_c>
{
public:
  /**
   * @brief создать экземпляр класса
   * @param [in] file_name имя и полный путь открываемого файла
   * @return для определния успешности открытия нужно анализировать возврат функции Get()
   */
  PcapReader_c(GeneratorParams_s& gparams, GeneratorParams_s::Pcap_s& pparams, GeneratorParams_s::EpsBearer_s& eparams);
  /**
   * @brief уничтожить экземпляр класса
   * открытый файл всегда после завершения работы с ним требуется закрыть
   */
  ~PcapReader_c();
	
	// начать работу с файлом
	bool Open();
  
	// завершить работу с файлом
	void Close();
  
	// взять из очереди пакетов пакет с самой ранней временной меткой
  std::shared_ptr<EpsBearerPacket_s> GetPacket();
	
	// получить ссылку на параметры EpsBearer
	GeneratorParams_s::EpsBearer_s& GetEpsBearer();
	
private:
  // переместиться в начальную позицию файа, то есть к первому пакету файла
  bool Restart();
  
	// получить уникальный идентификатор EpsBearer
	int GetTeid() const;
	
	// узнать содержит ли PCAP файл сервис видео (true=да, false=нет)
	bool IsVideo() const;
  
	GeneratorParams_s& GeneratorParams;
	GeneratorParams_s::Pcap_s& PcapParams;
	GeneratorParams_s::EpsBearer_s& EpsBearerParams;
  pcap_t* Pcap {NULL}; //!< указатель на pcap файл
  struct pcap_pkthdr PacketHeader; // PCAP заголовок считанного из файа пакета
  uint64_t PacketCount {0}; // номер последнего считанного из файла пакета
  uint64_t PacketFirstTimestamp {0}; //!< временная метка первого пакета файла в миллисекундах
  uint64_t PacketLastTimestamp {0}; //!< временная метка последнего считанного пакета файла в миллисекундах
  uint64_t PacketRestartTimestamp {0}; //!< временная метка первого пакета файла после рестарта в миллисекундах
  long int PcapBeginPos {0}; //!< начальная позиция в файле (соответстует первому пакету файла)
  long int PcapEndPos {0}; //!< конечная позиция в файле
};
