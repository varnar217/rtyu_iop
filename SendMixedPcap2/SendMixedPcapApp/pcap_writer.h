/**
 * @file pcap_reader.h
 * @author elija
 * @date 25/10/21
 * @brief работа с PCAP файлом в режиме записи
 */

#pragma once

#include <pcap.h>

/**
 * @class PcapWriter_c
 * @brief класс для работы с открытым в режиме записи PCAP файлом
 */
class PcapWriter_c //: public std::enable_shared_from_this<PcapWriter_c>
{
public:
	PcapWriter_c(std::string& path, unsigned int max_size);
	~PcapWriter_c();
	
	// записать один пакет в файл
	bool WritePacket(u_char* data, int size, bool video, uint64_t ts);
	
private:
	std::string Path; // путь к папке в котрой будут создаваться PACP файл и сопроводительный файл разметки
	unsigned int MaxSize; // максимальный размер PCAP файла в байтах
	unsigned int Size{0}; // текущий размер файла
	
	// параметры PCAP файла в который будут записываться пакеты библиотекой libpcap
	pcap_t* Pod{nullptr};
	// PCAP файл в который будут записываться пакеты библиотекой libpcap
	pcap_dumper_t* Pdo{nullptr};
	// файл сопроводительной разметки PCAP файл
	FILE* TaggedFile{NULL};
	// счётчик количества обработанных пакетов
	uint64_t PacketCount{0};
};