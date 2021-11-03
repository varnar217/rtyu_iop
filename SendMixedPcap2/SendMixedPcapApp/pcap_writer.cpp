#include "Global.h"
#include "Log.h"
#include "DateTime.h"
#include "common.h"
#include "pcap_writer.h"
#include <string>

#if ELIJA_TODO
// ещё раз продумать и проверить работу с libpcap для записи PCAP файла. что, где и как использовать?
#endif

//------------------------------------------------------------------------------
PcapWriter_c::PcapWriter_c(std::string& path, unsigned int max_size) : Path(path), MaxSize(max_size*1000000)
{
	PRINT_LOG(PRINT_LEVEL::MIDDLE, "PcapWriter(%p): is creating)\n", this);
	// не записывать дополнительных сетевых заголовков
	//Pod = pcap_open_dead(DLT_RAW, 65536);
	Pod = pcap_open_dead_with_tstamp_precision(DLT_RAW, 65536, PCAP_TSTAMP_PRECISION_MICRO);
	//Pod = pcap_open_dead_with_tstamp_precision(DLT_RAW, 65536, PCAP_TSTAMP_PRECISION_NANO);
	PRINT_LOG(PRINT_LEVEL::MIDDLE, "PcapWriter(%p): has created)\n", this);
}

//------------------------------------------------------------------------------
PcapWriter_c::~PcapWriter_c()
{
	PRINT_LOG(PRINT_LEVEL::MIDDLE, "PcapWriter(%p): is deleting)\n", this);
	// закрыть PCAP файл
  if(Pdo)
    pcap_dump_close(Pdo);
	// закрыть файл разметки
	if(TaggedFile)
		fclose(TaggedFile);
	PRINT_LOG(PRINT_LEVEL::MIDDLE, "PcapWriter(%p): has deleted)\n", this);
}

//------------------------------------------------------------------------------
bool PcapWriter_c::WritePacket(u_char* data, int size, bool video, uint64_t ts)
{
	struct pcap_pkthdr ph;
	ph.caplen = size;
	ph.len = size;

	ph.ts.tv_sec = ts / 1000000; // секунды
	ph.ts.tv_usec = ts % 1000000; // микросекунды
	
	// если PCAP файл превысил максимальный размер, то прекратить запись в этот файл
	if(Size > MaxSize)
	{
		pcap_dump_close(Pdo);
		Pdo = nullptr;
		Size = 0;
		
		fclose(TaggedFile);
	}
	
	// если PCAP файл ещё не открыт, то открыть его
	if(Pdo == nullptr)
	{
		std::string name = Path + "/" + DateTime::GetEpochTimeStringHTP() + ".pcap";
		Pdo = pcap_dump_open(Pod, name.c_str());
		if(Pdo == nullptr)
		{
			PRINT_ERR(PRINT_LEVEL::MIDDLE, "PcapWriter(%p): File %s cannot be opened for writing (error: %s)\n", this, name.c_str(), pcap_geterr(Pod));
			return false;
		}
		
		name += ".tag";
		TaggedFile = fopen(name.c_str(), "wb");
		if(TaggedFile == NULL)
		{
			PRINT_ERR(PRINT_LEVEL::MIDDLE, "PcapWriter(%p): File %s cannot be opened for writing\n", this, name.c_str());
			return false;
		}
	}
	
	// записать пакет в файл
	pcap_dump((u_char*)Pdo, &ph, data);
	if(pcap_dump_flush(Pdo) != 0)
	{
		PRINT_ERR(PRINT_LEVEL::MIDDLE, "PcapWriter(%p): Output PCAP file flushing error (packet count = %llu)\n", this, PacketCount);
		return false;
	}

	// порядковый номер пакета
	if(fwrite(&PacketCount, sizeof(PacketCount), 1, TaggedFile) != 1)
	{
		PRINT_ERR(PRINT_LEVEL::MIDDLE, "PcapWriter(%p): Tagged file writing error (packet count = %llu)\n", this, PacketCount);
		return false;
	}
	// временная метка пакета в микросекундах
	if(fwrite(&ts, sizeof(ts), 1, TaggedFile)!= 1)
	{
		PRINT_ERR(PRINT_LEVEL::MIDDLE, "PcapWriter(%p): Tagged file writing error (packet time stamp = %llu)\n", this, ts);
		return false;
	}
	// размер пакета в байтах
	if(fwrite(&size, sizeof(size), 1, TaggedFile) != 1)
	{
		PRINT_ERR(PRINT_LEVEL::MIDDLE, "PcapWriter(%p): Tagged file writing error (packet size = %i)\n", this, size);
		return false;
	}
	// 1 = пакет содержит сервис видео, 0 = не содержит
	if(fwrite(&video, sizeof(video), 1, TaggedFile) != 1)
	{
		PRINT_ERR(PRINT_LEVEL::MIDDLE, "PcapWriter(%p): Tagged file writing error (packet contains video service = %i)\n", this, video);
		return false;
	}
	
  // размер PCAP файла
  Size += size + sizeof(struct pcap_pkthdr);
	// увеличить счётчик количества обработанных пакетов
	PacketCount++;
	return true;
}

