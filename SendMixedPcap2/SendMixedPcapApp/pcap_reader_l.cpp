#include "Global.h"
#include "Log.h"
#include "DateTime.h"
#include "common.h"
#include "pcap_reader.h"

#if USE_PCAP_READ == USE_PCAP_READ_LIBPCAP

#include <memory.h>
#include <experimental/random>

#define USE_PCAP_READ_LIBPCAP 1 // читать пакеты из pcap файла с помощью библиотеки Libpcap
#define USE_PCAP_READ_FREAD 2 // читать пакеты из pcap файла с помощью fread()
#define USE_PCAP_READ USE_PCAP_READ_LIBPCAP // выбор средства чтения pcap файла

#define USE_PCAP_NEXT 1 // 1 = pcap_next(); 0 = pcap_next_ex()
#define USE_FAKE_PACKET_MALLOC 0 // использовать один и тот жезаранее подготовленный буфер для пакета (=1) или создавать его заново каждый раз (=0)
#define USE_FAKE_PACKET_READ 0 // использовать данные из фиктивного заранее подготовленного пакета размером 1378 байт (=1) или реально считывать их из PCAP файла (=0)

#define USE_TIMESTAMP_SCALING 1 // использовать (=1) или нет (=0) искусстенное масштабирование значений временных меток пакетов
#if USE_TIMESTAMP_SCALING
double TimestampScalingCoeff = 0.0001;
#endif

#if USE_FAKE_PACKET_MALLOC
std::shared_ptr<EpsBearerPacket_s> FakePacketPtr;
#endif

#if USE_FAKE_PACKET_READ
unsigned char FakePacketBytes[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00,
  0x05, 0x62, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11,
  0x2a, 0xac, 0x4d, 0x25, 0xfc, 0x0f, 0xc0, 0xa8,
  0x01, 0x02, 0x01, 0xbb, 0x82, 0x49, 0x05, 0x4e,
  0x00, 0x00, 0x08, 0xfe, 0xaa, 0x4c, 0xfc, 0xcb,
  0xa0, 0x87, 0xb7, 0x01, 0xd6, 0xbf, 0xbd, 0x08,
  0x05, 0x50, 0x50, 0xd8, 0xa4, 0x01, 0x70, 0x67,
  0x40, 0x01, 0x05, 0xee, 0x01, 0x00, 0x06, 0x00,
  0xa0, 0x01, 0x02, 0x5b, 0x52, 0x45, 0x4a, 0x00,
  0x07, 0x00, 0x00, 0x00, 0x53, 0x54, 0x4b, 0x00,
  0x38, 0x00, 0x00, 0x00, 0x53, 0x4e, 0x4f, 0x00,
  0x6c, 0x00, 0x00, 0x00, 0x50, 0x52, 0x4f, 0x46,
  0x6c, 0x01, 0x00, 0x00, 0x53, 0x43, 0x46, 0x47,
  0xf3, 0x01, 0x00, 0x00, 0x52, 0x52, 0x45, 0x4a,
  0xf7, 0x01, 0x00, 0x00, 0x53, 0x54, 0x54, 0x4c,
  0xff, 0x01, 0x00, 0x00, 0x43, 0x52, 0x54, 0xff,
  0x1b, 0x02, 0x00, 0x00, 0x0e, 0x66, 0x2e, 0x75,
  0xf4, 0x94, 0x1b, 0xcd, 0x45, 0x9c, 0x22, 0x9b,
  0x0c, 0x16, 0xe6, 0xa2, 0xe3, 0x37, 0x22, 0xee,
  0x01, 0x30, 0x6a, 0x7c, 0xd3, 0xd4, 0x82, 0x8c,
  0xa1, 0xcc, 0x0d, 0x22, 0x15, 0xc9, 0xe2, 0xf7,
  0xc1, 0x6b, 0xc4, 0x8f, 0xe5, 0x14, 0x02, 0x9a,
  0x4a, 0x51, 0x52, 0x6a, 0x4d, 0x48, 0xca, 0xfc,
  0x56, 0x1f, 0x0d, 0x83, 0xab, 0x2a, 0xb7, 0x5f,
  0xfc, 0xff, 0x38, 0xc8, 0x18, 0x63, 0x1d, 0x7e,
  0x0d, 0xcb, 0x35, 0x5d, 0xae, 0x23, 0x12, 0x0d,
  0x17, 0xac, 0xbf, 0x9d, 0x49, 0x19, 0xb1, 0x89,
  0x1a, 0x7e, 0x67, 0xa3, 0x88, 0x9c, 0xad, 0x9f,
  0xae, 0x37, 0xc0, 0xdd, 0xba, 0x73, 0x19, 0x44,
  0xa8, 0xe7, 0xb1, 0xa8, 0xe6, 0x6a, 0x5b, 0xd6,
  0x87, 0x3d, 0x5f, 0x9e, 0xbb, 0x6a, 0xd8, 0xd1,
  0x59, 0x31, 0xc8, 0x86, 0xd6, 0x29, 0x6f, 0x8a,
  0x15, 0xd3, 0xb0, 0x21, 0x33, 0xe5, 0x7c, 0x60,
  0x82, 0x49, 0xfe, 0x51, 0xbd, 0x28, 0xfd, 0x71,
  0x1e, 0xe9, 0x09, 0xd4, 0x85, 0xc3, 0xe1, 0xd7,
  0xe3, 0xfc, 0x50, 0x50, 0x4b, 0x15, 0xad, 0xa9,
  0x2d, 0xca, 0xbb, 0x3c, 0xdf, 0x2c, 0xba, 0x83,
  0x1e, 0xc9, 0xdf, 0xb4, 0x33, 0xf1, 0xff, 0x12,
  0xe1, 0x9b, 0x4a, 0x2e, 0xee, 0x93, 0x84, 0xe9,
  0x53, 0x73, 0x47, 0xda, 0x33, 0xce, 0xca, 0x9a,
  0x36, 0x5e, 0xc8, 0x26, 0x23, 0xa8, 0x95, 0x61,
  0x50, 0xc3, 0xbf, 0xcb, 0xd8, 0xd0, 0xfb, 0x8b,
  0xbc, 0x05, 0xaf, 0x72, 0xb5, 0xea, 0xbb, 0x1a,
  0x0f, 0xbe, 0xa7, 0xa5, 0x20, 0x17, 0xb1, 0xee,
  0x92, 0xf6, 0xf2, 0x15, 0xeb, 0x5e, 0x76, 0x84,
  0xda, 0xea, 0x03, 0x5a, 0x59, 0xe3, 0x7f, 0x01,
  0x16, 0x61, 0x16, 0x05, 0x28, 0x40, 0x33, 0x26,
  0xd6, 0x92, 0x8e, 0x42, 0x45, 0xea, 0xdf, 0x45,
  0x3a, 0x9a, 0x95, 0x2a, 0x8d, 0x63, 0xb0, 0x4a,
  0xef, 0x75, 0x88, 0x4f, 0x1a, 0xa1, 0x7f, 0x1e,
  0xb5, 0x53, 0xc6, 0x45, 0xc7, 0xc4, 0xe8, 0x0f,
  0x60, 0x20, 0x66, 0x4a, 0x58, 0xc5, 0xe4, 0xfa,
  0x65, 0x6c, 0x4e, 0x83, 0xd6, 0x20, 0x97, 0x6d,
  0x0a, 0x28, 0x6e, 0x14, 0x4c, 0x64, 0x4c, 0x83,
  0x13, 0xe7, 0x11, 0xa7, 0x6c, 0x42, 0xd7, 0xa2,
  0x85, 0x6a, 0x85, 0x06, 0x96, 0x89, 0xa6, 0x42,
  0x1a, 0x14, 0x15, 0xaa, 0x3b, 0xed, 0x54, 0x9c,
  0x6d, 0x5f, 0x8e, 0xf5, 0x05, 0xc2, 0xb2, 0xc8,
  0x8c, 0xb7, 0xb4, 0xc8, 0xe2, 0xde, 0x78, 0x95,
  0xaf, 0x36, 0xe0, 0xc7, 0xc0, 0x88, 0xc4, 0x75,
  0x44, 0xc7, 0x28, 0xf5, 0x1c, 0x7a, 0xb9, 0x1a,
  0x8b, 0xfd, 0x1b, 0xb8, 0x89, 0xf7, 0xb1, 0x26,
  0x53, 0x43, 0x46, 0x47, 0x06, 0x00, 0x00, 0x00,
  0x41, 0x45, 0x41, 0x44, 0x08, 0x00, 0x00, 0x00,
  0x53, 0x43, 0x49, 0x44, 0x18, 0x00, 0x00, 0x00,
  0x50, 0x55, 0x42, 0x53, 0x3b, 0x00, 0x00, 0x00,
  0x4b, 0x45, 0x58, 0x53, 0x3f, 0x00, 0x00, 0x00,
  0x4f, 0x42, 0x49, 0x54, 0x47, 0x00, 0x00, 0x00,
  0x45, 0x58, 0x50, 0x59, 0x4f, 0x00, 0x00, 0x00,
  0x41, 0x45, 0x53, 0x47, 0x43, 0x43, 0x32, 0x30,
  0x7c, 0x4e, 0x96, 0x0e, 0x6f, 0x0c, 0x00, 0x53,
  0xc1, 0xf1, 0xfa, 0xdc, 0x22, 0x6e, 0xb8, 0xc1,
  0x20, 0x00, 0x00, 0x2b, 0x33, 0x37, 0xd6, 0x9a,
  0x42, 0x9d, 0xc0, 0x0d, 0xec, 0x6f, 0xda, 0xd9,
  0x52, 0x9c, 0x50, 0xb3, 0x9b, 0xee, 0x6a, 0x00,
  0x41, 0x7a, 0x7c, 0x40, 0x04, 0x27, 0x79, 0xb5,
  0x9d, 0xb7, 0x44, 0x43, 0x32, 0x35, 0x35, 0xb5,
  0x82, 0xfa, 0xf5, 0x0c, 0xf3, 0xc8, 0xf9, 0x8d,
  0xf9, 0x0a, 0x62, 0x00, 0x00, 0x00, 0x00, 0x0d,
  0x00, 0x00, 0x00, 0xac, 0xb7, 0xea, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x02, 0x00, 0xaf, 0x97, 0x18,
  0x26, 0x80, 0xbe, 0x03, 0x02, 0x1e, 0x4d, 0x62,
  0xa3, 0x66, 0x4e, 0x7b, 0xa7, 0x02, 0xc2, 0x98,
  0xe3, 0x35, 0x48, 0x8a, 0x34, 0xc7, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#endif

//------------------------------------------------------------------------------
PcapReader_c::PcapReader_c(GeneratorParams_s& gparams, GeneratorParams_s::Pcap_s& pparams, GeneratorParams_s::EpsBearer_s& eparams) :
  GeneratorParams(gparams), PcapParams(pparams), EpsBearerParams(eparams)
{
  PRINT_LOG(PRINT_LEVEL::HIGH, "PcapReader_c(%p)::USE_GTP=%i\n", this, USE_GTP);
  PRINT_LOG(PRINT_LEVEL::HIGH, "PcapReader_c(%p)::USE_TIMESTAMP_SCALING=%i (coeff=%f)\n", this, USE_TIMESTAMP_SCALING, TimestampScalingCoeff);
  PRINT_LOG(PRINT_LEVEL::HIGH, "PcapReader_c(%p)::USE_FAKE_PACKET_MALLOC=%i\n", this, USE_FAKE_PACKET_MALLOC);
  PRINT_LOG(PRINT_LEVEL::HIGH, "PcapReader_c(%p)::USE_FAKE_PACKET_READ=%i\n", this, USE_FAKE_PACKET_READ);
  PRINT_LOG(PRINT_LEVEL::HIGH, "PcapReader_c(%p)::USE_PCAP_READ=%i (%s)\n", this, USE_PCAP_READ,
  USE_PCAP_READ == USE_PCAP_READ_LIBPCAP ? "Libpcap" : USE_PCAP_READ == USE_PCAP_READ_FREAD ?
  "Fread" : "Error");
}

//------------------------------------------------------------------------------
PcapReader_c::~PcapReader_c()
{
	Close();
}

//------------------------------------------------------------------------------
bool PcapReader_c::Open()
{
  char ErrorBuffer[PCAP_ERRBUF_SIZE];
  
#if USE_PCAP_READ == USE_PCAP_READ_LIBPCAP
  //Pcap = pcap_open_offline(PcapParams.Path.c_str(), ErrorBuffer);
  Pcap = pcap_open_offline_with_tstamp_precision(PcapParams.Path.c_str(), PCAP_TSTAMP_PRECISION_MICRO /*PCAP_TSTAMP_PRECISION_NANO*/, ErrorBuffer);
  if(Pcap == NULL)
	{
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "PCAP file %s has not opened (error: %s)\n", PcapParams.Path.c_str(), ErrorBuffer);
    std::string msg = std::string("PCAP file ") + PcapParams.Path + std::string(" open error");
    HttpClient.SendErr(msg);
		return false;
	}
  PRINT_LOG(PRINT_LEVEL::MIDDLE, "PCAP file %s has opened successfully\n", PcapParams.Path.c_str());

  // сохраняем текущую позицию в файле как начальную позицию
  PcapBeginPos = ftell(pcap_file(Pcap));
  if(PcapBeginPos == -1)
	{
    return false;
	}

  // считываем первый пакет файла, чтобы получить его временную метку
#if USE_PCAP_NEXT
  const unsigned char *packet = pcap_next(Pcap, &PacketHeader);
  if (packet == NULL)
	{
    return false;
	}
#else
  struct pcap_pkthdr * header;
  const unsigned char * data;
  int err = pcap_next_ex(Pcap, &header, &data);
  if(err != 1)
  {
    if(err == 0)
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "pcap_next_ex() error: timeout expired for a live capture\n");
    else if(err == -1)
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "pcap_next_ex() error: %s\n", pcap_geterr(Pcap));
    else if(err == -2)
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "pcap_next_ex() error: no more packets to read from the savefile\n");
    else
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "pcap_next_ex() error: undefined\n");
    return false;
  }
  PacketHeader = *header;
#endif
	uint64_t ts = PacketHeader.ts.tv_sec*1000000UL + PacketHeader.ts.tv_usec; // микросекунды
#if USE_TIMESTAMP_SCALING
	ts = ts * TimestampScalingCoeff;
#endif
  PacketLastTimestamp = PacketFirstTimestamp = ts;

  // вычисляем и сохраняем конечную позицию в файле
  if(fseek(pcap_file(Pcap), 0, SEEK_END) != 0)
	{
    return false;
	}
  PcapEndPos = ftell(pcap_file(Pcap));
  if(PcapEndPos == -1)
	{
    return false;
	}

  // возвращаемся к сохранённой начальной позиции
  if(fseek(pcap_file(Pcap), PcapBeginPos, SEEK_SET) != 0)
	{
    return false;
	}
#elif USE_PCAP_READ == USE_PCAP_READ_FREAD
#else
illegal option USE_PCAP_READ
#endif
    
#if USE_FAKE_PACKET_MALLOC
  FakePacketPtr = std::make_shared<EpsBearerPacket_s>();
//#if USE_FAKE_PACKET_READ
//  FakePacketPtr->Timestamp = 0;
//  FakePacketPtr->IpHeader = (struct sniff_ip*)(FakePacketBytes + 14);
//#endif
#endif
  return true;
}

//------------------------------------------------------------------------------
void PcapReader_c::Close()
{
#if USE_PCAP_READ == USE_PCAP_READ_LIBPCAP
  // если файл был открыт, то его требуется зкрыть
  if(Pcap)
  {
    pcap_close(Pcap);
    Pcap = NULL;
    PRINT_LOG(PRINT_LEVEL::MIDDLE, "PCAP file %s has closed\n", PcapParams.Path.c_str());
  }
#elif USE_PCAP_READ == USE_PCAP_READ_FREAD
#else
illegal option USE_PCAP_READ
#endif
}

//------------------------------------------------------------------------------
bool PcapReader_c::Restart()
{
#if USE_PCAP_READ == USE_PCAP_READ_LIBPCAP
  // возвращаемся к сохранённой начальной позиции
  if(fseek(pcap_file(Pcap), PcapBeginPos, SEEK_SET) != 0)
    return false;
  PacketRestartTimestamp = PacketLastTimestamp;
  return true;
#elif USE_PCAP_READ == USE_PCAP_READ_FREAD
#else
illegal option USE_PCAP_READ
#endif
}

//------------------------------------------------------------------------------
std::shared_ptr<EpsBearerPacket_s> PcapReader_c::GetPacket()
{
    //PRINT_TMP(PRINT_LEVEL::HIGH, "%p:%llu PcapReader_c::GetPacket()\n", this, DateTime::GetAppTimeMicrosecCount());
#if 0
  std::time_t start_time = DateTime::GetAppTimeMicrosecCount();
  PRINT_LOG(PRINT_LEVEL::MIDDLE, "%llu: PcapReader_c(%p) get\n", start_time, this);
#endif
#if USE_FAKE_PACKET_MALLOC
  std::shared_ptr<EpsBearerPacket_s> pkt(FakePacketPtr);
#else
  std::shared_ptr<EpsBearerPacket_s> pkt = std::make_shared<EpsBearerPacket_s>();
#endif

#if USE_FAKE_PACKET_READ
#if ! ELIJA_WARNING // начинали работать с обёрткой из протокола Ethernet, но сейчас используем чистые IP пакеты
  const unsigned char *data = FakePacketBytes;
#else
  const unsigned char *data = FakePacketBytes + SIZE_ETHERNET;
#endif
#else
#if USE_PCAP_READ == USE_PCAP_READ_LIBPCAP
#if USE_PCAP_NEXT  
  const unsigned char *data;
  if ((data = pcap_next(Pcap, &PacketHeader)) == NULL)
  {
    //PRINT_ERR(PRINT_LEVEL::MIDDLE, "pcap_next() error\n");
    if(Restart() == false)
    {
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "pcap_next() error + restart failed\n");
      return nullptr;
    }
    if ((data = pcap_next(Pcap, &PacketHeader)) == NULL)
    {
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "pcap_next() error after restart\n");
      return nullptr;
    }
  }
#else
  struct pcap_pkthdr * header;
  const unsigned char * data;
  int err = pcap_next_ex(Pcap, &header, &data);
  while(err != 1)
  {
    if(err == -2)
    {
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "pcap_next_ex() error = %i: no more packets to read from the savefile\n", err);
      if(Restart())
      {
        err = pcap_next_ex(Pcap, &header, &data);
        continue;
      }
    }
    else if(err == -1)
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "pcap_next_ex() error = %i: %s\n", err, pcap_geterr(Pcap));
    else if(err == 0)
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "pcap_next_ex() error = %i: timeout expired for a live capture\n", err);
    else
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "pcap_next_ex() error = %i: undefined\n", err);
    return nullptr;
  }
  PacketHeader = *header;
#endif
#elif USE_PCAP_READ == USE_PCAP_READ_FREAD
#else
illegal option USE_PCAP_READ
#endif
#endif
    
#if USE_PCAP_READ == USE_PCAP_READ_LIBPCAP
  const struct sniff_ethernet *ethernet; /* Заголовок Ethernet */
  struct sniff_ip *ip; /* Заголовок IP */
  struct sniff_gtp1 *gtp; /* Заголовок GTP поверх IP */
  struct sniff_udp *udp2; /* Заголовок UDP поверх GTP+IP */
  struct sniff_ip *ip2; /* Заголовок IP поверх UDP+GTP+IP */
  
  u_int size_ip_hdr; // размер только заголовка IP пакета

  //PRINT_LOG(PRINT_LEVEL::MIDDLE, "\nPacket number %llu:\n", PacketCount);
  // увеличить счётчик считанных пакетов
  ++PacketCount;

#if ELIJA_WARNING // у нас ВРОДЕ только чистые IP-пакеты, но если вдруг будет сверху обёртка, то под неё нужно писать парсер/анализатор
  /* define/compute ip header offset */
  ip = (struct sniff_ip*)data;
#else // если IP-пакеты оюёрнуты в Ethernet
  /* define ethernet header */
  ethernet = (struct sniff_ethernet*)(data);
  
  /* define/compute ip header offset */
  ip = (struct sniff_ip*)(data + SIZE_ETHERNET);
#endif
  size_ip_hdr = IP_HL(ip)*4;
  if (size_ip_hdr < SIZE_IP) {
      PRINT_ERR(PRINT_LEVEL::MIDDLE, "Invalid IP header length: %u bytes (%s)\n", size_ip_hdr, PcapParams.Path.c_str());
      return nullptr;
  }
  
  size_t size_ip_pkt = ntohs(ip->ip_len); // размер всего IP пакета (заголовок + данные)
#if ELIJA_TODO
/* Почему-то некоторые IP пакеты в PCAP файлах нашей базы имеют неправильное(?) значение ip->ip_len, которое превышает
 * значение pkt_hdr->incl_len, а этого быть не должно. Даже Wireshark подсвечивает красным эту ситуацию.
 * Для решения этой проблемы мы будем назначать ip->ip_len = pkt_hdr->incl_len, что верно в случае работы с "голыми" IP пакетами. */
  if(size_ip_pkt > pkt_hdr->incl_len)
  {
    size_ip_pkt = pkt_hdr->incl_len;
    ip->ip_len = htons(size_ip_pkt);
  }
#endif
  if(size_ip_pkt > EpsBearerPacketMaxSize - (SIZE_GTP + SIZE_UDP + SIZE_IP))
  {
    PRINT_ERR(PRINT_LEVEL::MIDDLE, "IP packet size is too large (current=%llu, maximum=%llu)\n", size_ip_pkt, EpsBearerPacketMaxSize - (SIZE_GTP + SIZE_UDP + SIZE_IP));
    return nullptr;
  }
  // копировать считанные данные в свой пакет
//#if USE_TMP_DEBUG
//#else
#if USE_GTP
  memcpy(pkt->Data + (SIZE_GTP + SIZE_UDP + SIZE_IP), ip, size_ip_pkt);
#else
  memcpy(pkt->Data, ip, size_ip_pkt);
#endif
//#endif
#elif USE_PCAP_READ == USE_PCAP_READ_FREAD
#else
illegal option USE_PCAP_READ
#endif
#if USE_GTP
  pkt->IpHeader2 = (struct sniff_ip*)pkt->Data;
  pkt->UdpHeader2 = (struct sniff_udp*)(pkt->Data + SIZE_IP);
  pkt->GtpHeader = (struct sniff_gtp1*)(pkt->Data + (SIZE_IP + SIZE_UDP));
  pkt->IpHeader = (struct sniff_ip*)(pkt->Data + (SIZE_IP + SIZE_UDP + SIZE_GTP));
	
	pkt->GtpHeader->length = size_ip_pkt;
	pkt->GtpHeader->flags = 0x30;
	pkt->GtpHeader->msg_type = 0xFF;
	pkt->GtpHeader->teid = htonl(GetTeid());
	
	pkt->UdpHeader2->uh_sport = htons(2152);
	pkt->UdpHeader2->uh_dport = htons(2152);
	pkt->UdpHeader2->uh_ulen = htons(size_ip_pkt + (SIZE_UDP + SIZE_GTP));
	pkt->UdpHeader2->uh_sum = 0;
	
	pkt->IpHeader2->ip_vhl = 0x45;
	pkt->IpHeader2->ip_tos = 0;
	pkt->IpHeader2->ip_len = htons(size_ip_pkt + (SIZE_IP + SIZE_UDP + SIZE_GTP));
	pkt->IpHeader2->ip_id = PacketCount & 0xFFFF;
	pkt->IpHeader2->ip_off = 0;
	pkt->IpHeader2->ip_ttl = 64;
	pkt->IpHeader2->ip_p = 17; // UDP
	pkt->IpHeader2->ip_sum = 0;
#else
  pkt->IpHeader = (struct sniff_ip*)pkt->Data;
#endif
//#if USE_TMP_DEBUG
//  pkt->IpHeader = (struct sniff_ip*)ip;
//#endif
  if(GeneratorParams.Gtp.IpSrc.empty())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "There is no source IP address for GTP\n");
		return nullptr;
	}
  if(GeneratorParams.Gtp.IpDst.empty())
	{
		PRINT_ERR(PRINT_LEVEL::HIGH, "There is no destination IP address for GTP\n");
		return nullptr;
	}
#if USE_GTP
  inet_aton(GeneratorParams.Gtp.IpSrc.c_str(), &pkt->IpHeader2->ip_src);
  inet_aton(GeneratorParams.Gtp.IpDst.c_str(), &pkt->IpHeader2->ip_dst);
#else
  inet_aton(GeneratorParams.Gtp.IpSrc.c_str(), &pkt->IpHeader->ip_src);
  inet_aton(GeneratorParams.Gtp.IpDst.c_str(), &pkt->IpHeader->ip_dst);
#endif
    
  // вычислить относительную временную метку пакета (первый пакет файла всегда имеет относительную временную метку равную 0)
#if USE_FAKE_PACKET_READ
  PacketLastTimestamp = pkt->Timestamp = 0;
#else
  uint64_t ts = PacketHeader.ts.tv_sec*1000000UL + PacketHeader.ts.tv_usec; // микросекунды
#if USE_TIMESTAMP_SCALING
	ts = ts * TimestampScalingCoeff;
#endif
  PacketLastTimestamp = pkt->Timestamp = ts - PacketFirstTimestamp + PacketRestartTimestamp;
#endif

	pkt->Video = IsVideo();
  
  // сохраняем указатель на экземпляр создателя этого пакета
  pkt->PcapReader = weak_from_this();

#if 0 // отладочный вывод
  /* print source and destination IP addresses */
  PRINT_LOG(PRINT_LEVEL::HIGH, "       From: %s\n", inet_ntoa(pkt->IpHeader->ip_src));
  PRINT_LOG(PRINT_LEVEL::HIGH, "         To: %s\n", inet_ntoa(pkt->IpHeader->ip_dst));
  PRINT_LOG(PRINT_LEVEL::HIGH, "        Len: %u (%u)\n", ntohs(pkt->IpHeader->ip_len), size_ip_pkt);
  PRINT_LOG(PRINT_LEVEL::HIGH, "  Timestamp: %llu\n", pkt->Timestamp);
#if USE_GTP
  PRINT_LOG(PRINT_LEVEL::HIGH, "GTP IP From: %s\n", inet_ntoa(pkt->IpHeader2->ip_src));
  PRINT_LOG(PRINT_LEVEL::HIGH, "GTP IP   To: %s\n", inet_ntoa(pkt->IpHeader2->ip_dst));
#endif
#endif
  
#if 0
  std::time_t stop_time = DateTime::GetAppTimeMicrosecCount();
  PRINT_LOG(PRINT_LEVEL::MIDDLE, "%llu: PcapReader_c(%p) get time %llu microseconds\n", stop_time, this, stop_time - start_time);
#endif
  return pkt;
}

//------------------------------------------------------------------------------
int PcapReader_c::GetTeid() const
{
	return EpsBearerParams.Id;
}

//------------------------------------------------------------------------------
bool PcapReader_c::IsVideo() const
{
	return PcapParams.Video;
}

//------------------------------------------------------------------------------
GeneratorParams_s::EpsBearer_s& PcapReader_c::GetEpsBearer()
{
	return EpsBearerParams;
}

#endif