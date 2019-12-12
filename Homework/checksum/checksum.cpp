#include <stdint.h>
#include <stdlib.h>
/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
const uint8_t protUDP=0x11;

bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
  int headLength = (int)(packet[0]&0xf) << 2;
  int i = 0;
  int sum = 0;
  unsigned short answer = 0;
  for(i = 0;i < headLength;i++) {
    if(i%2 == 0)
      sum += ((int)packet[i]) << 8;
    else
      sum += (int)packet[i];
  }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  if(answer == 0x0000)
    return true;
  return false;
}

int csUDP(uint8_t* pac) {
	return 0;////fuck UDP checksum
	int UDPchecksum = 0;
	uint16_t UDPLength = (((int)pac[24]) << 8) + pac[25];
	for(int i = 12;i < 20;i++) {
		if(i % 2 == 0) {
			UDPchecksum += ((int)pac[i]) << 8;
		} else {
			UDPchecksum += (int)pac[i];
		}
	}
	UDPchecksum += protUDP;
	UDPchecksum += UDPLength;
	//UDP header
	for(int i = 20;i < 26;i++) {
		if(i % 2 == 0) {
			UDPchecksum += ((int)pac[i]) << 8;
		} else {
			UDPchecksum += (int)pac[i];
		}
	}
	UDPchecksum = (UDPchecksum >> 16) + (UDPchecksum & 0xffff);
	UDPchecksum += (UDPchecksum >> 16);
	UDPchecksum = ~UDPchecksum;
	return UDPchecksum;
}