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
    
    int totalLength=(int)(packet[0]&0xf)*4;
    // printf("length:%d\n",totalLength);
    int i=0;
    int sum=0;
    uint8_t *temp=packet;
    uint16_t answer=0;
    for(i=0;i<totalLength;i++) {
      // printf("%x  ",(int)temp[i]);
      if(i%2==0) {
        sum+=((int)temp[i]) << 8;
      } else {
        sum+=(int)temp[i];
      }
    }
    // while(totalLength > 1){    
    //     sum += *temp;
    //     temp++;
    //     totalLength --;
    // }   
    // if(totalLength == 1){  
    //    sum += *(unsigned char *)temp;  
    // }
    // printf("\nraw answer:%x\n",(int)sum);   
    sum=(sum>>16)+(sum&0xffff);
    sum+=(sum>>16);
    answer=~sum;
    // printf("\nanswer:%x\n",(int)answer);
  if(answer == 0x0000){
    return true;
  }
  else
  {
    return false;
  }
  
}
int csUDP(uint8_t* pac) {
	return 0;
}

void csIP(uint8_t* pac) {
	int IPchecksum = 0;
	int headLength = (pac[0] & 0xf) * 4;
	pac[10] = 0;
	pac[11] = 0;
	for(int i = 0;i < headLength;i++) {
	if(i % 2 == 0) {
		IPchecksum += ((int)pac[i]) << 8;
	} else {
		IPchecksum += (int)pac[i];
	}
	}
	IPchecksum = (IPchecksum >> 16) + (IPchecksum & 0xffff);
	IPchecksum += (IPchecksum >> 16);
	IPchecksum = ~IPchecksum;
	pac[10] = IPchecksum >> 8;
	pac[11] = IPchecksum;
}
