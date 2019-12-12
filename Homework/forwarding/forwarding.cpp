#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
/**
 * @brief 进行转发时所需的 IP 头的更新：
 *        你需要先检查 IP 头校验和的正确性，如果不正确，直接返回 false ；
 *        如果正确，请更新 TTL 和 IP 头校验和，并返回 true 。
 *        你可以从 checksum 题中复制代码到这里使用。
 * @param packet 收到的 IP 包，既是输入也是输出，原地更改
 * @param len 即 packet 的长度，单位为字节
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validate(uint8_t *packet, size_t len) {
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

bool forward(uint8_t *packet, size_t len) {
  // TODO:
  
  int totalLength=(int)(packet[0]&0xf)*4;
  uint8_t *temp=packet;
  int i;
    // printf("length:%d\n",totalLength);
  if(!validate(packet,len)){
    return false;
  }
  else
  {
    temp[8]=temp[8]-1;
    int new_sum=0;
    for(i=0;i<totalLength;i++) {
      // printf("%x  ",(int)temp[i]);
      int curr = (int)temp[i];
      if(i==10)
      {
        continue;
      }
      else if(i==11)
      {
        continue;
      }
      if(i%2==0) {
        new_sum+=curr << 8;
      } else {
        new_sum+=curr;
      }
    }
    // printf("rawchecksum:%x\n",checksum);
    new_sum=(new_sum>>16)+(new_sum&0xffff);
    new_sum+=(new_sum>>16);
    new_sum=~new_sum;
    // printf("checksum:%x\n",checksum);
    temp[11]=new_sum&0xff;
    temp[10]=new_sum>>8; //shift right 8 digits 

    return true;
  }
}
