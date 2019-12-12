#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(response) and 0(request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'z', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， z 是否为 0，
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool isValid(uint32_t mask){

  int count=0;
  uint8_t curr;
  uint8_t before;

  for(int i=0;i<8;i++){
    
    if(i>0){
    mask = mask>>4;
    curr=mask&0xf;
    // printf("%x ",curr);
    if(curr!=before){
      // printf("curr:%x ",curr);
      // printf("before:%x ",before);
      // printf("num:%d ",i);   111111000000   10101001010101 111111110000000 11111111111 00000000000 11111100000011111
      count++;
    }
  before=curr;
    }
  else{
    curr=mask&0xf;
    before=curr;

  }
  
  }
  if(count==0||count==1)
    return true;

  // printf("%d ",count);
  return false;

}

bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // TODO:
  if((((int)packet[2])<<8)+packet[3]>len)
    {
         return false;
    }
  

  uint16_t z=((int)packet[30]<<8)+packet[31];

  if(z!=0x0000)
    return false;
  // printf("sup0");
int divide=((((int)packet[2])<<8)+packet[3]-(packet[0]&0xf)*4)/24;

output->numEntries=0;
output->command=packet[28];
uint8_t command=packet[28];
uint8_t version=packet[29];

  if(!((command==0x02||command==0x01) && version==0x02)){
    // printf("ccccc");
    return false;
  }

for(int i=0;i<divide;i++){
  int curr=i*20;
    uint16_t afi=((int)packet[32+curr]<<8)+packet[33+curr];
    if((command==0x02 && afi==0x0002) || (command==0x01 && afi==0x0000))
      {
        uint32_t metric=((int)packet[48+curr]<<24)+((int)packet[49+curr]<<16)+((int)packet[50+curr]<<8)+packet[51+curr];
        if(metric<=16&&metric>=1){
        uint32_t mask=((int)packet[40+curr]<<24)+((int)packet[41+curr]<<16)+((int)packet[42+curr]<<8)+packet[43+curr];

          if(!isValid(mask)){
            return false;
          }
            
            int numEntry=output->numEntries;
            output->entries[numEntry].addr=((int)packet[39+curr]<<24)+((int)packet[38+curr]<<16)+((int)packet[37+curr]<<8)+packet[36+curr];
            output->entries[numEntry].mask=((int)packet[43+curr]<<24)+((int)packet[42+curr]<<16)+((int)packet[41+curr]<<8)+packet[40+curr];;
            output->entries[numEntry].metric = ((int)packet[48 + curr] << 24) + ((int)packet[49 + curr] << 16) + ((int)packet[50 + curr] << 8) + packet[51 + curr];
            output->entries[numEntry].nexthop=((int)packet[47+curr]<<24)+((int)packet[46+curr]<<16)+((int)packet[45+curr]<<8)+packet[44+curr];
            output->numEntries++; 
        }
        else{
          // printf("sup2");
          return false;
        }
      }
      else{
        // printf("sup3");
        return false;
      }
    
    }
  
return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、z、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  buffer[0]=rip->command;
  buffer[1]=0x2;
  buffer[2]=0x00;
  buffer[3]=0x00;

  for(int i=0;i<rip->numEntries;i++){
  RipEntry entry = rip->entries[i];
  int curr=i*20;
  
  if(rip->command==0x2){
    buffer[4+curr]=0x00;
    buffer[5+curr]=0x02;
  }
  else{
    buffer[4+curr]=0x00;
    buffer[5+curr]=0x00;
  }
  buffer[7+curr]=0x00;
  buffer[6+curr]=0x00;

  //ip address
  buffer[11+curr]=entry.addr>>24;
  buffer[10+curr]=entry.addr>>16;
  buffer[9+curr]=entry.addr>>8;
  buffer[8+curr]=entry.addr;

  //mask
  buffer[15+curr]=entry.mask>>24;
  buffer[14+curr]=entry.mask>>16;
  buffer[13+curr]=entry.mask>>8;
  buffer[12+curr]=entry.mask;

  //nexthop
  buffer[19+curr]=entry.nexthop>>24;
  buffer[18+curr]=entry.nexthop>>16;
  buffer[17+curr]=entry.nexthop>>8;
  buffer[16+curr]=entry.nexthop;

  //metrics
  buffer[23+curr]=entry.metric>>24;
  buffer[22+curr]=entry.metric>>16;
  buffer[21+curr]=entry.metric>>8;
  buffer[20+curr]=entry.metric;

}
  return (rip->numEntries)*20+4;
}
