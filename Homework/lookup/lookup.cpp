#include "router.h"
#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <string>
using namespace std;


/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

std::vector<RoutingTableEntry> routers;

vector<RoutingTableEntry> getRTE(){
  return routers;
}
string toHex(int addr){
      stringstream my_ss;
      my_ss << hex << addr;
      string tempStr = my_ss.str();
      return tempStr;
}

int isExist(uint32_t addr, uint32_t len){
  int index=-1;
  for(int i=0;i<routers.size();i++){
    if(routers.at(i).addr==addr && routers.at(i).len==len)
      return i;
  }
  return index;

}

int isExist2(uint32_t addr){
  int index=-1;
  for(int i=0;i<routers.size();i++){
    if(routers.at(i).addr==addr)
      return i;
  }
  return index;

}

void update(bool insert, RoutingTableEntry entry) {
  //TODO:
  if(insert){
    int index=isExist(entry.addr,entry.len);
    if(index==-1){ // does not exist, just insert!
      routers.push_back(entry);
    }
    else{
      routers.at(index).if_index=entry.if_index;
      routers.at(index).nexthop=entry.nexthop;
    }
  }
  else{
    int index=isExist(entry.addr,entry.len);
    routers.erase(routers.begin() + index);
  }
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */

int max_prefix(uint32_t addr){

  int strAdd_toint=(int) addr;
  string strAdd=toHex(strAdd_toint);      

  int max=-1;
  int maxindex=-1;
  for(int i=0;i<routers.size();i++){
      RoutingTableEntry curr=routers.at(i);

      int len=(int)curr.len;
      // string tempStr=to_string((int)curr.addr);

      int decimal = (int)curr.addr;
      string tempStr=toHex(decimal);      
      // tempStr=tempStr.substr(tempStr.size()-(len/4),(len/4));
      // cout<<"tempStr: "<<tempStr<<endl;
      // cout<<"strAdd: "<<strAdd<<endl;
      // cout<<"boolean: "<<tempStr.find(strAdd)<<endl;
      if(strAdd.find(tempStr)!=-1){
        // cout<<"in"<<endl;
        // cout<<tempStr.size()<<endl;
        // cout<<max<<endl;
        // cout<<(max<tempStr.size())<<endl;
        if(max<(int)tempStr.size())
        {
          // cout<<"detect"<<endl;
          max=tempStr.length();
          maxindex=i;
        // cout<<"maxindex"<<maxindex<<endl;
        }
      }
    }

    if(maxindex==-1)
      return -1;
    else
    {
      return maxindex;
    }
    
}

bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  // TODO:

  int index=max_prefix(addr);
  // cout<<index;
  if(index==-1)
    return false;


  *nexthop = routers.at(index).nexthop;
  *if_index = routers.at(index).if_index;

  return true;
}

void updateTable(RipEntry entry, uint32_t if_index) {
  RoutingTableEntry RTEntry;
  RTEntry.addr = entry.addr;
  RTEntry.nexthop = entry.nexthop;
  uint32_t mask = entry.mask;
  uint32_t len = 0;
  printf("update, mask:%08x\n", mask);
  while((mask & 1) != 0) {
    len++;
    mask >>= 1;
  }
  printf("update, len:%d\n", len);
  RTEntry.len = len;
  RTEntry.if_index = if_index;
  RTEntry.metric = entry.metric;

  int index = getIndex(entry.addr, len);
  if(index >= 0) {
    //exist
    printf("update, exist\n");
    if(RTEntry.metric + 1 < routers.at(index).metric) {
      printf("update, newMetric < metric\n");
      RTEntry.metric++;
      update(true, RTEntry);
    }
  } else {
    //not exist
    //but why do not metric add 1 ???
    printf("update, not exist\n");
    RTEntry.metric++;
    update(true, RTEntry);
  }
}

void DEBUG_printRouterTable() {
  printf("f**king debugging babe?\n#########################################\n");
  for(int i = 0;i < routers.size();i++) {
    RoutingTableEntry RTEntry = routers.at(i);
    printf("entry %d:\n", i);
    printf("addr:%08x\nlen:%d\nif_index:%d\nnexthop:%08x\nmetric:%08x\n--------------------------------\n", RTEntry.addr, RTEntry.len, RTEntry.if_index, RTEntry.nexthop, RTEntry.metric);
  }
  printf("#########################################\n");
}