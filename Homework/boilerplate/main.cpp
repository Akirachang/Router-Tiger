#include "router_hal.h"
#include "rip.h"
#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <vector>

#define DEBUG

using namespace std;

const uint8_t protUDP=0x11;
const uint8_t protICMP=0x1;
const uint8_t timeTypeError=11;
const uint8_t timeCodeError=0;
const uint8_t unreachTypeError=3;
const uint8_t unreachCodeError=0;
const uint32_t multCast=0x090000e0;

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern void updateTable(RipEntry entry, uint32_t if_index);
extern void DEBUG_printRouterTable();
extern int getIndex(uint32_t addr, uint32_t len);
extern int csUDP(uint8_t* pac);
extern int csIP(uint8_t* pac);
extern vector<RoutingTableEntry> getRTE();


uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序 10.1.1.1
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0203a8c0, 0x0104a8c0, 0x0102000a, 0x0103000a};

macaddr_t MulticastMac = {0x01, 0x00, 0x5e, 0x00, 0x00, 0x09}; //idk big endian or ... fuck

int timeExceed(in_addr_t src_addr, in_addr_t dst_addr);
int unReachable(in_addr_t src_addr, in_addr_t dst_addr);
int Response(in_addr_t src_addr, in_addr_t dst_addr, uint8_t* pac);
uint32_t convertEndianess(uint32_t addr);


uint32_t convertEndianess(uint32_t addr) {
	return ((addr & 0x000000ff) << 24)|((addr & 0x0000ff00) << 8)|((addr & 0x00ff0000) >> 8)|((addr & 0xff000000) >> 24);
}

int main(int argc, char *argv[]) {
	int res = HAL_Init(1, addrs);
	if (res < 0) {
		return res;
	}
  
  // 0b. Add direct routes
  // Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
	for (uint32_t i = 0; i < N_IFACE_ON_BOARD;i++) {
		RoutingTableEntry entry = {
			.addr = addrs[i] & 0x00ffffff, // big endian
			.len = 24, // small endian
			.if_index = i, // small endian
			.nexthop = 0, // big endian, means direct
			.metric = 1
		};
		update(true, entry);
	}

	uint64_t last_time = 0;
	while (1) {
		uint64_t time = HAL_GetTicks();
		if (time > last_time + 5 * 1000) {
			// What to do?
			// send complete routing table to every interface
			// ref. RFC2453 3.8
			// multicast MAC for 224.0.0.9 is 01:00:5e:00:00:09
			#ifdef DEBUG
				printf("muliticast\n");
			#endif
			for (uint32_t i = 0; i < N_IFACE_ON_BOARD;i++) {
				#ifdef DEBUG
					printf("multicast from %08x\n", addrs[i]);
				#endif
				vector<RoutingTableEntry> routers;
				routers=getRTE();
				RipPacket resp;
					resp.command = 2;
					int cnt = 0;
				for(int i = 0;i < routers.size();i++){
					if((convertEndianess(multCast) & 0x00ffffff) != routers.at(i).addr) {
					printf("fill resp, dst_addr:%08x  addr:%08x\n", convertEndianess(multCast), routers.at(i).addr);
					resp.entries[cnt].addr = routers.at(i).addr;
					uint32_t len = routers.at(i).len;
					uint32_t mask = 0;
					for(int j = 0;j < len;j++)
						mask = (mask << 1) + 0x1;// big endian
					resp.entries[cnt].mask = mask;
					resp.entries[cnt].nexthop = routers.at(i).nexthop;
					resp.entries[cnt].metric = routers.at(i).metric;//not sure
					cnt++;
					}
				}
				resp.numEntries = cnt;

					// UDP
					// port = 520
					// source port
					output[20] = 0x02;
					output[21] = 0x08;
					// destination port
					output[22] = 0x02;
					output[23] = 0x08;
					// ...
					// RIP
					uint32_t rip_len = assemble(&resp, &output[20 + 8]);
					//total length of IP packet
					uint16_t totalLength = rip_len + 28;
					//fill IP header

					//this function fill a IP header 
						//version = 4, header length = 5
						output[0] = 0x45;
						//type of service = 0
						output[1] = 0x00;
						//total length
						output[2] = totalLength >> 8;
						output[3] = totalLength;
						//id = 0
						output[4] = 0x00;
						output[5] = 0x00;
						//flags = 0, fragmented offset = 0
						output[6] = 0x00;
						output[7] = 0x00;
						//time to live = 1
						output[8] = 0x01;
						//protocol = 17(UDP)
						output[9] = protUDP;
						//source address = src_addr
						output[12] = convertEndianess(addrs[i]) >> 24;
						output[13] = convertEndianess(addrs[i])>> 16;
						output[14] = convertEndianess(addrs[i]) >> 8;
						output[15] = convertEndianess(addrs[i]);
						//destination address = dst_addr
						output[16] = convertEndianess(multCast) >> 24;
						output[17] = convertEndianess(multCast) >> 16;
						output[18] = convertEndianess(multCast) >> 8;
						output[19] = convertEndianess(multCast);
						csIP(output);

					//length of UDP packet
					uint16_t UDPLength = rip_len + 8;
					output[24] = UDPLength >> 8;
					output[25] = UDPLength;
					// checksum calculation for ip and udp <---- IP checksum already calculated before
					//UDP checksum
					int UDPchecksum = csUDP(output);
					output[26] = UDPchecksum >> 8;
					output[27] = UDPchecksum;
				HAL_SendIPPacket(i, output, totalLength, MulticastMac);
			}
			last_time = time;
			printf("Timer\n");
			#ifdef DEBUG
				DEBUG_printRouterTable();
			#endif
		}

		int mask = (1 << N_IFACE_ON_BOARD) - 1;
		macaddr_t src_mac;
		macaddr_t dst_mac;
		int if_index;
		res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac,
										dst_mac, 1000, &if_index);
		if (res == HAL_ERR_EOF) {
			#ifdef DEBUG
				printf("res == HAL_ERR_EOF\n");
			#endif
			break;
		} else if (res < 0) {
			#ifdef DEBUG
				printf("res < 0\n");
			#endif
			return res;
		} else if (res == 0) {
			// Timeout
			#ifdef DEBUG
				printf("res == 0\n");
			#endif
			continue;
		} else if (res > sizeof(packet)) {
			// packet is truncated, ignore it
			#ifdef DEBUG
				printf("res > sizeof(packet)\n");
			#endif
			continue;
		}
		// res > 0
		// 1. validate
		uint8_t version = packet[0] >> 4;
		if(version != 4 && version != 6) {
			printf("Invalid version\n");
			continue;
		}

		uint8_t TTL = packet[8];
		if(TTL <= 0) {
			printf("Invalid TTL\n");
			continue;
		}

		if (!validateIPChecksum(packet, res)) {
			printf("Invalid IP Checksum\n");
			continue;
		}

		#ifdef DEBUG
			printf("IP valid!\n");
		#endif



		in_addr_t src_addr, dst_addr;
		// extract src_addr and dst_addr from packet
		// big endian
		src_addr = ((int)packet[12] << 24) + ((int)packet[13] << 16) + ((int)packet[14] << 8) + packet[15];
		dst_addr = ((int)packet[16] << 24) + ((int)packet[17] << 16) + ((int)packet[18] << 8) + packet[19];

		in_addr_t rev_dst_addr = convertEndianess(dst_addr);

		#ifdef DEBUG
			printf("source address:%08x\ndestination address:%08x\nconvertEndianess destination address:%08x\nif_index:%d\n", src_addr, dst_addr, rev_dst_addr, if_index);
		#endif

		// 2. check whether dst is me
		bool dst_is_me = false;
		for (int i = 0; i < N_IFACE_ON_BOARD;i++) {
			if (memcmp(&rev_dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
				dst_is_me = true;
				break;
			}
		}
		// TODO: Handle rip multicast address?
		if(rev_dst_addr == multCast) {
			dst_is_me = true;
			#ifdef DEBUG
				printf("multicast address\n");
			#endif
		}

		if (dst_is_me) {
			#ifdef DEBUG
				printf("destination is me!\n");
			#endif
			// TODO: RIP?
			// 3a.1
			RipPacket rip;
			// check and validate
			if (disassemble(packet, res, &rip)) {
				if (rip.command == 1) {
					// 3a.3 request, ref. RFC2453 3.9.1
					// only need to respond to whole table requests in the lab
					#ifdef DEBUG
						printf("processing request, numofentries:%d\nmetric:%d\n", rip.numEntries, rip.entries[0].metric);
					#endif
					if(rip.numEntries == 1 && rip.entries[0].metric == 16) {
						#ifdef DEBUG
							printf("processing request, whole table request\n");
						#endif
						in_addr_t resp_src_addr = dst_addr;
						if(rev_dst_addr == multCast) {
							#ifdef DEBUG
								printf("processing request, dst addr == Multicast addr\n");
							#endif
							for(int i = 0;i < N_IFACE_ON_BOARD;i++) {
								if((addrs[i] & 0x00ffffff) == (convertEndianess(src_addr) & 0x00ffffff)) {
									resp_src_addr = convertEndianess(addrs[i]);
									break;
								}
							}
						}
						#ifdef DEBUG
							printf("processing request, resp src addr = %08x\n", resp_src_addr);
						#endif
						// int length = Response(resp_src_addr, src_addr, output);//what if dst_addr is multicast??????

						RipPacket resp;
							vector<RoutingTableEntry> routers;
								routers=getRTE();
									resp.command = 2;
									int cnt = 0;
								for(int i = 0;i < routers.size();i++){
									if((convertEndianess(multCast) & 0x00ffffff) != routers.at(i).addr) {
									printf("fill resp, dst_addr:%08x  addr:%08x\n", convertEndianess(multCast), routers.at(i).addr);
									resp.entries[cnt].addr = routers.at(i).addr;
									uint32_t len = routers.at(i).len;
									uint32_t mask = 0;
									for(int j = 0;j < len;j++)
										mask = (mask << 1) + 0x1;// big endian
									resp.entries[cnt].mask = mask;
									resp.entries[cnt].nexthop = routers.at(i).nexthop;
									resp.entries[cnt].metric = routers.at(i).metric;//not sure
									cnt++;
									}
								}
								resp.numEntries = cnt;
							// UDP
							// port = 520
							// source port
							output[20] = 0x02;
							output[21] = 0x08;
							// destination port
							output[22] = 0x02;
							output[23] = 0x08;
							// ...
							// RIP
							uint32_t rip_len = assemble(&resp, &output[20 + 8]);
							//total length of IP packet
							uint16_t totalLength = rip_len + 28;
							//fill IP header
							//this function fill a IP header 
							//version = 4, header length = 5
							output[0] = 0x45;
							//type of service = 0
							output[1] = 0x00;
							//total length
							output[2] = totalLength >> 8;
							output[3] = totalLength;
							//id = 0
							output[4] = 0x00;
							output[5] = 0x00;
							//flags = 0, fragmented offset = 0
							output[6] = 0x00;
							output[7] = 0x00;
							//time to live = 1
							output[8] = 0x01;
							//protocol = 17(UDP)
							output[9] = protUDP;
							//source address = src_addr
							output[12] = src_addr >> 24;
							output[13] = src_addr >> 16;
							output[14] = src_addr >> 8;
							output[15] = src_addr;
							//destination address = dst_addr
							output[16] = dst_addr >> 24;
							output[17] = dst_addr >> 16;
							output[18] = dst_addr >> 8;
							output[19] = dst_addr;
							csIP(output);
							//length of UDP packet
							uint16_t UDPLength = rip_len + 8;
							output[24] = UDPLength >> 8;
							output[25] = UDPLength;
							// checksum calculation for ip and udp <---- IP checksum already calculated before
							//UDP checksum
							int UDPchecksum = csUDP(output);
							output[26] = UDPchecksum >> 8;
							output[27] = UDPchecksum;
						// send it back
						HAL_SendIPPacket(if_index, output, totalLength, src_mac);

					} else {
						#ifdef DEBUG
							printf("processing request, not whole table request(do nothing)\n");
						#endif
					}
				} else {
					// 3a.2 response, ref. RFC2453 3.9.2
					// update routing table
					// new metric = ?
					// update metric, if_index, nexthop
					// what is missing from RoutingTableEntry?
					// TODO: use query and update
					// triggered updates? ref. RFC2453 3.10.1
					#ifdef DEBUG
						printf("processing response, num of entries:%d\n", rip.numEntries);
					#endif
					for(int i = 0;i < rip.numEntries;i++) {
						RipEntry entry = rip.entries[i];
						uint32_t newMetirc = entry.metric + 1;
						#ifdef DEBUG
							printf("processing response, new Metric:%d\n", newMetirc);
						#endif
						uint32_t queryNexthop;
						uint32_t queryMetric;
						bool exist = query(entry.addr, &queryNexthop, &queryMetric);
						if(newMetirc > 16 && src_addr != 0xc0a80301 && src_addr != 0xc0a80402 && entry.nexthop == queryNexthop) { //reverse poisoning
							//delete this route
							#ifdef DEBUG
								printf("processing response, delete\n");
							#endif
							uint32_t len = 32;
							uint32_t mask = entry.mask;
							while((mask & 1) == 0) {
								mask >>= 1;
								len--;
							}
							RoutingTableEntry RTEntry = {
								.addr = entry.addr, // big endian
								.len = len, // small endian
								.if_index = if_index, // small endian 
								.nexthop = entry.nexthop, // big endian, means direct
								.metric = entry.metric
							};
							update(false, RTEntry);
						} else {
							#ifdef DEBUG
								printf("processing response, update routing table\n");
							#endif
							if(entry.nexthop == 0) {
								entry.nexthop = convertEndianess(src_addr);
								#ifdef DEBUG
									printf("processing response, next hop == 0, new next hop = %08x\n", entry.nexthop);
								#endif
							}
							//updarte RT
							vector<RoutingTableEntry> routers;
							routers=getRTE();
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
					}
				}
			} else {
				#ifdef DEBUG
					printf("disassemble failed\n");
				#endif
			} 
		} else { //dst_is_me
			#ifdef DEBUG
			printf("forward!\n");
			#endif
			// 3b.1 dst is not me
			// forward
			// beware of endianness
			uint32_t nexthop, dest_if;
			if (query(convertEndianess(dst_addr), &nexthop, &dest_if)) {
				// found
				#ifdef DEBUG
					printf("forward, found\n");
				#endif
				macaddr_t dest_mac;
				// direct routing
				if (nexthop == 0) {
					#ifdef DEBUG
						printf("forward, next hop == 0, dst addr =%08x\n", dst_addr);
					#endif
					nexthop = convertEndianess(dst_addr);
				}
				if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
					// found
					memcpy(output, packet, res);
					// update ttl and checksum
					forward(output, res);
					// TODO: you might want to check ttl=0 case
					uint8_t TTL = output[8];
					if(TTL == 0) {
						//return a ICMP Time Exceeded to sender 
						#ifdef DEBUG
							printf("forward, TTL = 0\n");
						#endif
						int length = timeExceed(dst_addr, src_addr);
						HAL_SendIPPacket(dest_if, output, length, dest_mac);
						continue;
					}
					HAL_SendIPPacket(dest_if, output, res, dest_mac);
				} else {
					// not found
					// you can drop it
					printf("ARP not found for %08x\n", nexthop);
				}
			} else {
				// not found
				// optionally you can send ICMP Host Unreachable
				// maxy : return a ICMP Destination Network Unreachable to sender 
				macaddr_t dest_mac;
				HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac);
				int length = unReachable(dst_addr, src_addr);//???
				HAL_SendIPPacket(dest_if, output, length, dest_mac);
				printf("IP not found for %08x\n", src_addr);
			}
		}
	}
  return 0;
}


int timeExceed(in_addr_t src_addr, in_addr_t dst_addr) {
	uint16_t packetHeaderLength = (packet[0] & 0xf) * 4;
	uint16_t ICMPLength = 8 + packetHeaderLength + 8;
	uint16_t totalLength = 20 + ICMPLength;
	//IP header

	//this function fill a IP header 
	//version = 4, header length = 5
	output[0] = 0x45;
	//type of service = 0
	output[1] = 0x00;
	//total length
	output[2] = totalLength >> 8;
	output[3] = totalLength;
	//id = 0
	output[4] = 0x00;
	output[5] = 0x00;
	//flags = 0, fragmented offset = 0
	output[6] = 0x00;
	output[7] = 0x00;
	//time to live = 1
	output[8] = 0x01;
	//protocol = 17(UDP)
	output[9] = protICMP;
	//source address = src_addr
	output[12] = src_addr >> 24;
	output[13] = src_addr >> 16;
	output[14] = src_addr >> 8;
	output[15] = src_addr;
	//destination address = dst_addr
	output[16] = dst_addr >> 24;
	output[17] = dst_addr >> 16;
	output[18] = dst_addr >> 8;
	output[19] = dst_addr;
	csIP(output);

	//ICMP header
	output[20] = timeTypeError;
	output[21] = timeCodeError;
	for(int i = 0;i < 6;i++)
		output[22 + i] = 0x0;
	//source packet IP header and 8 bytes
	memcpy(output + 20 + 8, packet, size_t(packetHeaderLength));

	output[22] = 0;
	output[23] = 0;
	int checksum = 0;
	for(int i = 0; i < ICMPLength;i++) {
		if(i % 2 == 0) {
			checksum += ((int)output[20 + i]) << 8;
		} else {
			checksum += (int)output[20 + i];
		}
	}
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);
	checksum = ~checksum;
	output[22] = checksum >> 8;
	output[23] = checksum;
	return (int)totalLength;
}


int unReachable(in_addr_t src_addr, in_addr_t dst_addr) {
	uint16_t packetHeaderLength = (packet[0] & 0xf) * 4;
	uint16_t ICMPLength = 8 + packetHeaderLength + 8;
	uint16_t totalLength = 20 + ICMPLength;
	//IP header

	//this function fill a IP header 
	//version = 4, header length = 5
	output[0] = 0x45;
	//type of service = 0
	output[1] = 0x00;
	//total length
	output[2] = totalLength >> 8;
	output[3] = totalLength;
	//id = 0
	output[4] = 0x00;
	output[5] = 0x00;
	//flags = 0, fragmented offset = 0
	output[6] = 0x00;
	output[7] = 0x00;
	//time to live = 1
	output[8] = 0x01;
	//protocol = 17(UDP)
	output[9] = protICMP;
	//source address = src_addr
	output[12] = src_addr >> 24;
	output[13] = src_addr >> 16;
	output[14] = src_addr >> 8;
	output[15] = src_addr;
	//destination address = dst_addr
	output[16] = dst_addr >> 24;
	output[17] = dst_addr >> 16;
	output[18] = dst_addr >> 8;
	output[19] = dst_addr;
	csIP(output);

	//ICMP header
	output[20] = unreachTypeError;
	output[21] = unreachCodeError;
	for(int i = 0;i < 6;i++)
		output[22 + i] = 0x0;
	//source packet IP header and 8 bytes
	memcpy(output + 20 + 8, packet, size_t(packetHeaderLength));

	output[22] = 0;
	output[23] = 0;
	int checksum = 0;
	for(int i = 0; i < ICMPLength;i++) {
		if(i % 2 == 0) {
			checksum += ((int)output[20 + i]) << 8;
		} else {
			checksum += (int)output[20 + i];
		}
	}
	checksum = (checksum >> 16) + (checksum & 0xffff);
	checksum += (checksum >> 16);
	checksum = ~checksum;
	output[22] = checksum >> 8;
	output[23] = checksum;
	return (int)totalLength;
}
