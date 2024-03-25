/*
 * This file is part of the Capibara zero
 * project(https://capibarazero.github.io/).
 *
 * Copyright (c) 2024 Andrea Canale.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdint.h>

typedef struct arp_hdr {
    uint16_t hw_type;  // Hardware type
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
} arp_hdr;

#define ETH_HDRLEN 14  // Ethernet header length
#define ARP_HDRLEN 28  // ARP header length
#define ETH_HW_TYPE 0x0800
#define ARP_REPLY_OPCODE 2
#define MAC_ADDRESS_LENGTH 6
#define IPV4_LENGTH 4
#define ETH_ARP_HW_TYPE 1
#define ETHERNET_PROTOCOL_ARP 0x0806
#define PACKET_LENGTH 42  // ETH packet + ARP packet

class ARP_poisoner {
   private:
    uint8_t broadcast_mac_address[6];
    arp_hdr arp_pkt;
    uint8_t ether_frame[PACKET_LENGTH];
    uint8_t *get_current_ip();
    void fill_arp_hdr(uint8_t *src_mac, uint8_t *src_ip, uint8_t *dest_mac,
                      uint8_t *dest_ip);
    uint8_t src_mac[MAC_ADDRESS_LENGTH];
    uint8_t *src_ip = get_current_ip();

   public:
    ARP_poisoner();
    ~ARP_poisoner();
    void send_arp_packet(uint8_t dest_ip[IPV4_LENGTH],
                         uint8_t dest_mac[MAC_ADDRESS_LENGTH]);
};
