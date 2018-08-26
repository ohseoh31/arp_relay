
struct ip_hdr
{
    unsigned int ip_hl:4;   /* header length */
    unsigned int ip_v:4;    /* version */
    u_int8_t ip_tos;        /* type of service */
    u_short ip_len;         /* total length */
    u_short ip_id;          /* identification */
    u_short ip_off;         /* fragment offset field */
    u_int8_t ip_ttl;        /* time to live */
    u_int8_t ip_p;          /* protocol */
    u_short ip_sum;         /* checksum */
    struct in_addr ip_src;
    struct in_addr ip_dst;
 };


struct ether_h /* 14byte */
{
  unsigned char ether_dst_mac[6];  /*dst_mac 6byte*/
  unsigned char ether_src_mac[6];  /*src_mac 6byte*/  
  unsigned short ether_type; //2byte
};


struct dst_info
{
  unsigned char dst_mac[6];
  struct in_addr ip_dst;
};

struct ARP_Spoof
{
  unsigned char ether_dst_mac[6];
  unsigned char ether_src_mac[6];
  unsigned short opcode;
  struct in_addr ip_src; 
  struct in_addr ip_dst;
  unsigned char my_mac[6];
};

struct ip_info
{
  char *ip_src;
  char *ip_dst;
  char *mac_info;
};

struct relay_info
{
  struct ip_info ip;
  unsigned char sender_mac[6];
  unsigned char receiver_mac[6];
  unsigned char my_mac[6];
};

struct arp_hdr /* 28byte */
{
   unsigned short hardware_type; /* hardware type 2byte */
   unsigned short proto_type;    /* protocol type 2byte */
   u_int8_t hard_add_len;        /* hardware address length 1byte */
   u_int8_t proto_add_len;       /* protocol address length 1byte */
   unsigned short opcode;        /* opcode */
   unsigned char send_mac[6];    /* sender Mac address 6byte */
   struct in_addr ip_src;             /* sender ip address 4byte */
   unsigned char dst_mac[6];     /* destination Mac address 6byte*/
   struct in_addr ip_dst;     	 /* destination ip address 4byte*/
};


struct arp_hdr_tmp /* 28byte */
{
   unsigned short hardware_type; /* hardware type 2byte */
   unsigned short proto_type;    /* protocol type 2byte */
   u_int8_t hard_add_len;        /* hardware address length 1byte */
   u_int8_t proto_add_len;       /* protocol address length 1byte */
   unsigned short opcode;        /* opcode */
   unsigned char send_mac[6];    /* sender Mac address 6byte */
   u_int32_t ip_src;             /* sender ip address 4byte */
   unsigned char dst_mac[6];     /* destination Mac address 6byte*/
   u_int32_t ip_dst;     	 /* destination ip address 4byte*/
};

struct arp_packet /* 14 + 28 byte */
{
   struct ether_h et_h;
   struct arp_hdr arp_h;
   struct ARP_Spoof spoof_info;
   struct ip_info ip_in; 
   struct dst_info dst_in;   	
};

//struct 

void printEthPacket(struct arp_packet * arp_packet){
    int i;
    printf("Ethernet\n");
    printf("---------------------------------------------------------\n\n");
    printf ("dst_mac : ");
    for (i =0 ; i< 6 ; i++ ){
        printf("%02x",arp_packet->et_h.ether_dst_mac[i]);
      if (i !=5)
                printf(":");
    }
    printf("\n");
    printf ("src_mac : ");
    for (i =0 ; i< 6 ; i++ ){
        printf("%02x",arp_packet->et_h.ether_src_mac[i]);
        if (i !=5)
                printf(":");
    }
    printf("\n");
    printf ("ether_Type : %d(0x%02x)\n",ntohs(arp_packet->et_h.ether_type),ntohs(arp_packet->et_h.ether_type));
    printf("---------------------------------------------------------\n\n");


    printf("IP header\n");

    printf("---------------------------------------------------------\n\n");
    printf("hardware_type : %04x\n",ntohs(arp_packet->arp_h.hardware_type));
    printf("proto_type    : %04x\n",ntohs(arp_packet->arp_h.proto_type));
    printf("hard_add_len  : %02x\n",ntohs(arp_packet->arp_h.hard_add_len));
    printf("hard_add_len  : %02x\n",ntohs(arp_packet->arp_h.proto_add_len));

    printf("opcode        : %04x\n",ntohs(arp_packet->arp_h.proto_add_len));
    printf ("send_mac : ");
    for (i =0 ; i< 6 ; i++ ){
        printf("%02x",arp_packet->arp_h.send_mac[i]);
        if (i !=5)
                printf(":");
    }printf("\n");
    //ip_src
    printf("ip_src : %s\n", inet_ntoa(arp_packet->arp_h.ip_src));
    printf("hard_add_len  : %02x\n",ntohs(arp_packet->arp_h.proto_add_len));
    printf ("dst_mac  : ");
    for (i =0 ; i< 6 ; i++ ){
        printf("%02x",arp_packet->arp_h.dst_mac[i]);
        if (i !=5)
                printf(":");
    }printf("\n");
    //ip_dst
    printf("ip_dst : %s\n", inet_ntoa(arp_packet->arp_h.ip_dst));
    printf("hard_add_len  : %02x\n",ntohs(arp_packet->arp_h.proto_add_len));
    printf("---------------------------------------------------------\n\n");
}


