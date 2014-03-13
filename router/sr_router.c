/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
 *             unsigned int orig_len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arpreply(struct sr_instance *sr, uint8_t *orig_pkt,
    unsigned int orig_len, struct sr_if *src_iface)
{
  /* Allocate space for packet */
  unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reply_pkt = (uint8_t *)malloc(reply_len);
  if (NULL == reply_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *orig_ethhdr = (sr_ethernet_hdr_t *)orig_pkt;
  sr_arp_hdr_t *orig_arphdr = 
      (sr_arp_hdr_t *)(orig_pkt + sizeof(sr_ethernet_hdr_t));

  sr_ethernet_hdr_t *reply_ethhdr = (sr_ethernet_hdr_t *)reply_pkt;
  sr_arp_hdr_t *reply_arphdr = 
      (sr_arp_hdr_t *)(reply_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memcpy(reply_ethhdr->ether_dhost, orig_ethhdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(reply_ethhdr->ether_shost, src_iface->addr, ETHER_ADDR_LEN);
  reply_ethhdr->ether_type = orig_ethhdr->ether_type;

  /* Populate ARP header */
  memcpy(reply_arphdr, orig_arphdr, sizeof(sr_arp_hdr_t));
  reply_arphdr->ar_hrd = orig_arphdr->ar_hrd;
  reply_arphdr->ar_pro = orig_arphdr->ar_pro;
  reply_arphdr->ar_hln = orig_arphdr->ar_hln;
  reply_arphdr->ar_pln = orig_arphdr->ar_pln;
  reply_arphdr->ar_op = htons(arp_op_reply); 
  memcpy(reply_arphdr->ar_tha, orig_arphdr->ar_sha, ETHER_ADDR_LEN);
  reply_arphdr->ar_tip = orig_arphdr->ar_sip;
  memcpy(reply_arphdr->ar_sha, src_iface->addr, ETHER_ADDR_LEN);
  reply_arphdr->ar_sip = src_iface->ip;

  /* Send ARP reply */
  printf("Send ARP reply\n");
  print_hdrs(reply_pkt, reply_len);
  sr_send_packet(sr, reply_pkt, reply_len, src_iface->name);
  free(reply_pkt);
} /* -- sr_send_arpreply -- */

/*---------------------------------------------------------------------
 * Method: sr_send_arprequest(struct sr_instance *sr, 
 *             struct sr_arpreq *req,i struct sr_if *out_iface)
 * Scope:  Local
 *
 * Send an ARP reply packet in response to an ARP request for one of
 * the router's interfaces 
 *---------------------------------------------------------------------*/
void sr_send_arprequest(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  /* Allocate space for ARP request packet */
  unsigned int reqst_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
  uint8_t *reqst_pkt = (uint8_t *)malloc(reqst_len);
  if (NULL == reqst_pkt)
  {
    fprintf(stderr,"Failed to allocate space for ARP reply");
    return;
  }

  sr_ethernet_hdr_t *reqst_ethhdr = (sr_ethernet_hdr_t *)reqst_pkt;
  sr_arp_hdr_t *reqst_arphdr = 
      (sr_arp_hdr_t *)(reqst_pkt + sizeof(sr_ethernet_hdr_t));

  /* Populate Ethernet header */
  memset(reqst_ethhdr->ether_dhost, 0xFF, ETHER_ADDR_LEN);
  memcpy(reqst_ethhdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
  reqst_ethhdr->ether_type = htons(ethertype_arp);

  /* Populate ARP header */
  reqst_arphdr->ar_hrd = htons(arp_hrd_ethernet);
  reqst_arphdr->ar_pro = htons(ethertype_ip);
  reqst_arphdr->ar_hln = ETHER_ADDR_LEN;
  reqst_arphdr->ar_pln = sizeof(uint32_t);
  reqst_arphdr->ar_op = htons(arp_op_request); 
  memcpy(reqst_arphdr->ar_sha, out_iface->addr, ETHER_ADDR_LEN);
  reqst_arphdr->ar_sip = out_iface->ip;
  memset(reqst_arphdr->ar_tha, 0x00, ETHER_ADDR_LEN);
  reqst_arphdr->ar_tip = req->ip;

  /* Send ARP request */
  printf("Send ARP request\n");
  print_hdrs(reqst_pkt, reqst_len);
  sr_send_packet(sr, reqst_pkt, reqst_len, out_iface->name);
  free(reqst_pkt);
} /* -- sr_send_arprequest -- */

/*---------------------------------------------------------------------
 * Method: sr_handle_arpreq(struct sr_instance *sr, 
 *             struct sr_arpreq *req, struct sr_if *out_iface)
 * Scope:  Global
 *
 * Perform processing for a pending ARP request: do nothing, timeout, or  
 * or generate an ARP request packet 
 *---------------------------------------------------------------------*/
void sr_handle_arpreq(struct sr_instance *sr, struct sr_arpreq *req,
    struct sr_if *out_iface)
{
  time_t now = time(NULL);
  if (difftime(now, req->sent) >= 1.0)
  {
    if (req->times_sent >= 5)
    {
      /*********************************************************************/
      /* TODO: send ICMP host uncreachable to the source address of all    */
      /* packets waiting on this request   				   */
  
	uint8_t* hdrbuf; 
	int bufsize = (sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t)); 

	struct sr_packet *currPacket;
	currPacket = req->packets;
	do {

	   hdrbuf = (uint8_t*)malloc(sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t)); 
	   memcpy(hdrbuf, currPacket->buf, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

	   /*Create ICMP Header*/
	   sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(hdrbuf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
	   icmp_t3_hdr->icmp_type = 3;
	   icmp_t3_hdr->icmp_code = 1;
           icmp_t3_hdr->icmp_sum = 0;
	   icmp_t3_hdr->next_mtu = IP_MAXPACKET;
	   /*Calculate ICMP checksum */
	   icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, currPacket->len - sizeof(sr_ethernet_hdr_t)- sizeof(sr_ip_hdr_t));
	   
	   /* Update destination IP to send back to source*/
	   sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(hdrbuf + sizeof(sr_ethernet_hdr_t));

	   ip_hdr->ip_dst = ip_hdr->ip_src;
	   
	   /* update information about next header */
	   ip_hdr->ip_p = htons(ip_protocol_icmp);
	   printf("IP PROTOCOL: %d\n", ip_hdr->ip_p);

	   
	   /* lookup outgoing interface in routing table */
	   char* iface_name = (char *)malloc(sizeof(char) * sr_IFACE_NAMELEN);	
	   int retval;
	   retval = sr_lookup_iface_rt(sr, ip_hdr->ip_dst, iface_name);
	   if (retval < 0) {
		printf("Interface lookup failed\n");
	   } else {
	   	printf("IP: %d\n", ip_hdr->ip_dst);
		printf("interface name: %s\n", iface_name);
	   }
           
	   /* update source IP to be the interface we are sending from */
	   struct sr_if *our_interface = sr_get_interface(sr, iface_name);		
	   ip_hdr->ip_src = our_interface->ip;	   
	   /* Calculate IP checksum */
	   ip_hdr->ip_sum = 0;
	   ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
	   print_hdr_ip((uint8_t *)ip_hdr);
	  

	   /* Update destination Eth */
	   sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(hdrbuf);
	   memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  	   /* Update the source Eth */
	   memcpy(eth_hdr->ether_shost, our_interface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);
	   eth_hdr->ether_type = htons(ethertype_ip);
	   
	   print_hdrs(hdrbuf, bufsize);
 
	   sr_send_packet(sr, hdrbuf, bufsize, iface_name);

	   /* free our buffers here */ 
	   free(hdrbuf);
	   free(iface_name);

	   currPacket = currPacket->next;
	} while (currPacket != NULL);

      /*********************************************************************/

      sr_arpreq_destroy(&(sr->cache), req);
    }
    else
    { 
      /* Send ARP request packet */
      sr_send_arprequest(sr, req, out_iface);
       
      /* Update ARP request entry to indicate ARP request packet was sent */ 
      req->sent = now;
      req->times_sent++;
    }
  }
} /* -- sr_handle_arpreq -- */

/*---------------------------------------------------------------------
 * Method: void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, uint32_t next_hop_ip, 
 *             struct sr_if *out_iface)
 * Scope:  Local
 *
 * Queue a packet to wait for an entry to be added to the ARP cache
 *---------------------------------------------------------------------*/
void sr_waitforarp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, uint32_t next_hop_ip, struct sr_if *out_iface)
{
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), next_hop_ip, 
            pkt, len, out_iface->name);
    sr_handle_arpreq(sr, req, out_iface);
} /* -- sr_waitforarp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
 *             unsigned int len, struct sr_if *src_iface)
 * Scope:  Local
 *
 * Handle an ARP packet that was received by the router
 *---------------------------------------------------------------------*/
void sr_handlepacket_arp(struct sr_instance *sr, uint8_t *pkt,
    unsigned int len, struct sr_if *src_iface)
{
  /* Drop packet if it is less than the size of Ethernet and ARP headers */
  if (len < (sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)))
  {
    printf("Packet is too short => drop packet\n");
    return;
  }

  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(pkt + sizeof(sr_ethernet_hdr_t));

  switch (ntohs(arphdr->ar_op))
  {
  case arp_op_request:
  {
    /* Check if request is for one of my interfaces */
    if (arphdr->ar_tip == src_iface->ip)
    { sr_send_arpreply(sr, pkt, len, src_iface); }
    break;
  }
  case arp_op_reply:
  {
    /* Check if reply is for one of my interfaces */
    if (arphdr->ar_tip != src_iface->ip)
    { 
    printf("Reply is  not for our interface\n");
	break; }
	
    printf("Reply is for our interface,updating arp cache\n");
    /* Update ARP cache with contents of ARP reply */
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha, 
        arphdr->ar_sip);

    
    /* Process pending ARP request entry, if there is one */
    if (req != NULL)
    {
      /*********************************************************************/
      /* TODO: send all packets on the req->packets linked list            */
	

	
	printf("Processing requests\n");

	if(req->packets == NULL)
        { break; }

        struct sr_packet * pak = req->packets;

        do{

          /* fill in destination MAC address */
          sr_ethernet_hdr_t  *  eth_hdr = (sr_ethernet_hdr_t *)(pak->buf);

	 printf(" Original Ether MAC addr:");
	  print_addr_eth(eth_hdr->ether_dhost);	  
	printf("\n");
          memcpy(eth_hdr->ether_dhost, arphdr->ar_sha, sizeof(unsigned char) * ETHER_ADDR_LEN);

	/* modify MAC source to be us*/
        memcpy(eth_hdr->ether_shost, src_iface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);

	 /* decrement TTL of ip header*/
        /*sr_ip_hdr_t  *  ip_hdr = (sr_ip_hdr_t *)(pak->buf + sizeof(sr_ip_hdr_t));
	ip_hdr->ip_ttl--;*/

	print_hdrs(pak->buf, sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t));	
 
	/* recompute checksum*/
	/*ip_hdr->ip_sum = 0;
	ip_hdr->ip_sum = cksum(ip_hdr, pak->len - sizeof(sr_ethernet_hdr_t));*/
	  
	printf("Interface: %s\n", pak->iface);
	/* send packet on outgoing interface */
        int retcode =  sr_send_packet(sr, pak->buf, pak->len, pak->iface);
        if (!retcode) {
		printf("Packet sent successfully...somewhere\n");
	}	 

	pak = (pak)->next;

        }while(pak != NULL);

			printf("DONE sending waiting arp packets\n");

	



      /*********************************************************************/

      /* Release ARP request entry */
      sr_arpreq_destroy(&(sr->cache), req);
    }
    break;
  }    
  default:
    printf("Unknown ARP opcode => drop packet\n");
    return;
  }
} /* -- sr_handlepacket_arp -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  print_hdrs(packet, len);

  /*************************************************************************/
  /* TODO: Handle packets                                                  */


   /*snity check header*/
   if (len < sizeof(sr_ethernet_hdr_t)){
    /*generate ICMP error packet */
   }

   sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *)packet;

   struct sr_if * this_interface =  sr_get_interface(sr, interface);
   sr_print_if(this_interface); 
	  
   if(!this_interface){
    printf("Ghost Interface!!!!!\n");
   }

 
   /* determine next header is ip or arp*/
   switch(ntohs(eth_hdr->ether_type)){

    printf("Packet Type: %u\n", ntohs(eth_hdr->ether_type));
    /* ARP Header*/
    case ethertype_arp: {
	
    	printf(" Calling Handle_Packet-ARP\n");
	sr_handlepacket_arp(sr, packet, len, this_interface);
	/* what happens if this interface doesn't exist? */
	break;
    }
    /* IP Header*/
    case ethertype_ip: {
	sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)); 


	/*Verify packet length, checksum */
	if(!sr_valid_len(len, eth+ip))  {
   	 printf("Length was invalid. Packet Dropped\n");
		break;	
	}
	
	uint16_t ip_sum =  ip_hdr->ip_sum;
	ip_hdr->ip_sum = 0;

	if( ip_sum != cksum(ip_hdr, ip_hdr->ip_hl * 4)){
   		 printf("Total Len: %u, Calc Len: %lu, Eth Size: %lu, IP Size: %lu\n", len, len - sizeof(sr_ethernet_hdr_t),sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t));
   		 printf("Pre-Check Sum: 0x%04X\n", ip_sum);
   		 printf("calculated sum: 0x%04X\n", cksum(ip_hdr, ip_hdr->ip_hl*4));
   		 printf("Checksum  was invalid. Packet Dropped\n");
		break;
	}
	printf("ip length and cksum ok\n");

        /* destined for our ip address */
	/*if(ip_hdr->ip_dst == this_interface->ip){*/
	printf("protocol: 0x%04X \t UDP: 0x%04X\n", ip_hdr->ip_p, ip_protocol_udp);
	if ( sr_is_our_packet(sr, ip_hdr->ip_dst) ) {

		switch(ip_hdr->ip_p){

			/* ICMP Packet*/
			case ip_protocol_icmp:
			{
			   sr_icmp_t3_hdr_t * icmp_hdr = (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
			  
			   /* ICMP Echo Request*/
			   if( icmp_hdr->icmp_type == icmp_echo_req){
				printf("identified echo request\n");
				/*Verify  Checksum*/
				uint16_t stated_cksum = icmp_hdr->icmp_sum;
				icmp_hdr->icmp_sum = 0;
				if(stated_cksum == cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t))){
					/*Send ICMP Echo Reply*/
					generate_icmp_message(sr, icmp_echo_reply, 0, packet, len, this_interface);

				}

			   }

				break;
			}
			/* TCP Packet*/
			case ip_protocol_tcp: 
			{	/* Send ICMP unrchbl*/
				generate_icmp_message(sr, icmp_dst_unrchbl, 3, packet, len, this_interface);
				break;
			}
			/* UDP Packet */
			case ip_protocol_udp:
			{	/* Send ICMP unrchbl*/
				generate_icmp_message(sr, icmp_dst_unrchbl, 3, packet, len, this_interface);
	 			break;
			}
			default:
    			{   printf("Unsupported IP Packet Type => drop packet\n");
    			   return;
			}
		}


	}
	/* Forward IP Packet Onward*/
	else{
		printf("IP packet ttl: %d\n", ip_hdr->ip_ttl);
		if(ip_hdr->ip_ttl == 0){
			/*Send ICMP packet time exceeded */
			generate_icmp_message(sr, icmp_timeout, 0, packet, len, this_interface);
			printf("ip packet timed out\n");
		}
		printf("forwarding packet onward\n");
		ip_hdr->ip_ttl--;
		
		/* recompute cksum */
		printf("computing new ip cksum\n");
		ip_hdr->ip_sum = 0;
		ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);	
		
		printf("looking up entry in routing table\n");

		/* look up ip address in routing table with longest prefix match */
		struct sr_rt* next_hop = sr_lookup_nexthop_ip(sr, ip_hdr->ip_dst);

		if (!next_hop) {
			/* Send ICMP message */
			printf("no next hop entry found in routing table\n");
			generate_icmp_message(sr, icmp_dst_unrchbl, 0, packet, len, this_interface);
			break;
		}
		printf("looking up mac address in cache\n");
		
		/* look up MAC address corresponding to next hop ip */
	struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), (next_hop->dest).s_addr);
         
		if (arp_entry) {
			printf("arp entry found in cache\n");


	   /* lookup outgoing interface name in routing table */
	   char* iface_name = (char *)malloc(sizeof(char) * sr_IFACE_NAMELEN);	
	   int retval;
	   retval = sr_lookup_iface_rt(sr, ip_hdr->ip_dst, iface_name);
	   if (retval < 0) {
		printf("Interface lookup failed\n");
	   } else {
	   	printf("IP: %d\n", ip_hdr->ip_dst);
		printf("interface name: %s\n", iface_name);
	   }

		/* Get interface struct based on name*/
		struct sr_if *out_if = sr_get_interface(sr, iface_name);








			/* replace ethernet mac address */
			memcpy(eth_hdr->ether_shost, out_if->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);
		/*	memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(unsigned char) * ETHER_ADDR_LEN);  */
			memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(unsigned char) * ETHER_ADDR_LEN);
				
 			print_addr_eth(eth_hdr->ether_shost);
 			print_addr_eth(eth_hdr->ether_dhost);
 			printf("Iterface from routing table: %s\n", iface_name);
 			printf("Iterface from  next hop function: %s\n", next_hop->interface);

			/* forward packet to next hop */
			sr_send_packet(sr, packet, len, iface_name);
		/*	sr_send_packet(sr, packet, len, next-hop->interface);*/
			free(arp_entry);
		} 


		else {
			printf("sending arp request\n");
			/* not in the cache -- send arp request */
			struct sr_if *out_if = sr_get_interface(sr, next_hop->interface);
			sr_waitforarp(sr, packet, len, (next_hop->dest).s_addr, out_if);
		}

	}


	


   /* -->
	if err occurs at any point, send ICMP error message back to sender*/

   		break;
	}
	default: 
	{
		printf("dropped packet with invalid ethernet next header type\n");
	}
   
    }



  /*************************************************************************/

}/* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 * Method: generate_icmp_message(struct sr_instance *sr, unsigned int type, unsigned int code, uint8_t *packet, unsigned int len, struct sr_if *iface)
 * Scope:  Global
 *
 * Sends an ICMP message of the specified type and code back to the 
 * source of the specified packet. 
 *---------------------------------------------------------------------*/
void generate_icmp_message(struct sr_instance *sr, unsigned int type, unsigned int code, uint8_t *packet, unsigned int len, struct sr_if *iface) {

	   uint8_t *hdrbuf;
	   uint size_of_icmp;

	   /*Create ICMP Header*/
	   if (type == icmp_dst_unrchbl) {
		size_of_icmp = sizeof(sr_icmp_t3_hdr_t) + 8;

	   	hdrbuf = (uint8_t*)malloc(sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + 8); 
	   	memcpy(hdrbuf, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + 8);
		
		sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(hdrbuf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + 8);
	   	icmp_t3_hdr->icmp_type = type;
	   	icmp_t3_hdr->icmp_code = code;
           	icmp_t3_hdr->icmp_sum = 0;
	   	icmp_t3_hdr->next_mtu = IP_MAXPACKET;
	   	/*Calculate ICMP checksum */
	   	icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
	   } 
	   else if (type == icmp_echo_reply) {
		printf("Generating ICMP ECHO REPLY packet\n");
		size_of_icmp = len - (sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
		hdrbuf = (uint8_t*) malloc(len);
		memcpy(hdrbuf, packet, len);
		sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(hdrbuf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		icmp_hdr->icmp_type = type;
		icmp_hdr->icmp_code = code;
		icmp_hdr->icmp_sum = 0;
		/*calculate ICMP cksum*/
		icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));
	   }
	   else {
		size_of_icmp = sizeof(sr_icmp_hdr_t);

		hdrbuf = (uint8_t*) malloc(sizeof(sr_icmp_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
	   	memcpy(hdrbuf, packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		
		sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(hdrbuf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		icmp_hdr->icmp_type = type;
		icmp_hdr->icmp_code = code;
		icmp_hdr->icmp_sum = 0;
		/*calculate ICMP cksum*/
		icmp_hdr->icmp_sum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));
			
	   }

	   /* Update destination IP to send back to source*/
	   sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(hdrbuf + sizeof(sr_ethernet_hdr_t));

	   ip_hdr->ip_dst = ip_hdr->ip_src;
	   
	   /* update information about next header */
	   printf("IP Protocol Before: %u\n", ip_hdr->ip_p);
	   ip_hdr->ip_p = ip_protocol_icmp;
	   printf("IP Protocol: %u\n", ip_hdr->ip_p);
	   /* update ip source to be our interface */
	   ip_hdr->ip_src = iface->ip;	   

	   /* set our icmp packet ttl = 64*/
	   ip_hdr->ip_ttl = 64;
	   /* Calculate IP checksum */
	   ip_hdr->ip_sum = 0; 
	   ip_hdr->ip_sum = cksum(ip_hdr, ip_hdr->ip_hl * 4);
	  

	   /* Update destination Eth */
	   sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(hdrbuf);
	   memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  	   /* Update the source Eth */
	   memcpy(eth_hdr->ether_shost, iface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);
	   /* set the type of the subsequent header */ 
	   eth_hdr->ether_type = htons(ethertype_ip);
	   
	   uint bufsize = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + size_of_icmp;
	   print_hdrs(hdrbuf, bufsize);

	   printf("sending ICMP message out interface %s\n", iface->name); 
	   print_hdrs(hdrbuf, bufsize);
	   sr_send_packet(sr, hdrbuf, bufsize, iface->name);

	   /* free our buffers here */ 
	   free(hdrbuf);
	   
}


/*---------------------------------------------------------------------
 * Method: sr_is_our_packet(struct sr_instance *sr, uint32_t ip) 
 * Scope:  Global
 *
 * Compares provided IP to all IP addresses associated with the given
 * router instance.  If there is a match, return 1.  Else return 0. 
 *---------------------------------------------------------------------*/
int sr_is_our_packet(struct sr_instance *sr, uint32_t ip) {
	struct sr_if *iface = sr->if_list;
	
	while(iface) {
		printf("IP: 0x%04X\t iface IP: 0x%04X\n", ip, iface->ip);
		if (ip == iface->ip) {
			return 1;
		}
		iface = iface->next;
	}
	return 0;

}



/*---------------------------------------------------------------------
 * Method: sr_valid_len(unsigned int len, int hdrs)
 * Scope:  Global
 *
 * Sanity checks length. 
 *---------------------------------------------------------------------*/
int sr_valid_len( unsigned int len, int hdrs){

	switch(hdrs){

	case eth:
        
		return(len >= sizeof(sr_ethernet_hdr_t));
		break;
	case eth+ip:

		return(len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
		break;
	case eth+arp:

		return(len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
		break;

	case eth+ip+icmp:
	
		return(len >= sizeof(sr_ethernet_hdr_t))+ sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
		break;

	default:
	
	  printf("Invalid Headers\n");
	  return 0;

	}



} /* end of sanity len check*/



