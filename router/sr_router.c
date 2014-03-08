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
	   icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
	   
	   /* Update destination IP to send back to source*/
	   sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(hdrbuf + sizeof(sr_ethernet_hdr_t));

	   ip_hdr->ip_dst = ip_hdr->ip_src;
	   
	   /* update information about next header */
	   ip_hdr->ip_p = htons(ip_protocol_icmp);

	   
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
	   /*print_hdrs(hdrbuf, len);*/
           
	   /* update source IP to be the interface we are sending from */
	   struct sr_if *our_interface = sr_get_interface(sr, iface_name);		
	   ip_hdr->ip_src = our_interface->ip;	   

	   /* Calculate IP checksum */
	   ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
	   print_hdr_ip((uint8_t *)ip_hdr);
	  

	   /* Update destination Eth */
	   sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)(hdrbuf);
	   memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  	   /* Update the source Eth */
	   memcpy(eth_hdr->ether_shost, our_interface->addr, sizeof(unsigned char) * ETHER_ADDR_LEN);
	   eth_hdr->ether_type = htons(ethertype_ip);
	   
	   print_hdr_eth(hdrbuf);
 
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
    { break; }

    /* Update ARP cache with contents of ARP reply */
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arphdr->ar_sha, 
        arphdr->ar_sip);

    /* Process pending ARP request entry, if there is one */
    if (req != NULL)
    {
      /*********************************************************************/
      /* TODO: send all packets on the req->packets linked list            */
	

	

	if(req->packets == NULL)
        { break; }

        struct sr_packet * pak = req->packets;

        do{

          /* fill in destination MAC address */
          sr_ethernet_hdr_t  *  eth_hdr = (sr_ethernet_hdr_t *)(pak->buf);
          memcpy(eth_hdr->ether_dhost, arphdr->ar_sha, sizeof(arphdr->ar_sha) * ETHER_ADDR_LEN);
	  
	 /* decrement TTL of ip header*/
          sr_ip_hdr_t  *  ip_hdr = (sr_ip_hdr_t *)(pak->buf + sizeof(sr_ip_hdr_t));
	  ip_hdr->ip_tll--;

	 /* recompute checksum*/
	  ip_hdr->ip_sum = 0;
	  ip_hdr->ip_sum = cksum(ip_hdr, pak->len - sizeof(sr_ethernet_hdr_t));
	  

	  /* send packet on outgoing interface */
          sr_send_packet(sr, pak->buf, pak->len, pak->iface);
          pak = (req->packets)->next;

        }while(pak != NULL);

	



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

  /*************************************************************************/
  /* TODO: Handle packets                                                  */


   /*snity check header*/
   if (len < sizeof(sr_ethernet_hdr_t)){
    /*generate ICMP error packet */
   }

   sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *)packet;

  /* determine next header is ip or arp*/
   switch(eth_hdr->ether_type){

    /* ARP Header*/
    case ethertype_arp:
	
	if( !sr_valid_len(len, eth+arp))
    		/*generate ICMP error packet */

	sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

	/*determine arp req or reply */
	switch(arp_hdr->ar_op) {

	  /* ARP Request */
	  case arp_op_request:
	
		/*if this request (ip) is matched one of our ip's, send reply */
		if( arp_hdr->ar_tip ==  

		break;

          /*ARP Reply */
	  case arp_op_reply:
		/* cache reply only if this request (ip) is matched one of our ip's */


		break;

          default:	 
    	       printf("Unknown ARP opcode => drop packet\n");
               return;




	}


		break;
    case ethertype_ip:

//destined for our ip address?

   // -->if ICMP echo req, verfiy checksum, send ICMP reply

   // -->if TCP or UPD send IMCP port unreachable to host

  // --> other type ignore 

//if else, forward logic


	// --> sanity check length & cksum
	// --> sanity check checksum
	// --> decrement ttl in ip
	//--> find longest prefix in routing table that matches w/ destination address
	//--> arpcache lookup for next hop MAC address
	// |--> if not in cache, send out arp req, wait for arp reply
	// |--> add packet to queue of packets waiting on ARP reply
	//if err occurs at any point, send ICMP error message back to sender



   		break;

	default:
    /*generate ICMP error packet */
   }
   





  /*************************************************************************/

}/* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 * Method: sr_valid_len(unsigned int len, int hdrs)
 * Scope:  Global
 *
 * Sanity checks length. 
 *---------------------------------------------------------------------*/
bool sr_valid_len( unsigned int plen, int hdrs){

	switch(hdrs){

	case eth:
        
		return( if(len >= sizeof(sr_ethernet_hdr_t)));
		break;
	case eth+ip:

		return( if(len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)));
		break;
	case eth+arp:

		return( if(len >= sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)));
		break;

	case eth+ip+icmp:
	
		return( if(len >= sizeof(sr_ethernet_hdr_t))+ sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
		break;

	default:

	  return NULL;

	}



} /* end of sanity len check*/



