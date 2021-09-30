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



void prepare_eth_header_response(sr_ethernet_hdr_t *new_eth_header, uint8_t *destination, uint8_t *source, uint32_t type){
  memcpy(new_eth_header-> ether_dhost, destination, ETHER_ADDR_LEN);
  memcpy(new_eth_header-> ether_shost, source, ETHER_ADDR_LEN);
  new_eth_header -> ether_type = htons(type);
}

void prepare_arp_header_resposne(sr_arp_hdr_t *new_arp_header, sr_arp_hdr_t *old_arp_header, unsigned char *mac_address){
  memcpy(new_arp_header, old_arp_header, sizeof(sr_arp_hdr_t));
  new_arp_header -> ar_op = htons(arp_op_reply);
  memcpy(&(new_arp_header -> ar_sip), &(old_arp_header -> ar_tip), 4);
  memcpy(&(new_arp_header -> ar_tip), &(old_arp_header -> ar_sip), 4);
  memcpy(new_arp_header -> ar_tha, old_arp_header -> ar_sha, ETHER_ADDR_LEN);
  memcpy(new_arp_header -> ar_sha, mac_address, ETHER_ADDR_LEN);
}

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

  struct in_addr eth2;
  struct in_addr eth3;
  struct in_addr eth1;
  inet_aton("192.168.2.1", &eth1);
  inet_aton("172.64.3.1", &eth2);
  inet_aton("10.0.1.1", &eth3);

  sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *) packet;
  /*print_hdr_eth(packet);*/


  

  if(ntohs(eth_header -> ether_type) == ethertype_ip){ 
    printf("Hello there");

    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    /* Check for the integrity of the IP packet */

    /* Check if packet is destined to router's interface */
    uint8_t flag = 0;
    struct sr_if *interface = sr -> if_list;
    while(interface){
      if(interface -> ip == ip_header -> ip_dst){
        flag = 1;
        break;
      }
      interface = interface -> next;
    }
    
    if(flag){ /* Packet is for interface */
      if(ip_header -> ip_p == ip_protocol_icmp){ 
        sr_icmp_hdr_t *icmp_header_for_interface = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        if(icmp_header_for_interface -> icmp_type == 8){ /* ICMP echo request */
          /* Send ICMP echo reply */

        }else{ /* Not sure what to do here  */

        }

      }else if(ip_header -> ip_p == 6 || ip_header -> ip_p == 17){ /* TCP/UDP payload */
        /* Send ICMP port unreachable */

      }else{ /* Not sure what to do here  */

      }
    }else{ /* Packet is destined somewhere else */

    }

  }else if(ntohs(eth_header -> ether_type) == ethertype_arp){

    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    if(ntohs(arp_header -> ar_op) == arp_op_request){ /* Handle ARP requests */
        uint8_t *arp_reply = malloc(42);
        sr_ethernet_hdr_t *response_eth_header = (sr_ethernet_hdr_t *) arp_reply;
        struct sr_if *interface = sr -> if_list;
        while(interface -> ip != arp_header -> ar_tip){
          interface = interface -> next;
        }
        if(interface){
          uint8_t *arp_reply = malloc(42);
          sr_ethernet_hdr_t *response_eth_header = (sr_ethernet_hdr_t *) arp_reply;
          sr_arp_hdr_t *response_arp_header = (sr_arp_hdr_t *) (arp_reply + sizeof(sr_ethernet_hdr_t));
          prepare_eth_header_response(response_eth_header, eth_header -> ether_shost, interface -> addr, ethertype_arp);
          prepare_arp_header_resposne(response_arp_header, arp_header, interface -> addr);
          print_hdr_eth((uint8_t *) response_eth_header);
          print_hdr_arp((uint8_t *) response_arp_header);
          sr_send_packet(sr, arp_reply, 42, interface -> name);
        }
    }else if(ntohs(arp_header -> ar_op) == arp_op_reply){ /* Handle ARP reply accordinly */

    }
  }else{ /* Not sure what to do here  */

  }
}

