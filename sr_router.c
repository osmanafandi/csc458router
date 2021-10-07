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



void prepare_eth_header_response(sr_ethernet_hdr_t *new_eth_header, uint8_t *destination, uint8_t *source, uint16_t type){
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

  if(len < sizeof(sr_ethernet_hdr_t)){ /* Check the length of the packet for integrity */
    return;
  }
 
  sr_ethernet_hdr_t *eth_header = (sr_ethernet_hdr_t *) packet;
  
  if(ntohs(eth_header -> ether_type) == ethertype_ip){ 

    if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)){  /* Check the length of the packet for integrity */
      return;
    }

    sr_ip_hdr_t *ip_header = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    

    /* Check for the integrity of the IP packet */
    uint32_t ip_checksum = ip_header -> ip_sum;
    memset(&(ip_header -> ip_sum), 0, 2);



    if(!(cksum(ip_header, sizeof(sr_ip_hdr_t)) == ip_checksum)){
      return;
    }

    ip_header -> ip_sum = ip_checksum;

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
    
    /* Find the right interface to send the packet from if need to be returned */
    interface = sr -> if_list;
    while(interface){
      int equal = 1;
      int j=0;
      for(; j < ETHER_ADDR_LEN; j++){
        if((interface -> addr)[j] != (eth_header -> ether_dhost)[j]){
          equal = 0;
          break;
        }
      }
      if(equal){
        break;
      }
      interface = interface -> next;
    }

    if(flag){ /* Packet is for interface */
      if(ip_header -> ip_p == ip_protocol_icmp){ 

        if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)){ /* Check the length of the packet for integrity */
          return;
        }

        sr_icmp_hdr_t *icmp_header_for_interface = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
        if(icmp_header_for_interface -> icmp_type == 8){ /* ICMP echo request */

          printf("Echo request to router's interface\n");
          /* Send ICMP echo reply */
          uint8_t *icmp_reply = (uint8_t *) malloc(len);
          memcpy(icmp_reply, packet, len);
          prepare_eth_header_response((sr_ethernet_hdr_t *) icmp_reply, eth_header -> ether_shost, eth_header -> ether_dhost, ethertype_ip);
        
          /* Prepare ip header for ICMP echo reply */
          sr_ip_hdr_t *response_ip_header = (sr_ip_hdr_t *) (icmp_reply + sizeof(sr_ethernet_hdr_t));
          memcpy(&(response_ip_header -> ip_dst), &(ip_header -> ip_src), 4);
          memcpy(&(response_ip_header -> ip_src), &(ip_header -> ip_dst), 4);
          memset(&(response_ip_header -> ip_sum), 0, 2);
          response_ip_header -> ip_sum = cksum(response_ip_header, sizeof(sr_ip_hdr_t));


          /* Prepare icmp header for ICMP echo reply */
          sr_icmp_hdr_t *response_icmp_header = (sr_icmp_hdr_t *) (icmp_reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          response_icmp_header -> icmp_type = 0;
          response_icmp_header -> icmp_code = 0;
          response_icmp_header -> icmp_sum = 0;
          response_icmp_header -> icmp_sum = cksum(response_icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
          

          sr_send_packet(sr, icmp_reply, len, interface -> name);
          free(icmp_reply);



        }

      }else if(ip_header -> ip_p == 6 || ip_header -> ip_p == 17){ /* TCP/UDP payload */
        /* Send ICMP port unreachable */
          printf("TCP/UDP payload to touer's interface\n");
          uint8_t *icmp_reply = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          prepare_eth_header_response((sr_ethernet_hdr_t *) icmp_reply, eth_header -> ether_shost, eth_header -> ether_dhost, ethertype_ip);

        /* Prepare ip header for ICMP TCP/UDP payload reply */
          sr_ip_hdr_t *response_ip_header = (sr_ip_hdr_t *) (icmp_reply + sizeof(sr_ethernet_hdr_t));
          memcpy(response_ip_header, ip_header, sizeof(sr_ip_hdr_t));
          response_ip_header->ip_src = ip_header->ip_dst;
          response_ip_header->ip_dst = ip_header->ip_src;
          response_ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          response_ip_header->ip_ttl = 64;
          response_ip_header->ip_p = ip_protocol_icmp;
          response_ip_header->ip_sum = 0;
          response_ip_header->ip_sum = cksum(response_ip_header, sizeof(sr_ip_hdr_t));

        /* Prepare ICMP header */
          sr_icmp_t3_hdr_t *response_icmp_header = (sr_icmp_t3_hdr_t *) (icmp_reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          response_icmp_header->icmp_type = 3;
          response_icmp_header->icmp_code = 3;
          response_icmp_header->icmp_sum = 0;
          response_icmp_header->unused = 0;
          response_icmp_header->next_mtu = 0;

          memcpy(response_icmp_header->data, ip_header, sizeof(sr_ip_hdr_t));
          memcpy(response_icmp_header->data + sizeof(sr_ip_hdr_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), 8);

          response_icmp_header->icmp_sum = cksum(response_icmp_header, sizeof(sr_icmp_t3_hdr_t));

          sr_send_packet(sr, icmp_reply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface->name);

          free(icmp_reply);

      }
    }else{ /* Packet is destined somewhere else */
      /* Find from routing table which interface should be used to send the packet */
      printf("Packet is destined somewhere else\n");
      struct sr_rt *routing_table = sr -> routing_table;
      struct sr_rt *current_max_entry = NULL;
      int current_max = 0;
      int temp_max;
      while(routing_table){
        temp_max = 0;
        int i=32;
        for(; i >= 0; i--){
          if((((routing_table -> dest).s_addr << (32 - i)) >> i) ^ ((ip_header -> ip_dst << (32 - i)) >> i)){
            break;
          }
          temp_max++;
        }
        if(temp_max > current_max){
            current_max = temp_max;
            current_max_entry = routing_table;
        }
        routing_table = routing_table -> next;
      }
      if(current_max_entry == NULL){ /* Send type3 code0 ICMP reply */
          printf("Destination net unreachable\n");
          uint8_t *icmp_reply = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          prepare_eth_header_response((sr_ethernet_hdr_t *) icmp_reply, eth_header -> ether_shost, eth_header -> ether_dhost, ethertype_ip);

        /* Prepare ip header for ICMP TCP/UDP payload reply */
          sr_ip_hdr_t *response_ip_header = (sr_ip_hdr_t *) (icmp_reply + sizeof(sr_ethernet_hdr_t));
          memcpy(response_ip_header, ip_header, sizeof(sr_ip_hdr_t));
          response_ip_header->ip_src = interface->ip;
          response_ip_header->ip_dst = ip_header->ip_src;
          response_ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          response_ip_header->ip_ttl = 64;
          response_ip_header->ip_p = ip_protocol_icmp;
          response_ip_header->ip_sum = 0;
          response_ip_header->ip_sum = cksum(response_ip_header, sizeof(sr_ip_hdr_t));

        /* Prepare ICMP header */
          sr_icmp_t3_hdr_t *response_icmp_header = (sr_icmp_t3_hdr_t *) (icmp_reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          response_icmp_header->icmp_type = 3;
          response_icmp_header->icmp_code = 0;
          response_icmp_header->icmp_sum = 0;
          response_icmp_header->unused = 0;
          response_icmp_header->next_mtu = 0;

          memcpy(response_icmp_header->data, ip_header, sizeof(sr_ip_hdr_t));
          memcpy(response_icmp_header->data + sizeof(sr_ip_hdr_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), 8);

          response_icmp_header->icmp_sum = cksum(response_icmp_header, sizeof(sr_icmp_t3_hdr_t));

          sr_send_packet(sr, icmp_reply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface->name);

          free(icmp_reply);            

      }else{ 
        printf("Searching for MAC address of destination IP address\n");
        if(ip_header -> ip_ttl - 1 == 0){ /* Send type 11 code 0 ICMP reply */ 
          printf("TTL is 0\n");

          uint8_t *icmp_reply = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          prepare_eth_header_response((sr_ethernet_hdr_t *) icmp_reply, eth_header -> ether_shost, eth_header -> ether_dhost, ethertype_ip);

        /* Prepare ip header for ICMP TCP/UDP payload reply */
          sr_ip_hdr_t *response_ip_header = (sr_ip_hdr_t *) (icmp_reply + sizeof(sr_ethernet_hdr_t));
          memcpy(response_ip_header, ip_header, sizeof(sr_ip_hdr_t));
          response_ip_header->ip_src = interface->ip;
          response_ip_header->ip_dst = ip_header->ip_src;
          response_ip_header->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          response_ip_header->ip_ttl = 64;
          response_ip_header->ip_p = ip_protocol_icmp;
          response_ip_header->ip_sum = 0;
          response_ip_header->ip_sum = cksum(response_ip_header, sizeof(sr_ip_hdr_t));

        /* Prepare ICMP header */
          sr_icmp_t3_hdr_t *response_icmp_header = (sr_icmp_t3_hdr_t *) (icmp_reply + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
          response_icmp_header->icmp_type = 11;
          response_icmp_header->icmp_code = 0;
          response_icmp_header->icmp_sum = 0;
          response_icmp_header->unused = 0;
          response_icmp_header->next_mtu = 0;

          memcpy(response_icmp_header->data, ip_header, sizeof(sr_ip_hdr_t));
          memcpy(response_icmp_header->data + sizeof(sr_ip_hdr_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), 8);

          response_icmp_header->icmp_sum = cksum(response_icmp_header, sizeof(sr_icmp_t3_hdr_t));

          sr_send_packet(sr, icmp_reply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t), interface->name);

          free(icmp_reply);            

        }else{ /* Find the mac address for the IP address */
          struct sr_arpentry *arp_value = sr_arpcache_lookup(&(sr -> cache), ip_header -> ip_dst);
          /* Recompute TTL and IP checksum */
          ip_header->ip_ttl--;
          ip_header->ip_sum = 0;
          ip_header->ip_sum = cksum((uint8_t *) ip_header, sizeof(sr_ip_hdr_t));
    
          if(arp_value == NULL){ /* Send ARP request as MAC address for entry is not found */
            printf("Did not find the MAC address for destination IP address\n");
            sr_arpcache_queuereq(&(sr -> cache), ip_header -> ip_dst, packet, len, current_max_entry -> interface);
          }else{ /* Generate apropriate values and direct the packet */
            printf("Redirecting the packet\n");
            struct sr_if *interface = sr-> if_list;
              while(interface){
                  if(strcmp(interface->name, current_max_entry->interface) == 0){
                      break;
                  }
                  interface = interface->next;
              }
            memcpy(eth_header->ether_shost, interface->addr, ETHER_ADDR_LEN);
            memcpy(eth_header->ether_dhost, arp_value->mac, ETHER_ADDR_LEN);
            sr_send_packet(sr, packet, len, current_max_entry->interface);

            free(arp_value);
          }
        }
      }
    }
  


  }else if(ntohs(eth_header -> ether_type) == ethertype_arp){

    if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)){  /* Check the length of the packet for integrity */
      return;
    }

    sr_arp_hdr_t *arp_header = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));

    if(ntohs(arp_header -> ar_op) == arp_op_request){ /* Handle ARP requests */
      printf("This ARP request\n");
      uint8_t *arp_reply = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
      sr_ethernet_hdr_t *response_eth_header = (sr_ethernet_hdr_t *) arp_reply;
      struct sr_if *interface = sr -> if_list;
      while(interface -> ip != arp_header -> ar_tip){
        interface = interface -> next;
      }
      if(interface){
        sr_ethernet_hdr_t *response_eth_header = (sr_ethernet_hdr_t *) arp_reply;
        sr_arp_hdr_t *response_arp_header = (sr_arp_hdr_t *) (arp_reply + sizeof(sr_ethernet_hdr_t));
        prepare_eth_header_response(response_eth_header, eth_header -> ether_shost, interface -> addr, ethertype_arp);
        prepare_arp_header_resposne(response_arp_header, arp_header, interface -> addr);
        sr_send_packet(sr, arp_reply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), interface -> name);
      }
      free(arp_reply);
    }else if(ntohs(arp_header -> ar_op) == arp_op_reply){ /* Handle ARP reply accordinly */
      printf("This ARP reply\n");

      struct sr_arpreq *arp_req = sr_arpcache_insert(&(sr->cache), arp_header->ar_sha, arp_header->ar_sip);
      if(arp_req != NULL){
        struct sr_packet *arp_packets = arp_req->packets;

        struct sr_if *interface = sr-> if_list;
        while(interface){
            if(strcmp(interface->name, arp_req->packets->iface) == 0){
                break;
            }
            interface = interface->next;
        }

        while(arp_packets){
          sr_ethernet_hdr_t *redirect_eth = (sr_ethernet_hdr_t *) arp_packets->buf;
          memcpy(redirect_eth->ether_shost, interface->addr, ETHER_ADDR_LEN);
          memcpy(redirect_eth->ether_dhost, arp_header->ar_sha, ETHER_ADDR_LEN);

          sr_send_packet(sr, arp_packets->buf, arp_packets->len, arp_packets->iface);

          arp_packets = arp_packets->next;
        }
        sr_arpreq_destroy(&(sr->cache), arp_req);
        }
    }
  }else{ /* Not sure what to do here  */

  }

}

