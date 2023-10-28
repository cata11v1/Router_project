#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
/* Routing table */
struct route_table_entry *rtable;
int rtable_len;
struct arp_entry *arp_table;
int arp_table_len;
struct in_addr adrbuf;
//compare 2 route_table_entry
int compare(const void *i1, const void *i2)
{
    struct route_table_entry *r1 = (struct route_table_entry *)i1;
    struct route_table_entry *r2 = (struct route_table_entry *)i2;
    uint32_t r1pref = ntohl(r1->prefix), r2pref = ntohl(r2->prefix);
    if (ntohl(r1->mask) > ntohl(r2->mask))
    {
        return -1;
    }
    else if (ntohl(r1->mask) == ntohl(r2->mask))
    {
        if (r1pref > r2pref)
        {
            return -1;
        }
    }
    return 1;
}
int binarySearch(struct route_table_entry *rtable, uint32_t x, int left, int right)
{
    if (left > right)
    {
        return -1;
    }
    else
    {
        int mid = (left + right) / 2;
        if ((x & rtable[mid].mask) == rtable[mid].prefix)
        {
            return mid;
        }
        else if ((ntohl(x & rtable[mid].mask)) > ntohl(rtable[mid].prefix))
        {
            return binarySearch(rtable, x, left, mid - 1);
        }
        else
        {
            return binarySearch(rtable, x, mid + 1, right);
        }
    }
}
//binary_search the ip_destination in the ordered groups
struct route_table_entry *get_best_route(uint32_t ip_dest, int v[100], int counter)
{
    for (int i = 0; i < counter; i = i + 2)
    //V[0]= start position for group with biggest mask
    //V[1]= end position for group with biggest mask
    {
        int next;
        next = binarySearch(rtable, ip_dest, v[i], v[i + 1]);
        if (rtable[next].prefix == (ip_dest & rtable[next].mask) && next != -1)
        {
            return &rtable[next];
        }
    }

    return NULL;
}

struct arp_entry *get_arp_entry(uint32_t ip_dest)
{
    /* TODO 2.4: Iterate through the MAC table and search for an entry
     * that matches ip_dest. */
    for (int i = 0; i < arp_table_len; i++)
    {
        if (ip_dest == arp_table[i].ip)
        {
            return &(arp_table[i]);
        }
    }
    /* We can iterate thrpigh the mac_table for (int i = 0; i <
     * mac_table_len; i++) */
    return NULL;
}
void errtype(char buf[MAX_PACKET_LEN], size_t len, int interface, int a)
{
    struct ether_header *eth_hdr = (struct ether_header *)buf;
    struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
    char buf1[MAX_PACKET_LEN];
    //start adding ethernet header
    //old ether source host now is destination host
    memcpy(buf1, &eth_hdr->ether_shost, 6);
    //get the ether address of interface and put it in ether host for new package
    get_interface_mac(interface, eth_hdr->ether_shost);
    memcpy(buf1 + 6, &eth_hdr->ether_shost, 6);
    memcpy(buf1 + 12, &eth_hdr->ether_type, 2);
    //start adding ip header
    memcpy(buf1 + 14, ip_hdr, 2); // ihl + version + tos
    //recalculate the total length
    uint16_t ln = htons(ip_hdr->tot_len) + sizeof(struct icmphdr) + sizeof(struct iphdr) + 8;
    ln = htons(ln);
    memcpy(buf1 + 16, &ln, 2);         // ltot-len
    memcpy(buf1 + 18, &ip_hdr->id, 4); // id + frag_off
    //new ttl, a random value
    uint8_t ttl = 111;
    memcpy(buf1 + 22, &ttl, 1); // ttl
    uint8_t protocol = 1;
    memcpy(buf1 + 23, &protocol, 1); // protocol
    uint16_t checkfals = 0;
    //reserve memory for checksum
    memcpy(buf1 + 24, &checkfals, 2);
    inet_aton(get_interface_ip(interface), &adrbuf);
    //get the current interface ip and put it in package
    memcpy(buf1 + 26, &adrbuf.s_addr, 4);
    //copy the destination ip
    memcpy(buf1 + 30, &ip_hdr->daddr, 4);
    uint16_t check;
    //recalculate the new checksum, with all new data, and put it in the package
    check = htons(checksum((uint16_t *)buf1 + 14, sizeof(ip_hdr)));
    memcpy(buf1 + 24, &check, 2);
    //put the errortype 11 for ttl expired, 3 for destination unreahable
    if (a == 1)
    {
        uint8_t type;
        type = 11;
        memcpy(buf1 + 34, &type, 1);
    }
    else
    {
        uint8_t type;
        type = 3;
        memcpy(buf1 + 34, &type, 1);
    }
    uint8_t cod = 0;
    memcpy(buf1 + 35, &cod, 1);
    memset(buf1 + 36, 0, 2);
    uint32_t gateway = 0;
    memcpy(buf1 + 38, &gateway, 4);
    memcpy(buf1 + 42, ip_hdr, sizeof(struct iphdr) + 8);
    uint16_t checksum1 = checksum((uint16_t *)(buf1 + 34), sizeof(struct icmphdr) + sizeof(ip_hdr) + 8);
    checksum1 = htons(checksum1);
    memcpy(buf1 + 36, &checksum1, 2);
    //send the package
    send_to_link(interface, (char *)buf1, len + sizeof(struct icmphdr) + sizeof(ip_hdr) + 8 + 12);
}

int main(int argc, char *argv[])
{
    char buf[MAX_PACKET_LEN];

    // Do not modify this line
    init(argc - 2, argv + 2);

    rtable = malloc(sizeof(struct route_table_entry) * 100000);
    arp_table = malloc(sizeof(struct arp_entry) * 100);
    arp_table_len = parse_arp_table("arp_table.txt", arp_table);
    rtable_len = read_rtable(argv[1], rtable);
    //sort the route table entries in descending order by prefix and mask
    qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare);
    int v[100], counter = 0;
    //store the start and finish position of every group that has the same mask
    for (int i = 0; i < rtable_len; i++)
    {
        if (i == 0)
        {
            v[counter] = i;
            counter++;
        }
        else if (rtable[i].mask != rtable[i - 1].mask)
        {
            v[counter] = i - 1;
            counter++;
            v[counter] = i;
            counter++;
        }
    }
    //after adding an element to vector, the counter must be increased
    v[counter] = rtable_len - 1;
    counter++;
    while (1)
    {
        int interface;
        size_t len;
        interface = recv_from_any_link(buf, &len);
        DIE(interface < 0, "recv_from_any_links");
        struct ether_header *eth_hdr = (struct ether_header *)buf;
        struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
        uint16_t chk = ip_hdr->check;
        ip_hdr->check = 0;
        //the received checksum differs from the calculated one, the package is corrupt, we throw it away
        if (checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr)) != ntohs(chk))
        {
            continue;
        }
        else
        {
            //time exceeded, errortype 11, code 0
            if (ip_hdr->ttl <= 1)
            {
                errtype(buf, len, interface, 1);
                continue;
            }
            struct route_table_entry *next_route = get_best_route(ip_hdr->daddr, v, counter);
            //destination unreachable, errortype 3, code 0
            if (!next_route)
            {
                errtype(buf, len, interface, 3);
                continue;
            }
            inet_aton(get_interface_ip(interface), &adrbuf);
            //router try to send a package to itself
            if (ip_hdr->daddr == adrbuf.s_addr)
            {
                memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
                get_interface_mac(interface, eth_hdr->ether_shost);
                //exchange ethernet addresses
                ip_hdr->daddr = ip_hdr->saddr;
                ip_hdr->saddr = adrbuf.s_addr;
                ip_hdr->check = 0;
                //recalculate checksum for ip header
                uint16_t check1 = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
                ip_hdr->check = htons(check1);
                struct icmphdr *icmphdr = (struct icmphdr *)((char *)ip_hdr + (sizeof(struct iphdr)));
                icmphdr->code = 0;
                icmphdr->type = 0;
                icmphdr->checksum = 0;
                //recalculate checksum for icmp header
                uint16_t check2 = checksum((uint16_t *)icmphdr, sizeof(struct icmphdr));
                icmphdr->checksum = htons(check2);
                //send the package
                send_to_link(interface, buf, len);
                continue;
            }
            //no error so this is a normal package
            //decrease ttl
            ip_hdr->ttl--;
            //recalculate checksum
            ip_hdr->check = 0;
            uint16_t newchck = checksum((uint16_t *)ip_hdr, sizeof(*ip_hdr));
            ip_hdr->check = htons(newchck);
            //find the new hop in the route
            struct arp_entry *next_mac = get_arp_entry(next_route->next_hop);
            get_interface_mac(next_route->interface, eth_hdr->ether_shost);
            memcpy(eth_hdr->ether_dhost, next_mac->mac, 6);
            //send the package
            send_to_link(next_route->interface, (char *)buf, len);
        }
        /* Note that packets received are in network order,
        any header field which has more than 1 byte will need to be conerted to
        host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
        sending a packet on the link, */
    }
}