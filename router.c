#include <queue.h>
#include "skel.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>


struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

struct arp_entry {
	__u32 ip;
	uint8_t mac[6];
};

int rtable_size;
int arp_table_len;


void merge(struct route_table_entry *rtable, int l, int m, int r)
{
    int i, j, k;
    int n1 = m - l + 1;
    int n2 = r - m;
 
    struct route_table_entry *L = malloc(n1 * sizeof(struct route_table_entry));
    struct route_table_entry *R = malloc(n2 * sizeof(struct route_table_entry));
 

    for (i = 0; i < n1; i++)
        L[i] = rtable[l + i];
    for (j = 0; j < n2; j++)
        R[j] = rtable[m + 1 + j];
 
    
    i = 0; 
    j = 0; 
    k = l; 
    while (i < n1 && j < n2) {
        if (L[i].prefix <= R[j].prefix) {
            rtable[k] = L[i];
            i++;
        }
        else {
            rtable[k] = R[j];
            j++;
        }
        k++;
    }
 
    while (i < n1) {
        rtable[k] = L[i];
        i++;
        k++;
    }
 
    while (j < n2) {
        rtable[k] = R[j];
        j++;
        k++;
    }

    free(L);
    free(R);
}
 
void mergeSort(struct route_table_entry *rtable, int l, int r)
{
    if (l < r) {
      
        int m = l + (r - l) / 2;
 
        mergeSort(rtable, l, m);
        mergeSort(rtable, m + 1, r);
 
        merge(rtable, l, m, r);
    }
}

void read_rtable(struct route_table_entry *rtable, char* path)
{

	FILE* file = fopen(path,"r");
	if (file == NULL) {
		printf("ERROR: cannot open rtable file\n");
		return;
	}

	char line[100];
	struct in_addr addr;
	char prefix[20];
	char next_hop[20];
	char mask[20];
	char interface[3];
	
	rtable_size = 0;
	while ((fscanf(file, "%[^\n]", line)) != EOF) {

		// citirea se face linie cu linie, se extrage informatia din linie
 		// si se salveaza in tabela
		int i = 0, cnt = 0;
		while (line[i] != ' ') {
			prefix[cnt++] = line[i++];
		}
		prefix[cnt] = '\0';
		inet_aton(prefix, &addr);
		rtable[rtable_size].prefix = (uint32_t) addr.s_addr;

		i++;
		cnt = 0;
		while (line[i] != ' ') {
			next_hop[cnt++] = line[i++];
		}
		next_hop[cnt] = '\0';
		inet_aton(next_hop, &addr);
		rtable[rtable_size].next_hop = (uint32_t) addr.s_addr;

		i++;
		cnt = 0;
		while (line[i] != ' ') {
			mask[cnt++] = line[i++];
		}
		mask[cnt] = '\0';
		inet_aton(mask, &addr);
		rtable[rtable_size].mask = (uint32_t) addr.s_addr;

		interface[0] = line[i + 1];
		interface[1] = '\0';
		rtable[rtable_size++].interface = atoi(interface);

		fgetc(file);
	
	 }
}

struct route_table_entry *get_best_route(__u32 dest_ip, struct route_table_entry *rtable)
{

	struct route_table_entry *entry = NULL;
	int left = 0;
	int right = rtable_size - 1;


	while (left <= right) {

		int mid = left + (right - left) / 2;

		if ((dest_ip & rtable[mid].mask) == rtable[mid].prefix) {
			return (&rtable[mid]);
		}

		if ((dest_ip & rtable[mid].mask) > rtable[mid].prefix) {
			left = mid + 1;
		}

		if ((dest_ip & rtable[mid].mask) < rtable[mid].prefix) {
			right = mid - 1;
		}

	}

	return entry;
}

struct arp_entry *get_arp_entry(__u32 ip, struct arp_entry *arp_table) 
{

	// se parcurge arp_table si se extrage instanta care are ip-ul 
	// egal cu ip-ul primit ca argument
	struct arp_entry *entry = NULL;

	for (int i = 0; i < arp_table_len && entry == NULL; i++) {
		if (ip == arp_table[i].ip) {
			entry = (&arp_table[i]);
		}
	}

    return entry;
}


int main(int argc, char *argv[])
{
	packet m;
	int rc;

	init(argc - 2, argv + 2);
	

	struct route_table_entry *rtable = malloc(100000 * sizeof(struct route_table_entry));
	struct arp_entry *arp_table = malloc(1000 * sizeof(struct arp_entry));
	arp_table_len = 0;

	// parsez informatia din fisier in rtable
	read_rtable(rtable, argv[1]);
	
	// sortez tabela de rutare pentru a putea face procesul de rutare intr-un timp eficient
	mergeSort(rtable, 0, rtable_size - 1);
	
	// creez o coada care va ajuta la rutare
	queue q = queue_create();


	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		// extrag header-ele din pachet
		struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
		struct arp_header *arp_hdr = parse_arp(m.payload);
		struct icmphdr *icmp_hdr = parse_icmp(m.payload);
		struct in_addr my_addr;
		
		// verific daca pachetul este IP 
		if (eth_hdr->ether_type == htons(2048)) {
			// verific daca este destinat ruterului
			inet_aton(get_interface_ip(m.interface), &my_addr);
			if (ip_hdr->daddr == my_addr.s_addr) {
				//verific daca este un pachet icmp
				if (icmp_hdr != NULL) {
					// daca este icmp echo request
					if (icmp_hdr->type == 8) {
						// trebuie sa trimit un icmp echo reply
						send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, 0, 0, m.interface, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
					}
					//arunca pachetul
					continue;
				}
			}
		}

		// daca este un pachet ARP
		if (eth_hdr->ether_type == htons(2054)) {
			if (arp_hdr != NULL) {
				//daca este un pachet arp request
				if (arp_hdr->op == htons(1)) {
					//raspunde cu arp reply cu adresa mac potrivita
					
					for (int i = 0; i < 6; i++) {
						eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
					}
					get_interface_mac(m.interface, eth_hdr->ether_shost);
					send_arp(arp_hdr->spa, arp_hdr->tpa, eth_hdr, m.interface, htons(2));
					
					// arunc pachetul original
					continue;
				
				} else {
					// este pachet arp reply

					// fac update la tabela arp
					arp_table[arp_table_len].ip = arp_hdr->spa;
					for (int j = 0; j < 6; j++) {
						arp_table[arp_table_len].mac[j] = arp_hdr->sha[j];	
					}
					arp_table_len++;

					// daca in coada exista pachete care trebuie dirijate catre adresa
					// sursa a pachetului arp reply, le trimit
					if (!queue_empty(q)) {

						queue q_aux = queue_create();
						while (!queue_empty(q)) {

							packet *p = queue_deq(q);
							queue_enq(q_aux, p);
							struct iphdr *ip_hdr_aux = (struct iphdr *)(p->payload + sizeof(struct ether_header));

							if (ip_hdr_aux != NULL) {
								if (ip_hdr_aux->daddr == arp_hdr->spa) {		
									send_packet(p->interface, p);
									queue_deq(q_aux);
								}
							}
						}

						while (!queue_empty(q_aux)) {
							queue_enq(q, queue_deq(q_aux));
						}
					}

					// arunc pachetul arp reply
					continue;
				}
			}
		}
			

		if (ip_hdr->ttl <= 1) {
			send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, 11, 0, m.interface);
			continue;
		}

		// verific checksum-ul
		uint16_t checksum = ip_hdr->check;
		ip_hdr->check = 0;
		uint16_t checksum2 = ip_checksum(ip_hdr, sizeof(struct iphdr));

		if (checksum != checksum2) {
			continue;
		}

		// decrementez ttl-ul si actualizez checksum-ul
		ip_hdr->ttl--;
		ip_hdr->check = 0;
		ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

		// incepe procesul de rutare 
		struct route_table_entry *best_route = get_best_route(ip_hdr->daddr, rtable);
		if (best_route != NULL) {
			// caut adresa next_hop in arp_table
			struct arp_entry* entry = get_arp_entry(best_route->next_hop, arp_table);
			if (entry != NULL) {
				
				// actualizez adresa sursa ethernet 
				get_interface_mac(best_route->interface, eth_hdr->ether_shost);
				//se actualizeaza adresa destinatie a header-ului Ethernet 
				//folosind adresa MAC a urmatorului nod(next_hop)
				for(int i = 0; i < 6; i++) {
					eth_hdr->ether_dhost[i] = entry->mac[i];						
				}
				eth_hdr->ether_type = htons(2048);	
				send_packet(best_route->interface, &m);
						
			} else {
				// trebuie sa trimit un arp request si pun pachetul in asteptare intr-o coada
				// pentru a face rutarea lui cand voi primi informatia ceruta
				// trebuie sa pun adresa destinatie a header-ului ethernet: ff:ff:ff:ff:ff:ff
				
				packet p = m;
				p.interface = best_route->interface;
				queue_enq(q, &p);

				hwaddr_aton("ff:ff:ff:ff:ff:ff", eth_hdr->ether_dhost);
				get_interface_mac(best_route->interface, eth_hdr->ether_shost);
				build_ethhdr(eth_hdr, eth_hdr->ether_shost, eth_hdr->ether_dhost, htons(2054));
				send_arp(ip_hdr->daddr, ip_hdr->saddr, eth_hdr, best_route->interface, htons(1));
				
			}
		} else {
			//daca nu am ruta
			send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, 3, 0, m.interface);
		}

	}
}
