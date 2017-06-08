Please note that certain snippet of following code is taken from
the link provided in question: http://www.linuxjournal.com/article/7184
*/



#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>

/*
Defining the IPs in integer
———————————————————————————

Topology uses the following IP addresses:

Network in which hosts are present: 10.0.0.0/24
Webserver IP: 10.0.0.100 (link 2)
Remote client: 192.168.1.0/24 (link 5)
*/

#define HOST_NW_IP 167772160
#define HOST_NW_IP_prefix 24

#define WEBSERVER_IP 167772260
#define WEBSERVER_IP_prefix 32

#define REMOTE_CLIENT 3232235776
#define REMOTE_CLIENT_prefix 24

// Structure define
static struct nf_hook_ops netfilter_ops_in;


/*
A function “network_has_ip()” is defined below which is used to find out
if a given IP address is present in a given IP or not.
The function returns 0 if function value is false and 1 if true.
*/

bool network_has_ip(unsigned int ip, unsigned int nw_ip, unsigned int prefix)
{
	unsigned int mask = ~(0xffffffff >> prefix);
	unsigned int mask_1, mask_2;

	mask_1 = nw_ip & mask;
	mask_2 = ip & mask;

	return mask_1 == mask_2;
}

// ***************** Defining the main hook *****************

unsigned int main_hook(unsigned int hooknum, struct sk_buff *skb,
			const struct net_device *in, const struct net_device *out, 
			int (*okfn) (struct sk_buff *))
{
	// Define structures for corresponding headers
	struct iphdr *ip_header = (struct iphdr *) ip_hdr(skb);
	struct icmphdr *icmp_header;
	struct tcphdr *tcp_header;

	// Variables declaration and initialization for source/destination IP and respective port numbers
	unsigned int src_ip = (unsigned int)ip_header ->saddr;
	unsigned int dest_ip = (unsigned int)ip_header->daddr;
	unsigned int icmp_type = 0;
	unsigned int src_port = 0;
	unsigned int dest_port = 0;

    char* management = "eth0";
    if((strcmp(in->name,management)==0)){
        return NF_ACCEPT;
    }
    
if (ip_header->protocol == 1)
{
	icmp_header = (struct icmphdr *)(ip_hdr(skb));
	icmp_type = icmp_header->type;
}

else if (ip_header->protocol == 6)
{
	tcp_header = (struct tcphdr *)(tcp_hdr(skb));
	src_port = ntohs((unsigned int) tcp_header->source);
	dest_port = ntohs((unsigned int) tcp_header->dest);
}
    

    //Debug information:
    
    printk(KERN_INFO " Packet Information : icmp type: %u,\n",
           icmp_type);
    
    printk(KERN_INFO " Packet Information : interface: %s, "
               "src ip: %u (%pI4), "
               "src port: %u; dest ip: %u (%pI4), "
               "dest port: %u; proto: %u\n",
               in->name, src_ip, &src_ip,  src_port,
               dest_ip, &dest_ip, dest_port,
               ip_header->protocol);

// ***************** RULE 1, 2 AND 3 IMPLEMENTATION *****************

if ( ip_header->protocol == 1)
{
	if (network_has_ip(ntohl(src_ip), REMOTE_CLIENT, 24))
		{
			if(icmp_hdr(skb)->type == 0)
			{
                		return NF_ACCEPT;
			}

        }
        if ((icmp_hdr(skb)->type == 8) && !network_has_ip((ntohl(dest_ip)), WEBSERVER_IP, WEBSERVER_IP_prefix))
		{
			printk(KERN_INFO "Block Rule 1: A remote  client with IP (%pI4) at %s is sending an ICMP packet to the web server %pI4.", &src_ip, in->name, &dest_ip);
			return NF_DROP;
		}
}

if (ip_header->protocol == IPPROTO_TCP && dest_port == 22)
{
        if(network_has_ip((ntohl(src_ip)),REMOTE_CLIENT,24))
	{
               	printk(KERN_INFO "Packets Dropped. Active: Rule 2 - A host from other network (%pI4) at %s is trying to SSH on TCP port:22 to %pI4.",&src_ip, in->name, &dest_ip);
		return NF_DROP;
	}
}

if (ip_header->protocol == IPPROTO_TCP && dest_port == 80)
{
	if(network_has_ip((ntohl(src_ip)),REMOTE_CLIENT,REMOTE_CLIENT_prefix))
	{
		if(network_has_ip(ntohl(dest_ip),WEBSERVER_IP,WEBSERVER_IP_prefix)) 	
		{
			printk(KERN_INFO "PERMIT Rule 3: A host from different network (%pI4) at %s is connecting with webserver %pI4 on TCP port:80.", &src_ip, in->name, &dest_ip);
			return NF_ACCEPT;
		}
		else if (network_has_ip((ntohl(dest_ip)), HOST_NW_IP, HOST_NW_IP_prefix))
		{I
			printk(KERN_INFO "Packets Dropped. Active: Rule 3 - A host from other  network (%pI4) on %s is connecting with a host in network %pI4 on TCP port:80\n", &src_ip, in->name, &dest_ip);
			return NF_DROP;
		}
    }
}cup
    return NF_ACCEPT;
}

// ***************** Defining the init module *****************

int init_module(void) {
	printk(KERN_INFO "Initializing for firewall kernel module.\n");
	netfilter_ops_in.hook = main_hook;
	netfilter_ops_in.hooknum = NF_INET_PRE_ROUTING;
	netfilter_ops_in.pf = PF_INET;
	netfilter_ops_in.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&netfilter_ops_in);

	return 0;

}

// ***************** Defining the Cleanup module *****************

void cleanup_module(void) {
	nf_unregister_hook(&netfilter_ops_in);
	printk(KERN_INFO "Firewall kernel module unloaded.\n");
}
