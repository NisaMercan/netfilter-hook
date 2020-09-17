/*** Netfilter Hook hook01.c
#  *   
#  * 01.09.2020 Nisa Mercan <nisamercan11@gmail.com>
#  * Please do not remove this header.
#  ***/
 /*
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/netfilter_ipv4.h> /* Ipv4 family */
#include <linux/skbuff.h> 
#include <linux/netfilter.h>	
#include <linux/udp.h> /* udphdr */
#include <linux/ip.h> /* iphdr */


/* This function to be called by hook. */
/* @param unsigned int hooknum: shows where the hooks made.NF_IP_PRE_ROUTING, NF_IP_LOCAL_IN, NF_IP_FORWARD 
 * @param struct sk_buff *skb: pointer to packets that inside the network stack. We can reach to packets through this pointer. 
 * @param const struct net_device *in: where network packets arrive to.
 * @param const struct net_device *out: where network packets leave from.
 * @param int (*okfn) (struct sk_buff *)): OK function. Never invoke, prevent other hooks from inspecting the packet. 
 * */
 unsigned int hook_func( unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn) (struct sk_buff *)) {


    struct udphdr *udp_header; 
    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);  


    if (!skb) { 
	    printk(KERN_INFO "Accept skb packet.\n IP: %pI4", (void *)&ip_header->saddr);
	    return NF_ACCEPT;
    } 

    if (ip_header->protocol == 17) { //IPPROTO_UDP The protocol that is requested
        udp_header = (struct udphdr *)skb_transport_header(skb); 
	    if (ntohs(udp_header->dest) == 53) {/* DNS tcp/udp port53. Convert values between host and network byte order(the unsigned short integer netshort from network byte order to host byte order). */
			printk(KERN_INFO "Accepted_up: IP: %pI4", (void *)&ip_header->saddr);
			return NF_ACCEPT;
		}
       }

    else if (ip_header->protocol == IPPROTO_TCP) {
	    printk(KERN_INFO "Accepted_tcp: IP: %pI4", (void *)&ip_header->saddr); 
	    return NF_ACCEPT;
	} 
	
	
	printk(KERN_INFO "Dropping: IP: %pI4", (void *)&ip_header->saddr);
	return NF_DROP;
  /*return NF_ACCEPT;*/
}

/* Inserting to the kernel
 * */
/ static struct nf_hook_ops nfho = { 
    .hook       = (nf_hookfn*)hook_func, 
    .hooknum    = NF_INET_PRE_ROUTING, /* where the hooks made */
    .pf         = PF_INET,             /* protocol family Ipv4 */
    .priority   = NF_IP_PRI_FIRST,     /* first, mangle, last */
}; 

/* Register
 * */ 
 static int __init init_nf(void) {
    printk(KERN_INFO "Registering the netfilter hook module.\n");
    nf_register_net_hook(&init_net,&nfho);

    return 0;
}

/* Unregister
 * */
static void __exit exit_nf(void) {
    printk(KERN_INFO "Unregistering the netfilter hook module.\n");
    nf_unregister_net_hook(&init_net, &nfho); */
}

module_init(init_nf);
module_exit(exit_nf);

MODULE_LICENSE("GPL"); /*General Public License*/
MODULE_AUTHOR("Nisa Mercan <nisamercan11@gmail.com>");
MODULE_DESCRIPTION("Netfilter Hook"); */