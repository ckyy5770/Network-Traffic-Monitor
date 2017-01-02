#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/string.h>
#include <linux/inet.h>

#define AUTHOR "Chuilian Kong <iloveyoukcl5770@gmail.com>"
#define DESC "NTMM: A kernel module that monitors network traffic"
#define LICENSE "KCL"
#define MODULE_PROC_NAME "htmm"

#define MAX_IP_ENTRY 200
#define MAX_QUOTA_ENTRY 200
#define MAX_HOOK_ENTRY 20
#define MSG_SIZE 200

#define PRIORITY_MONITOR -1
#define PRIORITY_DROP 0
#define PRIORITY_QUOTA 1

#define MONITOR_LOG_PATH "/var/log/htmm_monitor_log"
#define FILTER_LOG_PATH


#define LOG_ADDR_TO_MONITOR()
#define LOG_ADDR_TO_FILTER()

// log file descriptors
//int fd_monitor_log;
//int fd_filter_log;

// proc related globes
int len, temp;
static char *msg = 0;
struct proc_dir_entry *proc_file_entry;

// netfilter related globes
struct sk_buff *sock_buff;				// socket buffer
struct iphdr *ip_header;				// ip header struct
unsigned short packet_size_host;		// packet size in host byte order
__u8 head_size; 						// head size of the packet
unsigned short data_size;				// data size of the packet

// ip list related globes
static int saddr_block_num = 0;
static __be32 saddr_block_list[MAX_IP_ENTRY];
static int daddr_block_num = 0;
static __be32 daddr_block_list[MAX_IP_ENTRY];

// quota list related globes
static struct st_quota_list {
	__be32 addr;
	unsigned long quota;
	unsigned long current_traffic;
};
static int saddr_quota_num = 0;
static struct st_quota_list saddr_quota_list[MAX_QUOTA_ENTRY];
static int daddr_quota_num = 0;
static struct st_quota_list daddr_quota_list[MAX_QUOTA_ENTRY];

// hook table related structures and globes
enum hook_t {
	MONITOR,
	DROPALL,
	DROPBLOCKED,
	QUOTA
};
static struct {
	unsigned int hooknum;
	int priority;
	enum hook_t hooktype;
	struct nf_hook_ops *pnfho;
} hook_table[MAX_HOOK_ENTRY];
static int reg_hook_num = 0;

// all hook function here can be hooked either on NF_INET_LOCAL_IN or NF_INET_LOCAL_OUT
// this hook function will log all network traffic into MONITOR_LOG_PATH
// and accept all packets on where it is hooked
unsigned int hook_func_moniter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	// get hooknum from hook state
	unsigned int hooknum = state->hook;
	// get ip header of the packet
	sock_buff = skb;
	ip_header = (struct iphdr *)skb_network_header(sock_buff);
	// if sock_buff is NULL, log the info and accept
	if (!sock_buff)
	{
		printk(KERN_ERR "hook_func_moniter: sock_buff is NULL.(accept)\n");
		return NF_ACCEPT;
	}

	// get data size of the packet
	// convert netshort type to unsigned short in host
	packet_size_host = ntohs(ip_header->tot_len);
	// get head size of the packet
	head_size = ip_header->ihl * 32 / 8;
	// then data size should be packet_size_host-head_size
	data_size = packet_size_host - head_size;

	// depending on where the function is hooked,
	// the function will analyse source address or destination address, and log them and accept the packet
	if (hooknum == NF_INET_LOCAL_IN)
	{
		printk(KERN_INFO "hook_func_moniter: LOCAL_IN %pI4 (accept) data size: %hu bytes\n", (void*) & (ip_header->saddr),  data_size);
		return NF_ACCEPT;
	}
	else if (hooknum == NF_INET_LOCAL_OUT)
	{
		printk(KERN_INFO "hook_func_moniter: LOCAL_OUT %pI4 (accept) data size: %hu bytes\n", (void*) & (ip_header->daddr), data_size);
		return NF_ACCEPT;
	}
	else
	{
		printk(KERN_INFO "hook_func_moniter: the hook function is hooked on the wrong place. hooknum: %u saddr: %pI4 daddr: %pI4 (accept) data size: %hu bytes\n", hooknum, (void*) & (ip_header->saddr), (void*) & (ip_header->daddr), data_size);
		return NF_ACCEPT;
	}

}

// this hook function will drop all packets on where it is hooked and log them into FILTER_LOG_PATH
unsigned int hook_func_dropall(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	// get hooknum from hook state
	unsigned int hooknum = state->hook;
	// get ip header of the packet
	sock_buff = skb;
	ip_header = (struct iphdr *)skb_network_header(sock_buff);
	// if sock_buff is NULL, log the info and drop
	if (!sock_buff)
	{
		printk(KERN_ERR "hook_func_dropall: sock_buff is NULL.(drop)\n");
		return NF_DROP;
	}

	// get data size of the packet
	// convert netshort type to unsigned short in host
	packet_size_host = ntohs(ip_header->tot_len);
	// get head size of the packet
	head_size = ip_header->ihl * 32 / 8;
	// then data size should be packet_size_host-head_size
	data_size = packet_size_host - head_size;


	// depending on where the function is hooked,
	// the function will analyse source address or destination address, and log them and drop the packet
	if (hooknum == NF_INET_LOCAL_IN)
	{
		printk(KERN_INFO "hook_func_dropall: LOCAL_IN %pI4 (drop) data size: %hu bytes\n", (void*) & (ip_header->saddr), data_size);
		return NF_DROP;
	}
	else if (hooknum == NF_INET_LOCAL_OUT)
	{
		printk(KERN_INFO "hook_func_dropall: LOCAL_OUT %pI4 (drop) data size: %hu bytes\n", (void*) & (ip_header->daddr), data_size);
		return NF_DROP;
	}
	else
	{
		printk(KERN_INFO "hook_func_dropall: the hook function is hooked on the wrong place. hooknum: %u saddr: %pI4 daddr: %pI4 (drop) data size: %hu bytes\n", hooknum, (void*) & (ip_header->saddr), (void*) & (ip_header->daddr), data_size);
		return NF_DROP;
	}

}

// check if a ip address is listed in a block list
// return (entry index +1) if listed, 0 otherwise
// para listid specify which list should we check,
// 's' indicate saddr_block_list
// 'd' indicate daddr_block_list
int listed(__be32 ip, char listid)
{
	int i;
	if (listid == 's')
	{
		for (i = 0; i < saddr_block_num; i++)
		{
			if (ip == saddr_block_list[i])
				return i + 1;
		}
		return 0;
	}
	else if (listid == 'd')
	{
		for (i = 0; i < daddr_block_num; i++)
		{
			if (ip == daddr_block_list[i])
				return i + 1;
		}
		return 0;
	}
	else
	{
		printk(KERN_ERR "listed: listid is wrong: %c \n", listid);
		return 0;
	}
}



// check if the given ip address is listed in a block list
// if not, add it, if it is, report it.
// para listid specify which list should we check,
// 's' indicate saddr_block_list
// 'd' indicate daddr_block_list
int add_entry_to_list(__be32 ip, char listid)
{
	if (listed(ip, listid))
	{
		printk(KERN_INFO "add_entry_to_list: entry existed. ip: %pI4 listid: %c\n", (void*) & (ip), listid);
		return 0;
	}
	else
	{
		if (listid == 's')
		{
			saddr_block_list[saddr_block_num] = ip;
			saddr_block_num++;
			printk(KERN_INFO "add_entry_to_list: add ip: %pI4 to listid: %c \n", (void*) & (ip), listid);
			return 0;
		}
		else if (listid == 'd')
		{
			daddr_block_list[daddr_block_num] = ip;
			daddr_block_num++;
			printk(KERN_INFO "add_entry_to_list: add ip: %pI4 to listid: %c \n", (void*) & (ip), listid);
			return 0;
		}
		else
		{
			printk(KERN_ERR "add_entry_to_list: listid is wrong: %c \n", listid);
			return -1;
		}

	}
}



// check if the given ip address is listed in a block list
// if is, delete it, if not, report it.
// para listid specify which list should we check,
// 's' indicate saddr_block_list
// 'd' indicate daddr_block_list
int delete_entry_from_list(__be32 ip, char listid)
{
	int i;
	int ret;
	int entry_index;
	if (!(ret = listed(ip, listid)))
	{
		printk(KERN_INFO "delete_entry_to_list: entry not existed. ip: %pI4 listid: %c\n", (void*) & (ip), listid);
		return 0;
	}
	else
	{
		// get the entry number that we need to kill
		entry_index = ret - 1;
		// delet the entry by move every entry bebind it forward one entry.
		if (listid == 's')
		{
			for (i = entry_index; i < saddr_block_num - 1; i++)
			{
				saddr_block_list[i] = saddr_block_list[i + 1];
			}
			saddr_block_num--;
			printk(KERN_INFO "delete_entry_to_list: delete ip: %pI4 from listid: %c \n", (void*) & (ip), listid);
			return 0;
		}
		else if (listid == 'd')
		{
			for (i = entry_index; i < daddr_block_num - 1; i++)
			{
				daddr_block_list[i] = daddr_block_list[i + 1];
			}
			daddr_block_num--;
			printk(KERN_INFO "delete_entry_to_list: delete ip: %pI4 from listid: %c \n", (void*) & (ip), listid);
			return 0;
		}
		else
		{
			printk(KERN_ERR "delete_entry_to_list: listid is wrong: %c \n", listid);
			return -1;
		}

	}
}



// this hook function will drop packets in the block list
// if this function is hooked on the LOCAL_IN, the function will check saddr_block_list
// and block all packets listed
// if this function is hooked on the LOCAL_IN, the function will check daddr_block_list
// and block all packets listed
// the function will log all droped packets into FILTER_LOG_PATH
unsigned int hook_func_dropblocked(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	// get hooknum from hook state
	unsigned int hooknum = state->hook;
	// get ip header of the packet
	sock_buff = skb;
	ip_header = (struct iphdr *)skb_network_header(sock_buff);
	// if sock_buff is NULL, log the info and accept
	if (!sock_buff)
	{
		printk(KERN_ERR "hook_func_dropblocked: sock_buff is NULL.(drop)\n");
		return NF_ACCEPT;
	}

	// get data size of the packet
	// convert netshort type to unsigned short in host
	packet_size_host = ntohs(ip_header->tot_len);
	// get head size of the packet
	head_size = ip_header->ihl * 32 / 8;
	// then data size should be packet_size_host-head_size
	data_size = packet_size_host - head_size;

	// depending on where the function is hooked,
	// the function will analyse source address or destination address, and log them and drop the packet
	if (hooknum == NF_INET_LOCAL_IN)
	{
		// if this function is hooked on the LOCAL_IN, the function will check saddr_block_list
		// and block all packets listed
		if (listed(ip_header->saddr, 's')) {
			printk(KERN_INFO "hook_func_dropblocked: LOCAL_IN %pI4 (drop) data size: %hu bytes\n", (void*) & (ip_header->saddr), data_size);
			return NF_DROP;
		}
		else
		{
			return NF_ACCEPT;
		}

	}
	else if (hooknum == NF_INET_LOCAL_OUT)
	{
		// if this function is hooked on the LOCAL_OUT, the function will check daddr_block_list
		// and block all packets listed
		if (listed(ip_header->daddr, 'd'))
		{
			printk(KERN_INFO "hook_func_dropblocked: LOCAL_OUT %pI4 (drop) data size: %hu bytes\n", (void*) & (ip_header->daddr), data_size);
			return NF_DROP;
		}
		else
		{
			return NF_ACCEPT;
		}

	}
	else
	{
		printk(KERN_INFO "hook_func_dropblocked: the hook function is hooked on the wrong place. hooknum: %u saddr: %pI4 daddr: %pI4 (drop) data size: %hu bytes\n", hooknum, (void*) & (ip_header->saddr), (void*) & (ip_header->daddr), data_size);
		return NF_DROP;
	}

}


// check if a ip address is listed in a quota list
// return (entry index +1) if listed, 0 otherwise
// para listid specify which list should we check,
// 's' indicate saddr_quota_list
// 'd' indicate daddr_quota_list
int listed_quota(__be32 ip, char listid)
{
	int i;
	if (listid == 's')
	{
		for (i = 0; i < saddr_quota_num; i++)
		{
			if (ip == saddr_quota_list[i].addr)
				return i + 1;
		}
		return 0;
	}
	else if (listid == 'd')
	{
		for (i = 0; i < daddr_quota_num; i++)
		{
			if (ip == daddr_quota_list[i].addr)
				return i + 1;
		}
		return 0;
	}
	else
	{
		printk(KERN_ERR "listed_quota: listid is wrong: %c \n", listid);
		return 0;
	}
}


// check if the given ip address is listed in a quota list
// if not, add it, if it is, update it.
// para listid specify which list should we check,
// 's' indicate saddr_quota_list
// 'd' indicate daddr_quota_list
int add_entry_to_list_quota(__be32 ip, unsigned long quota, char listid)
{
	int index;
	unsigned long old_quota;
	unsigned long old_traffic;
	if (index = listed_quota(ip, listid))
	{
		// if the current traffic is already overwhelmed the old quota
		// (i.e. #IP is on the block list due to quota limit), it will free the #IP first.
		if (listid == 's')
		{
			index--;
			old_quota = saddr_quota_list[index].quota;
			old_traffic = saddr_quota_list[index].current_traffic;
			if (old_traffic > old_quota)
			{
				delete_entry_from_list(ip, 's');
			}
			// update new quota
			saddr_quota_list[index].quota = quota;
			printk(KERN_INFO "add_entry_to_list_quota: entry existed, update its quota to %lu bytes. ip: %pI4 listid: %c\n", quota, (void*) & (ip), listid);
			return 0;
		}
		else if (listid == 'd')
		{
			index--;
			old_quota = daddr_quota_list[index].quota;
			old_traffic = daddr_quota_list[index].current_traffic;
			if (old_traffic > old_quota)
			{
				delete_entry_from_list(ip, 'd');
			}
			// update new quota
			daddr_quota_list[index].quota = quota;
			printk(KERN_INFO "add_entry_to_list_quota: entry existed, update its quota to %lu bytes. ip: %pI4 listid: %c\n", quota, (void*) & (ip), listid);
			return 0;
		}
		else
		{
			printk(KERN_ERR "add_entry_to_list_quota: listid is wrong: %c \n", listid);
			return -1;
		}
	}
	else
	{
		if (listid == 's')
		{
			saddr_quota_list[saddr_quota_num].addr = ip;
			saddr_quota_list[saddr_quota_num].quota = quota;
			saddr_quota_list[saddr_quota_num].current_traffic = 0;
			saddr_quota_num++;
			printk(KERN_INFO "add_entry_to_list_quota: add ip: %pI4 quota: %lu bytes to listid: %c \n", (void*) & (ip), quota, listid);
			return 0;
		}
		else if (listid == 'd')
		{
			daddr_quota_list[daddr_quota_num].addr = ip;
			daddr_quota_list[daddr_quota_num].quota = quota;
			daddr_quota_list[daddr_quota_num].current_traffic = 0;
			daddr_quota_num++;
			printk(KERN_INFO "add_entry_to_list_quota: add ip: %pI4 quota: %lu bytes to listid: %c \n", (void*) & (ip), quota, listid);
			return 0;
		}
		else
		{
			printk(KERN_ERR "add_entry_to_list_quota: listid is wrong: %c \n", listid);
			return -1;
		}

	}
}

// check if the given ip address is listed in a quota list
// if is, delete it, if not, report it.
// if the current traffic is already overwhelmed the quota
// (i.e. #IP is on the block list due to quota limit), it will free the #IP first.
// para listid specify which list should we check,
// 's' indicate saddr_block_list
// 'd' indicate daddr_block_list
int delete_entry_from_list_quota(__be32 ip, char listid)
{
	int i;
	int ret;
	int entry_index;
	unsigned long old_quota;
	unsigned long old_traffic;
	if (!(ret = listed(ip, listid)))
	{
		printk(KERN_INFO "delete_entry_from_list_quota: entry not existed. ip: %pI4 listid: %c\n", (void*) & (ip), listid);
		return 0;
	}
	else
	{
		// get the entry number that we need to kill
		entry_index = ret - 1;

		// delet the entry by move every entry bebind it forward one entry.
		if (listid == 's')
		{

			// check if current traffic is already overwhelmed the quota
			// (i.e. if #IP is on the block list due to quota limit,it will free the #IP first.)
			old_quota = saddr_quota_list[entry_index].quota ;
			old_traffic = saddr_quota_list[entry_index].current_traffic;
			if (old_traffic > old_quota)
			{
				delete_entry_from_list(ip, 's');
			}
			// delete the entry
			for (i = entry_index; i < saddr_quota_num - 1; i++)
			{
				saddr_quota_list[i] = saddr_quota_list[i + 1];
			}
			saddr_quota_num--;
			printk(KERN_INFO "delete_entry_from_list_quota: delete ip: %pI4 from listid: %c \n", (void*) & (ip), listid);
			return 0;
		}
		// delet the entry by move every entry bebind it forward one entry.
		else if (listid == 'd')
		{

			// check if current traffic is already overwhelmed the quota
			// (i.e. if #IP is on the block list due to quota limit,it will free the #IP first.)
			old_quota = daddr_quota_list[entry_index].quota ;
			old_traffic = daddr_quota_list[entry_index].current_traffic;
			if (old_traffic > old_quota)
			{
				delete_entry_from_list(ip, 'd');
			}
			// delete the entry
			for (i = entry_index; i < daddr_quota_num - 1; i++)
			{
				daddr_quota_list[i] = daddr_quota_list[i + 1];
			}
			daddr_quota_num--;
			printk(KERN_INFO "delete_entry_from_list_quota: delete ip: %pI4 from listid: %c \n", (void*) & (ip), listid);
			return 0;
		}
		else
		{
			printk(KERN_ERR "delete_entry_to_list: listid is wrong: %c \n", listid);
			return -1;
		}

	}
}

// this function will monitor specific saddr/daddr on the saddr_quota_list/daddr_quota_list,
// and update current_traffic when there is a network traffic corresponding to the addr.
// Each time after update the current_traffic, it will check if current_traffic is more than quota,
// if it is, add the saddr/daddr to saddr_block_list/daddr_block_list.
// this function itself will ACCEPT all packet pass through it.
unsigned int hook_func_quota_controller(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	int index;
	// get hooknum from hook state
	unsigned int hooknum = state->hook;
	// get ip header of the packet
	sock_buff = skb;
	ip_header = (struct iphdr *)skb_network_header(sock_buff);
	// if sock_buff is NULL, log the info and accept
	if (!sock_buff)
	{
		printk(KERN_ERR "hook_func_quota_controller: sock_buff is NULL.(accept)\n");
		return NF_ACCEPT;
	}

	// get data size of the packet
	// convert netshort type to unsigned short in host
	packet_size_host = ntohs(ip_header->tot_len);
	// get head size of the packet
	head_size = ip_header->ihl * 32 / 8;
	// then data size should be packet_size_host-head_size
	data_size = packet_size_host - head_size;

	// depending on where the function is hooked,
	// the function will analyse source address or destination address, and log them and accept the packet
	if (hooknum == NF_INET_LOCAL_IN)
	{
		if (index = listed_quota(ip_header->saddr, 's'))
		{
			index--;
			saddr_quota_list[index].current_traffic += data_size;
			printk(KERN_INFO "hook_func_quota_controller: LOCAL_IN %pI4 (accept) data size: %hu bytes, quota: %lu bytes, current %lu bytes\n", (void*) & (ip_header->saddr),  data_size, saddr_quota_list[index].quota, saddr_quota_list[index].current_traffic);
			if (saddr_quota_list[index].current_traffic > saddr_quota_list[index].quota)
			{
				printk(KERN_INFO "hook_func_quota_controller: LOCAL_IN %pI4 (accept) traffic exceed quota, add it to block list.", (void*) & (ip_header->saddr));
				add_entry_to_list(ip_header->saddr, 's');
			}
		}

		return NF_ACCEPT;
	}
	else if (hooknum == NF_INET_LOCAL_OUT)
	{
		if (index = listed_quota(ip_header->daddr, 'd'))
		{
			index--;
			daddr_quota_list[index].current_traffic += data_size;
			printk(KERN_INFO "hook_func_quota_controller: LOCAL_OUT %pI4 (accept) data size: %hu bytes, quota: %lu bytes, current %lu bytes\n", (void*) & (ip_header->daddr),  data_size, daddr_quota_list[index].quota, daddr_quota_list[index].current_traffic);
			if (daddr_quota_list[index].current_traffic > daddr_quota_list[index].quota)
			{
				printk(KERN_INFO "hook_func_quota_controller: LOCAL_OUT %pI4 (accept) traffic exceed quota, add it to block list.", (void*) & (ip_header->daddr));
				add_entry_to_list(ip_header->daddr, 'd');
			}
		}

		return NF_ACCEPT;
	}
	else
	{
		printk(KERN_INFO "hook_func_quota_controller: the hook function is hooked on the wrong place. hooknum: %u saddr: %pI4 daddr: %pI4 (accept) data size: %hu bytes\n", hooknum, (void*) & (ip_header->saddr), (void*) & (ip_header->daddr), data_size);
		return NF_ACCEPT;
	}

}

// This function will see if there is a specific type hook function on a hook
// eg, is there a MONITOR hook on the hook number NF_INET_LOCAL_IN
// return the address of nfho if there is, 0 otherwise.
struct nf_hook_ops *existed_hook(unsigned hooknum,	enum hook_t hooktype)
{
	int i;
	for (i = 0; i < reg_hook_num; i++)
	{
		if (hook_table[i].hooknum == hooknum && hook_table[i].hooktype == hooktype)
			return hook_table[i].pnfho;
	}
	return 0;
}



// This function will register a hook to the hook table maintained by the module.
int register_hook_to_table(unsigned int hooknum, int priority,	enum hook_t hooktype, struct nf_hook_ops *pnfho)
{
	hook_table[reg_hook_num].hooknum = hooknum;
	hook_table[reg_hook_num].priority = priority;
	hook_table[reg_hook_num].hooktype = hooktype;
	hook_table[reg_hook_num].pnfho = pnfho;
	reg_hook_num++;
	return 0;
}

// this function will register a specified hook function to a specified hook num
// we need to specify the priority and type of hook function here
int register_hook(unsigned int (*hookfunc) (void *, struct sk_buff *, const struct nf_hook_state *),	enum hook_t hooktype, unsigned int hooknum, int priority)
{
	int ret;
	// create a new hook ops
	struct nf_hook_ops *pnfho = kmalloc(sizeof(struct nf_hook_ops), GFP_KERNEL);
	// fill out information of this new hook
	pnfho->hook = hookfunc;
	pnfho->hooknum = hooknum;
	pnfho->pf = PF_INET;
	pnfho->priority = priority;
	ret = nf_register_hook(pnfho);
	if (ret != 0)
	{
		printk(KERN_ERR "register_hook: hook register failed. hooktype: %d hooknum: %u priority: %d \n", hooktype, hooknum, priority);
		return -1;
	}
	// register the hook to the hook table
	ret = register_hook_to_table(hooknum, priority, hooktype, pnfho);
	if (ret != 0)
	{
		printk(KERN_ERR "register_hook: hook register to table failed. hooktype: %d hooknum: %u priority: %d \n", hooktype, hooknum, priority);
		return -1;
	}
	printk(KERN_INFO "register_hook: successfully registered a hook function. hooktype: %d hooknum: %u\n priority: %d", hooktype, hooknum, priority);
	return 0;
}

// this function will delete a hook entry from table
int delete_entry_from_hook_table(struct nf_hook_ops *pnfho)
{
	int i;
	for (i = 0; i < reg_hook_num; i++)
	{
		if (hook_table[i].pnfho == pnfho)
		{
			break;
		}
	}
	for (i++; i < reg_hook_num; i++)
	{
		hook_table[i - 1].pnfho = hook_table[i].pnfho;
		hook_table[i - 1].hooknum = hook_table[i].hooknum;
		hook_table[i - 1].priority = hook_table[i].priority;
		hook_table[i - 1].hooktype = hook_table[i].hooktype;
	}

	reg_hook_num--;
	return 0;
}

// this function will unregister a hook function and delete the corresponding entry from the hook_table
int unregister_hook(struct nf_hook_ops *pnfho)
{
	delete_entry_from_hook_table(pnfho);
	nf_unregister_hook(pnfho);
	kfree(pnfho);
	printk(KERN_INFO "unregister_hook: successfully unregistered a hook function.\n");
	return 0;
}

// this function will unregister all hook function in the current hook table
int unregister_all_hook(void)
{
	int i;
	int times = reg_hook_num;
	for (i = 0; i < times; i++)
	{
		unregister_hook(hook_table[0].pnfho);
	}

	return 0;
}

// read callback fuction
// if user is reading from the /proc/htmm, this function should be invoked.
static ssize_t proc_read_callback(struct file *filp, char __user *buf, size_t count, loff_t *offp)
{
	if (count > temp)
	{
		count = temp;
	}
	temp = temp - count;
	copy_to_user(buf, msg, count);
	printk(KERN_INFO "proc_read_callback: user read from /proc/htmm message: %s\n", msg);
	if (count == 0)
	{
		temp = len;
	}
	return count;
}

// get string version of ip address from the user msg
// and convert it to __be32 type
__be32 get_addr_from_msg(char* start)
{

	char ip_str[16];
	strncpy(ip_str, start, 15);
	ip_str[15] = '\0';
	return in_aton(ip_str);
}

// this function will read command from the user space msg
// and take action according to the specific command
int read_cmd_from_msg(char* msg)
{
	int ret;
	enum hook_t hooktype;
	struct nf_hook_ops *pnfho;
	__be32 addr;
	if (!strncmp(msg, "turn on incoming monitor", 24))
	{
		hooktype = MONITOR;
		if (existed_hook(NF_INET_LOCAL_IN, hooktype))
		{
			printk(KERN_INFO "read_cmd_from_msg: incoming monitor is already on: no need to turn on again. user command: %s\n", msg);
		}
		else
		{
			ret = register_hook(&hook_func_moniter, hooktype , NF_INET_LOCAL_IN, PRIORITY_MONITOR);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: register_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: incoming monitor is on. user command: %s\n", msg);
		}
		return 0;
	}
	else if (!strncmp(msg, "turn on outgoing monitor", 24))
	{
		hooktype = MONITOR;
		if (existed_hook(NF_INET_LOCAL_OUT, hooktype))
		{
			printk(KERN_INFO "read_cmd_from_msg: outgoing monitor is already on: no need to turn on again. user command: %s\n", msg);
		}
		else
		{
			ret = register_hook(&hook_func_moniter, hooktype , NF_INET_LOCAL_OUT, PRIORITY_MONITOR);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: register_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: outgoing monitor is on. user command: %s\n", msg);
		}
		return 0;
	}
	else if (!strncmp(msg, "turn on all monitor", 19))
	{
		hooktype = MONITOR;
		// check & register for incoming monitor
		if (existed_hook(NF_INET_LOCAL_IN, hooktype))
		{
			printk(KERN_INFO "read_cmd_from_msg: incoming monitor is already on: no need to turn on again. user command: %s\n", msg);
		}
		else
		{
			ret = register_hook(&hook_func_moniter, hooktype , NF_INET_LOCAL_IN, PRIORITY_MONITOR);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: register_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: incoming monitor is on. user command: %s\n", msg);
		}

		// check & register for outgoing monitor
		if (existed_hook(NF_INET_LOCAL_OUT, hooktype))
		{
			printk(KERN_INFO "read_cmd_from_msg: outgoing monitor is already on: no need to turn on again. user command: %s\n", msg);
		}
		else
		{
			ret = register_hook(&hook_func_moniter, hooktype , NF_INET_LOCAL_OUT, PRIORITY_MONITOR);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: register_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: outgoing monitor is on. user command: %s\n", msg);
		}
		return 0;
	}
	else if (!strncmp(msg, "turn off incoming monitor", 25))
	{
		hooktype = MONITOR;
		if (!(pnfho = existed_hook(NF_INET_LOCAL_IN, hooktype)))
		{
			printk(KERN_INFO "read_cmd_from_msg: incoming monitor is already off: no need to turn off again. user command: %s\n", msg);
		}
		else
		{
			ret = unregister_hook(pnfho);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: unregister_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: incoming monitor is off. user command: %s\n", msg);
		}
		return 0;
	}
	else if (!strncmp(msg, "turn off outgoing monitor", 25))
	{
		hooktype = MONITOR;
		if (!(pnfho = existed_hook(NF_INET_LOCAL_OUT, hooktype)))
		{
			printk(KERN_INFO "read_cmd_from_msg: outgoing monitor is already off: no need to turn off again. user command: %s\n", msg);
		}
		else
		{
			ret = unregister_hook(pnfho);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: unregister_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: outgoing monitor is off. user command: %s\n", msg);
		}
		return 0;
	}
	else if (!strncmp(msg, "turn off all monitor", 20))
	{
		hooktype = MONITOR;
		if (!(pnfho = existed_hook(NF_INET_LOCAL_IN, hooktype)))
		{
			printk(KERN_INFO "read_cmd_from_msg: incoming monitor is already off: no need to turn off again. user command: %s\n", msg);
		}
		else
		{
			ret = unregister_hook(pnfho);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: unregister_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: incoming monitor is off. user command: %s\n", msg);
		}

		if (!(pnfho = existed_hook(NF_INET_LOCAL_OUT, hooktype)))
		{
			printk(KERN_INFO "read_cmd_from_msg: outgoing monitor is already off: no need to turn off again. user command: %s\n", msg);
		}
		else
		{
			ret = unregister_hook(pnfho);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: unregister_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: outgoing monitor is off. user command: %s\n", msg);
		}
		return 0;
	}
	else if (!strncmp(msg, "block incoming", 14))
	{
		hooktype = DROPALL;
		if (existed_hook(NF_INET_LOCAL_IN, hooktype))
		{
			printk(KERN_INFO "read_cmd_from_msg: drop all incoming is already on: no need to turn on again. user command: %s\n", msg);
		}
		else
		{
			ret = register_hook(&hook_func_dropall, hooktype, NF_INET_LOCAL_IN, PRIORITY_DROP);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: register_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: drop all incoming is on. user command: %s\n", msg);
		}
		return 0;
	}
	else if (!strncmp(msg, "block outgoing", 14))
	{
		hooktype = DROPALL;
		if (existed_hook(NF_INET_LOCAL_OUT, hooktype))
		{
			printk(KERN_INFO "read_cmd_from_msg: drop all outgoing is already on: no need to turn on again. user command: %s\n", msg);
		}
		else
		{
			ret = register_hook(&hook_func_dropall, hooktype, NF_INET_LOCAL_OUT, PRIORITY_DROP);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: register_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: drop all outgoing is on. user command: %s\n", msg);
		}
		return 0;
	}
	else if (!strncmp(msg, "block all", 9))
	{
		hooktype = DROPALL;
		if (existed_hook(NF_INET_LOCAL_IN, hooktype))
		{
			printk(KERN_INFO "read_cmd_from_msg: drop all incoming is already on: no need to turn on again. user command: %s\n", msg);
		}
		else
		{
			ret = register_hook(&hook_func_dropall, hooktype, NF_INET_LOCAL_IN, PRIORITY_DROP);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: register_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: drop all incoming is on. user command: %s\n", msg);
		}

		if (existed_hook(NF_INET_LOCAL_OUT, hooktype))
		{
			printk(KERN_INFO "read_cmd_from_msg: drop all outgoing is already on: no need to turn on again. user command: %s\n", msg);
		}
		else
		{
			ret = register_hook(&hook_func_dropall, hooktype, NF_INET_LOCAL_OUT, PRIORITY_DROP);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: register_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: drop all outgoing is on. user command: %s\n", msg);
		}
		return 0;
	}
	else if (!strncmp(msg, "unblock incoming", 16))
	{
		hooktype = DROPALL;
		if (!(pnfho = existed_hook(NF_INET_LOCAL_IN, hooktype)))
		{
			printk(KERN_INFO "read_cmd_from_msg: drop all incoming is already off: no need to turn off again. user command: %s\n", msg);
		}
		else
		{
			ret = unregister_hook(pnfho);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: unregister_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: drop all incoming is off. user command: %s\n", msg);
		}
		return 0;
	}
	else if (!strncmp(msg, "unblock outgoing", 16))
	{
		hooktype = DROPALL;
		if (!(pnfho = existed_hook(NF_INET_LOCAL_OUT, hooktype)))
		{
			printk(KERN_INFO "read_cmd_from_msg: drop all outgoing is already off: no need to turn off again. user command: %s\n", msg);
		}
		else
		{
			ret = unregister_hook(pnfho);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: unregister_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: drop all outgoing is off. user command: %s\n", msg);
		}
		return 0;
	}
	else if (!strncmp(msg, "unblock all", 11))
	{
		hooktype = DROPALL;
		if (!(pnfho = existed_hook(NF_INET_LOCAL_IN, hooktype)))
		{
			printk(KERN_INFO "read_cmd_from_msg: drop all incoming is already off: no need to turn off again. user command: %s\n", msg);
		}
		else
		{
			ret = unregister_hook(pnfho);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: unregister_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: drop all incoming is off. user command: %s\n", msg);
		}

		if (!(pnfho = existed_hook(NF_INET_LOCAL_OUT, hooktype)))
		{
			printk(KERN_INFO "read_cmd_from_msg: drop all outgoing is already off: no need to turn off again. user command: %s\n", msg);
		}
		else
		{
			ret = unregister_hook(pnfho);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: unregister_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: drop all outgoing is off. user command: %s\n", msg);
		}
		return 0;
	}
	else if (!strncmp(msg, "block saddr", 11))
	{
		hooktype = DROPBLOCKED;
		// get string version of ip address from the user msg
		// and convert it to __be32 type
		addr = get_addr_from_msg(msg + 12);
		// make sure drop blocked incoming is on
		if (!existed_hook(NF_INET_LOCAL_IN, hooktype))
		{
			ret = register_hook(&hook_func_dropblocked, hooktype, NF_INET_LOCAL_IN, PRIORITY_DROP);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: register_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: drop blocked incoming is on. user command: %s\n", msg);
		}
		// add the addr to saddr_block_list
		ret = add_entry_to_list(addr, 's');
		if (ret != 0)
		{
			printk(KERN_ERR "read_cmd_from_msg: add_entry_to_list failed. user command: %s\n", msg);
			return -1;
		}
		printk(KERN_INFO "read_cmd_from_msg: added ip: %pI4 to saddr_block_list. user command: %s\n", (void*) & (addr), msg);
		return 0;
	}
	else if (!strncmp(msg, "block daddr", 11))
	{
		hooktype = DROPBLOCKED;
		// get string version of ip address from the user msg
		// and convert it to __be32 type
		addr = get_addr_from_msg(msg + 12);

		// make sure drop blocked outgoing is on
		if (!existed_hook(NF_INET_LOCAL_OUT, hooktype))
		{
			ret = register_hook(&hook_func_dropblocked, hooktype, NF_INET_LOCAL_OUT, PRIORITY_DROP);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: register_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: drop blocked outgoing is on. user command: %s\n", msg);
		}

		// add the addr to daddr_block_list
		ret = add_entry_to_list(addr, 'd');
		if (ret != 0)
		{
			printk(KERN_ERR "read_cmd_from_msg: add_entry_to_list failed. user command: %s\n", msg);
			return -1;
		}
		printk(KERN_INFO "read_cmd_from_msg: added ip: %pI4 to daddr_block_list. user command: %s\n", (void*) & (addr), msg);
		return 0;
	}
	else if (!strncmp(msg, "unblock saddr", 13))
	{
		hooktype = DROPBLOCKED;
		// get string version of ip address from the user msg
		// and convert it to __be32 type
		addr = get_addr_from_msg(msg + 14);

		// delete the addr from saddr_block_list
		ret = delete_entry_from_list(addr, 's');
		if (ret != 0)
		{
			printk(KERN_ERR "read_cmd_from_msg: delete_entry_from_list failed. user command: %s\n", msg);
			return -1;
		}
		printk(KERN_INFO "read_cmd_from_msg: deleted ip: %pI4 from saddr_block_list. user command: %s\n", (void*) & (addr), msg);

		// if the list is empty, make sure drop blocked incoming is off.
		if (saddr_block_num == 0)
		{
			if (pnfho = existed_hook(NF_INET_LOCAL_IN, hooktype))
			{
				ret = unregister_hook(pnfho);
				if (ret != 0)
				{
					printk(KERN_ERR "read_cmd_from_msg: unregister_hook failed. user command: %s\n", msg);
					return -1;
				}
				printk(KERN_INFO "read_cmd_from_msg: drop blocked incoming is off. user command: %s\n", msg);
			}
		}

		return 0;
	}
	else if (!strncmp(msg, "unblock daddr", 13))
	{
		hooktype = DROPBLOCKED;
		// get string version of ip address from the user msg
		// and convert it to __be32 type
		addr = get_addr_from_msg(msg + 14);

		// delete the addr from saddr_block_list
		ret = delete_entry_from_list(addr, 'd');
		if (ret != 0)
		{
			printk(KERN_ERR "read_cmd_from_msg: delete_entry_from_list failed. user command: %s\n", msg);
			return -1;
		}
		printk(KERN_INFO "read_cmd_from_msg: deleted ip: %pI4 from daddr_block_list. user command: %s\n", (void*) & (addr), msg);

		// if the list is empty, make sure drop blocked outgoing is off.
		if (daddr_block_num == 0)
		{
			if (pnfho = existed_hook(NF_INET_LOCAL_OUT, hooktype))
			{
				ret = unregister_hook(pnfho);
				if (ret != 0)
				{
					printk(KERN_ERR "read_cmd_from_msg: unregister_hook failed. user command: %s\n", msg);
					return -1;
				}
				printk(KERN_INFO "read_cmd_from_msg: drop blocked outgoing is off. user command: %s\n", msg);
			}
		}

		return 0;
	}
	else if (!strncmp(msg, "clear saddr block list", 22))
	{
		hooktype = DROPBLOCKED;
		// clear saddr list by set saddr_block_num=0
		saddr_block_num = 0;
		// since the saddr list is empty, make sure drop blocked incoming is off.
		if (saddr_block_num == 0)
		{
			if (pnfho = existed_hook(NF_INET_LOCAL_IN, hooktype))
			{
				ret = unregister_hook(pnfho);
				if (ret != 0)
				{
					printk(KERN_ERR "read_cmd_from_msg: unregister_hook failed. user command: %s\n", msg);
					return -1;
				}
				printk(KERN_INFO "read_cmd_from_msg: drop blocked incoming is off. user command: %s\n", msg);
			}
		}
		printk(KERN_INFO "read_cmd_from_msg: saddr list is empty and drop blocked incoming is off. user command: %s\n", msg);
		return 0;
	}
	else if (!strncmp(msg, "clear daddr block list", 22))
	{
		hooktype = DROPBLOCKED;
		// clear saddr list by set saddr_block_num=0
		daddr_block_num = 0;
		// since the saddr list is empty, make sure drop blocked outgoing is off.
		if (daddr_block_num == 0)
		{
			if (pnfho = existed_hook(NF_INET_LOCAL_OUT, hooktype))
			{
				ret = unregister_hook(pnfho);
				if (ret != 0)
				{
					printk(KERN_ERR "read_cmd_from_msg: unregister_hook failed. user command: %s\n", msg);
					return -1;
				}
				printk(KERN_INFO "read_cmd_from_msg: drop blocked outgoing is off. user command: %s\n", msg);
			}
		}
		printk(KERN_INFO "read_cmd_from_msg: saddr list is empty and drop blocked outgoing is off. user command: %s\n", msg);
		return 0;
	}
	else if (!strncmp(msg, "view saddr block list", 21))
	{
		int i;
		printk(KERN_INFO "read_cmd_from_msg: view saddr block list as follows: user command: %s\n", msg);
		printk(KERN_INFO "read_cmd_from_msg: saddr block list has %d entries.", saddr_block_num);
		for (i = 0; i < saddr_block_num; i++)
		{
			printk(KERN_INFO "read_cmd_from_msg: saddr entry[%d]: %pI4\n", i, (void*)&saddr_block_list[i]);
		}
		return 0;
	}
	else if (!strncmp(msg, "view daddr block list", 21))
	{
		int i;
		printk(KERN_INFO "read_cmd_from_msg: view daddr block list as follows: user command: %s\n", msg);
		printk(KERN_INFO "read_cmd_from_msg: daddr block list has %d entries.", daddr_block_num);
		for (i = 0; i < daddr_block_num; i++)
		{
			printk(KERN_INFO "read_cmd_from_msg: daddr entry[%d]: %pI4\n", i, (void*)&daddr_block_list[i]);
		}
		return 0;
	}
	else if (!strncmp(msg, "set saddr", 9))
	{
		int i;
		int t;
		unsigned long quota;
		char addr_str[50];
		char quota_str[150];

		// parse cmd
		int count = 10;
		while (*(msg + count) != 'q') count++;

		for (i = 10; i < count - 1; i++)
		{
			addr_str[i - 10] = msg[i];
		}
		addr_str[i - 10] = '\0';

		count = count + 6;
		t = count;
		while (*(msg + count) != '\0' && *(msg + count) != '\n' && *(msg + count) != ' ')
		{
			quota_str[count - t] = msg[count];
			count++;
		}
		quota_str[count - t] = '\0';

		//printk(KERN_INFO "read_cmd_from_msg: parse: addr %s quota %s", addr_str, quota_str);


		// get string version of ip address from the user msg
		// and convert it to __be32 type
		addr = get_addr_from_msg(addr_str);
		quota = simple_strtoul(quota_str, NULL, 10);


		hooktype = QUOTA;
		// make sure quota controller for incoming traffic is on
		if (!existed_hook(NF_INET_LOCAL_IN, hooktype))
		{
			ret = register_hook(&hook_func_quota_controller, hooktype, NF_INET_LOCAL_IN, PRIORITY_QUOTA);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: register_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: quota controller for incoming traffic is on. user command: %s\n", msg);
		}
		// add the addr to saddr_quota_list
		ret = add_entry_to_list_quota(addr, quota, 's');

		if (ret != 0)
		{
			printk(KERN_ERR "read_cmd_from_msg: add_entry_to_list_quota failed. user command: %s\n", msg);
			return -1;
		}
		printk(KERN_INFO "read_cmd_from_msg: added ip: %pI4 quota: %lu to saddr_quota_list. user command: %s\n", (void*) & (addr), quota, msg);

		hooktype = DROPBLOCKED;
		// make sure drop_blocked hook function for incoming traffic is also on
		if (!existed_hook(NF_INET_LOCAL_IN, hooktype))
		{
			ret = register_hook(&hook_func_dropblocked, hooktype, NF_INET_LOCAL_IN, PRIORITY_DROP);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: register_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: drop blocked addr for incoming traffic is on. user command: %s\n", msg);
		}

		return 0;
	}
	else if (!strncmp(msg, "set daddr", 9))
	{
		int i;
		int t;
		unsigned long quota;
		char addr_str[50];
		char quota_str[150];

		// parse cmd
		int count = 10;
		while (*(msg + count) != 'q') count++;

		for (i = 10; i < count - 1; i++)
		{
			addr_str[i - 10] = msg[i];
		}
		addr_str[i - 10] = '\0';

		count = count + 6;
		t = count;
		while (*(msg + count) != '\0' && *(msg + count) != '\n' && *(msg + count) != ' ')
		{
			quota_str[count - t] = msg[count];
			count++;
		}
		quota_str[count - t] = '\0';

		//printk(KERN_INFO "read_cmd_from_msg: parse: addr %s quota %s", addr_str, quota_str);


		// get string version of ip address from the user msg
		// and convert it to __be32 type
		addr = get_addr_from_msg(addr_str);
		quota = simple_strtoul(quota_str, NULL, 10);


		hooktype = QUOTA;
		// make sure quota controller for outgoing traffic is on
		if (!existed_hook(NF_INET_LOCAL_OUT, hooktype))
		{
			ret = register_hook(&hook_func_quota_controller, hooktype, NF_INET_LOCAL_OUT, PRIORITY_QUOTA);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: register_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: quota controller for outgoing traffic is on. user command: %s\n", msg);
		}
		// add the addr to daddr_quota_list
		ret = add_entry_to_list_quota(addr, quota, 'd');

		if (ret != 0)
		{
			printk(KERN_ERR "read_cmd_from_msg: add_entry_to_list_quota failed. user command: %s\n", msg);
			return -1;
		}
		printk(KERN_INFO "read_cmd_from_msg: added ip: %pI4 quota: %lu to daddr_quota_list. user command: %s\n", (void*) & (addr), quota, msg);

		hooktype = DROPBLOCKED;
		// make sure drop_blocked hook function for outgoing traffic is also on
		if (!existed_hook(NF_INET_LOCAL_OUT, hooktype))
		{
			ret = register_hook(&hook_func_dropblocked, hooktype, NF_INET_LOCAL_OUT, PRIORITY_DROP);
			if (ret != 0)
			{
				printk(KERN_ERR "read_cmd_from_msg: register_hook failed. user command: %s\n", msg);
				return -1;
			}
			printk(KERN_INFO "read_cmd_from_msg: drop blocked addr for outgoing traffic is on. user command: %s\n", msg);
		}

		return 0;
	}
	else if (!strncmp(msg, "unset quota saddr", 17))
	{
		hooktype = QUOTA;
		// get string version of ip address from the user msg
		// and convert it to __be32 type
		addr = get_addr_from_msg(msg + 18);

		// delete the addr from saddr_quota_list
		ret = delete_entry_from_list_quota(addr, 's');
		if (ret != 0)
		{
			printk(KERN_ERR "read_cmd_from_msg: delete_entry_from_list_quota failed. user command: %s\n", msg);
			return -1;
		}
		printk(KERN_INFO "read_cmd_from_msg: deleted ip: %pI4 from saddr_quota_list. user command: %s\n", (void*) & (addr), msg);

		// if the list is empty, make sure quota controller for incoming is off.
		if (saddr_quota_num == 0)
		{
			if (pnfho = existed_hook(NF_INET_LOCAL_IN, hooktype))
			{
				ret = unregister_hook(pnfho);
				if (ret != 0)
				{
					printk(KERN_ERR "read_cmd_from_msg: unregister_hook failed. user command: %s\n", msg);
					return -1;
				}
				printk(KERN_INFO "read_cmd_from_msg: quota controller for incoming is off. user command: %s\n", msg);
			}
		}

		return 0;
	}
	else if (!strncmp(msg, "unset quota daddr", 17))
	{
		hooktype = QUOTA;
		// get string version of ip address from the user msg
		// and convert it to __be32 type
		addr = get_addr_from_msg(msg + 18);

		// delete the addr from daddr_quota_list
		ret = delete_entry_from_list_quota(addr, 'd');
		if (ret != 0)
		{
			printk(KERN_ERR "read_cmd_from_msg: delete_entry_from_list_quota failed. user command: %s\n", msg);
			return -1;
		}
		printk(KERN_INFO "read_cmd_from_msg: deleted ip: %pI4 from daddr_quota_list. user command: %s\n", (void*) & (addr), msg);

		// if the list is empty, make sure quota controller for incoming is off.
		if (daddr_quota_num == 0)
		{
			if (pnfho = existed_hook(NF_INET_LOCAL_OUT, hooktype))
			{
				ret = unregister_hook(pnfho);
				if (ret != 0)
				{
					printk(KERN_ERR "read_cmd_from_msg: unregister_hook failed. user command: %s\n", msg);
					return -1;
				}
				printk(KERN_INFO "read_cmd_from_msg: quota controller for outgoing is off. user command: %s\n", msg);
			}
		}

		return 0;
	}
	else if (!strncmp(msg, "clear saddr quota list", 22))
	{
		hooktype = QUOTA;
		// clear saddr list by set saddr_block_num=0
		saddr_quota_num = 0;
		// since the saddr list is empty, make sure quota controller for incoming is off.
		if (saddr_quota_num == 0)
		{
			if (pnfho = existed_hook(NF_INET_LOCAL_IN, hooktype))
			{
				ret = unregister_hook(pnfho);
				if (ret != 0)
				{
					printk(KERN_ERR "read_cmd_from_msg: unregister_hook failed. user command: %s\n", msg);
					return -1;
				}
				printk(KERN_INFO "read_cmd_from_msg: quota controller for incoming is off. user command: %s\n", msg);
			}
		}
		printk(KERN_INFO "read_cmd_from_msg: saddr quota list is cleared. user command: %s\n", msg);
		return 0;
	}
	else if (!strncmp(msg, "clear daddr quota list", 22))
	{
		hooktype = QUOTA;
		// clear saddr list by set saddr_block_num=0
		daddr_quota_num = 0;
		// since the saddr list is empty, make sure quota controller for outgoing is off.
		if (daddr_quota_num == 0)
		{
			if (pnfho = existed_hook(NF_INET_LOCAL_OUT, hooktype))
			{
				ret = unregister_hook(pnfho);
				if (ret != 0)
				{
					printk(KERN_ERR "read_cmd_from_msg: unregister_hook failed. user command: %s\n", msg);
					return -1;
				}
				printk(KERN_INFO "read_cmd_from_msg: quota controller for outgoing is off. user command: %s\n", msg);
			}
		}
		printk(KERN_INFO "read_cmd_from_msg: daddr quota list is cleared. user command: %s\n", msg);
		return 0;
	}
	else if (!strncmp(msg, "view quota list saddr", 21))
	{
		int i;
		printk(KERN_INFO "read_cmd_from_msg: view saddr quota list as follows: user command: %s\n", msg);
		printk(KERN_INFO "read_cmd_from_msg: saddr quota list has %d entries.", saddr_quota_num);
		for (i = 0; i < saddr_quota_num; i++)
		{
			printk(KERN_INFO "read_cmd_from_msg: saddr entry[%d]: addr: %pI4 quota: %lu current: %lu \n", i, (void*) & (saddr_quota_list[i].addr), saddr_quota_list[i].quota, saddr_quota_list[i].current_traffic);
		}
		return 0;
	}
	else if (!strncmp(msg, "view quota list daddr", 21))
	{
		int i;
		printk(KERN_INFO "read_cmd_from_msg: view daddr quota list as follows: user command: %s\n", msg);
		printk(KERN_INFO "read_cmd_from_msg: daddr quota list has %d entries.", daddr_quota_num);
		for (i = 0; i < daddr_quota_num; i++)
		{
			printk(KERN_INFO "read_cmd_from_msg: daddr entry[%d]: addr: %pI4 quota: %lu current: %lu \n", i, (void*) & (daddr_quota_list[i].addr), daddr_quota_list[i].quota, daddr_quota_list[i].current_traffic);
		}
		return 0;
	}
	else if (!strncmp(msg, "view hook table", 15))
	{
		int i;
		printk(KERN_INFO "read_cmd_from_msg: view hook table as follows: user command: %s\n", msg);
		printk(KERN_INFO "read_cmd_from_msg: hook table has %d entries.", reg_hook_num);
		for (i = 0; i < reg_hook_num; i++)
		{
			printk(KERN_INFO "read_cmd_from_msg: hook table entry[%d]: hooknum: %u hooktype: %d priority: %d \n", i, hook_table[i].hooknum, hook_table[i].hooktype, hook_table[i].priority);
		}
		return 0;
	}
	else
	{
		printk(KERN_WARNING "read_cmd_from_msg: undefined command. user command: %s\n", msg);
		return 0;
	}
}

// write callback fuction
// if user is writing to the /proc/htmm, this function should be invoked.
static ssize_t proc_write_callback(struct file *filp, const char __user *buf, size_t count, loff_t *offp)
{
	int ret;
	if (msg == NULL || count > 100)
	{
		printk(KERN_INFO "proc_write_callback: either msg is NULL or count >100\n");
	}

	copy_from_user(msg, buf, count);
	printk(KERN_INFO "proc_write_callback: user write to /proc/htmm message: %s\n", msg);

	ret = read_cmd_from_msg(msg);
	if (ret != 0)
	{
		printk(KERN_ERR "proc_write_callback: read_cmd_from_msg failed. \n");
	}

	len = count;
	temp = len;
	return count;
}

// proc_create config: register callback function for /proc/htmm
static const struct file_operations proc_fops = {
	.owner = THIS_MODULE,
	.read = proc_read_callback,
	.write = proc_write_callback,
};

// create new proc htmm, malloc 100*char for msg
int create_new_proc_entry(void)
{
	proc_file_entry = proc_create(MODULE_PROC_NAME, 0666, NULL, &proc_fops);
	if (proc_file_entry == NULL)
	{
		printk(KERN_ERR "create_new_proc_entry: proc_create for htmm fail\n");
		return -1;
	}
	else
	{
		printk(KERN_INFO "create_new_proc_entry: successfully created /proc/htmm\n");
	}
	msg = kmalloc(MSG_SIZE * sizeof(char), GFP_KERNEL);
	if (msg == NULL)
	{
		printk(KERN_ERR "create_new_proc_entry: kmalloc for msg fail\n");
		return -1;
	}
	memset(msg, 0, MSG_SIZE * sizeof(char));
	return 0;
}

// the module should start from here
static int  __init init_monitor(void)
{
	int ret;

	printk(KERN_INFO "init_monitor: Network Traffic Monitor Module has been successfully loaded into kernel.\n");
	// create proc entry
	ret = create_new_proc_entry();
	if (ret != 0)
	{
		printk(KERN_ERR "init_monitor: create_new_proc_entry for htmm fail\n");
		return -1;
	}
	// open log files
	/*fd_monitor_log = open(MONITOR_LOG_PATH, O_WRONLY | OCREAT);
	if (fd_monitor_log == -1)
	{
		printk(KERN_ERR "init_monitor: open monitor log fail.\n");
	}

	fd_filter_log = open(FILTER_LOG_PATH, O_WRONLY | OCREAT);
	if (fd_filter_log == -1)
	{
		printk(KERN_ERR "init_monitor: open monitor log fail.\n");
	}
	// replace stdout using fd_monitor_log
	ret=dup2(fd_monitor_log,2);
	if (ret ==-1)
	{
		printk(KERN_ERR "init_monitor: dup2(fd_monitor_log,2) fail.\n");
		return -1;
	}
	printf("now I can print something.\n");*/
	return 0;
}

// the module should end here
static void  __exit cleanup_monitor(void)
{
	remove_proc_entry(MODULE_PROC_NAME, NULL);
	unregister_all_hook();
	printk(KERN_INFO "cleanup_monitor: Network Traffic Monitor Module has been successfully removed from kernel.\n");
}




module_init(init_monitor);
module_exit(cleanup_monitor);

MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESC);
MODULE_LICENSE(LICENSE);