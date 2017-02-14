# Network Traffic Monitor

OS Final Project - Dec.2016

## Brief Description

note: this module is built and tested on Linux kernel 4.4.0

In this project, I built a kernel module that monitors network traffic.
when you install this module, the module will be quietly running in the kernel and waiting for your command.
If you need the module do something neat for user, you need to write some command into the proc file "/proc/htmm".
Something like this:

```
echo "turn on incoming monitor">/proc/htmm
```


## How to build & run

make sure Makefile and netMonitor.c is in the same directory, open that directory and enter "make" in the terminal.

use following commands to install and remove module:

```
sudo insmod netMonitor.ko
```

```
sudo rmmod netMonitor
```

use following commands to give a instruction to module:


```
echo "turn on incoming monitor">/proc/htmm
```

since the module will print all the logs to kernel ring buffer (including packet information), so to see if your command works, use following command:

```
dmesg
```

## How to use test script

I wrote a test script to test the basic functionalities of my module and also included some sophisticated scenarios that the module may encounter. To run the test, you can simply enter

```
sh test.sh
```

in your terminal, and make sure the test script is in the same directory of the netMonitor.ko

the test.sh will generate two logs during the test, "ringbufferlog.log" is all the new information in the kernel ring buffer during the test and "testlog.log" stores the test results for the most recent test.

you may also add your customized test case in the end of the script and see what is going on in the "ringbufferlog.log" or just type command in the terminal and see what is going on using dmesg.

Good luck!


## User Commands:

"turn on incoming monitor": this command will enable the module to monitor incoming network traffic. 
And log them into /var/log/netTraffic, the log including the traffic category (in), a specific source address, and a timestamp.

"turn on outgoing monitor": this command will enable the module to monitor outgoing network traffic.
And log them into /var/log/netTraffic, the log including the traffic category (out), a specific destination address, and a timestamp.

"turn on all monitor": this command will enable the module to monitor both incoming and outgoing network traffic.
And log them into /var/log/netTraffic, the log including the traffic category (in or out), a specific source or destination address, and a timestamp.

"turn off incoming monitor": ~

"turn off outgoing monitor": ~

"turn off all monitor": ~

"block incoming": this command will enable the module to block all incoming network traffic. 
And log them into /var/log/netBlocked, the log including the traffic category (in), a specific source address, and a timestamp.


"block outgoing": this command will enable the module to block all outgoing network traffic.
And log them into /var/log/netBlocked, the log including the traffic category (out), a specific destination address, and a timestamp.


"block all": this command will enable the module to block all incoming and outgoing network traffic.
And log them into /var/log/netBlocked, the log including the traffic category (in or out), a specific source or destination address, and a timestamp.

"unblock incoming": ~

"unblock outgoing": ~

"unblock all": ~

"block saddr #IP": this command will enable the module to block a specific source IP address, the module will maintain a list "saddr block list" that specify which source address should be blocked. Thus this command basically add an entry to this list.

"block daddr #IP": this command will enable the module to block a specific daddr IP address, the module will maintain a list "daddr block list" that specify which destination address should be blocked. Thus this command basically add an entry to this list.

"unblock saddr #IP": this command will delete an entry from the "saddr block list"

"unblock daddr #IP": this command will delete an entry from the "daddr block list"

"clear saddr block list": delete all entries from the "saddr block list"

"clear daddr block list": delete all entries from the "daddr block list"

"view saddr block list": print information about evey entry in saddr_block_list

"view daddr block list": print information about evey entry in daddr_block_list

"set saddr #IP quota #BYTE": set a quota for #IP, if incoming network traffic from #IP exceed #BYTE, this #IP will be added to "saddr quota list"

"set daddr #IP quota #BYTE": set a quota for #IP, if outgoing network traffic to #IP exceed #BYTE, this #IP will be added to "daddr quota list"
 
"clear saddr quota list": unset every saddr on the list.

"clear daddr quota list": unset every daddr on the list.

"view saddr quota list": print information about evey entry in saddr_quota_list

"view daddr quota list": print information about evey entry in daddr_quota_list

"view hook table": print information about every hooks on the hook table
