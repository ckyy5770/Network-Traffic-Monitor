#!/bin/sh
# remove old test logs
sudo rm ./testlog.log
sudo rm ./ringbufferlog.log
sudo rm ./trash.log
pass_number=0
total_number=22


# clear ring buffer
sudo dmesg -c >>./trash.log
echo "====================basic tests====================="
echo "====================basic tests=====================" >>./testlog.log


# test ---- install module
# log
echo "[test] install modeule: run"
echo "[test] install modeule: run" >>./testlog.log
# cmd
sudo insmod netMonitor.ko
# check result
count=$(dmesg|grep "Network Traffic Monitor Module has been successfully loaded into kernel"|wc -l)
if [ ${count} -eq 1 ]; then
	test_install=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] install module: pass"
	echo "[test] install module: pass" >>./testlog.log
else
	echo "[test] install module: fail"
	echo "[test] install module: fail" >>./testlog.log
fi
echo "----------------------------------------------------"

# test ---- turn on incoming monitor

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] turn on incoming monitor: run"
echo "[test] turn on incoming monitor: run" >>./testlog.log
# cmd
echo "turn on incoming monitor" >>/proc/htmm
ping 8.8.8.8 -c 5 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: incoming monitor is on."|wc -l)
count2=$(dmesg|grep "hook_func_moniter: LOCAL_IN 8.8.8.8 (accept)"|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 5 ]; then
	test_turn_on_in_monitor=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] turn on incoming monitor: pass"
	echo "[test] turn on incoming monitor: pass" >>./testlog.log
else
	echo "[test] turn on incoming monitor: fail"
	echo "[test] turn on incoming monitor: fail" >>./testlog.log
fi
echo "----------------------------------------------------"

# test ---- turn off incoming monitor

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] turn off incoming monitor: run"
echo "[test] turn off incoming monitor: run" >>./testlog.log
# cmd
echo "turn off incoming monitor" >>/proc/htmm
ping 8.8.8.8 -c 5 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: incoming monitor is off."|wc -l)
count2=$(dmesg|grep "hook_func_moniter: LOCAL_IN 8.8.8.8 (accept)"|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 0 ]; then
	test_turn_off_in_monitor=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] turn off incoming monitor: pass"
	echo "[test] turn off incoming monitor: pass" >>./testlog.log
else
	echo "[test] turn off incoming monitor: fail"
	echo "[test] turn off incoming monitor: fail" >>./testlog.log
fi
echo "----------------------------------------------------"

# test ---- turn on outgoing monitor

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] turn on outgoing monitor: run"
echo "[test] turn on outgoing monitor: run" >>./testlog.log
# cmd
echo "turn on outgoing monitor" >>/proc/htmm
ping 8.8.8.8 -c 5 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: outgoing monitor is on."|wc -l)
count2=$(dmesg|grep "hook_func_moniter: LOCAL_OUT 8.8.8.8 (accept)"|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 5 ]; then
	test_turn_on_out_monitor=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] turn on outgoing monitor: pass"
	echo "[test] turn on outgoing monitor: pass" >>./testlog.log
else
	echo "[test] turn on outgoing monitor: fail"
	echo "[test] turn on outgoing monitor: fail" >>./testlog.log
fi
echo "----------------------------------------------------"


# test ---- turn off outgoing monitor

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] turn off outgoing monitor: run"
echo "[test] turn off outgoing monitor: run" >>./testlog.log
# cmd
echo "turn off outgoing monitor" >>/proc/htmm
ping 8.8.8.8 -c 5 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: outgoing monitor is off."|wc -l)
count2=$(dmesg|grep "hook_func_moniter: LOCAL_OUT 8.8.8.8 (accept)"|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 0 ]; then
	test_turn_on_out_monitor=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] turn off outgoing monitor: pass"
	echo "[test] turn off outgoing monitor: pass" >>./testlog.log
else
	echo "[test] turn off outgoing monitor: fail"
	echo "[test] turn off outgoing monitor: fail" >>./testlog.log
fi
echo "----------------------------------------------------"

# test ---- turn on all monitor

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] turn on all monitor: run"
echo "[test] turn on all monitor: run" >>./testlog.log
# cmd
echo "turn on all monitor" >>/proc/htmm
ping 8.8.8.8 -c 5 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: incoming monitor is on."|wc -l)
count2=$(dmesg|grep "read_cmd_from_msg: outgoing monitor is on."|wc -l)
count3=$(dmesg|grep "hook_func_moniter: LOCAL_IN 8.8.8.8 (accept)"|wc -l)
count4=$(dmesg|grep "hook_func_moniter: LOCAL_OUT 8.8.8.8 (accept)"|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 1 ] && [ ${count3} -eq 5 ] && [ ${count4} -eq 5 ]; then
	test_turn_on_all_monitor=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] turn on all monitor: pass"
	echo "[test] turn on all monitor: pass" >>./testlog.log
else
	echo "[test] turn on all monitor: fail"
	echo "[test] turn on all monitor: fail" >>./testlog.log
fi
echo "----------------------------------------------------"


# test ---- turn off all monitor

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] turn off all monitor: run"
echo "[test] turn off all monitor: run" >>./testlog.log
# cmd
echo "turn off all monitor" >>/proc/htmm
ping 8.8.8.8 -c 5 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: incoming monitor is off."|wc -l)
count2=$(dmesg|grep "read_cmd_from_msg: outgoing monitor is off."|wc -l)
count3=$(dmesg|grep "hook_func_moniter: LOCAL_IN 8.8.8.8 (accept)"|wc -l)
count4=$(dmesg|grep "hook_func_moniter: LOCAL_OUT 8.8.8.8 (accept)"|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 1 ] && [ ${count3} -eq 0 ] && [ ${count4} -eq 0 ]; then
	test_turn_off_all_monitor=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] turn off all monitor: pass"
	echo "[test] turn off all monitor: pass" >>./testlog.log
else
	echo "[test] turn off all monitor: fail"
	echo "[test] turn off all monitor: fail" >>./testlog.log
fi
echo "----------------------------------------------------"

# test ---- block incoming

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] block all incoming: run"
echo "[test] block all incoming: run" >>./testlog.log
# cmd
echo "block incoming" >>/proc/htmm
ping 8.8.8.8 -c 5 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: drop all incoming is on."|wc -l)
count2=$(dmesg|grep "hook_func_dropall: LOCAL_IN 8.8.8.8 (drop) "|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 5 ]; then
	test_block_incoming=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] block all incoming: pass"
	echo "[test] block all incoming: pass" >>./testlog.log
else
	echo "[test] block all incoming: fail"
	echo "[test] block all incoming: fail" >>./testlog.log
fi
echo "----------------------------------------------------"

# test ---- unblock incoming

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] unblock all incoming: run"
echo "[test] unblock all incoming: run" >>./testlog.log
# cmd
echo "unblock incoming" >>/proc/htmm
ping 8.8.8.8 -c 5 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: drop all incoming is off."|wc -l)
count2=$(dmesg|grep "hook_func_dropall: LOCAL_IN 8.8.8.8 (drop) "|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 0 ]; then
	test_unblock_incoming=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] unblock all incoming: pass"
	echo "[test] unblock all incoming: pass" >>./testlog.log
else
	echo "[test] unblock all incoming: fail"
	echo "[test] unblock all incoming: fail" >>./testlog.log
fi
echo "----------------------------------------------------"

# test ---- block outgoing

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] block all outgoing: run"
echo "[test] block all outgoing: run" >>./testlog.log
# cmd
echo "block outgoing" >>/proc/htmm
ping 8.8.8.8 -c 5 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: drop all outgoing is on."|wc -l)
count2=$(dmesg|grep "hook_func_dropall: LOCAL_OUT 8.8.8.8 (drop) "|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 5 ]; then
	test_block_outgoing=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] block all outgoing: pass"
	echo "[test] block all outgoing: pass" >>./testlog.log
else
	echo "[test] block all outgoing: fail"
	echo "[test] block all outgoing: fail" >>./testlog.log
fi
echo "----------------------------------------------------"

# test ---- unblock outgoing

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] unblock all outgoing: run"
echo "[test] unblock all outgoing: run" >>./testlog.log
# cmd
echo "unblock outgoing" >>/proc/htmm
ping 8.8.8.8 -c 5 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: drop all outgoing is off."|wc -l)
count2=$(dmesg|grep "hook_func_dropall: LOCAL_OUT 8.8.8.8 (drop) "|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 0 ]; then
	test_block_outgoing=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] unblock all outgoing: pass"
	echo "[test] unblock all outgoing: pass" >>./testlog.log
else
	echo "[test] unblock all outgoing: fail"
	echo "[test] unblock all outgoing: fail" >>./testlog.log
fi
echo "----------------------------------------------------"

# test ---- block all

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] block all: run"
echo "[test] block all: run" >>./testlog.log
# cmd
echo "block all" >>/proc/htmm
ping 8.8.8.8 -c 5 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: drop all incoming is on."|wc -l)
count2=$(dmesg|grep "read_cmd_from_msg: drop all outgoing is on."|wc -l)
#count3=$(dmesg|grep "hook_func_dropall: LOCAL_IN 8.8.8.8 (drop) "|wc -l)
count4=$(dmesg|grep "hook_func_dropall: LOCAL_OUT 8.8.8.8 (drop) "|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 1 ] && [ ${count4} -eq 5 ]; then
	test_block_all=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] block all: pass"
	echo "[test] block all: pass" >>./testlog.log
else
	echo "[test] block all: fail"
	echo "[test] block all: fail" >>./testlog.log
fi
echo "----------------------------------------------------"

# test ---- unblock all

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] unblock all: run"
echo "[test] unblock all: run" >>./testlog.log
# cmd
echo "unblock all" >>/proc/htmm
ping 8.8.8.8 -c 5 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: drop all incoming is off."|wc -l)
count2=$(dmesg|grep "read_cmd_from_msg: drop all outgoing is off."|wc -l)
count3=$(dmesg|grep "hook_func_dropall: LOCAL_IN 8.8.8.8 (drop) "|wc -l)
count4=$(dmesg|grep "hook_func_dropall: LOCAL_OUT 8.8.8.8 (drop) "|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 1 ] && [ ${count4} -eq 0 ] && [ ${count4} -eq 0 ]; then
	test_unblock_all=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] block all: pass"
	echo "[test] block all: pass" >>./testlog.log
else
	echo "[test] block all: fail"
	echo "[test] block all: fail" >>./testlog.log
fi
echo "----------------------------------------------------"


# test ---- block saddr #IP

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] block saddr #IP: run"
echo "[test] block saddr #IP: run" >>./testlog.log
# cmd
echo "block saddr 8.8.8.8" >>/proc/htmm
ping 8.8.8.8 -c 5 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: drop blocked incoming is on."|wc -l)
count2=$(dmesg|grep "read_cmd_from_msg: added ip: 8.8.8.8 to saddr_block_list."|wc -l)
count3=$(dmesg|grep "hook_func_dropblocked: LOCAL_IN 8.8.8.8 (drop) "|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 1 ] && [ ${count3} -eq 5 ]; then
	test_block_saddr_IP=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] block saddr #IP: pass"
	echo "[test] block saddr #IP: pass" >>./testlog.log
else
	echo "[test] block saddr #IP: fail"
	echo "[test] block saddr #IP: fail" >>./testlog.log
fi
echo "----------------------------------------------------"

# test ---- unblock saddr #IP

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] unblock saddr #IP: run"
echo "[test] unblock saddr #IP: run" >>./testlog.log
# cmd
echo "unblock saddr 8.8.8.8" >>/proc/htmm
ping 8.8.8.8 -c 5 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: drop blocked incoming is off."|wc -l)
count2=$(dmesg|grep "read_cmd_from_msg: deleted ip: 8.8.8.8 from saddr_block_list."|wc -l)
count3=$(dmesg|grep "hook_func_dropblocked: LOCAL_IN 8.8.8.8 (drop) "|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 1 ] && [ ${count3} -eq 0 ]; then
	test_unblock_saddr_IP=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] unblock saddr #IP: pass"
	echo "[test] unblock saddr #IP: pass" >>./testlog.log
else
	echo "[test] unblock saddr #IP: fail"
	echo "[test] unblock saddr #IP: fail" >>./testlog.log
fi
echo "----------------------------------------------------"

# test ---- block daddr #IP

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] block daddr #IP: run"
echo "[test] block daddr #IP: run" >>./testlog.log
# cmd
echo "block daddr 8.8.8.8" >>/proc/htmm
ping 8.8.8.8 -c 5 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: drop blocked outgoing is on."|wc -l)
count2=$(dmesg|grep "read_cmd_from_msg: added ip: 8.8.8.8 to daddr_block_list."|wc -l)
count3=$(dmesg|grep "hook_func_dropblocked: LOCAL_OUT 8.8.8.8 (drop) "|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 1 ] && [ ${count3} -eq 5 ]; then
	test_block_daddr_IP=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] block daddr #IP: pass"
	echo "[test] block daddr #IP: pass" >>./testlog.log
else
	echo "[test] block daddr #IP: fail"
	echo "[test] block daddr #IP: fail" >>./testlog.log
fi
echo "----------------------------------------------------"

# test ---- unblock daddr #IP

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] unblock daddr #IP: run"
echo "[test] unblock daddr #IP: run" >>./testlog.log
# cmd
echo "unblock daddr 8.8.8.8" >>/proc/htmm
ping 8.8.8.8 -c 5 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: drop blocked outgoing is off."|wc -l)
count2=$(dmesg|grep "read_cmd_from_msg: deleted ip: 8.8.8.8 from daddr_block_list."|wc -l)
count3=$(dmesg|grep "hook_func_dropblocked: LOCAL_OUT 8.8.8.8 (drop) "|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 1 ] && [ ${count3} -eq 0 ]; then
	test_unblock_daddr_IP=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] unblock daddr #IP: pass"
	echo "[test] unblock daddr #IP: pass" >>./testlog.log
else
	echo "[test] unblock daddr #IP: fail"
	echo "[test] unblock daddr #IP: fail" >>./testlog.log
fi
echo "----------------------------------------------------"

# test ---- set saddr #IP quota #BYTE

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] set saddr #IP quota #BYTE: run"
echo "[test] set saddr #IP quota #BYTE: run" >>./testlog.log
# cmd
echo "set saddr 8.8.8.8 quota 200" >>/proc/htmm
ping 8.8.8.8 -c 10 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: quota controller for incoming traffic is on."|wc -l)
count2=$(dmesg|grep "read_cmd_from_msg: added ip: 8.8.8.8 quota: 200 to saddr_quota_list."|wc -l)
count3=$(dmesg|grep "read_cmd_from_msg: drop blocked addr for incoming traffic is on."|wc -l)
count4=$(dmesg|grep "hook_func_quota_controller: LOCAL_IN 8.8.8.8 (accept)"|wc -l)
count5=$(dmesg|grep "hook_func_quota_controller: LOCAL_IN 8.8.8.8 (accept) traffic exceed quota, add it to block list."|wc -l)
count6=$(dmesg|grep "add_entry_to_list: add ip: 8.8.8.8 to listid: s"|wc -l)
count7=$(dmesg|grep "hook_func_dropblocked: LOCAL_IN 8.8.8.8 (drop)"|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 1 ] && [ ${count3} -eq 1 ] && [ ${count4} -eq 5 ] && [ ${count5} -eq 1 ] && [ ${count6} -eq 1 ] && [ ${count7} -eq 6 ]; then
	test_set_saddr_IP_quota_BYTE=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] set saddr #IP quota #BYTE: pass"
	echo "[test] set saddr #IP quota #BYTE: pass" >>./testlog.log
else
	echo "[test] set saddr #IP quota #BYTE: fail"
	echo "[test] set saddr #IP quota #BYTE: fail" >>./testlog.log
fi
echo "----------------------------------------------------"
# test ---- unset quota saddr #IP

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] unset quota saddr #IP: run"
echo "[test] unset quota saddr #IP: run" >>./testlog.log
# cmd
echo "unset quota saddr 8.8.8.8" >>/proc/htmm
ping 8.8.8.8 -c 10 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: quota controller for incoming is off."|wc -l)
count2=$(dmesg|grep "read_cmd_from_msg: deleted ip: 8.8.8.8 from saddr_quota_list."|wc -l)
count3=$(dmesg|grep "read_cmd_from_msg: drop blocked addr for incoming is off."|wc -l)
count4=$(dmesg|grep "hook_func_quota_controller: LOCAL_IN 8.8.8.8 (accept)"|wc -l)
count5=$(dmesg|grep "hook_func_quota_controller: LOCAL_IN 8.8.8.8 (accept) traffic exceed quota, add it to block list."|wc -l)
count6=$(dmesg|grep "add_entry_to_list: add ip: 8.8.8.8 to listid: s"|wc -l)
count7=$(dmesg|grep "hook_func_dropblocked: LOCAL_IN 8.8.8.8 (drop)"|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 1 ] && [ ${count3} -eq 0 ] && [ ${count4} -eq 0 ] && [ ${count5} -eq 0 ] && [ ${count6} -eq 0 ] && [ ${count7} -eq 0 ]; then
	test_unset_saddr_IP_quota_BYTE=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] unset quota saddr #IP: pass"
	echo "[test] unset quota saddr #IP: pass" >>./testlog.log
else
	echo "[test] unset quota saddr #IP: fail"
	echo "[test] unset quota saddr #IP: fail" >>./testlog.log
fi
# cmd turn off dropblocked
echo "clear saddr block list" >>/proc/htmm
echo "----------------------------------------------------"

# test ---- set daddr #IP quota #BYTE

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] set daddr #IP quota #BYTE: run"
echo "[test] set daddr #IP quota #BYTE: run" >>./testlog.log
# cmd
echo "set daddr 8.8.8.8 quota 200" >>/proc/htmm
ping 8.8.8.8 -c 10 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: quota controller for outgoing traffic is on."|wc -l)
count2=$(dmesg|grep "read_cmd_from_msg: added ip: 8.8.8.8 quota: 200 to daddr_quota_list."|wc -l)
count3=$(dmesg|grep "read_cmd_from_msg: drop blocked addr for outgoing traffic is on."|wc -l)
count4=$(dmesg|grep "hook_func_quota_controller: LOCAL_OUT 8.8.8.8 (accept)"|wc -l)
count5=$(dmesg|grep "hook_func_quota_controller: LOCAL_OUT 8.8.8.8 (accept) traffic exceed quota, add it to block list."|wc -l)
count6=$(dmesg|grep "add_entry_to_list: add ip: 8.8.8.8 to listid: d"|wc -l)
count7=$(dmesg|grep "hook_func_dropblocked: LOCAL_OUT 8.8.8.8 (drop)"|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 1 ] && [ ${count3} -eq 1 ] && [ ${count4} -eq 5 ] && [ ${count5} -eq 1 ] && [ ${count6} -eq 1 ] && [ ${count7} -eq 6 ]; then
	test_set_daddr_IP_quota_BYTE=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] set daddr #IP quota #BYTE: pass"
	echo "[test] set daddr #IP quota #BYTE: pass" >>./testlog.log
else
	echo "[test] set daddr #IP quota #BYTE: fail"
	echo "[test] set daddr #IP quota #BYTE: fail" >>./testlog.log
fi
echo "----------------------------------------------------"

# test ---- unset quota daddr #IP

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] unset quota daddr #IP: run"
echo "[test] unset quota daddr #IP" >>./testlog.log
# cmd
echo "unset quota daddr 8.8.8.8" >>/proc/htmm
ping 8.8.8.8 -c 10 >>./trash.log
# check result
count1=$(dmesg|grep "read_cmd_from_msg: quota controller for outgoing is off."|wc -l)
count2=$(dmesg|grep "read_cmd_from_msg: deleted ip: 8.8.8.8 from daddr_quota_list."|wc -l)
count3=$(dmesg|grep "read_cmd_from_msg: drop blocked addr for outgoing is off."|wc -l)
count4=$(dmesg|grep "hook_func_quota_controller: LOCAL_OUT 8.8.8.8 (accept)"|wc -l)
count5=$(dmesg|grep "hook_func_quota_controller: LOCAL_OUT 8.8.8.8 (accept) traffic exceed quota, add it to block list."|wc -l)
count6=$(dmesg|grep "add_entry_to_list: add ip: 8.8.8.8 to listid: d"|wc -l)
count7=$(dmesg|grep "hook_func_dropblocked: LOCAL_OUT 8.8.8.8 (drop)"|wc -l)
if [ ${count1} -eq 1 ] && [ ${count2} -eq 1 ] && [ ${count3} -eq 0 ] && [ ${count4} -eq 0 ] && [ ${count5} -eq 0 ] && [ ${count6} -eq 0 ] && [ ${count7} -eq 0 ]; then
	test_unset_daddr_IP_quota_BYTE=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] unset quota daddr #IP: pass"
	echo "[test] unset quota daddr #IP: pass" >>./testlog.log
else
	echo "[test] unset quota daddr #IP: fail"
	echo "[test] unset quota daddr #IP: fail" >>./testlog.log
fi
# cmd turn off dropblocked
echo "clear saddr block list" >>/proc/htmm
echo "----------------------------------------------------"

# test ---- remove module
# log
echo "[test] remove modeule: run"
echo "[test] remove modeule: run" >>./testlog.log
# cmd
sudo rmmod netMonitor
# check result
count=$(dmesg|grep "cleanup_monitor: Network Traffic Monitor Module has been successfully removed from kernel."|wc -l)
if [ ${count} -eq 1 ]; then
	test_remove=true
	pass_number=$(expr ${pass_number} + 1)
	echo "[test] remove module: pass"
	echo "[test] remove module: pass" >>./testlog.log
else
	echo "[test] remove module: fail"
	echo "[test] remove module: fail" >>./testlog.log
fi
echo "----------------------------------------------------"

echo basic tests summary:
echo basic tests summary: >>./testlog.log
echo pass/total:${pass_number}/${total_number}
echo pass/total:${pass_number}/${total_number} >>./testlog.log

echo "=================complicated tests=================="
echo "=================complicated tests==================" >>./testlog.log

pass_number_c=0
total_number_c=1
# test ---- complicated test 1

# log ring buffer before clear
dmesg>>./ringbufferlog.log
# clear ring buffer
sudo dmesg -c >>./trash.log

# log
echo "[test] complicated test 1: run"
echo "[test] complicated test 1: run" >>./testlog.log

# cmd
sudo insmod netMonitor.ko
echo "turn on all monitor" >>/proc/htmm
echo "drop all incoming" >>/proc/htmm
echo "set daddr 8.8.8.8 quota 200" >>/proc/htmm
echo "set daddr 8.8.4.4 quota 200" >>/proc/htmm
ping 8.8.8.8 -c 10 >>./trash.log
ping 8.8.4.4 -c 10 >>./trash.log
echo "unset quota daddr 8.8.8.8" >>/proc/htmm
ping 8.8.8.8 -c 10 >>./trash.log
echo "set daddr 8.8.4.4 quota 400" >>/proc/htmm
ping 8.8.4.4 -c 10 >>./trash.log
echo "clear saddr quota list" >>/proc/htmm
ping 8.8.8.8 -c 10 >>./trash.log
ping 8.8.4.4 -c 10 >>./trash.log
sudo rmmod netMonitor


# check result
count1=$(dmesg|grep "Network Traffic Monitor Module has been successfully loaded into kernel"|wc -l)
count2=$(dmesg|grep "hook_func_moniter: LOCAL_OUT 8.8.8.8 (accept)"|wc -l)
count4=$(dmesg|grep "hook_func_moniter: LOCAL_IN 8.8.8.8 (accept)"|wc -l)
count3=$(dmesg|grep "hook_func_quota_controller: LOCAL_OUT 8.8.8.8 (accept)"|wc -l)
count5=$(dmesg|grep "hook_func_quota_controller: LOCAL_OUT 8.8.8.8 (accept) traffic exceed quota"|wc -l)
count6=$(dmesg|grep "hook_func_dropblocked: LOCAL_OUT 8.8.8.8 (drop)"|wc -l)
count7=$(dmesg|grep "hook_func_moniter: LOCAL_OUT 8.8.4.4 (accept)"|wc -l)
count8=$(dmesg|grep "hook_func_moniter: LOCAL_IN 8.8.4.4 (accept)"|wc -l)
count9=$(dmesg|grep "hook_func_quota_controller: LOCAL_OUT 8.8.4.4 (accept)"|wc -l)
count11=$(dmesg|grep "hook_func_quota_controller: LOCAL_OUT 8.8.4.4 (accept) traffic exceed quota"|wc -l)
count10=$(dmesg|grep "hook_func_dropblocked: LOCAL_OUT 8.8.4.4 (drop)"|wc -l)
count12=$(dmesg|grep "cleanup_monitor: Network Traffic Monitor Module has been successfully removed from kernel."|wc -l)

if [ ${count1} -eq 1 ] && [ ${count2} -eq 30 ] && [ ${count3} -eq 5 ] && [ ${count4} -eq 24 ] && [ ${count5} -eq 1 ] && [ ${count6} -eq 6 ] && [ ${count7} -eq 30 ] && [ ${count8} -eq 7 ] && [ ${count9} -eq 9 ] && [ ${count10} -eq 23 ] && [ ${count11} -eq 2 ] && [ ${count12} -eq 1 ]; then
	test_complicated1_c=true
	pass_number_c=$(expr ${pass_number_c} + 1)
	echo "[test] complicated test 1: pass"
	echo "[test] complicated test 1: pass" >>./testlog.log
else
	echo "[test] complicated test 1: fail"
	echo "[test] complicated test 1: fail" >>./testlog.log
fi


echo "----------------------------------------------------"

echo complicated tests summary:
echo complicated tests summary: >>./testlog.log
echo pass/total:${pass_number_c}/${total_number_c}
echo pass/total:${pass_number_c}/${total_number_c} >>./testlog.log

echo "=====================tests end======================"
echo "=====================tests end======================" >>./testlog.log


# log ring buffer before clear
dmesg>>./ringbufferlog.log