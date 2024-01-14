BPF Creation Guide
===================

A small guide to aid in the creation of a Berkeley Packet Filter for use with ZerBea's `hcxdumptool`.

**Note:** `tcpdump` will accept a MAC address in any format. (eg. DE:AD:BE:EF, de:ad:be:ef, deadbeef)

Single Target Filter
---------------------

Let's say your target AP has the MAC address `DE:AD:BE:EF`.

Issue the following command to create a BPF that only targets that specific AP.

```sudo tcpdump -s 65535 -y IEEE802_11_RADIO wlan addr3 DE:AD:BE:EF or wlan addr3 FF:FF:FF:FF:FF:FF -ddd > target.bpf```

Multiple Target Filter
-----------------------

Let's say you're targeting APs that have the MAC addresses `DE:AD:BE:EF` and `11:22:33:44:55:66`.

Issue the following command to create a BPF that'll target all APs specified.

```sudo tcpdump -s 65535 -y IEEE802_11_RADIO wlan addr3 DE:AD:BE:EF or wlan addr3 11:22:33:44:55:66 or wlan addr3 FF:FF:FF:FF:FF:FF -ddd > target.bpf```

Protection
-----------

Let's say your AP's MAC address is `1A:2A:3A:4A:5A:6A`.

Issue the following command to create a BPF that'll attack all other APs but will ignore your own.

```sudo tcpdump -s 65535 -y IEEE802_11_RADIO not wlan addr3 1A:2A:3A:4A:5A:6A -ddd > protect.bpf```