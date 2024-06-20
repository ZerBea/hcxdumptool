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

### Example Attack - Details/Goals

This example will simulate attacking a single network of interest.
It is assumed all information relating to the target is already known.

ESSID of AP: **TestAP**
MAC address of AP: **00c0cab035be**.
AP channel: **11**

### Step One - Creating a BPF

The creation of a [BPF](https://wiki.wireshark.org/CaptureFilters) is **mandatory** as it make hcxdumptool either _ignore_ the specified address, or _attack_ the specified address.

The full command to create a BPF to _attack_ 00c0cab035be would be as follows:

```
hcxdumptool --bpfc="wlan addr1 00c0cab035be or wlan addr2 00c0cab035be or wlan addr3 00c0cab035be" >> attack.bpf
```

The full command to create a BPF to _protect_ 00c0cab035be would be as follows:

```
hcxdumptool --bpfc="not wlan addr3 00c0cab035be" >> protect.bpf
```

Since we are going to attack 00c0cab035be, we will use the **attack.bpf** filter.

### Step Two - Running hcxdumptool

Since we have now made the BPF, we can start the attack using all the information mentioned above.

```
sudo hcxdumptool -i wlan0 -c 11a --bpf=attack.bpf -w TestAP.pcapng
```

> [!NOTE]
> hcxdumptool **requires** either super user (root) privileges to run or the use of sudo!

After running that command for a while, the output was as follows:

![hcxdumptool output](/docs/example-pic-1.png?raw=true "hcxdumptool TestAP output")

### Step Three - Conversion

We now have a complete capture with all information needed for cracking the PSK. Before we crack the PSK, we need to convert it into a format Hashcat/JtR can understand using hcxpcapngtool.

The command to do so is as follows:

```
hcxpcapngtool -o TestAP.hc22000 TestAP.pcapng
```

After running hcxpcapngtool, the output was as follows:

![hcxpcapngtool output](/docs/example-pic-2.png?raw=true "hcxpcapngtool output")

> [!NOTE]
> hcxpcapngtool will throw errors if:
> 1. The capture was too short/incomplete.
> 2. The format used is old/outdated.
> 3. Too many DEAUTHENTICATION frames were detected.
> 4. The capture file was cleaned.
> 5. No PROBEREQUESTS were detected.
> 6. Too few M1 frames were detected.

### Step Four - Cracking

Finally, we have a Hashcat/JtR compatible format for cracking the PSK of our target network. For this example, we will use Hashcat for our cracking tool of choice.

There are many different ways to use Hashcat but we will just use a straight dictionary attack.

The command will be as follows:

```
sudo hashcat -a 0 -m 22000 ./TestAP.hc22000 ./Wordlists/probable.txt
```

After letting Hashcat run for a while, the output was as follows:

![Hashcat output](/docs/example-pic-3.png?raw=true "cracked Hashcat output")