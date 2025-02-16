# hcxdumptool

A tool to capture packets from WLAN devices and to discover potential weak points within own WiFi networks by running layer 2 attacks against the WPA protocol.

Designed to to run (mostly headless) on small systems like a Raspberry Pi Zero.

# hcxnmealog

A tool to handle NMEA 0183 sentences from GPS devices.

Designed to to run (mostly headless) on small systems like a Raspberry Pi Zero.

### General Information

- [An overview of Hashcat mode 22000.](https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2)

- [A set of tools by **ZerBea** intended for processing capture files.](https://github.com/ZerBea/hcxtools)

- [Old but still applicable write-up by **atom** of the Hashcat forums covering a new attack on WPA/WPA2 using PMKID.](https://hashcat.net/forum/thread-7717.html)

- [Hashcat mode 22000 write-up by **atom** of the Hashcat forums.](https://hashcat.net/forum/thread-10253.html)

- [A write-up by **Ido Hoorvitch** from CyberArk covering the statistics of WPA/WPA2 password cracking.](https://www.cyberark.com/resources/threat-research-blog/cracking-wifi-at-scale-with-one-simple-trick)

- [A section of this README that covers hcxdumptool's abilities and the responsibilities of using it.](https://github.com/ZerBea/hcxdumptool#caution)

- hcxdumptool uses the modern [pcapng](https://pcapng.com/) format, allowing for use with wireshark or tshark.

- [A document showcasing an example attack using hcxdumptool and hcxtools.](https://github.com/ZerBea/hcxdumptool/blob/master/docs/example.md)

### What Doesn't hcxdumptool Do?

- It does not crack WPA PSK related hashes. (Use Hashcat or JtR to recover the PSK.)

- It does not crack WEP. (Use the aircrack-ng suite instead.)

- It does not crack WPS. (Use Reaver or Bully instead.)

- It does not decrypt encrypted traffic. (Use tshark or Wireshark in parallel.)

- It does not record all traffic captured on the WLAN device. (Use tshark or Wireshark in parallel.)

- It does not perform Evil Twin attacks.

- It does not provide a beautiful status display.

- It is not a honey pot.

**Unsupported:** Windows OS, macOS, Android, emulators or wrappers!

> [!NOTE]
>
> **hcxdumptool** does not perform conversion or cracking! It is designed to be used in conjunction with the following tools:
>
> | Tool          | Description                                                                                           |
> | ------------- | ------------------------------------------------------------------------------------------------------|
> | hcxnmealog    | Tool to handle NMEA 0183 sentences                                                                    |
> | hcxpcapngtool | Tool to convert raw PCAPNG files to Hashcat and JtR readable formats. (hcxtools)                      |
> | hcxhashtool   | Tool to filter hashes from HC22000 files based on user input. (hcxtools)                              |
> | hcxpsktool    | Tool to get weak PSK candidates from HC22000 files. (hcxtools)                                        |
> | hcxeiutool    | Tool to calculate wordlists based off ESSIDs gathered. (hcxtools)                                     |
> | Hashcat/JtR   | Third party tools used to infer PSK from HC22000 hash files.                                          |
>
> **hcxtools** can be found [here](https://github.com/ZerBea/hcxtools). Hashcat can be found [here](https://github.com/hashcat/hashcat).

### Work Flow

hcxdumptool -> hcxpcapngtool -> hcxhashtool (additional hcxpsktool/hcxeiutool) -> Hashcat or JtR

### Requirements

You might expect me to recommend that everyone should be using hcxdumptool/hcxtools. But the fact of the matter is, however, that hcxdumptool/hcxtools is NOT recommended to be used by unexperienced users or newbies.
If you are not familiar with Linux generally or if you do not have at least a basic level of knowledge as mentioned in section "Requirements", hcxdumptool/hcxtools is probably not what you are looking for.
However, if you have that knowledge this tools can do magic.

- Knowledge of radio technology.
- Knowledge of electromagnetic-wave engineering.
- Detailed knowledge of 802.11 protocol.
- Detailed knowledge of key derivation functions.
- Detailed knwoldege of NMEA 0183 protocol.
- Detailed knowledge of Linux.
- Detailed knowledge of filter procedures. (Berkeley Packet Filter, capture filter, display filter, etc.)
- Detailed knowledge of Bolean Operators.
- Operating system: Linux (latest longterm or stable [kernel](https://www.kernel.org), mandatory >= 5.15)
- Recommended distribution: [Arch Linux](https://archlinux.org/) (notebooks and desktop systems), [OpenWRT](https://openwrt.org/) (small systems like Raspberry Pi, WiFi router)
- WLAN device chipset must be able to run in monitor mode.
- WLAN device driver *must* support monitor and full frame injection mode.
- gcc >= 14 recommended (deprecated versions are not supported: https://gcc.gnu.org/)
- make
- libpcap and libpcap-dev (If internal BPF compiler has been enabled.)
- Raspberry Pi A, B, A+, B+, Zero (WH). (Recommended: Zero or A+, because of a very low power consumption), but notebooks and desktops will work as well.
- GPIO hardware mod recommended (push button and LED) on Raspberry Pi
- To allow 5/6/7GHz packet injection, it is mandatory to uncomment a regulatory domain that support this: /etc/conf.d/wireless-regdom 
- Make sure that the version of hcxdumptool always fits to the version of hcxpcapngtool 

### Install Guide

> [!IMPORTANT]
>
> While hcxdumptool and hcxtools are available through the package manager on most distributions, these packages are usually very old and outdated, thus cloning and building is recommended. 
>
> Make sure that your distribution is updated to it's latest version and make sure that all header files and dependencies have been installed BEFORE attempting to compile!
>
> The packages mentioned in the "Requirements" section sometimes come under different names in a package manager! Make sure to install the correct packages!

#### Clone Repository

```
git clone https://github.com/ZerBea/hcxdumptool.git
cd hcxdumptool
```

#### Compile & Install

Compiling:
```
make -j $(nproc)
```

Installing to `/usr/bin`:
```
make install (as super user)
```

Or installing to `/usr/local/bin`:
```
make install PREFIX=/usr/local (as super user)
```

> [!TIP]
>
> On headless operation, remove -DSTATUSOUT from the Makefile before compiling! That way, the status display will not be compiled. This will save CPU cycles and prevent ERRORs from occurring.
>
> It is theoretically possible to compile hcxdumptool for other systems (e.g. Android) and other distributions (e.g. KALI) and other operating systems (BSD) as well.
> There is no plan to support the operating systems and feature requests will be rejected.

### Adapters

> [!WARNING]
>
> - Do not expect flawless drivers on brand new hardware!
>
> - Driver must support monitor mode and full packet injection!
>
> - PRISM devices are _not_ supported! 
>
> - WIRELESS EXTENSIONS are deprecated and no longer supported!

> [!NOTE]
>
> Manufacturers do change chipsets without changing model numbers. Sometimes they add (v)ersion or (rev)vision.
> As long as a manufacturer or a company does not consider it necessary to supply drivers to the Linux kernel avoid to buy this products!
>
> **Always verify the actual chipset with 'lsusb' and/or 'lspci'!**
>
> No support for a third party driver which is not part of the [official Linux kernel](https://www.kernel.org/).
> Report related issues to the site, from which you downloaded the driver.
>
> No support for a driver which doesn't support monitor mode and full frame injection natively.
> If you need these features, do a request on www.kernel.org
>
> Several device and driver tests can be found [here](https://github.com/ZerBea/hcxdumptool/discussions/361).
> Dependent on the version of the Linux kernel, expect massive driver issues.

Known as working WiFi chipsets:

* Atheros (ath9k_htc) old chipset

* Ralink (rt2800usb) old chipset

* MediaTek (mt76) depending on chipset and the version of the Linux Kernel expect massive driver issues

* Realtek (rtl8xxxu) depending on chpset and the version of the Linux Kernel expect massive driver issues

Not recommended WiFi chipsets:

* Intel (Monitor mode and frame injection problems.)

* Broadcom (Neither monitor mode nor frame injection by official Linux kernel.)

* Qualcomm (No frame injection by official Linux kernel.)

Absolutely not recommended:

* All kinds of WiFi PCIe cards, due to massive interference.
https://duckduckgo.com/?t=ffab&q=Static+Interference+from+PCIe+wifi&ia=web

More information about possible issues or limitations can be found [here](https://github.com/ZerBea/hcxdumptool#useful-links).

### Antennas

The best high frequency amplifier is a good antenna!

It is much better to achieve gain using a good antenna instead of increasing transmission power.

| VENDOR MODEL           | TYPE            |
| ---------------------- | --------------- |
| LOGILINK WL0097        | Grid Parabolic  |
| TP-LINK TL-ANT2414 A/B | Panel           |
| LevelOne WAN-1112      | Panel           |
| DELOCK 88806           | Panel           |
| TP-LINK TL-ANT2409 A   | Panel           |

### GPS devices (NMEA 0183 protocol)

| VENDOR MODEL                | TYPE            |
| --------------------------- | --------------- |
| NAVILOCK NL-701US           | USB             |
| JENTRO BT-GPS-8 activepilot | BLUETOOTH       |
| HiLetgo VK172               | USB             |

### Useful Scripts

| Script       | Description                                              |
| ------------ | -------------------------------------------------------- |
| stopnm       | Example script to stop NetworkManager                    |
| startnm      | Example script to start NetworkManager                   |
| startnlmon   | Example script to activate NETLINK monitor               |

### Caution!

You might expect me to recommend that everyone should be using hcxdumptool/hcxtools. But the fact of the matter is, hcxdumptool/hcxtools is _NOT_ recommended to be used by inexperienced users or newbies.

If you are not familiar with Linux in general or you do not have at least a basic level of knowledge as mentioned in the "Requirements" section, hcxdumptool/hcxtools is probably not what you are looking for.
However, if you have that knowledge hcxdumptool/hcxtools can do magic for you.

Misuse of hcxdumptool within a network, particularly without authorization, may cause irreparable damage and result in significant consequences. “Not understanding what you were doing” is not going to work as an excuse.

The entire toolkit (hcxdumptool and hcxtools) is designed to be an analysis toolkit. 

**hcxdumptool should only be used in a 100% controlled environment!**

If you can't control the environment, it is absolutely mandatory to set the [BPF](https://wiki.wireshark.org/CaptureFilters)!

The BPF can be used to select a target (or multible targets) or to protect devices.

By default, hcxdumptool is utilizing three attack vectors:

- Connecting to an ACCESS POINT to get a PMKID (turn off by --attemptapmax)

- Disconnecting a CLIENT from an associated ACCESS POINT to get a complete handshake (M1M2M3M4) and a PMKID (turn off by --attemptapmax)

- Allowing a CLIENT to connect to hcxdumptool to get a challenge (M1M2) or an EAP-ID (turn off by --attemptclientmax)

> [!WARNING]
>
> **You may only use hcxdumptool on networks that you have permission to attack, because:**
>
> - hcxdumptool is able to prevent complete WLAN traffic transmission. (Depending on selected options.)
>
> - hcxdumptool is able to capture PMKIDs from access points if the accesspoint supports PMKID caching. (Only one single PMKID from an access point is required. Use hcxpcapngtool to convert them to a format Hashcat or JtR understands.)
>
> - hcxdumptool is able to capture handshakes from non-connected clients. (Only one single M2 from the client is required. Use hcxpcapngtool to convert them to a format Hashcat or JtR understands.)
>
> - hcxdumptool is able to capture handshakes from 5/6GHz clients on 2.4GHz. (Only one single M2 from the client is required. Use hcxpcapngtool to convert to a format Hashcat or JtR understands.)
>
> - hcxdumptool is able to capture passwords from the WLAN traffic. (Use hcxpcapngtool -R to save them to file, or together with networknames [-E].)
>
> - hcxdumptool is able to request and capture extended EAPOL. (RADIUS, GSM-SIM, WPS. hcxpcapngtool will show you information about them.)
>
> - hcxdumptool is able to capture identities from the WLAN traffic. (Example: Request IMSI numbers from mobile phones - use hcxpcapngtool -I to save them to file.)
>
> - hcxdumptool is able to capture usernames from the WLAN traffic. (Example: User name of a server authentication - use hcxpcapngtool -U to save them to file.)
>
> **Do Not:**
>
> - Use a logical interface and leave the physical interface in managed mode!
>
> - Use hcxdumptool in combination with the aircrack-ng suite, Reaver, Bully, or any other tools that take access to the interface!
>
> - Use tools like macchanger as they are useless since hcxdumptool uses its own random MAC address space.
>
> - Merge PCAPNG dumpfiles because doing so will destroy custom block hash assignments!

### Useful Links

- [PCAPNG Format Information](https://pcapng.com/)

- [The Linux Kernel Documentation](https://www.kernel.org/doc/html/latest/)

- [Existing Linux Wireless drivers](https://wireless.docs.kernel.org/en/latest/en/users/drivers.html)

- [BPF Documentation](https://www.kernel.org/doc/html/latest/bpf/index.html)

- [Linux Commands Handbook](https://www.freecodecamp.org/news/the-linux-commands-handbook/)

- [WPA2 Information](https://en.wikipedia.org/wiki/Wpa2)

- [802.11 Frame Types](https://en.wikipedia.org/wiki/802.11_Frame_Types)

- [802.11 Security Improvements](https://en.wikipedia.org/wiki/IEEE_802.11i-2004)

- [Kernel Bugzilla](https://bugzilla.kernel.org)

- [About ath10k](https://wireless.wiki.kernel.org/en/users/Drivers/ath10k)

- [Status of Realtek out-of-kernel Drivers](https://github.com/morrownr/USB-WiFi/issues/314)

- [PCAPNG Status Options](https://github.com/ZerBea/hcxdumptool/blob/master/docs/option-codes.md)
