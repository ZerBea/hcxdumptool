hcxdumptool
==============

Small tool to capture packets from wlan devices and to detect weak points within own WiFi networks
(e.g.: PreSharedKey or PlainMasterKey is transmitted unencrypted by a CLIENT).


Brief description
--------------

Stand-alone binaries - designed to run on Arch Linux, but other Linux distributions should work, too.

Capture format pcapng is compatible to Wireshark and tshark.

Read this post: hcxtools - solution for capturing wlan traffic and conversion to hashcat formats (https://hashcat.net/forum/thread-6661.html)

Read this post: New attack on WPA/WPA2 using PMKID (https://hashcat.net/forum/thread-7717.html)

Read this post: Hash mode 22000 explained (https://hashcat.net/forum/thread-10253.html)

Read this wiki: https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2

Unsupported: Windows OS, macOS, Android, emulators or wrappers and NETLINK!


Detailed description
--------------

| Tool           | Description                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------------------ |
| hcxdumptool    | Tool to run several tests to determine if ACCESS POINTs or CLIENTs are vulnerable                      |
| hcxpioff       | Turns Raspberry Pi off via GPIO switch                                                                 |


Work flow
--------------

hcxdumptool -> hcxpcapngtool -> hcxhashtool (additional hcxpsktool/hcxeiutool) -> hashcat or JtR

hcxdumptool: attack and capture everything (depending on options)

hcxpcapngtool: convert everything

hcxhashtool: filter hashes

hcxpsktool: get weak PSK candidates

hcxeiutool: calculate wordlists from ESSID
 
hashcat or JtR: get PSK from hash


Get source
--------------
```
git clone https://github.com/ZerBea/hcxdumptool.git
cd hcxdumptool
```

Solve dependencies (Debian based distributions: KALI, UBUNTU, ...) 
-------------- 

You need to install missing dependencies before running `make`:

```
sudo apt-get install libcurl4-openssl-dev libssl-dev pkg-config
```

Compile
--------------
```
make
make install (as super user)
```

Or install via packet manager
--------------

### Arch Linux
[Arch Linux](https://www.archlinux.org/) 
`pacman -S hcxtools`

### Arch Linux ARM
[Arch Linux ARM ](https://archlinuxarm.org/) 
`pacman -S hcxtools`

### Black Arch
[Black Arch](https://blackarch.org/) is an Arch Linux-based penetration testing distribution for penetration testers and security researchers  
`pacman -S hcxtools`


Compile for Android
--------------

You need:
* Android NDK installed in your system and in path variable

* This repository cloned with all submodules (`--recursive` flag in `git clone` or `git submodules update` command run)

Just run `ndk-build` - built executables for some architectures should be created inside `libs` directory.
Copy it to your phone and enjoy.


Requirements
--------------

* Operatingsystem: Arch Linux (strict), Kernel >= 5.4 (strict). It may work on other Linux systems (notebooks, desktops) and distributions, too (no support for other distributions, no support for other operating systems).

* Chipset must be able to run in monitor mode and driver must support monitor mode as well as full packet injection. Recommended: MEDIATEK (MT7601) or RALINK (RT2870, RT3070, RT5370) chipset 

* gcc >= 11 recommended (deprecated versions are not supported: https://gcc.gnu.org/)

* libopenssl and openssl-dev installed

* pkg-config installed

* Raspberry Pi A, B, A+, B+, Zero (WH). (Recommended: Zero (WH) or A+, because of a very low power consumption), but notebooks and desktops may work, too.

* GPIO hardware mod recommended (push button and LED).

* to allow 5GHz packet injection, it is mandatory to uncomment a regulatory domain that support this: /etc/conf.d/wireless-regdom 

If you decide to compile latest git head, make sure that your distribution is updated on latest version.


Adapters
--------------

hcxdumptool need full (monitor mode and full packet injection running all packet types) and exclusive access to the adapter! Otherwise it will not start!

The driver must support monitor mode and full packet injection, as well as ioctl() system calls!

Virtual Netlink (libnl) interfaces are not supported!

Get information about VENDOR, model, chipset and driver here: https://wikidevi.wi-cat.ru/

Manufacturers do change chipsets without changing model numbers. Sometimes they add (v)ersion or (rev)vision.

This list is for information purposes only and should not be regarded as a binding presentation of the products:

| VENDOR MODEL            | ID                                                            |
| ----------------------- | ------------------------------------------------------------- |
| ALLNET ALL-WA0150N      | ID 148f:7601 Ralink Technology, Corp. MT7601U Wireless Adapter |
| SEMPRE WU150-1          | ID 148f:7601 Ralink Technology, Corp. MT7601U Wireless Adapter |
| TP-LINK Archer T2UH     | ID 148f:761a Ralink Technology, Corp. MT7610U ("Archer T2U" 2.4G+5G WLAN Adapter) |
| ASUS USB-AC51           | ID 0b05:17d1 ASUSTek Computer, Inc. AC51 802.11a/b/g/n/ac Wireless Adapter [Mediatek MT7610U] |
| ALFA AWUS036ACM         | ID 0e8d:7612 MediaTek Inc. MT7612U 802.11a/b/g/n/ac Wireless Adapter |
| CSL 300MBit 300649      | ID 148f:5572 Ralink Technology, Corp. RT5572 Wireless Adapter |
| EDIMAX EW-7711UAN       | ID 7392:7710 Edimax Technology Co., Ltd |
| TENDA W311U+            | ID 148f:3070 Ralink Technology, Corp. RT2870/RT3070 Wireless Adapter |
| ALFA AWUS036H           | ID 0bda:8187 Realtek Semiconductor Corp. RTL8187 Wireless Adapter |
| ALFA AWUS036NH          | ID 148f:3070 Ralink Technology, Corp. RT2870/RT3070 Wireless Adapter |
| LogiLink WL0151         | ID 148f:5370 Ralink Technology, Corp. RT5370 Wireless Adapter |
| WiFi N (noname)         | ID 148f:5370 Ralink Technology, Corp. RT5370 Wireless Adapter |
| TP-Link TL-WN722N <br /> v1 | ID 0cf3:9271 Qualcomm Atheros Communications AR9271 802.11n <br /> Partly driver freezes and overheating problems |
| TP-Link TL-WN722N <br /> v2/v3 | ID 2357:010c TP-Link TL-WN722N v2/v3 [Realtek RTL8188EUS] <br /> Recommended driver: https://github.com/kimocoder/realtek_rtwifi |
| LogiLink WL0151A        | ID 0bda:8179 Realtek Semiconductor Corp. RTL8188EUS 802.11n Wireless Network Adapter <br /> Recommended driver: https://github.com/kimocoder/realtek_rtwifi |
| ALFA AWUS036ACH         | ID 0bda:8812 Realtek Semiconductor Corp. RTL8812AU 802.11a/b/g/n/ac 2T2R DB WLAN Adapter <br /> Required driver: https://github.com/aircrack-ng/rtl8812au - interface must be set to monitor mode manually using iw before starting hcxdumptool |


Always verify the actual chipset with 'lsusb' and/or 'lspci'!

Due to a bug in xhci subsystem other devices may not work at the moment: <br /> https://bugzilla.kernel.org/show_bug.cgi?id=202541

Third party drivers may not compile or work as expected on latest kernels

No support for a third party driver which is not part of the official kernel (https://www.kernel.org/) <br /> Report related issues to the site, from which you downloaded the driver

No support for a driver which doesn't support monitor and packet injection, native <br /> If you need this features, do a request on www.kernel.org


Not recommended WiFi chipsets:

* Intel PRO/Wireless (due to MICROCODE issues)

* Broadcom (neither monitor mode nor frame injection)

* Realtek RTL8811AU, RTL8812AU, RTL 8814AU (due to NETLINK dependency)


Antennas
--------------

The best high frequency amplifier is a good antenna!

It is much better to achieve gain using a good antenna instead of increasing transmitter power.

| VENDOR MODEL           | TYPE            |
| ---------------------- | --------------- |
| LOGILINK WL0097        | grid parabolic  |
| TP-LINK TL-ANT2414 A/B | panel           |
| LevelOne WAN-1112      | panel           |
| DELOCK 88806           | panel           |
| TP-LINK TL-ANT2409 A   | panel           |


GPS devices
--------------

| VENDOR MODEL                | TYPE            |
| --------------------------- | --------------- |
| NAVILOCK NL-701US           | USB             |
| JENTRO BT-GPS-8 activepilot | BLUETOOTH       |


Useful scripts
--------------

| Script       | Description                                              |
| ------------ | -------------------------------------------------------- |
| bash_profile | Autostart for Raspberry Pi (copy to /root/.bash_profile) |
| pireadcard   | Back up a Pi SD card                                     |
| piwritecard  | Restore a Pi SD card                                     |
| makemonnb    | Example script to activate monitor mode                  |
| killmonnb    | Example script to deactivate monitor mode                |


Hardware mod - see docs gpiowait.odg (hcxdumptool)
--------------

LED flashes 5 times if hcxdumptool successfully started

LED flashes every 5 seconds if everything is fine and signals are received

LED flashes twice, if no signal received during the last past 5 seconds

Press push button at least > 5 seconds until LED turns on (also LED turns on if hcxdumptool terminates)

Green ACT LED flashes 10 times

Raspberry Pi turned off and can be disconnected from power supply

Do not use hcxdumptool and hcxpioff together!


Hardware mod - see docs gpiowait.odg (hcxpioff)
--------------

LED flashes every 5 seconds 2 times if hcxpioff successfully started

Press push button at least > 5 seconds until LED turns on

Green ACT LED flashes 10 times

Raspberry Pi turned off safely and can be disconnected from power supply


Procedure
--------------

first run hcxdumptool -i interface --do_rcascan at least for 30 seconds

to determine that the driver support monitor mode and required ioctl() calls,

to determine that the driver support full packet injection,

to retrieve information about access points and

to determine which access points are in attack range.


pcapng option codes (Section Header Block)
--------------

ENTERPRISE NUMBER        0x2a, 0xce, 0x46, 0xa1

MAGIC NUMBER             0x2a, 0xce, 0x46, 0xa1, 0x79, 0xa0, 0x72, 0x33,

                         0x83, 0x37, 0x27, 0xab, 0x59, 0x33, 0xb3, 0x62,

                         0x45, 0x37, 0x11, 0x47, 0xa7, 0xcf, 0x32, 0x7f,

                         0x8d, 0x69, 0x80, 0xc0, 0x89, 0x5e, 0x5e, 0x98

OPTIONCODE_MACMYORIG     0xf29a (6 byte)

OPTIONCODE_MACMYAP       0xf29b (6 byte)

OPTIONCODE_RC            0xf29c (8 byte)

OPTIONCODE_ANONCE        0xf29d (32 byte)

OPTIONCODE_MACMYSTA      0xf29e (6 byte)

OPTIONCODE_SNONCE        0xf29f (32 byte)

OPTIONCODE_WEAKCANDIDATE 0xf2a0 (64 byte) == 63 characters + zero

OPTIONCODE_GPS           0xf2a1 (max 128 byte)


Warning
--------------

hcxdumptool is designed to be an analysis tool. This means that everything is requested/stored by default. Unwanted information must be filtered out later on, offline! 

You must use hcxdumptool only on networks you have permission to do this, because:

* hcxdumptool is able to prevent complete wlan traffic
  (depend on selected options)

* hcxdumptool is able to capture PMKIDs from access points (only one single PMKID from an access point required)
  (use hcxpcapngtool to convert them to a format hashcat and/Or JtR understand)

* hcxdumptool is able to capture handshakes from not connected clients (only one single M2 from the client is required)
  (use hcxpcapngtool to convert them to a format hashcat and/Or JtR understand)

* hcxdumptool is able to capture handshakes from 5GHz clients on 2.4GHz (only one single M2 from the client is required)
  (use hcxpcapngtool to to a format hashcat and/Or JtR understand)

* hcxdumptool is able to capture passwords from the wlan traffic
  (use hcxpcapngtool -E to save them to file, together with networknames)

* hcxdumptool is able to request and capture extended EAPOL (RADIUS, GSM-SIM, WPS)
  (hcxpcapngtool will show you information about them)

* hcxdumptool is able to capture identities from the wlan traffic
  (for example: request IMSI numbers from mobile phones - use hcxpcapngtool -I to save them to file)

* hcxdumptool is able to capture usernames from the wlan traffic
  (for example: user name of a server authentication - use hcxpcapngtool -U to save them to file)

* Do not use a logical interface and leave the physical interface in managed mode

* Do not use hcxdumptool in combination with aircrack-ng, reaver, bully or other tools which take access to the interface

* Stop all services which take access to the physical interface (NetworkManager, wpa_supplicant,...)

* Do not use tools like macchanger, as they are useless, because hcxdumptool uses its own random mac address space
