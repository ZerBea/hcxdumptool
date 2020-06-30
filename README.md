hcxdumptool
==============

Small tool to capture packets from wlan devices.
After capturing, upload the "uncleaned" cap here (https://wpa-sec.stanev.org/?submit)
to see if your ap or the client is vulnerable by using common wordlists.
Convert the pcapng file to WPA-PBKDF2-PMKID+EAPOL hashline (22000) with hcxpcapngtool (hcxtools)
and check if wlan-key or plainmasterkey was transmitted unencrypted.


Brief description
--------------

Stand-alone binaries - designed to run on Raspberry Pi's with installed Arch Linux.
It may work on other Linux systems (notebooks, desktops) and distributions, too.


Detailed description
--------------

| Tool           | Description                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------------------ |
| hcxdumptool    | Tool to run several tests to determine if access points or clients are vulnerable                      |
| hcxpioff       | Turns Raspberry Pi off via GPIO switch                                                                 |


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
sudo apt-get install libcurl4-openssl-dev
sudo apt-get install libssl-dev
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

* Chipset must be able to run in monitor mode and driver must support monitor mode. Recommended: MEDIATEK (MT7601) or RALINK (RT2870, RT3070, RT5370) chipset 

* libopenssl and openssl-dev installed

* Raspberry Pi A, B, A+, B+, Zero (WH). (Recommended: Zero (WH) or A+, because of a very low power consumption), but notebooks and desktops may work, too.

* GPIO hardware mod recommended (push button and LED).


Adapters
--------------

hcxdumptool need full (monitor mode and full packet injection running all packet types) and exclusive access to the adapter! Otherwise it will not start!

The driver must support monitor mode and full packet injection, as well as ioctl() calls!

Netlink (libnl) interfaces are not supported!

Get information about VENDOR, model, chipset and driver here: https://wikidevi.wi-cat.ru/

Manufacturers do change chipsets without changing model numbers. Sometimes they add (v)ersion or (rev)vision.

This list is for information purposes only and should not be regarded as a binding presentation of the products:

| VENDOR MODEL         | ID                                                                                            |
| -------------------- | --------------------------------------------------------------------------------------------- |
| EDIMAX EW-7711UAN    | ID 7392:7710 Edimax Technology Co., Ltd                                                       |
| ALLNET ALL-WA0150N   | ID 148f:7601 Ralink Technology, Corp. MT7601U Wireless Adapter                                |
| SEMPRE WU150-1       | ID 148f:7601 Ralink Technology, Corp. MT7601U Wireless Adapter                                |
| TENDA W311U+         | ID 148f:3070 Ralink Technology, Corp. RT2870/RT3070 Wireless Adapter                          |
| ALFA AWUS036H        | ID 0bda:8187 Realtek Semiconductor Corp. RTL8187 Wireless Adapter                             |
| ALFA AWUS036NH       | ID 148f:3070 Ralink Technology, Corp. RT2870/RT3070 Wireless Adapter                          |
| LogiLink WL0151      | ID 148f:5370 Ralink Technology, Corp. RT5370 Wireless Adapter                                 |
| TP-LINK TL-WN722N v1 | ID 0cf3:9271 Qualcomm Atheros Communications AR9271 802.11n                                   |
| TP-LINK Archer T2UH  | ID 148f:761a Ralink Technology, Corp. MT7610U ("Archer T2U" 2.4G+5G WLAN Adapter)             |
| ASUS USB-AC51        | ID 0b05:17d1 ASUSTek Computer, Inc. AC51 802.11a/b/g/n/ac Wireless Adapter [Mediatek MT7610U] |

Always verify the actual chipset with 'lsusb' and/or 'lspci'!

Due to a bug in xhci subsystem other devices may not work at the moment: https://bugzilla.kernel.org/show_bug.cgi?id=202541

No support for a third party driver which is not part of the official kernel (https://www.kernel.org/)

No support for a driver which doesn't support monitor and packet injection, native - if you need this features, do a request on www.kernel.org


Not recommended WiFi chipsets:

Intel PRO/Wireless

Broadcom


Antennas
--------------

The best high frequency amplifier is a good antenna!

It is much better to achieve gain using a good antenna instead of increasing transmitter power

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


Hardware mod - see docs gpiowait.odg
--------------

LED flashes every 5 seconds 2 times if hcxpioff successfully started

Press push button at least > 5 seconds until LED turns on

Green ACT LED flashes 10 times

Raspberry Pi turned off safely and can be disconnected from power supply

Do not use hcxdumptool and hcxpioff together!


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

You must use hcxdumptool only on networks you have permission to do this, because:

* hcxdumptool is able to prevent complete wlan traffic
  (depend on selected options)

* hcxdumptool is able to capture PMKIDs from access points (only one single PMKID from an access point required)
  (use hcxpcapngtool to save them to file)

* hcxdumptool is able to capture handshakes from not connected clients (only one single M2 from the client is required)
  (use hcxpcapngtool to save them to file)

* hcxdumptool is able to capture handshakes from 5GHz clients on 2.4GHz (only one single M2 from the client is required)
  (use hcxpcapngtool to save them to file)

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
