hcxdumptool
============

A tool to capture packets from WLAN devices and to discover potential weak points within own WiFi networks by running layer 2 attacks against the WPA protocol.

General Information
--------------------

An overview of Hashcat mode 22000 - (https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2)

hcxtools - A solution for capturing WLAN traffic and conversion to hashcat formats. - (https://hashcat.net/forum/thread-6661.html)

Old but still applicable write-up by **atom** of the Hashcat forums covering a new attack on WPA/WPA2 using PMKID (https://hashcat.net/forum/thread-7717.html)

Hashcat mode 22000 write-up by **atom** of the Hashcat forums. (https://hashcat.net/forum/thread-10253.html)

What Doesn't hcxdumptool Do?
-----------------------------

* It does not crack WPA PSK related hashes. (Use Hashcat or JtR to recover the PSK.)

* It does not crack WEP. (Use the aircrack-ng suite instead.)

* It does not crack WPS. (Use Reaver or Bully instead.)

* It does not decrypt encrypted traffic. (Use tshark or Wireshark in parallel.)

* It does not record all traffic captured on the WLAN device. (Use tshark or Wireshark in parallel.)

* It does not perform Evil Twin attacks.

* It is not a honey pot.

**Unsupported:** Windows OS, macOS, Android, emulators or wrappers!

Detailed Description
---------------------

| Tool | Description |
| -------------- | ------------------------------------------------------------------------------------------------------|
| hcxdumptool | Tool to run several tests against WPA PSK to determine if ACCESS POINTs or CLIENTs are vulnerable. |
| hcxpcapngtool | Tool to convert raw PCAPNG files to Hashcat and JtR readable formats.|
| hcxhashtool | Tool to filter hashes from HC22000 files based on user input. |
| hcxpsktool | Tool to get weak PSK canidates from HC22000 files. |
| hcxeiutool | Tool to calculate wordlists based off ESSIDs gathered. |
| Hashcat/JtR | Third party tools used to infer PSK from HC22000 hash files. |

Work Flow
----------

hcxdumptool -> hcxpcapngtool -> hcxhashtool (additional hcxpsktool/hcxeiutool) -> hashcat or JtR

Requirements
-------------

* Knowledge of radio technology.
* Knowledge of electromagnetic-wave engineering.
* Detailed knowledge of 802.11 protocol.
* Detailed knowledge of key derivation functions.
* Detailed knowledge of Linux.
* Detailed knowledge of filter procedures. (Berkeley Packet Filter, capture filter, display filter, etc.)
* Operating system: Linux (recommended: kernel >= 6.4, mandatory: kernel >= 5.10)
* Recommended: Arch Linux on notebooks and desktop systems, Arch Linux Arm on Raspberry Pi >= ARMv7 systems, Raspbian OS Lite or Debian on Raspberry Pi ARMv6 systems .
* WLAN device chipset must be able to run in monitor mode. MediaTek chipsets are preferred due to active monitor mode capabilities.
* WLAN device driver must support monitor and full frame injection mode. **(MANDATORY!)**
* gcc >= 13 recommended (deprecated versions are not supported: https://gcc.gnu.org/)
* libpcap and libpcap-dev (If internal BPF compiler has been enabled.)
* Raspberry Pi A, B, A+, B+, Zero (WH). (Recommended: Zero (WH) or A+, because of a very low power consumption), but notebooks and desktops will work as well.
* GPIO hardware mod recommended (push button and LED) on Raspberry Pi
* To allow 5/6/7GHz packet injection, it is mandatory to uncomment a regulatory domain that support this: /etc/conf.d/wireless-regdom 

**If you decide to compile latest git head, make sure that your distribution is updated to it's latest version!**

**Important Notice**: If you are running Debian on ARM, it is **mandatory** to add "iomem=relaxed" to cmdline.txt to allow IO memory mapping.

Solve dependencies 
-------------------
**As mentioned in Requirements chapter!**

Install Guide
--------------
### Clone Repository
---------------------
```
git clone https://github.com/ZerBea/hcxdumptool.git
cd hcxdumptool
```

### Compile & Install
----------------------
```
make -j $(nproc)
```

Install to `/usr/bin`:
```
make install (as super user)
```

Or install to `/usr/local/bin`:
```
make install PREFIX=/usr/local (as super user)
```

On headless opearation remove -DSTATUSOUT from Makefile before compiling! The entire status display will not be compiled. That saves CPU cycles and prevent ERRORs.

It is theoretically possible to compile hcxdumptool for other systems (e.g. Android) and other distributions (e.g. KALI) and other operating systems (BSD) as well, but feature requests will be rejected.

Or Install Via Package Manager
-------------------------------

### Arch Linux
[Arch Linux](https://www.archlinux.org/) 
`pacman -S hcxdumptool`

### Arch Linux ARM
[Arch Linux ARM](https://archlinuxarm.org/) 
`pacman -S hcxdumptool`

### Black Arch
[Black Arch](https://blackarch.org/)
`pacman -S hcxdumptool`

### Raspbian (Debian, Kali, Ubuntu) release requirements >= bookworm (testing/Debian 12)  
To install use the following:  
```sudo apt-get update && sudo apt-get install make gcc```

From here, install hcxdumptool using the clone, compile, and install method mentioned earlier.
### Android (example)
Install [Android NDK](https://developer.android.com/ndk/downloads) on your system and add it to `PATH`:
```
$ ndk-build --version
GNU Make 4.3
Built for x86_64-pc-linux-gnu
Copyright (C) 1988-2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
```

Run `ndk-build` - built executables for some architectures will be created inside `libs` directory:
```
$ ndk-build
[arm64-v8a] Compile        : hcxdumptool <= hcxdumptool.c
[arm64-v8a] Executable     : hcxdumptool
[arm64-v8a] Install        : hcxdumptool => libs/arm64-v8a/hcxdumptool
[armeabi-v7a] Compile thumb  : hcxdumptool <= hcxdumptool.c
[armeabi-v7a] Executable     : hcxdumptool
[armeabi-v7a] Install        : hcxdumptool => libs/armeabi-v7a/hcxdumptool
[x86] Compile        : hcxdumptool <= hcxdumptool.c
[x86] Executable     : hcxdumptool
[x86] Install        : hcxdumptool => libs/x86/hcxdumptool
[x86_64] Compile        : hcxdumptool <= hcxdumptool.c
[x86_64] Executable     : hcxdumptool
[x86_64] Install        : hcxdumptool => libs/x86_64/hcxdumptool
```
Copy it to your phone.

Adapters
---------
* Do not expect flawless drivers on brand new hardware!

* Driver must support monitor mode and full packet injection!

* No support for prism devices! 

* WIRELESS EXTENSIONS are deprecated and not longer supported!

Get information about VENDOR, model, chipset, and driver here: https://wikidevi.wi-cat.ru/

Manufacturers do change chipsets without changing model numbers. Sometimes they add (v)ersion or (rev)vision.

Preferred chipsets come from MediaTek due to active monitor mode being very reliable. (Important notice: Massive problems with MT76 USB 3.0 devices if connected to some USB 3.0 ports!)

Some device and driver tests are here: https://github.com/ZerBea/hcxdumptool/discussions/361

**Always verify the actual chipset with 'lsusb' and/or 'lspci'!**

No support for a third party driver which is not part of the official Linux kernel (https://www.kernel.org/) <br /> Report related issues to the site, from which you downloaded the driver.

No support for a driver which doesn't support monitor mode and full frame injection natively <br /> If you need these features, do a request on www.kernel.org

Recommended WiFi chipsets:

* Ralink

* MediaTek

Not recommended WiFi chipsets:

* Broadcom (neither monitor mode nor frame injection by official Linux kernel)

* Qualcomm (no frame injection by official Linux kernel)

* Intel (monitor mode and frame injection problems)

More information about possible issues or limitations:

https://bugzilla.kernel.org

https://wireless.wiki.kernel.org/en/users/Drivers/ath10k

https://github.com/morrownr/USB-WiFi/issues/314

Antennas
---------

The best high frequency amplifier is a good antenna!

It is much better to achieve gain using a good antenna instead of increasing transmitter power.

| VENDOR MODEL           | TYPE            |
| ---------------------- | --------------- |
| LOGILINK WL0097        | Grid Parabolic  |
| TP-LINK TL-ANT2414 A/B | Panel           |
| LevelOne WAN-1112      | Panel           |
| DELOCK 88806           | Panel           |
| TP-LINK TL-ANT2409 A   | Panel           |


GPS devices (NMEA 0183 protocol)
---------------------------------

| VENDOR MODEL                | TYPE            |
| --------------------------- | --------------- |
| NAVILOCK NL-701US           | USB             |
| JENTRO BT-GPS-8 activepilot | BLUETOOTH       |


Useful Scripts
---------------

| Script       | Description                                              |
| ------------ | -------------------------------------------------------- |
| bash_profile | Autostart for Raspberry Pi (copy to /root/.bash_profile) |
| pireadcard   | Back up a Pi SD card                                     |
| piwritecard  | Restore a Pi SD card                                     |
| stopnm       | Example script to start NetworkManager                   |
| startnm      | Example script to stop NetworkManager                    |


Hardware mod - See docs gpiowait.odg (hcxdumptool)
---------------------------------------------------

The LED will flash every 10 seconds if everything is fine and signals are received correctly.

Press push button at least > 10 seconds until LED turns on (also LED turns on if hcxdumptool terminates)

Raspberry Pi turned off and can be disconnected from power supply

Press push button at least 10 seconds and Raspberry Pi turned off safely and can be disconnected from power supply

PCAPNG Option Codes (Section Header Block)
-------------------------------------------

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
--------

You might expect me to recommend that everyone should be using hcxdumptool/hcxtools. But the fact of the matter is, hcxdumptool/hcxtools is NOT recommended to be used by inexperienced users or newbies.

If you are not familiar with Linux in general or you do not have at least a basic level of knowledge as mentioned in section "Requirements", hcxdumptool/hcxtools is probably not what you are looking for.
However, if you have that knowledge hcxdumptool/hcxtools can do magic for you.

The entire toolkit (hcxdumptool and hcxtools) is designed to be an analysis toolkit. 

**It should only be used in a 100% controlled environment!**

If you can't control the environment it is absolutely mandatory to set the BPF.

Everything is requested/stored by default and unwanted information must be filtered out by option/filter or later on (offline).

You must use hcxdumptool only on networks you have permission to do this and if you know what you are doing, because:

* hcxdumptool is able to prevent complete WLAN traffic transmission. (Depending on selected options.)

* hcxdumptool is able to capture PMKIDs from access points. (Only one single PMKID from an access point is required. Use hcxpcapngtool to convert them to a format Hashcat or JtR understands.)

* hcxdumptool is able to capture handshakes from non-connected clients. (Only one single M2 from the client is required. Use hcxpcapngtool to convert them to a format Hashcat or JtR understands.)

* hcxdumptool is able to capture handshakes from 5/6GHz clients on 2.4GHz. (Only one single M2 from the client is required. Use hcxpcapngtool to to a format Hashcat or JtR understands.)

* hcxdumptool is able to capture passwords from the WLAN traffic. (Use hcxpcapngtool -R to save them to file, or together with networknames [-E].)

* hcxdumptool is able to request and capture extended EAPOL (RADIUS, GSM-SIM, WPS. hcxpcapngtool will show you information about them.)

* hcxdumptool is able to capture identities from the WLAN traffic. (Example: Request IMSI numbers from mobile phones - use hcxpcapngtool -I to save them to file.)

* hcxdumptool is able to capture usernames from the WLAN traffic. (Example: User name of a server authentication - use hcxpcapngtool -U to save them to file.)

* Do not use a logical interface and leave the physical interface in managed mode!

* Do not use hcxdumptool in combination with the aircrack-ng suite, Reaver, Bully or other tools which take access to the interface!

* Stop all services which take access to the physical interface! (NetworkManager, wpa_supplicant,...)

* Do not use tools like macchanger as they are useless since hcxdumptool uses its own random MAC address space.

* Do not merge PCAPNG dumpfiles because that will destroy custom block hash assignments!

* Capture format PCAPNG is compatible with Wireshark and tshark.

Useful Links
--------------

https://pcapng.com/

https://www.kernel.org/doc/html/latest/

https://www.kernel.org/doc/html/latest/bpf/index.html

https://www.freecodecamp.org/news/the-linux-commands-handbook/

https://en.wikipedia.org/wiki/Wpa2

https://en.wikipedia.org/wiki/802.11_Frame_Types

https://en.wikipedia.org/wiki/IEEE_802.11i-2004

