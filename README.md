hcxdumptool
==============

Small tool to capture packets from wlan devices and to discover potential weak points within own WiFi networks by running layer 2 attacks against WPA protocol  
(e.g.: PreSharedKey or PlainMasterKey is transmitted unencrypted by a CLIENT).


Brief description
--------------

Stand-alone binaries - designed to run on Arch Linux, but other Linux distributions should work, too.

Capture format pcapng is compatible to Wireshark and tshark.

Read this post: hcxtools - solution for capturing wlan traffic and conversion to hashcat formats (https://hashcat.net/forum/thread-6661.html)

Read this post: New attack on WPA/WPA2 using PMKID (https://hashcat.net/forum/thread-7717.html)

Read this post: Hash mode 22000 explained (https://hashcat.net/forum/thread-10253.html)

Read this wiki: https://hashcat.net/wiki/doku.php?id=cracking_wpawpa2

Unsupported: Windows OS, macOS, Android, emulators or wrappers!


What doesn't hcxdumptool do
--------------

it does not crack WPA PSK related hashes (use hashat or JtR to recover the PSK)

it does not crack WEP (use aircrack-ng instead)

it does not crack WPS (use reaver or bully instead)

it does not decrypt encrypted traffic (use Wireshark in parallel)

it does not record entire traffic (use tshark or Wireshark in parallel)

it does not perform Evil Twin attacks

it is not a honey pot


Detailed description
--------------

| Tool           | Description                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------------------ |
| hcxdumptool    | Tool to run several tests against WPA PSK to determine if ACCESS POINTs or CLIENTs are vulnerable      |


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

Solve dependencies 
-------------- 
as mentioned in Requirements chapter


Compile & install
--------------
```
make
```

install to `/usr/bin`:
```
make install (as super user)
```

or install to `/usr/local/bin`:
```
make install PREFIX=/usr/local (as super user)
```

Or install via package manager
--------------

### Arch Linux
[Arch Linux](https://www.archlinux.org/) 
`pacman -S hcxdumptool`

### Arch Linux ARM
[Arch Linux ARM ](https://archlinuxarm.org/) 
`pacman -S hcxdumptool`

### Black Arch
[Black Arch](https://blackarch.org/) is an Arch Linux-based penetration testing distribution for penetration testers and security researchers  
`pacman -S hcxdumptool`

### Debian (e.g. Kali, Ubuntu) release requirements >= bookworm (testing/Debian 12)  
To install use the following:  
`apt-get install make gcc`


Compile for Android
--------------

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
Copy it to your phone and enjoy.


Requirements
--------------

* knowledge of radio technology
* knowledge of electromagnetic-wave engineering
* detailed knowledge of 802.11 protocol
* detailed knowledge of key derivation functions
* detailed knowledge of Linux
* detailed knowledge of filter procedures (Berkeley Packet Filter, capture filter, display filter)
* operating system: Linux (recommended: kernel >= 6.1, mandatory: kernel >= 5.10)
* recommended: Arch Linux on notebooks and desktop systems, Arch Linux Arm on Raspberry Pi >= ARMv7 systems, Raspbian OS Lite or Debian on Raspberry Pi ARMv6 systems 
* chipset must be able to run in monitor mode. Recommended: MediaTek chipsets (due to active monitor mode capabilities)
* driver must (mandatory) support monitor and full frame injection mode
* gcc >= 12 recommended (deprecated versions are not supported: https://gcc.gnu.org/)
* Raspberry Pi A, B, A+, B+, Zero (WH). (Recommended: Zero (WH) or A+, because of a very low power consumption), but notebooks and desktops will work, too.
* GPIO hardware mod recommended (push button and LED) on Raspberry Pi
* to allow 5/6GHz packet injection, it is mandatory to uncomment a regulatory domain that support this: /etc/conf.d/wireless-regdom 

If you decide to compile latest git head, make sure that your distribution is updated to latest version.

Important notice: running Debian on arm it is mandatory to add "iomem=relaxed" to cmdline.txt to allow io memory mapping


Adapters
--------------

Driver must support (mandatory) monitor mode and full packet injection

WIRELESS EXTENSIONS are deprecated and no longer supported

Get information about VENDOR, model, chipset and driver here: https://wikidevi.wi-cat.ru/

Manufacturers do change chipsets without changing model numbers. Sometimes they add (v)ersion or (rev)vision.

Preferred chipsets MediaTek due to active monitor mode feature

Always verify the actual chipset with 'lsusb' and/or 'lspci'!

No support for a third party driver which is not part of the official Linux kernel (https://www.kernel.org/) <br /> Report related issues to the site, from which you downloaded the driver

No support for a driver which doesn't support monitor mode and full frame injection natively <br /> If you need these features, do a request on www.kernel.org

No support for prism devices.

Not recommended WiFi chipsets:

* Broadcom (neither monitor mode nor frame injection by official Linux kernel)

* Qualcomm (no frame injection by official Linux kernel)

more information about possible issues or limitations:

https://bugzilla.kernel.org

https://wireless.wiki.kernel.org/en/users/Drivers/ath10k

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


GPS devices (NMEA 0183 protocol)
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
| stopnm       | Example script to start NetworkManager                   |
| startnm      | Example script to stop NetworkManager                    |


Hardware mod - see docs gpiowait.odg (hcxdumptool)
--------------

LED flashes every 10 seconds if everything is fine and signals are received

Press push button at least > 10 seconds until LED turns on (also LED turns on if hcxdumptool terminates)

Raspberry Pi turned off and can be disconnected from power supply


Hardware mod - see docs gpiowait.odg
--------------

Press push button at least 10 seconds and Raspberry Pi turned off safely and can be disconnected from power supply


Procedure
--------------

first run hcxdumptool -L to get information about suitable interfaces

run hcxdumptool [-i \<interface\>] [--rcascan=p] to retrieve information about access points


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

hcxdumptool is designed to be an analysis tool. 

It should only be used in a 100% controlled environment(!).

If you can't control the environment it is absolutely mandatory to set the BPF.

Everything is requested/stored by default and unwanted information must be filtered out by option/filter or later on (offline)! 

You must use hcxdumptool only on networks you have permission to do this and if you know what you are doing, because:

* hcxdumptool is able to prevent complete wlan traffic
  (depend on selected options)

* hcxdumptool is able to capture PMKIDs from access points (only one single PMKID from an access point required)
  (use hcxpcapngtool to convert them to a format hashcat and/Or JtR understand)

* hcxdumptool is able to capture handshakes from not connected clients (only one single M2 from the client is required)
  (use hcxpcapngtool to convert them to a format hashcat and/Or JtR understand)

* hcxdumptool is able to capture handshakes from 5/6GHz clients on 2.4GHz (only one single M2 from the client is required)
  (use hcxpcapngtool to to a format hashcat and/Or JtR understand)

* hcxdumptool is able to capture passwords from the wlan traffic
  (use hcxpcapngtool -R to save them to file, or together with networknames [-E])

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

* Do not merge (pcapng) dumpfiles because that destroys custom block hash assignments
