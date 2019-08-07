hcxdumptool
==============

Small tool to capture packets from wlan devices.
After capturing, upload the "uncleaned" cap here (https://wpa-sec.stanev.org/?submit)
to see if your ap or the client is vulnerable by using common wordlists.
Convert the cap to hccapx and/or to WPA-PMKID-PBKDF2 hashline (16800) with hcxpcaptool (hcxtools)
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


Compile
--------------

Simply run:

```
make
make install (as super user)
```


Compile for Android
--------------

You need:
* Android NDK installed in your system and in path variable

* This repository cloned with all submodules (`--recursive` flag in `git clone` or `git submodules update` command run)

Just run `ndk-build` - built executables for some architectures should be created inside `libs` directory.
Copy it to your phone and enjoy.


Requirements
--------------

* Operatingsystem: Arch Linux (strict), Kernel >= 4.19 (strict). It may work on other Linux systems (notebooks, desktops) and distributions, too (no support for other distributions, no support for other operating systems). Don't use Kernel 4.4 (rt2x00 driver regression)

* Chipset must be able to run in monitor mode and driver must support monitor mode. Recommended: MEDIATEK (MT7601) or RALINK (RT2870, RT3070, RT5370) chipset 

* Raspberry Pi A, B, A+, B+, Zero (WH). (Recommended: Zero (WH) or A+, because of a very low power consumption), but notebooks and desktops may work, too.

* GPIO hardware mod recommended (push button and LED).
 

Adapters
--------------

hcxdumptool need full (monitor mode and full packet injection running all packet types) and exclusive access to the adapter! Otherwise it will not start!

The driver must support monitor mode and full packet injection, as well as ioctl() calls!

Netlink (libnl) interfaces are not supported!

Get information about VENDOR, model, chipset and driver here: https://wikidevi.com

Manufacturers do change chipsets without changing model numbers. Sometimes they add (v)ersion or (rev)vision.

This list is for information purposes only and should not be regarded as a binding presentation of the products:

| VENDOR MODEL         | ID                                                                               |
| -------------------- | -------------------------------------------------------------------------------- |
| EDIMAX EW-7711UAN    | ID 7392:7710 Edimax Technology Co., Ltd                                          |
| ALLNET ALL-WA0150N   | ID 148f:7601 Ralink Technology, Corp. MT7601U Wireless Adapter                   |
| SEMPRE WU150-1       | ID 148f:7601 Ralink Technology, Corp. MT7601U Wireless Adapter                   |
| TENDA W311U+         | ID 148f:3070 Ralink Technology, Corp. RT2870/RT3070 Wireless Adapter             |
| TP-LINK TL-WN722N v1 | ID 0cf3:9271 Qualcomm Atheros Communications AR9271 802.11n                      |
| ALFA AWUS036H        | ID 0bda:8187 Realtek Semiconductor Corp. RTL8187 Wireless Adapter                |
| RTL8821AE            | Realtek Semiconductor Co., Ltd. RTL8821AE 802.11ac PCIe Wireless Network Adapter |

Always verify the actual chipset with 'lsusb' and/or 'lspci'!

Due to a bug in xhci subsystem other devices may not work at the moment: https://bugzilla.kernel.org/show_bug.cgi?id=202541

No support for a third party driver which is not part of the official kernel (https://www.kernel.org/)

No support for a driver which doesn't support monitor and packet injection, native - if you need this features, do a request on www.kernel.org


Antennas
--------------

The best high frequency amplifier is a good antenna!

| VENDOR MODEL           | TYPE            |
| ---------------------- | --------------- |
| LOGILINK WL0097        | grid parabolic  |
| TP-LINK TL-ANT2414 A/B | panel           |
| LevelOne WAN-1112      | panel           |
| DELOCK 88806           | panel           |
| TP-LINK TL-ANT2409 A   | panel           |


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

LED turns on, if no signal received during the last past 5 seconds

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


Warning
--------------

You must use hcxdumptool only on networks you have permission to do this, because:

* hcxdumptool is able to prevent complete wlan traffic
  (depend on selected options)

* hcxdumptool is able to capture PMKIDs from access points (only one single PMKID from an access point required)
  (use hcxpcaptool to save them to file)

* hcxdumptool is able to capture handshakes from not connected clients (only one single M2 from the client is required)
  (use hcxpcaptool to save them to file)

* hcxdumptool is able to capture handshakes from 5GHz clients on 2.4GHz (only one single M2 from the client is required)
  (use hcxpcaptool to save them to file)

* hcxdumptool is able to capture passwords from the wlan traffic
  (use hcxpcaptool -E to save them to file, together with networknames)

* hcxdumptool is able to capture plainmasterkeys from the wlan traffic
  (use hcxpcaptool -P to save them to file)

* hcxdumptool is able to request and capture extended EAPOL (RADIUS, GSM-SIM, WPS)
  (hcxpcaptool will show you information about them)

* hcxdumptool is able to capture identities from the wlan traffic
  (for example: request IMSI numbers from mobile phones - use hcxpcaptool -I to save them to file)

* hcxdumptool is able to capture usernames from the wlan traffic
  (for example: user name of a server authentication - use hcxpcaptool -U to save them to file)

* Do not use a logical interface and leave the physical interface in managed mode

* Do not use hcxdumptool in combination with aircrack-ng, reaver, bully or other tools which take access to the interface

* Stop all services which take access to the physical interface (NetworkManager, wpa_supplicant,...)

* Do not use tools like macchanger, as they are useless, because hcxdumptool uses its own random mac address space
