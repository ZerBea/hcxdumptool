hcxdumptool
==============

Small tool to capture packets from wlan devices.
After capturing, upload the "uncleaned" cap here (https://wpa-sec.stanev.org/?submit)
to see if your ap or the client is vulnerable by using common wordlists.
Convert the cap to hccapx and/or to WPA-PMKID-PBKDF2 hashline (16800) with hcxpcaptool (hcxtools)
and check if wlan-key or plainmasterkey was transmitted unencrypted.


Brief description
--------------

Stand-alone binary - designed to run on Raspberry Pi's with installed Arch Linux.
It should work on other Linux systems (notebooks, desktops) and distributions, too.


Detailed description
--------------

| Tool           | Description                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------------------ |
| hcxdumptool    | Tool to run several tests to determine if access points or clients are vulnerable                      |
| pioff          | Turns Raspberry Pi off via GPIO switch                                                                 |


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

* Operatingsystem: Arch Linux (strict), Kernel >= 4.14 (strict). It should work on other Linux systems (notebooks, desktops) and distributions, too (no support for other distributions). Don't use Kernel 4.4 (rt2x00 driver regression)

* Chipset must be able to run in monitor mode and driver must support monitor mode (strict by: ip and iw). Recommended: RALINK chipset (good receiver sensitivity), rt2x00 driver (fast)

* Raspberry Pi A, B, A+, B+ (Recommended: Zero (WH) or A+ = very low power consumption or B+), but notebooks and desktops could work, too.

* GPIO hardware mod recommended
 

Adapters
--------------

* Due continuous further development of hardware components (chipsets) by VENDORs and several kernel issues (kernel >= 4.20), I decided to remove all device names (read changelog 14.04.2019).

* I recommend to study wikidevi if you consider to buy a device, to make sure driver supports monitor mode and packet injection: https://wikidevi.com

* no support for a third party driver which is not part of the official kernel (https://www.kernel.org/)

* no support for a driver which doesn't support monitor and packet injection, native - if you need this features, do a request on www.kernel.org


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


Hardware mod - see docs gpiowait.odg (hcxpioff)
--------------

LED flashes every 5 seconds 2 times if hcxpioff successfully started

Press push button at least > 5 seconds until LED turns on (hcxpioff will shut down Raspberry Pi safely)

Green ACT LED flashes 10 times

Raspberry Pi turned off and can be disconnected from power supply

Do not use hcxdumptool or hcxpioff together!


Warning
--------------

You must use hcxdumptool only on networks you have permission to do this, because:

* hcxdumptool is able to prevent complete wlan traffic
  (depends on selected options)

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

* Do not use hcxdumptool in combination with aircrack-ng, reaver, bully or other tools which takes access to the interface

* Stop all services which takes access to the physical interface (NetworkManager, wpa_supplicant,...)

* Do not use tools like macchanger, as they are useless, because hcxdumptool uses its own random mac address space
