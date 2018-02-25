hcxdumptool
==============

Small tool to capture packets from wlan devices.


Brief description
--------------

Stand-alone binary - designed to run on Raspberry Pi's.


Detailed description
--------------

| Tool           | Description                                                                                            |
| -------------- | ------------------------------------------------------------------------------------------------------ |
| hcxdumptool    | Raw socket version of wlandump-ng                                                                      |
| pioff          | Turns Raspberry Pi off via GPIO switch                                                                 |


Compile
--------------

Simply run:

```
make
make install (as super user)
```

or (with GPIO support - hardware mods required)

```
make GPIOSUPPORT=on
make GPIOSUPPORT=on install (as super user)
```


Requirements
--------------

* Linux (Recommended Arch, but other distros should work, too), Kernel >= 4.9

* libpthread and pthread-dev installed (used by hcxhashcattool)

* Raspberry Pi: additionally libwiringpi and wiringpi dev installed (Raspberry Pi GPIO support)

* Chipset must be able to run in monitor mode. Recommended: RALINK chipset (good receiver sensitivity), rt2x00 driver (stable and fast)

* Raspberry Pi (Recommended: A+ = very low power consumption or B+), but notebooks and desktops should work, too.


Tested adapters
--------------

USB ID 148f:7601 Ralink Technology, Corp. MT7601U Wireless Adapter

USB ID 148f:3070 Ralink Technology, Corp. RT2870/RT3070 Wireless Adapter

USB ID 148f:5370 Ralink Technology, Corp. RT5370 Wireless Adapter

USB ID 0bda:8187 Realtek Semiconductor Corp. RTL8187 Wireless Adapter

USB ID 0bda:8189 Realtek Semiconductor Corp. RTL8187B Wireless 802.11g 54Mbps Network Adapter


Useful scripts
--------------

| Script       | Description                                              |
| ------------ | -------------------------------------------------------- |
| bash_profile | Autostart for Raspberry Pi (copy to /root/.bash_profile) |
| pireadcard   | Back up a Pi SD card                                     |
| piwritecard  | Restore a Pi SD card                                     |
| makemonnb    | Example script to activate monitor mode                  |
| killmonnb    | Example script to deactivate monitor mode                |


Hardware mod (hcxdumptool)
--------------

LED flashes 5 times if hcxdumptool successfully started

LED flashes every 5 seconds if everything is fine

Press push button at least > 5 seconds until LED turns on (LED turns on if hcxdumptool terminates)

Green ACT LED flashes 10 times

Raspberry Pi turned off and can be disconnected from power supply

Do not use hcxdumptool and hcxpioff together!


Hardware mod (hcxpioff)
--------------

LED flashes every 10 seconds 2 times if hcxpioff successfully started

Press push button at least > 10 seconds until LED turns on (hcxpioff will shut down Raspberry Pi safely)

Green ACT LED flashes 10 times

Raspberry Pi turned off and can be disconnected from power supply

Do not use hcxdumptool or hcxpioff together!


Warning
--------------

You must use hcxdumptool only on networks you have permission to do this, because

* hcxdumptool is able to prevent complete wlan traffic

* hcxdumptool is able to capture handshakes from not connected clients (only one single M2 from the client is required)

* hcxdumptool is are able to capture handshakes from 5GHz clients on 2.4GHz (only one single M2 from the client is required)

* hcxdumptool is able to capture extended EAPOL (RADIUS, GSM-SIM, WPS)

* hcxdumptool is able to capture passwords from the wlan traffic

* hcxdumptool is able to capture plainmasterkeys from the wlan traffic

* hcxdumptool is able to capture usernames and identities from the wlan traffic
