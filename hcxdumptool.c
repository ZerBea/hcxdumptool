#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#if defined (_POSIX_VERSION)
#include <fcntl.h>
#endif
#include <getopt.h>
#include <inttypes.h>
#include <linux/filter.h>
#include <linux/genetlink.h>
#include <linux/if_packet.h>
#include <linux/limits.h>
#include <linux/nl80211.h>
#include <linux/rtnetlink.h>
#include <linux/version.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#if defined (_POSIX_VERSION)
#include <sys/stat.h>
#include <sys/utsname.h>
#include <termios.h>
#endif
#include "include/types.h"
#include "include/hcxdumptool.h"
#include "include/raspberry.h"
#include "include/wireless-lite.h"
#include "include/radiotap.h"
#include "include/ieee80211.h"
#include "include/pcapng.h"
/*===========================================================================*/
/*
static void debugprint();
{
int x;

for(int x = 0; x < 6; x++) printf("%02x", macfrx->addr2[x]);
printf(" ");
for(int x = 0; x < 6; x++) printf("%02x", macfrx->addr1[x]);
printf(" sende eapol m1\n");

return;
}
*/
/*===========================================================================*/
/* global var */
static bool deauthenticationflag = true;
static bool proberequestflag = true;
static bool associationflag = true;
static bool reassociationflag = true;

static u8 wanteventflag = 0;

static int gpiostatusled = 0;
static int gpiobutton = 0;

static pid_t hcxpid = 0;

static unsigned int seed = 7;

static int fd_socket_nl = 0;
static int fd_socket_rt = 0;
static int fd_socket_unix = 0;
static int fd_socket_rx = 0;
static int fd_socket_tx = 0;
static int fd_timer1 = 0;
static int fd_pcapng = 0;
#ifdef NMEAOUT
static int fd_gps = 0;
static int fd_hcxpos = 0;
#endif
static struct sock_fprog bpf = { 0 };

static int ifaktindex = 0;
static u8 ifaktstatus = 0;
static u8 ifakttype = 0;

static frequencylist_t *ifaktfrequencylist = NULL;
static char ifaktname[IF_NAMESIZE] = { 0 };
static u8 ifakthwmac[ETH_ALEN] = { 0 };

static u16 nlfamily = 0;
static u32 nlseqcounter = 1;

static size_t ifpresentlistcounter = 0;

static size_t scanlistindex = 0;
static frequencylist_t *scanlist = NULL;

static interface_t *ifpresentlist;

static aplist_t* aplist = NULL;
static aprglist_t* aprglist = NULL;
static clientlist_t* clientlist = NULL;
static maclist_t* maclist = NULL;
static u64 lifetime = 0;
static u32 ouiaprg = 0;
static u32 nicaprg = 0;
static u32 ouiclientrg = 0;
static u32 nicclientrg = 0;
static u64 replaycountrg = 0;

static struct timespec tspecakt = { 0 };
static u64 tsakt = 0;
static u64 tsfirst = 0;
static u64 tshold = 0;
static u64 tottime = 0;
static u64 timehold = TIMEHOLD;
static int timerwaitnd = TIMER_EPWAITND;

static u64 errorcountmax = ERROR_MAX;
static u64 errorcount = 0;
static u32 watchdogcountmax = WATCHDOG_MAX;
static u32 attemptapmax = ATTEMPTAP_MAX;
static u32 attemptclientmax = ATTEMPTCLIENT_MAX;

static u64 packetcount = 1;

static size_t beaconindex = 0;
static size_t proberesponseindex = 0;

static u32 beacontxmax = BEACONTX_MAX;
static u32 proberesponsetxmax = PROBERESPONSETX_MAX;

static u64 beacontimestamp = 1;

static rth_t *rth = NULL;
static ssize_t packetlen = 0;
static u8 *packetptr = NULL;
static u16 ieee82011len = 0;
static u8 *ieee82011ptr = NULL;
static u16 payloadlen = 0;
static u8 *payloadptr = NULL;
static ieee80211_mac_t *macfrx = NULL;
static u8 *llcptr = NULL;
static ieee80211_llc_t *llc = NULL;
static u16 eapauthlen = 0;
static ieee80211_eapauth_t *eapauth;
static u16 eapauthpllen = 0;
static u8 *eapauthplptr = NULL;
static u16 eapolpllen = 0;
static u8 *eapolplptr = NULL;
static ieee80211_wpakey_t *wpakey;
static ieee80211_pmkid_t *pmkid;
static u16 keyinfo = 0;
static u8 kdv = 0;

static enhanced_packet_block_t *epbhdr = NULL;
#ifdef NMEAOUT
static ssize_t nmealen = 0;
static ssize_t gprmclen = 0;
static ssize_t gpggalen = 0;
#endif
static ieee80211_mac_t *macftx = NULL;
static u16 seqcounter1 = 1; /* deauthentication / disassociation */
static u16 seqcounter2 = 1; /* proberequest authentication association */
static u16 seqcounter3 = 1; /* probereresponse authentication response 3 */
static u16 seqcounter4 = 1; /* beacon */
/*---------------------------------------------------------------------------*/
static const uint8_t beacondata[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: DS Parameter set: Current Channel: 1 */
0x03, 0x01, 0x01,
/* Tag: TIM Information */
0x05, 0x04, 0x00, 0x01, 0x00, 0x00,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* Tag: RSN Information CCM CCM PSK */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x00, 0x00,
};
#define BEACONDATA_SIZE sizeof(beacondata)
/*---------------------------------------------------------------------------*/
static const uint8_t proberesponsedata[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: DS Parameter set: Current Channel: 1 */
0x03, 0x01, 0x01,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* Tag: RSN Information CCM CCM PSK */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x00, 0x00,
};
#define PROBERESPONSEDATA_SIZE sizeof(proberesponsedata)
/*---------------------------------------------------------------------------*/
static const uint8_t proberequest_undirected_data[] =
{
/* Tag: Wildcard */
0x00, 0x00,
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c
};
#define PROBEREQUEST_UNDIRECTED_SIZE sizeof(proberequest_undirected_data)
/*---------------------------------------------------------------------------*/
static const uint8_t authenticationrequestdata[] =
{
0x00, 0x00, 0x01, 0x00, 0x00, 0x00
};
#define AUTHENTICATIONREQUEST_SIZE sizeof(authenticationrequestdata)
/*---------------------------------------------------------------------------*/
static const uint8_t authenticationresponsedata[] =
{
0x00, 0x00, 0x02, 0x00, 0x00, 0x00
};
#define AUTHENTICATIONRESPONSE_SIZE sizeof(authenticationresponsedata)
/*---------------------------------------------------------------------------*/
static const uint8_t reassociationrequestdata[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* RSN information AES PSK (WPA2) */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x04, /* pairwise cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x02, /* AKM */
0x80, 0x00,
/* RM Enabled Capabilities */
0x46, 0x05, 0x7b, 0x00, 0x02, 0x00, 0x00,
/* Supported Operating Classes */
0x3b, 0x04, 0x51, 0x51, 0x53, 0x54
};
#define REASSOCIATIONREQUEST_SIZE sizeof(reassociationrequestdata)
/*---------------------------------------------------------------------------*/
static const uint8_t associationrequestcapa[] =
{
0x31, 0x04, 0x05, 0x00
};
#define ASSOCIATIONREQUESTCAPA_SIZE sizeof(associationrequestcapa)
/*---------------------------------------------------------------------------*/
static const uint8_t associationrequestdata[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* RSN information AES PSK (WPA2) */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x04, /* pairwise cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x02, /* AKM */
0x80, 0x00,
/* RM Enabled Capabilities */
0x46, 0x05, 0x7b, 0x00, 0x02, 0x00, 0x00,
/* Supported Operating Classes */
0x3b, 0x04, 0x51, 0x51, 0x53, 0x54
};
#define ASSOCIATIONREQUEST_SIZE sizeof(associationrequestdata)
/*---------------------------------------------------------------------------*/
static const uint8_t associationresponsedata[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* Tag: Extended Capabilities (8 octets) */
//0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
};
#define ASSOCIATIONRESPONSEDATA_SIZE sizeof(associationresponsedata)
/*---------------------------------------------------------------------------*/
static uint8_t eapolm1data[] =
{
/* LLC */
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
/* M1 WPA2 */
0x02,
0x03,
0x00, 0x5f,
0x02,
0x00, 0x8a,
0x00, 0x10,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00
};
#define EAPOLM1DATA_SIZE sizeof(eapolm1data)
/*---------------------------------------------------------------------------*/
/* interface bit rate */
static const uint8_t legacy241mbdata[] =
{
0x10, 0x00,
0x5a, 0x80,
0x0c, 0x00,
0x01, 0x80,
0x05, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00
};
#define LEGACYXXXMB_SIZE sizeof(legacy241mbdata)
/*---------------------------------------------------------------------------*/
static const uint8_t legacy56mbdata[] =
{
0x10, 0x00,
0x5a, 0x80,
0x0c, 0x00,
0x01, 0x80,
0x05, 0x00, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x00
};
/*---------------------------------------------------------------------------*/
static u8 macaprg[ETH_ALEN] = { 0 };
static u8 macclientrg[ETH_ALEN +2] = { 0 };
static u8 anoncerg[32] = { 0 };
static u8 snoncerg[32] = { 0 };
static char weakcandidate[PSK_MAX];
static char timestring[16];

static char country[3];


static authseqakt_t authseqakt = { 0 };

static u8 nltxbuffer[NLTX_SIZE] = { 0 };
static u8 nlrxbuffer[NLRX_SIZE] = { 0 };

static u8 epb[PCAPNG_SNAPLEN * 2] = { 0 };
static u8 epbown[WLTXBUFFER] = { 0 };
static u8 wltxbuffer[WLTXBUFFER] = { 0 };
static u8 wltxnoackbuffer[WLTXBUFFER] = { 0 };

#ifdef NMEAOUT
static char nmeabuffer[NMEA_SIZE] = { 0 };
static char gpwpl[NMEA_MSG_MAX] = { 0 };
static char gprmc[NMEA_MSG_MAX] = { 0 };
static char gpgga[NMEA_MSG_MAX] = { 0 };
static char gptxt[NMEA_MSG_MAX] = { 0 };
#endif

static char rtb[RTD_LEN] = { 0 };
/*===========================================================================*/
/*===========================================================================*/
/* status print */
static void show_interfacecapabilities2(void)
{
static size_t i;
static const char *po = "N/A";
static const char *mode = "-";
static frequencylist_t *iffreql;

for(i = 0; i < ifpresentlistcounter; i++)
	{
	if((ifpresentlist + i)->index != ifaktindex) continue;
	fprintf(stdout, "\ninterface information:\n\nphy idx hw-mac       virtual-mac  m ifname           driver (protocol)\n"
			"---------------------------------------------------------------------------------------------\n");
	if(((ifpresentlist + i)->type & IF_HAS_NLWEXT) == IF_HAS_NLWEXT) po = "NETLINK & WIRELESS EXTENSIONS";
	else if(((ifpresentlist + i)->type & IF_HAS_NETLINK) == IF_HAS_NETLINK) po = "NETLINK";
	else if(((ifpresentlist + i)->type & IF_HAS_WEXT) == IF_HAS_WEXT) po = "WIRELESS EXTENSIONS";
	if(((ifpresentlist + i)->type & IFTYPEMONACT) == IFTYPEMONACT) mode = "*";
	else if(((ifpresentlist + i)->type & IFTYPEMON) == IFTYPEMON) mode = "+";
	fprintf(stdout, "%3d %3d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s %-*s %s (%s)\n", (ifpresentlist + i)->wiphy, (ifpresentlist + i)->index,
		(ifpresentlist + i)->hwmac[0], (ifpresentlist + i)->hwmac[1], (ifpresentlist + i)->hwmac[2], (ifpresentlist + i)->hwmac[3], (ifpresentlist + i)->hwmac[4], (ifpresentlist + i)->hwmac[5],
		(ifpresentlist + i)->vimac[0], (ifpresentlist + i)->vimac[1], (ifpresentlist + i)->vimac[2], (ifpresentlist + i)->vimac[3], (ifpresentlist + i)->vimac[4], (ifpresentlist + i)->vimac[5],
		mode, IF_NAMESIZE, (ifpresentlist + i)->name, (ifpresentlist + i)->driver, po);
	iffreql = (ifpresentlist + i)->frequencylist;
	fprintf(stdout, "\n\navailable frequencies: frequency [channel] tx-power of Regulatory Domain: %s\n", country);
	for(i = 0; i < FREQUENCYLIST_MAX; i++)
		{
		if((iffreql + i)->frequency == 0) break;
		if(i % 4 == 0) fprintf(stdout, "\n");
		else  fprintf(stdout, "\t");
		if((iffreql + i)->status == 0) fprintf(stdout, "%6d [%3d] %.1f dBm", (iffreql + i)->frequency, (iffreql + i)->channel, 0.01 *(iffreql + i)->pwr);
		else fprintf(stdout, "%6d [%3d] disabled", (iffreql + i)->frequency, (iffreql + i)->channel);
		}
	fprintf(stdout, "\n");
	fprintf(stdout, "\n\nscan frequencies: frequency [channel] of Regulatory Domain: %s\n", country);
	for(i = 0; i < FREQUENCYLIST_MAX; i++)
		{
		if((scanlist + i)->frequency == 0) break;
		if(i % 5 == 0) fprintf(stdout, "\n");
		else  fprintf(stdout, "\t");
		fprintf(stdout, "%6d [%3d]", (scanlist + i)->frequency, (scanlist + i)->channel);
		}
	fprintf(stdout, "\n");



	}
return;
}
/*---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
static void show_interfacecapabilities(void)
{
static size_t i;
static const char *po = "N/A";
static const char *mode = "-";
static frequencylist_t *iffreql;

for(i = 0; i < ifpresentlistcounter; i++)
	{
	if((ifpresentlist + i)->index != ifaktindex) continue;
	fprintf(stdout, "\ninterface information:\n\nphy idx hw-mac       virtual-mac  m ifname           driver (protocol)\n"
			"---------------------------------------------------------------------------------------------\n");
	if(((ifpresentlist + i)->type & IF_HAS_NLWEXT) == IF_HAS_NLWEXT) po = "NETLINK & WIRELESS EXTENSIONS";
	else if(((ifpresentlist + i)->type & IF_HAS_NETLINK) == IF_HAS_NETLINK) po = "NETLINK";
	else if(((ifpresentlist + i)->type & IF_HAS_WEXT) == IF_HAS_WEXT) po = "WIRELESS EXTENSIONS";
	if(((ifpresentlist + i)->type & IFTYPEMONACT) == IFTYPEMONACT) mode = "*";
	else if(((ifpresentlist + i)->type & IFTYPEMON) == IFTYPEMON) mode = "+";
	fprintf(stdout, "%3d %3d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s %-*s %s (%s)\n", (ifpresentlist + i)->wiphy, (ifpresentlist + i)->index,
		(ifpresentlist + i)->hwmac[0], (ifpresentlist + i)->hwmac[1], (ifpresentlist + i)->hwmac[2], (ifpresentlist + i)->hwmac[3], (ifpresentlist + i)->hwmac[4], (ifpresentlist + i)->hwmac[5],
		(ifpresentlist + i)->vimac[0], (ifpresentlist + i)->vimac[1], (ifpresentlist + i)->vimac[2], (ifpresentlist + i)->vimac[3], (ifpresentlist + i)->vimac[4], (ifpresentlist + i)->vimac[5],
		mode, IF_NAMESIZE, (ifpresentlist + i)->name, (ifpresentlist + i)->driver, po);
	iffreql = (ifpresentlist + i)->frequencylist;
	fprintf(stdout, "\n\navailable frequencies: frequency [channel] tx-power of Regulatory Domain: %s\n", country);
	for(i = 0; i < FREQUENCYLIST_MAX; i++)
		{
		if((iffreql + i)->frequency == 0) break;
		if(i % 4 == 0) fprintf(stdout, "\n");
		else  fprintf(stdout, "\t");
		if((iffreql + i)->status == 0) fprintf(stdout, "%6d [%3d] %.1f dBm", (iffreql + i)->frequency, (iffreql + i)->channel, 0.01 *(iffreql + i)->pwr);
		else fprintf(stdout, "%6d [%3d] disabled", (iffreql + i)->frequency, (iffreql + i)->channel);
		}
	fprintf(stdout, "\n");
	}
return;
}
/*---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
static void show_interfacelist(void)
{
static size_t i;
static const char *po = "N/A";
static const char *mode = "-";

fprintf(stdout, "\navailable wlan devices:\n\nphy idx hw-mac       virtual-mac  m ifname           driver (protocol)\n"
		"---------------------------------------------------------------------------------------------\n");
for(i = 0; i < ifpresentlistcounter; i++)
	{
	if(((ifpresentlist + i)->type & IF_HAS_NLWEXT) == IF_HAS_NLWEXT) po = "NETLINK & WIRELESS EXTENSIONS";
	else if(((ifpresentlist + i)->type & IF_HAS_NETLINK) == IF_HAS_NETLINK) po = "NETLINK";
	else if(((ifpresentlist + i)->type & IF_HAS_WEXT) == IF_HAS_WEXT) po = "WIRELESS EXTENSIONS";
	if(((ifpresentlist + i)->type & IFTYPEMONACT) == IFTYPEMONACT) mode = "*";
	else if(((ifpresentlist + i)->type & IFTYPEMON) == IFTYPEMON) mode = "+";
	fprintf(stdout, "%3d %3d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s %-*s %s (%s)\n", (ifpresentlist + i)->wiphy, (ifpresentlist + i)->index,
		(ifpresentlist + i)->hwmac[0], (ifpresentlist + i)->hwmac[1], (ifpresentlist + i)->hwmac[2], (ifpresentlist + i)->hwmac[3], (ifpresentlist + i)->hwmac[4], (ifpresentlist + i)->hwmac[5],
		(ifpresentlist + i)->vimac[0], (ifpresentlist + i)->vimac[1], (ifpresentlist + i)->vimac[2], (ifpresentlist + i)->vimac[3], (ifpresentlist + i)->vimac[4], (ifpresentlist + i)->vimac[5],
		mode, IF_NAMESIZE, (ifpresentlist + i)->name, (ifpresentlist + i)->driver, po);
	}

fprintf(stdout, "\n"
		"* active monitor mode available\n"
		"+ monitor mode available\n"
		"- no monitor mode available\n");
return;
}
/*---------------------------------------------------------------------------*/
static inline void show_realtime_rca(void)
{
static size_t i;
static size_t p;
static time_t tvlast;
static char *pmdef = " ";
static char *pmok = "+";
static char *ar;
static char *ak;

system("clear");
sprintf(&rtb[0], "  CHA  FREQ    LAST   R A    MAC-AP    ESSID                 SCAN-FREQUENCY: %6u\n"
	"------------------------------------------------------------------------------------\n", (scanlist + scanlistindex)->frequency);
p = strlen(rtb);
i = 0;
for(i = 0; i < 40 ; i++)
	{
	if((aplist + i)->tsakt == 0) break;
	if(((aplist +i)->status & AP_IN_RANGE) == AP_IN_RANGE) ar = pmok;
	else ar = pmdef;
	if(((aplist +i)->ie.flags & APAKM_MASK) != 0) ak = pmok;
	else ak = pmdef;
	tvlast = (aplist + i)->tsakt / 1000000000;
	strftime(timestring, 32, "%H:%M:%S", localtime(&tvlast));

	sprintf(&rtb[p], " [%3d %5d] %s %s %s %02x%02x%02x%02x%02x%02x %.*s\n",
			(aplist + i)->ie.channel, (aplist + i)->count, timestring, ar, ak,
			(aplist + i)->macap[0], (aplist + i)->macap[1], (aplist + i)->macap[2], (aplist + i)->macap[3], (aplist + i)->macap[4], (aplist + i)->macap[5],
			(aplist + i)->ie.essidlen, (aplist + i)->ie.essid);
	p = strlen(rtb);
	}
rtb[p] = 0;
fprintf(stdout, "%s", rtb);
return;
}
/*---------------------------------------------------------------------------*/
#ifdef STATUSOUT
static inline void show_realtime(void)
{
static size_t i;
static size_t p;
static size_t pa;
static char *pmdef = " ";
static char *pmok = "+";
static char *ps;
static char *ms;
static char *ak;
static char *ar;

system("clear");
sprintf(&rtb[0], "  CHA  R P M A    MAC-AP    ESSID (last seen on top)         SCAN-FREQUENCY: %6u\n"
	"------------------------------------------------------------------------------------\n", (scanlist + scanlistindex)->frequency);
p = strlen(rtb);
i = 0;
pa = 0;
for(i = 0; i < 20 ; i++)
	{
	if((aplist + i)->tsakt == 0) break;
	if(((aplist +i)->status & AP_PMKID) == AP_PMKID) ps = pmok;
	else ps = pmdef;
	if(((aplist +i)->status & AP_EAPOL_M3) == AP_EAPOL_M3) ms = pmok;
	else ms = pmdef;
	if(((aplist +i)->ie.flags & APAKM_MASK) != 0) ak = pmok;
	else ak = pmdef;
	if(((aplist +i)->status & AP_IN_RANGE) == AP_IN_RANGE) ar = pmok;
	else ar = pmdef;
	sprintf(&rtb[p], " [%3d] %s %s %s %s %02x%02x%02x%02x%02x%02x %.*s\n",
			(aplist + i)->ie.channel, ar, ps, ms, ak,
			(aplist + i)->macap[0], (aplist + i)->macap[1], (aplist + i)->macap[2], (aplist + i)->macap[3], (aplist + i)->macap[4], (aplist + i)->macap[5],
			(aplist + i)->ie.essidlen, (aplist + i)->ie.essid);
	p = strlen(rtb);
	pa++;
	}
for(i = 0; i < (22 - pa); i++) rtb[p++] = '\n';
sprintf(&rtb[p], "  M2R    MAC-AP     MAC-CLIENT  ESSID (last seen on top)\n"
	"------------------------------------------------------------------------------------\n");
p = strlen(rtb);
for(i = 0; i < 20; i++)
	{
	if((clientlist + i)->tsakt == 0) break;
	if(((clientlist + i)->status & CLIENT_EAPOL_M2) == CLIENT_EAPOL_M2) ms = pmok;
	else ms = pmdef;
	sprintf(&rtb[p], "   %s  %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %.*s\n",
			ms,
			(clientlist + i)->macap[0], (clientlist + i)->macap[1], (clientlist + i)->macap[2], (clientlist + i)->macap[3], (clientlist + i)->macap[4], (clientlist + i)->macap[5],
			(clientlist + i)->macclient[0], (clientlist + i)->macclient[1], (clientlist + i)->macclient[2], (clientlist + i)->macclient[3], (clientlist + i)->macclient[4], (clientlist + i)->macclient[5],
			(clientlist + i)->ie.essidlen, (clientlist + i)->ie.essid);
	p = strlen(rtb);
	}
rtb[p] = 0;
fprintf(stdout, "%s", rtb);
return;
}
#endif
/*===========================================================================*/
/* frequency handling */
/*---------------------------------------------------------------------------*/
static u32 channel_to_frequency(u16 channel, u16 band)
{
if(channel <= 0) return 0;
switch(band)
	{
	case NL80211_BAND_2GHZ:
	if(channel == 14) return 2484;
	else if (channel < 14) return 2407 + (channel * 5);
	break;

	case NL80211_BAND_5GHZ:
	if(channel >= 182 && channel <= 196) return 4000 + (channel * 5);
	else return 5000 + channel * 5;
	break;

	case NL80211_BAND_6GHZ:
	if(channel == 2) return 5935;
	if(channel <= 233) return 5950 + (channel * 5);
	break;

	case NL80211_BAND_60GHZ:
	if(channel < 7) return 56160 + (channel * 2160);
	break;

	case NL80211_BAND_S1GHZ:
	return 902000 + (channel * 500);
	}
return 0;
}
/*---------------------------------------------------------------------------*/
static u16 frequency_to_channel(u32 frequency)
{
if(frequency == 2484) return 14;
else if(frequency < 2484) return (frequency - 2407) / 5;
else if(frequency >= 4910 && frequency <= 4980) return (frequency - 4000) / 5;
else if(frequency < 5925) return (frequency - 5000) / 5;
else if(frequency == 5935) return 2;
else if(frequency <= 45000) return (frequency - 5950) / 5;
else if(frequency >= 58320 && frequency <= 70200) return (frequency - 56160) / 2160;
else return 0;
}
/*===========================================================================*/
#ifdef NMEAOUT
static void writegpwpl(size_t i)
{
static ssize_t p1;
static ssize_t p2;
static size_t c;
static u8 cs;
static char lookuptable[] = { '0', '1', '2','3','4','5','6','7','8','9','a','b','c','d','e','f' };

if(gprmclen == 0) return;
if(write(fd_hcxpos, gprmc, gprmclen) != gprmclen) errorcount++;
if(gpggalen != 0)
	{
	if(write(fd_hcxpos, gpgga, gpggalen) != gpggalen) errorcount++;
	}
p1 = 0;
p2 = 6;
c = 0;
cs = 0x5c;
while((p1 < gprmclen) && (c < 7))
	{
	if(gprmc[p1] == ',') c++;
	if(c > 2)
		{
		gpwpl[p2] = gprmc[p1];
		cs ^= gpwpl[p2++];
		}
	p1++;
	}
for (p1 = 0; p1 < ETH_ALEN; ++p1)
	{
	gpwpl[p2] = lookuptable[((aplist + i)->macap[p1] & 0xf0) >> 4];
	cs ^= gpwpl[p2++];
	gpwpl[p2] = lookuptable[(aplist + i)->macap[p1] & 0xf];
	cs ^= gpwpl[p2++];
	}
gpwpl[p2++] = '*';
gpwpl[p2++] = lookuptable[(cs & 0xf0) >> 4];
gpwpl[p2++] = lookuptable[cs & 0x0f];
gpwpl[p2++] = 0x0d;
gpwpl[p2++] = 0x0a;
if(write(fd_hcxpos, gpwpl, p2) != p2) errorcount++;
gpwpl[p2++] = 0x00;
if(((aplist + i)->ie.essidlen == 0) || ((aplist + i)->ie.essidlen > ESSID_MAX)) return;

p2 = 7;
cs = 0x63;
for(p1 = 0; p1 < (aplist + i)->ie.essidlen; p1 ++)
	{
	gptxt[p2] = lookuptable[((aplist + i)->ie.essid[p1] & 0xf0) >> 4];
	cs ^= gptxt[p2++];
	gptxt[p2] = lookuptable[(aplist + i)->ie.essid[p1] & 0xf];
	cs ^= gptxt[p2++];
	}
gptxt[p2++] = '*';
gptxt[p2++] = lookuptable[(cs & 0xf0) >> 4];
gptxt[p2++] = lookuptable[cs & 0x0f];
gptxt[p2++] = 0x0d;
gptxt[p2++] = 0x0a;
if(write(fd_hcxpos, gptxt, p2) != p2) errorcount++;
gptxt[p2++] = 0x00;
return;
}
#endif
/*===========================================================================*/
static u16 addoption(u8 *posopt, u16 optioncode, u16 optionlen, char *option)
{
static u16 padding;
static option_header_t *optionhdr;

optionhdr = (option_header_t*)posopt;
optionhdr->option_code = optioncode;
optionhdr->option_length = optionlen;
padding = (4 -(optionlen % 4)) % 4;
memset(optionhdr->option_data, 0, optionlen +padding);
memcpy(optionhdr->option_data, option, optionlen);
return optionlen + padding + 4;
}
/*---------------------------------------------------------------------------*/
/*
static u16 addcustomoptionheader(u8 *pospt)
{
static u16 colen;
static option_header_t *optionhdr;

optionhdr = (option_header_t*)pospt;
optionhdr->option_code = SHB_CUSTOM_OPT;
colen = OH_SIZE;
memcpy(pospt +colen, &hcxmagic, 4);
colen += 4;
memcpy(pospt +colen, &hcxmagic, 32);
colen += 32;
return colen;
}
*/
/*===========================================================================*/
static u16 addcustomoption(u8 *pospt)
{
static u16 colen;
static option_header_t *optionhdr;
static optionfield64_t *of;

optionhdr = (option_header_t*)pospt;
optionhdr->option_code = SHB_CUSTOM_OPT;
colen = OH_SIZE;
memcpy(pospt +colen, &hcxmagic, 4);
colen += 4;
memcpy(pospt +colen, &hcxmagic, 32);
colen += 32;
colen += addoption(pospt +colen, OPTIONCODE_MACAP, 6, (char*)macaprg);
of = (optionfield64_t*)(pospt +colen);
of->option_code = OPTIONCODE_RC;
of->option_length = 8;
of->option_value = replaycountrg;
colen += 12;
colen += addoption(pospt +colen, OPTIONCODE_ANONCE, 32, (char*)anoncerg);
colen += addoption(pospt +colen, OPTIONCODE_MACCLIENT, 6, (char*)macclientrg);
colen += addoption(pospt +colen, OPTIONCODE_SNONCE, 32, (char*)snoncerg);
colen += addoption(pospt +colen, OPTIONCODE_WEAKCANDIDATE, strnlen(weakcandidate, PSK_MAX), weakcandidate);
colen += addoption(pospt +colen, 0, 0, NULL);
optionhdr->option_length = colen -OH_SIZE;
return colen;
}
/*===========================================================================*/
static inline void writeepbm1(void)
{
static ssize_t epblen;
static ssize_t ii;
static u64 tsm1;
static u16 padding;
static total_length_t *totallength;

ii = RTHTX_SIZE + EPB_SIZE;
macftx = (ieee80211_mac_t*)&epbown[ii];
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_DATA;
macftx->from_ds = 1;
macftx->duration = 0x0431;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macfrx->addr1, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr3, ETH_ALEN);
macftx->sequence = seqcounter3++ << 4;
if(seqcounter1 > 4095) seqcounter3 = 1;
ii += MAC_SIZE_NORM;
memcpy(&epbown[ii], &eapolm1data, EAPOLM1DATA_SIZE);
ii += EAPOLM1DATA_SIZE;
epbhdr = (enhanced_packet_block_t*)epbown;
epblen = EPB_SIZE;
epbhdr->block_type = EPBID;
epbhdr->interface_id = 0;
epbhdr->cap_len = ii;
epbhdr->org_len = ii;
tsm1 = tsakt - 1;
epbhdr->timestamp_high = tsm1 >> 32;
epbhdr->timestamp_low = (u32)tsm1 & 0xffffffff;
padding = (4 -(epbhdr->cap_len % 4)) % 4;
epblen += ii;
memset(&epbown[epblen], 0, padding);
epblen += padding;
epblen += addoption(epbown +epblen, SHB_EOC, 0, NULL);
totallength = (total_length_t*)(epbown +epblen);
epblen += TOTAL_SIZE;
epbhdr->total_length = epblen;
totallength->total_length = epblen;
if(write(fd_pcapng, &epbown, epblen) != epblen) errorcount++;
return;
}
/*===========================================================================*/
static inline void writeepb(void)
{
static ssize_t epblen;
static u16 padding;
static total_length_t *totallength;

epbhdr = (enhanced_packet_block_t*)epb;
epblen = EPB_SIZE;
epbhdr->block_type = EPBID;
epbhdr->interface_id = 0;
epbhdr->cap_len = packetlen;
epbhdr->org_len = packetlen;
epbhdr->timestamp_high = tsakt >> 32;
epbhdr->timestamp_low = (u32)tsakt & 0xffffffff;
padding = (4 -(epbhdr->cap_len % 4)) % 4;
epblen += packetlen;
memset(&epb[epblen], 0, padding);
epblen += padding;
epblen += addoption(epb +epblen, SHB_EOC, 0, NULL);
totallength = (total_length_t*)(epb +epblen);
epblen += TOTAL_SIZE;
epbhdr->total_length = epblen;
totallength->total_length = epblen;
if(write(fd_pcapng, &epb, epblen) != epblen) errorcount++;
return;	
}
/*---------------------------------------------------------------------------*/
static bool writeshb(void)
{
static ssize_t shblen;
static section_header_block_t *shbhdr;
static total_length_t *totallength;
static struct utsname unameData;
static char sysinfo[256];
static u8 shb[PCAPNG_BLOCK_SIZE];

memset(&shb, 0, PCAPNG_BLOCK_SIZE);
shblen = SHB_SIZE;
shbhdr = (section_header_block_t*)shb;
shbhdr->block_type = PCAPNGBLOCKTYPE;
shbhdr->byte_order_magic = PCAPNGMAGICNUMBER;
shbhdr->major_version = PCAPNG_MAJOR_VER;
shbhdr->minor_version = PCAPNG_MINOR_VER;
shbhdr->section_length = -1;
if(uname(&unameData) == 0)
	{
	shblen += addoption(shb +shblen, SHB_HARDWARE, strlen(unameData.machine), unameData.machine);
	sprintf(sysinfo, "%s %s", unameData.sysname, unameData.release);
	shblen += addoption(shb +shblen, SHB_OS, strlen(sysinfo), sysinfo);
	sprintf(sysinfo, "hcxdumptool %s", VERSION_TAG);
	shblen += addoption(shb +shblen, SHB_USER_APPL, strlen(sysinfo), sysinfo);
	}
shblen += addcustomoption(shb +shblen);
shblen += addoption(shb +shblen, SHB_EOC, 0, NULL);
totallength = (total_length_t*)(shb +shblen);
shblen += TOTAL_SIZE;
shbhdr->total_length = shblen;
totallength->total_length = shblen;
if(write(fd_pcapng, &shb, shblen) != shblen) return false;
return true;
}
/*---------------------------------------------------------------------------*/
static bool writeidb(void)
{
static ssize_t idblen;
static interface_description_block_t *idbhdr;
static total_length_t *totallength;
static char tr[1];
static u8 idb[PCAPNG_BLOCK_SIZE];

memset(&idb, 0, PCAPNG_BLOCK_SIZE);
idblen = IDB_SIZE;
idbhdr = (interface_description_block_t*)idb;
idbhdr->block_type = IDBID;
idbhdr->linktype = DLT_IEEE802_11_RADIO;
idbhdr->reserved = 0;
idbhdr->snaplen = PCAPNG_SNAPLEN;
idblen += addoption(idb +idblen, IF_NAME, strnlen(ifaktname, IF_NAMESIZE), ifaktname);
idblen += addoption(idb +idblen, IF_MACADDR, 6, (char*)ifakthwmac);
tr[0] = TSRESOL_NSEC;
idblen += addoption(idb +idblen, IF_TSRESOL, 1, tr);
idblen += addoption(idb +idblen, SHB_EOC, 0, NULL);
totallength = (total_length_t*)(idb +idblen);
idblen += TOTAL_SIZE;
idbhdr->total_length = idblen;
totallength->total_length = idblen;
if(write(fd_pcapng, &idb, idblen) != idblen) return false;
return true;
}
/*---------------------------------------------------------------------------*/
static bool writecb(void)
{
static ssize_t cblen;
static custom_block_t *cbhdr;
static optionfield64_t *of;
static total_length_t *totallength;
static u8 cb[PCAPNG_BLOCK_SIZE];

memset(&cb, 0, PCAPNG_BLOCK_SIZE);
cbhdr = (custom_block_t*)cb;
cblen = CB_SIZE;
cbhdr->block_type = CBID;
cbhdr->total_length = CB_SIZE;
memcpy(cbhdr->pen, &hcxmagic, 4);
memcpy(cbhdr->hcxm, &hcxmagic, 32);
cblen += addoption(cb +cblen, OPTIONCODE_MACAP, 6, (char*)macaprg);
of = (optionfield64_t*)(cb +cblen);
of->option_code = OPTIONCODE_RC;
of->option_length = 8;
of->option_value = replaycountrg;
cblen += 12;
cblen += addoption(cb +cblen, OPTIONCODE_ANONCE, 32, (char*)anoncerg);
cblen += addoption(cb +cblen, OPTIONCODE_MACCLIENT, 6, (char*)macclientrg);
cblen += addoption(cb +cblen, OPTIONCODE_SNONCE, 32, (char*)snoncerg);
cblen += addoption(cb +cblen, OPTIONCODE_WEAKCANDIDATE, strnlen(weakcandidate, PSK_MAX), weakcandidate);
cblen += addoption(cb +cblen, 0, 0, NULL);
totallength = (total_length_t*)(cb +cblen);
cblen += TOTAL_SIZE;
cbhdr->total_length = cblen;
totallength->total_length = cblen;
if(write(fd_pcapng, &cb, cblen) != cblen) return false;
return true;
}
/*---------------------------------------------------------------------------*/
static bool open_pcapng(char *pcapngoutname)
{
static int c;
static struct stat statinfo;
static char *pcapngfilename = NULL;
static char pcapngname[PATH_MAX];

if(pcapngoutname == NULL)
	{
	c = 0;
	snprintf(pcapngname, PATH_MAX, "%s-%s.pcapng", timestring, ifaktname);
	while(stat(pcapngname, &statinfo) == 0)
		{
		snprintf(pcapngname, PATH_MAX, "%s-%s-%02d.pcapng", timestring, ifaktname, c);
		c++;
		}
	pcapngfilename = pcapngname;
	}
else pcapngfilename = pcapngoutname;
umask(0);
if((fd_pcapng = open(pcapngfilename, O_WRONLY | O_TRUNC | O_CREAT, 0777)) < 0) return false;
if(writeshb() == false) return false;
if(writeidb() == false) return false;
if(writecb() == false) return false;
return true;
}
/*===========================================================================*/
/*===========================================================================*/
/* TX 802.11 */
/*===========================================================================*/
static inline void send_80211_associationrequest_org(size_t i)
{
ssize_t ii;

ii = RTHTXNOACK_SIZE;
macftx = (ieee80211_mac_t*)&wltxnoackbuffer[ii];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
wltxnoackbuffer[ii + 1] = 0;
macftx->duration = 0x013a;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, (aplist + i)->macclient, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr3, ETH_ALEN);
macftx->sequence = seqcounter2++ << 4;
if(seqcounter1 > 4095) seqcounter2 = 1;
ii += MAC_SIZE_NORM;
memcpy(&wltxnoackbuffer[ii], &associationrequestcapa, ASSOCIATIONREQUESTCAPA_SIZE);
ii += ASSOCIATIONREQUESTCAPA_SIZE;
wltxnoackbuffer[ii ++] = 0;
wltxnoackbuffer[ii ++] = (aplist + i)->ie.essidlen;
memcpy(&wltxnoackbuffer[ii], (aplist + i)->ie.essid, (aplist + i)->ie.essidlen);
ii += (aplist + i)->ie.essidlen;
memcpy(&wltxnoackbuffer[ii], &associationrequestdata, ASSOCIATIONREQUEST_SIZE);
if(((aplist + i)->ie.flags & APGS_CCMP) == APGS_CCMP) wltxnoackbuffer[ii +0x17] = RSN_CS_CCMP;
else if(((aplist + i)->ie.flags & APGS_TKIP) == APGS_TKIP) wltxnoackbuffer[ii +0x17] = RSN_CS_TKIP;
if(((aplist + i)->ie.flags & APCS_CCMP) == APCS_CCMP) wltxnoackbuffer[ii +0x1d] = RSN_CS_CCMP;
else if(((aplist + i)->ie.flags & APCS_TKIP) == APCS_TKIP) wltxnoackbuffer[ii +0x1d] = RSN_CS_TKIP;
ii += ASSOCIATIONREQUEST_SIZE;
if((write(fd_socket_tx, &wltxnoackbuffer, ii)) == ii) return;
errorcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline void send_80211_associationrequest(size_t i)
{
ssize_t ii;

ii = RTHTX_SIZE;
macftx = (ieee80211_mac_t*)&wltxbuffer[ii];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
wltxbuffer[ii + 1] = 0;
macftx->duration = 0x013a;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macclientrg, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr3, ETH_ALEN);
macftx->sequence = seqcounter2++ << 4;
if(seqcounter1 > 4095) seqcounter2 = 1;
ii += MAC_SIZE_NORM;
memcpy(&wltxbuffer[ii], &associationrequestcapa, ASSOCIATIONREQUESTCAPA_SIZE);
ii += ASSOCIATIONREQUESTCAPA_SIZE;
wltxbuffer[ii ++] = 0;
wltxbuffer[ii ++] = (aplist + i)->ie.essidlen;
memcpy(&wltxbuffer[ii], (aplist + i)->ie.essid, (aplist + i)->ie.essidlen);
ii += (aplist + i)->ie.essidlen;
memcpy(&wltxbuffer[ii], &associationrequestdata, ASSOCIATIONREQUEST_SIZE);
if(((aplist + i)->ie.flags & APGS_CCMP) == APGS_CCMP) wltxbuffer[ii +0x17] = RSN_CS_CCMP;
else if(((aplist + i)->ie.flags & APGS_TKIP) == APGS_TKIP) wltxbuffer[ii +0x17] = RSN_CS_TKIP;
if(((aplist + i)->ie.flags & APCS_CCMP) == APCS_CCMP) wltxbuffer[ii +0x1d] = RSN_CS_CCMP;
else if(((aplist + i)->ie.flags & APCS_TKIP) == APCS_TKIP) wltxbuffer[ii +0x1d] = RSN_CS_TKIP;
ii += ASSOCIATIONREQUEST_SIZE;
if((write(fd_socket_tx, &wltxbuffer, ii)) == ii) return;
errorcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline void send_80211_eapolm1(void)
{
static ssize_t ii;

ii = RTHTX_SIZE;
macftx = (ieee80211_mac_t*)&wltxbuffer[ii];
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_DATA;
wltxbuffer[ii + 1] = 0;
macftx->from_ds = 1;
macftx->duration = 0x0431;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macfrx->addr1, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr3, ETH_ALEN);
macftx->sequence = seqcounter3++ << 4;
if(seqcounter1 > 4095) seqcounter3 = 1;
ii += MAC_SIZE_NORM;
memcpy(&wltxbuffer[ii], &eapolm1data, EAPOLM1DATA_SIZE);
ii += EAPOLM1DATA_SIZE;
if(write(fd_socket_tx, wltxbuffer, ii) == ii) return;
errorcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline void send_80211_reassociationresponse(u16 aid)
{
static ssize_t ii;
static ieee80211_assoc_or_reassoc_resp_t *associationresponsetx;

ii = RTHTX_SIZE;
macftx = (ieee80211_mac_t*)&wltxbuffer[ii];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_REASSOC_RESP;
wltxbuffer[ii + 1] = 0;
macftx->duration = 0x013a;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macfrx->addr1, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr3, ETH_ALEN);
macftx->sequence = seqcounter3++ << 4;
if(seqcounter1 > 4095) seqcounter3 = 1;
ii += MAC_SIZE_NORM;
associationresponsetx = (ieee80211_assoc_or_reassoc_resp_t*)&wltxbuffer[ii];
associationresponsetx->capability = 0x431;
associationresponsetx->status = 0;
associationresponsetx->aid = aid;
ii += IEEE80211_ASSOCIATIONRESPONSE_SIZE;
memcpy(&wltxbuffer[ii], &associationresponsedata, ASSOCIATIONRESPONSEDATA_SIZE);
ii += ASSOCIATIONRESPONSEDATA_SIZE;
if(write(fd_socket_tx, &wltxbuffer, ii) == ii) return;
errorcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline void send_80211_associationresponse(void)
{
static ssize_t ii;
static ieee80211_assoc_or_reassoc_resp_t *associationresponsetx;

ii = RTHTX_SIZE;
macftx = (ieee80211_mac_t*)&wltxbuffer[ii];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_RESP;
wltxbuffer[ii + 1] = 0;
macftx->duration = 0x013a;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macfrx->addr1, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr3, ETH_ALEN);
macftx->sequence = seqcounter3++ << 4;
if(seqcounter1 > 4095) seqcounter3 = 1;
ii += MAC_SIZE_NORM;
associationresponsetx = (ieee80211_assoc_or_reassoc_resp_t*)&wltxbuffer[ii];
associationresponsetx->capability = 0x431;
associationresponsetx->status = 0;
associationresponsetx->aid = 1;
ii += IEEE80211_ASSOCIATIONRESPONSE_SIZE;
memcpy(&wltxbuffer[ii], &associationresponsedata, ASSOCIATIONRESPONSEDATA_SIZE);
ii += ASSOCIATIONRESPONSEDATA_SIZE;
if(write(fd_socket_tx, &wltxbuffer, ii) == ii) return;
errorcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline void send_80211_authenticationresponse(void)
{
macftx = (ieee80211_mac_t*)&wltxbuffer[RTHTX_SIZE];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_AUTH;
wltxbuffer[RTHTX_SIZE + 1] = 0;
macftx->duration = 0x013a;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macfrx->addr1, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr3, ETH_ALEN);
macftx->sequence = seqcounter3++ << 4;
if(seqcounter1 > 4095) seqcounter3 = 1;
memcpy(&wltxbuffer[RTHTX_SIZE + MAC_SIZE_NORM], authenticationresponsedata, AUTHENTICATIONRESPONSE_SIZE);
if((write(fd_socket_tx, &wltxbuffer, RTHTX_SIZE + MAC_SIZE_NORM + AUTHENTICATIONRESPONSE_SIZE)) == RTHTX_SIZE + MAC_SIZE_NORM + AUTHENTICATIONRESPONSE_SIZE) return;
errorcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline void send_80211_reassociationrequest(size_t i)
{
static ssize_t ii;
static ieee80211_reassoc_req_t *reassociationrequest;

ii = RTHTXNOACK_SIZE;
macftx = (ieee80211_mac_t*)&wltxnoackbuffer[ii];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_REASSOC_REQ;
wltxnoackbuffer[ii + 1] = 0;
macftx->duration = 0x013a;
memcpy(macftx->addr1, (aplist + i)->macap, ETH_ALEN);
memcpy(macftx->addr2, (aplist + i)->macclient, ETH_ALEN);
memcpy(macftx->addr3, (aplist + i)->macap, ETH_ALEN);
macftx->sequence = seqcounter3++ << 4;
if(seqcounter1 > 4095) seqcounter3 = 1;
ii += MAC_SIZE_NORM;
reassociationrequest = (ieee80211_reassoc_req_t*)&wltxnoackbuffer[ii];
reassociationrequest->capability = 0x431;
reassociationrequest->listen_interval = 0x14;
memcpy(reassociationrequest->current_macap, (aplist + i)->macap, ETH_ALEN);
ii += sizeof(ieee80211_reassoc_req_t);
wltxnoackbuffer[ii ++] = 0;
wltxnoackbuffer[ii ++] = (aplist + i)->ie.essidlen;
memcpy(&wltxnoackbuffer[ii], (aplist + i)->ie.essid, (aplist + i)->ie.essidlen);
ii += (aplist + i)->ie.essidlen;
memcpy(&wltxnoackbuffer[ii], &reassociationrequestdata, REASSOCIATIONREQUEST_SIZE);
if(((aplist + i)->ie.flags & APGS_CCMP) == APGS_CCMP) wltxnoackbuffer[ii +0x17] = RSN_CS_CCMP;
else if(((aplist + i)->ie.flags & APGS_TKIP) == APGS_TKIP) wltxnoackbuffer[ii +0x17] = RSN_CS_TKIP;
if(((aplist + i)->ie.flags & APCS_CCMP) == APCS_CCMP) wltxnoackbuffer[ii +0x1d] = RSN_CS_CCMP;
else if(((aplist + i)->ie.flags & APCS_TKIP) == APCS_TKIP) wltxnoackbuffer[ii +0x1d] = RSN_CS_TKIP;
ii += REASSOCIATIONREQUEST_SIZE;
if((write(fd_socket_tx, &wltxnoackbuffer, ii)) == ii) return;
errorcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline void send_80211_authenticationrequestnoack(void)
{
macftx = (ieee80211_mac_t*)&wltxnoackbuffer[RTHTXNOACK_SIZE];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_AUTH;
wltxnoackbuffer[RTHTX_SIZE + 1] = 0;
macftx->duration = 0x013a;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macclientrg, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr3, ETH_ALEN);
macftx->sequence = seqcounter2++ << 4;
if(seqcounter1 > 4095) seqcounter2 = 1;
memcpy(&wltxnoackbuffer[RTHTXNOACK_SIZE + MAC_SIZE_NORM], authenticationrequestdata, AUTHENTICATIONREQUEST_SIZE);
if((write(fd_socket_tx, &wltxnoackbuffer, RTHTXNOACK_SIZE + MAC_SIZE_NORM + AUTHENTICATIONREQUEST_SIZE)) == RTHTXNOACK_SIZE + MAC_SIZE_NORM + AUTHENTICATIONREQUEST_SIZE) return;
errorcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline void send_80211_authenticationrequest(void)
{
macftx = (ieee80211_mac_t*)&wltxbuffer[RTHTX_SIZE];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_AUTH;
wltxbuffer[RTHTX_SIZE + 1] = 0;
macftx->duration = 0x013a;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macclientrg, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr3, ETH_ALEN);
macftx->sequence = seqcounter2++ << 4;
if(seqcounter1 > 4095) seqcounter2 = 1;
memcpy(&wltxbuffer[RTHTX_SIZE + MAC_SIZE_NORM], authenticationrequestdata, AUTHENTICATIONREQUEST_SIZE);
if((write(fd_socket_tx, &wltxbuffer, RTHTX_SIZE + MAC_SIZE_NORM + AUTHENTICATIONREQUEST_SIZE)) == RTHTX_SIZE + MAC_SIZE_NORM + AUTHENTICATIONREQUEST_SIZE) return;
errorcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline void send_80211_probereresponse(u8 *macclientrsp, u8 *macaprgrsp, u8 essidlenrsp, u8 *essidrsp)
{
static ssize_t ii;
static ieee80211_beacon_proberesponse_t *beacontx;

ii = RTHTXNOACK_SIZE;
macftx = (ieee80211_mac_t*)&wltxnoackbuffer[ii];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_RESP;
wltxnoackbuffer[ii + 1] = 0;
macftx->duration = 0x013a;
memcpy(macftx->addr1, macclientrsp, ETH_ALEN);
memcpy(macftx->addr2, macaprgrsp, ETH_ALEN);
memcpy(macftx->addr3, macaprgrsp, ETH_ALEN);
macftx->sequence = seqcounter3++ << 4;
if(seqcounter1 > 4095) seqcounter3 = 1;
ii += MAC_SIZE_NORM;
beacontx = (ieee80211_beacon_proberesponse_t*)&wltxnoackbuffer[ii];
beacontx->timestamp = beacontimestamp++;
beacontx->beacon_interval = 1024;
beacontx->capability = 0x431;
ii += IEEE80211_PROBERESPONSE_SIZE;
wltxnoackbuffer[ii ++] = 0;
wltxnoackbuffer[ii ++] = essidlenrsp;
memcpy(&wltxnoackbuffer[ii], essidrsp, essidlenrsp);
ii += essidlenrsp;
memcpy(&wltxnoackbuffer[ii], proberesponsedata, PROBERESPONSEDATA_SIZE);
wltxnoackbuffer[ii + 0x0c] = (u8)(scanlist + scanlistindex)->channel; 
ii += PROBERESPONSEDATA_SIZE;
if((write(fd_socket_tx, &wltxnoackbuffer, ii)) == ii) return;
errorcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline void send_80211_beacon(void)
{
static ssize_t ii;
static ieee80211_beacon_proberesponse_t *beacontx;

beaconindex++;
if(beaconindex >= beacontxmax) beaconindex = 0;
if((aprglist + beaconindex)->essidlen == 0) beaconindex = 0;
ii = RTHTXNOACK_SIZE;
macftx = (ieee80211_mac_t*)&wltxnoackbuffer[ii];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_BEACON;
wltxnoackbuffer[ii + 1] = 0;
macftx->duration = 0x013a;
memcpy(macftx->addr1, macbc, ETH_ALEN);
memcpy(macftx->addr2, (aprglist + beaconindex)->macaprg, ETH_ALEN);
memcpy(macftx->addr3, (aprglist + beaconindex)->macaprg, ETH_ALEN);
macftx->sequence = seqcounter4++ << 4;
if(seqcounter1 > 4095) seqcounter4 = 1;
ii += MAC_SIZE_NORM;
beacontx = (ieee80211_beacon_proberesponse_t*)&wltxnoackbuffer[ii];
beacontx->timestamp = beacontimestamp++;
beacontx->beacon_interval = 1024;
beacontx->capability = 0x431;
ii += IEEE80211_BEACON_SIZE;
wltxnoackbuffer[ii ++] = 0;
wltxnoackbuffer[ii ++] = (aprglist + beaconindex)->essidlen;
memcpy(&wltxnoackbuffer[ii], (aprglist + beaconindex)->essid, (aprglist + beaconindex)->essidlen);
ii += (aprglist + beaconindex)->essidlen;
memcpy(&wltxnoackbuffer[ii], beacondata, BEACONDATA_SIZE);
wltxnoackbuffer[ii + 0x0c] = (u8)(scanlist + scanlistindex)->channel; 
ii += BEACONDATA_SIZE;
if((write(fd_socket_tx, &wltxnoackbuffer, ii)) == ii) return;
errorcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline void send_80211_proberequest_undirected(void)
{
macftx = (ieee80211_mac_t*)&wltxnoackbuffer[RTHTXNOACK_SIZE];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_REQ;
wltxnoackbuffer[RTHTXNOACK_SIZE + 1] = 0;
macftx->duration = 0x013a;
memcpy(macftx->addr1, macbc, ETH_ALEN);
memcpy(macftx->addr2, macclientrg, ETH_ALEN);
memcpy(macftx->addr3, macbc, ETH_ALEN);
macftx->sequence = seqcounter2++ << 4;
if(seqcounter1 > 4095) seqcounter2 = 1;
memcpy(&wltxnoackbuffer[RTHTXNOACK_SIZE + MAC_SIZE_NORM], proberequest_undirected_data, PROBEREQUEST_UNDIRECTED_SIZE);
if((write(fd_socket_tx, &wltxnoackbuffer, RTHTXNOACK_SIZE + MAC_SIZE_NORM + PROBEREQUEST_UNDIRECTED_SIZE)) == RTHTXNOACK_SIZE + MAC_SIZE_NORM + PROBEREQUEST_UNDIRECTED_SIZE) return;
errorcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline void send_80211_disassociation_fm_ap(const u8* macclient, const u8* macap, u8 reason)
{
macftx = (ieee80211_mac_t*)&wltxnoackbuffer[RTHTXNOACK_SIZE];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DISASSOC;
wltxnoackbuffer[RTHTXNOACK_SIZE + 1] = 0;
macftx->duration = 0x013a;
memcpy(macftx->addr1, macclient, ETH_ALEN);
memcpy(macftx->addr2, macap, ETH_ALEN);
memcpy(macftx->addr3, macap, ETH_ALEN);
macftx->sequence = seqcounter1++ << 4;
if(seqcounter1 > 4095) seqcounter1 = 1;
wltxnoackbuffer[RTHTXNOACK_SIZE + MAC_SIZE_NORM] = reason;
if((write(fd_socket_tx, &wltxnoackbuffer, RTHTXNOACK_SIZE + MAC_SIZE_NORM + 2)) == RTHTXNOACK_SIZE + MAC_SIZE_NORM +2) return;
errorcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline void send_80211_disassociation_fm_client(const u8* macclient, const u8* macap, u8 reason)
{
macftx = (ieee80211_mac_t*)&wltxnoackbuffer[RTHTXNOACK_SIZE];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DISASSOC;
wltxnoackbuffer[RTHTXNOACK_SIZE + 1] = 0;
macftx->duration = 0x013a;
memcpy(macftx->addr1, macap, ETH_ALEN);
memcpy(macftx->addr2, macclient, ETH_ALEN);
memcpy(macftx->addr3, macap, ETH_ALEN);
macftx->sequence = seqcounter1++ << 4;
if(seqcounter1 > 4095) seqcounter1 = 1;
wltxnoackbuffer[RTHTXNOACK_SIZE + MAC_SIZE_NORM] = reason;
if((write(fd_socket_tx, &wltxnoackbuffer, RTHTXNOACK_SIZE + MAC_SIZE_NORM + 2)) == RTHTXNOACK_SIZE + MAC_SIZE_NORM +2) return;
errorcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline void send_80211_deauthentication_fm_ap(const u8* macclient, const u8* macap, u8 reason)
{
macftx = (ieee80211_mac_t*)&wltxnoackbuffer[RTHTXNOACK_SIZE];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DEAUTH;
wltxnoackbuffer[RTHTXNOACK_SIZE + 1] = 0;
macftx->duration = 0x013a;
memcpy(macftx->addr1, macclient, ETH_ALEN);
memcpy(macftx->addr2, macap, ETH_ALEN);
memcpy(macftx->addr3, macap, ETH_ALEN);
macftx->sequence = seqcounter1++ << 4;
if(seqcounter1 > 4095) seqcounter1 = 1;
wltxnoackbuffer[RTHTXNOACK_SIZE +MAC_SIZE_NORM] = reason;
if((write(fd_socket_tx, &wltxnoackbuffer, RTHTXNOACK_SIZE + MAC_SIZE_NORM + 2)) ==RTHTXNOACK_SIZE + MAC_SIZE_NORM +2) return;
errorcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline void send_80211_deauthentication_fm_client(const u8* macclient, const u8* macap, u8 reason)
{
macftx = (ieee80211_mac_t*)&wltxnoackbuffer[RTHTXNOACK_SIZE];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DEAUTH;
wltxnoackbuffer[RTHTXNOACK_SIZE + 1] = 0;
macftx->duration = 0x013a;
memcpy(macftx->addr1, macap, ETH_ALEN);
memcpy(macftx->addr2, macclient, ETH_ALEN);
memcpy(macftx->addr3, macap, ETH_ALEN);
macftx->sequence = seqcounter1++ << 4;
if(seqcounter1 > 4095) seqcounter1 = 1;
wltxnoackbuffer[RTHTXNOACK_SIZE + MAC_SIZE_NORM] = reason;
if((write(fd_socket_tx, &wltxnoackbuffer, RTHTXNOACK_SIZE + MAC_SIZE_NORM + 2)) == RTHTXNOACK_SIZE + MAC_SIZE_NORM +2) return;
errorcount++;
return;
}
/*===========================================================================*/
/*===========================================================================*/
/* RX 802.11 */
static inline __attribute__((always_inline)) void get_tagvendor(infoelement_t *infoelement, int infolen, u8 *infostart)
{
static size_t c;
static ieee80211_wpaie_t *iewpa;
static ieee80211_wpasuite_t *wpasuite;
static ieee80211_wpasuitecount_t *wpasuitecount;

iewpa = (ieee80211_wpaie_t*)infostart;
if(memcmp(&wpasuiteoui, iewpa->oui, 3) != 0) return;
if(iewpa->type != 1) return;
if(iewpa->version != 1) return;

infostart += IEEE80211_WPAIE_SIZE;
infolen -= IEEE80211_WPAIE_SIZE;
wpasuite =(ieee80211_wpasuite_t*)infostart;
if(memcmp(&wpasuiteoui, wpasuite->oui, 3) != 0) return;

infostart += IEEE80211_WPASUITE_SIZE;
infolen -= IEEE80211_WPASUITE_SIZE;
wpasuitecount =(ieee80211_wpasuitecount_t*)infostart;
infostart += IEEE80211_WPASUITECOUNT_SIZE;
infolen -= IEEE80211_WPASUITECOUNT_SIZE;
for(c = 0; c < wpasuitecount->count; c++)
	{
	if(infolen <= 0) return;
	wpasuite =(ieee80211_wpasuite_t*)infostart;
	infostart += IEEE80211_WPASUITE_SIZE;
	infolen -= IEEE80211_WPASUITE_SIZE;
	}
wpasuitecount =(ieee80211_wpasuitecount_t*)infostart;
infostart += IEEE80211_WPASUITECOUNT_SIZE;
infolen -= IEEE80211_WPASUITECOUNT_SIZE;
for(c = 0; c < wpasuitecount->count; c++)
	{
	if(infolen <= 0) return;
	wpasuite =(ieee80211_wpasuite_t*)infostart;
	if(memcmp(&wpasuiteoui, wpasuite->oui, 3) == 0)
		{
		if(wpasuite->type == WPA_AKM_PSK) infoelement->flags |= APWPAAKM_PSK;
		}
	infostart += IEEE80211_WPASUITE_SIZE;
	infolen -= IEEE80211_WPASUITE_SIZE;
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void get_tagrsn(infoelement_t *infoelement, int infolen, u8 *infostart)
{
static size_t c;
static ieee80211_rsnie_t *iersn;
static ieee80211_rnsuite_t *rsnsuite;
static ieee80211_rsnsuitecount_t *rsnsuitecount;
static ieee80211_rsncapability_t *rsncapability;

iersn = (ieee80211_rsnie_t*)infostart;
if(iersn->version != 1) return;
infostart += IEEE80211_RSNIE_SIZE;
infolen -= IEEE80211_RSNIE_SIZE;
rsnsuite =(ieee80211_rnsuite_t*)infostart;
if(memcmp(&rsnsuiteoui, rsnsuite->oui, 3) != 0) return;
if(rsnsuite->type == RSN_CS_CCMP) infoelement->flags |= APGS_CCMP;
if(rsnsuite->type == RSN_CS_TKIP) infoelement->flags |= APGS_TKIP;
infostart += IEEE80211_RSNSUITE_SIZE;
infolen -= IEEE80211_RSNSUITE_SIZE;
rsnsuitecount =(ieee80211_rsnsuitecount_t*)infostart;
infostart += IEEE80211_RSNSUITECOUNT_SIZE;
infolen -= IEEE80211_RSNSUITECOUNT_SIZE;
for(c = 0; c < rsnsuitecount->count; c++)
	{
	if(infolen <= 0) return;
	rsnsuite =(ieee80211_rnsuite_t*)infostart;
	if(memcmp(&rsnsuiteoui, rsnsuite->oui, 3) == 0)
		{
		if(rsnsuite->type == RSN_CS_CCMP) infoelement->flags |= APCS_CCMP;
		if(rsnsuite->type == RSN_CS_TKIP) infoelement->flags |= APCS_TKIP;
		}
	infostart += IEEE80211_RSNSUITE_SIZE;
	infolen -= IEEE80211_RSNSUITE_SIZE;
	}
rsnsuitecount =(ieee80211_rsnsuitecount_t*)infostart;
infostart += IEEE80211_RSNSUITECOUNT_SIZE;
infolen -= IEEE80211_RSNSUITECOUNT_SIZE;
for(c = 0; c < rsnsuitecount->count; c++)
	{
	if(infolen <= 0) return;
	rsnsuite =(ieee80211_rnsuite_t*)infostart;
	if(memcmp(&rsnsuiteoui, rsnsuite->oui, 3) == 0)
		{
		if(rsnsuite->type == RSN_AKM_PSK) infoelement->flags |= APRSNAKM_PSK;
		if(rsnsuite->type == RSN_AKM_PSK256) infoelement->flags |= APRSNAKM_PSK256;
		if(rsnsuite->type == RSN_AKM_PSKFT) infoelement->flags |= APRSNAKM_PSKFT;
		}
	infostart += IEEE80211_RSNSUITE_SIZE;
	infolen -= IEEE80211_RSNSUITE_SIZE;
	}
if(infolen < 2) return;
rsncapability = (ieee80211_rsncapability_t*)infostart;
if((rsncapability->capability & MFP_REQUIRED) == MFP_REQUIRED) infoelement->flags |= AP_MFP;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void tagwalk_channel_essid_rsn(infoelement_t *infoelement, int infolen, u8 *infostart)
{
static ieee80211_ietag_t *infoptr;

while(0 < infolen)
	{
	infoptr = (ieee80211_ietag_t*)infostart;
	if(infolen < (int)(infoptr->len + IEEE80211_IETAG_SIZE)) return;
	if(infoptr->id == TAG_SSID)
		{
		if((infoptr->len > 0) && (infoptr->len <= ESSID_MAX))
			{
			infoelement->flags |= APIE_ESSID;
			infoelement->essidlen = infoptr->len;
			memcpy(infoelement->essid, &infoptr->ie[0], infoptr->len);
			}
		}
	else if(infoptr->id == TAG_CHAN)
		{
		if(infoptr->len == 1) infoelement->channel = (u16)infoptr->ie[0];
		}
	else if(infoptr->id == TAG_RSN)
		{
		if(infoptr->len >= IEEE80211_RSNIE_LEN_MIN) get_tagrsn(infoelement, infoptr->len, infoptr->ie);
		}
	else if(infoptr->id == TAG_VENDOR)
		{
		if(infoptr->len >= IEEE80211_WPAIE_LEN_MIN) get_tagvendor(infoelement, infoptr->len, infoptr->ie);
		}
	infostart += infoptr->len + IEEE80211_IETAG_SIZE;
	infolen -= infoptr->len + IEEE80211_IETAG_SIZE;
	}
return;
}
/*---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
static inline int get_keyinfo(uint16_t kyif)
{
if(kyif & WPA_KEY_INFO_ACK)
	{
	if(kyif & WPA_KEY_INFO_INSTALL) return 3; /* handshake 3 */
	else return 1; /* handshake 1 */
	}
else
	{
	if(kyif & WPA_KEY_INFO_SECURE) return 4; /* handshake 4 */
	else return 2; /* handshake 2 */
	}
return 0;
}
/*---------------------------------------------------------------------------*/
static inline void process80211pspoll(void)
{
static size_t i;

for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if(memcmp(macfrx->addr1, (aplist + i)->macap, ETH_ALEN) == 0)
		{
		if((aplist + i)->status >= AP_EAPOL_M3) return;
		if(memcmp(&macbc, (aplist + i)->macclient, ETH_ALEN) == 0) (aplist + i)->count = attemptapmax;
		memcpy((aplist + i)->macclient, macfrx->addr2, ETH_ALEN);
		return;
		}
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211action(void)
{
static size_t i;
static ieee80211_action_t *action;

for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if(memcmp((aplist + i)->macap, macfrx->addr1, ETH_ALEN) == 0)
		{
		if((aplist + i)->status >= AP_EAPOL_M3) return;
		if(memcmp(&macbc, (aplist + i)->macclient, ETH_ALEN) == 0) (aplist + i)->count = attemptapmax;
		memcpy((aplist + i)->macclient, macfrx->addr2, ETH_ALEN);
		break;
		}
	}
action = (ieee80211_action_t*)payloadptr;
if(payloadlen < (IEEE80211_ACTION_SIZE + IEEE80211_IETAG_SIZE)) return;
if((action->category == RADIO_MEASUREMENT) && (action->code == NEIGHBOR_REPORT_REQUEST)) writeepb();
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211qosdata(void)
{
static size_t i;

if((macfrx->to_ds != 1) && (macfrx->from_ds != 0)) return;
for(i = 0; i < APLIST_MAX - 1; i++)
	{
		{
		if(memcmp((aplist + i)->macap, macfrx->addr1, ETH_ALEN) == 0)
			{
			if((aplist + i)->status >= AP_EAPOL_M3) return;
			if(memcmp(&macbc, (aplist + i)->macclient, ETH_ALEN) == 0) (aplist + i)->count = attemptapmax;
			memcpy((aplist + i)->macclient, macfrx->addr2, ETH_ALEN);
			return;
			}
		}
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211qosnull(void)
{
static size_t i;

if((macfrx->to_ds != 1) && (macfrx->from_ds != 0)) return;
for(i = 0; i < APLIST_MAX - 1; i++)
	{
		{
		if(memcmp((aplist + i)->macap, macfrx->addr1, ETH_ALEN) == 0)
			{
			if((aplist + i)->status >= AP_EAPOL_M3) return;
			if(memcmp(&macbc, (aplist + i)->macclient, ETH_ALEN) == 0) (aplist + i)->count = attemptapmax;
			memcpy((aplist + i)->macclient, macfrx->addr2, ETH_ALEN);
			return;
			}
		}
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211null(void)
{
static size_t i;

if((macfrx->to_ds != 1) && (macfrx->from_ds != 0)) return;
for(i = 0; i < APLIST_MAX - 1; i++)
	{
		{
		if(memcmp((aplist + i)->macap, macfrx->addr1, ETH_ALEN) == 0)
			{
			if((aplist + i)->status >= AP_EAPOL_M3) return;
			if(memcmp(&macbc, (aplist + i)->macclient, ETH_ALEN) == 0) (aplist + i)->count = attemptapmax;
			memcpy((aplist + i)->macclient, macfrx->addr2, ETH_ALEN);
			return;
			}
		}
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211blockack(void)
{
static size_t i;

for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if(memcmp((aplist + i)->macap, macfrx->addr1, ETH_ALEN) == 0)
		{
		if((aplist + i)->status >= AP_EAPOL_M3) return;
		if(memcmp(&macbc, (aplist + i)->macclient, ETH_ALEN) == 0) (aplist + i)->count = attemptapmax;
		memcpy((aplist + i)->macclient, macfrx->addr2, ETH_ALEN);
		return;
		}
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211blockackreq(void)
{
static size_t i;

for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if(memcmp((aplist + i)->macap, macfrx->addr1, ETH_ALEN) == 0)
		{
		if((aplist + i)->status >= AP_EAPOL_M3) return;
		if(memcmp(&macbc, (aplist + i)->macclient, ETH_ALEN) == 0) (aplist + i)->count = attemptapmax;
		memcpy((aplist + i)->macclient, macfrx->addr2, ETH_ALEN);
		return;
		}
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211eapol_m4(void)
{
static size_t i;

for(i = 0; i < APLIST_MAX -1; i++)
	{
	if(memcmp((aplist + i)->macap, macfrx->addr3, ETH_ALEN) == 0)
		{
		if((aplist + i)->status >= AP_EAPOL_M3) return;
		if(deauthenticationflag == true)
			{
			if(((aplist + i)->ie.flags & APAKM_MASK) == 0)
				{
				send_80211_disassociation_fm_ap((aplist + i)->macclient, (aplist + i)->macap, WLAN_REASON_DISASSOC_AP_BUSY);
				send_80211_disassociation_fm_client(macfrx->addr2, (aplist + i)->macap, WLAN_REASON_DISASSOC_STA_HAS_LEFT);
				}
			}
		memcpy((aplist + i)->macclient, macfrx->addr2, ETH_ALEN);
		qsort(aplist, APLIST_MAX, APLIST_SIZE, sort_aplist_by_tsakt);
		return;
		}
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211eapol_m3(void)
{
static size_t i;

if((authseqakt.status & AP_EAPOL_M2) == AP_EAPOL_M2)
	{
	if(memcmp(&authseqakt.macap, macfrx->addr2, ETH_ALEN) == 0)
		{
		if(authseqakt.replaycountm2 == (be64toh(wpakey->replaycount) - 1))
			{
			if(authseqakt.kdv2 == kdv)
				{
				if((tsakt - tshold) < EAPOLM3TIMEOUT)
					{
					if(memcmp(&authseqakt.noncem1, &wpakey->nonce[28], 4) == 0)
						{
						for(i = 0; i < APLIST_MAX -1; i++)
							{
							if(memcmp((aplist + i)->macap, authseqakt.macap, ETH_ALEN) == 0)
								{
								authseqakt.status = 0;
								(aplist + i)->status |= AP_EAPOL_M3;
								return;
								}
							}
						}
					}
				}
			}
		}
	}
authseqakt.status = 0;
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211eapol_m2rg(void)
{
size_t i;

authseqakt.status = 0;
writeepbm1();
for(i = 0; i < CLIENTLIST_MAX - 1; i++)
	{
	if(memcmp(macfrx->addr2, (clientlist + i)->macclient, ETH_ALEN) != 0) continue;
	if(memcmp(macfrx->addr1, (clientlist + i)->macap, ETH_ALEN) != 0) continue;
	(clientlist + i)->tsakt = tsakt;
	(clientlist + i)->status |= CLIENT_EAPOL_M2;
	if((clientlist + i)->count == 0) return;
	if(memcmp((clientlist + i)->mic, &wpakey->keymic[0], 4) == 0) send_80211_disassociation_fm_ap(macfrx->addr2, macfrx->addr1, WLAN_REASON_PREV_AUTH_NOT_VALID);
	memcpy((clientlist + i)->mic, &wpakey->keymic[0], 4);
	(clientlist + i)->count--;
	return;
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211eapol_m2(void)
{
authseqakt.replaycountm2 = be64toh(wpakey->replaycount);
if(replaycountrg == authseqakt.replaycountm2)
	{
	process80211eapol_m2rg();
	return;
	}
if((authseqakt.status & AP_EAPOL_M1) == AP_EAPOL_M1)
	{
	if(memcmp(&authseqakt.macap, macfrx->addr1, ETH_ALEN) == 0)
		{
		if(authseqakt.replaycountm1 == authseqakt.replaycountm2)
			{
			authseqakt.kdv2 = kdv;
			if(authseqakt.kdv1 == authseqakt.kdv2)
				{
				if((tsakt - tshold) < EAPOLM2TIMEOUT) authseqakt.status |= AP_EAPOL_M2;
				else authseqakt.status = 0;
				return;
				}
			}
		}
	}
authseqakt.status = 0;
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211eapol_m1(void)
{
static size_t i;

memset(&authseqakt, 0, AUTHSEQAKT_SIZE);
memcpy(&authseqakt.macap, macfrx->addr2, ETH_ALEN);
authseqakt.kdv1 = kdv;
authseqakt.replaycountm1 = be64toh(wpakey->replaycount);
memcpy(&authseqakt.noncem1, &wpakey->nonce[28], 4);
authseqakt.status = AP_EAPOL_M1;
if(ntohs(wpakey->wpadatalen) == IEEE80211_PMKID_SIZE)
	{
	pmkid = (ieee80211_pmkid_t*)(eapolplptr + IEEE80211_WPAKEY_SIZE);
	if(memcmp(&rsnsuiteoui, pmkid->oui, 3) == 0)
		{
		if(pmkid->len >= 0x14)
			{
			if(pmkid->type == PMKID_KDE)
				{
				if(memcmp(pmkid->pmkid, &zeroed, PMKID_MAX) != 0) authseqakt.status |= AP_PMKID;
				}
			}
		}
	}
for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if(memcmp((aplist + i)->macap, authseqakt.macap, ETH_ALEN) == 0)
		{
		if(((aplist + i)->status & AP_PMKID) == AP_PMKID) return;
		(aplist + i)->status |= authseqakt.status;
		return;
		}
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211eapol(void)
{

eapolplptr = eapauthplptr + IEEE80211_EAPAUTH_SIZE;
eapolpllen = eapauthpllen - IEEE80211_EAPAUTH_SIZE;
if((eapolpllen + IEEE80211_EAPAUTH_SIZE + IEEE80211_LLC_SIZE) > payloadlen) return;
wpakey = (ieee80211_wpakey_t*)eapolplptr;
if((kdv = ntohs(wpakey->keyinfo) & WPA_KEY_INFO_TYPE_MASK) == 0) return;
keyinfo = (get_keyinfo(ntohs(wpakey->keyinfo)));
switch(keyinfo)
	{
	case M1:
	process80211eapol_m1();
	break;

	case M2:
	process80211eapol_m2();
	break;

	case M3:
	process80211eapol_m3();
	break;

	case M4:
	if(deauthenticationflag == true) process80211eapol_m4();
	break;
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211eapauthentication(void)
{
tshold = tsakt;
eapauthplptr = payloadptr + IEEE80211_LLC_SIZE;
eapauthpllen = payloadlen - IEEE80211_LLC_SIZE;
eapauth = (ieee80211_eapauth_t*)eapauthplptr;
eapauthlen = ntohs(eapauth->len);
if(eapauthlen > (eapauthpllen - IEEE80211_EAPAUTH_SIZE)) return;
if(eapauth->type == EAPOL_KEY) process80211eapol();
/*
else if(auth->type == EAP_PACKET) process80211exteap(authlen);
else if(auth->type == EAPOL_START)
	{
	send_eap_request_id(macfrx->addr2, macfrx->addr1);
	}
*/
writeepb();
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211reassociationresponse(void)
{
tshold = tsakt;
memcpy(&authseqakt.macap, macfrx->addr2, ETH_ALEN);
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211reassociationrequest(void)
{
static size_t i;
static ieee80211_reassoc_req_t *reassociationrequest;
static u16 reassociationrequestlen;

tshold = tsakt;
reassociationrequest = (ieee80211_reassoc_req_t*)payloadptr;
if((reassociationrequestlen = payloadlen - IEEE80211_REASSOCIATIONREQUEST_SIZE) < IEEE80211_IETAG_SIZE) return;
memcpy(&authseqakt.macap, macfrx->addr1, ETH_ALEN);
for(i = 0; i < CLIENTLIST_MAX - 1; i++)
	{
	if(memcmp(macfrx->addr2, (clientlist + i)->macclient, ETH_ALEN) != 0) continue;
	if(memcmp(macfrx->addr1, (clientlist + i)->macap, ETH_ALEN) != 0) continue;
	(clientlist + i)->tsakt = tsakt;
	if((clientlist + i)->count == 0) return;
	if((tsakt - (clientlist + i)->tsassoc) > TIMEREASSOCWAIT)
		{
		tagwalk_channel_essid_rsn(&(clientlist + i)->ie, reassociationrequestlen, reassociationrequest->ie);
		if(((clientlist + i)->ie.flags & APRSNAKM_PSK) != 0)
			{
			send_80211_reassociationresponse((clientlist + i)->aid++);
			if((clientlist + i)->aid > 0xff) (clientlist + i)->aid  = 1;
			send_80211_eapolm1();
			(clientlist + i)->count--;
			}
		else (clientlist + i)->count = 0;
		writeepb();
		}
	(clientlist + i)->tsassoc = tsakt;
	return;
	}
memset((clientlist + i), 0, CLIENTLIST_SIZE);
(clientlist + i)->tsakt = tsakt;
(clientlist + i)->tsassoc = tsfirst;
(clientlist + i)->tsreassoc = tsfirst;
(clientlist + i)->count = attemptclientmax;
(clientlist + i)->aid = 1;
memcpy((clientlist + i)->macclient, macfrx->addr2, ETH_ALEN);
memcpy((clientlist + i)->macap, macfrx->addr1, ETH_ALEN);
tagwalk_channel_essid_rsn(&(clientlist + i)->ie, reassociationrequestlen, reassociationrequest->ie);
if(((clientlist + i)->ie.flags & APRSNAKM_PSK) != 0)
	{
	send_80211_reassociationresponse((clientlist + i)->aid++);
	send_80211_eapolm1();
	}
else (clientlist + i)->count = 0;
qsort(clientlist, i + 1, CLIENTLIST_SIZE, sort_clientlist_by_tsakt);
writeepb();
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211associationresponse(void)
{
tshold = tsakt;
memcpy(&authseqakt.macap, macfrx->addr2, ETH_ALEN);
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211associationrequest(void)
{
static size_t i;
static ieee80211_assoc_req_t *associationrequest;
static u16 associationrequestlen;

tshold = tsakt;
associationrequest = (ieee80211_assoc_req_t*)payloadptr;
if((associationrequestlen = payloadlen - IEEE80211_ASSOCIATIONREQUEST_SIZE) < IEEE80211_IETAG_SIZE) return;
memcpy(&authseqakt.macap, macfrx->addr1, ETH_ALEN);
for(i = 0; i < CLIENTLIST_MAX - 1; i++)
	{
	if(memcmp(macfrx->addr2, (clientlist + i)->macclient, ETH_ALEN) != 0) continue;
	if(memcmp(macfrx->addr1, (clientlist + i)->macap, ETH_ALEN) != 0) continue;
	(clientlist + i)->tsakt = tsakt;
	if((clientlist + i)->count == 0) return;
	tagwalk_channel_essid_rsn(&(clientlist + i)->ie, associationrequestlen, associationrequest->ie);
	if((tsakt - (clientlist + i)->tsassoc) > TIMEASSOCWAIT)
		{
		if(((clientlist + i)->ie.flags & APRSNAKM_PSK) != 0)
			{
			send_80211_associationresponse();
			send_80211_eapolm1();
			(clientlist + i)->count--;
			}
		else (clientlist + i)->count = 0;
		writeepb();
		}
	(clientlist + i)->tsassoc = tsakt;
	return;
	}
memset((clientlist + i), 0, CLIENTLIST_SIZE);
(clientlist + i)->tsakt = tsakt;
(clientlist + i)->tsassoc = tsfirst;
(clientlist + i)->tsreassoc = tsfirst;
(clientlist + i)->count = attemptclientmax;
memcpy((clientlist + i)->macclient, macfrx->addr2, ETH_ALEN);
memcpy((clientlist + i)->macap, macfrx->addr1, ETH_ALEN);
tagwalk_channel_essid_rsn(&(clientlist + i)->ie, associationrequestlen, associationrequest->ie);
if(((clientlist + i)->ie.flags & APRSNAKM_PSK) != 0)
	{
	send_80211_associationresponse();
	send_80211_eapolm1();
	}
else (clientlist + i)->count = 0;
qsort(clientlist, i + 1, CLIENTLIST_SIZE, sort_clientlist_by_tsakt);
writeepb();
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211authentication_fmclient(void)
{
size_t i;

for(i = 0; i < CLIENTLIST_MAX - 1; i++)
	{
	if(memcmp(macfrx->addr2, (clientlist + i)->macclient, ETH_ALEN) != 0) continue;
	if(memcmp(macfrx->addr1, (clientlist + i)->macap, ETH_ALEN) != 0) continue;
	(clientlist + i)->tsakt = tsakt;
	if((clientlist + i)->count == 0) return;
	if((tsakt - (clientlist + i)->tsauth) > TIMEAUTHWAIT)
		{
		send_80211_authenticationresponse();
		writeepb();
		}
	(clientlist + i)->tsauth = tsakt;
	return;
	}
memset((clientlist + i), 0, CLIENTLIST_SIZE);
(clientlist + i)->tsakt = tsakt;
(clientlist + i)->tsauth = tsfirst;
(clientlist + i)->tsassoc = tsfirst;
(clientlist + i)->tsreassoc = tsfirst;
(clientlist + i)->count = attemptclientmax;
memcpy((clientlist + i)->macclient, macfrx->addr2, ETH_ALEN);
memcpy((clientlist + i)->macap, macfrx->addr1, ETH_ALEN);
send_80211_authenticationresponse();
qsort(clientlist, i + 1, CLIENTLIST_SIZE, sort_clientlist_by_tsakt);
writeepb();
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211authentication(void)
{
size_t i;
static ieee80211_auth_t *auth;

tshold = tsakt;
auth = (ieee80211_auth_t*)payloadptr;
if(payloadlen < IEEE80211_AUTH_SIZE) return;
if(auth->algorithm == OPEN_SYSTEM)
	{
	if(auth->sequence == 1) process80211authentication_fmclient();
	else if(auth->sequence == 2)
		{
		if(memcmp(&macclientrg, macfrx->addr1, 3) == 0)
			{
			for(i = 0; i < APLIST_MAX - 1; i++)
				{
				if(memcmp((aplist + i)->macap, macfrx->addr2, ETH_ALEN) == 0)
					{
					(aplist + i)->status |= AP_IN_RANGE;
					if((tsakt - (aplist + i)->tsauth) > TIMEAUTHWAIT)
						{
						if(((aplist + i)->ie.flags & APRSNAKM_PSK) != 0) send_80211_associationrequest(i);
						writeepb();
						}
					(aplist + i)->tsauth = tsakt;
					break;
					}
				}
			}
		}
	}
return;
}
/*---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
static void get_tag(u8 ietag, essid_t *essid, int infolen, u8 *infostart)
{
static ieee80211_ietag_t *infoptr;

while(0 < infolen)
	{
	infoptr = (ieee80211_ietag_t*)infostart;
	if(infolen < (int)(infoptr->len + IEEE80211_IETAG_SIZE)) return;
	if(infoptr->id == ietag)
		{
		essid->len = infoptr->len;
		essid->essid = (u8*)infoptr->ie;
		return;
		}
	infostart += infoptr->len + IEEE80211_IETAG_SIZE;
	infolen -= infoptr->len + IEEE80211_IETAG_SIZE;
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211proberequest_directed(void)
{
static size_t i;
static ieee80211_proberequest_t *proberequest;
static u16 proberequestlen; 
static essid_t essid;

proberequest = (ieee80211_proberequest_t*)payloadptr;
if((proberequestlen = payloadlen - IEEE80211_PROBERESPONSE_SIZE)  < IEEE80211_IETAG_SIZE) return;
get_tag(TAG_SSID, &essid, proberequestlen, proberequest->ie);
if(memcmp(&macaprg, macfrx->addr1, 3) != 0)
	{
	send_80211_probereresponse(macfrx->addr2, macfrx->addr1, essid.len, essid.essid);
	for(i = 0; i < MACLIST_MAX - 1; i++)
		{
		if(memcmp(macfrx->addr1, (maclist + i)->mac, ETH_ALEN) != 0) continue;
		(aplist + i)->tsakt = tsakt;
		return;
		}
	(maclist + i)->tsakt = tsakt;
	memcpy((maclist + i)->mac, macfrx->addr1, ETH_ALEN);
	qsort(maclist, i + 1, MACLIST_SIZE, sort_maclist_by_tsakt);
	writeepb();
	return;
	}
for(i = 0; i < APRGLIST_MAX - 1; i++)
	{
	if(memcmp(&macaprg, macfrx->addr1, ETH_ALEN) != 0) continue;
	(aprglist + i)->tsakt = tsakt;
	send_80211_probereresponse(macfrx->addr2, (aprglist + i)->macaprg, essid.len, essid.essid);
	return;
	}
writeepb();
return;
}
/*---------------------------------------------------------------------------*/
static inline void process80211proberequest_undirected(void)
{
static size_t i;
static ieee80211_proberequest_t *proberequest;
static u16 proberequestlen; 
static essid_t essid;

proberequest = (ieee80211_proberequest_t*)payloadptr;
if((proberequestlen = payloadlen - IEEE80211_PROBERESPONSE_SIZE)  < IEEE80211_IETAG_SIZE) return;
get_tag(TAG_SSID, &essid, proberequestlen, proberequest->ie);
if(essid.len == 0)
	{
	if(proberesponseindex >= proberesponsetxmax) proberesponseindex = 0;
	if((aprglist + proberesponseindex)->essidlen == 0)  proberesponseindex = 0;
	send_80211_probereresponse(macfrx->addr2, (aprglist + proberesponseindex)->macaprg, (aprglist + proberesponseindex)->essidlen, (aprglist + proberesponseindex)->essid);
	proberesponseindex++;
	return;
	}
for(i = 0; i < APRGLIST_MAX - 1; i++)
	{
	if((aprglist + i)->essidlen != essid.len) continue;
	if(memcmp((aprglist + i)->essid, essid.essid, essid.len) != 0) continue;
	(aprglist + i)->tsakt = tsakt;
	send_80211_probereresponse(macfrx->addr2, (aprglist + i)->macaprg, essid.len, essid.essid);
	return;
	}
memset((aprglist + i), 0, APRGLIST_SIZE);
(aprglist + i)->tsakt = tsakt;
(aprglist + i)->essidlen = essid.len;
memcpy((aprglist + i)->essid, essid.essid, essid.len);
(aprglist + i)->macaprg[5] = nicaprg & 0xff;
(aprglist + i)->macaprg[4] = (nicaprg >> 8) & 0xff;
(aprglist + i)->macaprg[3] = (nicaprg >> 16) & 0xff;
(aprglist + i)->macaprg[2] = ouiaprg & 0xff;
(aprglist + i)->macaprg[1] = (ouiaprg >> 8) & 0xff;
(aprglist + i)->macaprg[0] = (ouiaprg >> 16) & 0xff;
nicaprg++;
send_80211_probereresponse(macfrx->addr2, (aprglist + i)->macaprg, essid.len, essid.essid);
qsort(aprglist, i + 1, APRGLIST_SIZE, sort_aprglist_by_tsakt);
writeepb();
return;
}
/*---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
static inline void process80211proberesponse(void)
{
static size_t i;
static ieee80211_beacon_proberesponse_t *proberesponse;
static u16 proberesponselen;

proberesponse = (ieee80211_beacon_proberesponse_t*)payloadptr;
if((proberesponselen = payloadlen - IEEE80211_PROBERESPONSE_SIZE) < IEEE80211_IETAG_SIZE) return;
for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if(memcmp(macfrx->addr3, (aplist + i)->macap, ETH_ALEN) != 0) continue;
	(aplist + i)->tsakt = tsakt;
	if(((aplist + i)->status & AP_PROBERESPONSE) == 0)
		{
		writeepb();
		#ifdef NMEAOUT
		if(fd_gps > 0) writegpwpl(i);
		#endif
		(aplist + i)->status |= AP_PROBERESPONSE;
		tshold = tsakt;
		}
	tagwalk_channel_essid_rsn(&(aplist + i)->ie, proberesponselen, proberesponse->ie);
	if((aplist + i)->ie.channel == 0) (aplist + i)->ie.channel = (scanlist + scanlistindex)->channel;
	if(((aplist + i)->ie.flags & APIE_ESSID) == APIE_ESSID) (aplist + i)->status |= AP_ESSID;
	return;
	}
memset((aplist + i), 0, APLIST_SIZE);
(aplist + i)->tsakt = tsakt;
(aplist + i)->tshold1 = tsakt;
(aplist + i)->tsauth = tsfirst;
(aplist + i)->count = attemptapmax;
memcpy((aplist + i)->macap, macfrx->addr3, ETH_ALEN);
memcpy((aplist + i)->macclient, &macbc, ETH_ALEN);
(aplist + i)->status |= AP_PROBERESPONSE;
tagwalk_channel_essid_rsn(&(aplist + i)->ie, proberesponselen, proberesponse->ie);
if((aplist + i)->ie.channel == 0) (aplist + i)->ie.channel = (scanlist + scanlistindex)->channel;
if((aplist + i)->ie.channel != (scanlist + scanlistindex)->channel) return;
if(((aplist + i)->ie.flags & APIE_ESSID) == APIE_ESSID) (aplist + i)->status |= AP_ESSID;
if(deauthenticationflag == true)
	{
	if(((aplist + i)->ie.flags & AP_MFP) == 0)
		{
		if(((aplist + i)->ie.flags & APAKM_MASK) != 0) send_80211_deauthentication_fm_ap(macbc, (aplist + i)->macap, WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA);
		}
	}
if(associationflag == true)
	{
	if((((aplist + i)->ie.flags & APRSNAKM_PSK) != 0) && (((aplist + i)->ie.flags & APIE_ESSID) == 0)) send_80211_authenticationrequest();
	}
if(reassociationflag == true)
	{
	if(((aplist + i)->ie.flags & APRSNAKM_PSK) != 0) send_80211_reassociationrequest(i);
	}
writeepb();
#ifdef NMEAOUT
if(fd_gps > 0) writegpwpl(i);
#endif
qsort(aplist, i + 1, APLIST_SIZE, sort_aplist_by_tsakt);
tshold = tsakt;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211beacon_rca(void)
{
static size_t i;
static ieee80211_beacon_proberesponse_t *beacon;
static u16 beaconlen;

beacon = (ieee80211_beacon_proberesponse_t*)payloadptr;
if((beaconlen = payloadlen - IEEE80211_BEACON_SIZE) < IEEE80211_IETAG_SIZE) return;
for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if(memcmp(macfrx->addr3, (aplist + i)->macap, ETH_ALEN) != 0) continue;
	(aplist + i)->tsakt = tsakt;
	if(((aplist + i)->status & AP_BEACON) == 0)
		{
		tshold = tsakt;
		(aplist + i)->status |= AP_BEACON;
		}
	if((aplist + i)->status >= AP_EAPOL_M3) return;
	tagwalk_channel_essid_rsn(&(aplist + i)->ie, beaconlen, beacon->ie);
	if((aplist + i)->ie.channel == 0) (aplist + i)->ie.channel = (scanlist + scanlistindex)->channel;
	if((aplist + i)->ie.channel != (scanlist + scanlistindex)->channel) return;
	(aplist + i)->count = (scanlist + scanlistindex)->frequency;
	return;
	}
memset((aplist + i), 0, APLIST_SIZE);
(aplist + i)->tsakt = tsakt;
(aplist + i)->tshold1 = tsakt;
(aplist + i)->tsauth = tsfirst;
(aplist + i)->count = attemptapmax;
memcpy((aplist + i)->macap, macfrx->addr3, ETH_ALEN);
memcpy((aplist + i)->macclient, &macbc, ETH_ALEN);
(aplist + i)->status |= AP_BEACON;
tagwalk_channel_essid_rsn(&(aplist + i)->ie, beaconlen, beacon->ie);
if((aplist + i)->ie.channel == 0) (aplist + i)->ie.channel = (scanlist + scanlistindex)->channel;
if((aplist + i)->ie.channel != (scanlist + scanlistindex)->channel) return;
(aplist + i)->count = (scanlist + scanlistindex)->frequency;
qsort(aplist, i + 1, APLIST_SIZE, sort_aplist_by_tsakt);
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211beacon(void)
{
static size_t i;
static ieee80211_beacon_proberesponse_t *beacon;
static u16 beaconlen;

beacon = (ieee80211_beacon_proberesponse_t*)payloadptr;
if((beaconlen = payloadlen - IEEE80211_BEACON_SIZE) < IEEE80211_IETAG_SIZE) return;
for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if(memcmp(macfrx->addr3, (aplist + i)->macap, ETH_ALEN) != 0) continue;
	(aplist + i)->tsakt = tsakt;
	if(((aplist + i)->status & AP_BEACON) == 0)
		{
		writeepb();
		tshold = tsakt;
		#ifdef NMEAOUT
		if(fd_gps > 0) writegpwpl(i);
		#endif
		(aplist + i)->status |= AP_BEACON;
		}
	if((aplist + i)->status >= AP_EAPOL_M3) return;
	tagwalk_channel_essid_rsn(&(aplist + i)->ie, beaconlen, beacon->ie);
	if((aplist + i)->ie.channel == 0) (aplist + i)->ie.channel = (scanlist + scanlistindex)->channel;
	if((aplist + i)->ie.channel != (scanlist + scanlistindex)->channel) return;
	if((aplist + i)->tsakt - (aplist + i)->tshold1 > TIMEBEACONNEW)
		{
		(aplist + i)->count = attemptapmax;
		memcpy((aplist + i)->macclient, &macbc, ETH_ALEN);
		(aplist + i)->tshold1 = tsakt;
		}
	if((aplist + i)->count == 0) return;
	if(associationflag == true)
		{
		if(((aplist + i)->count % 8) == 6)
			{
			if(((aplist + i)->status & AP_EAPOL_M1) == 0)
				{
				if(((aplist + i)->status & AP_ESSID) == AP_ESSID)
					{
					if(((aplist + i)->ie.flags & APRSNAKM_PSK) != 0) send_80211_authenticationrequest();
					}
				}
			}
		}
	if(deauthenticationflag == true)
		{
		if(((aplist + i)->count % 8) == 4)
			{
			if(((aplist + i)->ie.flags & AP_MFP) == 0)
				{
				if(((aplist + i)->ie.flags & APAKM_MASK) != 0)
					{
					if(memcmp(&macbc, (aplist + i)->macclient, ETH_ALEN) != 0)
						{
						send_80211_deauthentication_fm_ap((aplist + i)->macclient, (aplist + i)->macap, WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA);
						send_80211_deauthentication_fm_client((aplist + i)->macclient, (aplist + i)->macap, WLAN_REASON_DEAUTH_LEAVING);
						}
					else send_80211_deauthentication_fm_ap(macbc, (aplist + i)->macap, WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA);
					}
				}
			}
		}
	if(reassociationflag == true)
		{
		if(((aplist + i)->count % 8) == 2)
			{
			if(((aplist + i)->ie.flags & APRSNAKM_PSK) != 0) send_80211_associationrequest_org(i);
			}
		if(((aplist + i)->count % 8) == 0)
			{
			if(((aplist + i)->ie.flags & APRSNAKM_PSK) != 0) send_80211_reassociationrequest(i);
			}
		}
	(aplist + i)->count--;
	return;
	}
memset((aplist + i), 0, APLIST_SIZE);
(aplist + i)->tsakt = tsakt;
(aplist + i)->tshold1 = tsakt;
(aplist + i)->tsauth = tsfirst;
(aplist + i)->count = attemptapmax;
memcpy((aplist + i)->macap, macfrx->addr3, ETH_ALEN);
memcpy((aplist + i)->macclient, &macbc, ETH_ALEN);
(aplist + i)->status |= AP_BEACON;
tagwalk_channel_essid_rsn(&(aplist + i)->ie, beaconlen, beacon->ie);
if((aplist + i)->ie.channel == 0) (aplist + i)->ie.channel = (scanlist + scanlistindex)->channel;
if((aplist + i)->ie.channel != (scanlist + scanlistindex)->channel) return;
if(((aplist + i)->ie.flags & APIE_ESSID) == APIE_ESSID) (aplist + i)->status |= AP_ESSID;
if(deauthenticationflag == true)
	{
	if(((aplist + i)->ie.flags & AP_MFP) == 0)
		{
		if(((aplist + i)->ie.flags & APAKM_MASK) != 0) send_80211_deauthentication_fm_ap(macbc, (aplist + i)->macap, WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA);
		}
	}
if(associationflag == true)
	{
	if((((aplist + i)->ie.flags & APRSNAKM_PSK) != 0) && (((aplist + i)->ie.flags & APIE_ESSID) == 0)) send_80211_authenticationrequest();
	}
if(proberequestflag == true)
	{
	if(((aplist + i)->ie.flags & APIE_ESSID) == 0) send_80211_proberequest_undirected();
	}
if(reassociationflag == true)
	{
	if(((aplist + i)->ie.flags & APRSNAKM_PSK) != 0) send_80211_associationrequest_org(i);
	}
writeepb();
#ifdef NMEAOUT
if(fd_gps > 0) writegpwpl(i);
#endif
qsort(aplist, i + 1, APLIST_SIZE, sort_aplist_by_tsakt);
tshold = tsakt;
return;
}
/*===========================================================================*/
/*===========================================================================*/
#ifdef NMEAOUT
static inline __attribute__((always_inline)) void process_nmea0183(void)
{
static char *nmeaptr;
static const char *gprmcid = "$GPRMC,";
static const char *gpggaid = "$GPGGA,";

if((nmealen = read(fd_gps, nmeabuffer, NMEA_SIZE)) < NMEA_MIN)
	{
	if(packetlen == - 1) errorcount++;
	return;
	}
nmeabuffer[nmealen] = 0;
if((nmeaptr = strstr(nmeabuffer, gprmcid)) != NULL)
	{
	gprmclen = 0;
	while(gprmclen < (NMEA_MSG_MAX -2))
		{
		if(nmeaptr[gprmclen] == '*')
			{
			gprmclen += strlen("00\r\n") + 1;
			memcpy(&gprmc, nmeaptr, gprmclen);
			break;
			}
		gprmclen++;
		}
	}
if((nmeaptr = strstr(nmeabuffer, gpggaid)) != NULL)
	{
	gpggalen = 0;
	while(gpggalen < (NMEA_MSG_MAX -2))
		{
		if(nmeaptr[gpggalen] == '*')
			{
			gpggalen += strlen("00\r\n") + 1;
			memcpy(&gpgga, nmeaptr, gpggalen);
			return;
			}
		gpggalen++;
		}
	}
return;
}
#endif
/*===========================================================================*/
static inline __attribute__((always_inline)) void process_packet_rca(void)
{
if((packetlen = read(fd_socket_rx, packetptr, PCAPNG_SNAPLEN)) < RTHRX_SIZE)
	{
	if(packetlen == - 1) errorcount++;
	return;
	}
rth = (rth_t*)packetptr;
#ifndef __LITTLE_ENDIAN__
if((rth->it_present & IEEE80211_RADIOTAP_DBM_ANTSIGNAL) == 0) return;
if(rth->it_len > packetlen)
	{
	errorcount++;
	return;
	}
ieee82011ptr = packetptr + rth->it_len;
ieee82011len = packetlen - rth->it_len;
#else
if((le32toh(rth->it_present) & IEEE80211_RADIOTAP_DBM_ANTSIGNAL) == 0) return;
if(le16toh(rth->it_len) > packetlen)
	{
	errorcount++;
	return;
	}
ieee82011ptr = packetptr + le16toh(rth->it_len);
ieee82011len = packetlen - le16toh(rth->it_len);
#endif
if(ieee82011len <= MAC_SIZE_RTS) return;
macfrx = (ieee80211_mac_t*)ieee82011ptr;
if((macfrx->from_ds == 1) && (macfrx->to_ds == 1))
	{
	payloadptr = ieee82011ptr +MAC_SIZE_LONG;
	payloadlen = ieee82011len -MAC_SIZE_LONG;
	}
else
	{
	payloadptr = ieee82011ptr +MAC_SIZE_NORM;
	payloadlen = ieee82011len -MAC_SIZE_NORM;
	}
clock_gettime(CLOCK_REALTIME, &tspecakt);
tsakt = ((u64)tspecakt.tv_sec * 1000000000ULL) + tspecakt.tv_nsec;
packetcount++;
if(macfrx->type == IEEE80211_FTYPE_MGMT)
	{
	if(macfrx->subtype == IEEE80211_STYPE_BEACON) process80211beacon_rca();
//	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_RESP) process80211proberesponse_rca();
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process_packet(void)
{
if((packetlen = read(fd_socket_rx, packetptr, PCAPNG_SNAPLEN)) < RTHRX_SIZE)
	{
	if(packetlen == -1) errorcount++;
	return;
	}
rth = (rth_t*)packetptr;
#ifndef __LITTLE_ENDIAN__
if((rth->it_present & IEEE80211_RADIOTAP_DBM_ANTSIGNAL) == 0) return;
if(rth->it_len > packetlen)
	{
	errorcount++;
	return;
	}
ieee82011ptr = packetptr + rth->it_len;
ieee82011len = packetlen - rth->it_len;
#else
if((le32toh(rth->it_present) & IEEE80211_RADIOTAP_DBM_ANTSIGNAL) == 0) return;
if(le16toh(rth->it_len) > packetlen)
	{
	errorcount++;
	return;
	}
ieee82011ptr = packetptr + le16toh(rth->it_len);
ieee82011len = packetlen - le16toh(rth->it_len);
#endif
if(ieee82011len <= MAC_SIZE_RTS) return;
macfrx = (ieee80211_mac_t*)ieee82011ptr;
if((macfrx->from_ds == 1) && (macfrx->to_ds == 1))
	{
	payloadptr = ieee82011ptr +MAC_SIZE_LONG;
	payloadlen = ieee82011len -MAC_SIZE_LONG;
	}
else
	{
	payloadptr = ieee82011ptr +MAC_SIZE_NORM;
	payloadlen = ieee82011len -MAC_SIZE_NORM;
	}
clock_gettime(CLOCK_REALTIME, &tspecakt);
tsakt = ((u64)tspecakt.tv_sec * 1000000000ULL) + tspecakt.tv_nsec;
packetcount++;
if(macfrx->type == IEEE80211_FTYPE_MGMT)
	{
	if(macfrx->subtype == IEEE80211_STYPE_BEACON) process80211beacon();
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_RESP) process80211proberesponse();
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_REQ)
		{
		if(memcmp(&macbc, macfrx->addr3, ETH_ALEN) == 0) process80211proberequest_undirected();
		else process80211proberequest_directed();
		}
	else if(macfrx->subtype == IEEE80211_STYPE_AUTH) process80211authentication();
	else if(macfrx->subtype == IEEE80211_STYPE_ASSOC_REQ) process80211associationrequest();
	else if(macfrx->subtype == IEEE80211_STYPE_ASSOC_RESP) process80211associationresponse();
	else if(macfrx->subtype == IEEE80211_STYPE_REASSOC_REQ)process80211reassociationrequest();
	else if(macfrx->subtype == IEEE80211_STYPE_REASSOC_RESP) process80211reassociationresponse();
	else if(macfrx->subtype == IEEE80211_STYPE_ACTION) process80211action();
	}
else if(macfrx->type == IEEE80211_FTYPE_CTL)
	{
	if(macfrx->subtype == IEEE80211_STYPE_BACK) process80211blockack();
	else if(macfrx->subtype == IEEE80211_STYPE_BACK) process80211blockackreq();
	else if(macfrx->subtype == IEEE80211_STYPE_PSPOLL) process80211pspoll();
	}
else if(macfrx->type == IEEE80211_FTYPE_DATA)
	{
	if((macfrx->subtype &IEEE80211_STYPE_QOS_DATA) == IEEE80211_STYPE_QOS_DATA)
		{
		payloadptr += IEEE80211_QOS_SIZE;
		payloadlen -= IEEE80211_QOS_SIZE;
		}
	if(payloadlen > IEEE80211_LLC_SIZE)
		{
		llcptr = payloadptr;
		llc = (ieee80211_llc_t*)llcptr;
		if(((ntohs(llc->type)) == LLC_TYPE_AUTH) && (llc->dsap == IEEE80211_LLC_SNAP) && (llc->ssap == IEEE80211_LLC_SNAP)) process80211eapauthentication();
		}
	if((macfrx->subtype &IEEE80211_STYPE_QOS_NULLFUNC) == IEEE80211_STYPE_QOS_NULLFUNC) process80211qosnull();
	else if((macfrx->subtype &IEEE80211_STYPE_NULLFUNC) == IEEE80211_STYPE_NULLFUNC) process80211null();
	else if((macfrx->subtype &IEEE80211_STYPE_QOS_DATA) == IEEE80211_STYPE_QOS_DATA) process80211qosdata();
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
/* MAIN SCAN LOOP */
static bool nl_scanloop(void)
{
static ssize_t i;
static int fd_epoll = 0;
static int epi = 0;
static int epret = 0;
static struct epoll_event ev, events[EPOLL_EVENTS_MAX];
static size_t packetcountlast = 0;
static u64 timer1count;
static struct timespec sleepled;

if((fd_epoll= epoll_create(1)) < 0) return false;
ev.data.fd = fd_socket_rx;
ev.events = EPOLLIN;
if(epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_socket_rx, &ev) < 0) return false;
epi++;

ev.data.fd = fd_timer1;
ev.events = EPOLLIN;
if(epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_timer1, &ev) < 0) return false;
epi++;

#ifdef NMEAOUT
if(fd_gps > 0)
	{
	ev.data.fd = fd_gps;
	ev.events = EPOLLIN;
	if(epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_gps, &ev) < 0) return false;
	epi++;
	}
#endif

sleepled.tv_sec = 0;
sleepled.tv_nsec = GPIO_LED_DELAY;
while(!wanteventflag)
	{
	if(errorcount > errorcountmax) wanteventflag |= EXIT_ON_ERROR;
	epret = epoll_pwait(fd_epoll, events, epi, timerwaitnd, NULL);
	if(epret == -1)
		{
		if(errno != EINTR) errorcount++;
		continue;
		}
	for(i = 0; i < epret; i++)
		{
		if(events[i].data.fd == fd_socket_rx) process_packet();
		else if(events[i].data.fd == fd_timer1)
			{
			read(fd_timer1, &timer1count, sizeof(u64));
			lifetime++;
			#ifdef STATUSOUT
			show_realtime();
			#endif
			clock_gettime(CLOCK_REALTIME, &tspecakt);
			tsakt = ((u64)tspecakt.tv_sec * 1000000000ULL) + tspecakt.tv_nsec;
			if((tsakt - tshold) > timehold)
				{
				scanlistindex++;
				if(nl_set_frequency() == false) errorcount++;
				tshold = tsakt;
				}
			if((lifetime % 10) == 0)
				{
				if(gpiostatusled > 0)
					{
					GPIO_SET = 1 << gpiostatusled;
					nanosleep(&sleepled, NULL);
					GPIO_CLR = 1 << gpiostatusled;
					}
				if(gpiobutton > 0)
					{
					if(GET_GPIO(gpiobutton) > 0)
						{
						wanteventflag |= EXIT_ON_GPIOBUTTON;
						if(gpiostatusled > 0) GPIO_SET = 1 << gpiostatusled;
						}
					}
				}
			if((tottime > 0) && (lifetime >= tottime)) wanteventflag |= EXIT_ON_TOT;
			if((lifetime % watchdogcountmax) == 0)
				{
				if(packetcount == packetcountlast) wanteventflag |= EXIT_ON_WATCHDOG;
				packetcountlast = packetcount;
				}
			}
		#ifdef NMEAOUT
		else if(events[i].data.fd == fd_gps) process_nmea0183();
		#endif
		}
	if(epret == 0) send_80211_beacon();
	}
return true;
}
/*===========================================================================*/
/* RCA SCAN LOOP */
static bool nl_scanloop_rca(void)
{
static ssize_t i;
static int fd_epoll = 0;
static int epi = 0;
static int epret = 0;
static struct epoll_event ev, events[EPOLL_EVENTS_MAX];
static size_t packetcountlast = 0;
static u64 timer1count;
static struct timespec sleepled;

if((fd_epoll= epoll_create(1)) < 0) return false;
ev.data.fd = fd_socket_rx;
ev.events = EPOLLIN;
if(epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_socket_rx, &ev) < 0) return false;
epi++;

ev.data.fd = fd_timer1;
ev.events = EPOLLIN;
if(epoll_ctl(fd_epoll, EPOLL_CTL_ADD, fd_timer1, &ev) < 0) return false;
epi++;

sleepled.tv_sec = 0;
sleepled.tv_nsec = GPIO_LED_DELAY;
while(!wanteventflag)
	{
	if(errorcount > errorcountmax) wanteventflag |= EXIT_ON_ERROR;
	epret = epoll_pwait(fd_epoll, events, epi, timerwaitnd, NULL);
	if(epret == -1)
		{
		if(errno != EINTR) errorcount++;
		continue;
		}
	for(i = 0; i < epret; i++)
		{
		if(events[i].data.fd == fd_socket_rx) process_packet_rca();
		else if(events[i].data.fd == fd_timer1)
			{
			read(fd_timer1, &timer1count, sizeof(u64));
			lifetime++;
			if((lifetime % 5) == 0) show_realtime_rca();
			scanlistindex++;
			if(nl_set_frequency() == false) errorcount++;
			if((lifetime % 10) == 0)
				{
				if(gpiostatusled > 0)
					{
					GPIO_SET = 1 << gpiostatusled;
					nanosleep(&sleepled, NULL);
					GPIO_CLR = 1 << gpiostatusled;
					}
				if(gpiobutton > 0)
					{
					if(GET_GPIO(gpiobutton) > 0)
						{
						wanteventflag |= EXIT_ON_GPIOBUTTON;
						if(gpiostatusled > 0) GPIO_SET = 1 << gpiostatusled;
						}
					}
				}
			if((tottime > 0) && (lifetime >= tottime)) wanteventflag |= EXIT_ON_TOT;
			if((lifetime % watchdogcountmax) == 0)
				{
				if(packetcount == packetcountlast) wanteventflag |= EXIT_ON_WATCHDOG;
				packetcountlast = packetcount;
				}
			}
		}
	}
return true;
}
/*===========================================================================*/
/*===========================================================================*/
/* IOCTL WIRELESS EXTENSIONS */
static void ioctl_get_wireless_extensions(size_t i)
{
struct iwreq pwrq;
static const char *protocol80211 = "IEEE 802.11";

memset(&pwrq, 0, sizeof(pwrq));
memcpy(pwrq.ifr_name, (ifpresentlist + i)->name, IF_NAMESIZE);
if(ioctl(fd_socket_unix, SIOCGIWNAME, &pwrq) < 0) return;
if(strncmp(protocol80211, pwrq.u.name, 11) == 0) (ifpresentlist + i)->type |= IF_HAS_WEXT;
return;
}
/*===========================================================================*/
/* NETLINK */
static struct nlattr *nla_next(const struct nlattr *nla, int *remaining)
{
int totlen = NLA_ALIGN(nla->nla_len);

*remaining -= totlen;
return (struct nlattr*)((u8*)nla + totlen);
}
/*---------------------------------------------------------------------------*/
static int nla_ok(const struct nlattr *nla, int remaining)
{
size_t r = remaining;

return r >= sizeof(*nla) && nla->nla_len >= sizeof(*nla) && nla->nla_len <= r;
}
/*---------------------------------------------------------------------------*/
static int nla_datalen(const struct nlattr *nla)
{
return nla->nla_len - NLA_HDRLEN;
}
/*---------------------------------------------------------------------------*/
static void *nla_data(const struct nlattr *nla)
{
return (u8*)nla + NLA_HDRLEN;
}
/*---------------------------------------------------------------------------*/
static void nl_get_supported_bands(interface_t *ipl, struct nlattr* nla)
{
static int nlanremlen;
static struct nlattr *nlai, *nlan;
static frequencylist_t *freql;

nlai = (struct nlattr*)nla_data(nla);
nlan = (struct nlattr*)nla_data(nlai);
if(nlan->nla_type != NL80211_BAND_ATTR_FREQS) return;
nlai = (struct nlattr*)nla_data(nlan);
nlanremlen = nlai->nla_len - sizeof(struct nlattr);
nlan = (struct nlattr*)nla_data(nlai);
freql = ipl->frequencylist;
if(ipl->i > FREQUENCYLIST_MAX -1) return;
(freql + ipl->i)->frequency = 0;
(freql + ipl->i)->pwr = 0;
(freql + ipl->i)->status = 0;
while(nla_ok(nlan, nlanremlen))
	{
	if(nlan->nla_type == NL80211_FREQUENCY_ATTR_FREQ)
		{
		(freql + ipl->i)->frequency = *((u32*)nla_data(nlan));
		(freql + ipl->i)->channel = frequency_to_channel((freql + ipl->i)->frequency);
		}
	if(nlan->nla_type == NL80211_FREQUENCY_ATTR_MAX_TX_POWER) (freql + ipl->i)->pwr = *((u32*)nla_data(nlan));
	if(nlan->nla_type == NL80211_FREQUENCY_ATTR_DISABLED) (freql + ipl->i)->status = IF_STAT_FREQ_DISABLED;
	nlan = nla_next(nlan, &nlanremlen);
	}
if((freql + ipl->i)->frequency != 0) ipl->i++;

return;
}
/*---------------------------------------------------------------------------*/
static u8 nl_get_supported_iftypes(struct nlattr* nla)
{
struct nlattr *pos = (struct nlattr*)nla_data(nla);
int nestremlen = nla_datalen(nla);
while(nla_ok(pos, nestremlen))
	{
	if(pos->nla_type == NL80211_IFTYPE_MONITOR) return IF_HAS_MONITOR;
	pos = nla_next(pos, &nestremlen);
	}
return 0;
}
/*---------------------------------------------------------------------------*/
static bool nl_get_interfacelist(void)
{
static ssize_t i;
static size_t ii;
static ssize_t msglen;
static int nlremlen = 0;
static u32 ifindex;
static u32 wiphy;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;
static char ifname[IF_NAMESIZE];
static u8 vimac[ETH_ALEN];

i = 0;
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = nlfamily; 
nlh->nlmsg_flags =  NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = hcxpid;
i += sizeof(struct nlmsghdr);
glh = (struct genlmsghdr*)(nltxbuffer + i);
glh->cmd = NL80211_CMD_GET_INTERFACE;
glh->version = 1;
glh->reserved = 0;
i += sizeof(struct genlmsghdr);
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return false;
ii = 0;
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, msglen); nlh = NLMSG_NEXT (nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return true;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			errorcount++;
			nlfamily = 0;
			return false;
			}
		glh = (struct genlmsghdr*)NLMSG_DATA(nlh);
		if(glh->cmd != NL80211_CMD_NEW_INTERFACE) continue;
		nla = (struct nlattr*)(NLMSG_DATA(nlh) + sizeof(struct genlmsghdr));
		nlremlen =  NLMSG_PAYLOAD(nlh, 0) -4;
		while(nla_ok(nla, nlremlen))
			{
			if(nla->nla_type == NL80211_ATTR_IFINDEX) ifindex = *((u32*)nla_data(nla));
			if(nla->nla_type == NL80211_ATTR_IFNAME) strncpy(ifname, nla_data(nla), IF_NAMESIZE -1);
			if(nla->nla_type == NL80211_ATTR_WIPHY)
				{
				wiphy = *((u32*)nla_data(nla));
				}
			if(nla->nla_type == NL80211_ATTR_MAC)
				{
				if(nla->nla_len == 10) memcpy(vimac, nla_data(nla), ETH_ALEN);
				}
			nla = nla_next(nla, &nlremlen);
			}
		for(ii = 0; ii < INTERFACELIST_MAX; ii++)
			{
			if((ifpresentlist + ii)->wiphy == wiphy)
				{
				(ifpresentlist + ii)->index = ifindex;
				strncpy((ifpresentlist + ii)->name, ifname, IF_NAMESIZE);
				memcpy((ifpresentlist + ii)->vimac, &vimac, ETH_ALEN);
				break;
				}
			}
		}
	}
return false;
}
/*---------------------------------------------------------------------------*/
static bool nl_get_interfacestatus(void)
{
static ssize_t i;
static ssize_t msglen;
static int nlremlen = 0;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;

i = 0;
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = nlfamily; 
nlh->nlmsg_flags =  NLM_F_REQUEST | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = hcxpid;
i += sizeof(struct nlmsghdr);
glh = (struct genlmsghdr*)(nltxbuffer + i);
glh->cmd = NL80211_CMD_GET_INTERFACE;
glh->version = 1;
glh->reserved = 0;
i += sizeof(struct genlmsghdr);
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;
nla->nla_type = NL80211_ATTR_IFINDEX;
*(u32*)nla_data(nla) = ifaktindex;
i += 8;
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, msglen); nlh = NLMSG_NEXT (nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return true;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			errorcount++;
			nlfamily = 0;
			return false;
			}
		glh = (struct genlmsghdr*)NLMSG_DATA(nlh);
		if(glh->cmd != NL80211_CMD_NEW_INTERFACE) continue;
		nla = (struct nlattr*)(NLMSG_DATA(nlh) + sizeof(struct genlmsghdr));
		nlremlen =  NLMSG_PAYLOAD(nlh, 0) -4;
		while(nla_ok(nla, nlremlen))
			{
			if(nla->nla_type == NL80211_ATTR_IFTYPE)
				{
				if(*((u32*)nla_data(nla)) == NL80211_IFTYPE_MONITOR) ifaktstatus |= IF_STAT_MONITOR;
				}
			nla = nla_next(nla, &nlremlen);
			}
		}
	}
return false;
}
/*---------------------------------------------------------------------------*/
static bool nl_get_regulatorydomain(void)
{
static ssize_t i;
static ssize_t msglen;
static int nlremlen = 0;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;

country[0] = 0;
country[1] = 0;
country[2] = 0;
i = 0;
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = nlfamily; 
nlh->nlmsg_flags =  NLM_F_REQUEST | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = hcxpid;
i += sizeof(struct nlmsghdr);
glh = (struct genlmsghdr*)(nltxbuffer + i);
glh->cmd = NL80211_CMD_GET_REG;
glh->version = 1;
glh->reserved = 0;
i += sizeof(struct genlmsghdr);
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, msglen); nlh = NLMSG_NEXT (nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return true;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			errorcount++;
			nlfamily = 0;
			return false;
			}
		glh = (struct genlmsghdr*)NLMSG_DATA(nlh);
		if(glh->cmd != NL80211_CMD_GET_REG) continue;
		nla = (struct nlattr*)(NLMSG_DATA(nlh) + sizeof(struct genlmsghdr));
		nlremlen =  NLMSG_PAYLOAD(nlh, 0) -4;
		while(nla_ok(nla, nlremlen))
			{
			if(nla->nla_type == NL80211_ATTR_REG_ALPHA2)
				{
				if(nla->nla_len == 7) memcpy(country, nla_data(nla), 2);
				}
			nla = nla_next(nla, &nlremlen);
			}
		}
	}
return false;
}
/*---------------------------------------------------------------------------*/
static bool nl_get_interfacecapabilities(void)
{
static ssize_t i;
static ssize_t ii;
static ssize_t msglen;
static int nlremlen;
static size_t dnlen;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;
static char *drivername = NULL;
static char driverfmt[128] = { 0 };
static char driverlink[128] = { 0 };

nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = nlfamily; 
nlh->nlmsg_flags =  NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = hcxpid;
i += sizeof(struct nlmsghdr);
glh = (struct genlmsghdr*)(nltxbuffer + i);
glh->cmd = NL80211_CMD_GET_WIPHY;
glh->version = 1;
glh->reserved = 0;
i += sizeof(struct genlmsghdr);
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 4;
nla->nla_type = NL80211_ATTR_SPLIT_WIPHY_DUMP;
*(u32*)nla_data(nla) = ifaktindex;
i += 4;
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return false;
ii = 0;
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, msglen); nlh = NLMSG_NEXT (nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return true;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			errorcount++;
			return false;
			}
		nlremlen = 0;
		glh = (struct genlmsghdr*)NLMSG_DATA(nlh);
		if(glh->cmd != NL80211_CMD_NEW_WIPHY) continue;
		nla = (struct nlattr*)(NLMSG_DATA(nlh) + sizeof(struct genlmsghdr));
		nlremlen =  NLMSG_PAYLOAD(nlh, 0) -4;
		while(nla_ok(nla, nlremlen))
			{
			if(nla->nla_type == NL80211_ATTR_WIPHY) 
				{
				(ifpresentlist + ii)->wiphy = *((u32*)nla_data(nla));
				snprintf(driverfmt, 64, "/sys/class/ieee80211/phy%d/device/driver", (ifpresentlist + ii)->wiphy);
				memset(&driverlink, 0, 128);
				if((dnlen = readlink(driverfmt, driverlink, 64)) > 0)
					{
					drivername = basename(driverlink);
					if(drivername != NULL) strncpy((ifpresentlist + ii)->driver, drivername, DRIVERNAME_MAX -1);
					}
				}
			if(nla->nla_type == NL80211_ATTR_SUPPORTED_IFTYPES)
				{
				(ifpresentlist + ii)->type |= nl_get_supported_iftypes(nla);
				(ifpresentlist + ii)->type |= IF_HAS_NETLINK;
				}
			if(nla->nla_type == NL80211_ATTR_WIPHY_BANDS) nl_get_supported_bands((ifpresentlist + ii), nla);
			if(nla->nla_type == NL80211_ATTR_FEATURE_FLAGS)
				{
				if((*((u32*)nla_data(nla)) & NL80211_FEATURE_ACTIVE_MONITOR) == NL80211_FEATURE_ACTIVE_MONITOR) (ifpresentlist + ii)->type |= IF_HAS_MONITOR_ACTIVE;
				}
			nla = nla_next(nla, &nlremlen);
			}
		}
	if(ii < INTERFACELIST_MAX) ii++;
	}
return false;
}
/*---------------------------------------------------------------------------*/
static inline bool nl_set_frequency(void)
{
static ssize_t i;
static ssize_t msglen;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;

i = 0;
if(((scanlist + scanlistindex)->frequency) == 0) scanlistindex = 0;
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = nlfamily; 
nlh->nlmsg_flags =  NLM_F_REQUEST | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = hcxpid;
i += sizeof(struct nlmsghdr);
glh = (struct genlmsghdr*)(nltxbuffer + i);
glh->cmd = NL80211_CMD_SET_WIPHY;
glh->version = 1;
glh->reserved = 0;
i += sizeof(struct genlmsghdr);
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;
nla->nla_type = NL80211_ATTR_IFINDEX;
*(u32*)nla_data(nla) = ifaktindex;
i += 8;
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;
nla->nla_type = NL80211_ATTR_WIPHY_FREQ;
*(u32*)nla_data(nla) = (scanlist + scanlistindex)->frequency;
i += 8;
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;
nla->nla_type = NL80211_ATTR_CHANNEL_WIDTH;
*(u32*)nla_data(nla) = NL80211_CHAN_WIDTH_20_NOHT;
i += 8;
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;
nla->nla_type = NL80211_ATTR_WIPHY_CHANNEL_TYPE;
*(u32*)nla_data(nla) = NL80211_CHAN_NO_HT;
i += 8;
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;
nla->nla_type = NL80211_ATTR_CENTER_FREQ1;
*(u32*)nla_data(nla) = (scanlist + scanlistindex)->frequency;
i += 8;
if(((scanlist + scanlistindex)->frequency) <= 2484) memcpy(&nltxbuffer[i], legacy241mbdata, LEGACYXXXMB_SIZE);
else memcpy(&nltxbuffer[i], legacy56mbdata, LEGACYXXXMB_SIZE);
i += LEGACYXXXMB_SIZE;
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, msglen); nlh = NLMSG_NEXT (nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return true;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			errorcount++;
			return false;
			}
		}
	}
return false;
}
/*---------------------------------------------------------------------------*/
static inline void nl_set_powersave_off(void)
{
static ssize_t i;
static ssize_t msglen;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;

i = 0;
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = nlfamily; 
nlh->nlmsg_flags =  NLM_F_REQUEST | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = hcxpid;
i += sizeof(struct nlmsghdr);
glh = (struct genlmsghdr*)(nltxbuffer + i);
glh->cmd = NL80211_CMD_SET_INTERFACE;
glh->version = 1;
glh->reserved = 0;
i += sizeof(struct genlmsghdr);
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;
nla->nla_type = NL80211_ATTR_IFINDEX;
*(u32*)nla_data(nla) = ifaktindex;
i += 8;
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;
nla->nla_type = NL80211_ATTR_PS_STATE;
*(u32*)nla_data(nla) = NL80211_PS_DISABLED;
i += 8;

nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return;
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, msglen); nlh = NLMSG_NEXT (nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return;
			errorcount++;
			return;
			}
		}
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline bool nl_set_monitormode(void)
{
static ssize_t i;
static ssize_t msglen;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;

i = 0;
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = nlfamily; 
nlh->nlmsg_flags =  NLM_F_REQUEST | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = hcxpid;
i += sizeof(struct nlmsghdr);
glh = (struct genlmsghdr*)(nltxbuffer + i);
glh->cmd = NL80211_CMD_SET_INTERFACE;
glh->version = 1;
glh->reserved = 0;
i += sizeof(struct genlmsghdr);
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;
nla->nla_type = NL80211_ATTR_IFINDEX;
*(u32*)nla_data(nla) = ifaktindex;
i += 8;
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;
nla->nla_type = NL80211_ATTR_IFTYPE;
*(u32*)nla_data(nla) = NL80211_IFTYPE_MONITOR;
i += 8;
if((ifakttype & IFTYPEMONACT) == IFTYPEMONACT)
	{
	nla = (struct nlattr*)(nltxbuffer + i);
	nla->nla_len = 8;
	nla->nla_type = NL80211_ATTR_MNTR_FLAGS;
	nla =  (struct nlattr*)nla_data(nla);
	nla->nla_len = 4;
	nla->nla_type = NL80211_MNTR_FLAG_ACTIVE;
	i += 8;
	}
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, msglen); nlh = NLMSG_NEXT (nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return true;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			errorcount++;
			return false;
			}
		}
	}
return false;
}
/*===========================================================================*/
/* RTLINK */
static void *rta_data(const struct rtattr *rta)
{
return (u8*)rta +4;
}
/*---------------------------------------------------------------------------*/
static bool rt_set_interfacemac(void)
{
static ssize_t i;
static ssize_t msglen;
static struct nlmsghdr *nlh;
static struct ifinfomsg *ifih;
static struct rtattr *rta;
static struct nlmsgerr *nle;

i = 0;
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = RTM_NEWLINK;
nlh->nlmsg_flags =  NLM_F_REQUEST | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = hcxpid;
i += sizeof(struct nlmsghdr);
ifih = (struct ifinfomsg*)(nltxbuffer+ i);
ifih->ifi_family = 0;
ifih->ifi_type = 0;
ifih->ifi_index = ifaktindex;
ifih->ifi_flags = 0;
ifih->ifi_change = 0;
i += sizeof(struct ifinfomsg);
rta = (struct rtattr*)(nltxbuffer+ i);
rta->rta_len = 10;
rta->rta_type = IFLA_ADDRESS;
memcpy(&nltxbuffer[i + 4], &macclientrg, ETH_ALEN +2); 
i += 12;
nlh->nlmsg_len = i;
if((write(fd_socket_rt, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_rt, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, msglen); nlh = NLMSG_NEXT (nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return false;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			errorcount++;
			return false;
			}
		}
	}
return false;
}
/*---------------------------------------------------------------------------*/
static bool rt_set_interface(u32 condition)
{
static ssize_t i;
static ssize_t msglen;
static struct nlmsghdr *nlh;
static struct ifinfomsg *ifih;
static struct nlmsgerr *nle;

i = 0;
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = RTM_NEWLINK;
nlh->nlmsg_flags =  NLM_F_REQUEST | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = hcxpid;
i += sizeof(struct nlmsghdr);
ifih = (struct ifinfomsg*)(nltxbuffer+ i);
ifih->ifi_family = 0;
ifih->ifi_type = 0;
ifih->ifi_index = ifaktindex;
ifih->ifi_flags = condition;
ifih->ifi_change = 1;
i += sizeof(struct ifinfomsg);
nlh->nlmsg_len = i;
if((write(fd_socket_rt, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_rt, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, msglen); nlh = NLMSG_NEXT (nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return false;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			errorcount++;
			return false;
			}
		}
	}
return false;
}
/*---------------------------------------------------------------------------*/
static bool rt_get_interfacestatus(void)
{
static ssize_t i;
static ssize_t msglen;
static struct nlmsghdr *nlh;
static struct ifinfomsg *ifih;
static struct nlmsgerr *nle;

i = 0;
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = RTM_GETLINK;
nlh->nlmsg_flags =  NLM_F_REQUEST | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = hcxpid;
i += sizeof(struct nlmsghdr);
ifih = (struct ifinfomsg*)(nltxbuffer+ i);
ifih->ifi_family = AF_PACKET;
ifih->ifi_type = 0;
ifih->ifi_index = ifaktindex;
ifih->ifi_flags = 0;
ifih->ifi_change = 0;
i += sizeof(struct ifinfomsg);
nlh->nlmsg_len = i;
if((write(fd_socket_rt, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_rt, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, msglen); nlh = NLMSG_NEXT (nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return false;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			errorcount++;
			return false;
			}
		ifih = (struct ifinfomsg*)NLMSG_DATA(nlh);
		if((ifih->ifi_flags & IFF_UP) == IFF_UP) ifaktstatus |= IF_STAT_UP;
		}
	}
return false;
}
/*---------------------------------------------------------------------------*/
static bool rt_get_interfacelist(void)
{
static ssize_t i;
static ssize_t msglen;
static struct nlmsghdr *nlh;
static struct ifinfomsg *ifih;
static struct nlmsgerr *nle;
static struct rtattr *rta;
static int rtaremlen;
static u8 hwmac[ETH_ALEN];

i = 0;
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = RTM_GETLINK;
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = hcxpid;
i += sizeof(struct nlmsghdr);
ifih = (struct ifinfomsg*)(nltxbuffer+ i);
ifih->ifi_family = AF_PACKET;
ifih->ifi_type = 0;
ifih->ifi_index = 0;
ifih->ifi_flags = 0;
ifih->ifi_change = 0;
i += sizeof(struct ifinfomsg);
rta = (struct rtattr*)(nltxbuffer+ i);
rta->rta_type = IFLA_EXT_MASK;
*(u32*)rta_data(rta) = 1;
rta->rta_len = 8;
i += 8;
nlh->nlmsg_len = i;
if((write(fd_socket_rt, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_rt, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, msglen); nlh = NLMSG_NEXT (nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return true;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			errorcount++;
			return false;
			}
		ifih = (struct ifinfomsg*)NLMSG_DATA(nlh);
		if((ifih->ifi_flags & IFF_UP) == IFF_UP) ifaktstatus |= IF_STAT_UP;
		rta = (struct rtattr*)(NLMSG_DATA(nlh) + sizeof(struct ifinfomsg));
		rtaremlen = NLMSG_PAYLOAD(nlh, 0) - sizeof(struct ifinfomsg);
		while(RTA_OK(rta, rtaremlen))
			{
			if(rta->rta_type == IFLA_PERM_ADDRESS)
				{
				if(rta->rta_len == 10) memcpy(hwmac, rta_data(rta), ETH_ALEN);
				}
			rta = RTA_NEXT(rta, rtaremlen);
			}
		for(i = 0; i < INTERFACELIST_MAX; i++)
			{
			if((ifpresentlist + i)->index == ifih->ifi_index)
				memcpy((ifpresentlist + i)->hwmac, &hwmac, ETH_ALEN);
			}
		}
	}
return false;
}
/*---------------------------------------------------------------------------*/
static bool nl_get_familyid(void)
{
static ssize_t i;
static ssize_t msglen;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;
static int nlremlen = 0;

i = 0;
nlfamily = 0;
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = GENL_ID_CTRL;
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = hcxpid;
i += sizeof(struct nlmsghdr);
glh = (struct genlmsghdr*)(nltxbuffer + i);
glh->cmd = CTRL_CMD_GETFAMILY;
glh->version = 1;
glh->reserved = 0;
i += sizeof(struct genlmsghdr);
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_type = CTRL_ATTR_FAMILY_NAME;
i += sizeof(struct nlattr);
memcpy(nltxbuffer +i, NL80211_GENL_NAME, sizeof(NL80211_GENL_NAME));
i += sizeof(NL80211_GENL_NAME);
nla->nla_len = sizeof(struct nlattr) + sizeof(NL80211_GENL_NAME);
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, msglen); nlh = NLMSG_NEXT (nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return true;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			errorcount++;
			nlfamily = 0;
			return false;
			}
		glh = (struct genlmsghdr*)NLMSG_DATA(nlh);
		nla = (struct nlattr*)(NLMSG_DATA(nlh) + sizeof(struct genlmsghdr));
		nlremlen = 0;
		nlremlen =  NLMSG_PAYLOAD(nlh, 0) -4;
		while(nla_ok(nla, nlremlen))
			{
			if(nla->nla_type == CTRL_ATTR_FAMILY_ID) nlfamily = *((u32*)nla_data(nla));
			nla = nla_next(nla, &nlremlen);
			}
		}
	}
nlfamily = 0;
return false;
}
/*===========================================================================*/
static void usrfrequency_to_scanlist(u16 ufrq)
{
size_t i;

if(ufrq == 0) return;
for(i = 0; i < (FREQUENCYLIST_MAX -1); i++)
	{
	if((ifaktfrequencylist + i)->status == 0)
		{
		if((ifaktfrequencylist + i)->frequency == ufrq)
			{
			(scanlist + scanlistindex)->frequency = ufrq;
			(scanlist + scanlistindex)->channel = frequency_to_channel(ufrq);
			scanlistindex++;
			if(scanlistindex >= (FREQUENCYLIST_MAX -1)) return;
			return;
			}
		}
	}
return;
}
/*---------------------------------------------------------------------------*/
static bool set_interface(bool interfacefrequencyflag, char *userfrequencylistname, char *userchannellistname)
{
static size_t i;
static char *ufld = NULL;
static char *tokptr = NULL;
static char *userband = NULL;
static u16 uband;
static u32 ufreq;

if(ifaktindex == 0)
	{
	for(i = 0; i < ifpresentlistcounter; i++)
		{
		if(((ifpresentlist + i)->type & IF_HAS_NLMON) == IF_HAS_NLMON)
			{
			ifaktindex = (ifpresentlist + i )->index;
			ifakttype = (ifpresentlist + i )->type;
			memcpy(&ifaktname, (ifpresentlist + i )->name, IF_NAMESIZE);
			memcpy(&ifakthwmac, (ifpresentlist + i )->hwmac, ETH_ALEN);
			ifaktfrequencylist = (ifpresentlist + i)->frequencylist;
			break;
			}
		}
	}
else
	{
	for(i = 0; i < ifpresentlistcounter; i++)
		{
		if((ifpresentlist + i )->index == ifaktindex)
			{
			if(((ifpresentlist + i)->type & IF_HAS_NLMON) == 0) return false;
			ifakttype = (ifpresentlist + i )->type;
			memcpy(&ifakthwmac, (ifpresentlist + i )->hwmac, ETH_ALEN);
			ifaktfrequencylist = (ifpresentlist + i)->frequencylist;
			break;
			}
		}
	}
if(ifaktfrequencylist == NULL) return false;
if(rt_set_interface(0) == false) return false;
if(rt_set_interfacemac() == false) return false;
if(nl_set_monitormode() == false) return false;
if(rt_set_interface(IFF_UP) == false) return false;
nl_set_powersave_off();
if(nl_get_interfacestatus() == false) return false;
if(rt_get_interfacestatus() == false) return false;
scanlistindex = 0;
if(interfacefrequencyflag == true)
	{
	for(i = 0; i < (FREQUENCYLIST_MAX -1); i++)
		{
		if((ifaktfrequencylist + i)->status == 0)
			{
			(scanlist + scanlistindex)->frequency = (ifaktfrequencylist + i)->frequency;
			(scanlist + scanlistindex)->channel = (ifaktfrequencylist + i)->channel;
			scanlistindex++;
			if(scanlistindex >= (FREQUENCYLIST_MAX -1)) break;
			}
		if((ifaktfrequencylist + i)->frequency == 0) break;
		}
	}
else if((userfrequencylistname != NULL) || (userchannellistname != NULL))
	{
	if(userfrequencylistname != NULL)
		{
		ufld = strdup(userfrequencylistname);
		tokptr = strtok(ufld, ",");
		while((tokptr != NULL) && (i < (SCANLIST_MAX - 1)))
			{
			usrfrequency_to_scanlist(strtol(tokptr, NULL, 10));
			tokptr = strtok(NULL, ",");
			}
		free(ufld);
		}
	if(userchannellistname != NULL)
		{
		ufld = strdup(userchannellistname);
		tokptr = strtok(ufld, ",");
		while((tokptr != NULL) && (i < (SCANLIST_MAX - 1)))
			{
			uband = strtol(tokptr, &userband, 10);
			if(userband[0] == 'a') ufreq = channel_to_frequency(uband, NL80211_BAND_2GHZ);
			else if(userband[0] == 'b') ufreq = channel_to_frequency(uband, NL80211_BAND_5GHZ);
			else if(userband[0] == 'c') ufreq = channel_to_frequency(uband, NL80211_BAND_6GHZ);
			else if(userband[0] == 'd') ufreq = channel_to_frequency(uband, NL80211_BAND_60GHZ);
			else if(userband[0] == 'e') ufreq = channel_to_frequency(uband, NL80211_BAND_S1GHZ);
			usrfrequency_to_scanlist(ufreq);
			tokptr = strtok(NULL, ",");
			}
		free(ufld);
		}
	}
else
	{
	(scanlist + scanlistindex)->frequency = 2412;
	(scanlist + scanlistindex++)->channel = 1;
	(scanlist + scanlistindex)->frequency = 2437;
	(scanlist + scanlistindex++)->channel = 6;
	(scanlist + scanlistindex)->frequency = 2462;
	(scanlist + scanlistindex++)->channel = 11;
	(scanlist + scanlistindex)->frequency = 0;
	(scanlist + scanlistindex)->channel = 0;
	}
scanlistindex = 0;
if(nl_set_frequency() == false) return false;
show_interfacecapabilities2();
return true;
}
/*===========================================================================*/
static bool set_monitormode(void)
{
if(rt_set_interface(0) == false) return false;
if(nl_set_monitormode() == false) return false;
if(rt_set_interface(IFF_UP) == false) return false;
if(nl_get_interfacestatus() == false) return false;
if(rt_get_interfacestatus() == false) return false;
show_interfacecapabilities();
fprintf(stdout, "\n\nmonitor mode is active...\n");
return true;
}
/*===========================================================================*/
static bool get_interfacelist(void)
{
static size_t i;

nl_get_familyid();
if(nlfamily == 0)
	{
	errorcount++;
	return false;
	}
nl_get_regulatorydomain();
if(nl_get_interfacecapabilities() == false) return false;
if(nl_get_interfacelist() == false) return false;
for(i = 0; i < INTERFACELIST_MAX -1; i++)
	{
	if((ifpresentlist + i)->index == 0) break;
	ioctl_get_wireless_extensions(i);
	ifpresentlistcounter++;
	}
if(rt_get_interfacelist() == false) return false;
if(ifpresentlistcounter == 0) return false;
qsort(ifpresentlist, ifpresentlistcounter, INTERFACELIST_SIZE, sort_interfacelist_by_index);
return true;
}
/*===========================================================================*/
/* RAW PACKET SOCKET */
static bool open_socket_tx(void)
{
static struct sockaddr_ll saddr;
static struct packet_mreq mrq;
static int socket_rx_flags;
static int prioval;
static socklen_t priolen;

if((fd_socket_tx = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) return false;
memset(&mrq, 0, sizeof(mrq));
mrq.mr_ifindex = ifaktindex;
mrq.mr_type = PACKET_MR_PROMISC;
if(setsockopt(fd_socket_tx, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mrq, sizeof(mrq)) < 0) return false;
priolen = sizeof(prioval);
prioval = 20;
if(setsockopt(fd_socket_rx, SOL_SOCKET, SO_PRIORITY, &prioval, priolen) < 0) return false;
memset(&saddr, 0, sizeof(saddr));
saddr.sll_family = PF_PACKET;
saddr.sll_ifindex = ifaktindex;
saddr.sll_protocol = htons(ETH_P_ALL);
saddr.sll_halen = ETH_ALEN;
saddr.sll_pkttype = PACKET_OTHERHOST;
if(bind(fd_socket_tx, (struct sockaddr*) &saddr, sizeof(saddr)) < 0) return false;
if((socket_rx_flags = fcntl(fd_socket_rx, F_GETFL, 0)) < 0) return false;
if(fcntl(fd_socket_tx, F_SETFL, socket_rx_flags | O_NONBLOCK) < 0) return false;
return true;
}
/*---------------------------------------------------------------------------*/
static bool open_socket_rx(char *bpfname)
{
size_t c = 10;
static struct sockaddr_ll saddr;
static struct packet_mreq mrq;
static int enable = 1;
static int socket_rx_flags;
static int prioval;
static socklen_t priolen;

bpf.len = 0;
if(bpfname != NULL)
	{
	if(read_bpf(bpfname) == false)
		{
		errorcount++;
		fprintf(stderr, "failed to read BPF\n");
		return false;
		}
	}
if((fd_socket_rx = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) return false;
memset(&mrq, 0, sizeof(mrq));
mrq.mr_ifindex = ifaktindex;
mrq.mr_type = PACKET_MR_PROMISC;
if(setsockopt(fd_socket_rx, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mrq, sizeof(mrq)) < 0) return false;
priolen = sizeof(prioval);
prioval = 20;
if(setsockopt(fd_socket_rx, SOL_SOCKET, SO_PRIORITY, &prioval, priolen) < 0) return false;
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
if(setsockopt(fd_socket_rx, SOL_PACKET, PACKET_IGNORE_OUTGOING, &enable, sizeof(int)) < 0) return false;
#endif

if(bpf.len > 0)
	{
	if(setsockopt(fd_socket_rx, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) return false;
	}
memset(&saddr, 0, sizeof(saddr));
saddr.sll_family = PF_PACKET;
saddr.sll_ifindex = ifaktindex;
saddr.sll_protocol = htons(ETH_P_ALL);
saddr.sll_halen = ETH_ALEN;
saddr.sll_pkttype = PACKET_OTHERHOST;
if(bind(fd_socket_rx, (struct sockaddr*) &saddr, sizeof(saddr)) < 0) return false;
if((socket_rx_flags = fcntl(fd_socket_rx, F_GETFL, 0)) < 0) return false;
if(fcntl(fd_socket_rx, F_SETFL, socket_rx_flags | O_NONBLOCK) < 0) return false;
while((!wanteventflag) || (c != 0))
	{
	packetlen = read(fd_socket_rx, epb +EPB_SIZE, PCAPNG_SNAPLEN);
	if(packetlen == -1) break;
	c--;
	}
return true;
}
/*===========================================================================*/
/* GPS */
#ifdef NMEAOUT
static bool open_nmea0183_file(char *hcxposoutname)
{
static int c;
static struct stat statinfo;
static char *hcxposfilename = NULL;
static char hcxposname[PATH_MAX];

if(hcxposoutname == NULL)
	{
	c = 0;
	snprintf(hcxposname, PATH_MAX, "%s.nmea", timestring);
	while(stat(hcxposname, &statinfo) == 0)
		{
		snprintf(hcxposname, PATH_MAX, "%s-%02d.nmea", timestring, c);
		c++;
		}
	hcxposfilename = hcxposname;
	}
else hcxposfilename = hcxposoutname;
if((fd_hcxpos = open(hcxposfilename, O_WRONLY | O_CREAT, 0777)) < 0) return false;
return true;
}
/*---------------------------------------------------------------------------*/
static bool open_socket_gpsd(char *hcxposoutname)
{
static int socket_gps_flags;
static struct sockaddr_in gpsd_addr;
static const char *gpsd_enable_nmea = "?WATCH={\"enable\":true,\"json\":false,\"nmea\":true}";

if((fd_gps = socket(AF_INET, SOCK_STREAM, 0)) < 0) return false;
memset(&gpsd_addr, 0, sizeof(struct sockaddr_in));
gpsd_addr.sin_family = AF_INET;
gpsd_addr.sin_port = htons(2947);
gpsd_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
if(connect(fd_gps, (struct sockaddr*) &gpsd_addr, sizeof(gpsd_addr)) < 0) return false;
if(fcntl(fd_gps, F_SETFL, socket_gps_flags | O_NONBLOCK) < 0) return false;
if(write(fd_gps, gpsd_enable_nmea, 47) != 47) return false;
if(open_nmea0183_file(hcxposoutname) == false) return false;
return true;
}
/*---------------------------------------------------------------------------*/
static bool open_device_nmea0183(char *nmea0183name, char *hcxposoutname)
{
static struct termios tty;

if((fd_gps = open(nmea0183name, O_RDONLY | O_NONBLOCK)) < 0) return false;
if(flock(fd_gps, LOCK_EX) < 0) return false;
if(tcgetattr(fd_gps, &tty) < 0) return false;
tty.c_cflag &= ~PARENB; // Clear parity bit, disabling parity (most common)
tty.c_cflag &= ~CSTOPB; // Clear stop field, only one stop bit used in communication (most common)
tty.c_cflag &= ~CSIZE; // Clear all bits that set the data size 
tty.c_cflag |= CS8; // 8 bits per byte (most common)
tty.c_cflag &= ~CRTSCTS; // Disable RTS/CTS hardware flow control (most common)
tty.c_cflag |= CREAD | CLOCAL; // Turn on READ & ignore ctrl lines (CLOCAL = 1)
tty.c_lflag &= ~ICANON;
tty.c_lflag &= ~ECHO; // Disable echo
tty.c_lflag &= ~ECHOE; // Disable erasure
tty.c_lflag &= ~ECHONL; // Disable new-line echo
tty.c_lflag &= ~ISIG; // Disable interpretation of INTR, QUIT and SUSP
tty.c_iflag &= ~(IXON | IXOFF | IXANY); // Turn off s/w flow ctrl
tty.c_iflag &= ~(IGNBRK|BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL); // Disable any special handling of received bytes
tty.c_oflag &= ~OPOST; // Prevent special interpretation of output bytes (e.g. newline chars)
tty.c_oflag &= ~ONLCR; // Prevent conversion of newline to carriage return/line feed
tty.c_cc[VTIME] = 10;    // Wait for up to 1s (10 deciseconds), returning as soon as any data is received.
tty.c_cc[VMIN] = 0;
cfsetispeed(&tty, B9600);
cfsetospeed(&tty, B9600);
if (tcsetattr(fd_gps, TCSANOW, &tty) < 0) return false;
if(open_nmea0183_file(hcxposoutname) == false) return false;
return true;
}
#endif
/*===========================================================================*/
/* CONTROL SOCKETS */
static void close_sockets(void)
{
if(fd_socket_unix != 0) close(fd_socket_unix);
if(fd_socket_rt != 0) close(fd_socket_rt);
if(fd_socket_nl != 0) close(fd_socket_nl);
if(fd_socket_tx != 0) close(fd_socket_tx);
if(bpf.filter != NULL)
	{
	if(fd_socket_rx > 0) setsockopt(fd_socket_rx, SOL_SOCKET, SO_DETACH_FILTER, &bpf, sizeof(bpf));
	free(bpf.filter);
	}
if(fd_socket_rx != 0) close(fd_socket_rx);
return;
}
/*---------------------------------------------------------------------------*/
static bool open_socket_unix(void)
{
if((fd_socket_unix = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) return false;
return true;
}
/*---------------------------------------------------------------------------*/
static bool open_socket_rt(void)
{
static struct sockaddr_nl saddr;
static int nltxbuffsize = NLTX_SIZE;
static int nlrxbuffsize = NLRX_SIZE;

if((fd_socket_rt = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC, NETLINK_ROUTE)) < 0) return false;
if(setsockopt(fd_socket_rt, SOL_SOCKET, SO_SNDBUF, &nltxbuffsize, sizeof(nltxbuffsize)) < 0) return false;
if(setsockopt(fd_socket_rt, SOL_SOCKET, SO_RCVBUF, &nlrxbuffsize, sizeof(nlrxbuffsize)) < 0) return false;
memset(&saddr, 0, sizeof(saddr));
saddr.nl_family = AF_NETLINK;
saddr.nl_pid = getpid();
if(bind(fd_socket_rt, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) return false;
return true;
}
/*---------------------------------------------------------------------------*/
static bool open_socket_nl(void)
{
static struct sockaddr_nl saddr;
static int nltxbuffsize = NLTX_SIZE;
static int nlrxbuffsize = NLRX_SIZE;

if((fd_socket_nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC)) < 0) return false;
if(setsockopt(fd_socket_nl, SOL_SOCKET, SO_SNDBUF, &nltxbuffsize, sizeof(nltxbuffsize)) < 0) return false;
if(setsockopt(fd_socket_nl, SOL_SOCKET, SO_RCVBUF, &nlrxbuffsize, sizeof(nlrxbuffsize)) < 0) return false;
if(fcntl(fd_socket_nl, F_SETFL, O_NONBLOCK) < 0) return false;
memset(&saddr, 0, sizeof(saddr));
saddr.nl_family = AF_NETLINK;
saddr.nl_pid = hcxpid;
if(bind(fd_socket_nl, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) return false;
return true;
}
/*===========================================================================*/
static bool open_control_sockets(void)
{
if(open_socket_rt() == false) return false;
if(open_socket_nl() == false) return false;
if(open_socket_unix() == false) return false;
return true;
}
/*===========================================================================*/
/* TIMER */
static bool set_timer(void)
{
static struct itimerspec tval1;

if((fd_timer1 = timerfd_create(CLOCK_BOOTTIME, 0)) <0 ) return false;
tval1.it_value.tv_sec = TIMER1_VALUE_SEC;
tval1.it_value.tv_nsec = TIMER1_VALUE_NSEC;
tval1.it_interval.tv_sec = TIMER1_INTERVAL_SEC;
tval1.it_interval.tv_nsec = TIMER1_INTERVAL_NSEC;
if(timerfd_settime(fd_timer1, 0, &tval1, NULL) == -1) return false;
return true;
}
/*---------------------------------------------------------------------------*/
static bool set_timer_rca(void)
{
static struct itimerspec tval1;

if((fd_timer1 = timerfd_create(CLOCK_BOOTTIME, 0)) <0 ) return false;
tval1.it_value.tv_sec = TIMER_RCA_VALUE_SEC;
tval1.it_value.tv_nsec = TIMER_RCA_VALUE_NSEC;
tval1.it_interval.tv_sec = TIMER_RCA_INTERVAL_SEC;
tval1.it_interval.tv_nsec = TIMER_RCA_INTERVAL_NSEC;
if(timerfd_settime(fd_timer1, 0, &tval1, NULL) == -1) return false;
return true;
}
/*===========================================================================*/
/* SIGNALHANDLER */
static void signal_handler(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL) || (signum ==  SIGTSTP))
	{
	wanteventflag |= EXIT_ON_SIGTERM;
	}
return;
}
/*---------------------------------------------------------------------------*/
static bool set_signal_handler(void)
{
struct sigaction sa;

sa.sa_handler = signal_handler;
sigemptyset(&sa.sa_mask);
sa.sa_flags = SA_RESTART;
if(sigaction(SIGINT, &sa, NULL) < 0) return false;
if(sigaction(SIGTERM, &sa, NULL) < 0) return false;
if(sigaction(SIGTSTP, &sa, NULL) < 0) return false;
return true;
}
/*===========================================================================*/
static void init_values(void)
{
static size_t i;
static struct timespec waitfordevice;
static const char *macaprgfirst = "internet";
#ifdef NMEAOUT
static const char gpwplid[] = "$GPWPL";
static const char gptxtid[] = "$GPTXT,";
#endif

waitfordevice.tv_sec = 1;
waitfordevice.tv_nsec = 0;
clock_gettime(CLOCK_REALTIME, &tspecakt);
tsfirst = ((u64)tspecakt.tv_sec * 1000000000ULL) + tspecakt.tv_nsec;
nanosleep(&waitfordevice, NULL);
clock_gettime(CLOCK_REALTIME, &tspecakt);
tsakt = ((u64)tspecakt.tv_sec * 1000000000ULL) + tspecakt.tv_nsec;
tshold = ((u64)tspecakt.tv_sec * 1000000000ULL) + tspecakt.tv_nsec;
strftime(timestring, PATH_MAX, "%Y%m%d%H%M%S", localtime(&tspecakt.tv_sec));

seed += tspecakt.tv_nsec & 0x7ffffffffff;
srand(seed);

ouiaprg = (vendoraprg[rand() % ((VENDORAPRG_SIZE / sizeof(int)))]) &0xffffff;
nicaprg = rand() & 0xffffff;
macaprg[5] = nicaprg & 0xff;
macaprg[4] = (nicaprg >> 8) & 0xff;
macaprg[3] = (nicaprg >> 16) & 0xff;
macaprg[2] = ouiaprg & 0xff;
macaprg[1] = (ouiaprg >> 8) & 0xff;
macaprg[0] = (ouiaprg >> 16) & 0xff;

aprglist->tsakt = tsakt;
aprglist->essidlen = strnlen(macaprgfirst, ESSID_MAX);
memcpy(aprglist->essid, macaprgfirst, strnlen(macaprgfirst, ESSID_MAX));
memcpy(aprglist->macaprg, &macaprg, ETH_ALEN);
nicaprg++;

ouiclientrg = (vendorclientrg[rand() % ((VENDORCLIENTRG_SIZE / sizeof(int)))]) &0xffffff;
nicclientrg = rand() & 0xffffff;
macclientrg[7] = 0;
macclientrg[6] = 0;
macclientrg[5] = nicclientrg & 0xff;
macclientrg[4] = (nicclientrg >> 8) & 0xff;
macclientrg[3] = (nicclientrg >> 16) & 0xff;
macclientrg[2] = ouiclientrg & 0xff;
macclientrg[1] = (ouiclientrg >> 8) & 0xff;
macclientrg[0] = (ouiclientrg >> 16) & 0xff;

strncpy(weakcandidate, WEAKCANDIDATEDEF, PSK_MAX);
replaycountrg = (rand() % 0xfff) + 0xf000;
eapolm1data[0x17] = (replaycountrg >> 8) &0xff;
eapolm1data[+0x18] = replaycountrg &0xff;
for(i = 0; i < 32; i++)
	{
	anoncerg[i] = rand() % 0xff;
	eapolm1data[i + 0x19] = anoncerg[i];
	snoncerg[i] = rand() % 0xff;
	}
packetptr = &epb[EPB_SIZE];
memcpy(&wltxbuffer, &rthtxdata, RTHTX_SIZE);
memcpy(&wltxnoackbuffer, &rthtxnoackdata, RTHTXNOACK_SIZE);
memcpy(&epbown[EPB_SIZE], &rthtxdata, RTHTX_SIZE);
#ifdef NMEAOUT
memcpy(&gpwpl, &gpwplid, 6);
memcpy(&gptxt, &gptxtid, 7);
#endif
return;
}
/*---------------------------------------------------------------------------*/
static void close_lists(void)
{
static size_t i;

if(maclist != NULL) free(maclist);
if(clientlist != NULL) free(clientlist);
if(aprglist != NULL) free(aprglist);
if(aplist != NULL) free(aplist);
if(scanlist != NULL) free(scanlist);
if(ifpresentlist != NULL)
	{
	for(i = 0; i < INTERFACELIST_MAX; i++)
		{
		if((ifpresentlist + i)->frequencylist != NULL) free((ifpresentlist + i)->frequencylist);
		}
	free(ifpresentlist);
	}
return;
}
/*---------------------------------------------------------------------------*/
static void close_fds(void)
{
if(fd_timer1 != 0) close(fd_timer1);
if(fd_pcapng != 0) close(fd_pcapng);
#ifdef NMEAOUT
if(fd_gps != 0) close(fd_gps);
if(fd_hcxpos != 0) close(fd_hcxpos);
#endif
return;
}
/*---------------------------------------------------------------------------*/
static bool init_lists(void)
{
ssize_t i;

if((scanlist = (frequencylist_t*)calloc(SCANLIST_MAX, FREQUENCYLIST_SIZE)) == NULL) return false;
if((aplist = (aplist_t*)calloc(APLIST_MAX, APLIST_SIZE)) == NULL) return false;
if((aprglist = (aprglist_t*)calloc(APRGLIST_MAX, APRGLIST_SIZE)) == NULL) return false;
if((clientlist = (clientlist_t*)calloc(CLIENTLIST_MAX, CLIENTLIST_SIZE)) == NULL) return false;
if((maclist = (maclist_t*)calloc(MACLIST_MAX, MACLIST_SIZE)) == NULL) return false;
if((ifpresentlist = (interface_t*)calloc(INTERFACELIST_MAX, INTERFACELIST_SIZE)) == NULL) return false;
for(i = 0; i < INTERFACELIST_MAX; i++)
	{
	if(((ifpresentlist + i)->frequencylist = (frequencylist_t*)calloc(FREQUENCYLIST_MAX, FREQUENCYLIST_SIZE)) == NULL) return false;
	}
return true;
}
/*===========================================================================*/
static size_t chop(char *buffer, size_t len)
{
char *ptr = NULL;

ptr = buffer +len - 1;
while(len)
	{
	if(*ptr != '\n') break;
	*ptr-- = 0;
	len--;
	}
while(len)
	{
	if(*ptr != '\r') break;
	*ptr-- = 0;
	len--;
	}
return len;
}
/*---------------------------------------------------------------------------*/
static int fgetline(FILE *inputstream, size_t size, char *buffer)
{
size_t len = 0;
char *buffptr = NULL;

if(feof(inputstream)) return -1;
buffptr = fgets(buffer, size, inputstream);
if(buffptr == NULL) return -1;
len = strlen(buffptr);
len = chop(buffptr, len);
return len;
}
/*===========================================================================*/
static bool read_bpf(char *bpfname)
{
static int len;
static u16 c;
static struct sock_filter *bpfptr;
static FILE *fh_filter;
static char linein[128];

if((fh_filter = fopen(bpfname, "r")) == NULL) return false;
if((len = fgetline(fh_filter, 128, linein)) < 0) return false;
sscanf(linein, "%"SCNu16, &bpf.len);
if(bpf.len == 0) return false;
bpf.filter = (struct sock_filter*)calloc(bpf.len, sizeof(struct sock_filter));
c = 0;
bpfptr = bpf.filter;
while(c < bpf.len)
	{
	if((len = fgetline(fh_filter, 128, linein)) == -1)
		{
		bpf.len = 0;
		break;
		}
	sscanf(linein, "%" SCNu16 "%" SCNu8 "%" SCNu8 "%" SCNu32, &bpfptr->code, &bpfptr->jt, &bpfptr->jf, &bpfptr->k);
	bpfptr++;
	c++;
	}
if(bpf.len != c) return false;
fclose(fh_filter);
return true;
}
/*---------------------------------------------------------------------------*/
static void read_essidlist(char *listname)
{
static size_t i;
static int len;
static FILE *fh_essidlist;
static char linein[ESSID_MAX];

if((fh_essidlist = fopen(listname, "r")) == NULL)
	{
	fprintf(stderr, "failed to open beacon list %s\n", listname);
	return;
	}
i = 0;
while(i < (APRGLIST_MAX - 1))
	{
	if((len = fgetline(fh_essidlist, ESSID_MAX, linein)) == -1) break;
	if((len == 0) || (len > ESSID_MAX)) continue;
	(aprglist + i)->tsakt = tsakt -i;
	(aprglist + i)->essidlen = len;
	memcpy((aprglist + i)->essid, linein, len);
	(aprglist + i)->macaprg[5] = nicaprg & 0xff;
	(aprglist + i)->macaprg[4] = (nicaprg >> 8) & 0xff;
	(aprglist + i)->macaprg[3] = (nicaprg >> 16) & 0xff;
	(aprglist + i)->macaprg[2] = ouiaprg & 0xff;
	(aprglist + i)->macaprg[1] = (ouiaprg >> 8) & 0xff;
	(aprglist + i)->macaprg[0] = (ouiaprg >> 16) & 0xff;
	nicaprg++;
	i++;
	}
(aprglist + i)->essidlen = 0;
fclose(fh_essidlist);
beaconindex = 0;
return;
}
/*===========================================================================*/
/*===========================================================================*/
/* RASPBERRY PI */
static bool init_rpigpio(unsigned int gpioperi)
{
static int fd_devinfo;

if((fd_devinfo = open("/dev/mem", O_RDWR | O_SYNC)) < 0)
	{
	fprintf(stderr, "failed to get device memory\n");
	return false;
	}
gpio_map = mmap(NULL, RPI_BLOCK_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd_devinfo, gpioperi);
close(fd_devinfo);
if(gpio_map == MAP_FAILED)
	{
	fprintf(stderr, "failed to map GPIO memory\n");
	return false;
	}
gpio = (volatile unsigned *)gpio_map;
return true;
}
/*---------------------------------------------------------------------------*/
static unsigned int get_rpigpiobasemem(void)
{
static FILE *procinfo;
static int len = 0;
static bool rpi = false;
static unsigned int gpioperibase = 0;
static char linein[RASPBERRY_INFO] = { 0 };

if((procinfo = fopen("/proc/cpuinfo", "r")) == NULL)
	{
	perror("failed to retrieve cpuinfo");
	return gpioperibase;
	}
while(1)
	{
	if((len = fgetline(procinfo, RASPBERRY_INFO, linein)) == -1) break;
	if(len < 18) continue;
	if(strstr(linein, "Raspberry Pi")) rpi = true;
	if(strstr(linein, "Serial") != NULL)
		{
		if(len > 8) seed += strtoul(&linein[len - 6], NULL, 16);
		}
	}
fclose(procinfo);
if(rpi == true)
	{
	if((procinfo = fopen("/proc/iomem", "r")) == NULL)
		{
		perror("failed to retrieve iomem");
		return gpioperibase;
		}
	while(1)
		{
		if((len = fgetline(procinfo, RASPBERRY_INFO, linein)) == -1) break;
		if(strstr(linein, ".gpio") != NULL)
			{
			if(linein[8] == '-')
				{
				linein[8] = 0;
				gpioperibase = strtoul(linein, NULL, 16);
				}
			break;
			}
		}
	fclose(procinfo);
	}
return gpioperibase;
}
/*---------------------------------------------------------------------------*/
static bool init_rpi(void)
{
static unsigned int gpiobasemem;

gpiobasemem = get_rpigpiobasemem();
if(gpiobasemem == 0)
	{
	fprintf(stderr, "failed to locate GPIO\n");
	return false;
	}
if(init_rpigpio(gpiobasemem) == false)
	{
	fprintf(stderr, "failed to init GPIO\n");
	return false;
	}
if(gpiostatusled > 0)
	{
	INP_GPIO(gpiostatusled);
	OUT_GPIO(gpiostatusled);
	}
if(gpiobutton > 0) INP_GPIO(gpiobutton);
return true;
}
/*===========================================================================*/
/*===========================================================================*/
__attribute__ ((noreturn))
static inline void version(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s ZeroBeat\n", eigenname, VERSION_TAG, VERSION_YEAR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usage(char *eigenname)
{
fprintf(stdout, "%s %s  (C) %s ZeroBeat\n"
	"usage: %s <options>\n"
	"        first stop all services that take access to the interface, e.g.:\n"
	"        $ sudo systemctl stop NetworkManager.service\n"
	"        $ sudo systemctl stop wpa_supplicant.service\n"
	"        then run %s\n"
	"        press ctrl+c to terminate\n"
	"        press GPIO button to terminate\n"
	"        hardware modification is necessary, read more:\n"
	"        https://github.com/ZerBea/hcxdumptool/tree/master/docs\n"
	"        do not set monitor mode by third party tools (iwconfig, iw, airmon-ng)\n"
	"        do not use logical (NETLINK) interfaces (monx, wlanxmon, prismx, ...) created by airmon-ng and iw\n"
	"        do not use virtual machines or emulators\n"
	"        do not run other tools that take access to the interface in parallel (except: tshark, wireshark, tcpdump)\n"
	"        do not use tools to change MAC (like macchanger)\n"
	"        stop all services (e.g.: wpa_supplicant.service, NetworkManager.service) that take access to the interface\n"
	"\n"
	"short options:\n"
	"-i <INTERFACE> : name of INTERFACE to be used\n"
	"                  default: first suitable INTERFACE\n"
	"                  warning: %s changes the virtual MAC address of the INTERFACE\n"
	"-w <outfile>   : write packets to a pcapng-format file named <outfile>\n"
	"                  default outfile name: yyyyddmmhhmmss-interfacename.pcapng\n"
	"                  get more information: https://pcapng.com/\n"
	"-c <digit>     : set channel (1a,2a,36b...)\n"
	"                  default: 1a,6a,11a\n"
	"                  important notice: channel numbers are not unique\n"
	"                  it is mandatory to add band information to the channel number (e.g. 12a)\n"
	"                   band a: NL80211_BAND_2GHZ\n"
	"                   band b: NL80211_BAND_5GHZ\n"
	"                   band c: NL80211_BAND_6GHZ\n"
	"                   band d: NL80211_BAND_60GHZ\n"
	"                   band e: NL80211_BAND_S1GHZ (902 MHz)\n" 
	"                  to disable frequency management, set this option to a single frequency/channel\n" 
	"-f <digit>     : set frequency (2412,2417,5180,...)\n"
	"-F             : use available frequencies from INTERFACE\n"
	"-t <second>    : minimum stay time (will increase on new stations and/or authentications)\n"
	"                  default %llu seconds\n"
	"-m <INTERFACE> : set monitor mode and terminate\n"
	"-L             : show INTERFACE list\n"
	"-I <INTERFACE> : show detailed information about INTERFACE\n"
	"-h             : show this help\n"
	"-v             : show version\n"
	"\n",
	eigenname, VERSION_TAG, VERSION_YEAR, eigenname, eigenname, eigenname, TIMEHOLD / 1000000000ULL);
fprintf(stdout, "long options:\n"
	"--bpf=<file>                   : input kernel space Berkeley Packet Filter (BPF) code\n"
	"                                  steps to create a BPF (it only has to be done once):\n"
	"                                  $ %s -m <interface>\n"
	"                                  create BPF to protect MACs\n"
	"                                  $ tcpdump -i <INTERFACE> not wlan addr2 11:22:33:44:55:66 -ddd > protect.bpf\n"
	"                                  recommended to protect own devices\n"
	"                                  create BPF to attack a MAC\n"
	"                                  $ tcpdump -i <INTERFACE> wlan addr1 11:22:33:44:55:66 or wlan addr2 11:22:33:44:55:66 or wlan addr3 11:22:33:44:55:66 -ddd > attack.bpf\n"
	"                                  it is strongly recommended to allow all PROBEREQUEST frames (wlan_type mgt && wlan_subtype probe-req)\n"
	"                                  $ tcpdump -i <interface> wlan addr1 11:22:33:44:55:66 or wlan addr2 11:22:33:44:55:66 or wlan addr3 11:22:33:44:55:66 or wlan addr3 ff:ff:ff:ff:ff:ff -ddd > attack.bpf\n"
	"                                  see man pcap-filter for a list of all filter options\n"
	"                                  add BPF code: \n"
	"                                  $ %s -i <INTERFACE> --bpf=attack.bpf ...\n"
	"--disable_beacon               : do not transmit BEACON frames\n"
	"--disable_deauthentication     : do not transmit DEAUTHENTICATION/DISASSOCIATION frames\n"
	"--disable_proberequest         : do not transmit PROBEREQUEST frames\n"
	"--disable_association          : do not AUTHENTICATE/ASSOCIATE\n"
	"--disable_reassociation        : do not REASSOCIATE a CLIENT\n"
	"--beacontx=<digit>             : transmit BEACON of first n entries of ESSID list\n"
	"                                 default: %d\n"
	"--proberesponsetx=<digit>      : transmit PROBERESPONSEs of first n entries of ESSID list\n"
	"                                 default: %d\n"
	"--essidlist=<file>             : initialize ESSID list with these ESSIDs\n"
	"--errormax=<digit>             : set maximum allowed ERRORs\n"
	"                                 default: %d ERRORs\n"
	"--watchdogmax=<seconds>        : set maximum TIMEOUT when no packets received\n"
	"                                 default: %d seconds\n"
	"--attemptclientmax=<digit>     : set maximum of attempts to request an EAPOL M2\n"
	"                                 default: %d attempts\n"
	"--attemptapmax=<digit>         : set maximum of received BEACONs to request a PMKID or to get a 4-way handshake\n"
	"                                 default: stop after %d received BEACONs\n"
	"--tot=<digit>                  : enable timeout timer in minutes\n"
	"--onsigterm=<action>           : action when the program has been terminated (poweroff, reboot)\n"
	"                                  poweroff: power off system\n"
	"                                  reboot:   reboot system\n"
	"--ongpiobutton=<action>        : action when the program has been terminated (poweroff, reboot)\n"
	"                                  poweroff: power off system\n"
	"                                  reboot:   reboot system\n"
	"--ontot=<action>               : action when the program has been terminated (poweroff, reboot)\n"
	"                                  poweroff: power off system\n"
	"                                  reboot:   reboot system\n"
	"--onwatchdog=<action>          : action when the program has been terminated (poweroff, reboot)\n"
	"                                  poweroff: power off system\n"
	"                                  reboot:   reboot system\n"
	"--onerror=<action>             : action when the program has been terminated (poweroff, reboot)\n"
	"                                  poweroff: power off system\n"
	"                                  reboot:   reboot system\n"
	"--gpio_button=<digit>          : Raspberry Pi GPIO pin number of button (2...27)\n"
	"                                  push GPIO button (> 10 seconds) to terminate program\n"
	"                                  default: 0 (GPIO not in use)\n"
	"--gpio_statusled=<digit>       : Raspberry Pi GPIO number of status LED (2...27)\n"
	"                                  default: 0 (GPIO not in use)\n"
	#ifdef NMEAOUT
	"--nmea_dev=<NMEA device>       : open NMEA device (/dev/ttyACM0, /dev/tty/USB0, ...)\n"
	"                                  baudrate = BD9600\n"
	"--gpsd                         : use gpsd to get position\n"
	"                                  gpsd will be switched to NMEA0183 mode\n"
	"--nmea_out=<outfile>           : write GPS information to a nmea-format file named <outfile>\n"
	"                                  default outfile name: yyyyddmmhhmmss.nmea\n"
	"                                  output: NMEA 0183 standard messages:\n"
	"                                          $GPRMC: Position, velocity, time and date\n"
	"                                          $GPGGA: Position, orthometric height, fix related data, time\n"
	"                                          $GPWPL: Position and MAC AP\n"
	"                                          $GPTXT: ESSID in HEX ASCII\n"
	"                                  use gpsbabel to convert to other formats:\n"
	"                                   gpsbabel -w -t -i nmea -f in_file.nmea -o gpx -F out_file_gpx\n"
	"                                   gpsbabel -w -t -i nmea -f in_file.nmea -o kml -F out_file.kml\n"
	"                                  get more information: https://en.wikipedia.org/wiki/NMEA_0183\n"
	#endif
	"--rcascan_passive              : do passive (R)adio (C)hannel (A)ssignment scan\n" 
	"--help                         : show this help\n"
	"--version                      : show version\n"
	"\n",
	eigenname, eigenname,
	BEACONTX_MAX, PROBERESPONSETX_MAX, ERROR_MAX, WATCHDOG_MAX, ATTEMPTCLIENT_MAX, ATTEMPTAP_MAX / 8);

fprintf(stdout, "Legend\n"
	"real time display:\n"
	" R = + AP is in TX range\n"
	" P = + got PMKID\n"
	" M = + AP display:     got EAPOL M1M2M3 (AUTHORIZATION)\n"
	" M = + CLIENT display: got EAPOL M1M2 (ROGUE CHALLENGE)\n"
	" A = + AUTHENTICATION KEY MANAGEMENT PSK\n"
	"Notice:\n"
	"This is a penetration testing tool!\n"
	"It is made to detect vulnerabilities in your NETWORK mercilessly!\n" 
	"To store entire traffic, run <tshark -i <interface> -w allframes.pcapng> in parallel\n"
	"\n");


exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usageerror(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSION_TAG, VERSION_YEAR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl = -1;
static int index = 0;
static u8 exitsigtermflag = 0;
static u8 exitgpiobuttonflag = 0;
static u8 exittotflag = 0;
static u8 exitwatchdogflag = 0;
static u8 exiterrorflag = 0;
static struct timespec tspecifo, tspeciforem;
static bool monitormodeflag = false;
static bool interfaceinfoflag = false;
static bool interfacefrequencyflag = false;
static bool interfacelistflag = false;
static bool rcascanflag = false;
static char *bpfname = NULL;
static char *essidlistname = NULL;
static char *userchannellistname = NULL;
static char *userfrequencylistname = NULL;
static char *pcapngoutname = NULL;

#ifdef NMEAOUT
static bool gpsdflag = false;
static char *nmea0183name = NULL;
static char *nmeaoutname = NULL;
#endif

static const char *rebootstring = "reboot";
static const char *poweroffstring = "poweroff";
static const char *short_options = "i:w:c:f:m:I:t:FLhv";
static const struct option long_options[] =
{
	{"bpf",				required_argument,	NULL,	HCX_BPF},
	{"disable_beacon",		no_argument,		NULL,	HCX_DISABLE_BEACON},
	{"disable_deauthentication",	no_argument,		NULL,	HCX_DISABLE_DEAUTHENTICATION},
	{"disable_proberequest",	no_argument,		NULL,	HCX_DISABLE_PROBEREQUEST},
	{"disable_association",		no_argument,		NULL,	HCX_DISABLE_ASSOCIATION},
	{"disable_reassociation",	no_argument,		NULL,	HCX_DISABLE_REASSOCIATION},
	{"beacontx",			required_argument,	NULL,	HCX_BEACONTX_MAX},
	{"proberesponsetx",		required_argument,	NULL,	HCX_PROBERESPONSETX_MAX},
	{"attemptclientmax",		required_argument,	NULL,	HCX_ATTEMPT_CLIENT_MAX},
	{"attemptapmax",		required_argument,	NULL,	HCX_ATTEMPT_AP_MAX},
	{"tot",				required_argument,	NULL,	HCX_TOT},
	{"essidlist",			required_argument,	NULL,	HCX_ESSIDLIST},
	#ifdef NMEAOUT
	{"nmea_dev",			required_argument,	NULL,	HCX_NMEA0183},
	{"gpsd",			no_argument,		NULL,	HCX_GPSD},
	{"nmea_out",			required_argument,	NULL,	HCX_NMEA0183_OUT},
	#endif
	{"errormax",			required_argument,	NULL,	HCX_ERROR_MAX},
	{"watchdogmax",			required_argument,	NULL,	HCX_WATCHDOG_MAX},
	{"onsigterm",			required_argument,	NULL,	HCX_ON_SIGTERM},
	{"ongpiobutton",		required_argument,	NULL,	HCX_ON_GPIOBUTTON},
	{"ontot",			required_argument,	NULL,	HCX_ON_TOT},
	{"onwatchdog",			required_argument,	NULL,	HCX_ON_WATCHDOG},
	{"onerror",			required_argument,	NULL,	HCX_ON_ERROR},
	{"gpio_button",			required_argument,	NULL,	HCX_GPIO_BUTTON},
	{"gpio_statusled",		required_argument,	NULL,	HCX_GPIO_STATUSLED},
	{"rcascan_passive",		no_argument,		NULL,	HCX_RCASCAN_PASSIVE},
	{"version",			no_argument,		NULL,	HCX_VERSION},
	{"help",			no_argument,		NULL,	HCX_HELP},
	{NULL,				0,			NULL,	0}
};
optind = 1;
optopt = 0;
while((auswahl = getopt_long(argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCX_IFNAME:
		if((ifaktindex = if_nametoindex(optarg)) == 0)
			{
			perror("failed to get interface index");
			exit(EXIT_FAILURE);
			}
		strncpy(ifaktname, optarg, IF_NAMESIZE -1);
		break;

		case HCX_BPF:
		bpfname = optarg;
		break;

		case HCX_PCAPNGNAME:
		pcapngoutname = optarg;
		break;

		case HCX_SET_SCANLIST_FROM_INTERFACE:
		interfacefrequencyflag = true;
		break;

		case HCX_SET_SCANLIST_FROM_USER_FREQ:
		userfrequencylistname = optarg;
		break;

		case HCX_SET_SCANLIST_FROM_USER_CH:
		userchannellistname = optarg;
		break;

		case HCX_ESSIDLIST:
		essidlistname = optarg;
		break;

		case HCX_DISABLE_BEACON:
		timerwaitnd = -1;
		break;

		case HCX_DISABLE_DEAUTHENTICATION:
		deauthenticationflag = false;
		break;

		case HCX_DISABLE_PROBEREQUEST:
		proberequestflag = false;
		break;

		case HCX_DISABLE_ASSOCIATION:
		associationflag = false;
		break;

		case HCX_DISABLE_REASSOCIATION:
		reassociationflag = false;
		break;

		case HCX_BEACONTX_MAX:
		beacontxmax = strtoul(optarg, NULL, 10);
		if((beacontxmax == 0) || (beacontxmax > (APRGLIST_MAX - 1)))
			{
			fprintf(stderr, "must be greater than > 0 and < than %d \n", APRGLIST_MAX - 1);
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_PROBERESPONSETX_MAX:
		proberesponsetxmax = strtoul(optarg, NULL, 10);
		if((proberesponsetxmax == 0) || (proberesponsetxmax > (APRGLIST_MAX - 1)))
			{
			fprintf(stderr, "must be greater than > 0 and < than %d \n", APRGLIST_MAX - 1);
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_ATTEMPT_CLIENT_MAX:
		if((attemptclientmax = strtoul(optarg, NULL, 10)) < 1)
			{
			fprintf(stderr, "number of attempts must be > 0\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_ATTEMPT_AP_MAX:
		if((attemptapmax = strtoul(optarg, NULL, 10)) < 1)
			{
			fprintf(stderr, "number of attempts must be > 0\n");
			exit(EXIT_FAILURE);
			}
		attemptapmax *= 8;
		break;

		case HCX_HOLD_TIME:
		if((timehold = strtoull(optarg, NULL, 10)) < 2)
			{
			fprintf(stderr, "hold time must be > 2 seconds");
			exit(EXIT_FAILURE);
			}
		timehold *= 1000000000ULL;
		break;

		case HCX_TOT:
		if((tottime = strtoul(optarg, NULL, 10)) < 1)
			{
			fprintf(stderr, "time out timer must be > 0 minutes\n");
			exit(EXIT_FAILURE);
			}
		tottime *= 60;
		break;

		case HCX_WATCHDOG_MAX:
		if((watchdogcountmax = strtoul(optarg, NULL, 10)) < 1)
			{
			fprintf(stderr, "time out timer must be > 0\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_ERROR_MAX:
		if((errorcountmax = strtoul(optarg, NULL, 10)) < 1)
			{
			fprintf(stderr, "error counter must be > 0\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_ON_SIGTERM:
		if(strncmp(rebootstring, optarg, 8) == 0) exitsigtermflag = EXIT_ACTION_REBOOT;
		else if(strncmp(poweroffstring, optarg, 8) == 0) exitsigtermflag = EXIT_ACTION_POWEROFF;
		break;

		case HCX_ON_GPIOBUTTON:
		if(strncmp(rebootstring, optarg, 8) == 0) exitgpiobuttonflag = EXIT_ACTION_REBOOT;
		else if(strncmp(poweroffstring, optarg, 8) == 0) exitgpiobuttonflag = EXIT_ACTION_POWEROFF;
		break;

		case HCX_ON_TOT:
		if(strncmp(rebootstring, optarg, 8) == 0) exittotflag = EXIT_ACTION_REBOOT;
		else if(strncmp(poweroffstring, optarg, 8) == 0) exittotflag = EXIT_ACTION_POWEROFF;
		break;

		case HCX_ON_WATCHDOG:
		if(strncmp(rebootstring, optarg, 8) == 0) exitwatchdogflag = EXIT_ACTION_REBOOT;
		else if(strncmp(poweroffstring, optarg, 8) == 0) exitwatchdogflag = EXIT_ACTION_POWEROFF;
		break;

		case HCX_ON_ERROR:
		if(strncmp(rebootstring, optarg, 8) == 0) exiterrorflag = EXIT_ACTION_REBOOT;
		else if(strncmp(poweroffstring, optarg, 8) == 0) exiterrorflag = EXIT_ACTION_POWEROFF;
		break;

		case HCX_GPIO_BUTTON:
		gpiobutton = strtol(optarg, NULL, 10);
		if((gpiobutton < 2) || (gpiobutton > 27))
			{
			fprintf(stderr, "invalid GPIO option\n");
			exit(EXIT_FAILURE);
			}
		if(gpiostatusled == gpiobutton)
			{
			fprintf(stderr, "GPIO pin ERROR (same value of GPIO button and GPIO status LED)\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_GPIO_STATUSLED:
		gpiostatusled = strtol(optarg, NULL, 10);
		if((gpiostatusled < 2) || (gpiostatusled > 27))
			{
			fprintf(stderr, "invalid GPIO option\n");
			exit(EXIT_FAILURE);
			}
		if(gpiostatusled == gpiobutton)
			{
			fprintf(stderr, "GPIO pin ERROR (same value of GPIO button and GPIO status LED)\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_INTERFACE_INFO:
		if((ifaktindex = if_nametoindex(optarg)) == 0)
			{
			perror("failed to get interface index");
			exit(EXIT_FAILURE);
			}
		strncpy(ifaktname, optarg, IF_NAMESIZE -1);
		interfaceinfoflag = true;
		break;

		case HCX_SET_MONITORMODE:
		if((ifaktindex = if_nametoindex(optarg)) == 0)
			{
			perror("failed to get interface index");
			exit(EXIT_FAILURE);
			}
		strncpy(ifaktname, optarg, IF_NAMESIZE -1);
		monitormodeflag = true;
		break;

		case HCX_SHOW_INTERFACE_LIST:
		interfacelistflag = true;
		break;

		#ifdef NMEAOUT
		case HCX_NMEA0183:
		if(gpsdflag == true)
			{
			fprintf(stderr, "nmea_dev not allowed in combination with gpsd\n");
			exit(EXIT_FAILURE);
			}
		nmea0183name = optarg;
		break;

		case HCX_GPSD:
		if(nmea0183name != NULL)
			{
			fprintf(stderr, "gpsd not allowed in combination with nmea_dev\n");
			exit(EXIT_FAILURE);
			}
		gpsdflag = true;
		break;

		case HCX_NMEA0183_OUT:
		nmeaoutname = optarg;
		break;
		#endif

		case HCX_RCASCAN_PASSIVE:
		rcascanflag = true;
		break;

		case HCX_HELP:
		usage(basename(argv[0]));
		break;

		case HCX_VERSION:
		version(basename(argv[0]));
		break;

		case '?':
		usageerror(basename(argv[0]));
		break;

		default:
		usageerror(basename(argv[0]));
		}
	}
setbuf(stdout, NULL);
hcxpid = getpid();
fprintf(stdout, "\nRequesting interface capabilities. This may take some time.\n"
		"Please be patient...\n\n");
if(set_signal_handler() == false)
	{
	errorcount++;
	fprintf(stderr, "failed to initialize signal handler\n");
	goto byebye;
	}
if((gpiobutton + gpiostatusled) > 0)
	{
	if(init_rpi() == false)
		{
		errorcount++;
		fprintf(stderr, "failed to initialize Raspberry Pi GPIO\n");
		goto byebye;
		}
	}
if(init_lists() == false)
	{
	errorcount++;
	fprintf(stderr, "failed to open control sockets\n");
	goto byebye;
	}
init_values();
#ifdef NMEAOUT
if(nmea0183name != NULL)
	{
	if(open_device_nmea0183(nmea0183name, nmeaoutname) == false)
		{
		errorcount++;
		fprintf(stderr, "failed to open NMEA0183 device\n");
		goto byebye;
		}
	}
if(gpsdflag == true)
	{
	if(open_socket_gpsd(nmeaoutname) == false)
		{
		errorcount++;
		fprintf(stderr, "failed to connect to GPSD\n");
		goto byebye;
		}
	}
#endif
/*---------------------------------------------------------------------------*/
if(open_control_sockets() == false)
	{
	errorcount++;
	fprintf(stderr, "failed to open control sockets\n");
	goto byebye;
	}
if(get_interfacelist() == false)
	{
	errorcount++;
	fprintf(stderr, "failed to get interface list\n");
	goto byebye;
	}
if(interfacelistflag == true)
	{
	show_interfacelist();
	goto byebye;
	}
if(interfaceinfoflag == true)
	{
	show_interfacecapabilities();
	goto byebye;
	}
/*---------------------------------------------------------------------------*/
if(getuid() != 0)
	{
	errorcount++;
	fprintf(stderr, "%s must be run as root\n", basename(argv[0]));
	goto byebye;
	}
if(monitormodeflag == true)
	{
	if(set_monitormode() == false)
		{
		errorcount++;
		fprintf(stderr, "failed to set monitor mode\n");
		}
	goto byebye;
	}
if(set_interface(interfacefrequencyflag, userfrequencylistname, userchannellistname) == false)
	{
	errorcount++;
	fprintf(stderr, "failed to arm interface\n");
	goto byebye;
	}
if(essidlistname != NULL) read_essidlist(essidlistname);
if(rcascanflag == false)
	{
	if(open_pcapng(pcapngoutname) == false)
		{
		errorcount++;
		fprintf(stderr, "failed to open dump file\n");
		goto byebye;
		}
	}
if(open_socket_rx(bpfname) == false)
	{
	errorcount++;
	fprintf(stderr, "failed to open raw packet socket\n");
	goto byebye;
	}
if(open_socket_tx() == false)
	{
	errorcount++;
	fprintf(stderr, "failed to open transmit socket\n");
	goto byebye;
	}
if(rcascanflag == false)
	{
	if(set_timer() == false)
		{
		errorcount++;
		fprintf(stderr, "failed to initialize timer\n");
		goto byebye;
		}
	}
else
	{
	if(set_timer_rca() == false)
		{
		errorcount++;
		fprintf(stderr, "failed to initialize timer\n");
		goto byebye;
		}
	}
/*---------------------------------------------------------------------------*/
tspecifo.tv_sec = 5;
tspecifo.tv_nsec = 0;
fprintf(stdout, "\nThis is a highly experimental penetration testing tool!\n"
		"It is made to detect vulnerabilities in your NETWORK mercilessly!\n\n");
if(bpf.len == 0) fprintf(stderr, "BPF is unset! Make sure hcxdumptool is running in a 100%% controlled environment!\n\n");
fprintf(stdout, "Initialize main scan loop...\e[?25l");
nanosleep(&tspecifo, &tspeciforem);

if(rcascanflag == false)
	{
	if(nl_scanloop() == false)
		{
		errorcount++;
		fprintf(stderr, "failed to initialize main scan loop\n");
		}
	}
else
	{
	if(nl_scanloop_rca() == false)
		{
		errorcount++;
		fprintf(stderr, "failed to initialize rca scan loop\n");
		}
	}
/*---------------------------------------------------------------------------*/
byebye:
close_fds();
close_sockets();
close_lists();
if(errorcount > 0) fprintf(stderr, "\n%" PRIu64 " errors during runtime\n", errorcount);
if((wanteventflag & EXIT_ON_SIGTERM) == EXIT_ON_SIGTERM)
	{
	if(exitsigtermflag == EXIT_ACTION_REBOOT)
		{
		if(system("reboot") != 0) fprintf(stderr, "\ncan't reboot system\n");
		}
	else if(exitsigtermflag == EXIT_ACTION_POWEROFF)
		{
		if(system("poweroff") != 0) fprintf(stderr, "\ncan't power off\n");
		}
	}
else if((wanteventflag & EXIT_ON_GPIOBUTTON) == EXIT_ON_GPIOBUTTON)
	{
	if(exitgpiobuttonflag == EXIT_ACTION_REBOOT)
		{
		if(system("reboot") != 0) fprintf(stderr, "\ncan't reboot system\n");
		}
	else if(exitgpiobuttonflag == EXIT_ACTION_POWEROFF)
		{
		if(system("poweroff") != 0) fprintf(stderr, "\ncan't power off\n");
		}
	}
else if((wanteventflag & EXIT_ON_TOT) == EXIT_ON_TOT)
	{
	if(exittotflag == EXIT_ACTION_REBOOT)
		{
		if(system("reboot") != 0) fprintf(stderr, "\ncan't reboot system\n");
		}
	else if(exittotflag == EXIT_ACTION_POWEROFF)
		{
		if(system("poweroff") != 0) fprintf(stderr, "\ncan't power off\n");
		}
	}
else if((wanteventflag & EXIT_ON_WATCHDOG) == EXIT_ON_WATCHDOG)
	{
	if(exitwatchdogflag == EXIT_ACTION_REBOOT)
		{
		if(system("reboot") != 0) fprintf(stderr, "\ncan't reboot system\n");
		}
	else if(exitwatchdogflag == EXIT_ACTION_POWEROFF)
		{
		if(system("poweroff") != 0) fprintf(stderr, "\ncan't power off\n");
		}
	}
else if((wanteventflag & EXIT_ON_ERROR) == EXIT_ON_ERROR)
	{
	if(exiterrorflag == EXIT_ACTION_REBOOT)
		{
		if(system("reboot") != 0) fprintf(stderr, "\ncan't reboot system\n");
		}
	else if(exiterrorflag == EXIT_ACTION_POWEROFF)
		{
		if(system("poweroff") != 0) fprintf(stderr, "\ncan't power off\n");
		}
	}
fprintf(stdout, "\nbye-bye\n\e[?25h");
return EXIT_SUCCESS;
}
/*===========================================================================*/
