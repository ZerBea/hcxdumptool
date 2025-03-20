#define _GNU_SOURCE
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#if defined (_POSIX_VERSION)
#include <fcntl.h>
#endif
#if defined (__GLIBC__)
#include <gnu/libc-version.h>
#endif
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <linux/filter.h>
#include <linux/genetlink.h>
#include <linux/if_packet.h>
#include <linux/limits.h>
#include <linux/nl80211.h>
#include <linux/rtnetlink.h>
#include <linux/version.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
#ifdef HCXWANTLIBPCAP
#include <pcap/pcap.h>
#endif
#include "include/types.h"
#include "include/byteorder.h"
#include "include/ieee80211.h"
#include "include/pcapng.h"
#include "include/radiotap.h"
#include "include/raspberry.h"
#include "include/hcxdumptool.h"
/*===========================================================================*/
/* global var */
static bool activemonitorflag = false;
static bool vmflag = true;
static bool disassociationflag = true;
static bool ftcflag = false;
static bool rdtflag = false;

static uid_t uid = 1000;
static struct passwd *pwd = NULL;

static u16 wanteventflag = 0;
static u16 exiteapolpmkidflag = 0;
static u16 exiteapolm3flag = 0;
static u16 exiteapolm2flag = 0;
static u16 exiteapolm2rgflag = 0;
static u16 exiteapolm1flag = 0;

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
static int fd_fakeclock = 0;

#ifdef HCXDEBUG
static FILE *fh_debug = NULL;
static clock_t debugtms;
static double debugtmstaken;
#endif

static struct sock_fprog bpf = { 0 };

static int ifaktindex = 0;
static int ifaktwiphy = 0;
static u8 ifaktstatus = 0;
static u8 ifakttype = 0;
static u8 rds = 0;
static u8 rcascanmode = 0;

static aplist_t *aplist = NULL;
static aplist_t *aprglist = NULL;
static calist_t *calist = NULL;

static frequencylist_t *ifaktfrequencylist = NULL;
static char ifaktname[IF_NAMESIZE +1] = { 0 };
static u8 ifakthwmac[ETH_ALEN] = { 0 };

static u16 nlfamily = 0;
static u32 nlseqcounter = 1;

static size_t ifpresentlistcounter = 0;

static size_t scanlistindex = 0;
static frequencylist_t *scanlist = NULL;

static interface_t *ifpresentlist = NULL;

static u64 lifetime = 0;
static u32 ouiaprg = 0;
static u32 nicaprg = 0;
static u32 ouiclientrg = 0;
static u32 nicclientrg = 0;
static u64 replaycountrg = 0;

static struct timespec tspecakt = { 0 };
static struct timespec tsremain, tsreq = {0, TSWAITEAPOLA};

static u64 tsakt = 0;
static u64 tottime = 0;
static u64 timehold = TIMEHOLD;
static int timerwaitnd = TIMER_EPWAITND;

static u32 errorcountmax = ERROR_MAX;
static u32 errorcount = 0;
static u32 errortxcount = 0;

static u32 timewatchdog = WATCHDOG_MAX;
static int apcountmax = APCOUNT_MAX;
static int clientcountmax = CLIENTCOUNT_MAX;

static u64 packetcount = 1;
static size_t proberesponsetxindex = 0;
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
static u16 keyinfo = 0;
static u8 kdv = 0;
static u16 rtfrequency = 0;
static u8 rtrssi = 0;

static enhanced_packet_block_t *epbhdr = NULL;

static ieee80211_mac_t *macftx = NULL;
static u16 seqcounter1 = 1; /* authentication / association */
static u16 seqcounter2 = 1; /*  */
static u16 seqcounter3 = 1; /*  */
static u16 seqcounter4 = 1; /*  */
/*---------------------------------------------------------------------------*/
#ifdef HCXNMEAOUT
static const char gpwplid[] = "$GPWPL";
static const char gptxtid[] = "$GPTXT,";
static const char lookuptable[] = { '0', '1', '2','3','4','5','6','7','8','9','a','b','c','d','e','f' };
#endif
/*---------------------------------------------------------------------------*/
static const u8 proberesponsedata[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
//0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,

/* Tag: Supported Rates 1, 2, 5.5, 11, 6, 9, 12, 18, [Mbit/sec] */
0x01, 0x08, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24,

/* Tag: DS Parameter set: Current Channel: 1 */
0x03, 0x01, 0x01,

/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
//0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,

/* Tag: Extended Supported Rates 24, 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,

/* Tag: RSN Information CCM CCM PSK */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x80, 0x00,
};
#define PROBERESPONSEDATA_SIZE sizeof(proberesponsedata)
/*---------------------------------------------------------------------------*/
static const u8 proberequest_undirected_data[] =
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
static const u8 authenticationrequestdata[] =
{
0x00, 0x00, 0x01, 0x00, 0x00, 0x00
};
#define AUTHENTICATIONREQUEST_SIZE sizeof(authenticationrequestdata)
/*---------------------------------------------------------------------------*/
static const u8 associationrequestcapa[] =
{
0x31, 0x04, 0x05, 0x00
};
#define ASSOCIATIONREQUESTCAPA_SIZE sizeof(associationrequestcapa)
/*---------------------------------------------------------------------------*/
static const u8 associationrequestdata[] =
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
static const u8 eaprequestiddata[] =
{
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x01, 0x00, 0x00, 0x05, 0x01, 0x01, 0x00, 0x05, 0x01
};
#define EAPREQUESTID_SIZE sizeof(eaprequestiddata)
/*---------------------------------------------------------------------------*/
static u8 eapolm1wpa1data[] =
{
/* LLC */
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
/* M1 WPA2 */
0x01,
0x03,
0x00, 0x5f,
0xfe,
0x00, 0x89,
0x00, 0x20,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00
};
#define EAPOLM1WPA1DATA_SIZE sizeof(eapolm1wpa1data)
/*---------------------------------------------------------------------------*/
static u8 eapolm1wpa2data[] =
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
#define EAPOLM1WPA2DATA_SIZE sizeof(eapolm1wpa2data)
/*---------------------------------------------------------------------------*/
static const u8 associationresponsedata[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
//0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
//0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,

/* Tag: Supported Rates 1, 2, 5.5, 11, 6, 9, 12, 18, [Mbit/sec] */
0x01, 0x08, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24,
/* Tag: Extended Supported Rates 24, 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,


};
#define ASSOCIATIONRESPONSEDATA_SIZE sizeof(associationresponsedata)
/*---------------------------------------------------------------------------*/
static const u8 authenticationresponsedata[] =
{
0x00, 0x00, 0x02, 0x00, 0x00, 0x00
};
#define AUTHENTICATIONRESPONSE_SIZE sizeof(authenticationresponsedata)
/*---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
static u8 macaprghidden[ETH_ALEN] = { 0 };
static u8 macaprg[ETH_ALEN] = { 0 };
static u8 macclientrg[ETH_ALEN +2] = { 0 };
static u8 anoncerg[32] = { 0 };
static u8 snoncerg[32] = { 0 };
static char weakcandidate[PSK_MAX];
static char timestring[TIMESTRING_LEN];
static char timestringresponse[TIMESTRING_LEN];

static char country[3];

static u8 nltxbuffer[NLTX_SIZE] = { 0 };
static u8 nlrxbuffer[NLRX_SIZE] = { 0 };

static u8 epb[PCAPNG_SNAPLEN * 2] = { 0 };
static u8 epbown[WLTXBUFFER] = { 0 };
static u8 wltxbuffer[WLTXBUFFER] = { 0 };
/*===========================================================================*/
/*===========================================================================*/
/* status print */
/*---------------------------------------------------------------------------*/
static void show_interfacecapabilities(void)
{
static size_t i;
static size_t ifl;

static const char *po = "N/A";
static const char *mode = "-";
static frequencylist_t *iffreql;

for(i = 0; i < ifpresentlistcounter; i++)
	{
	if((ifpresentlist + i)->index != ifaktindex) continue;
	fprintf(stdout, "interface information:\n\nphy idx hw-mac       virtual-mac  m ifname           driver (protocol)\n"
			"---------------------------------------------------------------------------------------------\n");
	if(((ifpresentlist + i)->type & IF_HAS_NETLINK) == IF_HAS_NETLINK) po = "NETLINK";
	if(((ifpresentlist + i)->type & IF_IS_SHARED) != IF_IS_SHARED)
		{
		if(((ifpresentlist + i)->type & IFTYPEMONACT) == IFTYPEMONACT) mode = "*";
		else if(((ifpresentlist + i)->type & IFTYPEMON) == IFTYPEMON) mode = "+";
		}
	else
		{
		if(((ifpresentlist + i)->type & IFTYPEMONACT) == IFTYPEMONACT) mode = "S";
		else if(((ifpresentlist + i)->type & IFTYPEMON) == IFTYPEMON) mode = "s";
		}
	fprintf(stdout, "%3d %3d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s %-*s %s (%s)\n", (ifpresentlist + i)->wiphy, (ifpresentlist + i)->index,
		(ifpresentlist + i)->hwmac[0], (ifpresentlist + i)->hwmac[1], (ifpresentlist + i)->hwmac[2], (ifpresentlist + i)->hwmac[3], (ifpresentlist + i)->hwmac[4], (ifpresentlist + i)->hwmac[5],
		(ifpresentlist + i)->vimac[0], (ifpresentlist + i)->vimac[1], (ifpresentlist + i)->vimac[2], (ifpresentlist + i)->vimac[3], (ifpresentlist + i)->vimac[4], (ifpresentlist + i)->vimac[5],
		mode, IF_NAMESIZE, (ifpresentlist + i)->name, (ifpresentlist + i)->driver, po);
	iffreql = (ifpresentlist + i)->frequencylist;
	fprintf(stdout, "\n\navailable frequencies: frequency [channel] tx-power of Regulatory Domain: %s\n", country);
	for(ifl = 0; ifl < FREQUENCYLIST_MAX; ifl++)
		{
		if((iffreql + ifl)->frequency == 0) break;
		if(ifl % 4 == 0) fprintf(stdout, "\n");
		else  fprintf(stdout, "\t");
		if((iffreql + ifl)->status == 0) fprintf(stdout, "%6d [%3d] %.1f dBm", (iffreql + ifl)->frequency, (iffreql + ifl)->channel, 0.01 *(iffreql + ifl)->pwr);
		else fprintf(stdout, "%6d [%3d] disabled", (iffreql + ifl)->frequency, (iffreql + ifl)->channel);
		}
	fprintf(stdout, "\n");
	}
return;
}
/*---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
static void show_interfacelist_short(void)
{
static size_t i;
static const char *po = "N/A";
static const char *mode = "-";
static const char *unassigned = "unassigned";

for(i = 0; i < ifpresentlistcounter; i++)
	{
	if(((ifpresentlist + i)->type & IF_HAS_NETLINK) == IF_HAS_NETLINK) po = "NETLINK";
	if(((ifpresentlist + i)->type & IF_IS_SHARED) != IF_IS_SHARED)
		{
		if(((ifpresentlist + i)->type & IFTYPEMONACT) == IFTYPEMONACT) mode = "*";
		else if(((ifpresentlist + i)->type & IFTYPEMON) == IFTYPEMON) mode = "+";
		}
	else
		{
		if(((ifpresentlist + i)->type & IFTYPEMONACT) == IFTYPEMONACT) mode = "S";
		else if(((ifpresentlist + i)->type & IFTYPEMON) == IFTYPEMON) mode = "s";
		}
	if((ifpresentlist + i)->name[0] != 0) fprintf(stdout, "%3d\t%3d\t%02x%02x%02x%02x%02x%02x\t%02x%02x%02x%02x%02x%02x\t%s\t%-*s\t%s\t%s\n", (ifpresentlist + i)->wiphy, (ifpresentlist + i)->index,
		(ifpresentlist + i)->hwmac[0], (ifpresentlist + i)->hwmac[1], (ifpresentlist + i)->hwmac[2], (ifpresentlist + i)->hwmac[3], (ifpresentlist + i)->hwmac[4], (ifpresentlist + i)->hwmac[5],
		(ifpresentlist + i)->vimac[0], (ifpresentlist + i)->vimac[1], (ifpresentlist + i)->vimac[2], (ifpresentlist + i)->vimac[3], (ifpresentlist + i)->vimac[4], (ifpresentlist + i)->vimac[5],
		mode, IF_NAMESIZE, (ifpresentlist + i)->name, (ifpresentlist + i)->driver, po);
	else fprintf(stdout, "%3d\t%3d\t%02x%02x%02x%02x%02x%02x\t%02x%02x%02x%02x%02x%02x\t%s\t%-*s\t%s\t%s\n", (ifpresentlist + i)->wiphy, (ifpresentlist + i)->index,
		(ifpresentlist + i)->hwmac[0], (ifpresentlist + i)->hwmac[1], (ifpresentlist + i)->hwmac[2], (ifpresentlist + i)->hwmac[3], (ifpresentlist + i)->hwmac[4], (ifpresentlist + i)->hwmac[5],
		(ifpresentlist + i)->vimac[0], (ifpresentlist + i)->vimac[1], (ifpresentlist + i)->vimac[2], (ifpresentlist + i)->vimac[3], (ifpresentlist + i)->vimac[4], (ifpresentlist + i)->vimac[5],
		mode, IF_NAMESIZE, unassigned, (ifpresentlist + i)->driver, po);
	}
return;
}
/*---------------------------------------------------------------------------*/
static void show_interfacelist(void)
{
static size_t i;
static const char *po = "N/A";
static const char *mode = "-";
static const char *unassigned = "unassigned";

fprintf(stdout, "available physical wlan devices:\n\nphy idx hw-mac       virtual-mac  m ifname           driver (protocol)\n"
		"---------------------------------------------------------------------------------------------\n");
for(i = 0; i < ifpresentlistcounter; i++)
	{
	if(((ifpresentlist + i)->type & IF_HAS_NETLINK) == IF_HAS_NETLINK) po = "NETLINK";
	if(((ifpresentlist + i)->type & IF_IS_SHARED) != IF_IS_SHARED)
		{
		if(((ifpresentlist + i)->type & IFTYPEMONACT) == IFTYPEMONACT) mode = "*";
		else if(((ifpresentlist + i)->type & IFTYPEMON) == IFTYPEMON) mode = "+";
		}
	else
		{
		if(((ifpresentlist + i)->type & IFTYPEMONACT) == IFTYPEMONACT) mode = "S";
		else if(((ifpresentlist + i)->type & IFTYPEMON) == IFTYPEMON) mode = "s";
		}
	if((ifpresentlist + i)->name[0] != 0) fprintf(stdout, "%3d %3d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s %-*s %s (%s)\n", (ifpresentlist + i)->wiphy, (ifpresentlist + i)->index,
		(ifpresentlist + i)->hwmac[0], (ifpresentlist + i)->hwmac[1], (ifpresentlist + i)->hwmac[2], (ifpresentlist + i)->hwmac[3], (ifpresentlist + i)->hwmac[4], (ifpresentlist + i)->hwmac[5],
		(ifpresentlist + i)->vimac[0], (ifpresentlist + i)->vimac[1], (ifpresentlist + i)->vimac[2], (ifpresentlist + i)->vimac[3], (ifpresentlist + i)->vimac[4], (ifpresentlist + i)->vimac[5],
		mode, IF_NAMESIZE, (ifpresentlist + i)->name, (ifpresentlist + i)->driver, po);
	else fprintf(stdout, "%3d %3d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s %-*s %s (%s)\n", (ifpresentlist + i)->wiphy, (ifpresentlist + i)->index,
		(ifpresentlist + i)->hwmac[0], (ifpresentlist + i)->hwmac[1], (ifpresentlist + i)->hwmac[2], (ifpresentlist + i)->hwmac[3], (ifpresentlist + i)->hwmac[4], (ifpresentlist + i)->hwmac[5],
		(ifpresentlist + i)->vimac[0], (ifpresentlist + i)->vimac[1], (ifpresentlist + i)->vimac[2], (ifpresentlist + i)->vimac[3], (ifpresentlist + i)->vimac[4], (ifpresentlist + i)->vimac[5],
		mode, IF_NAMESIZE, unassigned, (ifpresentlist + i)->driver, po);

	}
fprintf(stdout, "\nmodes reported by the driver:\n"
		"* active monitor mode available (do not trust it)\n"
		"S active monitor mode available on shared interface (do not trust it)\n"
		"+ monitor mode available\n"
		"s monitor mode available on shared interface\n"
		"- no monitor available\n");
return;
}
/*---------------------------------------------------------------------------*/
static inline void show_realtime_rca(void)
{
static size_t i;
static time_t tvlast;
struct winsize w;

if(rdtflag == false)
	{
	if(system("clear") != 0) errorcount++;
	w.ws_row = 12;
	if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == -1) errorcount++;
	if(w.ws_row > 10) w.ws_row -= 4;
	}
fprintf(stdout, "CHA  BEACON  RESPONSE RSSI    MAC-AP    ESSID                  SCAN:%6u/%u\n"
		"------------------------------------------------------------------------------\n", (scanlist + scanlistindex)->frequency, (scanlist + scanlistindex)->channel);
if(rds == 0)
	{
	qsort(aplist, APLIST_MAX, APLIST_SIZE, sort_aplist_by_tsakt);
	for(i = 0; i < APLIST_MAX - 1; i++)
		{
		if((aplist + i)->tsakt == 0) return;
		if((scanlist + scanlistindex)->channel == (aplist + i)->apdata->channel)
			{
			tvlast = (aplist +i)->tsakt / 1000000000ULL;
			strftime(timestring, TIMESTRING_LEN, "%H:%M:%S", localtime(&tvlast));
			if((aplist + i)->apdata->tsresponse > 0)
				{
				tvlast = (aplist + i)->apdata->tsresponse / 1000000000ULL;
				strftime(timestringresponse, TIMESTRING_LEN, "%H:%M:%S", localtime(&tvlast));
				fprintf(stdout, "%3u %s %s %4d %02x%02x%02x%02x%02x%02x %.*s\n",
				(aplist + i)->apdata->channel, timestring, timestringresponse, (s8)(aplist + i)->apdata->rtrssi,
				(aplist + i)->apdata->maca[00], (aplist + i)->apdata->maca[01], (aplist + i)->apdata->maca[02],
				(aplist + i)->apdata->maca[03],	(aplist + i)->apdata->maca[04], (aplist + i)->apdata->maca[05],
				(aplist + i)->apdata->essidlen, (aplist + i)->apdata->essid);
				}
			else
				{
				fprintf(stdout, "%3u %s          %4d %02x%02x%02x%02x%02x%02x %.*s\n",
				(aplist + i)->apdata->channel, timestring, (s8)(aplist + i)->apdata->rtrssi,
				(aplist + i)->apdata->maca[00], (aplist + i)->apdata->maca[01], (aplist + i)->apdata->maca[02],
				(aplist + i)->apdata->maca[03],	(aplist + i)->apdata->maca[04], (aplist + i)->apdata->maca[05],
				(aplist + i)->apdata->essidlen, (aplist + i)->apdata->essid);
				}
			}
		}
	return;
	}
else if(rds == 1)
	{
	qsort(aplist, APLIST_MAX, APLIST_SIZE, sort_aplist_by_tsresponse);
	for(i = 0; i < APLIST_MAX - 1; i++)
		{
		if((aplist + i)->tsakt == 0) break;
		if((scanlist + scanlistindex)->channel == (aplist + i)->apdata->channel)
			{
			tvlast = (aplist +i)->tsakt / 1000000000ULL;
			strftime(timestring, TIMESTRING_LEN, "%H:%M:%S", localtime(&tvlast));
			if((aplist + i)->apdata->tsresponse > 0)
				{
				tvlast = (aplist + i)->apdata->tsresponse / 1000000000ULL;
				strftime(timestringresponse, TIMESTRING_LEN, "%H:%M:%S", localtime(&tvlast));
				fprintf(stdout, "%3u %s %s %4d %02x%02x%02x%02x%02x%02x %.*s\n",
				(aplist + i)->apdata->channel, timestring, timestringresponse, (s8)(aplist + i)->apdata->rtrssi,
				(aplist + i)->apdata->maca[00], (aplist + i)->apdata->maca[01], (aplist + i)->apdata->maca[02],
				(aplist + i)->apdata->maca[03],	(aplist + i)->apdata->maca[04], (aplist + i)->apdata->maca[05],
				(aplist + i)->apdata->essidlen, (aplist + i)->apdata->essid);
				}
			else
				{
				fprintf(stdout, "%3u %s          %4d %02x%02x%02x%02x%02x%02x %.*s\n",
				(aplist + i)->apdata->channel, timestring, (s8)(aplist + i)->apdata->rtrssi,
				(aplist + i)->apdata->maca[00], (aplist + i)->apdata->maca[01], (aplist + i)->apdata->maca[02],
				(aplist + i)->apdata->maca[03],	(aplist + i)->apdata->maca[04], (aplist + i)->apdata->maca[05],
				(aplist + i)->apdata->essidlen, (aplist + i)->apdata->essid);
				}
			}
		}
	}
else if(rds == 2)
	{
	qsort(aplist, APLIST_MAX, APLIST_SIZE, sort_aplist_by_rtrssi);
	for(i = 0; i < APLIST_MAX - 1; i++)
		{
		if((aplist + i)->tsakt == 0) break;
		if((scanlist + scanlistindex)->channel == (aplist + i)->apdata->channel)
			{
			tvlast = (aplist +i)->tsakt / 1000000000ULL;
			strftime(timestring, TIMESTRING_LEN, "%H:%M:%S", localtime(&tvlast));
			if((aplist + i)->apdata->tsresponse > 0)
				{
				tvlast = (aplist + i)->apdata->tsresponse / 1000000000ULL;
				strftime(timestringresponse, TIMESTRING_LEN, "%H:%M:%S", localtime(&tvlast));
				fprintf(stdout, "%3u %s %s %4d %02x%02x%02x%02x%02x%02x %.*s\n",
				(aplist + i)->apdata->channel, timestring, timestringresponse, (s8)(aplist + i)->apdata->rtrssi,
				(aplist + i)->apdata->maca[00], (aplist + i)->apdata->maca[01], (aplist + i)->apdata->maca[02],
				(aplist + i)->apdata->maca[03],	(aplist + i)->apdata->maca[04], (aplist + i)->apdata->maca[05],
				(aplist + i)->apdata->essidlen, (aplist + i)->apdata->essid);
				}
			else
				{
				fprintf(stdout, "%3u %s          %4d %02x%02x%02x%02x%02x%02x %.*s\n",
				(aplist + i)->apdata->channel, timestring, (s8)(aplist + i)->apdata->rtrssi,
				(aplist + i)->apdata->maca[00], (aplist + i)->apdata->maca[01], (aplist + i)->apdata->maca[02],
				(aplist + i)->apdata->maca[03],	(aplist + i)->apdata->maca[04], (aplist + i)->apdata->maca[05],
				(aplist + i)->apdata->essidlen, (aplist + i)->apdata->essid);
				}
			}
		}
	}
qsort(aplist, APLIST_MAX, APLIST_SIZE, sort_aplist_by_tsakt);
return;
}
/*---------------------------------------------------------------------------*/
static inline void show_realtime(void)
{
static size_t i, ii;
static time_t tvlast;
struct winsize w;

if(rdtflag == false)
	{
	if(system("clear") != 0) errorcount++;
	w.ws_row = 12;
	if(ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == -1) errorcount++;
	if(w.ws_row > 10) w.ws_row -= 4;
	ii = 0;
	}
qsort(aplist, APLIST_MAX, APLIST_SIZE, sort_aplist_by_tsakt);
qsort(calist, CALIST_MAX, CALIST_SIZE, sort_calist_by_tsakt);
fprintf(stdout, "CHA   LAST   EA123P    MAC-CL       MAC-AP    ESSID            SCAN:%6u/%u\n"
		"------------------------------------------------------------------------------\n", (scanlist + scanlistindex)->frequency, (scanlist + scanlistindex)->channel);
if(rds == 1)
	{
	for(i = 0; i < APLIST_MAX - 1; i++)
		{
		if((aplist + i)->tsakt == 0) break;
		if((scanlist + scanlistindex)->channel == (aplist + i)->apdata->channel)
			{
			tvlast = (aplist +i)->tsakt / 1000000000ULL;
			strftime(timestring, TIMESTRING_LEN, "%H:%M:%S", localtime(&tvlast));
			fprintf(stdout, "%3u %s %c%c%c%c%c%c %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %.*s\n", (aplist + i)->apdata->channel, timestring,
			(aplist + i)->apdata->privacy,
			(aplist + i)->apdata->akmstat,
			(aplist + i)->apdata->m1, (aplist + i)->apdata->m1m2, (aplist + i)->apdata->m1m2m3, (aplist + i)->apdata->pmkid,
			(aplist + i)->apdata->macc[00], (aplist + i)->apdata->macc[01], (aplist + i)->apdata->macc[02],
			(aplist + i)->apdata->macc[03],	(aplist + i)->apdata->macc[04], (aplist + i)->apdata->macc[05],
			(aplist + i)->apdata->maca[00], (aplist + i)->apdata->maca[01], (aplist + i)->apdata->maca[02],
			(aplist + i)->apdata->maca[03],	(aplist + i)->apdata->maca[04], (aplist + i)->apdata->maca[05],
			(aplist + i)->apdata->essidlen, (aplist + i)->apdata->essid);
			if(rdtflag == false)
				{
				if((ii += 1) > w.ws_row) break;
				}
			}
		}
	for(i = 0; i < CALIST_MAX - 1; i++)
		{
		if((calist + i)->tsakt == 0) break;
		if((scanlist + scanlistindex)->channel == (calist + i)->cadata->channel)
		if((calist +i)->cadata->m2 == '+')
			{
			tvlast = (calist +i)->tsakt / 1000000000ULL;
			strftime(timestring, TIMESTRING_LEN, "%H:%M:%S", localtime(&tvlast));
				fprintf(stdout, "%3u %s ep+%c   %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %.*s\n", (calist + i)->cadata->channel, timestring,
				(calist + i)->cadata->m2,
				(calist + i)->cadata->macc[00], (calist + i)->cadata->macc[01], (calist + i)->cadata->macc[02],
				(calist + i)->cadata->macc[03],	(calist + i)->cadata->macc[04], (calist + i)->cadata->macc[05],
				(calist + i)->cadata->maca[00], (calist + i)->cadata->maca[01], (calist + i)->cadata->maca[02],
				(calist + i)->cadata->maca[03],	(calist + i)->cadata->maca[04], (calist + i)->cadata->maca[05],
				(calist + i)->cadata->essidlen, (calist + i)->cadata->essid);
			if(rdtflag == false)
				{
				if((ii += 1) > w.ws_row) break;
				}
			}
		}
	}
else if(rds == 2)
	{
	for(i = 0; i < APLIST_MAX - 1; i++)
		{
		if((aplist + i)->tsakt == 0) break;
		if(((aplist +i)->apdata->m1m2 == '+') || ((aplist +i)->apdata->m1m2m3 == '+') || ((aplist +i)->apdata->pmkid == '+'))
			{
			tvlast = (aplist +i)->tsakt / 1000000000ULL;
			strftime(timestring, TIMESTRING_LEN, "%H:%M:%S", localtime(&tvlast));
				fprintf(stdout, "%3u %s %c%c%c%c%c%c %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %.*s\n", (aplist + i)->apdata->channel, timestring,
				(aplist + i)->apdata->privacy,
				(aplist + i)->apdata->akmstat,
				(aplist + i)->apdata->m1, (aplist + i)->apdata->m1m2, (aplist + i)->apdata->m1m2m3, (aplist + i)->apdata->pmkid,
				(aplist + i)->apdata->macc[00], (aplist + i)->apdata->macc[01], (aplist + i)->apdata->macc[02],
				(aplist + i)->apdata->macc[03],	(aplist + i)->apdata->macc[04], (aplist + i)->apdata->macc[05],
				(aplist + i)->apdata->maca[00], (aplist + i)->apdata->maca[01], (aplist + i)->apdata->maca[02],
				(aplist + i)->apdata->maca[03],	(aplist + i)->apdata->maca[04], (aplist + i)->apdata->maca[05],
				(aplist + i)->apdata->essidlen, (aplist + i)->apdata->essid);
			if(rdtflag == false)
				{
				if((ii += 1) > w.ws_row) break;
				}
			}
		}
	for(i = 0; i < CALIST_MAX - 1; i++)
		{
		if((calist + i)->tsakt == 0) break;
		if((calist +i)->cadata->m2 == '+')
			{
			tvlast = (calist +i)->tsakt / 1000000000ULL;
			strftime(timestring, TIMESTRING_LEN, "%H:%M:%S", localtime(&tvlast));
				fprintf(stdout, "%3u %s ep+%c   %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %.*s\n", (calist + i)->cadata->channel, timestring,
				(calist + i)->cadata->m2,
				(calist + i)->cadata->macc[00], (calist + i)->cadata->macc[01], (calist + i)->cadata->macc[02],
				(calist + i)->cadata->macc[03],	(calist + i)->cadata->macc[04], (calist + i)->cadata->macc[05],
				(calist + i)->cadata->maca[00], (calist + i)->cadata->maca[01], (calist + i)->cadata->maca[02],
				(calist + i)->cadata->maca[03],	(calist + i)->cadata->maca[04], (calist + i)->cadata->maca[05],
				(calist + i)->cadata->essidlen, (calist + i)->cadata->essid);
			if(rdtflag == false)
				{
				if((ii += 1) > w.ws_row) break;
				}
			}
		}
	}
else if(rds == 3)
	{
	for(i = 0; i < APLIST_MAX - 1; i++)
		{
		if((aplist + i)->tsakt == 0) break;
		tvlast = (aplist +i)->tsakt / 1000000000ULL;
		strftime(timestring, TIMESTRING_LEN, "%H:%M:%S", localtime(&tvlast));
			fprintf(stdout, "%3u %s %c%c%c%c%c%c %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %.*s\n", (aplist + i)->apdata->channel, timestring,
			(aplist + i)->apdata->privacy,
			(aplist + i)->apdata->akmstat,
			(aplist + i)->apdata->m1, (aplist + i)->apdata->m1m2, (aplist + i)->apdata->m1m2m3, (aplist + i)->apdata->pmkid,
			(aplist + i)->apdata->macc[00], (aplist + i)->apdata->macc[01], (aplist + i)->apdata->macc[02],
			(aplist + i)->apdata->macc[03],	(aplist + i)->apdata->macc[04], (aplist + i)->apdata->macc[05],
			(aplist + i)->apdata->maca[00], (aplist + i)->apdata->maca[01], (aplist + i)->apdata->maca[02],
			(aplist + i)->apdata->maca[03],	(aplist + i)->apdata->maca[04], (aplist + i)->apdata->maca[05],
			(aplist + i)->apdata->essidlen, (aplist + i)->apdata->essid);
			if(rdtflag == false)
				{
				if((ii += 1) > w.ws_row) break;
				}
		}
	for(i = 0; i < CALIST_MAX - 1; i++)
		{
		if((calist + i)->tsakt == 0) break;
		if((calist +i)->cadata->m2 == '+')
			{
			tvlast = (calist +i)->tsakt / 1000000000ULL;
			strftime(timestring, TIMESTRING_LEN, "%H:%M:%S", localtime(&tvlast));
				fprintf(stdout, "%3u %s ep+%c   %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %.*s\n", (calist + i)->cadata->channel, timestring,
				(calist + i)->cadata->m2,
				(calist + i)->cadata->macc[00], (calist + i)->cadata->macc[01], (calist + i)->cadata->macc[02],
				(calist + i)->cadata->macc[03],	(calist + i)->cadata->macc[04], (calist + i)->cadata->macc[05],
				(calist + i)->cadata->maca[00], (calist + i)->cadata->maca[01], (calist + i)->cadata->maca[02],
				(calist + i)->cadata->maca[03],	(calist + i)->cadata->maca[04], (calist + i)->cadata->maca[05],
				(calist + i)->cadata->essidlen, (calist + i)->cadata->essid);
			if(rdtflag == false)
				{
				if((ii += 1) > w.ws_row) break;
				}
			}
		}
	}
return;
}
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

	#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
	case NL80211_BAND_6GHZ:
	if(channel == 2) return 5935;
	if(channel <= 233) return 5950 + (channel * 5);
	break;

	case NL80211_BAND_60GHZ:
	if(channel < 7) return 56160 + (channel * 2160);
	break;

	case NL80211_BAND_S1GHZ:
	return 902000 + (channel * 500);
	#endif
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
static u16 addoption(u8 *posopt, u16 optioncode, u16 optionlen, char *option)
{
static u16 padding;
static option_header_t *optionhdr;

if (optionlen == 0) return 0;
optionhdr = (option_header_t*)posopt;
optionhdr->option_code = optioncode;
optionhdr->option_length = optionlen;
padding = (4 - (optionlen % 4)) % 4;
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
static inline void writeepbm1wpa1(void)
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
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macfrx->addr1, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr3, ETH_ALEN);
macftx->sequence = __hcx16le(seqcounter3++ << 4);
if(seqcounter1 > BCD_MAX) seqcounter3 = 1;
ii += MAC_SIZE_NORM;
memcpy(epbown + ii, eapolm1wpa1data, EAPOLM1WPA1DATA_SIZE);
ii += EAPOLM1WPA2DATA_SIZE;
epbhdr = (enhanced_packet_block_t*)epbown;
epblen = EPB_SIZE;
epbhdr->block_type = EPBID;
epbhdr->interface_id = 0;
epbhdr->cap_len = ii;
epbhdr->org_len = ii;
tsm1 = tsakt - 1;
epbhdr->timestamp_high = tsm1 >> 32;
epbhdr->timestamp_low = (u32)tsm1 & 0xffffffff;
padding = 4 - (epbhdr->cap_len % 4);
epblen += ii;
memset(epbown + epblen, 0, padding);
epblen += padding;
epblen += addoption(epbown +epblen, SHB_EOC, 0, NULL);
totallength = (total_length_t*)(epbown +epblen);
epblen += TOTAL_SIZE;
epbhdr->total_length = epblen;
totallength->total_length = epblen;
if(write(fd_pcapng, epbown, epblen) != epblen) errorcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline void writeepbm1wpa2(void)
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
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macfrx->addr1, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr3, ETH_ALEN);
macftx->sequence = __hcx16le(seqcounter3++ << 4);
if(seqcounter1 > BCD_MAX) seqcounter3 = 1;
ii += MAC_SIZE_NORM;
memcpy(epbown + ii, eapolm1wpa2data, EAPOLM1WPA2DATA_SIZE);
ii += EAPOLM1WPA2DATA_SIZE;
epbhdr = (enhanced_packet_block_t*)epbown;
epblen = EPB_SIZE;
epbhdr->block_type = EPBID;
epbhdr->interface_id = 0;
epbhdr->cap_len = ii;
epbhdr->org_len = ii;
tsm1 = tsakt - 1;
epbhdr->timestamp_high = tsm1 >> 32;
epbhdr->timestamp_low = (u32)tsm1 & 0xffffffff;
padding = (4 - (epbhdr->cap_len % 4));
epblen += ii;
memset(epbown + epblen, 0, padding);
epblen += padding;
epblen += addoption(epbown +epblen, SHB_EOC, 0, NULL);
totallength = (total_length_t*)(epbown +epblen);
epblen += TOTAL_SIZE;
epbhdr->total_length = epblen;
totallength->total_length = epblen;
if(write(fd_pcapng, epbown, epblen) != epblen) errorcount++;
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
padding = (4 - (epbhdr->cap_len % 4));
epblen += packetlen;
memset(epb + epblen, 0, padding);
epblen += padding;
epblen += addoption(epb +epblen, SHB_EOC, 0, NULL);
totallength = (total_length_t*)(epb +epblen);
epblen += TOTAL_SIZE;
epbhdr->total_length = epblen;
totallength->total_length = epblen;
if(write(fd_pcapng, epb, epblen) != epblen) errorcount++;
return;
}
/*---------------------------------------------------------------------------*/
static bool writeshb(void)
{
static ssize_t shblen;
static section_header_block_t *shbhdr;
static total_length_t *totallength;
static struct utsname unameData;
static char sysinfo[SHB_SYSINFO_LEN];
static u8 shb[PCAPNG_BLOCK_SIZE];

memset(shb, 0, PCAPNG_BLOCK_SIZE);
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
	snprintf(sysinfo, SHB_SYSINFO_LEN, "%s %s", unameData.sysname, unameData.release);
	shblen += addoption(shb +shblen, SHB_OS, strlen(sysinfo), sysinfo);
	snprintf(sysinfo, SHB_SYSINFO_LEN, "hcxdumptool %s", VERSION_TAG);
	shblen += addoption(shb +shblen, SHB_USER_APPL, strlen(sysinfo), sysinfo);
	}
shblen += addcustomoption(shb +shblen);
shblen += addoption(shb +shblen, SHB_EOC, 0, NULL);
totallength = (total_length_t*)(shb +shblen);
shblen += TOTAL_SIZE;
shbhdr->total_length = shblen;
totallength->total_length = shblen;
if(write(fd_pcapng, shb, shblen) != shblen) return false;
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

memset(idb, 0, PCAPNG_BLOCK_SIZE);
idblen = IDB_SIZE;
idbhdr = (interface_description_block_t*)idb;
idbhdr->block_type = IDBID;
idbhdr->linktype = DLT_IEEE802_11_RADIO;
idbhdr->reserved = 0;
idbhdr->snaplen = PCAPNG_SNAPLEN;
idblen += addoption(idb + idblen, IF_NAME, strnlen(ifaktname, IF_NAMESIZE), ifaktname);
idblen += addoption(idb + idblen, IF_MACADDR, 6, (char*)ifakthwmac);
tr[0] = TSRESOL_NSEC;
idblen += addoption(idb + idblen, IF_TSRESOL, 1, tr);
idblen += addoption(idb + idblen, SHB_EOC, 0, NULL);
totallength = (total_length_t*)(idb + idblen);
idblen += TOTAL_SIZE;
idbhdr->total_length = idblen;
totallength->total_length = idblen;
if(write(fd_pcapng, idb, idblen) != idblen) return false;
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

memset(cb, 0, PCAPNG_BLOCK_SIZE);
cbhdr = (custom_block_t*)cb;
cblen = CB_SIZE;
cbhdr->block_type = CBID;
cbhdr->total_length = CB_SIZE;
memcpy(cbhdr->pen, hcxmagic, 4);
memcpy(cbhdr->hcxm, hcxmagic, 32);
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
if(write(fd_pcapng, cb, cblen) != cblen) return false;
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
		snprintf(pcapngname, PATH_MAX, "%s-%s.pcapng-%02d", timestring, ifaktname, c);
		c++;
		}
	pcapngfilename = pcapngname;
	}
else
	{
	c = 0;
	snprintf(pcapngname, PATH_MAX -4, "%s", pcapngoutname);
	while(stat(pcapngname, &statinfo) == 0)
		{
		snprintf(pcapngname, PATH_MAX -4, "%s-%02d", pcapngoutname, c);
		c++;
		}
	pcapngfilename = pcapngname;
	}
umask(0);
if((fd_pcapng = open(pcapngfilename, O_WRONLY | O_TRUNC | O_CREAT, 0644)) < 0) return false;
if(writeshb() == false) return false;
if(writeidb() == false) return false;
if(writecb() == false) return false;
return true;
}
/*===========================================================================*/
/*===========================================================================*/
/* TX 802.11 */


/*===========================================================================*/
/*===========================================================================*/
/* RX 802.11 */
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static inline __attribute__((always_inline)) int get_keyinfo(u16 kyif)
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
static inline __attribute__((always_inline)) void send_80211_eap_request_id(void)
{
static ssize_t ii;

ii = RTHTX_SIZE;
macftx = (ieee80211_mac_t*)&wltxbuffer[ii];
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_DATA;
wltxbuffer[ii + 1] = 0;
macftx->from_ds = 1;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macfrx->addr1, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr3, ETH_ALEN);
macftx->sequence = 0;
ii += MAC_SIZE_NORM;
memcpy(&wltxbuffer[ii], &eaprequestiddata, EAPREQUESTID_SIZE);
ii += EAPREQUESTID_SIZE;
if(write(fd_socket_tx, &wltxbuffer, ii) == ii)	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write_80211_eap_request_id failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211eap_start(void)
{

if(macfrx->retry == 0) send_80211_eap_request_id();
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211eapol_m4(void)
{
writeepb();
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211eapol_m3(void)
{
size_t i;

for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if((aplist + i)->tsakt == 0) break;
	if(memcmp((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN) != 0) continue;
	(aplist + i)->tsakt = tsakt;
	(aplist + i)->apdata->tsm3 = tsakt;
	(aplist + i)->apdata->privacy = 'e';
	if(memcmp((aplist + i)->apdata->macc, macfrx->addr1, ETH_ALEN) != 0) break;
	if(memcmp((aplist + i)->apdata->nonce, &wpakey->nonce[28], 4) != 0) break;
	(aplist + i)->apdata->replaycount3 = __hcx64be(wpakey->replaycount);
	if(((aplist + i)->apdata->replaycount1 +1) != (aplist + i)->apdata->replaycount3) break;
	if(((aplist + i)->apdata->replaycount2 +1) != (aplist + i)->apdata->replaycount3) break;
	if(((aplist + i)->apdata->tsm3 - (aplist + i)->apdata->tsm2) > TSEAPOL1) break;
	if(((aplist + i)->apdata->tsm3 - (aplist + i)->apdata->tsm1) > TSEAPOL2) break;
	if(((aplist + i)->apdata->tsm2 - (aplist + i)->apdata->tsm1) > TSEAPOL1) break;
	wanteventflag |= exiteapolm3flag;
	(aplist + i)->apdata->m1m2m3 = '+';
	writeepb();
	return;
	}
writeepb();
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211eapol_m2(void)
{
static size_t i;
static u64 replaycount;

replaycount = __hcx64be(wpakey->replaycount);
if(replaycountrg == replaycount)
	{
	for(i = 0; i < CALIST_MAX - 1; i++)
		{
		if((calist + i)->tsakt == 0) return;
		if(memcmp((calist + i)->cadata->maca, macfrx->addr1, ETH_ALEN) != 0) continue;
		if(memcmp((calist + i)->cadata->macc, macfrx->addr2, ETH_ALEN) != 0) continue;
		(calist + i)->tsakt = tsakt;
			{
			if(memcmp((calist + i)->cadata->mic, wpakey->keymic, KEYMIC_MAX) == 0) return;
			memcpy((calist + i)->cadata->mic, wpakey->keymic, KEYMIC_MAX);
			(calist + i)->cadata->clientcount -= 1;
			(calist + i)->cadata->m2 = '+';
			(calist + i)->cadata->channel = (scanlist + scanlistindex)->channel;
			wanteventflag |= exiteapolm2rgflag;
			if((calist + i)->cadata->akm == RSNPSK) writeepbm1wpa2();
			else if((calist + i)->cadata->akm == WPAPSK) writeepbm1wpa1();
			writeepb();
			}
		if(i > CALIST_HALF) qsort(calist, i + 1, CALIST_SIZE, sort_calist_by_tsakt);
		return;
		}
	return;
	}
for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if((aplist + i)->tsakt == 0) break;
	if(memcmp((aplist + i)->apdata->maca, macfrx->addr1, ETH_ALEN) != 0) continue;
	(aplist + i)->tsakt = tsakt;
	(aplist + i)->apdata->tsm2 = tsakt;
	if(memcmp((aplist + i)->apdata->macc, macfrx->addr2, ETH_ALEN) != 0) break;
	(aplist + i)->apdata->replaycount2 = __hcx64be(wpakey->replaycount);
	if(((aplist + i)->apdata->replaycount1) != (aplist + i)->apdata->replaycount2) break;
	if(((aplist + i)->apdata->tsm2 - (aplist + i)->apdata->tsm1) > TSEAPOL1) break;
	(aplist + i)->apdata->m1m2 = '+';
	wanteventflag |= exiteapolm2flag;
	writeepb();
	return;
	}
writeepb();
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211eapol_m1(void)
{
static size_t i;
static ieee80211_pmkid_t *pmkid;

if(memcmp(macbc, macfrx->addr1, ETH_ALEN) == 0)
	{
	writeepb();
	return;
	}
for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if((aplist + i)->tsakt == 0) break;
	if(memcmp((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN) != 0) continue;
	(aplist + i)->tsakt = tsakt;
	(aplist + i)->apdata->tsm1 = tsakt;
	(aplist + i)->apdata->m1 = '+';
	(aplist + i)->apdata->privacy = 'e';
	wanteventflag |= exiteapolm1flag;
	if(memcmp(macclientrg, (aplist + i)->apdata->macc, ETH_ALEN) == 0) (aplist + i)->apdata->apcount = apcountmax;
	memcpy((aplist + i)->apdata->macc, macfrx->addr1, ETH_ALEN);
	(aplist + i)->apdata->replaycount1 = __hcx64be(wpakey->replaycount);
	memcpy((aplist + i)->apdata->nonce, &wpakey->nonce[28], 4);
	if(wpakey->wpadatalen >= IEEE80211_PMKID_SIZE)
		{
		pmkid = (ieee80211_pmkid_t*)wpakey->data;
		if(pmkid->tag == TAG_VENDOR)
			{
			if(pmkid->len != IEEE80211_PMKID_SIZE)
				{
				if(memcmp(rsnpmkid, pmkid->pmkoui, SUITE_SIZE) == 0)
					{
					if(memcmp(zeroed, pmkid->pmkid, PMKID_MAX) != 0)
						{
						if((aplist + i)->apdata->essidlen != 0) (aplist + i)->apdata->pmkid = '+';
						memcpy((aplist + i)->apdata->rsnpmkid, pmkid->pmkid, PMKID_MAX);
						wanteventflag |= exiteapolpmkidflag;
						}
					}
				}
			}
		}
	writeepb();
	return;
	}
writeepb();
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211eapol(void)
{
eapolplptr = eapauthplptr + IEEE80211_EAPAUTH_SIZE;
eapolpllen = eapauthpllen - IEEE80211_EAPAUTH_SIZE;
if((eapolpllen + IEEE80211_EAPAUTH_SIZE + IEEE80211_LLC_SIZE) > payloadlen) return;
wpakey = (ieee80211_wpakey_t*)eapolplptr;
if((kdv = __hcx16be(wpakey->keyinfo) & WPA_KEY_INFO_TYPE_MASK) == 0)
	{
	writeepb();
	return;
	}
keyinfo = (get_keyinfo(__hcx16be(wpakey->keyinfo)));
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
	process80211eapol_m4();
	break;
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211eapauthentication(void)
{
eapauthplptr = payloadptr + IEEE80211_LLC_SIZE;
eapauthpllen = payloadlen - IEEE80211_LLC_SIZE;
eapauth = (ieee80211_eapauth_t*)eapauthplptr;
eapauthlen = __hcx16be(eapauth->len);
if(eapauthlen > (eapauthpllen - IEEE80211_EAPAUTH_SIZE)) return;
if(eapauth->type == EAPOL_KEY) process80211eapol();
else if(eapauth->type == EAPOL_START) process80211eap_start();
else if(eapauth->type == EAP_PACKET) writeepb();
else if(eapauth->type > EAPOL_KEY) writeepb();
return;
}
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static inline void send_80211_ack(void)
{
macftx = (ieee80211_mac_t*)&wltxbuffer[RTHTX_SIZE];
macftx->type = IEEE80211_FTYPE_CTL;
macftx->subtype = IEEE80211_STYPE_ACK;
macftx->duration = 0;
wltxbuffer[RTHTX_SIZE + 1] = 0;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
if((write(fd_socket_tx, wltxbuffer, RTHTX_SIZE + MAC_SIZE_ACK)) == RTHTX_SIZE + MAC_SIZE_ACK)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write_80211_ack failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_80211_null(void)
{
macftx = (ieee80211_mac_t*)&wltxbuffer[RTHTX_SIZE];
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_NULLFUNC;
wltxbuffer[RTHTX_SIZE +1] = 0;
macftx->to_ds = 1;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macfrx->addr1, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr2, ETH_ALEN);
macftx->sequence = __hcx16le(seqcounter1++ << 4);
if(seqcounter1 > BCD_MAX) seqcounter1 = 1;
if((write(fd_socket_tx, wltxbuffer, RTHTX_SIZE + MAC_SIZE_NORM +2)) == RTHTX_SIZE + MAC_SIZE_NORM +2)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write_80211_null failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_80211_associationrequest2bc(apdata_t *apdata)
{
ssize_t ii;

ii = RTHTX_SIZE;
macftx = (ieee80211_mac_t*)&wltxbuffer[ii];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
wltxbuffer[ii + 1] = 0;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, apdata->maca, ETH_ALEN);
memcpy(macftx->addr2, macbc, ETH_ALEN);
memcpy(macftx->addr3, apdata->maca, ETH_ALEN);
macftx->sequence = __hcx16le(seqcounter2++ << 4);
if(seqcounter1 > 4095) seqcounter2 = 1;
ii += MAC_SIZE_NORM;
memcpy(&wltxbuffer[ii], &associationrequestcapa, ASSOCIATIONREQUESTCAPA_SIZE);
ii += ASSOCIATIONREQUESTCAPA_SIZE;
wltxbuffer[ii ++] = 0;
wltxbuffer[ii ++] = apdata->essidlen;
memcpy(&wltxbuffer[ii], apdata->essid, apdata->essidlen);
ii += apdata->essidlen;
memcpy(&wltxbuffer[ii], &associationrequestdata, ASSOCIATIONREQUEST_SIZE);
wltxbuffer[ii +OFFSETGCS] = apdata->gcs;
wltxbuffer[ii +OFFSETPCS] = apdata->pcs;
wltxbuffer[ii +OFFSETAKM] = apdata->akm;
ii += ASSOCIATIONREQUEST_SIZE;
if((write(fd_socket_tx, &wltxbuffer, ii)) == ii)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write associationrequest failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_80211_associationrequest2rg(apdata_t *apdata)
{
ssize_t ii;

ii = RTHTX_SIZE;
macftx = (ieee80211_mac_t*)&wltxbuffer[ii];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
wltxbuffer[ii + 1] = 0;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, apdata->maca, ETH_ALEN);
memcpy(macftx->addr2, macclientrg, ETH_ALEN);
memcpy(macftx->addr3, apdata->maca, ETH_ALEN);
macftx->sequence = __hcx16le(seqcounter2++ << 4);
if(seqcounter1 > 4095) seqcounter2 = 1;
ii += MAC_SIZE_NORM;
memcpy(&wltxbuffer[ii], &associationrequestcapa, ASSOCIATIONREQUESTCAPA_SIZE);
ii += ASSOCIATIONREQUESTCAPA_SIZE;
wltxbuffer[ii ++] = 0;
wltxbuffer[ii ++] = apdata->essidlen;
memcpy(&wltxbuffer[ii], apdata->essid, apdata->essidlen);
ii += apdata->essidlen;
memcpy(&wltxbuffer[ii], &associationrequestdata, ASSOCIATIONREQUEST_SIZE);
wltxbuffer[ii +OFFSETGCS] = apdata->gcs;
wltxbuffer[ii +OFFSETPCS] = apdata->pcs;
wltxbuffer[ii +OFFSETAKM] = apdata->akm;
ii += ASSOCIATIONREQUEST_SIZE;
if((write(fd_socket_tx, &wltxbuffer, ii)) == ii)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write associationrequest failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_80211_associationrequest2(apdata_t *apdata)
{
ssize_t ii;

ii = RTHTX_SIZE;
macftx = (ieee80211_mac_t*)&wltxbuffer[ii];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
wltxbuffer[ii + 1] = 0;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, apdata->maca, ETH_ALEN);
memcpy(macftx->addr2, apdata->macc, ETH_ALEN);
memcpy(macftx->addr3, apdata->maca, ETH_ALEN);
macftx->sequence = __hcx16le(seqcounter2++ << 4);
if(seqcounter1 > 4095) seqcounter2 = 1;
ii += MAC_SIZE_NORM;
memcpy(&wltxbuffer[ii], &associationrequestcapa, ASSOCIATIONREQUESTCAPA_SIZE);
ii += ASSOCIATIONREQUESTCAPA_SIZE;
wltxbuffer[ii ++] = 0;
wltxbuffer[ii ++] = apdata->essidlen;
memcpy(&wltxbuffer[ii], apdata->essid, apdata->essidlen);
ii += apdata->essidlen;
memcpy(&wltxbuffer[ii], &associationrequestdata, ASSOCIATIONREQUEST_SIZE);
wltxbuffer[ii +OFFSETGCS] = apdata->gcs;
wltxbuffer[ii +OFFSETPCS] = apdata->pcs;
wltxbuffer[ii +OFFSETAKM] = apdata->akm;
ii += ASSOCIATIONREQUEST_SIZE;
if((write(fd_socket_tx, &wltxbuffer, ii)) == ii)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write associationrequest failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_80211_authenticationrequest(apdata_t *apdata)
{
macftx = (ieee80211_mac_t*)&wltxbuffer[RTHTX_SIZE];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_AUTH;
wltxbuffer[RTHTX_SIZE + 1] = 0;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, apdata->macc, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr3, ETH_ALEN);
macftx->sequence = __hcx16le(seqcounter2++ << 4);
if(seqcounter1 > 4095) seqcounter2 = 1;
memcpy(&wltxbuffer[RTHTX_SIZE + MAC_SIZE_NORM], &authenticationrequestdata, AUTHENTICATIONREQUEST_SIZE);
if((write(fd_socket_tx, &wltxbuffer, RTHTX_SIZE + MAC_SIZE_NORM + AUTHENTICATIONREQUEST_SIZE)) == RTHTX_SIZE + MAC_SIZE_NORM + AUTHENTICATIONREQUEST_SIZE)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write_80211_authenticationrequest failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_80211_authenticationrequestrg(void)
{
macftx = (ieee80211_mac_t*)&wltxbuffer[RTHTX_SIZE];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_AUTH;
wltxbuffer[RTHTX_SIZE + 1] = 0;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macclientrg, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr3, ETH_ALEN);
macftx->sequence = __hcx16le(seqcounter2++ << 4);
if(seqcounter1 > 4095) seqcounter2 = 1;
memcpy(&wltxbuffer[RTHTX_SIZE + MAC_SIZE_NORM], &authenticationrequestdata, AUTHENTICATIONREQUEST_SIZE);
if((write(fd_socket_tx, &wltxbuffer, RTHTX_SIZE + MAC_SIZE_NORM + AUTHENTICATIONREQUEST_SIZE)) == RTHTX_SIZE + MAC_SIZE_NORM + AUTHENTICATIONREQUEST_SIZE)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write_80211_authenticationrequest failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_80211_disassociationaca(u8 *fmcl, u8 *toap)
{
macftx = (ieee80211_mac_t*)&wltxbuffer[RTHTX_SIZE];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DISASSOC;
wltxbuffer[RTHTX_SIZE +1] = 0;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, toap, ETH_ALEN);
memcpy(macftx->addr2, fmcl, ETH_ALEN);
memcpy(macftx->addr3, toap, ETH_ALEN);
macftx->sequence = __hcx16le(seqcounter1++ << 4);
if(seqcounter1 > BCD_MAX) seqcounter1 = 1;
wltxbuffer[RTHTX_SIZE + MAC_SIZE_NORM] = WLAN_REASON_DISASSOC_STA_HAS_LEFT;
wltxbuffer[RTHTX_SIZE + MAC_SIZE_NORM +1] = 0;
if((write(fd_socket_tx, wltxbuffer, RTHTX_SIZE + MAC_SIZE_NORM +2)) == RTHTX_SIZE + MAC_SIZE_NORM +2)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write_80211_disassociation121 failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_80211_disassociationcaa(u8 *tocl, u8 *fmap)
{
macftx = (ieee80211_mac_t*)&wltxbuffer[RTHTX_SIZE];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DISASSOC;
wltxbuffer[RTHTX_SIZE +1] = 0;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, tocl, ETH_ALEN);
memcpy(macftx->addr2, fmap, ETH_ALEN);
memcpy(macftx->addr3, fmap, ETH_ALEN);
macftx->sequence = __hcx16le(seqcounter1++ << 4);
if(seqcounter1 > BCD_MAX) seqcounter1 = 1;
wltxbuffer[RTHTX_SIZE + MAC_SIZE_NORM] = WLAN_REASON_DISASSOC_STA_HAS_LEFT;
wltxbuffer[RTHTX_SIZE + MAC_SIZE_NORM +1] = 0;
if((write(fd_socket_tx, wltxbuffer, RTHTX_SIZE + MAC_SIZE_NORM +2)) == RTHTX_SIZE + MAC_SIZE_NORM +2)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write_80211_disassociation211 failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*---------------------------------------------------------------------------*/
/*
static inline __attribute__((always_inline)) void send_80211_authenticationrequestaca(u8 *fmcl, u8 *toap)
{
macftx = (ieee80211_mac_t*)&wltxbuffer[RTHTX_SIZE];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_AUTH;
wltxbuffer[RTHTX_SIZE + 1] = 0;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, toap, ETH_ALEN);
memcpy(macftx->addr2, fmcl, ETH_ALEN);
memcpy(macftx->addr3, toap, ETH_ALEN);
macftx->sequence = __hcx16le(seqcounter2++ << 4);
if(seqcounter1 > BCD_MAX) seqcounter2 = 1;
memcpy(wltxbuffer + RTHTX_SIZE + MAC_SIZE_NORM, authenticationrequestdata, AUTHENTICATIONREQUEST_SIZE);
if((write(fd_socket_tx, wltxbuffer, RTHTX_SIZE + MAC_SIZE_NORM + AUTHENTICATIONREQUEST_SIZE)) == RTHTX_SIZE + MAC_SIZE_NORM + AUTHENTICATIONREQUEST_SIZE)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write_80211_authenticationrequest212 failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
*/
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static inline __attribute__((always_inline)) void send_80211_eapol_m1_wpa1(void)
{
static ssize_t ii;

ii = RTHTX_SIZE;
macftx = (ieee80211_mac_t*)&wltxbuffer[ii];
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_DATA;
wltxbuffer[ii + 1] = 0;
macftx->from_ds = 1;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macfrx->addr1, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr1, ETH_ALEN);
macftx->sequence = 0;
ii += MAC_SIZE_NORM;
memcpy(wltxbuffer + ii, eapolm1wpa1data, EAPOLM1WPA1DATA_SIZE);
ii += EAPOLM1WPA1DATA_SIZE;
if(write(fd_socket_tx, wltxbuffer, ii) == ii)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write_80211_eapol_m1_wpa1 failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_80211_eapol_m1_wpa2(void)
{
static ssize_t ii;

ii = RTHTX_SIZE;
macftx = (ieee80211_mac_t*)&wltxbuffer[ii];
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_DATA;
wltxbuffer[ii + 1] = 0;
macftx->from_ds = 1;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macfrx->addr1, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr1, ETH_ALEN);
macftx->sequence = 0;
ii += MAC_SIZE_NORM;
memcpy(wltxbuffer + ii, eapolm1wpa2data, EAPOLM1WPA2DATA_SIZE);
ii += EAPOLM1WPA2DATA_SIZE;
if(write(fd_socket_tx, wltxbuffer, ii) == ii)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write_80211_eapol_m1_wpa2 failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static inline __attribute__((always_inline)) void process80211rata(void)
{
size_t i;

for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if((aplist + i)->tsakt == 0) break;
	if(memcmp((aplist + i)->apdata->maca, macfrx->addr1, ETH_ALEN) == 0)
		{
		(aplist + i)->apdata->tsmacc = tsakt;
		if(memcmp(macclientrg, (aplist + i)->apdata->macc, ETH_ALEN) == 0) (aplist + i)->apdata->apcount = apcountmax;
		memcpy((aplist + i)->apdata->macc, macfrx->addr2, ETH_ALEN);
		return;
		}
	}
for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if((aplist + i)->tsakt == 0) return;
	if(memcmp((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN) == 0)
		{
		(aplist + i)->tsakt = tsakt;
		if(memcmp(macclientrg, (aplist + i)->apdata->macc, ETH_ALEN) == 0) (aplist + i)->apdata->apcount = apcountmax;
		memcpy((aplist + i)->apdata->macc, macfrx->addr1, ETH_ALEN);
		return;
		}
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211reassociationresponse(void)
{
static size_t i;
static ieee80211_assoc_or_reassoc_resp_t *capa;

if(memcmp(macbc, macfrx->addr1, ETH_ALEN) == 0)
	{
	writeepb();
	return;
	}
capa = (ieee80211_assoc_or_reassoc_resp_t*)payloadptr;
if(payloadlen < IEEE80211_REASSOCIATIONRESPONSE_SIZE) return;
for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if((aplist + i)->tsakt == 0) break;
	if(memcmp((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN) != 0) continue;
	(aplist + i)->tsakt = tsakt;
	(aplist + i)->apdata->aid = __hcx16le(capa->aid);
	if(memcmp(macclientrg, (aplist + i)->apdata->macc, ETH_ALEN) == 0) (aplist + i)->apdata->apcount = apcountmax;
	memcpy((aplist + i)->apdata->macc, macfrx->addr1, ETH_ALEN);
	if((aplist + i)->apdata->apcount <= 0) return;
	if((aplist + i)->apdata->essidlen == 0) return;
	if(((aplist + i)->apdata->akm != AKMPSK) && ((aplist + i)->apdata->akm != AKMPSK256)) return;
	if((aplist + i)->apdata->m1 == '+') return;
	if((tsakt - (aplist + i)->apdata->tsreassocresponse) < TSSECOND05) return;
	send_80211_ack();
	send_80211_null();
	(aplist + i)->apdata->tsreassocresponse = tsakt;
	(aplist + i)->apdata->apcount -= 1;
	if((aplist + i)->apdata->reassociationresponse == false)
		{
		(aplist + i)->apdata->reassociationresponse = true;
		writeepb();
		}
	return;
	}
(aplist + i)->tsakt = tsakt;
memset((aplist + i)->apdata, 0, APDATA_SIZE);
(aplist + i)->apdata->channel = (scanlist + scanlistindex)->channel;
(aplist + i)->apdata->pmkid = ' ';
(aplist + i)->apdata->m1 = ' ';
(aplist + i)->apdata->m1m2 = ' ';
(aplist + i)->apdata->m1m2m3 = ' ';
(aplist + i)->apdata->pmkid = ' ';
(aplist + i)->apdata->akmstat = ' ';
(aplist + i)->apdata->apcount = apcountmax;
(aplist + i)->apdata->reassociationresponse = true;
(aplist + i)->apdata->aid = __hcx16le(capa->aid);
memcpy((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN);
memcpy((aplist + i)->apdata->macc, macfrx->addr1, ETH_ALEN);
qsort(aplist, i + 1, APLIST_SIZE, sort_aplist_by_tsakt);
writeepb();

return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211associationresponse(void)
{
static size_t i;
static ieee80211_assoc_or_reassoc_resp_t *capa;

if(memcmp(macbc, macfrx->addr1, ETH_ALEN) == 0)
	{
	writeepb();
	return;
	}
capa = (ieee80211_assoc_or_reassoc_resp_t*)payloadptr;
if(payloadlen < IEEE80211_ASSOCIATIONRESPONSE_SIZE) return;
for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if((aplist + i)->tsakt == 0) break;
	if(memcmp((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN) != 0) continue;
	(aplist + i)->tsakt = tsakt;
	(aplist + i)->apdata->aid = __hcx16le(capa->aid);
	if(memcmp(macclientrg, (aplist + i)->apdata->macc, ETH_ALEN) == 0) (aplist + i)->apdata->apcount = apcountmax;
	memcpy((aplist + i)->apdata->macc, macfrx->addr1, ETH_ALEN);
	if((aplist + i)->apdata->apcount <= 0) return;
	if((aplist + i)->apdata->essidlen == 0) return;
	if(((aplist + i)->apdata->akm != AKMPSK) && ((aplist + i)->apdata->akm != AKMPSK256)) return;
	if((aplist + i)->apdata->m1 == '+') return;
	if((tsakt - (aplist + i)->apdata->tsassocresponse) < TSSECOND05) return;
	send_80211_ack();
	send_80211_null();
	(aplist + i)->apdata->tsassocresponse = tsakt;
	(aplist + i)->apdata->apcount -= 1;
	if((aplist + i)->apdata->associationresponse == false)
		{
		(aplist + i)->apdata->associationresponse = true;
		writeepb();
		}
	return;
	}
(aplist + i)->tsakt = tsakt;
memset((aplist + i)->apdata, 0, APDATA_SIZE);
(aplist + i)->apdata->channel = (scanlist + scanlistindex)->channel;
(aplist + i)->apdata->pmkid = ' ';
(aplist + i)->apdata->m1 = ' ';
(aplist + i)->apdata->m1m2 = ' ';
(aplist + i)->apdata->m1m2m3 = ' ';
(aplist + i)->apdata->pmkid = ' ';
(aplist + i)->apdata->akmstat = ' ';
(aplist + i)->apdata->apcount = apcountmax;
(aplist + i)->apdata->associationresponse = true;
(aplist + i)->apdata->aid = __hcx16le(capa->aid);
memcpy((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN);
memcpy((aplist + i)->apdata->macc, macfrx->addr1, ETH_ALEN);
qsort(aplist, i + 1, APLIST_SIZE, sort_aplist_by_tsakt);
writeepb();
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211qosnull(void)
{
size_t i;

if((macfrx->to_ds == 1) && (macfrx->power == 0))
	{
	for(i = 0; i < CALIST_MAX - 1; i++)
		{
		if((calist + i)->tsakt == 0) break;
		if(memcmp((calist + i)->cadata->maca, macfrx->addr1, ETH_ALEN) != 0) continue;
		if(memcmp((calist + i)->cadata->macc, macfrx->addr2, ETH_ALEN) != 0) continue;
		if((calist + i)->cadata->clientcount <= 0) return;
		(calist + i)->tsakt = tsakt;
		if(macfrx->retry == 0)
			{
			if((tsakt - (calist + i)->cadata->tsassoc) > TSSECOND2) break;
			(calist + i)->cadata->tsnull = tsakt;
			(calist + i)->cadata->channel = (scanlist + scanlistindex)->channel;
			if((calist + i)->cadata->akm == RSNPSK)
				{
				send_80211_ack();
				send_80211_eapol_m1_wpa2();
				}
			else if((calist + i)->cadata->akm == WPAPSK)
				{
				send_80211_ack();
				send_80211_eapol_m1_wpa1();
				}
			}
		if(i > CALIST_HALF) qsort(calist, i + 1, CALIST_SIZE, sort_calist_by_tsakt);
		}
	}
if(macfrx->from_ds == 1)
	{
	for(i = 0; i < APLIST_MAX - 1; i++)
		{
		if((aplist + i)->tsakt == 0) break;
			{
			if(memcmp((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN) == 0)
				{
				(aplist + i)->tsakt = tsakt;
				if(memcmp(macclientrg, (aplist + i)->apdata->macc, ETH_ALEN) == 0) (aplist + i)->apdata->apcount = apcountmax;
				memcpy((aplist + i)->apdata->macc, macfrx->addr1, ETH_ALEN);
				return;
				}
			}
		}
	}
if(macfrx->from_ds == 1)
	{
	for(i = 0; i < APLIST_MAX - 1; i++)
		{
		if((aplist + i)->tsakt == 0) break;
			{
			if(memcmp((aplist + i)->apdata->maca, macfrx->addr1, ETH_ALEN) == 0)
				{
				(aplist + i)->apdata->tsmacc = tsakt;
				memcpy((aplist + i)->apdata->macc, macfrx->addr2, ETH_ALEN);
				return;
				}
			}
		}
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211null(void)
{
size_t i;

if((macfrx->to_ds == 1) && (macfrx->power == 0))
	{
	for(i = 0; i < CALIST_MAX - 1; i++)
		{
		if((calist + i)->tsakt == 0) break;
		if(memcmp((calist + i)->cadata->maca, macfrx->addr1, ETH_ALEN) != 0) continue;
		if(memcmp((calist + i)->cadata->macc, macfrx->addr2, ETH_ALEN) != 0) continue;
		(calist + i)->tsakt = tsakt;
		(calist + i)->cadata->channel = (scanlist + scanlistindex)->channel;
		if((calist + i)->cadata->clientcount <= 0) return;
		if((tsakt - (calist + i)->cadata->tsnull) <= TSSECOND1) return;
		if((tsakt - (calist + i)->cadata->tsnull) > TSSECOND2) break;
		if((calist + i)->cadata->akm == RSNPSK)
			{
			send_80211_ack();
			send_80211_eapol_m1_wpa2();
			(calist + i)->cadata->tsnull = tsakt;
			}
		else if((calist + i)->cadata->akm == WPAPSK)
			{
			send_80211_ack();
			send_80211_eapol_m1_wpa1();
			(calist + i)->cadata->tsnull = tsakt;
			}
		if(i > CALIST_HALF) qsort(calist, i + 1, CALIST_SIZE, sort_calist_by_tsakt);
		}
	}
if(macfrx->from_ds == 1)
	{
	for(i = 0; i < APLIST_MAX - 1; i++)
		{
		if((aplist + i)->tsakt == 0) break;
			{
			if(memcmp((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN) == 0)
				{
				(aplist + i)->tsakt = tsakt;
				if(memcmp(macclientrg, (aplist + i)->apdata->macc, ETH_ALEN) == 0) (aplist + i)->apdata->apcount = apcountmax;
				memcpy((aplist + i)->apdata->macc, macfrx->addr1, ETH_ALEN);
				return;
				}
			}
		}
	}
if(macfrx->to_ds == 1)
	{
	for(i = 0; i < APLIST_MAX - 1; i++)
		{
		if((aplist + i)->tsakt == 0) break;
			{
			if(memcmp((aplist + i)->apdata->maca, macfrx->addr1, ETH_ALEN) == 0)
				{
				(aplist + i)->apdata->tsmacc = tsakt;
				memcpy((aplist + i)->apdata->macc, macfrx->addr2, ETH_ALEN);
				return;
				}
			}
		}
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_80211_reassociationresponse(void)
{
static ssize_t ii;
static ieee80211_assoc_or_reassoc_resp_t *associationresponsetx;

ii = RTHTX_SIZE;
macftx = (ieee80211_mac_t*)&wltxbuffer[ii];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_REASSOC_RESP;
wltxbuffer[ii + 1] = 0;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macfrx->addr1, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr3, ETH_ALEN);
macftx->sequence = __hcx16le(seqcounter3++ << 4);
if(seqcounter1 > BCD_MAX) seqcounter3 = 1;
ii += MAC_SIZE_NORM;
associationresponsetx = (ieee80211_assoc_or_reassoc_resp_t*)&wltxbuffer[ii];
associationresponsetx->capability = HCXTXCAPABILITY;
associationresponsetx->status = 0;
associationresponsetx->aid = HCXTXAID;
ii += IEEE80211_REASSOCIATIONRESPONSE_SIZE;
memcpy(wltxbuffer + ii, associationresponsedata, ASSOCIATIONRESPONSEDATA_SIZE);
ii += ASSOCIATIONRESPONSEDATA_SIZE;
if(write(fd_socket_tx, wltxbuffer, ii) == ii)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write_80211_reassociationresponse failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) u8 get_akm(cadata_t *cadata, int infolen, u8 *infostart)
{
static ieee80211_ietag_t *infoptr;
static ieee80211_suite_t *rsn;
static ieee80211_suite_t *wpa;
while(0 < infolen)
	{
	infoptr = (ieee80211_ietag_t*)infostart;
	if(infolen < (int)(infoptr->len + IEEE80211_IETAG_SIZE)) return 0;
	if(infoptr->id == TAG_SSID)
		{
		if((infoptr->len > 0) && (infoptr->len <= ESSID_MAX))
			{
			cadata->essidlen = infoptr->len;
			memcpy(cadata->essid, infoptr->ie, cadata->essidlen);
			}
		}
	if(infoptr->id == TAG_RSN)
		{
		if(infoptr->len >= RSNLEN_MIN)
			{
			rsn = (ieee80211_suite_t*)infoptr->ie;
			if(__hcx16le(rsn->count) == 1) rsn += 1;
			if(__hcx16le(rsn->count) == 1) rsn += 1;
			if(memcmp(rsnpsk, rsn->suite, SUITE_SIZE) == 0) return RSNPSK;
			else if(memcmp(rsnpskft, rsn->suite, SUITE_SIZE) == 0) return RSNPSKFT;
			else if(memcmp(rsnpsk256, rsn->suite, SUITE_SIZE) == 0) return RSNPSK256;
			return 0;
			}
		}
	if(infoptr->id == TAG_VENDOR)
		{
		if(infoptr->len >= WPALEN_MIN)
			{
			if(memcmp(wpatype, infoptr->ie, SUITE_SIZE) == 0)
				{
				wpa = (ieee80211_suite_t*)(infoptr->ie +4);
				if(__hcx16le(wpa->count) == 1) wpa += 1;
				if(__hcx16le(wpa->count) == 1) wpa += 1;
				if(memcmp(wpapsk, wpa->suite, SUITE_SIZE) == 0) return WPAPSK;
				return 0;
				}
			}
		}
	infostart += infoptr->len + IEEE80211_IETAG_SIZE;
	infolen -= infoptr->len + IEEE80211_IETAG_SIZE;
	}
return 0;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) ieee80211_ietag_t* get_tag(u8 ietag, int infolen, u8 *infostart)
{
static ieee80211_ietag_t *infoptr;

while(0 < infolen)
	{
	infoptr = (ieee80211_ietag_t*)infostart;
	if(infolen < (int)(infoptr->len + IEEE80211_IETAG_SIZE)) return NULL;
	if(infoptr->id == ietag) return infoptr;
	infostart += infoptr->len + IEEE80211_IETAG_SIZE;
	infolen -= infoptr->len + IEEE80211_IETAG_SIZE;
	}
return NULL;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void get_tag_channel(apdata_t *apdata, int infolen, u8 *infostart)
{
static ieee80211_ietag_t *infoptr;

apdata->channel = (scanlist + scanlistindex)->channel;
while(0 < infolen)
	{
	infoptr = (ieee80211_ietag_t*)infostart;
	if(infolen < (int)(infoptr->len + IEEE80211_IETAG_SIZE)) return;
	if(infoptr->id == TAG_CHAN)
		{
		if(infoptr->len == 1) apdata->channel = (u8)infoptr->ie[0];
		return;
		}
	infostart += infoptr->len + IEEE80211_IETAG_SIZE;
	infolen -= infoptr->len + IEEE80211_IETAG_SIZE;
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211reassociationrequest(void)
{
static size_t i;
static ieee80211_reassoc_req_t *reassociationrequest;
static u16 reassociationrequestlen;

reassociationrequest = (ieee80211_reassoc_req_t*)payloadptr;
if((reassociationrequestlen = payloadlen - IEEE80211_REASSOCIATIONREQUEST_SIZE) < IEEE80211_IETAG_SIZE) return;
for(i = 0; i < CALIST_MAX - 1; i++)
	{
	if((calist + i)->tsakt == 0) break;
	if(memcmp((calist + i)->cadata->maca, macfrx->addr1, ETH_ALEN) != 0) continue;
	if(memcmp((calist + i)->cadata->macc, macfrx->addr2, ETH_ALEN) != 0) continue;
	(calist + i)->tsakt = tsakt;
	(calist + i)->cadata->channel = (scanlist + scanlistindex)->channel;
	if((calist + i)->cadata->clientcount <= 0) return;
	if((tsakt - (calist + i)->cadata->tsreassoc) < TSSECOND1) return;
	(calist + i)->cadata->akm = get_akm((calist + i)->cadata, reassociationrequestlen, reassociationrequest->ie);
	if((calist + i)->cadata->akm == RSNPSK)
		{
		send_80211_ack();
		send_80211_reassociationresponse();
		nanosleep(&tsremain, &tsreq);
		send_80211_eapol_m1_wpa2();
		(calist + i)->cadata->tsreassoc = tsakt;
		}
	else if((calist + i)->cadata->akm == WPAPSK)
		{
		send_80211_ack();
		send_80211_reassociationresponse();
		nanosleep(&tsremain, &tsreq);
		send_80211_eapol_m1_wpa1();
		(calist + i)->cadata->tsreassoc = tsakt;
		}
	if(i > CALIST_HALF) qsort(calist, i + 1, CALIST_SIZE, sort_calist_by_tsakt);
	writeepb();
	return;
	}
(calist + i)->tsakt = tsakt;
memset((calist + i)->cadata, 0, CADATA_SIZE);
(calist + i)->cadata->channel = (scanlist + scanlistindex)->channel;
(calist + i)->cadata->m2 = ' ';
(calist + i)->cadata->clientcount = clientcountmax;
memcpy((calist + i)->cadata->maca, macfrx->addr1, ETH_ALEN);
memcpy((calist + i)->cadata->macc, macfrx->addr2, ETH_ALEN);
if(clientcountmax > 0)
	{
	(calist + i)->cadata->akm = get_akm((calist + i)->cadata, reassociationrequestlen, reassociationrequest->ie);
	if((calist + i)->cadata->akm == RSNPSK)
		{
		send_80211_ack();
		send_80211_reassociationresponse();
		nanosleep(&tsremain, &tsreq);
		send_80211_eapol_m1_wpa2();
		(calist + i)->cadata->tsreassoc = tsakt;
		}
	else if((calist + i)->cadata->akm == WPAPSK)
		{
		send_80211_ack();
		send_80211_reassociationresponse();
		nanosleep(&tsremain, &tsreq);
		send_80211_eapol_m1_wpa1();
		(calist + i)->cadata->tsreassoc = tsakt;
		}
	}
qsort(calist, i + 1, CALIST_SIZE, sort_calist_by_tsakt);
writeepb();
return;
}
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static inline __attribute__((always_inline)) void send_80211_associationresponse(void)
{
static ssize_t ii;
static ieee80211_assoc_or_reassoc_resp_t *associationresponsetx;

ii = RTHTX_SIZE;
macftx = (ieee80211_mac_t*)&wltxbuffer[ii];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_RESP;
wltxbuffer[ii + 1] = 0;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macfrx->addr1, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr3, ETH_ALEN);
macftx->sequence = __hcx16le(seqcounter1++ << 4);
if(seqcounter1 > BCD_MAX) seqcounter1 = 1;
ii += MAC_SIZE_NORM;
associationresponsetx = (ieee80211_assoc_or_reassoc_resp_t*)&wltxbuffer[ii];
associationresponsetx->capability = HCXTXCAPABILITY;
associationresponsetx->status = 0;
associationresponsetx->aid = HCXTXAID;
ii += IEEE80211_ASSOCIATIONRESPONSE_SIZE;
memcpy(wltxbuffer + ii, associationresponsedata, ASSOCIATIONRESPONSEDATA_SIZE);
ii += ASSOCIATIONRESPONSEDATA_SIZE;
if(write(fd_socket_tx, wltxbuffer, ii) == ii)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write_80211_associationresponse failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211associationrequest(void)
{
static size_t i;
static ieee80211_assoc_req_t *associationrequest;
static u16 associationrequestlen;

associationrequest = (ieee80211_assoc_req_t*)payloadptr;
if((associationrequestlen = payloadlen - IEEE80211_ASSOCIATIONREQUEST_SIZE) < IEEE80211_IETAG_SIZE) return;
for(i = 0; i < CALIST_MAX - 1; i++)
	{
	if((calist + i)->tsakt == 0) break;
	if(memcmp((calist + i)->cadata->maca, macfrx->addr1, ETH_ALEN) != 0) continue;
	if(memcmp((calist + i)->cadata->macc, macfrx->addr2, ETH_ALEN) != 0) continue;
	(calist + i)->tsakt = tsakt;
	(calist + i)->cadata->channel = (scanlist + scanlistindex)->channel;
	if((calist + i)->cadata->clientcount <= 0) return;
	if((tsakt - (calist + i)->cadata->tsassoc) < TSSECOND1) return;
	(calist + i)->cadata->akm = get_akm((calist + i)->cadata, associationrequestlen, associationrequest->ie);
	if((calist + i)->cadata->akm == RSNPSK)
		{
		send_80211_ack();
		send_80211_associationresponse();
		nanosleep(&tsremain, &tsreq);
		send_80211_eapol_m1_wpa2();
		(calist + i)->cadata->tsassoc = tsakt;
		}
	else if((calist + i)->cadata->akm == WPAPSK)
		{
		send_80211_ack();
		send_80211_associationresponse();
		nanosleep(&tsremain, &tsreq);
		send_80211_eapol_m1_wpa1();
		(calist + i)->cadata->tsassoc = tsakt;
		}
	if(i > CALIST_HALF) qsort(calist, i + 1, CALIST_SIZE, sort_calist_by_tsakt);
	writeepb();
	return;
	}
(calist + i)->tsakt = tsakt;
memset((calist + i)->cadata, 0, CADATA_SIZE);
(calist + i)->cadata->m2 = ' ';
(calist + i)->cadata->channel = (scanlist + scanlistindex)->channel;
(calist + i)->cadata->clientcount = clientcountmax;
memcpy((calist + i)->cadata->maca, macfrx->addr1, ETH_ALEN);
memcpy((calist + i)->cadata->macc, macfrx->addr2, ETH_ALEN);
if(clientcountmax > 0)
	{
	(calist + i)->cadata->akm = get_akm((calist + i)->cadata, associationrequestlen, associationrequest->ie);
	if((calist + i)->cadata->akm == RSNPSK)
		{
		(calist + i)->cadata->tsassoc = tsakt;
		send_80211_ack();
		send_80211_associationresponse();
		nanosleep(&tsremain, &tsreq);
		send_80211_eapol_m1_wpa2();
		(calist + i)->cadata->tsassoc = tsakt;
		}
	else if((calist + i)->cadata->akm == WPAPSK)
		{
		send_80211_ack();
		send_80211_associationresponse();
		nanosleep(&tsremain, &tsreq);
		send_80211_eapol_m1_wpa1();
		(calist + i)->cadata->tsassoc = tsakt;
		}
	}
qsort(calist, i + 1, CALIST_SIZE, sort_calist_by_tsakt);
writeepb();
return;
}
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
static inline __attribute__((always_inline)) void send_80211_authenticationresponse(void)
{
macftx = (ieee80211_mac_t*)&wltxbuffer[RTHTX_SIZE];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_AUTH;
wltxbuffer[RTHTX_SIZE + 1] = 0;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macfrx->addr1, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr3, ETH_ALEN);
macftx->sequence = __hcx16le(seqcounter1++ << 4);
if(seqcounter1 > BCD_MAX) seqcounter1 = 1;
memcpy(wltxbuffer + RTHTX_SIZE + MAC_SIZE_NORM, authenticationresponsedata, AUTHENTICATIONRESPONSE_SIZE);
if((write(fd_socket_tx, wltxbuffer, RTHTX_SIZE + MAC_SIZE_NORM + AUTHENTICATIONRESPONSE_SIZE)) == RTHTX_SIZE + MAC_SIZE_NORM + AUTHENTICATIONRESPONSE_SIZE)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write_80211_authenticationresponse failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211authentication(void)
{
size_t i;
static ieee80211_auth_t *auth;

auth = (ieee80211_auth_t*)payloadptr;
if(payloadlen < IEEE80211_AUTH_SIZE) return;
if(auth->algorithm == OPEN_SYSTEM)
	{
	if(__hcx16le(auth->sequence) == 1) /* CA request */
		{
		for(i = 0; i < CALIST_MAX - 1; i++)
			{
			if((calist + i)->tsakt == 0) break;
			if(memcmp((calist + i)->cadata->maca, macfrx->addr1, ETH_ALEN) != 0) continue;
			if(memcmp((calist + i)->cadata->macc, macfrx->addr2, ETH_ALEN) != 0) continue;
			(calist + i)->tsakt = tsakt;
			(calist + i)->cadata->channel = (scanlist + scanlistindex)->channel;
			if((calist + i)->cadata->clientcount <= 0) return;
			if((tsakt - (calist + i)->cadata->tsauth) < TSSECOND1) return;
				{
				(calist + i)->cadata->tsauth = tsakt;
				send_80211_ack();
				send_80211_authenticationresponse();
				}
			if(i > CALIST_HALF) qsort(calist, i + 1, CALIST_SIZE, sort_calist_by_tsakt);
			return;
			}
		(calist + i)->tsakt = tsakt;
		memset((calist + i)->cadata, 0, CADATA_SIZE);
		(calist + i)->cadata->m2 = ' ';
		(calist + i)->cadata->clientcount = clientcountmax;
		memcpy((calist + i)->cadata->maca, macfrx->addr1, ETH_ALEN);
		memcpy((calist + i)->cadata->macc, macfrx->addr2, ETH_ALEN);
		if(clientcountmax > 0)
			{
			(calist + i)->cadata->tsauth = tsakt;
			send_80211_ack();
			send_80211_authenticationresponse();
			}
		qsort(calist, i + 1, CALIST_SIZE, sort_calist_by_tsakt);
		writeepb();
		}
	else if(__hcx16le(auth->sequence) == 2) /* AP response */
		{
		if(__hcx16le(auth->status) == 0)
			{
			for(i = 0; i < APLIST_MAX - 1; i++)
				{
				if((aplist + i)->tsakt == 0) break;
				if(memcmp((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN) != 0) continue;
				memcpy((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN);
				(aplist + i)->tsakt = tsakt;
				(aplist + i)->apdata->opensystem = 1;
				if(memcmp(macclientrg, (aplist + i)->apdata->macc, ETH_ALEN) == 0) (aplist + i)->apdata->apcount = apcountmax;
				memcpy((aplist + i)->apdata->macc, macfrx->addr1, ETH_ALEN);
				if((aplist + i)->apdata->apcount <= 0) return;
				if((aplist + i)->apdata->essidlen == 0) return;
				if(((aplist + i)->apdata->akm != AKMPSK) && ((aplist + i)->apdata->akm != AKMPSK256)) return;
				if((aplist + i)->apdata->m1 == '+') return;
				if((tsakt - (aplist + i)->apdata->tsauthresponse) < TSSECOND05) return;
				send_80211_ack();
				send_80211_associationrequest2((aplist + i)->apdata);
				(aplist + i)->apdata->tsauthresponse = tsakt;
				(aplist + i)->apdata->apcount -= 1;
				return;
				}
			(aplist + i)->tsakt = tsakt;
			memset((aplist + i)->apdata, 0, APDATA_SIZE);
			(aplist + i)->apdata->channel = (scanlist + scanlistindex)->channel;
			(aplist + i)->apdata->pmkid = ' ';
			(aplist + i)->apdata->m1 = ' ';
			(aplist + i)->apdata->m1m2 = ' ';
			(aplist + i)->apdata->m1m2m3 = ' ';
			(aplist + i)->apdata->pmkid = ' ';
			(aplist + i)->apdata->akmstat = ' ';
			(aplist + i)->apdata->apcount = apcountmax;
			(aplist + i)->apdata->opensystem = 1;
			memcpy((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN);
			memcpy((aplist + i)->apdata->macc, macfrx->addr1, ETH_ALEN);
			if(apcountmax > 0)
				{
				if((aplist + i)->apdata->essidlen != 0)
					{
					if(((aplist + i)->apdata->akm != AKMPSK) && ((aplist + i)->apdata->akm != AKMPSK256)) return;
						{
						send_80211_ack();
						send_80211_associationrequest2((aplist + i)->apdata);
						(aplist + i)->apdata->tsauthresponse = tsakt;
						(aplist + i)->apdata->apcount -= 1;
						}
					}
				}
			qsort(aplist, i + 1, APLIST_SIZE, sort_aplist_by_tsakt);
			writeepb();
			return;
			}
		}
	return;
	}
writeepb();
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211action(void)
{
static size_t i;
static ieee80211_action_t *action;

action = (ieee80211_action_t*)payloadptr;
if(payloadlen < (IEEE80211_ACTION_SIZE + IEEE80211_IETAG_SIZE)) return;
if((action->category == RADIO_MEASUREMENT) && (action->code == NEIGHBOR_REPORT_REQUEST)) writeepb();

if(memcmp(macfrx->addr3, macfrx->addr2, ETH_ALEN) == 0)
	{
	for(i = 0; i < APLIST_MAX - 1; i++)
		{
		if((aplist + i)->tsakt == 0) break;
		if(memcmp((aplist + i)->apdata->maca, macfrx->addr3, ETH_ALEN) != 0) continue;
		(aplist + i)->tsakt = tsakt;
		memcpy((aplist + i)->apdata->macc, macfrx->addr1, ETH_ALEN);
		return;
		}
	}
if(memcmp(macfrx->addr3, macfrx->addr1, ETH_ALEN) == 0)
	{
	for(i = 0; i < APLIST_MAX - 1; i++)
		{
		if((aplist + i)->tsakt == 0) break;
		if(memcmp((aplist + i)->apdata->maca, macfrx->addr3, ETH_ALEN) != 0) continue;
		(aplist + i)->apdata->tsmacc = tsakt;
		memcpy((aplist + i)->apdata->macc, macfrx->addr2, ETH_ALEN);
		return;
		}
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_80211_probereresponse_list()
{
static ssize_t ii;
static ieee80211_beacon_proberesponse_t *beacontx;

if(proberesponsetxindex >= proberesponsetxmax) proberesponsetxindex = 0;
if((aprglist + proberesponsetxindex)->tsakt == 0) proberesponsetxindex = 0;
if((aprglist + proberesponsetxindex)->tsakt == 0) return;

ii = RTHTX_SIZE;
macftx = (ieee80211_mac_t*)&wltxbuffer[ii];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_RESP;
wltxbuffer[ii + 1] = 0;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, (aprglist + proberesponsetxindex)->apdata->maca, ETH_ALEN);
memcpy(macftx->addr3, (aprglist + proberesponsetxindex)->apdata->maca, ETH_ALEN);
macftx->sequence = __hcx16le(seqcounter3++ << 4);
if(seqcounter1 > BCD_MAX) seqcounter3 = 1;
ii += MAC_SIZE_NORM;
beacontx = (ieee80211_beacon_proberesponse_t*)&wltxbuffer[ii];
beacontx->timestamp = __hcx64le(beacontimestamp++);
beacontx->beacon_interval = HCXTXBEACONINTERVAL;
beacontx->capability = HCXTXCAPABILITY;
ii += IEEE80211_PROBERESPONSE_SIZE;
wltxbuffer[ii ++] = 0;
wltxbuffer[ii ++] = (aprglist + proberesponsetxindex)->apdata->essidlen;
memcpy(wltxbuffer + ii, (aprglist + proberesponsetxindex)->apdata->essid, (aprglist + proberesponsetxindex)->apdata->essidlen);
ii += (aprglist + proberesponsetxindex)->apdata->essidlen;
memcpy(wltxbuffer + ii, proberesponsedata, PROBERESPONSEDATA_SIZE);
wltxbuffer[ii + OFFSETCHANNEL] = (u8)(scanlist + scanlistindex)->channel;
ii += PROBERESPONSEDATA_SIZE;
proberesponsetxindex += 1;
if((write(fd_socket_tx, wltxbuffer, ii)) == ii)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write_80211_probereresponse failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_80211_probereresponse_directed(ieee80211_ietag_t *essid)
{
static ssize_t ii;
static ieee80211_beacon_proberesponse_t *beacontx;

ii = RTHTX_SIZE;
macftx = (ieee80211_mac_t*)&wltxbuffer[ii];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_RESP;
wltxbuffer[ii + 1] = 0;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, macfrx->addr1, ETH_ALEN);
memcpy(macftx->addr3, macfrx->addr3, ETH_ALEN);
macftx->sequence = __hcx16le(seqcounter3++ << 4);
if(seqcounter1 > BCD_MAX) seqcounter3 = 1;
ii += MAC_SIZE_NORM;
beacontx = (ieee80211_beacon_proberesponse_t*)&wltxbuffer[ii];
beacontx->timestamp = __hcx64le(beacontimestamp++);
beacontx->beacon_interval = HCXTXBEACONINTERVAL;
beacontx->capability = HCXTXCAPABILITY;
ii += IEEE80211_PROBERESPONSE_SIZE;
wltxbuffer[ii ++] = 0;
wltxbuffer[ii ++] = essid->len;
memcpy(wltxbuffer + ii, essid->ie, essid->len);
ii += essid->len;
memcpy(wltxbuffer + ii, proberesponsedata, PROBERESPONSEDATA_SIZE);
wltxbuffer[ii + OFFSETCHANNEL] = (u8)(scanlist + scanlistindex)->channel;
ii += PROBERESPONSEDATA_SIZE;
if((write(fd_socket_tx, wltxbuffer, ii)) == ii)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write_80211_probereresponse failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void send_80211_probereresponse(apdata_t *stndata)
{
static ssize_t ii;
static ieee80211_beacon_proberesponse_t *beacontx;

ii = RTHTX_SIZE;
macftx = (ieee80211_mac_t*)&wltxbuffer[ii];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_RESP;
wltxbuffer[ii + 1] = 0;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, macfrx->addr2, ETH_ALEN);
memcpy(macftx->addr2, stndata->maca, ETH_ALEN);
memcpy(macftx->addr3, stndata->maca, ETH_ALEN);
macftx->sequence = __hcx16le(seqcounter3++ << 4);
if(seqcounter1 > BCD_MAX) seqcounter3 = 1;
ii += MAC_SIZE_NORM;
beacontx = (ieee80211_beacon_proberesponse_t*)&wltxbuffer[ii];
beacontx->timestamp = __hcx64le(beacontimestamp++);
beacontx->beacon_interval = HCXTXBEACONINTERVAL;
beacontx->capability = HCXTXCAPABILITY;
ii += IEEE80211_PROBERESPONSE_SIZE;
wltxbuffer[ii ++] = 0;
wltxbuffer[ii ++] = stndata->essidlen;
memcpy(wltxbuffer + ii, stndata->essid, stndata->essidlen);
ii += stndata->essidlen;
memcpy(wltxbuffer + ii, proberesponsedata, PROBERESPONSEDATA_SIZE);
wltxbuffer[ii + OFFSETCHANNEL] = (u8)(scanlist + scanlistindex)->channel;
ii += PROBERESPONSEDATA_SIZE;
if((write(fd_socket_tx, wltxbuffer, ii)) == ii)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write_80211_probereresponse failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211proberequest(void)
{
static size_t i;
static ieee80211_proberequest_t *proberequest;
static u16 proberequestlen;
static ieee80211_ietag_t *essid;

proberequest = (ieee80211_proberequest_t*)payloadptr;
if((proberequestlen = payloadlen - IEEE80211_PROBERESPONSE_SIZE) < IEEE80211_IETAG_SIZE) return;
if((essid = get_tag(TAG_SSID, proberequestlen, proberequest->ie)) == NULL) return;
if(essid->len > ESSID_MAX) return;

if((essid->len == 0) || (essid->ie[0] == 0))
	{
	if(macfrx->retry == 0) send_80211_probereresponse_list();
	return;
	}
for(i = 0; i < APRGLIST_MAX - 1; i++)
	{
	if((aprglist + i)->tsakt == 0) break;
	if((aprglist + i)->apdata->essidlen != essid->len) continue;
	if(memcmp((aprglist + i)->apdata->essid, essid->ie, essid->len) != 0) continue;
	if(macfrx->retry == 0)
		{
		if(memcmp(macbc, macfrx->addr3, ETH_ALEN) == 0) send_80211_probereresponse((aprglist + i)->apdata);
		else send_80211_probereresponse_directed(essid);
		}
	(aprglist + i)->tsakt = tsakt;
	if(i > APRGLIST_HALF) qsort(aprglist, i + 1, APLIST_SIZE, sort_aplist_by_tsakt);
	return;
	}
(aprglist + i)->tsakt = tsakt;
memset((aprglist + i)->apdata, 0, APDATA_SIZE);
(aprglist + i)->apdata->essidlen = essid->len;
memcpy((aprglist + i)->apdata->essid, essid->ie, essid->len);
(aprglist + i)->apdata->maca[5] = nicaprg & 0xff;
(aprglist + i)->apdata->maca[4] = (nicaprg >> 8) & 0xff;
(aprglist + i)->apdata->maca[3] = (nicaprg >> 16) & 0xff;
(aprglist + i)->apdata->maca[2] = ouiaprg & 0xff;
(aprglist + i)->apdata->maca[1] = (ouiaprg >> 8) & 0xff;
(aprglist + i)->apdata->maca[0] = (ouiaprg >> 16) & 0xff;
nicaprg++;
if(macfrx->retry == 0)
	{
	if(memcmp(macbc, macfrx->addr3, ETH_ALEN) == 0) send_80211_probereresponse((aprglist + i)->apdata);
	else send_80211_probereresponse_directed(essid);
	}
qsort(aprglist, i + 1, APLIST_SIZE, sort_aplist_by_tsakt);
writeepb();
return;
}
/*---------------------------------------------------------------------------*/
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void get_tags(apdata_t *apdata, int infolen, u8 *infostart)
{
static size_t i;
static int tlen;
static ieee80211_ietag_t *infoptr;
static ieee80211_suite_t *rsn;
static ieee80211_suite_t *wpa;

apdata->channel = (scanlist + scanlistindex)->channel;
while(0 < infolen)
	{
	infoptr = (ieee80211_ietag_t*)infostart;
	if(infolen < (int)(infoptr->len + IEEE80211_IETAG_SIZE)) return;
	if(infoptr->id == TAG_SSID)
		{
		if((infoptr->len > 0) && (infoptr->len <= ESSID_MAX))
			{
			if(infoptr->ie[0] != 0)
				{
				apdata->essidlen = infoptr->len;
				memcpy(apdata->essid, infoptr->ie, apdata->essidlen);
				}
			}
		}
	else if(infoptr->id == TAG_CHAN)
		{
		if(infoptr->len == 1) apdata->channel = (u8)infoptr->ie[0];
		}
	else if(infoptr->id == TAG_RSN)
		{
		if(infoptr->len >= RSNLEN_MIN)
			{
			rsn = (ieee80211_suite_t*)infoptr->ie;
			if(__hcx16le(rsn->count) == 1)
				{
				if(memcmp(rsnccmp, rsn->suite, 3) == 0)
					{
					apdata->gcs = rsn->suite[3];
					rsn += 1;
					tlen = 8;
					for(i = 0; i < __hcx16le(rsn->count); i++)
						{
						if(memcmp(rsnccmp, &infoptr->ie[tlen], 4) == 0) apdata->pcs = infoptr->ie[tlen +3];
						else if((apdata->pcs == 0) && (memcmp(rsntkip, &infoptr->ie[tlen], 4) == 0)) apdata->pcs = infoptr->ie[tlen +3];
						tlen += 4;
						if(tlen > infoptr->len) return;
						}
					rsn = (ieee80211_suite_t*)&infoptr->ie[tlen];
					tlen += 2;
					for(i = 0; i < __hcx16le(rsn->count); i++)
						{
						if(memcmp(rsnpsk, &infoptr->ie[tlen], 4) == 0)
							{
							apdata->akm = infoptr->ie[tlen +3];
							apdata->akmstat = 'p';
							}
						else if((apdata->akm == 0) && (memcmp(rsnpsk256, &infoptr->ie[tlen], 4) == 0))
							{
							apdata->akm = infoptr->ie[tlen +3];
							apdata->akmstat = 'p';
							}
						tlen += 4;
						if(tlen > infoptr->len) return;
						}
					apdata->mfp = infoptr->ie[tlen] & 0xc0;
					}
				}
			}
		}
	else if(infoptr->id == TAG_VENDOR)
		{
		if(infoptr->len >= WPALEN_MIN)
			{
			if(memcmp(wpatype, infoptr->ie, SUITE_SIZE) == 0)
				{
				wpa = (ieee80211_suite_t*)(infoptr->ie +4);
				if(__hcx16le(wpa->count) == 1)
					{
					if(memcmp(wpatkip, wpa->suite, 3) == 0)
						{
						apdata->mcs = wpa->suite[3];
						wpa += 1;
						tlen = 12;
						for(i = 0; i < __hcx16le(wpa->count); i++)
							{
							if(memcmp(wpaccmp, &infoptr->ie[tlen], 4) == 0) apdata->ucs = infoptr->ie[tlen +3];
							else if((apdata->ucs == 0) && (memcmp(wpatkip, &infoptr->ie[tlen], 4) == 0)) apdata->ucs = infoptr->ie[tlen +3];
							tlen += 4;
							if(tlen > infoptr->len) return;
							}
						wpa = (ieee80211_suite_t*)&infoptr->ie[tlen];
						tlen += 2;
						for(i = 0; i < __hcx16le(wpa->count); i++)
							{
							if(memcmp(wpapsk, &infoptr->ie[tlen], 4) == 0)
								{
								apdata->akm1 = infoptr->ie[tlen +3];
								apdata->akmstat = 'p';
								}
							tlen += 4;
							if(tlen > infoptr->len) return;
							}
						}
					}
				}
			}
		}
	infostart += infoptr->len + IEEE80211_IETAG_SIZE;
	infolen -= infoptr->len + IEEE80211_IETAG_SIZE;
	}
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211proberesponse_rcascan(void)
{
static size_t i;
static ieee80211_beacon_proberesponse_t *proberesponse;
static u16 proberesponselen;

proberesponse = (ieee80211_beacon_proberesponse_t*)payloadptr;
if((proberesponselen = payloadlen - IEEE80211_BEACON_SIZE) < IEEE80211_IETAG_SIZE) return;
for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if((aplist + i)->tsakt == 0) break;
	if(memcmp((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN) != 0) continue;
	(aplist + i)->tsakt = tsakt;
	if(memcmp(macclientrg, macfrx->addr1, ETH_ALEN) != 0) (aplist + i)->apdata->tsresponse = tsakt;
	(aplist + i)->apdata->rtfrequency = rtfrequency;
	(aplist + i)->apdata->rtrssi = rtrssi;
	if(__hcx16le(proberesponse->capability) & WLAN_CAPABILITY_PRIVACY) (aplist + i)->apdata->privacy = 'e';
	else (aplist + i)->apdata->privacy = 'o';
	get_tags((aplist + i)->apdata, proberesponselen, proberesponse->ie);
	if(i > APLIST_HALF) qsort(aplist, i + 1, APLIST_SIZE, sort_aplist_by_tsakt);
	return;
	}
(aplist + i)->tsakt = tsakt;
memset((aplist + i)->apdata, 0, APDATA_SIZE);
memcpy((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN);
if(memcmp(macclientrg, macfrx->addr1, ETH_ALEN) != 0) (aplist + i)->apdata->tsresponse = tsakt;
(aplist + i)->apdata->rtfrequency = rtfrequency;
(aplist + i)->apdata->rtrssi = rtrssi;
if(__hcx16le(proberesponse->capability) & WLAN_CAPABILITY_PRIVACY) (aplist + i)->apdata->privacy = 'e';
else (aplist + i)->apdata->privacy = 'o';
get_tags((aplist + i)->apdata, proberesponselen, proberesponse->ie);
qsort(aplist, i + 1, APLIST_SIZE, sort_aplist_by_tsakt);
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211proberesponse(void)
{
static size_t i;
static ieee80211_beacon_proberesponse_t *proberesponse;
static u16 proberesponselen;

proberesponse = (ieee80211_beacon_proberesponse_t*)payloadptr;
if((proberesponselen = payloadlen - IEEE80211_BEACON_SIZE) < IEEE80211_IETAG_SIZE) return;
for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if((aplist + i)->tsakt == 0) break;
	if(memcmp((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN) != 0) continue;
	(aplist + i)->tsakt = tsakt;
	if((aplist + i)->apdata->proberesponse == false)
		{
		(aplist + i)->apdata->proberesponse = true;
		writeepb();
		}
	if(__hcx16le(proberesponse->capability) & WLAN_CAPABILITY_PRIVACY) (aplist + i)->apdata->privacy = 'e';
	else (aplist + i)->apdata->privacy = 'o';
	get_tags((aplist + i)->apdata, proberesponselen, proberesponse->ie);
	if(i > APLIST_HALF) qsort(aplist, i + 1, APLIST_SIZE, sort_aplist_by_tsakt);
	return;
	}
(aplist + i)->tsakt = tsakt;
memset((aplist + i)->apdata, 0, APDATA_SIZE);
(aplist + i)->apdata->pmkid = ' ';
(aplist + i)->apdata->m1 = ' ';
(aplist + i)->apdata->m1m2 = ' ';
(aplist + i)->apdata->m1m2m3 = ' ';
(aplist + i)->apdata->pmkid = ' ';
(aplist + i)->apdata->akmstat = ' ';
(aplist + i)->apdata->apcount = apcountmax;
(aplist + i)->apdata->proberesponse = true;
memcpy((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN);
memcpy((aplist + i)->apdata->macc, macclientrg, ETH_ALEN);
if(__hcx16le(proberesponse->capability) & WLAN_CAPABILITY_PRIVACY) (aplist + i)->apdata->privacy = 'e';
else (aplist + i)->apdata->privacy = 'o';
get_tags((aplist + i)->apdata, proberesponselen, proberesponse->ie);
if(apcountmax > 0)
	{
	if((aplist + i)->apdata->channel == (scanlist + scanlistindex)->channel)
		{
		if((aplist + i)->apdata->akm == AKMPSK)
			{
			if((aplist + i)->apdata->essidlen != 0)
				{
				send_80211_associationrequest2bc((aplist + i)->apdata);
				(aplist + i)->apdata->tsrequest = tsakt;
				(aplist + i)->apdata->apcount -= 1;
				}
			}
		if((disassociationflag == true) && (((aplist + i)->apdata->mfp & MFP_REQUIRED) != MFP_REQUIRED))
			{
			send_80211_disassociationcaa(macfrx->addr1, macfrx->addr2);
			(aplist + i)->apdata->tsrequest = tsakt;
			(aplist + i)->apdata->apcount -= 1;
			}
		}
	}
qsort(aplist, i + 1, APLIST_SIZE, sort_aplist_by_tsakt);
writeepb();
return;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) void process80211beacon_rcascan(void)
{
static size_t i;
static ieee80211_beacon_proberesponse_t *beacon;
static u16 beaconlen;

beacon = (ieee80211_beacon_proberesponse_t*)payloadptr;
if((beaconlen = payloadlen - IEEE80211_BEACON_SIZE) < IEEE80211_IETAG_SIZE) return;
for(i = 0; i < APLIST_MAX - 1; i++)
	{
	if((aplist + i)->tsakt == 0) break;
	if(memcmp((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN) != 0) continue;
	(aplist + i)->tsakt = tsakt;
	(aplist + i)->apdata->rtfrequency = rtfrequency;
	(aplist + i)->apdata->rtrssi = rtrssi;
	if(__hcx16le(beacon->capability) & WLAN_CAPABILITY_PRIVACY) (aplist + i)->apdata->privacy = 'e';
	else (aplist + i)->apdata->privacy = 'o';
	get_tags((aplist + i)->apdata, beaconlen, beacon->ie);
	if(i > APLIST_HALF) qsort(aplist, i + 1, APLIST_SIZE, sort_aplist_by_tsakt);
	return;
	}
(aplist + i)->tsakt = tsakt;
memset((aplist + i)->apdata, 0, APDATA_SIZE);
memcpy((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN);
(aplist + i)->apdata->rtfrequency = rtfrequency;
(aplist + i)->apdata->rtrssi = rtrssi;
if(__hcx16le(beacon->capability) & WLAN_CAPABILITY_PRIVACY) (aplist + i)->apdata->privacy = 'e';
else (aplist + i)->apdata->privacy = 'o';
get_tags((aplist + i)->apdata, beaconlen, beacon->ie);
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
	if((aplist + i)->tsakt == 0) break;
	if(memcmp((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN) != 0) continue;
	if((aplist + i)->apdata->beacon == true) get_tag_channel((aplist + i)->apdata, beaconlen, beacon->ie);
	else get_tags((aplist + i)->apdata, beaconlen, beacon->ie);
	if((aplist + i)->apdata->beacon == false)
		{
		(aplist + i)->apdata->beacon = true;
		writeepb();
		}
	(aplist + i)->tsakt = tsakt;
	if((aplist + i)->apdata->channel != (scanlist + scanlistindex)->channel) return;
	if((aplist + i)->apdata->m1m2m3 == '+') return;
	if((aplist + i)->apdata->pmkid == '+') return;
	if((tsakt - (aplist + i)->apdata->tsrequest) < TSSECOND2) return;
	if((tsakt - (aplist + i)->apdata->tsrequest) > TSHOUR1) (aplist + i)->apdata->apcount = apcountmax;
	if((aplist + i)->apdata->apcount <= 0) return;
	if((aplist + i)->apdata->essidlen != 0)
		{
		if(((aplist + i)->apdata->akm == AKMPSK) || ((aplist + i)->apdata->akm == AKMPSK256))
			{
			if(memcmp(macclientrg, (aplist + i)->apdata->macc, ETH_ALEN) == 0)
				{
				if((aplist + i)->apdata->m1 != '+')
					{
					send_80211_associationrequest2bc((aplist + i)->apdata);
					send_80211_authenticationrequest((aplist + i)->apdata);
					(aplist + i)->apdata->tsrequest = tsakt;
					(aplist + i)->apdata->apcount -= 1;
					}
				}
			else
				{
				send_80211_associationrequest2((aplist + i)->apdata);
				(aplist + i)->apdata->tsrequest = tsakt;
				(aplist + i)->apdata->apcount -= 1;
				}
			}
		}
	if(disassociationflag == true)
		{
		if(((aplist + i)->apdata->mfp & MFP_REQUIRED) != MFP_REQUIRED)
			{
			if((memcmp(macclientrg, (aplist + i)->apdata->macc, ETH_ALEN) == 0) || (tsakt - (aplist + i)->apdata->tsmacc) > TSMINUTE1)
				{
				send_80211_disassociationcaa(macfrx->addr1, macfrx->addr2);
				(aplist + i)->apdata->tsrequest = tsakt;
				(aplist + i)->apdata->apcount -= 1;
				}
			else
				{
				send_80211_disassociationcaa((aplist + i)->apdata->macc, macfrx->addr2);
				(aplist + i)->apdata->tsrequest = tsakt;
				(aplist + i)->apdata->apcount -= 1;
				}
			}
		}
	if(i > APLIST_HALF) qsort(aplist, i + 1, APLIST_SIZE, sort_aplist_by_tsakt);
	return;
	}
(aplist + i)->tsakt = tsakt;
memset((aplist + i)->apdata, 0, APDATA_SIZE);
(aplist + i)->apdata->pmkid = ' ';
(aplist + i)->apdata->m1 = ' ';
(aplist + i)->apdata->m1m2 = ' ';
(aplist + i)->apdata->m1m2m3 = ' ';
(aplist + i)->apdata->pmkid = ' ';
(aplist + i)->apdata->akmstat = ' ';
(aplist + i)->apdata->apcount = apcountmax;
(aplist + i)->apdata->beacon = true;
memcpy((aplist + i)->apdata->maca, macfrx->addr2, ETH_ALEN);
memcpy((aplist + i)->apdata->macc, macclientrg, ETH_ALEN);
if(__hcx16le(beacon->capability) & WLAN_CAPABILITY_PRIVACY) (aplist + i)->apdata->privacy = 'e';
else (aplist + i)->apdata->privacy = 'o';
get_tags((aplist + i)->apdata, beaconlen, beacon->ie);
if(apcountmax > 0)
	{
	if((aplist + i)->apdata->channel == (scanlist + scanlistindex)->channel)
		{
		if(((aplist + i)->apdata->akm == AKMPSK) || ((aplist + i)->apdata->akm == AKMPSK256))
			{
			if((aplist + i)->apdata->essidlen != 0)
				{
				send_80211_associationrequest2bc((aplist + i)->apdata);
				(aplist + i)->apdata->tsrequest = tsakt;
				(aplist + i)->apdata->apcount -= 1;
				}
			}
		if((disassociationflag == true) && (((aplist + i)->apdata->mfp & MFP_REQUIRED) != MFP_REQUIRED))
			{
			send_80211_disassociationcaa(macfrx->addr1, macfrx->addr2);
			(aplist + i)->apdata->tsrequest = tsakt;
			(aplist + i)->apdata->apcount -= 1;
			}
		}
	}
qsort(aplist, i + 1, APLIST_SIZE, sort_aplist_by_tsakt);
writeepb();
return;
}
/*===========================================================================*/
static inline __attribute__((always_inline)) void process_packet(void)
{
if((packetlen = read(fd_socket_rx, packetptr, PCAPNG_SNAPLEN)) < RTHRX_SIZE)
	{
	if(packetlen == -1) errorcount++;
	return;
	}
rth = (rth_t*)packetptr;
if((__hcx32le(rth->it_present) & IEEE80211_RADIOTAP_DBM_ANTSIGNAL) == 0) return;
if(__hcx16le(rth->it_len) > packetlen)
	{
	errorcount++;
	return;
	}
ieee82011ptr = packetptr + __hcx16le(rth->it_len);
ieee82011len = packetlen - __hcx16le(rth->it_len);
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
tsakt = ((u64)tspecakt.tv_sec * TSSECOND1) + tspecakt.tv_nsec;
packetcount++;
if(macfrx->type == IEEE80211_FTYPE_MGMT)
	{
	if(macfrx->subtype == IEEE80211_STYPE_BEACON) process80211beacon();
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_RESP) process80211proberesponse();
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_REQ) process80211proberequest();
	else if(macfrx->subtype == IEEE80211_STYPE_AUTH) process80211authentication();
	else if(macfrx->subtype == IEEE80211_STYPE_ASSOC_REQ) process80211associationrequest();
	else if(macfrx->subtype == IEEE80211_STYPE_REASSOC_REQ)process80211reassociationrequest();
	else if(macfrx->subtype == IEEE80211_STYPE_ASSOC_RESP) process80211associationresponse();
	else if(macfrx->subtype == IEEE80211_STYPE_REASSOC_RESP) process80211reassociationresponse();
	else if(macfrx->subtype == IEEE80211_STYPE_ACTION) process80211action();
	}
else if(macfrx->type == IEEE80211_FTYPE_CTL)
	{
	if(macfrx->subtype == IEEE80211_STYPE_BACK_REQ) process80211rata();
	else if(macfrx->subtype == IEEE80211_STYPE_BACK) process80211rata();
	else if(macfrx->subtype == IEEE80211_STYPE_RTS) process80211rata();
	else if(macfrx->subtype == IEEE80211_STYPE_VHT) process80211rata();
	else if((macfrx->subtype == IEEE80211_STYPE_TRIGGER) && (memcmp(macbc, macfrx->addr1, 6) != 0)) process80211rata();
//	else if(macfrx->subtype == IEEE80211_STYPE_PSPOLL) process80211pspoll();
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
		if((__hcx16be(llc->type) == LLC_TYPE_AUTH) && (llc->dsap == IEEE80211_LLC_SNAP) && (llc->ssap == IEEE80211_LLC_SNAP))
			{
			process80211eapauthentication();
			return;
			}
		}
	if((macfrx->subtype &IEEE80211_STYPE_NULLFUNC) == IEEE80211_STYPE_NULLFUNC) process80211null();
	else if((macfrx->subtype &IEEE80211_STYPE_QOS_NULLFUNC) == IEEE80211_STYPE_QOS_NULLFUNC) process80211qosnull();
/*
	else if((macfrx->subtype &IEEE80211_STYPE_DATA) == IEEE80211_STYPE_DATA)
	else if((macfrx->subtype &IEEE80211_STYPE_QOS_DATA) == IEEE80211_STYPE_QOS_DATA) process80211qosdata();
*/
	}
return;
}
/*===========================================================================*/
static inline __attribute__((always_inline)) void send_80211_proberequest_undirected(void)
{
macftx = (ieee80211_mac_t*)&wltxbuffer[RTHTX_SIZE];
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_REQ;
wltxbuffer[RTHTX_SIZE + 1] = 0;
macftx->duration = HCXTXDURATION;
memcpy(macftx->addr1, macbc, ETH_ALEN);
memcpy(macftx->addr2, macclientrg, ETH_ALEN);
memcpy(macftx->addr3, macbc, ETH_ALEN);
macftx->sequence = __hcx16le(seqcounter2++ << 4);
if(seqcounter1 > 4095) seqcounter4 = 1;
memcpy(&wltxbuffer[RTHTX_SIZE + MAC_SIZE_NORM], &proberequest_undirected_data, PROBEREQUEST_UNDIRECTED_SIZE);
if((write(fd_socket_tx, &wltxbuffer, RTHTX_SIZE + MAC_SIZE_NORM + PROBEREQUEST_UNDIRECTED_SIZE)) == RTHTX_SIZE + MAC_SIZE_NORM + PROBEREQUEST_UNDIRECTED_SIZE)
	{
	errortxcount = 0;
	return;
	}
#ifdef HCXDEBUG
fprintf(fh_debug, "write_80211_proberequest_undirected failed: %s\n", strerror(errno));
#endif
errortxcount++;
return;
}
/*---------------------------------------------------------------------------*/
static void get_radiotapfield(uint16_t rthlen)
{
static int i;
static uint16_t pf;
static rth_t *rth;
static uint32_t *pp;

rth = (rth_t*)packetptr;
pf = RTHRX_SIZE;
rtfrequency = 0;
rtrssi = 0;
if((rth->it_present & IEEE80211_RADIOTAP_EXT) == IEEE80211_RADIOTAP_EXT)
	{
	pp = (uint32_t*)packetptr;
	for(i = 2; i < rthlen /4; i++)
		{
		#ifdef BIG_ENDIAN_HOST
		pp[i] = byte_swap_32(pp[i]);
		#endif
		pf += 4;
		if((pp[i] & IEEE80211_RADIOTAP_EXT) != IEEE80211_RADIOTAP_EXT) break;
		}
	}
if((rth->it_present & IEEE80211_RADIOTAP_TSFT) == IEEE80211_RADIOTAP_TSFT)
	{
	if(pf > rthlen) return;
	if((pf %8) != 0) pf += 4;
	pf += 8;
	}
if((rth->it_present & IEEE80211_RADIOTAP_FLAGS) == IEEE80211_RADIOTAP_FLAGS)
	{
	if(pf > rthlen) return;
	pf += 1;
	}
if((rth->it_present & IEEE80211_RADIOTAP_RATE) == IEEE80211_RADIOTAP_RATE) pf += 1;
if((rth->it_present & IEEE80211_RADIOTAP_CHANNEL) == IEEE80211_RADIOTAP_CHANNEL)
	{
	if(pf > rthlen) return;
	if((pf %2) != 0) pf += 1;
	rtfrequency = (packetptr[pf +1] << 8) + packetptr[pf];
	pf += 4;
	}
if((rth->it_present & IEEE80211_RADIOTAP_FHSS) == IEEE80211_RADIOTAP_FHSS)
		{
		if((pf %2) != 0) pf += 1;
		pf += 2;
		}
if((rth->it_present & IEEE80211_RADIOTAP_DBM_ANTSIGNAL) == IEEE80211_RADIOTAP_DBM_ANTSIGNAL) rtrssi = packetptr[pf];
return;
}
/*===========================================================================*/
static inline __attribute__((always_inline)) void process_packet_rcascan(void)
{
if((packetlen = read(fd_socket_rx, packetptr, PCAPNG_SNAPLEN)) < RTHRX_SIZE)
	{
	if(packetlen == -1) errorcount++;
	return;
	}
rth = (rth_t*)packetptr;
if((__hcx32le(rth->it_present) & IEEE80211_RADIOTAP_DBM_ANTSIGNAL) == 0) return;
if(__hcx16le(rth->it_len) > packetlen)
	{
	errorcount++;
	return;
	}
ieee82011ptr = packetptr + __hcx16le(rth->it_len);
ieee82011len = packetlen - __hcx16le(rth->it_len);
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
tsakt = ((u64)tspecakt.tv_sec * TSSECOND1) + tspecakt.tv_nsec;
packetcount++;
if(macfrx->type == IEEE80211_FTYPE_MGMT)
	{
	if(macfrx->subtype == IEEE80211_STYPE_BEACON)
		{
		get_radiotapfield(__hcx16le(rth->it_len));
		process80211beacon_rcascan();
		}
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_RESP)
		{
		get_radiotapfield(__hcx16le(rth->it_len));
		process80211proberesponse_rcascan();
		}
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
/*SCAN LOOPs */
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

sleepled.tv_sec = 0;
sleepled.tv_nsec = GPIO_LED_DELAY;
if(gpiostatusled > 0)
	{
	GPIO_SET = 1 << gpiostatusled;
	nanosleep(&sleepled, NULL);
	GPIO_CLR = 1 << gpiostatusled;
	}
if(nl_set_frequency() == false) errorcount++;
while(!wanteventflag)
	{
	if(errorcount > errorcountmax) wanteventflag |= EXIT_ON_ERROR;
	epret = epoll_pwait(fd_epoll, events, epi, timerwaitnd, NULL);
	if(epret == -1)
		{
		if(errno != EINTR)
			{
			#ifdef HCXDEBUG
			fprintf(fh_debug, "epret failed: %s\n", strerror(errno));
			#endif
			errorcount++;
			}
		continue;
		}
	for(i = 0; i < epret; i++)
		{
		if(events[i].data.fd == fd_socket_rx) process_packet();
		else if(events[i].data.fd == fd_timer1)
			{
			if(read(fd_timer1, &timer1count, sizeof(u64)) == -1) errorcount++;
			lifetime++;
			if((lifetime % timehold) == 0)
				{
				scanlistindex++;
				if(nl_set_frequency() == false) errorcount++;
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
				if(errortxcount > errorcountmax) wanteventflag |= EXIT_ON_ERROR;
				}
			if((tottime > 0) && (lifetime >= tottime)) wanteventflag |= EXIT_ON_TOT;
			if((lifetime % timewatchdog) == 0)
				{
				if(packetcount == packetcountlast) wanteventflag |= EXIT_ON_WATCHDOG;
				packetcountlast = packetcount;
				}
			}
		}
	}
return true;
}
/*---------------------------------------------------------------------------*/
static bool nl_scanloop_rds(void)
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
if(gpiostatusled > 0)
	{
	GPIO_SET = 1 << gpiostatusled;
	nanosleep(&sleepled, NULL);
	GPIO_CLR = 1 << gpiostatusled;
	}

if(nl_set_frequency() == false) errorcount++;
while(!wanteventflag)
	{
	if(errorcount > errorcountmax) wanteventflag |= EXIT_ON_ERROR;
	epret = epoll_pwait(fd_epoll, events, epi, timerwaitnd, NULL);
	if(epret == -1)
		{
		if(errno != EINTR)
			{
			#ifdef HCXDEBUG
			fprintf(fh_debug, "epret failed: %s\n", strerror(errno));
			#endif
			errorcount++;
			}
		continue;
		}
	for(i = 0; i < epret; i++)
		{
		if(events[i].data.fd == fd_socket_rx) process_packet();
		else if(events[i].data.fd == fd_timer1)
			{
			if(read(fd_timer1, &timer1count, sizeof(u64)) == -1) errorcount++;
			lifetime++;
			if((lifetime % timehold) == 0)
				{
				show_realtime();
				scanlistindex++;
				if(nl_set_frequency() == false) errorcount++;
				}
			else if((lifetime % 5) == 0) show_realtime();
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
				if(errortxcount > errorcountmax) wanteventflag |= EXIT_ON_ERROR;
				}
			if((tottime > 0) && (lifetime >= tottime)) wanteventflag |= EXIT_ON_TOT;
			if((lifetime % timewatchdog) == 0)
				{
				if(packetcount == packetcountlast) wanteventflag |= EXIT_ON_WATCHDOG;
				packetcountlast = packetcount;
				}
			}
		}
	}
return true;
}
/*---------------------------------------------------------------------------*/
static bool nl_scanloop_rcascan()
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
if(gpiostatusled > 0)
	{
	GPIO_SET = 1 << gpiostatusled;
	nanosleep(&sleepled, NULL);
	GPIO_CLR = 1 << gpiostatusled;
	}

if(nl_set_frequency() == false) errorcount++;
while(!wanteventflag)
	{
	if(errorcount > errorcountmax) wanteventflag |= EXIT_ON_ERROR;
	epret = epoll_pwait(fd_epoll, events, epi, timerwaitnd, NULL);
	if(epret == -1)
		{
		if(errno != EINTR)
			{
			#ifdef HCXDEBUG
			fprintf(fh_debug, "epret failed: %s\n", strerror(errno));
			#endif
			errorcount++;
			}
		continue;
		}
	for(i = 0; i < epret; i++)
		{
		if(events[i].data.fd == fd_socket_rx) process_packet_rcascan();
		else if(events[i].data.fd == fd_timer1)
			{
			if(read(fd_timer1, &timer1count, sizeof(u64)) == -1) errorcount++;
			lifetime++;
			if((lifetime % 5) == 0)
				{
				show_realtime_rca();
				scanlistindex++;
				if(nl_set_frequency() == false) errorcount++;
				if(rcascanmode == RCASCAN_ACTIVE) send_80211_proberequest_undirected();
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
				if(errortxcount > errorcountmax) wanteventflag |= EXIT_ON_ERROR;
				}
			if((tottime > 0) && (lifetime >= tottime)) wanteventflag |= EXIT_ON_TOT;
			if((lifetime % timewatchdog) == 0)
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
		if((freql + ipl->i)->channel == 0) (freql + ipl->i)->frequency = 0;
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
/*
Linux Generic Netlink protocol
    Netlink message header (type: 0x0025)
    Command: NL80211_CMD_NEW_INTERFACE (7)
    Family Version: 0
    Reserved
Linux 802.11 Netlink
    Attribute: NL80211_ATTR_WIPHY
        Len: 8
        Type: 0x0001, NL80211_ATTR_WIPHY (1)
        Attribute Value: 0x00000003 (3)
    Attribute: NL80211_ATTR_IFNAME
        Len: 12
        Type: 0x0004, NL80211_ATTR_IFNAME (4)
        Interface Name: hcxmon0
    Attribute: NL80211_ATTR_IFTYPE
        Len: 8
        Type: 0x0005, NL80211_ATTR_IFTYPE (5)
        Attribute Type: NL80211_IFTYPE_MONITOR (6)
*/

static inline bool nl_set_interface(void)
{
static size_t ii;
static ssize_t i;
static ssize_t msglen;
static int nlremlen = 0;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;
static u32 *wiphytmp;
static u64 *wdevtmp;
static u32 *ifidxtmp;
static u8 *vimactmp;
static char *ifnametmp;

i = 0;
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = nlfamily;
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
nlh->nlmsg_seq = nlseqcounter++;
nlh->nlmsg_pid = hcxpid;
i += sizeof(struct nlmsghdr);
glh = (struct genlmsghdr*)(nltxbuffer + i);
glh->cmd = NL80211_CMD_NEW_INTERFACE;
glh->version = 1;
glh->reserved = 0;
i += sizeof(struct genlmsghdr);
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;

nla->nla_type = NL80211_ATTR_WIPHY;
//*(u32*)nla_data(nla) = phyindex;
i += 8;
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;

nla->nla_type = NL80211_ATTR_IFNAME;
//memcpy(nla_data(nla), hcxname, hcxnamelen);
i += 8;
nla = (struct nlattr*)(nltxbuffer + i);
nla->nla_len = 8;


nla->nla_type = NL80211_ATTR_IFTYPE;
*(u32*)nla_data(nla) = NL80211_IFTYPE_MONITOR;
i += 8;
if(((ifakttype & IFTYPEMONACT) == IFTYPEMONACT) && (activemonitorflag == true))
	{
	nla = (struct nlattr*)(nltxbuffer + i);
	nla->nla_len = 8;
	nla->nla_type = NL80211_ATTR_MNTR_FLAGS;
	nla = (struct nlattr*)nla_data(nla);
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
	wiphytmp = NULL;
	wdevtmp = NULL;
	ifidxtmp = NULL;;
	vimactmp = NULL;;
	ifnametmp = NULL;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
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
		nla = (struct nlattr*)((unsigned char*)NLMSG_DATA(nlh) + sizeof(struct genlmsghdr));
		nlremlen = NLMSG_PAYLOAD(nlh, 0) -4;
		while(nla_ok(nla, nlremlen))
			{
			if(nla->nla_type == NL80211_ATTR_WDEV) wdevtmp = nla_data(nla);
			if(nla->nla_type == NL80211_ATTR_IFINDEX) ifidxtmp = nla_data(nla);
			if(nla->nla_type == NL80211_ATTR_IFNAME) ifnametmp = nla_data(nla);
			if(nla->nla_type == NL80211_ATTR_WIPHY) wiphytmp = nla_data(nla);
			if(nla->nla_type == NL80211_ATTR_MAC)
				{
				if(nla->nla_len == 10) vimactmp = nla_data(nla);
				}
			nla = nla_next(nla, &nlremlen);
			}
		for(ii = 0; ii < ifpresentlistcounter; ii++)
			{
			if((ifpresentlist + ii)->wiphy == *(int*)wiphytmp)
				{
				if(ifidxtmp != NULL) (ifpresentlist + ii)->index = *(u32*)ifidxtmp;
				if(wdevtmp != NULL)
					{
					if((ifpresentlist + ii)->wdev != 0)
						{
						if((ifpresentlist + ii)->wdev != *(u64*)wdevtmp) (ifpresentlist + ii)->type |= IF_IS_SHARED;
						}
					(ifpresentlist + ii)->wdev = *(u64*)wdevtmp;
					}
				if(vimactmp != NULL)memcpy((ifpresentlist + ii)->vimac, vimactmp, ETH_ALEN);
				if(ifnametmp != NULL)strncpy((ifpresentlist + ii)->name, ifnametmp, IF_NAMESIZE);
				}
			}
		}
	}
return false;
}
/*---------------------------------------------------------------------------*/
static bool nl_get_interfacelist(void)
{
static size_t ii;
static ssize_t i;
static ssize_t msglen;
static int nlremlen = 0;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;
static u32 *wiphytmp;
static u64 *wdevtmp;
static u32 *ifidxtmp;
static u8 *vimactmp;
static char *ifnametmp;

i = 0;
nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = nlfamily;
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK;
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
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	wiphytmp = NULL;
	wdevtmp = NULL;
	ifidxtmp = NULL;;
	vimactmp = NULL;;
	ifnametmp = NULL;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
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
		nla = (struct nlattr*)((unsigned char*)NLMSG_DATA(nlh) + sizeof(struct genlmsghdr));
		nlremlen = NLMSG_PAYLOAD(nlh, 0) -4;
		while(nla_ok(nla, nlremlen))
			{
			if(nla->nla_type == NL80211_ATTR_WDEV) wdevtmp = nla_data(nla);
			if(nla->nla_type == NL80211_ATTR_IFINDEX) ifidxtmp = nla_data(nla);
			if(nla->nla_type == NL80211_ATTR_IFNAME) ifnametmp = nla_data(nla);
			if(nla->nla_type == NL80211_ATTR_WIPHY) wiphytmp = nla_data(nla);
			if(nla->nla_type == NL80211_ATTR_MAC)
				{
				if(nla->nla_len == 10) vimactmp = nla_data(nla);
				}
			nla = nla_next(nla, &nlremlen);
			}
		for(ii = 0; ii < ifpresentlistcounter; ii++)
			{
			if((ifpresentlist + ii)->wiphy == *(int*)wiphytmp)
				{
				if(ifidxtmp != NULL) (ifpresentlist + ii)->index = *(u32*)ifidxtmp;
				if(wdevtmp != NULL)
					{
					if((ifpresentlist + ii)->wdev != 0)
						{
						if((ifpresentlist + ii)->wdev != *(u64*)wdevtmp) (ifpresentlist + ii)->type |= IF_IS_SHARED;
						}
					(ifpresentlist + ii)->wdev = *(u64*)wdevtmp;
					}
				if(vimactmp != NULL)memcpy((ifpresentlist + ii)->vimac, vimactmp, ETH_ALEN);
				if(ifnametmp != NULL)strncpy((ifpresentlist + ii)->name, ifnametmp, IF_NAMESIZE);
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
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
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
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
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
		nla = (struct nlattr*)((unsigned char*)NLMSG_DATA(nlh) + sizeof(struct genlmsghdr));
		nlremlen = NLMSG_PAYLOAD(nlh, 0) -4;
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
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
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
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
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
		nla = (struct nlattr*)((unsigned char*)NLMSG_DATA(nlh) + sizeof(struct genlmsghdr));
		nlremlen = NLMSG_PAYLOAD(nlh, 0) -4;
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
static bool nl_get_interfacephylist(void)
{
static ssize_t i;
static size_t ii;
static ssize_t msglen;
static int nlremlen;
static size_t dnlen;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;
static char *drivername = NULL;
static char driverfmt[DRIVER_FORMAT] = { 0 };
static char driverlink[DRIVER_LINK] = { 0 };

nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = nlfamily;
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK;
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
i += 4;
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return false;
ii = 0;
while(ii <= ifpresentlistcounter)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
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
		nla = (struct nlattr*)((unsigned char*)NLMSG_DATA(nlh) + sizeof(struct genlmsghdr));
		nlremlen = NLMSG_PAYLOAD(nlh, 0) -4;
		while(nla_ok(nla, nlremlen))
			{
			if(nla->nla_type == NL80211_ATTR_WIPHY)
				{
				(ifpresentlist + ii)->wiphy = *((u32*)nla_data(nla));
				snprintf(driverfmt, DRIVER_FORMAT, "/sys/class/ieee80211/phy%d/device/driver", (ifpresentlist + ii)->wiphy);
				memset(driverlink, 0, DRIVER_LINK);
				if((dnlen = readlink(driverfmt, driverlink, DRIVER_LINK)) > 0)
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
	ii += 1;
	}
return false;
}
/*---------------------------------------------------------------------------*/
static bool nl_get_interfacephycount(void)
{
static ssize_t i;
static ssize_t msglen;
static struct nlmsghdr *nlh;
static struct genlmsghdr *glh;
static struct nlattr *nla;
static struct nlmsgerr *nle;

nlh = (struct nlmsghdr*)nltxbuffer;
nlh->nlmsg_type = nlfamily;
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP | NLM_F_ACK;
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
i += 4;
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return false;
ifpresentlistcounter = 0;
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
		{
		if(nlh->nlmsg_type == NLMSG_DONE) return true;
		if(nlh->nlmsg_type == NLMSG_ERROR)
			{
			nle = (struct nlmsgerr*)(nlrxbuffer + sizeof(struct nlmsghdr));
			if(nle->error == 0) return true;
			errorcount++;
			return 0;
			}
		}
	ifpresentlistcounter += 1;
	}
return false;
}
/*---------------------------------------------------------------------------*/
static inline __attribute__((always_inline)) bool nl_set_frequency(void)
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
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
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
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i)
	{
	#ifdef HCXDEBUG
	fprintf(fh_debug, "nl_set_frequency failed: %s\n", strerror(errno));
	#endif
	return false;
	}
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
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
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
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
if((write(fd_socket_nl, nltxbuffer, i)) != i)
	{
	#ifdef HCXDEBUG
	fprintf(fh_debug, "nl_set_powersave_off failed: %s\n", strerror(errno));
	#endif
	return;
	}
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
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
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
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
if(((ifakttype & IFTYPEMONACT) == IFTYPEMONACT) && (activemonitorflag == true))
	{
	nla = (struct nlattr*)(nltxbuffer + i);
	nla->nla_len = 8;
	nla->nla_type = NL80211_ATTR_MNTR_FLAGS;
	nla = (struct nlattr*)nla_data(nla);
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
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
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
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
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
memcpy(nltxbuffer + i + 4, macclientrg, ETH_ALEN +2);
i += 12;
nlh->nlmsg_len = i;
if((write(fd_socket_rt, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_rt, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
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
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
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
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
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
nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
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
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
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

static size_t ii;
static ssize_t i;
static ssize_t msglen;
static struct nlmsghdr *nlh;
static struct ifinfomsg *ifih;
static struct nlmsgerr *nle;
static struct rtattr *rta;
static int rtaremlen;
static u8 *hwmactmp;

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
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
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
		rta = (struct rtattr*)((unsigned char*)NLMSG_DATA(nlh) + sizeof(struct ifinfomsg));
		rtaremlen = NLMSG_PAYLOAD(nlh, 0) - sizeof(struct ifinfomsg);
		hwmactmp = NULL;
		while(RTA_OK(rta, rtaremlen))
			{
			#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
			if(rta->rta_type == IFLA_PERM_ADDRESS)
				{
				if(rta->rta_len == 10) hwmactmp = rta_data(rta);
				}
			#else
			if(rta->rta_type == IFLA_ADDRESS)
				{
				if(rta->rta_len == 10) hwmactmp = rta_data(rta);
				}
			#endif
			rta = RTA_NEXT(rta, rtaremlen);
			}
		for(ii = 0; ii < ifpresentlistcounter; ii++)
			{
			if((ifpresentlist + ii)->index == ifih->ifi_index)
				{
				if(hwmactmp != 0) memcpy((ifpresentlist + ii)->hwmac, hwmactmp, ETH_ALEN);
				}
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
memcpy(nltxbuffer + i, NL80211_GENL_NAME, sizeof(NL80211_GENL_NAME));
i += sizeof(NL80211_GENL_NAME);
nla->nla_len = sizeof(struct nlattr) + sizeof(NL80211_GENL_NAME);
nlh->nlmsg_len = i;
if((write(fd_socket_nl, nltxbuffer, i)) != i) return false;
while(1)
	{
	msglen = read(fd_socket_nl, &nlrxbuffer, NLRX_SIZE);
	if(msglen == -1) break;
	if(msglen == 0) break;
	for(nlh = (struct nlmsghdr*)nlrxbuffer; NLMSG_OK(nlh, (u32)msglen); nlh = NLMSG_NEXT(nlh, msglen))
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
		nla = (struct nlattr*)((unsigned char*)NLMSG_DATA(nlh) + sizeof(struct genlmsghdr));
		nlremlen = NLMSG_PAYLOAD(nlh, 0) -4;
		while(nla_ok(nla, nlremlen))
			{
			if(nla->nla_type == CTRL_ATTR_FAMILY_ID) nlfamily = *((u16*)nla_data(nla));
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
			ifaktwiphy = (ifpresentlist + i)->wiphy;
			ifaktindex = (ifpresentlist + i)->index;
			ifakttype = (ifpresentlist + i)->type;
			memcpy(ifaktname, (ifpresentlist + i)->name, IF_NAMESIZE);
			memcpy(ifakthwmac, (ifpresentlist + i)->hwmac, ETH_ALEN);
			ifaktfrequencylist = (ifpresentlist + i)->frequencylist;
			break;
			}
		}
	}
else
	{
	for(i = 0; i < ifpresentlistcounter; i++)
		{
		if((ifpresentlist + i)->index == ifaktindex)
			{
			if(((ifpresentlist + i)->type & IF_HAS_NLMON) == 0) return false;
			ifakttype = (ifpresentlist + i)->type;
			memcpy(ifakthwmac, (ifpresentlist + i)->hwmac, ETH_ALEN);
			ifaktfrequencylist = (ifpresentlist + i)->frequencylist;
			break;
			}
		}
	}
if(ifaktfrequencylist == NULL) return false;
if(rt_set_interface(0) == false) return false;
if(rt_set_interfacemac() == false) vmflag = false;
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
			#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
			else if(userband[0] == 'c') ufreq = channel_to_frequency(uband, NL80211_BAND_6GHZ);
			else if(userband[0] == 'd') ufreq = channel_to_frequency(uband, NL80211_BAND_60GHZ);
			else if(userband[0] == 'e') ufreq = channel_to_frequency(uband, NL80211_BAND_S1GHZ);
			#endif
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
if(nl_get_interfacephycount() == false) return false;
if((ifpresentlist = (interface_t*)calloc(ifpresentlistcounter, INTERFACELIST_SIZE)) == NULL) return false;
for(i = 0; i < ifpresentlistcounter; i++)
	{
	if(((ifpresentlist + i)->frequencylist = (frequencylist_t*)calloc(FREQUENCYLIST_MAX, FREQUENCYLIST_SIZE)) == NULL) return false;
	}
#ifdef HCXDEBUG
debugtms = clock();
#endif
if(nl_get_interfacephylist() == false) return false;
#ifdef HCXDEBUG
debugtms = clock() - debugtms;
debugtmstaken = ((double)debugtms)/CLOCKS_PER_SEC;
fprintf(fh_debug, "nl_get_interfacephylist took %f seconds to execute \n", debugtmstaken);
#endif

#ifdef HCXDEBUG
debugtms = clock();
#endif
if(nl_get_interfacelist() == false) return false;
#ifdef HCXDEBUG
debugtms = clock() - debugtms;
debugtmstaken = ((double)debugtms)/CLOCKS_PER_SEC;
fprintf(fh_debug, "nl_get_interfacelist took %f seconds to execute \n", debugtmstaken);
#endif

#ifdef HCXDEBUG
debugtms = clock();
#endif
if(rt_get_interfacelist() == false) return false;
#ifdef HCXDEBUG
debugtms = clock() - debugtms;
debugtmstaken = ((double)debugtms)/CLOCKS_PER_SEC;
fprintf(fh_debug, "rt_get_interfacelist took %f seconds to execute \n", debugtmstaken);
#endif


if(ifpresentlistcounter == 0) return false;
qsort(ifpresentlist, ifpresentlistcounter, INTERFACELIST_SIZE, sort_interfacelist_by_wiphy);
return true;
}
/*===========================================================================*/
/* RAW PACKET SOCKET */
static bool open_socket_tx(void)
{
static struct sockaddr_ll saddr;
static struct packet_mreq mrq;
static int socket_tx_flags;
static int prioval;
static socklen_t priolen;

if((fd_socket_tx = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL))) < 0) return false;
memset(&mrq, 0, sizeof(mrq));
mrq.mr_ifindex = ifaktindex;
mrq.mr_type = PACKET_MR_PROMISC;
if(setsockopt(fd_socket_tx, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mrq, sizeof(mrq)) < 0) return false;
priolen = sizeof(prioval);
prioval = 20;
if(setsockopt(fd_socket_tx, SOL_SOCKET, SO_PRIORITY, &prioval, priolen) < 0) return false;
memset(&saddr, 0, sizeof(saddr));
saddr.sll_family = AF_PACKET;
saddr.sll_ifindex = ifaktindex;
saddr.sll_protocol = htons(ETH_P_ALL);
saddr.sll_halen = ETH_ALEN;
saddr.sll_pkttype = PACKET_OTHERHOST;
if(bind(fd_socket_tx, (struct sockaddr*) &saddr, sizeof(saddr)) < 0) return false;
if((socket_tx_flags = fcntl(fd_socket_tx, F_GETFL, 0)) < 0) return false;
if(fcntl(fd_socket_tx, F_SETFL, socket_tx_flags | O_NONBLOCK) < 0) return false;
return true;
}
/*---------------------------------------------------------------------------*/
static bool open_socket_rx(char *bpfname)
{
static size_t c = 10;
static struct sockaddr_ll saddr;
static struct packet_mreq mrq;
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
 static int enable = 1;
#endif
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
if((fd_socket_rx = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL))) < 0) return false;
memset(&mrq, 0, sizeof(mrq));
mrq.mr_ifindex = ifaktindex;
mrq.mr_type = PACKET_MR_PROMISC;
if(setsockopt(fd_socket_rx, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mrq, sizeof(mrq)) < 0) return false;
priolen = sizeof(prioval);
prioval = 20;
if(setsockopt(fd_socket_rx, SOL_SOCKET, SO_PRIORITY, &prioval, priolen) < 0) return false;
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
if(setsockopt(fd_socket_rx, SOL_PACKET, PACKET_IGNORE_OUTGOING, &enable, sizeof(int)) < 0) fprintf(stderr, "PACKET_IGNORE_OUTGOING is not supported by kernel\nfalling back to validate radiotap header length\n");
#endif
if(bpf.len > 0)
	{
	if(setsockopt(fd_socket_rx, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0)
		{
		fprintf(stderr, "failed to attach BPF (SO_ATTACH_FILTER): %s\n", strerror(errno));
		#ifdef HCXDEBUG
		fprintf(fh_debug, "SO_ATTACH_FILTER failed: %s\n", strerror(errno));
		#endif
		return false;
		}
	}
memset(&saddr, 0, sizeof(saddr));
saddr.sll_family = AF_PACKET;
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
if((fd_socket_unix = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)) < 0) return false;
return true;
}
/*---------------------------------------------------------------------------*/
static bool open_socket_rt(void)
{
static struct sockaddr_nl saddr;
static int nltxbuffsize = NLTX_SIZE;
static int nlrxbuffsize = NLRX_SIZE;

if((fd_socket_rt = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)) < 0) return false;
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

if((fd_timer1 = timerfd_create(CLOCK_BOOTTIME, 0)) < 0) return false;
tval1.it_value.tv_sec = TIMER1_VALUE_SEC;
tval1.it_value.tv_nsec = TIMER1_VALUE_NSEC;
tval1.it_interval.tv_sec = TIMER1_INTERVAL_SEC;
tval1.it_interval.tv_nsec = TIMER1_INTERVAL_NSEC;
if(timerfd_settime(fd_timer1, 0, &tval1, NULL) == -1) return false;
return true;
}
/*===========================================================================*/
/* FTC */
static void save_ftc(void)
{
static char ftcname[PATH_MAX] = { 0 };

strncpy(ftcname, pwd->pw_dir, PATH_MAX -10);
strcat(ftcname, "/.hcxftc");
clock_gettime(CLOCK_REALTIME, &tspecakt);
if((fd_fakeclock = open(ftcname, O_WRONLY | O_TRUNC | O_CREAT, 0644)) > 0)
	{
	if(write(fd_fakeclock, &tspecakt, sizeof(struct timespec)) != sizeof(struct timespec)) fprintf(stderr, "failed to write timestamp\n");
	close(fd_fakeclock);
	}
return;
}
/*---------------------------------------------------------------------------*/
static void set_ftc(void)
{
static struct timespec tssaved = { 0 };
static char ftcname[PATH_MAX] = { 0 };

clock_gettime(CLOCK_REALTIME, &tspecakt);
strncpy(ftcname, pwd->pw_dir, PATH_MAX -10);
strcat(ftcname, "/.hcxftc");
if((fd_fakeclock = open(ftcname, O_RDONLY)) > 0)
	{
	if(read(fd_fakeclock, &tssaved, sizeof(struct timespec)) == sizeof(struct timespec))
		{
		if(tspecakt.tv_sec < tssaved.tv_sec) clock_settime(CLOCK_REALTIME, &tssaved);
		}
	close(fd_fakeclock);
	}
save_ftc();
return;
}
/*===========================================================================*/
/* SIGNALHANDLER */
static void signal_handler(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL) || (signum == SIGTSTP)) wanteventflag |= EXIT_ON_SIGTERM;
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

clock_gettime(CLOCK_REALTIME, &tspecakt);
tsakt = ((u64)tspecakt.tv_sec * TSSECOND1) + tspecakt.tv_nsec;
strftime(timestring, TIMESTRING_LEN, "%Y%m%d%H%M%S", localtime(&tspecakt.tv_sec));
seed += (unsigned int)tspecakt.tv_nsec & 0xffffffff;
srand(seed);
ouiaprg = (vendoraprg[rand() % ((VENDORAPRG_SIZE / sizeof(int)))]) &0xffffff;
nicaprg = rand() & 0xffffff;
macaprghidden[5] = nicaprg & 0xff;
macaprghidden[4] = (nicaprg >> 8) & 0xff;
macaprghidden[3] = (nicaprg >> 16) & 0xff;
macaprghidden[2] = ouiaprg & 0xff;
macaprghidden[1] = (ouiaprg >> 8) & 0xff;
macaprghidden[0] = (ouiaprg >> 16) & 0xff;
nicaprg++;
macaprg[5] = nicaprg & 0xff;
macaprg[4] = (nicaprg >> 8) & 0xff;
macaprg[3] = (nicaprg >> 16) & 0xff;
macaprg[2] = ouiaprg & 0xff;
macaprg[1] = (ouiaprg >> 8) & 0xff;
macaprg[0] = (ouiaprg >> 16) & 0xff;
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
eapolm1wpa1data[0x17] = (replaycountrg >> 8) &0xff;
eapolm1wpa1data[+0x18] = replaycountrg &0xff;
eapolm1wpa2data[0x17] = (replaycountrg >> 8) &0xff;
eapolm1wpa2data[+0x18] = replaycountrg &0xff;
for(i = 0; i < 32; i++)
	{
	anoncerg[i] = rand() % 0xff;
	eapolm1wpa1data[i + 0x19] = anoncerg[i];
	eapolm1wpa2data[i + 0x19] = anoncerg[i];
	snoncerg[i] = rand() % 0xff;
	}
packetptr = &epb[EPB_SIZE];
memcpy(wltxbuffer, rthtxdata, RTHTX_SIZE);
memcpy(epbown + EPB_SIZE, rthtxdata, RTHTX_SIZE);
return;
}
/*---------------------------------------------------------------------------*/
static void close_lists(void)
{
static size_t i;

for(i = 0; i < CALIST_MAX; i++)
	{
	if((calist + i)->cadata != NULL) free((calist + i)->cadata);
	}
if(calist != NULL) free(calist);

for(i = 0; i < APRGLIST_MAX; i++)
	{
	if((aprglist + i)->apdata != NULL) free((aprglist + i)->apdata);
	}
if(aprglist != NULL) free(aprglist);

for(i = 0; i < APLIST_MAX; i++)
	{
	if((aplist + i)->apdata != NULL) free((aplist + i)->apdata);
	}
if(aplist != NULL) free(aplist);

if(scanlist != NULL) free(scanlist);
if(ifpresentlist != NULL)
	{
	for(i = 0; i < ifpresentlistcounter; i++)
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
#ifdef HCXNMEAOUT
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
for(i = 0; i < APLIST_MAX; i++)
	{
	if(((aplist + i)->apdata = (apdata_t*)calloc(1, APDATA_SIZE)) == NULL) return false;
	}

if((aprglist = (aplist_t*)calloc(APRGLIST_MAX, APLIST_SIZE)) == NULL) return false;
for(i = 0; i < APRGLIST_MAX; i++)
	{
	if(((aprglist + i)->apdata = (apdata_t*)calloc(1, APDATA_SIZE)) == NULL) return false;
	}

if((calist = (calist_t*)calloc(CALIST_MAX, CALIST_SIZE)) == NULL) return false;
for(i = 0; i < CALIST_MAX; i++)
	{
	if(((calist + i)->cadata = (cadata_t*)calloc(1, CADATA_SIZE)) == NULL) return false;
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
static struct sock_filter *bpfptr;
static FILE *fh_filter;
static char linein[128];

if((fh_filter = fopen(bpfname, "r")) == NULL) return false;
bpf.filter = (struct sock_filter*)calloc(BPF_MAXINSNS, sizeof(struct sock_filter));
if (bpf.filter == NULL) return false;
bpf.len = 0;
bpfptr = bpf.filter;
while(bpf.len < BPF_MAXINSNS +1)
	{
	if((len = fgetline(fh_filter, 128, linein)) == -1) break;
	if(bpf.len == BPF_MAXINSNS)
		{
		bpf.len = 0;
		break;
		}
	if(len < 7) continue;
	if(linein[0] != '{')
		{
		if(sscanf(linein, "%" SCNu16 "%" SCNu8 "%" SCNu8 "%" SCNu32, &bpfptr->code, &bpfptr->jt, &bpfptr->jf, &bpfptr->k) != 4)
			{
			bpf.len = 0;
			break;
			}
		}
	else
		{
		if(sscanf(linein, "{ %" SCNx16 ", %" SCNu8 ", %" SCNu8 ", %" SCNx32 " },",&bpfptr->code, &bpfptr->jt, &bpfptr->jf, &bpfptr->k) != 4)
			{
			bpf.len = 0;
			break;
			}
		}
	bpfptr++;
	bpf.len++;
	}
fclose(fh_filter);
if(bpf.len == 0) return false;
return true;
}
/*---------------------------------------------------------------------------*/
#ifdef HCXWANTLIBPCAP
static bool compile_bpf(char *bpfs, int bpfmode)
{
static u16 i;
static pcap_t *hpcap = NULL;
static struct bpf_program bpfp;
struct bpf_insn *bpfins;

if((hpcap = pcap_open_dead(DLT_IEEE802_11_RADIO, PCAPNG_SNAPLEN)) == NULL)
	{
	fprintf(stderr, "failed to open libpcap\n");
	return false;
	}
if(pcap_compile(hpcap, &bpfp, bpfs, 1, 0))
	{
	fprintf(stderr, "failed to compile BPF\n");
	return false;
	}

if(bpfmode == BPFD_HCX)
	{
	bpfins = bpfp.bf_insns;
	for(i = 0; i < bpfp.bf_len; ++bpfins, ++ i) fprintf(stdout, "%u %u %u %u\n", bpfins->code, bpfins->jt, bpfins->jf, bpfins->k);
	}
else if(bpfmode == BPFD_ASM) bpf_dump(&bpfp, 1);
else if(bpfmode == BPFD_C) bpf_dump(&bpfp, 2);
else if(bpfmode == BPFD_TCPDUMP) bpf_dump(&bpfp, 3);
else if(bpfmode == BPFD_DBG)
	{
	bpfins = bpfp.bf_insns;
	fprintf(stdout, "%u", bpfp.bf_len);
	for(i = 0; i < bpfp.bf_len; ++bpfins, ++ i) fprintf(stdout, ",%u %u %u %u", bpfins->code, bpfins->jt, bpfins->jf, bpfins->k);
	fprintf(stdout, "\n");
	}
pcap_freecode(&bpfp);
return true;
}
#endif
/*---------------------------------------------------------------------------*/
static void read_essidlist(char *listname)
{
static size_t i;
static int len;
static FILE *fh_essidlist;
static char linein[ESSID_MAX];

if((fh_essidlist = fopen(listname, "r")) == NULL)
	{
	fprintf(stderr, "failed to open ESSID list %s\n", listname);
	return;
	}
i = 0;
while(i < (APRGLIST_MAX - 1))
	{
	if((len = fgetline(fh_essidlist, ESSID_MAX, linein)) == -1) break;
	if((len == 0) || (len > ESSID_MAX)) continue;
	(aprglist + i)->tsakt = tsakt -i;
	(aprglist + i)->apdata->essidlen = len;
	memcpy((aprglist + i)->apdata->essid, linein, len);
	(aprglist + i)->apdata->maca[5] = nicaprg & 0xff;
	(aprglist + i)->apdata->maca[4] = (nicaprg >> 8) & 0xff;
	(aprglist + i)->apdata->maca[3] = (nicaprg >> 16) & 0xff;
	(aprglist + i)->apdata->maca[2] = ouiaprg & 0xff;
	(aprglist + i)->apdata->maca[1] = (ouiaprg >> 8) & 0xff;
	(aprglist + i)->apdata->maca[0] = (ouiaprg >> 16) & 0xff;
	nicaprg++;
	i++;
	}
(aprglist + i)->apdata->essidlen = 0;
fclose(fh_essidlist);
return;
}
/*===========================================================================*/
/*===========================================================================*/
/* RASPBERRY PI */
static bool init_rpi(void)
{
static FILE *modinfo;
static FILE *procinfo;
static int fd_devinfo;
static int len = 0;
static unsigned int gpioperibase = 0;
static char linein[RASPBERRY_INFO] = { 0 };

gpio_map = MAP_FAILED;
if((modinfo = fopen("/proc/device-tree/model", "r")) == NULL)
	{
	perror("failed to get model information");
	return false;
	}
len = fgetline(modinfo, RASPBERRY_INFO, linein);
fclose(modinfo);
if(len < RPINAME_SIZE) return false;
if(memcmp(rpiname, linein, RPINAME_SIZE) != 0) return false;
if((procinfo = fopen("/proc/cpuinfo", "r")) != NULL)
	{
	while(1)
		{
		if((len = fgetline(procinfo, RASPBERRY_INFO, linein)) == -1) break;
		if(len > 8)
			{
			if(strstr(linein, "Serial") != NULL)
				{
				seed += strtoul(&linein[len - 6], NULL, 16);
				}
			}
		}
	fclose(procinfo);
	}
if((fd_devinfo = open("/dev/gpiomem", O_RDWR | O_SYNC)) > 0)
	{
	gpio_map = mmap(NULL, RPI_BLOCK_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd_devinfo, gpioperibase);
	close(fd_devinfo);
	}
else
	{
	if((procinfo = fopen("/proc/iomem", "r")) != NULL)
		{
		while(1)
			{
			if((len = fgetline(procinfo, RASPBERRY_INFO, linein)) == -1) break;
			if(strstr(linein, ".gpio") != NULL)
				{
				if(linein[8] != '-') break;
					{
					linein[8] = 0;
					gpioperibase = strtoul(linein, NULL, 16);
					if(gpioperibase != 0)
						{
						if((fd_devinfo = open("/dev/mem", O_RDWR | O_SYNC)) > 0)
							{
							gpio_map = mmap(NULL, RPI_BLOCK_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd_devinfo, gpioperibase);
							close(fd_devinfo);
							}
						}
					break;
					}
				}
			}
		fclose(procinfo);
		}
	}
if(gpio_map == MAP_FAILED)
	{
	fprintf(stderr, "failed to map GPIO memory\n");
	return false;
	}
gpio = (volatile unsigned *)gpio_map;
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
struct utsname utsbuffer;

fprintf(stdout, "%s %s (C) %s ZeroBeat\n", eigenname, VERSION_TAG, VERSION_YEAR);
if(uname(&utsbuffer) == 0) fprintf(stdout, "running on Linux kernel %s\n", utsbuffer.release);
#if defined (__GLIBC__)
fprintf(stdout, "running GNU libc version %s\n", gnu_get_libc_version());
#endif
#if defined(__GNUC__) && !defined(__clang__)
fprintf(stdout, "compiled by gcc %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#elif defined(__clang__)
fprintf(stdout, "compiled by clang %d.%d.%d\n", __clang_major__, __clang_minor__, __clang_patchlevel__);
#else
fprintf(stdout, "compiler (__clang__ / __GNUC__) is not defined\n");
#endif
#if defined (LINUX_VERSION_MAJOR)
fprintf(stdout, "compiled with Linux API headers %d.%d.%d\n", LINUX_VERSION_MAJOR, LINUX_VERSION_PATCHLEVEL, LINUX_VERSION_SUBLEVEL);
#else
fprintf(stdout, "Linux API headers (LINUX_VERSION_MAJOR) is not defined\n");
#endif
#if defined (__GLIBC__)
fprintf(stdout, "compiled with GNU libc headers %d.%d\n", __GLIBC__, __GLIBC_MINOR__);
#else
fprintf(stdout, "glibc (__GLIBC_MINOR__) is not defined\n");
#endif
#ifdef HCXWANTLIBPCAP
fprintf(stdout, "enabled BPF compiler\n");
#else
fprintf(stdout, "disabled BPF compiler\n");
#endif
#ifdef HCXDEBUG
fprintf(stdout, "running in debug mode\n");
#endif
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usage_additional(char *eigenname)
{
fprintf(stdout, "%s %s  (C) %s ZeroBeat\n"
	"Additional information:\n-----------------------\n"
	"press GPIO button to terminate\n"
	" hardware modification is necessary, read more:\n"
	" https://github.com/ZerBea/hcxdumptool/tree/master/docs\n"
	"to store entire traffic, run tshark in parallel on the same interface:\n"
	" $ tshark -i <interface> -w allframes.pcapng\n"
	"\n"
	"Berkeley Packet Filter:\n"
	"-----------------------\n"
	"  see man bpfc\n"
	"\n"
	"Important recommendation:\n"
	"-------------------------\n"
	"Do not set monitor mode by third party tools or third party scripts!\n"
	"Do not use virtual interfaces (monx, wlanxmon, prismx, ...)!\n"
	"Do not use virtual machines or emulators!\n"
	"Do not run other tools that take access to the interface in parallel (except: tshark, wireshark, tcpdump)!\n"
	"Do not use tools to change the virtual MAC (like macchanger)!\n"
	"Do not merge (pcapng) dump files, because this destroys assigned hash values!\n"
	"\n",
	eigenname, VERSION_TAG, VERSION_YEAR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usage(char *eigenname)
{
fprintf(stdout, "%s %s  (C) %s ZeroBeat\n"
	"usage: %s <options>\n"
	"\n"
	"most common options:\n--------------------\n"
	"-i <INTERFACE>   : name of INTERFACE to be used\n"
	"                    default: first suitable INTERFACE\n"
	"                    warning:\n"
	"                     %s changes the mode of the INTERFACE\n"
	"                     %s changes the virtual MAC address of the INTERFACE\n"
	"                     %s changes the channel of the INTERFACE\n"
	"-w <outfile>     : write packets to a pcapng-format file named <outfile>\n"
	"                    default outfile name: yyyyddmmhhmmss-interfacename.pcapng\n"
	"                    existing file will not be overwritten\n"
	"                    get more information: https://pcapng.com/\n"
	"-c <digit>       : set channel (1a,2a,36b,...)\n"
	"                    default: 1a,6a,11a\n"
	"                    important notice: channel numbers are not unique\n"
	"                    it is mandatory to add band information to the channel number (e.g. 12a)\n"
	"                     band a: NL80211_BAND_2GHZ\n"
	"                     band b: NL80211_BAND_5GHZ\n"
	#if(LINUX_VERSION_CODE >= KERNEL_VERSION(5, 10, 0))
	"                     band c: NL80211_BAND_6GHZ\n"
	"                     band d: NL80211_BAND_60GHZ\n"
	"                     band e: NL80211_BAND_S1GHZ (902 MHz)\n"
	#endif
	"                    to disable frequency management, set this option to a single frequency/channel\n"
	"-f <digit>       : set frequency (2412,2417,5180,...)\n"
	"-F               : use all available frequencies from INTERFACE\n"
	"-t <second>      : minimum stay time (will increase on new stations and/or authentications)\n"
	"                    default %d seconds\n"
	"-A               : ACK incoming frames\n"
	"                    INTERFACE must support active monitor mode\n"
	"-L               : show PHYSICAL INTERFACE list and terminate\n"
	"-l               : show PHYSICAL INTERFACE list (tabulator separated and greppable) and terminate\n"
	"-I <INTERFACE>   : show detailed information about INTERFACE and terminate\n"
#ifdef HCXWANTLIBPCAP
	"--bpfc=<filter>  : compile Berkeley Packet Filter (BPF) and exit\n"
	"                    $ %s --bpfc=\"wlan addr3 112233445566\" > filter.bpf\n"
	"                    see man pcap-filter\n"
	"--bpfd=<mode>    : set output mode for compiled Berkeley Packet Filter (BPF)\n"
	"                    default = 0\n"
	"                    0 = compile BPF code as decimal numbers (readable by --bpf)\n"
	"                    1 = compile BPF code as decimal numbers preceded with a count (readable by --bpf)\n"
	"                    2 = compile BPF code as a C program fragment (readable by --bpf)\n"
	"                    3 = compile BPF code as a ASM program (tcpdump style)\n"
	"                    4 = compile BPF code as as decimal numbers (bpf_debug style)\n"
	"                    see man pcap-filter\n"
#endif
	"--bpf=<file>     : input Berkeley Packet Filter (BPF) code (maximum %d instructions) in tcpdump decimal numbers format\n"
	"                    see --help for more information\n", 
#ifdef HCXWANTLIBPCAP
	eigenname, VERSION_TAG, VERSION_YEAR, eigenname, eigenname, eigenname, eigenname, TIMEHOLD, eigenname, BPF_MAXINSNS);
#else
	eigenname, VERSION_TAG, VERSION_YEAR, eigenname, eigenname, eigenname, eigenname, TIMEHOLD, BPF_MAXINSNS);
#endif
fprintf(stdout, "--ftc            : enable fake time clock\n"
	"--rds=<digit>    : enable real time display\n"
	"                    attack mode:\n"
	"                     0 = off(default)\n"
	"                     1 = show APs on current channel, show CLIENTs (M1M2ROGUE)\n"
	"                     2 = show all APs (M1M2, M1M2M3 or PMKID), show CLIENTs (M1M2ROGUE)\n"
	"                     3 = show all APs, show CLIENTs (M1M2ROGUE)\n"
	"                     columns:\n"
	"                      E = encryption (e)ncrypted / (o)pen\n"
	"                      A = AKM (p)re-shared key\n"
	"                      1 = received M1\n"
	"                      2 = received M1M2\n"
	"                      3 = received M1M2M3\n"
	"                      P = received PMKID\n"
	"                    rcascan mode\n"
	"                     0 = show APs on current channel sorted by BEACON timestamp\n"
	"                     1 = show APs on current channel sorted by PROBERESPONSE timestamp\n"
	"                     2 = show APs on current channel sorted by RSSI\n"
	"--rdt            : disable TIOCGWINSZ for real time displays\n"
	"--rcascan=<mode> : radio channel assement scan\n"
	"                    (a)ctive = activ scan (transmit undirected PROBEREQUEST frames)\n"
	"                     no PROBERESPONSE, AP is out of RANGE, packet injection is broken\n"
	"                    (p)assive = passive scan (listen only)\n"
	"-h               : show this help\n"
	"-v               : show version\n"
	"\n");
fprintf(stdout, "less common options:\n--------------------\n"
	"-m <INTERFACE>            : set monitor mode and terminate\n"
	"--m2max=<digit>           : set maximum of received M1M2ROGUE\n"
	"                             default: %d M1M2ROGUE\n"
	"                             to reject CLIENTs set 0\n"
	"--associationmax=<digit>  : set maximum of attempts to associate with an AP\n"
	"                             default: %d attempts\n"
	"                             to disable association with an AP set 0\n"
	"--disable_disassociation  : do not transmit DISASSOCIATION frames\n"
	"--proberesponsetx=<digit> : transmit n PROBERESPONSEs from the ESSID ring buffer\n"
	"                             default: %d\n"
	"--essidlist=<file>        : initialize ESSID list with these ESSIDs\n"
	"--errormax=<digit>        : set maximum allowed ERRORs\n"
	"                             default: %d ERRORs\n"
	"--watchdogmax=<seconds>   : set maximum TIMEOUT when no packets received\n"
	"                             default: %d seconds\n",
	CLIENTCOUNT_MAX, APCOUNT_MAX, PROBERESPONSETX_MAX, ERROR_MAX, WATCHDOG_MAX);
fprintf(stdout, "--tot=<digit>             : enable timeout timer in minutes\n"
	"--exitoneapol=<type>      : exit on first EAPOL occurrence:\n"
	"                             bitmask:\n"
	"                               1 = PMKID (from AP)\n"
	"                               2 = EAPOL M2M3 (authorized)\n"
	"                               4 = EAPOL M1M2 (not authorized)\n"
	"                               8 = EAPOL M1M2ROGUE (not authorized)\n"
	"                              16 = EAPOL M1\n"
	"                             target BPF filter is recommended\n"
	"--onsigterm=<action>      : action when the program has been terminated (poweroff, reboot)\n"
	"                             poweroff: power off system\n"
	"                             reboot:   reboot system\n"
	"--ongpiobutton=<action>   : action when the program has been terminated (poweroff, reboot)\n"
	"                             poweroff: power off system\n"
	"                             reboot:   reboot system\n"
	"--ontot=<action>          : action when the program has been terminated (poweroff, reboot)\n"
	"                             poweroff: power off system\n"
	"                             reboot:   reboot system\n"
	"--onwatchdog=<action>     : action when the program has been terminated (poweroff, reboot)\n"
	"                             poweroff: power off system\n"
	"                             reboot:   reboot system\n"
	"--onerror=<action>        : action when the program has been terminated (poweroff, reboot)\n"
	"                             poweroff: power off system\n"
	"                             reboot:   reboot system\n"
	"--gpio_button=<digit>     : Raspberry Pi GPIO pin number of button (2...27)\n"
	"                             push GPIO button (> 10 seconds) to terminate program\n"
	"                             default: 0 (GPIO not in use)\n"
	"--gpio_statusled=<digit>  : Raspberry Pi GPIO number of status LED (2...27)\n"
	"                             default: 0 (GPIO not in use)\n"
	"--help                    : show additional help (example and trouble shooting)\n"
	"--version                 : show version\n\n");
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usageerror(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s by ZeroBeat\n"
	"This is a penetration testing tool!\n"
	"It is made to detect vulnerabilities in your NETWORK mercilessly!\n"
	"\n"
	"usage:\n"
	" $ %s -h for an overview of all options\n"
	" $ %s --help for an example and trouble shooting\n",
	 eigenname, VERSION_TAG, VERSION_YEAR, eigenname, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl = -1;
static int index = 0;
#ifdef HCXWANTLIBPCAP
static int bpfdmode = 0;
#endif
static u8 exiteapolflag = 0;
static u8 exitsigtermflag = 0;
static u8 exitgpiobuttonflag = 0;
static u8 exittotflag = 0;
static u8 exitwatchdogflag = 0;
static u8 exiterrorflag = 0;
static struct timespec tspecifo, tspeciforem;
static struct tpacket_stats lStats = { 0 };
static socklen_t lStatsLength = sizeof(lStats);
static char *bpfname = NULL;
#ifdef HCXWANTLIBPCAP
static char *bpfstring = NULL;
#endif
static bool monitormodeflag = false;
static bool interfaceinfoflag = false;
static bool interfacefrequencyflag = false;
static bool interfacelistflag = false;
static bool interfacelistshortflag = false;
static bool rooterrorflag = false;
static char *essidlistname = NULL;
static char *userchannellistname = NULL;
static char *userfrequencylistname = NULL;
static char *pcapngoutname = NULL;
#ifdef HCXNMEAOUT
static bool gpsdflag = false;
static char *nmea0183name = NULL;
static char *nmeaoutname = NULL;
#endif
static const char *rebootstring = "reboot";
static const char *poweroffstring = "poweroff";
static const char *short_options = "i:w:c:f:m:I:t:FLlAhHv";
static const struct option long_options[] =
{
	{"bpf",				required_argument,	NULL,	HCX_BPF},
#ifdef HCXWANTLIBPCAP
	{"bpfc",			required_argument,	NULL,	HCX_BPFC},
	{"bpfd",			required_argument,	NULL,	HCX_BPFD},
#endif
	{"ftc",				no_argument,		NULL,	HCX_FTC},
	{"disable_disassociation",	no_argument,		NULL,	HCX_DISABLE_DISASSOCIATION},
	{"m2max",			required_argument,	NULL,	HCX_M1M2ROGUE_MAX},
	{"associationmax",		required_argument,	NULL,	HCX_APCOUNT_MAX},
	{"prtxmax",			required_argument,	NULL,	HCX_PRTX_MAX},
	{"tot",				required_argument,	NULL,	HCX_TOT},
	{"essidlist",			required_argument,	NULL,	HCX_ESSIDLIST},
	{"errormax",			required_argument,	NULL,	HCX_ERROR_MAX},
	{"watchdogmax",			required_argument,	NULL,	HCX_WATCHDOG_MAX},
	{"onsigterm",			required_argument,	NULL,	HCX_ON_SIGTERM},
	{"ongpiobutton",		required_argument,	NULL,	HCX_ON_GPIOBUTTON},
	{"ontot",			required_argument,	NULL,	HCX_ON_TOT},
	{"onwatchdog",			required_argument,	NULL,	HCX_ON_WATCHDOG},
	{"exitoneapol",			required_argument,	NULL,	HCX_EXIT_ON_EAPOL},
	{"onerror",			required_argument,	NULL,	HCX_ON_ERROR},
	{"gpio_button",			required_argument,	NULL,	HCX_GPIO_BUTTON},
	{"gpio_statusled",		required_argument,	NULL,	HCX_GPIO_STATUSLED},
	{"rds",				required_argument,	NULL,	HCX_RDS},
	{"rdt",				no_argument,		NULL,	HCX_RDT},
	{"rcascan",			required_argument,	NULL,	HCX_RCASCAN},
	{"version",			no_argument,		NULL,	HCX_VERSION},
	{"help",			no_argument,		NULL,	HCX_HELP_ADDITIONAL},
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
		strncpy(ifaktname, optarg, IF_NAMESIZE);
		break;

		case HCX_BPF:
		bpfname = optarg;
		break;

#ifdef HCXWANTLIBPCAP
		case HCX_BPFC:
		bpfstring = optarg;
		if(strlen(bpfstring) < 2)
			{
			fprintf(stderr, "BPF ERROR\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_BPFD:
		bpfdmode = atoi(optarg);
		if(bpfdmode > BPFD_DBG)
			{
			fprintf(stderr, "BPF mode ERROR (allowed 0 to 4)\n");
			exit(EXIT_FAILURE);
			}
		break;
#endif
		case HCX_FTC:
		ftcflag = true;
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

		case HCX_DISABLE_DISASSOCIATION:
		disassociationflag = false;
		break;

		case HCX_PRTX_MAX:
		proberesponsetxmax = strtoul(optarg, NULL, 10);
		break;

		case HCX_M1M2ROGUE_MAX:
		clientcountmax = strtoul(optarg, NULL, 10);
		break;

		case HCX_APCOUNT_MAX:
		apcountmax = strtoul(optarg, NULL, 10);
		break;

		case HCX_HOLD_TIME:
		if((timehold = strtoull(optarg, NULL, 10)) < 5)
			{
			fprintf(stderr, "hold time must be >= 5 seconds");
			exit(EXIT_FAILURE);
			}
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
		if((timewatchdog = strtoul(optarg, NULL, 10)) < 1)
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

		case HCX_EXIT_ON_EAPOL:
		exiteapolflag = (atoi(optarg) & 0x0f) << 4;
		exiteapolpmkidflag |= exiteapolflag & EXIT_ON_EAPOL_PMKID;
		exiteapolm3flag |= exiteapolflag & EXIT_ON_EAPOL_M3;
		exiteapolm2rgflag |= exiteapolflag & EXIT_ON_EAPOL_M2RG;
		exiteapolm1flag |= exiteapolflag & EXIT_ON_EAPOL_M1;
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
		if(interfacelistshortflag == true)
			{
			fprintf(stderr, "combination of options -L and -l is not allowed\n");
			exit(EXIT_FAILURE);
			}
		interfacelistflag = true;
		break;

		case HCX_SHOW_INTERFACE_LIST_SHORT:
		if(interfacelistflag == true)
			{
			fprintf(stderr, "combination of options -L and -l is not allowed\n");
			exit(EXIT_FAILURE);
			}
		interfacelistshortflag = true;
		break;

		case HCX_SET_MONITORMODE_ACTIVE:
		activemonitorflag = true;
		break;

		case HCX_RDS:
		rds = strtol(optarg, NULL, 10);
		break;

		case HCX_RDT:
		rdtflag = true;
		break;

		case HCX_RCASCAN:
		if(optarg[0] == 'a') rcascanmode = RCASCAN_ACTIVE;
		else if(optarg[0] == 'p') rcascanmode = RCASCAN_PASSIVE;
		else
			{
			fprintf(stderr, "only (a)ctive or (p)assive is allowed\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_HELP:
		usage(basename(argv[0]));
		break;

		case HCX_HELP_ADDITIONAL:
		usage_additional(basename(argv[0]));
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
uid = getuid();
pwd = getpwuid(uid);
if((uid == 0) && (ftcflag == true)) set_ftc();
hcxpid = getpid();
#ifdef HCXDEBUG
if((fh_debug = fopen("hcxerror.log", "a")) == NULL)
	{
	fprintf(stdout, "error opening hcxerror.log: %s\n", strerror(errno));
	goto byebye;
	}
#endif
#ifdef HCXWANTLIBPCAP
if(bpfstring != NULL)
	{
	if(compile_bpf(bpfstring, bpfdmode) == true) exit(EXIT_SUCCESS);
	else exit(EXIT_FAILURE);
	}
#endif
if(set_signal_handler() == false)
	{
	errorcount++;
	fprintf(stderr, "failed to initialize signal handler\n");
	wanteventflag |= EXIT_ON_ERROR;
	goto byebye;
	}
if((gpiobutton + gpiostatusled) > 0)
	{
	if(init_rpi() == false)
		{
		errorcount++;
		fprintf(stderr, "failed to initialize Raspberry Pi GPIO\n");
		wanteventflag |= EXIT_ON_ERROR;
		goto byebye;
		}
	if(gpiobutton > 0)
		{
		if(GET_GPIO(gpiobutton) > 0)
			{
			wanteventflag = EXIT_ON_SIGTERM;
			if(gpiostatusled > 0) GPIO_SET = 1 << gpiostatusled;
			goto byebye;
			}
		}
	}
if(init_lists() == false)
	{
	errorcount++;
	fprintf(stderr, "failed to initialize lists\n");
	wanteventflag |= EXIT_ON_ERROR;
	goto byebye;
	}
init_values();
/*---------------------------------------------------------------------------*/
if(open_control_sockets() == false)
	{
	errorcount++;
	fprintf(stderr, "failed to open control sockets\n");
	wanteventflag |= EXIT_ON_ERROR;
	goto byebye;
	}
if(get_interfacelist() == false)
	{
	errorcount++;
	fprintf(stderr, "failed to get interface list\n");
	wanteventflag |= EXIT_ON_ERROR;
	goto byebye;
	}
if(interfacelistflag == true)
	{
	show_interfacelist();
	goto byebye;
	}
if(interfacelistshortflag == true)
	{
	show_interfacelist_short();
	goto byebye;
	}
if(interfaceinfoflag == true)
	{
	show_interfacecapabilities();
	goto byebye;
	}
/*---------------------------------------------------------------------------*/
if(uid != 0)
	{
	errorcount++;
	fprintf(stderr, "%s must be run as root\n", basename(argv[0]));
	rooterrorflag = true;
	goto byebye;
	}
if(set_interface(interfacefrequencyflag, userfrequencylistname, userchannellistname) == false)
	{
	errorcount++;
	wanteventflag |= EXIT_ON_ERROR;
	fprintf(stderr, "failed to arm interface\n");
	goto byebye;
	}
if(monitormodeflag == true)
	{
	if(set_monitormode() == false)
		{
		errorcount++;
		wanteventflag |= EXIT_ON_ERROR;
		fprintf(stderr, "failed to set monitor mode\n");
		}
	if((userfrequencylistname != NULL) || (userchannellistname != 0))
		{
		if(nl_set_frequency() == false)
			{
			errorcount++;
			wanteventflag |= EXIT_ON_ERROR;
			fprintf(stderr, "failed to set frequency\n");
			}
		}
	goto byebye;
	}
if(essidlistname != NULL) read_essidlist(essidlistname);
if(rcascanmode == 0)
	{
	if(open_pcapng(pcapngoutname) == false)
		{
		errorcount++;
		wanteventflag |= EXIT_ON_ERROR;
		fprintf(stderr, "failed to open dump file\n");
		goto byebye;
		}
	}
if(open_socket_rx(bpfname) == false)
	{
	errorcount++;
	wanteventflag |= EXIT_ON_ERROR;
	fprintf(stderr, "failed to open raw packet socket\n");
	goto byebye;
	}
if(open_socket_tx() == false)
	{
	errorcount++;
	wanteventflag |= EXIT_ON_ERROR;
	fprintf(stderr, "failed to open transmit socket\n");
	goto byebye;
	}
if(set_timer() == false)
	{
	errorcount++;
	wanteventflag |= EXIT_ON_ERROR;
	fprintf(stderr, "failed to initialize timer\n");
	goto byebye;
	}
/*---------------------------------------------------------------------------*/
tspecifo.tv_sec = 5;
tspecifo.tv_nsec = 0;
fprintf(stdout, "\nThis is a highly experimental penetration testing tool!\n"
		"It is made to detect vulnerabilities in your NETWORK mercilessly!\n"
		"Misuse within a network, without specific authorization, may cause\n"
		"irreparable damage and result in significant consequences!\n"
		"Not understanding what you were doing is not going to work as an excuse!\n\n");
if(vmflag == false) fprintf(stdout, "Failed to set virtual MAC!\n");
if((bpf.len == 0) && (rcascanmode == 0)) fprintf(stderr, "BPF is unset! Make sure hcxdumptool is running in a 100%% controlled environment!\n\n");
fprintf(stdout, "starting...\033[?25l\n");
nanosleep(&tspecifo, &tspeciforem);

if(rcascanmode > 0)
	{
	if(nl_scanloop_rcascan() == false)
		{
		errorcount++;
		fprintf(stderr, "failed to initialize rcascan scan loop\n");
		}
	}
else if(rds == 0)
	{
	if(nl_scanloop() == false)
		{
		errorcount++;
		fprintf(stderr, "failed to initialize main scan loop\n");
		}
	}
else
	{
	if(nl_scanloop_rds() == false)
		{
		errorcount++;
		fprintf(stderr, "failed to initialize main scan loop\n");
		}
	}
/*---------------------------------------------------------------------------*/
byebye:
#ifdef HCXDEBUG
if(fh_debug != NULL) fclose(fh_debug);
#endif
if((monitormodeflag != true) && (interfacelistflag != true) && (interfaceinfoflag != true) && (interfacelistshortflag != true) && (rooterrorflag == false))
	{
	if(getsockopt(fd_socket_rx, SOL_PACKET, PACKET_STATISTICS, &lStats, &lStatsLength) != 0) fprintf(stdout, "PACKET_STATISTICS failed\n");
	}
close_fds();
close_sockets();
close_lists();

if(rooterrorflag == true) exit(EXIT_FAILURE);
if((monitormodeflag == true) || (interfacelistflag == true) || (interfaceinfoflag == true) || (interfacelistshortflag == true)) return EXIT_SUCCESS;
fprintf(stdout, "\n\033[?25h");
if(errorcount > 0) fprintf(stderr, "%u ERROR(s) during runtime (mostly caused by a broken driver)\n", errorcount);
if(errortxcount > 0) fprintf(stderr, "%u TX ERROR(s) during runtime (mostly caused by a broken driver)\n", errortxcount);
fprintf(stdout, "%u Packet(s) captured by kernel\n", lStats.tp_packets);
fprintf(stdout, "%u Packet(s) dropped by kernel\n", lStats.tp_drops);
if((uid == 0) && (ftcflag == true)) save_ftc();
if(exiteapolflag != 0)
	{
	if((wanteventflag & EXIT_ON_EAPOL_PMKID) == EXIT_ON_EAPOL_PMKID) fprintf(stdout, "exit on PMKID\n");
	if((wanteventflag & EXIT_ON_EAPOL_M3) == EXIT_ON_EAPOL_M3) fprintf(stdout, "exit on EAPOL M1M2M3\n");
	if((wanteventflag & EXIT_ON_EAPOL_M2) == EXIT_ON_EAPOL_M2) fprintf(stdout, "exit on EAPOL M1M2\n");
	if((wanteventflag & EXIT_ON_EAPOL_M2RG) == EXIT_ON_EAPOL_M2RG) fprintf(stdout, "exit on EAPOL M1M2ROGUE\n");
	if((wanteventflag & EXIT_ON_EAPOL_M1) == EXIT_ON_EAPOL_M1) fprintf(stdout, "exit on EAPOL M1\n");
	}
if((wanteventflag & EXIT_ON_SIGTERM) == EXIT_ON_SIGTERM)
	{
	fprintf(stdout, "exit on sigterm\n");
	if(exitsigtermflag == EXIT_ACTION_REBOOT)
		{
		if(system("reboot") != 0) fprintf(stderr, "can't reboot system\n");
		}
	else if(exitsigtermflag == EXIT_ACTION_POWEROFF)
		{
		if(system("poweroff") != 0) fprintf(stderr, "can't power off\n");
		}
	}
else if((wanteventflag & EXIT_ON_GPIOBUTTON) == EXIT_ON_GPIOBUTTON)
	{
	fprintf(stdout, "exit on GPIO button\n");
	if(exitgpiobuttonflag == EXIT_ACTION_REBOOT)
		{
		if(system("reboot") != 0) fprintf(stderr, "can't reboot system\n");
		}
	else if(exitgpiobuttonflag == EXIT_ACTION_POWEROFF)
		{
		if(system("poweroff") != 0) fprintf(stderr, "can't power off\n");
		}
	}
else if((wanteventflag & EXIT_ON_TOT) == EXIT_ON_TOT)
	{
	fprintf(stdout, "exit on TOT\n");
	if(exittotflag == EXIT_ACTION_REBOOT)
		{
		if(system("reboot") != 0) fprintf(stderr, "can't reboot system\n");
		}
	else if(exittotflag == EXIT_ACTION_POWEROFF)
		{
		if(system("poweroff") != 0) fprintf(stderr, "can't power off\n");
		}
	}
else if((wanteventflag & EXIT_ON_WATCHDOG) == EXIT_ON_WATCHDOG)
	{
	fprintf(stdout, "exit on watchdog\n");
	if(exitwatchdogflag == EXIT_ACTION_REBOOT)
		{
		if(system("reboot") != 0) fprintf(stderr, "can't reboot system\n");
		}
	else if(exitwatchdogflag == EXIT_ACTION_POWEROFF)
		{
		if(system("poweroff") != 0) fprintf(stderr, "can't power off\n");
		}
	}
else if((wanteventflag & EXIT_ON_ERROR) == EXIT_ON_ERROR)
	{
	fprintf(stdout, "exit on error\n");
	if(exiterrorflag == EXIT_ACTION_REBOOT)
		{
		if(system("reboot") != 0) fprintf(stderr, "can't reboot system\n");
		}
	else if(exiterrorflag == EXIT_ACTION_POWEROFF)
		{
		if(system("poweroff") != 0) fprintf(stderr, "can't power off\n");
		}
	}
return EXIT_SUCCESS;
}
/*===========================================================================*/
