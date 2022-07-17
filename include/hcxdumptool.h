#define HCX_DO_RCASCAN				1
#define HCX_RCASCAN_MAX				2
#define HCX_RCASCAN_ORDER			3
#define HCX_DO_TARGETSCAN			4
#define HCX_DEAUTH_REASON_CODE			5
#define HCX_DISABLE_DEAUTHENTICATION		6
#define HCX_DISABLE_AP_ATTACKS			7
#define HCX_STOP_AP_ATTACKS			8
#define HCX_RESUME_AP_ATTACKS			9
#define HCX_DISABLE_CLIENT_ATTACKS		10
#define HCX_STOP_CLIENT_M2_ATTACKS		11
#define HCX_SILENT				12
#define HCX_SILENT_NOCM				13
#define HCX_GPS_DEVICE				14
#define HCX_GPSD				15
#define HCX_NMEA_NAME				16
#define HCX_EAPOL_TIMEOUT			17
#define HCX_ACTIVE_BEACON			18
#define HCX_FLOOD_BEACON			19
#define HCX_EXTAP_BEACON			20
#define HCX_EXTAP_WPAENTBEACON			21
#define HCX_INFINITY				22
#define HCX_FILTERLIST_AP			23
#define HCX_FILTERLIST_CLIENT			24
#define HCX_FILTERLIST_AP_VENDOR		25
#define HCX_FILTERLIST_CLIENT_VENDOR		26
#define HCX_FILTERMODE				27
#define HCX_BPFC				28
#define HCX_WEAKCANDIDATE			29
#define HCX_TOT					30
#define HCX_REBOOT				31
#define HCX_POWER_OFF				32
#define HCX_GPIO_BUTTON				33
#define HCX_GPIO_STATUSLED			34
#define HCX_GPIO_STATUSLED_FLASHINTERVAL	35
#define HCX_IP					36
#define HCX_SERVER_PORT				37
#define HCX_CLIENT_PORT				38
#define HCX_CHECK_DRIVER			39
#define HCX_CHECK_INJECTION			40
#define HCX_FORCE_INTERFACE			41
#define HCX_ERROR_MAX				42
#define HCX_STATUS				43
#define HCX_BEACONPARAMS			44
#define HCX_WPAENT				45
#define HCX_EAPREQ				46
#define HCX_EAPREQ_FOLLOWNAK			47
#define HCX_EAPTUN				48
#define HCX_EAP_SERVER_CERT			49
#define HCX_EAP_SERVER_KEY			50
#define HCX_EAPOL_EAP_TIMEOUT			51
#define HCX_INTERFACE_NAME			'i'
#define HCX_PCAPNG_NAME				'o'
#define HCX_PACPNG_FRAMES			'f'
#define HCX_CHANNEL				'c'
#define HCX_SCANLIST				's'
#define HCX_STAYTIME				't'
#define HCX_SHOW_INTERFACES			'I'
#define HCX_SHOW_CHANNELS			'C'
#define HCX_SET_MONITORMODE			'm'
#define HCX_HELP				'h'
#define HCX_EXAMPLE				'x'
#define HCX_VERSION				'v'

#define ERROR_MAX		100
#define WATCHDOG		600

#define PHYIFNAMESIZE		128

#define APLIST_MAX		512
#define RGLIST_MAX		1024
#define OWNLIST_MAX		1024
#define PMKLIST_MAX		1024

#define EAPLIST_MAX		1024
#define EAPREQLIST_MAX		20

#define FSCANLIST_MAX		1000
#define SCANLIST_MAX		256
#define FILTERLIST_MAX		256
#define	FILTERLIST_LINE_LEN	256
#define BEACONEXTLIST_MAX	256
#define FDNSECTIMERB		50000000L /* 5msec */
#define FDNSECTIMER		200000000L
#define FDSECTXTIMER		5L

#define RCA_SORT_BY_HIT		0
#define RCA_SORT_BY_COUNT	1
#define RCA_SORT_BY_CHANNEL	2

#define ATTACKSTOP_MAX		600
#define ATTACKRESUME_MAX	864000

#define OW_M1M2ROGUE_MAX	10

#define SERVERMSG_MAX				2048
#define MCPORT					60123
#define SERVERMSG_HEAD_SIZE			1
#define SERVERMSG_TYPE_CONTROL			0x00
#define SERVERMSG_TYPE_STATUS			0x01
#define SERVERMSG_TYPE_PCAPNGHEAD		0x02
#define SERVERMSG_TYPE_PCAPNG			0x03
#define SERVERMSG_CONTROL_SENDPCAPNGHEAD	0x01

#define DEBUGMSG_MAX		1024
#define STATUSMSG_MAX		1024

#define EAPOLTIMEOUT		20000
#define EAPOLEAPTIMEOUT		2500000

#define USER_EXIT_TOT		2
#define STAYTIME		4
#define LEDFLASHINTERVAL	5

#define NMEA_MAX		256

#define ESSID_LEN_MAX		32
#define RSN_LEN_MIN		20
#define WPA_LEN_MIN		22
#define BEACONBODY_LEN_MAX	2301
#define EAP_LEN_MAX		1418

#define IESETLEN_MAX		50

#define PAGIDLIST_MAX		256

#define BEACONINTERVALL		0x3e8

#define PCAPNG_FRAME_MANAGEMENT	0b00000001
#define PCAPNG_FRAME_EAP	0b00000010
#define PCAPNG_FRAME_DEFAULT	0b00000011
#define PCAPNG_FRAME_IPV4	0b00000100
#define PCAPNG_FRAME_IPV6	0b00001000
#define PCAPNG_FRAME_WEP	0b00010000
#define PCAPNG_FRAME_WPA	0b00100000
#define PCAPNG_FRAME_VENDOR	0b01000000

#define STATUS_EAPOL		0b0000000000000001
#define STATUS_ASSOCIATION	0b0000000000000010
#define STATUS_AUTHENTICATION	0b0000000000000100
#define STATUS_AP_BEACON_PROBE	0b0000000000001000
#define STATUS_ROGUE		0b0000000000010000
#define STATUS_GPS		0b0000000000100000
#define STATUS_INTERNAL		0b0000000001000000
#define STATUS_SERVER		0b0000000010000000
#define STATUS_CLIENT		0b0000000100000000
#define STATUS_EAP		0b0000001000000000
#define STATUS_EAP_NAK		0b0000010000000000

#define DISABLE_CLIENT_ATTACKS		0b00000001
#define DISABLE_DEAUTHENTICATION	0b00000010
#define DISABLE_AP_ATTACKS		0b00000110
#define SILENT				0b00000111

#define EAP_TLSFLAGS_VERSION		0b00000111
#define EAP_TLSFLAGS_START		0b00100000
#define EAP_TLSFLAGS_MORE_FRAGMENTS	0b01000000
#define EAP_TLSFLAGS_LENGTH_INCL	0b10000000
#define EAP_TLSFLAGS_SIZE		1
#define EAP_TLSLENGTH_SIZE		4

#define FM_PROTECT		1
#define FI_ATTACK		2
#define FI_VENDOR		3
#define FI_MAC			6

#define PACKET_RESEND_COUNT_MAX 	7
#define PACKET_RESEND_TIMER_USEC	15500

#ifdef __BYTE_ORDER__
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BIG_ENDIAN_HOST
#endif
#else
#ifdef __OpenBSD__
# include <endian.h>
# if BYTE_ORDER == BIG_ENDIAN
#   define BIG_ENDIAN_HOST
# endif
#endif
#endif
/*===========================================================================*/
typedef struct
{
 uint8_t		channel;
 uint8_t		kdversion;
#define KV_RSNIE	1
#define KV_WPAIE	2
 uint8_t		groupcipher;
 uint8_t		cipher;
#define TCS_WEP40	0b00000001
#define TCS_TKIP	0b00000010
#define TCS_WRAP	0b00000100
#define TCS_CCMP	0b00001000
#define TCS_WEP104	0b00010000
#define TCS_BIP		0b00100000
#define TCS_NOT_ALLOWED	0b01000000
 uint16_t		akm;
#define	TAK_PMKSA	0b0000000000000001
#define	TAK_PSK		0b0000000000000010
#define TAK_FT		0b0000000000000100
#define TAK_FT_PSK	0b0000000000001000
#define	TAK_PMKSA256	0b0000000000010000
#define	TAK_PSKSHA256	0b0000000000100000
#define	TAK_TDLS	0b0000000001000000
#define	TAK_SAE_SHA256	0b0000000010000000
#define TAK_FT_SAE	0b0000000100000000
 uint8_t		pmkid[16];
 uint8_t		essidlen;
 uint8_t		essid[ESSID_LEN_MAX];
}tags_t;
#define	TAGS_SIZE (sizeof(tags_t))
/*===========================================================================*/
typedef struct
{
 uint8_t	mac[6];
}maclist_t;
#define	MACLIST_SIZE (sizeof(maclist_t))

static int sort_maclist(const void *a, const void *b)
{
const maclist_t *ia = (const maclist_t *)a;
const maclist_t *ib = (const maclist_t *)b;

if(memcmp(ia->mac, ib->mac, 6) > 0) return 1;
else if(memcmp(ia->mac, ib->mac, 6) < 0) return -1;
return 0;
}
/*===========================================================================*/
#define EAPTLSCTX_BUF_SIZE (65535)
typedef struct eaptlsctx_t
{
SSL			*ssl;
BIO			*tls_in;
BIO			*tls_out;
uint32_t		tlslen;
uint8_t			buf[EAPTLSCTX_BUF_SIZE];
size_t			buflen;
size_t			txpos;
bool			fragments_rx;
bool			fragments_tx;
}eaptlsctx_t;
#define EAPTLSCTX_SIZE (sizeof(eaptlsctx_t))
#define EAPTLS_TIMEOUT (50000000)
/*===========================================================================*/
typedef struct eapctx_t
{
uint8_t			reqstate;
uint8_t			id;
uint8_t			type;
uint8_t			version;
uint8_t			inner_id;
uint8_t			inner_type;
uint8_t			inner_version;
bool			tlstun;
}eapctx_t;
#define EAPCTX_SIZE (sizeof(eapctx_t))
/*===========================================================================*/
typedef struct
{
 uint64_t		timestamp;
 uint16_t		status;
#define OW_AUTH		0b0000000000000001
#define OW_ASSOC	0b0000000000000010
#define OW_REASSOC	0b0000000000000100
#define OW_EAP_REQ	0b0000000000001000
#define OW_EAP_RESP	0b0000000000010000
#define OW_M1M2ROGUE	0b0000000000100000
#define OW_M2M3		0b0000000001000000
#define FILTERED	0b1000000000000000
 int			owm1m2roguecount;
 uint8_t		ap[6];
 uint8_t		client[6];
 uint8_t		essidlen;
 uint8_t		essid[ESSID_LEN_MAX];
 eapctx_t		eapctx;

}ownlist_t;
#define	OWNLIST_SIZE (sizeof(ownlist_t))

static int sort_ownlist_by_time(const void *a, const void *b)
{
const ownlist_t *ia = (const ownlist_t *)a;
const ownlist_t *ib = (const ownlist_t *)b;

if(ia->timestamp < ib->timestamp) return 1;
else if(ia->timestamp > ib->timestamp) return -1;
return 0;
}
/*===========================================================================*/
typedef struct
{
 uint8_t		ap[6];
 uint64_t		timestamp;
 uint32_t		count;
 uint8_t		reason;
 uint16_t		status;
#define	AP_SEND		0b0000000000000001
#define	AP_BEACON	0b0000000000000010
#define	AP_PROBE_RESP	0b0000000000000100
#define	AP_AUTH_RESP	0b0000000000001000
#define	AP_ASSOC_RESP	0b0000000000010000
#define	AP_REASSOC_RESP	0b0000000000100000
#define	AP_EAP		0b0000000001000000
#define	AP_M1		0b0000000010000000
#define	AP_M3M4ZEROED	0b0000000100000000
#define	AP_M1M2		0b0000001000000000
#define AP_M3M4		0b0000010000000000
#define AP_M2M3		0b0000100000000000
#define AP_PMKID	0b0001000000000000
 uint8_t		channel;
 uint16_t		algorithm;
 uint8_t		kdversion;
 uint8_t		groupcipher;
 uint8_t		cipher;
 uint16_t		akm;
 uint8_t		essidlen;
 uint8_t		essid[ESSID_LEN_MAX];
 uint8_t		client[6];
}macessidlist_t;
#define	MACESSIDLIST_SIZE (sizeof(macessidlist_t))

static int sort_macessidlist_by_time(const void *a, const void *b)
{
const macessidlist_t *ia = (const macessidlist_t *)a;
const macessidlist_t *ib = (const macessidlist_t *)b;

if(ia->timestamp < ib->timestamp) return 1;
else if(ia->timestamp > ib->timestamp) return -1;
return 0;
}
/*===========================================================================*/
typedef struct
{
 uint64_t		timestamp;
 uint8_t		pmk[32];
 uint8_t		essidlen;
 uint8_t		essid[ESSID_LEN_MAX];
}pmklist_t;
#define	PMKLIST_SIZE (sizeof(pmklist_t))

static int sort_pmklist_by_time(const void *a, const void *b)
{
const pmklist_t *ia = (const pmklist_t *)a;
const pmklist_t *ib = (const pmklist_t *)b;

if(ia->timestamp < ib->timestamp) return 1;
else if(ia->timestamp > ib->timestamp) return -1;
return 0;
}
/*===========================================================================*/
typedef struct
{
 uint64_t		timestamp;
 char			id[64];
}pagidlist_t;
#define	PAGIDLIST_SIZE (sizeof(pagidlist_t))

static int sort_pagidlist_by_time(const void *a, const void *b)
{
const pagidlist_t *ia = (const pagidlist_t *)a;
const pagidlist_t *ib = (const pagidlist_t *)b;

if(ia->timestamp < ib->timestamp) return 1;
else if(ia->timestamp > ib->timestamp) return -1;
return 0;
}
/*===========================================================================*/
typedef struct
{
 uint64_t		timestamp;
 uint8_t		ap[6];
 unsigned int		count;
 unsigned int		beacon;
 unsigned int		proberesponse;
 unsigned int		proberequest;
 unsigned int		hit;
 char			rssi;
 uint8_t		channel;
 unsigned int		frequency;
 uint8_t		essidlen;
 uint8_t		essid[ESSID_LEN_MAX];
}scanlist_t;
#define	SCANLIST_SIZE (sizeof(scanlist_t))

static int sort_scanlist_by_hit(const void *a, const void *b)
{
const scanlist_t *ia = (const scanlist_t *)a;
const scanlist_t *ib = (const scanlist_t *)b;

if(ia->hit < ib->hit) return 1;
else if(ia->hit > ib->hit) return -1;
if(ia->count < ib->count) return 1;
else if(ia->count > ib->count) return -1;
if(ia->channel > ib->channel) return 1;
else if(ia->channel < ib->channel) return -1;
if(memcmp(ia->ap, ib->ap, 6) < 0) return 1;
else if(memcmp(ia->ap, ib->ap, 6) > 0) return -1;
return 0;
}

static int sort_scanlist_by_beacon(const void *a, const void *b)
{
const scanlist_t *ia = (const scanlist_t *)a;
const scanlist_t *ib = (const scanlist_t *)b;

if(ia->beacon < ib->beacon) return 1;
else if(ia->beacon > ib->beacon) return -1;
if(ia->hit < ib->hit) return 1;
else if(ia->hit > ib->hit) return -1;
if(ia->channel > ib->channel) return 1;
else if(ia->channel < ib->channel) return -1;
if(memcmp(ia->ap, ib->ap, 6) < 0) return 1;
else if(memcmp(ia->ap, ib->ap, 6) > 0) return -1;
return 0;
}

static int sort_scanlist_by_channel(const void *a, const void *b)
{
const scanlist_t *ia = (const scanlist_t *)a;
const scanlist_t *ib = (const scanlist_t *)b;

if(ia->channel < ib->channel) return 1;
else if(ia->channel > ib->channel) return -1;
if(ia->hit < ib->hit) return 1;
else if(ia->hit > ib->hit) return -1;
if(ia->count < ib->count) return 1;
else if(ia->count > ib->count) return -1;
if(memcmp(ia->ap, ib->ap, 6) < 0) return 1;
else if(memcmp(ia->ap, ib->ap, 6) > 0) return -1;
return 0;
}
/*===========================================================================*/
typedef struct
{
uint8_t			termination;
#define EAPREQLIST_TERM_ENDTLS 0xfd
#define EAPREQLIST_TERM_DEAUTH 0xfe
#define EAPREQLIST_TERM_NOTERM 0xff
uint16_t		length;
uint8_t			type;
uint8_t			data[EAP_LEN_MAX];
uint8_t			mode;
#define EAPREQLIST_MODE_TLS 1
}eapreqlist_t;
#define EAPREQLIST_SIZE (sizeof(eapreqlist_t))
/*===========================================================================*/
typedef struct
{
int	frequency;
int	channel;
}fscanlist_t;
#define	FSCANLIST_SIZE (sizeof(fscanlist_t))
/*===========================================================================*/
