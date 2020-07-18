#define HCX_DO_RCASCAN			1
#define HCX_DO_TARGETSCAN		2
#define HCX_DEAUTH_REASON_CODE		3
#define HCX_DISABLE_DEAUTHENTICATION	4
#define HCX_DISABLE_AP_ATTACKS		5
#define HCX_STOP_AP_ATTACKS		6
#define HCX_RESUME_AP_ATTACKS		7
#define HCX_DISABLE_CLIENT_ATTACKS	8
#define HCX_SILENT			9
#define HCX_GPS_DEVICE			10
#define HCX_GPSD			11
#define HCX_NMEA_NAME			12
#define HCX_EAPOL_TIMEOUT		13
#define HCX_ACTIVE_BEACON		14
#define HCX_FLOOD_BEACON		15
#define HCX_EXTAP_BEACON		16
#define HCX_INFINITY			17
#define HCX_FILTERLIST_AP		18
#define HCX_FILTERLIST_CLIENT		19
#define HCX_FILTERMODE			20
#define HCX_BPFC			21
#define HCX_WEAKCANDIDATE		22
#define HCX_TOT				23
#define HCX_REBOOT			24
#define HCX_POWER_OFF			25
#define HCX_GPIO_BUTTON			26
#define HCX_GPIO_STATUSLED		27
#define HCX_SERVER_PORT			28
#define HCX_CLIENT_PORT			29
#define HCX_CHECK_DRIVER		30
#define HCX_CHECK_INJECTION		31
#define HCX_ERROR_MAX			32
#define HCX_STATUS			33
#define HCX_BEACONPARAMS		34
#define HCX_INTERFACE_NAME		'i'
#define HCX_PCAPNG_NAME			'o'
#define HCX_PACPNG_FRAMES		'f'
#define HCX_CHANNEL			'c'
#define HCX_SCANLIST			's'
#define HCX_STAYTIME			't'
#define HCX_SHOW_INTERFACES		'I'
#define HCX_SHOW_CHANNELS		'C'
#define HCX_SET_MONITORMODE		'm'
#define HCX_HELP			'h'
#define HCX_VERSION			'v'

#define ERROR_MAX		100

#define APLIST_MAX		512
#define RGLIST_MAX		1024
#define OWNLIST_MAX		1024
#define PMKLIST_MAX		1024

#define SCANLIST_MAX		256
#define FILTERLIST_MAX		256
#define	FILTERLIST_LINE_LEN	256
#define BEACONEXTLIST_MAX	256
#define FDUSECTIMER		200000

#define ATTACKSTOP_MAX		600
#define ATTACKRESUME_MAX	864000

#define SERVERMSG_MAX		2048

#define MCHOST			"224.0.0.255"
#define MCPORT			60123
#define SERVERSTATUS_MAX	1024

#define EAPOLTIMEOUT		20000

#define USER_EXIT_TOT		2
#define STAYTIME		4
#define NMEA_MAX		256

#define ESSID_LEN_MAX		32
#define RSN_LEN_MIN		20
#define WPA_LEN_MIN		22
#define BEACONBODY_LEN_MAX	2301

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

#define DISABLE_CLIENT_ATTACKS		0b00000001
#define DISABLE_DEAUTHENTICATION	0b00000010
#define DISABLE_AP_ATTACKS		0b00000110
#define SILENT				0b00000111

#define FM_PROTECT		1
#define FI_ATTACK		2

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
 uint8_t		ap[6];
 uint8_t		client[6];
 uint8_t		essidlen;
 uint8_t		essid[ESSID_LEN_MAX];

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
 int			count;
 int			counthit;
 uint8_t		channel;
 uint8_t		essidlen;
 uint8_t		essid[ESSID_LEN_MAX];
}scanlist_t;
#define	SCANLIST_SIZE (sizeof(scanlist_t))

static int sort_scanlist_by_count(const void *a, const void *b)
{
const scanlist_t *ia = (const scanlist_t *)a;
const scanlist_t *ib = (const scanlist_t *)b;

if(ia->count < ib->count) return 1;
else if(ia->count > ib->count) return -1;
return 0;
}
/*===========================================================================*/
typedef struct
{
uint8_t     tag;
uint8_t     len;
uint8_t     *val;
}tlv_t;
#define TLV_SIZE (sizeof(tlv_t))
#define TLVSETLEN_MAX 50
/*===========================================================================*/
