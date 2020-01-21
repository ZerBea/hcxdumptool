#define HCX_DO_RCASCAN			1
#define HCX_DISABLE_AP_ATTACKS		2
#define HCX_DISABLE_CLIENT_ATTACKS	3
#define HCX_SILENT			4
#define HCX_GPS_DEVICE			5
#define HCX_GPSD			6
#define HCX_NMEA_NAME			7
#define HCX_EAPOL_TIMEOUT		8
#define HCX_REACTIVE_BEACON		9
#define HCX_ACTIVE_BEACON		10
#define HCX_FLOOD_BEACON		11
#define HCX_EXTAP_BEACON		12
#define HCX_FILTERLIST_AP		13
#define HCX_FILTERLIST_CLIENT		14
#define HCX_FILTERMODE			15
#define HCX_WEAKCANDIDATE		16
#define HCX_MAC_AP			17
#define HCX_MAC_CLIENT			18
#define HCX_TOT				19
#define HCX_REBOOT			20
#define HCX_POWER_OFF			21
#define HCX_GPIO_BUTTON			22
#define HCX_GPIO_STATUSLED		23
#define HCX_SERVER_PORT			24
#define HCX_CLIENT_PORT			25
#define HCX_CHECK_DRIVER		26
#define HCX_STATUS			27
#define HCX_INTERFACE_NAME		'i'
#define HCX_PCAPNG_NAME			'o'
#define HCX_PACPNG_FRAMES		'f'
#define HCX_CHANNEL			'c'
#define HCX_STAYTIME			't'
#define HCX_SHOW_INTERFACES		'I'
#define HCX_SHOW_CHANNELS		'C'
#define HCX_HELP			'h'
#define HCX_VERSION			'v'

#define ERROR_MAX		100

#define MACLIST_MAX		1024
#define HANDSHAKELIST_MAX	16
#define SCANLIST_MAX		256
#define FILTERLIST_MAX		256
#define	FILTERLIST_LINE_LEN	256
#define BEACONEXTLIST_MAX	256

#define SERVERMSG_MAX		2048

#define MCHOST			"224.0.0.255"
#define MCPORT			60123
#define SERVERSTATUS_MAX	1024

#define EAPOLTIMEOUT		200000

#define USER_EXIT_TOT		2
#define STAYTIME		5
#define NMEA_MAX		256

#define ESSID_LEN_MAX		32
#define RSN_LEN_MIN		20
#define WPA_LEN_MIN		22

#define BEACONINTERVALL		0x3e8

#define DPC			3
#define RECHECKCOUNT		1000000

#define PCAPNG_FRAME_MANAGEMENT	1
#define PCAPNG_FRAME_EAP	2
#define PCAPNG_FRAME_DEFAULT	3
#define PCAPNG_FRAME_IPV4	4
#define PCAPNG_FRAME_IPV6	8
#define PCAPNG_FRAME_WEP	16
#define PCAPNG_FRAME_WPA	32

#define STATUS_EAPOL		1
#define STATUS_PROBES		2
#define STATUS_AUTH		4
#define STATUS_ASSOC		8
#define STATUS_BEACON		16
#define STATUS_GPS		32
#define STATUS_INTERNAL		64
#define STATUS_SERVER		128
#define STATUS_CLIENT		256

#define DISABLE_AP_ATTACKS	1
#define DISABLE_CLIENT_ATTACKS	2
#define SILENT			3

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
struct maclist_s
{
 uint64_t		timestamp;
 int			count;
 int			dpv;
 int			status;
#define NET_BEACON		1
#define NET_PROBE_RESP		2
#define NET_PROBE_REQ		4
#define NET_AUTH		8
#define NET_ASSOC_REQ		16
#define NET_ASSOC_RESP		32
#define NET_REASSOC_REQ		64
#define NET_REASSOC_RESP	128
#define NET_M1			256
#define NET_M2			512
#define NET_M3			1024
#define NET_M4			2048
#define NET_PMKID		4096
 uint8_t		addr[6];
 uint8_t		kdversion;
 uint8_t		groupcipher;
 uint8_t		cipher;
 uint8_t		akm;
#define	WPA1		1
#define WPA2		2
#define WPA2kv3		4
 uint8_t		algorithm;
 uint8_t		channel;
 uint8_t		essidlen;
 uint8_t		essid[ESSID_LEN_MAX];
};
typedef struct maclist_s maclist_t;
#define	MACLIST_SIZE (sizeof(maclist_t))

static int sort_maclist_by_time(const void *a, const void *b)
{
const maclist_t *ia = (const maclist_t *)a;
const maclist_t *ib = (const maclist_t *)b;

if(ia->timestamp < ib->timestamp) return 1;
else if(ia->timestamp > ib->timestamp) return -1;
return 0;
}
/*===========================================================================*/
struct tags_s
{
 uint8_t	channel;
 uint8_t	kdversion;
#define KV_RSNIE	1
#define KV_WPAIE	2
 uint8_t	groupcipher;
 uint8_t	cipher;
#define TCS_WEP40	0b00000001
#define TCS_TKIP	0b00000010
#define TCS_WRAP	0b00000100
#define TCS_CCMP	0b00001000
#define TCS_WEP104	0b00010000
#define TCS_BIP		0b00100000
#define TCS_NOT_ALLOWED	0b01000000
 uint8_t	akm;
#define	TAK_PMKSA	0b0000000000000001
#define	TAK_PSK		0b0000000000000010
#define TAK_FT		0b0000000000000100
#define TAK_FT_PSK	0b0000000000001000
#define	TAK_PMKSA256	0b0000000000010000
#define	TAK_PSKSHA256	0b0000000000100000
#define	TAK_TDLS	0b0000000001000000
#define	TAK_SAE_SHA256	0b0000000010000000
#define TAK_FT_SAE	0b0000000100000000
 uint8_t	pmkid[16];
 uint8_t	essidlen;
 uint8_t	essid[ESSID_LEN_MAX];
};
typedef struct tags_s tags_t;
#define	TAGS_SIZE (sizeof(tags_t))
/*===========================================================================*/
struct handshakelist_s
{
 uint64_t	timestamp;
 uint8_t	client[6];
 uint8_t	ap[6];
 uint8_t	message;
#define HS_M1	1
#define HS_M2	2
#define HS_M3	4
#define HS_M4	8
 uint64_t	rc;
 uint8_t	nonce[32];
};
typedef struct handshakelist_s handshakelist_t;
#define	HANDSHAKELIST_SIZE (sizeof(handshakelist_t))

static int sort_handshakelist_by_time(const void *a, const void *b)
{
const handshakelist_t *ia = (const handshakelist_t *)a;
const handshakelist_t *ib = (const handshakelist_t *)b;

if(ia->timestamp < ib->timestamp) return 1;
else if(ia->timestamp > ib->timestamp) return -1;
return 0;
}
/*===========================================================================*/
struct scanlist_s
{
 uint64_t		timestamp;
 int			count;
 int			counthit;
 uint8_t		addr[6];
 uint8_t		channel;
 uint8_t		essidlen;
 uint8_t		essid[ESSID_LEN_MAX];
};
typedef struct scanlist_s scanlist_t;
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
struct filterlist_s
{
 uint8_t	mac[6];
};
typedef struct filterlist_s filterlist_t;
#define	FILTERLIST_SIZE (sizeof(filterlist_t))

static int sort_filterlist_by_mac(const void *a, const void *b)
{
const filterlist_t *ia = (const filterlist_t *)a;
const filterlist_t *ib = (const filterlist_t *)b;

if(memcmp(ia->mac, ib->mac, 6) > 0) return 1;
else if(memcmp(ia->mac, ib->mac, 6) < 0) return -1;
return 0;
}
/*===========================================================================*/
