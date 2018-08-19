#define ERRORMAX 100000

#define ESSID_LEN_MAX 32
#define RSN_LEN_MAX 24
#define TIME_INTERVAL 5
#define EAPOLTIMEOUT 150000
#define DEAUTHENTICATIONINTERVALL 10
#define DEAUTHENTICATIONS_MAX 100
#define APATTACKSINTERVALL 10
#define APPATTACKS_MAX 100

#define FILTERLIST_MAX 32
#define FILTERLIST_LINE_LEN 256

#define RCASCANLIST_MAX 256
#define BEACONLIST_MAX 256
#define PROBEREQUESTLIST_MAX 512
#define PROBERESPONSELIST_MAX 512
#define MYPROBERESPONSELIST_MAX 512
#define POWNEDLIST_MAX 512

#define RX_M1		0b00000001
#define RX_M12		0b00000010
#define RX_PMKID	0b00000100
#define RX_M23		0b00001000

#define STATUS_EAPOL		0b00000001
#define STATUS_PROBES		0b00000010
#define STATUS_AUTH		0b00000100
#define STATUS_ASSOC		0b00001000


#define HCXD_HELP			1
#define HCXD_VERSION			2
#define HCXD_FILTERLIST			3
#define HCXD_FILTERMODE			4
#define HCXD_DISABLE_ACTIVE_SCAN	5
#define HCXD_DISABLE_DEAUTHENTICATIONS	6
#define HCXD_GIVE_UP_DEAUTHENTICATIONS	7
#define HCXD_DISABLE_DISASSOCIATIONS	8
#define HCXD_DISABLE_AP_ATTACKS		9
#define HCXD_GIVE_UP_AP_ATTACKS		10
#define HCXD_DISABLE_CLIENT_ATTACKS	11
#define HCXD_DO_RCASCAN			12
#define HCXD_ENABLE_STATUS		13

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BIG_ENDIAN_HOST
#endif

/*===========================================================================*/
struct maclist_s
{
 uint64_t	timestamp;
 uint8_t	status;
 int		count;
 uint8_t	addr[6];
};
typedef struct maclist_s maclist_t;
#define	MACLIST_SIZE (sizeof(maclist_t))

static int sort_maclist_by_time(const void *a, const void *b)
{
const maclist_t *ia = (const maclist_t *)a;
const maclist_t *ib = (const maclist_t *)b;
if(ia->timestamp < ib->timestamp)
	return 1;
else if(ia->timestamp > ib->timestamp)
	return -1;
return 0;
}
/*===========================================================================*/
struct macmaclist_s
{
 uint64_t	timestamp;
 uint8_t	status;
 uint8_t	addr1[6];
 uint8_t	addr2[6];
};
typedef struct macmaclist_s macmaclist_t;
#define	MACMACLIST_SIZE (sizeof(macmaclist_t))

static int sort_macmaclist_by_time(const void *a, const void *b)
{
const macmaclist_t *ia = (const macmaclist_t *)a;
const macmaclist_t *ib = (const macmaclist_t *)b;
if(ia->timestamp < ib->timestamp)
	return 1;
else if(ia->timestamp > ib->timestamp)
	return -1;
return 0;
}
/*===========================================================================*/
struct macessidlist_s
{
 uint64_t	timestamp;
 uint8_t	status;
 uint8_t	addr[6];
 uint8_t	essid_len;
 uint8_t	essid[ESSID_LEN_MAX];
 uint8_t	rsn_len;
 uint8_t	rsn[RSN_LEN_MAX];
};
typedef struct macessidlist_s macessidlist_t;
#define	MACESSIDLIST_SIZE (sizeof(macessidlist_t))

static int sort_macessidlist_by_time(const void *a, const void *b)
{
const macessidlist_t *ia = (const macessidlist_t *)a;
const macessidlist_t *ib = (const macessidlist_t *)b;
if(ia->timestamp < ib->timestamp)
	return 1;
else if(ia->timestamp > ib->timestamp)
	return -1;
return 0;
}
/*===========================================================================*/
struct rcascanlist_s
{
 uint64_t	timestamp;
 uint8_t	status;
 int		channel;
 uint8_t	addr[6];
 uint8_t	essid_len;
 uint8_t	essid[ESSID_LEN_MAX];
};
typedef struct rcascanlist_s rcascanlist_t;
#define	RCASCANLIST_SIZE (sizeof(rcascanlist_t))

static int sort_rcascanlist_by_essid(const void *a, const void *b)
{
const rcascanlist_t *ia = (const rcascanlist_t *)a;
const rcascanlist_t *ib = (const rcascanlist_t *)b;
if(memcmp(ia->essid, ib->essid, 32) > 0)
	return 1;
else if(memcmp(ia->essid, ib->essid, 32) < 0)
	return -1;
return 0;
}
/*===========================================================================*/
