#define ERRORMAX 100000

#define ESSID_LEN_MAX 32
#define RSN_LEN_MAX 24
#define TIME_INTERVAL 5
#define EAPOLTIMEOUT 1000000
#define DEAUTHENTICATIONINTERVALL 20
#define DEAUTHENTICATIONS_MAX 10
#define APATTACKSINTERVALL 20
#define APPATTACKS_MAX 10

#define FILTERLIST_MAX 32
#define FILTERLIST_LINE_LEN 256

#define BEACONLIST_MAX 256
#define PROBEREQUESTLIST_MAX 512
#define PROBERESPONSELIST_MAX 512
#define MYPROBERESPONSELIST_MAX 512

#define OWNEDLIST_MAX 1024

#define RX_M1		0b00000001
#define RX_M12		0b00000010
#define RX_PMKID	0b00000100
#define RX_M23		0b00001000

#define HCXD_HELP			1
#define HCXD_VERSION			2
#define HCXD_FILTERLIST			3
#define HCXD_FILTERMODE			4
#define HCXD_DISABLE_DEAUTHENTICATIONS	5
#define HCXD_GIVE_UP_DEAUTHENTICATIONS	6
#define HCXD_DISABLE_DISASSOCIATIONS	7
#define HCXD_DISABLE_AP_ATTACKS		8
#define HCXD_GIVE_UP_AP_ATTACKS		9
#define HCXD_DISABLE_CLIENT_ATTACKS	10


#define HCXD_ENABLE_STATUS		11

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
//*===========================================================================*/
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
