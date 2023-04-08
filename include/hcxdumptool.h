/*===========================================================================*/
#define HCX_BPF				1
#define HCX_DISABLE_BEACON		2
#define HCX_DISABLE_DEAUTHENTICATION	3
#define HCX_DISABLE_PROBEREQUEST	4
#define HCX_DISABLE_ASSOCIATION		5
#define HCX_DISABLE_REASSOCIATION	6
#define HCX_BEACONTX_MAX		7
#define HCX_PROBERESPONSETX_MAX		8
#define HCX_GPIO_BUTTON			9
#define HCX_GPIO_STATUSLED		10
#define HCX_TOT				11
#define HCX_ERROR_MAX			12
#define HCX_WATCHDOG_MAX		13
#define HCX_ATTEMPT_CLIENT_MAX		14
#define HCX_ATTEMPT_AP_MAX		15
#define HCX_ON_SIGTERM			16
#define HCX_ON_TOT			17
#define HCX_ON_GPIOBUTTON		18
#define HCX_ON_WATCHDOG			19
#define HCX_ON_ERROR			20
#define HCX_ESSIDLIST			21
#define HCX_NMEA0183			22
#define HCX_GPSD			23
#define HCX_NMEA0183_OUT		24
#define HCX_RCASCAN_PASSIVE		25
#define HCX_RCASCAN_ACTVE		26
#define HCX_IFNAME			'i'
#define HCX_PCAPNGNAME			'w'
#define HCX_INTERFACE_INFO		'I'
#define HCX_SET_MONITORMODE		'm'
#define HCX_SET_SCANLIST_FROM_USER_CH	'c'
#define HCX_SET_SCANLIST_FROM_USER_FREQ	'f'
#define HCX_SET_SCANLIST_FROM_INTERFACE	'F'
#define HCX_SHOW_INTERFACE_LIST		'L'
#define HCX_HOLD_TIME			't'
#define HCX_HELP			'h'
#define HCX_VERSION			'v'
/*---------------------------------------------------------------------------*/
#define EXIT_EVENT_MASK		0b00011111
#define EXIT_ON_SIGTERM		0b00000001
#define EXIT_ON_GPIOBUTTON	0b00000010
#define EXIT_ON_TOT		0b00000100
#define EXIT_ON_WATCHDOG	0b00001000
#define EXIT_ON_ERROR		0b00010000

#define EXIT_ACTION_REBOOT	0b00000001
#define EXIT_ACTION_POWEROFF	0b00000010

#define ERROR_MAX		100
#define WATCHDOG_MAX		600
#define ATTEMPTCLIENT_MAX	10
#define ATTEMPTAP_MAX		32

#define IFTYPENL		0b00000001
#define IFTYPEWE		0b00000010
#define IFTYPENLWE		0b00000011
#define IFTYPEMON		0b00000100
#define IFTYPEMONACT		0b00001000
#define ETHTOOL_STD_LEN		32

#define TIMER_EPWAITND		100
#define TIMER1_VALUE_SEC	1L
#define TIMER1_VALUE_NSEC	0L
#define TIMER1_INTERVAL_SEC	1L
#define TIMER1_INTERVAL_NSEC	0L

#define TIMER_RCA_VALUE_SEC	0L
#define TIMER_RCA_VALUE_NSEC	200000000L
#define TIMER_RCA_INTERVAL_SEC	0L
#define TIMER_RCA_INTERVAL_NSEC	200000000L


#define TIMEHOLD		1000000000ULL
#define TIMEBEACONNEW		3600000000000ULL
#define	TIMEAUTHWAIT		200000000ULL
#define	TIMEASSOCWAIT		200000000ULL
#define	TIMEREASSOCWAIT		200000000ULL
#define EPOLL_EVENTS_MAX	5

#define APLIST_MAX		250
#define APRGLIST_MAX		500
#define CLIENTLIST_MAX		500
#define MACLIST_MAX		250
#define ESSID_MAX		32
#define PMKID_MAX		16
#define PSK_MAX			64
#define DRIVERNAME_MAX		32
#define EAPOLM2TIMEOUT		20000000ULL
#define EAPOLM3TIMEOUT		20000000ULL

#define BEACONTX_MAX		10
#define PROBERESPONSETX_MAX	10

#define PCAPNG_SNAPLEN		0xffff
#define RTD_LEN			9128

#define WLTXBUFFER		256

#define NMEA_SIZE		9128
#define NMEA_MSG_MAX		128
#define NMEA_MIN		10
#define NMEA_GPRMC_MIN		56

#define NLTX_SIZE		0xfff
#define NLRX_SIZE		0xffff

#define WEAKCANDIDATEDEF	"12345678"
/*===========================================================================*/
typedef struct
{
 u8	status;
 u8	macap[6];
 u8	kdv1;
 u64	replaycountm1;
 u8	noncem1[4];
 u8	kdv2;
 u64	replaycountm2;
}authseqakt_t;
#define AUTHSEQAKT_SIZE (sizeof(authseqakt_t))
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u8 	len;
 u8	*essid;
}essid_t;
#define ESSID_SIZE (sizeof(essid_t))
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
#define	APIE_ESSID	0b0000000000000001
#define APGS_CCMP	0b0000000000000010
#define APGS_TKIP	0b0000000000000100
#define APCS_CCMP	0b0000000000001000
#define APCS_TKIP	0b0000000000010000
#define APRSNAKM_PSK	0b0000000000100000
#define APRSNAKM_PSK256	0b0000000001000000
#define APRSNAKM_PSKFT	0b0000000010000000
#define APWPAAKM_PSK	0b0000000100000000
#define APAKM_MASK	0b0000000111100000
#define AP_MFP		0b0000001000000000
 u8	flags;
 u8	essidlen;
 u8	essid[ESSID_MAX];
 u16	channel;
}infoelement_t;
#define INFOELEMENT_SIZE (sizeof(infoelement_t))
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u64	tsakt;
 u64	tshold1;
 u64	tsauth;
 u32	count;
 u8	macap[6];
 u8	macclient[6];
 u8	status;
#define AP_IN_RANGE		0b00000001
#define AP_ESSID		0b00000010
#define AP_BEACON		0b00000100
#define AP_PROBERESPONSE	0b00001000
#define AP_EAPOL_M1		0b00010000
#define AP_EAPOL_M2		0b00100000
#define AP_EAPOL_M3		0b01000000
#define AP_PMKID		0b10000000
#define AP_PMKID_EAPOL		0b11000000
 infoelement_t	ie;
}aplist_t;
#define APLIST_SIZE (sizeof(aplist_t))
/*---------------------------------------------------------------------------*/
static int sort_aplist_by_tsakt(const void *a, const void *b)
{
const aplist_t *ai = (const aplist_t *)a;
const aplist_t *bi = (const aplist_t *)b;

if(ai->tsakt < bi->tsakt) return 1;
else if(ai->tsakt > bi->tsakt) return -1;
return 0;
}
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u64	tsakt;
 u8	macaprg[6];
 u8	essidlen;
 u8	essid[ESSID_MAX];
}aprglist_t;
#define APRGLIST_SIZE (sizeof(aprglist_t))
static int sort_aprglist_by_tsakt(const void *a, const void *b)
{
const aprglist_t *ai = (const aprglist_t *)a;
const aprglist_t *bi = (const aprglist_t *)b;

if(ai->tsakt < bi->tsakt) return 1;
else if(ai->tsakt > bi->tsakt) return -1;
return 0;
}
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u64	tsakt;
 u64	tsauth;
 u64	tsassoc;
 u64	tsreassoc;
 u16	aid;
 u8	macclient[6];
 u8	macap[6];
 u8	mic[4];
#define CLIENT_EAPOL_M2		0b00010000
 u8	status;
 u32	count;
 infoelement_t	ie;
}clientlist_t;
#define CLIENTLIST_SIZE (sizeof(clientlist_t))

static int sort_clientlist_by_tsakt(const void *a, const void *b)
{
const clientlist_t *ai = (const clientlist_t *)a;
const clientlist_t *bi = (const clientlist_t *)b;

if(ai->tsakt < bi->tsakt) return 1;
else if(ai->tsakt > bi->tsakt) return -1;
return 0;
}
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u64	tsakt;
 u8	mac[6];
}maclist_t;
#define MACLIST_SIZE (sizeof(maclist_t))

static int sort_maclist_by_tsakt(const void *a, const void *b)
{
const maclist_t *ai = (const maclist_t *)a;
const maclist_t *bi = (const maclist_t *)b;

if(ai->tsakt < bi->tsakt) return 1;
else if(ai->tsakt > bi->tsakt) return -1;
return 0;
}
/*---------------------------------------------------------------------------*/
#define SCANLIST_MAX		512
#define FREQUENCYLIST_MAX	256
typedef struct __attribute__((__packed__))
{
 u32	frequency;
 u32	channel;
 u32	pwr;
#define IF_STAT_FREQ_DISABLED	0b00000001
 u8	status;
}frequencylist_t;
#define FREQUENCYLIST_SIZE (sizeof(frequencylist_t))
/*---------------------------------------------------------------------------*/
#define INTERFACELIST_MAX	64
typedef struct __attribute__((__packed__))
{
 int	index;
 u32	wiphy;
#define IF_HAS_WEXT		0b00000001
#define IF_HAS_NETLINK		0b00000010
#define IF_HAS_NLWEXT		0b00000011
#define IF_HAS_MONITOR		0b00000100
#define IF_HAS_MONITOR_ACTIVE	0b00001000
#define IF_HAS_NLMON		0b00000110
#define IF_HAS_NLMON_ACTIVE	0b00001110
 u8	type;
#define IF_STAT_MONITOR		0b00000001
#define IF_STAT_UP		0b00000010
#define IF_STAT_OK		0b00000011
 u8	status;
 u8	hwmac[6];
 u8	vimac[6];
 char	name[IFNAMSIZ];
 char	driver[DRIVERNAME_MAX];
 size_t	i;
 frequencylist_t *frequencylist;
}interface_t;
#define INTERFACELIST_SIZE (sizeof(interface_t))

static int sort_interfacelist_by_index(const void *a, const void *b)
{
const interface_t *ia = (const interface_t *)a;
const interface_t *ib = (const interface_t *)b;

if(ia->index > ib->index) return 1;
else if(ia->index < ib->index) return -1;
return 0;
}
/*===========================================================================*/
typedef struct
{
 struct nlmsghdr  nlh;
 struct ifinfomsg ifinfo;
 char attrbuf[512];
}req_t;
/*===========================================================================*/
static bool read_bpf(char *bpfname);
static inline bool nl_set_frequency();
/*===========================================================================*/
