/*===========================================================================*/
#define HCX_BPF				1
#ifdef HCXWANTLIBPCAP
#define HCX_BPFC			2
#define HCX_BPFD			3
#endif
#define HCX_FTC				4
#define HCX_TX_MAX			5
#define HCX_GPIO_BUTTON			6
#define HCX_GPIO_STATUSLED		7
#define HCX_TOT				8
#define HCX_ERROR_MAX			9
#define HCX_DISABLE_DISASSOCIATION	10
#define HCX_WATCHDOG_MAX		11
#define HCX_M1M2ROGUE_MAX		12
#define HCX_APCOUNT_MAX			13
#define HCX_PRTX_MAX			14
#define HCX_ON_SIGTERM			15
#define HCX_ON_TOT			16
#define HCX_ON_GPIOBUTTON		17
#define HCX_ON_WATCHDOG			18
#define HCX_EXIT_ON_EAPOL		19
#define HCX_ON_ERROR			20
#define HCX_ESSIDLIST			21
#define HCX_RDS				22
#define HCX_RDT				23
#define HCX_RCASCAN			24
#define HCX_DAEMON			25
#define HCX_IFNAME			'i'
#define HCX_PCAPNGNAME			'w'
#define HCX_INTERFACE_INFO		'I'
#define HCX_SET_MONITORMODE		'm'
#define HCX_SET_MONITORMODE_ACTIVE	'A'
#define HCX_SET_SCANLIST_FROM_USER_CH	'c'
#define HCX_SET_SCANLIST_FROM_USER_FREQ	'f'
#define HCX_SET_SCANLIST_FROM_INTERFACE	'F'
#define HCX_SHOW_INTERFACE_LIST		'L'
#define HCX_SHOW_INTERFACE_LIST_SHORT	'l'
#define HCX_HOLD_TIME			't'
#define HCX_HELP			'h'
#define HCX_HELP_ADDITIONAL		'H'
#define HCX_VERSION			'v'
/*---------------------------------------------------------------------------*/
#define HCX_DONE		1
#define EXIT_ON_SIGTERM		0x0001
#define EXIT_ON_GPIOBUTTON	0x0002
#define EXIT_ON_TOT		0x0004
#define EXIT_ON_WATCHDOG	0x0008
#define EXIT_ON_EAPOL_PMKID	0x0010
#define EXIT_ON_EAPOL_M3	0x0020
#define EXIT_ON_EAPOL_M2	0x0040
#define EXIT_ON_EAPOL_M2RG	0x0080
#define EXIT_ON_EAPOL_M1	0x0100
#define EXIT_ON_ERROR		0x0200

#define EXIT_ACTION_REBOOT	0x01
#define EXIT_ACTION_POWEROFF	0x02

#define ERROR_MAX		100
#define WATCHDOG_MAX		600
#define CLIENTCOUNT_MAX		4
#define APCOUNT_MAX		100

#define IFTYPENL		0x01
#define IFTYPEMON		0x02
#define IFTYPEMONACT		0x04

#define BPFD_HCX		0
#define BPFD_TCPDUMP		1
#define BPFD_C			2
#define BPFD_ASM		3
#define BPFD_DBG		4

#define RCASCAN_ACTIVE		0x01
#define RCASCAN_PASSIVE		0x02

#define ETHTOOL_STD_LEN		32

#define TIMER_EPWAITND		100
#define TIMER1_VALUE_SEC	1L
#define TIMER1_VALUE_NSEC	0L
#define TIMER1_INTERVAL_SEC	1L
#define TIMER1_INTERVAL_NSEC	0L
#define EPOLL_EVENTS_MAX	5

#define TIMEHOLD		5
#define TSWAITEAPOLA		10000000UL
#define TSSECOND1		1000000000ULL
#define TSEAPOL1		50000000ULL
#define TSEAPOL2		150000000ULL

#define TSSECOND05		500000000ULL
#define TSSECOND1		1000000000ULL
#define TSSECOND2		2000000000ULL
#define TSSECOND3		3000000000ULL
#define TSSECOND4		4000000000ULL
#define TSSECOND5		5000000000ULL
#define TSSECOND6		6000000000ULL
#define TSMINUTE1		60000000000ULL
#define TSHOUR1			3600000000000ULL

#define APLIST_MAX		250
#define APLIST_HALF		125
#define APDATA_MAX		100
#define APRGLIST_MAX		1024
#define APRGLIST_HALF		512
#define CALIST_MAX		250
#define CALIST_HALF		125

#define OFFSETCHANNEL		0x0c
#define OFFSETGCS		0x17
#define OFFSETPCS		0x1d
#define OFFSETAKM		0x23

#define	BCD_MAX			4095

#define MACLIST_MAX		250
#define ESSID_MAX		32
#define PSK_MAX			64
#define DRIVERNAME_MAX		32

#define DRIVER_FORMAT		128
#define DRIVER_LINK		128

#define PROBERESPONSETX_MAX	(APRGLIST_MAX - 1)

#define PCAPNG_SNAPLEN		0x400

#define TIMESTRING_LEN		128

#define WLTXBUFFER		256

#define NLTX_SIZE		0xfff
#define NLRX_SIZE		0xffff

#define WEAKCANDIDATEDEF	"12345678"

/*===========================================================================*/
/*===========================================================================*/
typedef struct __attribute__((__packed__))
{
 u64	tsauth;
 u64	tsassoc;
 u64	tsreassoc;
 u64	tsnull;
 u8	macc[ETH_ALEN];
 u8	maca[ETH_ALEN];
 int	clientcount;
 u16	channel;
 u8	mic[16];
 u8	essid[ESSID_MAX];
 u8	essidlen;
 u8	akm;
 char	m2;
 }cadata_t;
#define CADATA_SIZE (sizeof(cadata_t))
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u64	tsakt;
 cadata_t	*cadata;
}calist_t;
#define CALIST_SIZE (sizeof(calist_t))
/*---------------------------------------------------------------------------*/
static int sort_calist_by_tsakt(const void *a, const void *b)
{
const calist_t *ai = (const calist_t *)a;
const calist_t *bi = (const calist_t *)b;

if(ai->tsakt < bi->tsakt) return 1;
else if(ai->tsakt > bi->tsakt) return -1;
return 0;
}
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
typedef struct __attribute__((__packed__))
{
 u64	tsrequest;
 u64	tsauthresponse;
 u64	tsassocresponse;
 u64	tsreassocresponse;
 u64	tsmacc;
 u64	tsm1;
 u64	tsm2;
 u64	tsm3;
 u64	tsresponse;
 u64	replaycount1;
 u64	replaycount2;
 u64	replaycount3;
 int	apcount;
 u16	channel;
 u16	aid;
 u16	rtfrequency;
 u8	rtrssi;
 u8	nonce[4];
 u8	rsnpmkid[PMKID_MAX];
 u8	maca[ETH_ALEN];
 u8	macc[ETH_ALEN];
 u8	essid[ESSID_MAX];
 u8	essidlen;
 u8	opensystem;
 u8	gcs;
 u8	pcs;
 u8	akm;
 u8	mcs;
 u8	ucs;
 u8	akm1;
 u8	mfp;
 u8	akmstat;
 char	privacy;
 char	pmkid;
 char	m1;
 char	m1m2;
 char	m1m2m3;
 bool	beacon;
 bool	proberesponse;
 bool	suthentication;
 bool	associationresponse;
 bool	reassociationresponse;
 }apdata_t;
#define APDATA_SIZE (sizeof(apdata_t))
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u64	tsakt;
 apdata_t	*apdata;
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
static int sort_aplist_by_tsresponse(const void *a, const void *b)
{
const aplist_t *ai = (const aplist_t *)a;
const aplist_t *bi = (const aplist_t *)b;

if(ai->apdata->tsresponse < bi->apdata->tsresponse) return 1;
else if(ai->apdata->tsresponse > bi->apdata->tsresponse) return -1;
return 0;
}
/*---------------------------------------------------------------------------*/
static int sort_aplist_by_rtrssi(const void *a, const void *b)
{
const aplist_t *ai = (const aplist_t *)a;
const aplist_t *bi = (const aplist_t *)b;

if(ai->apdata->rtrssi < bi->apdata->rtrssi) return 1;
else if(ai->apdata->rtrssi > bi->apdata->rtrssi) return -1;
return 0;
}
/*+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++*/
/*---------------------------------------------------------------------------*/
#define SCANLIST_MAX		512
#define FREQUENCYLIST_MAX	256
typedef struct __attribute__((__packed__))
{
 u32	frequency;
 u32	channel;
 u32	pwr;
#define IF_STAT_FREQ_DISABLED	0x01
 u8	status;
}frequencylist_t;
#define FREQUENCYLIST_SIZE (sizeof(frequencylist_t))
/*---------------------------------------------------------------------------*/
#define INTERFACELIST_MAX	64
typedef struct __attribute__((__packed__))
{
 int	index;
 int	wiphy;
 u64	wdev;
#define IF_HAS_NETLINK		0x01
#define IF_HAS_MONITOR		0x02
#define IF_HAS_MONITOR_ACTIVE	0x04
#define IF_HAS_NLMON		0x03
#define IF_HAS_NLMON_ACTIVE	0x07
#define IF_IS_SHARED		0x08
 u8	type;
#define IF_STAT_MONITOR		0x01
#define IF_STAT_UP		0x02
#define IF_STAT_OK		0x03
 u8	status;
 u8	hwmac[6];
 u8	vimac[6];
 char	name[IFNAMSIZ +1];
 char	driver[DRIVERNAME_MAX];
 size_t	i;
 frequencylist_t *frequencylist;
}interface_t;
#define INTERFACELIST_SIZE (sizeof(interface_t))

static int sort_interfacelist_by_wiphy(const void *a, const void *b)
{
const interface_t *ia = (const interface_t *)a;
const interface_t *ib = (const interface_t *)b;

if(ia->wiphy > ib->wiphy) return 1;
else if(ia->wiphy < ib->wiphy) return -1;
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
static inline bool nl_set_frequency(void);
/*===========================================================================*/
