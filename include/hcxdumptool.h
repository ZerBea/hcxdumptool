/*===========================================================================*/
#define HCX_BPF				1
#ifdef HCXWANTLIBPCAP
#define HCX_BPFC			2
#endif
#define HCX_DISABLE_DEAUTHENTICATION	3
#define HCX_DISABLE_PROBEREQUEST	4
#define HCX_DISABLE_ASSOCIATION		5
#define HCX_DISABLE_REASSOCIATION	6
#define HCX_DISABLE_BEACON		7
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
#define HCX_EXIT_ON_EAPOL		20
#define HCX_ON_ERROR			21
#define HCX_ESSIDLIST			22
#define HCX_NMEA0183			23
#define HCX_GPSD			24
#define HCX_NMEA0183_OUT		25
#define HCX_NMEA0183_PCAPNG		26
#define HCX_RCASCAN			27
#define HCX_RD_SORT			28
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
#define EXIT_ON_SIGTERM		0x0001
#define EXIT_ON_GPIOBUTTON	0x0002
#define EXIT_ON_TOT		0x0004
#define EXIT_ON_WATCHDOG	0x0008
#define EXIT_ON_EAPOL_PMKID	0x0010
#define EXIT_ON_EAPOL_M3	0x0020
#define EXIT_ON_EAPOL_M2	0x0040
#define EXIT_ON_EAPOL_M1	0x0080
#define EXIT_ON_ERROR		0x0100

#define EXIT_ACTION_REBOOT	0x01
#define EXIT_ACTION_POWEROFF	0x02

#define ERROR_MAX		100
#define WATCHDOG_MAX		600
#define ATTEMPTCLIENT_MAX	10
#define ATTEMPTAP_MAX		32

#define IFTYPENL		0x01
#define IFTYPEMON		0x02
#define IFTYPEMONACT		0x04
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
#define EAPOLM4TIMEOUT		20000000ULL


#define DRIVER_FORMAT		128
#define DRIVER_LINK		128

#define RCAD_MAX		40

#define PROBERESPONSETX_MAX	5

#define PCAPNG_SNAPLEN		0x400
#define RTD_LEN			9128

#define TIMESTRING_LEN		128

#define WLTXBUFFER		256

#define NMEA_SIZE		9128
#define NMEA_MSG_MAX		128
#define NMEA_MIN		10
#define NMEA_GPRMC_MIN		56
#define NMEA_CS_CR_LF_SIZE	5
#define NMEA_GPWPLID_SIZE	6
#define NMEA_GPTXTID_SIZE	6 +1

#define NLTX_SIZE		0xfff
#define NLRX_SIZE		0xffff

#define WEAKCANDIDATEDEF	"12345678"
/*===========================================================================*/
typedef struct
{
 u16	status;
 u8	macap[6];
 u8	kdv1;
 u64	replaycountm1;
 u8	noncem1[4];
 u8	kdv2;
 u64	replaycountm2;
 u8	kdv3;
 u64	replaycountm3;
 u8	kdv4;
 u64	replaycountm4;
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
#define	APIE_ESSID	0x0001
#define APGS_CCMP	0x0002
#define APGS_TKIP	0x0004
#define APCS_CCMP	0x0008
#define APCS_TKIP	0x0010
#define APRSNAKM_PSK	0x0020
#define APRSNAKM_PSK256	0x0040
#define APRSNAKM_PSKFT	0x0080
#define APWPAAKM_PSK	0x0100
#define APAKM_MASK	0x01e0
#define AP_MFP		0x0200
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
 u32	frequency;
 u8	macap[6];
 u8	macclient[6];
 u16	status;
#define AP_IN_RANGE_TOT		120000000000ULL
#define AP_IN_RANGE		0x0001
#define AP_IN_RANGE_MASK	0xfffe
#define AP_ESSID		0x0002
#define AP_BEACON		0x0004
#define AP_PROBERESPONSE	0x0008
#define AP_EAPOL_M1		0x0010
#define AP_EAPOL_M2		0x0020
#define AP_EAPOL_M3		0x0040
#define AP_EAPOL_M4		0x0080
#define AP_PMKID		0x0100
#define AP_PMKID_EAPOL		0x01f0

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
static int sort_aplist_by_count(const void *a, const void *b)
{
const aplist_t *ai = (const aplist_t *)a;
const aplist_t *bi = (const aplist_t *)b;

if(ai->count < bi->count) return 1;
else if(ai->count > bi->count) return -1;
if(ai->tsakt < bi->tsakt) return 1;
else if(ai->tsakt > bi->tsakt) return -1;
return 0;
}
/*---------------------------------------------------------------------------*/
#ifdef HCXSTATUSOUT
static int sort_aplist_by_status(const void *a, const void *b)
{
const aplist_t *ai = (const aplist_t *)a;
const aplist_t *bi = (const aplist_t *)b;

if(ai->status < bi->status) return 1;
else if(ai->status > bi->status) return -1;
if(ai->tsakt < bi->tsakt) return 1;
else if(ai->tsakt > bi->tsakt) return -1;
return 0;
}
#endif
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
#define CLIENT_EAP_START	0x01
#define CLIENT_EAPOL_M2		0x02
 u8	status;
 u32	count;
 infoelement_t	ie;
}clientlist_t;
#define CLIENTLIST_SIZE (sizeof(clientlist_t))
/*---------------------------------------------------------------------------*/
static int sort_clientlist_by_tsakt(const void *a, const void *b)
{
const clientlist_t *ai = (const clientlist_t *)a;
const clientlist_t *bi = (const clientlist_t *)b;

if(ai->tsakt < bi->tsakt) return 1;
else if(ai->tsakt > bi->tsakt) return -1;
return 0;
}
/*---------------------------------------------------------------------------*/
#ifdef HCXSTATUSOUT
static int sort_clientlist_by_status(const void *a, const void *b)
{
const clientlist_t *ai = (const clientlist_t *)a;
const clientlist_t *bi = (const clientlist_t *)b;

if(ai->status < bi->status) return 1;
else if(ai->status > bi->status) return -1;
if(ai->tsakt < bi->tsakt) return 1;
else if(ai->tsakt > bi->tsakt) return -1;
return 0;
}
#endif
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
#define IF_STAT_FREQ_DISABLED	0x01
 u8	status;
}frequencylist_t;
#define FREQUENCYLIST_SIZE (sizeof(frequencylist_t))
/*---------------------------------------------------------------------------*/
#define INTERFACELIST_MAX	64
typedef struct __attribute__((__packed__))
{
 int	index;
 u32	wiphy;
#define IF_HAS_NETLINK		0x01
#define IF_HAS_MONITOR		0x02
#define IF_HAS_MONITOR_ACTIVE	0x04
#define IF_HAS_NLMON		0x03
#define IF_HAS_NLMON_ACTIVE	0x07
 u8	type;
#define IF_STAT_MONITOR		0x01
#define IF_STAT_UP		0x02
#define IF_STAT_OK		0x03
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
static inline bool nl_set_frequency(void);
/*===========================================================================*/
