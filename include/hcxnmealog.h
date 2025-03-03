#define HCX_OUTPUT_NMEA			'n'
#define HCX_OUTPUT_TSV			't'
#define HCX_GPS_DEVICE			'd'
#define HCX_GPS_BAUDRATE		'b'
#define HCX_IFNAME			'i'
#define HCX_BPF				1

#define HCX_HELP			'h'
#define HCX_HELP_ADDITIONAL		'H'
#define HCX_VERSION			'v'

#define ERROR_MAX			100

#define NMEA_MIN			10
#define NMEA_SIZE			2048
#define NMEA_FIELD_SIZE			20
#define NMEA_FIELD_MAX			20

#define EXIT_ON_SIGTERM		0x0001
#define EXIT_ON_ERROR		0x0100

#define TIMER_EPWAITND		100
#define EPOLL_EVENTS_MAX	5
#define TIMER_VALUE_SEC	1L
#define TIMER_VALUE_NSEC	0L
#define TIMER_INTERVAL_SEC	1L
#define TIMER_INTERVAL_NSEC	0L
#define PCAPNG_SNAPLEN		0x400

#define TIMESTRING_LEN		128
#define ESSID_MAX		32

#define APLIST_MAX		1024

#define TWSTATUS_ERR		0x0001
#define TWSTATUS_ESSID		0x0002
#define TWSTATUS_FREQ		0x0003
#define TWSTATUS_RSSI		0x0008
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 float		lat;
 float		lon;
 float		latitude;
 float		longitude;
 float		altitude;
 float		speed;
 float		pdop;
 float		hdop;
 float		vdop;
 char		ns;
 char		ew;
 char		altitudeunit;
 int		channel;
#define CS_WEP			0x00000001
#define CS_TKIP			0x00000002
#define CS_RESERVED		0x00000004
#define CS_CCMP128		0x00000008
#define CS_WEP104		0x00000010
#define CS_BIPCMAC128		0x00000020
#define CS_GC_NOT_ALLOWED	0x00000040
#define CS_GCMP128		0x00000080
#define CS_GCMP256		0x00000100
#define CS_CCMP256		0x00000200
#define CS_BIPGMAC128		0x00000400
#define CS_BIPGMAC256		0x00000800
#define CS_BIPCMAC256		0x00001000
#define CS_UNKNOWN		0x00008000
#define AKM_WEP			0x00010000
#define AKM_TKIP		0x00020000
#define AKM_RESERVED		0x00040000
#define AKM_CCMP128		0x00080000
#define AKM_WEP104		0x00100000
#define AKM_BIPCMAC128		0x00200000
#define AKM_GA_NOT_ALLOWED	0x00400000
#define AKM_GCMP128		0x00800000
#define AKM_GCMP256		0x01000000
#define AKM_CCMP256		0x02000000
#define AKM_BIPGMAC128		0x04000000
#define AKM_BIBGMAC256		0x08000000
#define AKM_BIPCMAC256		0x10000000
#define AKM_UNKNOWN		0x80000000
 u32		rsnie;
 u32		wpaie;
 u32		wpsie;
 u16		frequency;
 u8		rssi;
 char		*encmode;
 char		country[2];
 u8		essidlen;
 u8		essid[ESSID_MAX];
 }apdata_t;
#define APDATA_SIZE (sizeof(apdata_t))
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 time_t		tsakt;
 u8		maca[ETH_ALEN];
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
