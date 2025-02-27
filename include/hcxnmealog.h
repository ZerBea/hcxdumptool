#define HCX_OUTPUT_NMEA			'n'
#define HCX_OUTPUT_CSV			'c'
#define HCX_GPS_DEVICE			'd'
#define HCX_GPS_BAUDRATE		'b'
#define HCX_IFNAME			'i'
#define HCX_BPF				1

#define HCX_HELP			'h'
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
 float	lat;
 float	lon;
 float	latitude;
 float	longitude;
 float	altitude;
 float	speed;
 float	pdop;
 float	hdop;
 float	vdop;
 int	channel;
 u16	frequency;
 u8	rssi;
 char	ns;
 char	ew;
 char	altitudeunit;
 char	country[2];
 u8	essid[ESSID_MAX];
 u8	essidlen;
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
