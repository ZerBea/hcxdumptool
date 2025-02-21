#define HCX_OUTPUT_NMEA			'o'
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

#define ESSID_MAX		32

/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u8	rssi;
 u8	essid[ESSID_MAX];
 u8	essidlen;
 }apdata_t;
#define APDATA_SIZE (sizeof(apdata_t))
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 time_t		tv_sec;
 u8		maca[ETH_ALEN];
 apdata_t	*apdata;
}aplist_t;
#define APLIST_SIZE (sizeof(aplist_t))
/*---------------------------------------------------------------------------*/
