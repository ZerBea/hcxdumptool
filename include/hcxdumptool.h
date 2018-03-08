#define MACAPESSIDLISTZEMAX 256
#define NETWORKLISTZEMAX 512
#define ERRORMAX 100000

#define TIME_INTERVAL 5

/*===========================================================================*/
struct arg_s
{
 uint32_t	waittime;
} __attribute__((__packed__));
typedef struct arg_s arg_t;
/*===========================================================================*/
struct networklist_s
{
 long int	tv_sec;
 long int	tv_usec;
 uint8_t	status;
 uint8_t	mac_sta[6];
 uint8_t	mac_ap[6];
 uint8_t	essid_len;
 uint8_t	essid[32];
};
typedef struct networklist_s networklist_t;
#define	NETWORKLIST_SIZE (sizeof(networklist_t))

static int sort_networklist_by_time(const void *a, const void *b)
{
const networklist_t *ia = (const networklist_t *)a;
const networklist_t *ib = (const networklist_t *)b;
if(ia->tv_sec < ib->tv_sec)
	return 1;
else if(ia->tv_sec > ib->tv_sec)
	return -1;
if(ia->tv_usec < ib->tv_usec)
	return 1;
else if(ia->tv_usec > ib->tv_usec)
	return -1;
return 0;
}
/*===========================================================================*/
struct macessidlist_s
{
 long int	tv_sec;
 long int	tv_usec;
 uint8_t	status;
 uint8_t	addr[6];
 uint8_t	essid_len;
 uint8_t	essid[32];
};
typedef struct macessidlist_s macessidlist_t;
#define	MACESSIDLIST_SIZE (sizeof(macessidlist_t))

static int sort_macessidlist_by_time(const void *a, const void *b)
{
const macessidlist_t *ia = (const macessidlist_t *)a;
const macessidlist_t *ib = (const macessidlist_t *)b;
if(ia->tv_sec < ib->tv_sec)
	return 1;
else if(ia->tv_sec > ib->tv_sec)
	return -1;
if(ia->tv_usec < ib->tv_usec)
	return 1;
else if(ia->tv_usec > ib->tv_usec)
	return -1;
return 0;
}
/*===========================================================================*/
