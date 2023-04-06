/*===========================================================================*/
#define	DLT_IEEE802_11_RADIO	127
/*===========================================================================*/
enum ieee80211_radiotap_presence
{
 IEEE80211_RADIOTAP_TSFT		 = 0x00000001,
 IEEE80211_RADIOTAP_FLAGS		 = 0x00000002,
 IEEE80211_RADIOTAP_RATE		 = 0x00000004,
 IEEE80211_RADIOTAP_CHANNEL		 = 0x00000008,
 IEEE80211_RADIOTAP_FHSS		 = 0x00000010,
 IEEE80211_RADIOTAP_DBM_ANTSIGNAL	 = 0x00000020,
 IEEE80211_RADIOTAP_DBM_ANTNOISE	 = 0x00000040,
 IEEE80211_RADIOTAP_LOCK_QUALITY	 = 0x00000080,
 IEEE80211_RADIOTAP_TX_ATTENUATION	 = 0x00000100,
 IEEE80211_RADIOTAP_DB_TX_ATTENUATION	 = 0x00000200,
 IEEE80211_RADIOTAP_DBM_TX_POWER	 = 0x00000400,
 IEEE80211_RADIOTAP_ANTENNA		 = 0x00000800,
 IEEE80211_RADIOTAP_DB_ANTSIGNAL	 = 0x00001000,
 IEEE80211_RADIOTAP_DB_ANTNOISE		 = 0x00002000,
 IEEE80211_RADIOTAP_RX_FLAGS		 = 0x00004000,
 IEEE80211_RADIOTAP_TX_FLAGS		 = 0x00008000,
 IEEE80211_RADIOTAP_RTS_RETRIES		 = 0x00010000,
 IEEE80211_RADIOTAP_DATA_RETRIES	 = 0x00020000,
 /* 18 is XChannel, not defined */
 IEEE80211_RADIOTAP_MCS			 = 0x00080000,
 IEEE80211_RADIOTAP_AMPDU_STATUS	 = 0x00100000,
 IEEE80211_RADIOTAP_VHT			 = 0x00200000,
 IEEE80211_RADIOTAP_TIMESTAMP		 = 0x00400000,
 /* valid in every it_present bitmap, even vendor namespaces */
 IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE	 = 0x20000000,
 IEEE80211_RADIOTAP_VENDOR_NAMESPACE	 = 0x40000000,
 IEEE80211_RADIOTAP_EXT			 = 0x80000000,
};
/*---------------------------------------------------------------------------*/
enum ieee80211_radiotap_flags
{
 IEEE80211_RADIOTAP_F_CFP = 0x01,
 IEEE80211_RADIOTAP_F_SHORTPRE = 0x02,
 IEEE80211_RADIOTAP_F_WEP = 0x04,
 IEEE80211_RADIOTAP_F_FRAG = 0x08,
 IEEE80211_RADIOTAP_F_FCS = 0x10,
 IEEE80211_RADIOTAP_F_DATAPAD = 0x20,
 IEEE80211_RADIOTAP_F_BADFCS = 0x40,
};
/*===========================================================================*/
typedef struct  __attribute__((__packed__))
{
 u8	it_version;
 u8	it_pad;
 u16	it_len;
 u32	it_present;
}rth_t;
#define	RTHRX_SIZE (ssize_t)(sizeof(rth_t))
/*---------------------------------------------------------------------------*/
static const u8 rthtxdata[] =
{
0x00, 0x00, /* radiotap version and padding */
0x08, 0x00, /* radiotap header length */
0x00, 0x00, 0x00, 0x00, /* bitmap */
};
#define RTHTX_SIZE sizeof(rthtxdata)
/*---------------------------------------------------------------------------*/
static const u8 rthtxnoackdata[] =
{
0x00, 0x00, /* radiotap version and padding */
0x0a, 0x00, /* radiotap header length */
0x00, 0x80, 0x00, 0x00, /* bitmap */
0x18, 0x00 /* tx flags */
};
#define RTHTXNOACK_SIZE sizeof(rthtxnoackdata)
/*===========================================================================*/
