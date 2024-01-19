/*===========================================================================*/
#define MAC_SIZE_ACK		(10)
#define MAC_SIZE_RTS		(16)
#define MAC_SIZE_NORM		(24)
#define MAC_SIZE_QOS		(26)
#define MAC_SIZE_LONG		(30)
#define MAC_SIZE_QOS_LONG	(32)

#define FCS_LEN 4

/* types */
#define IEEE80211_FTYPE_MGMT		0x0
#define IEEE80211_FTYPE_CTL		0x1
#define IEEE80211_FTYPE_DATA		0x2
#define IEEE80211_FTYPE_RCVD		0x3

/* management */
#define IEEE80211_STYPE_ASSOC_REQ	0x0
#define IEEE80211_STYPE_ASSOC_RESP	0x1
#define IEEE80211_STYPE_REASSOC_REQ	0x2
#define IEEE80211_STYPE_REASSOC_RESP	0x3
#define IEEE80211_STYPE_PROBE_REQ	0x4
#define IEEE80211_STYPE_PROBE_RESP	0x5
#define IEEE80211_STYPE_BEACON		0x8
#define IEEE80211_STYPE_ATIM		0x9
#define IEEE80211_STYPE_DISASSOC	0xa
#define IEEE80211_STYPE_AUTH		0xb
#define IEEE80211_STYPE_DEAUTH		0xc
#define IEEE80211_STYPE_ACTION		0xd
#define IEEE80211_STYPE_NO_ACTION	0xe
#define IEEE80211_STYPE_MGTRESERVED	0xf

/* control */
#define IEEE80211_STYPE_VHT		0x5
#define IEEE80211_STYPE_CTL_EXT		0x6
#define IEEE80211_STYPE_BACK_REQ	0x8
#define IEEE80211_STYPE_BACK		0x9
#define IEEE80211_STYPE_PSPOLL		0xa
#define IEEE80211_STYPE_RTS		0xb
#define IEEE80211_STYPE_CTS		0xc
#define IEEE80211_STYPE_ACK		0xd
#define IEEE80211_STYPE_CFEND		0xe
#define IEEE80211_STYPE_CFENDACK	0xf

/* data */
#define IEEE80211_STYPE_DATA			0x0
#define IEEE80211_STYPE_DATA_CFACK		0x1
#define IEEE80211_STYPE_DATA_CFPOLL		0x2
#define IEEE80211_STYPE_DATA_CFACKPOLL		0x3
#define IEEE80211_STYPE_NULLFUNC		0x4
#define IEEE80211_STYPE_CFACK			0x5
#define IEEE80211_STYPE_CFPOLL			0x6
#define IEEE80211_STYPE_CFACKPOLL		0x7
#define IEEE80211_STYPE_QOS_DATA		0x8
#define IEEE80211_STYPE_QOS_DATA_CFACK		0x9
#define IEEE80211_STYPE_QOS_DATA_CFPOLL		0xa
#define IEEE80211_STYPE_QOS_DATA_CFACKPOLL	0xb
#define IEEE80211_STYPE_QOS_NULLFUNC		0xc
#define IEEE80211_STYPE_QOS_CFACK		0xd
#define IEEE80211_STYPE_QOS_CFPOLL		0xe
#define IEEE80211_STYPE_QOS_CFACKPOLL		0xf

/* Reason codes (IEEE 802.11-2007, 7.3.1.7, Table 7-22) */
#define WLAN_REASON_UNSPECIFIED 1 /* ok */
#define WLAN_REASON_PREV_AUTH_NOT_VALID 2
#define WLAN_REASON_DEAUTH_LEAVING 3
#define WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY 4
#define WLAN_REASON_DISASSOC_AP_BUSY 5
#define WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA 6 /* ok */
#define WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA 7  /* ok */
#define WLAN_REASON_DISASSOC_STA_HAS_LEFT 8
#define WLAN_REASON_STA_REQ_ASSOC_WITHOUT_AUTH 9
/* IEEE 802.11h */
#define WLAN_REASON_PWR_CAPABILITY_NOT_VALID 10
#define WLAN_REASON_SUPPORTED_CHANNEL_NOT_VALID 11
/* IEEE 802.11i */
#define WLAN_REASON_INVALID_IE 13
#define WLAN_REASON_MICHAEL_MIC_FAILURE 14
#define WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT 15
#define WLAN_REASON_GROUP_KEY_UPDATE_TIMEOUT 16
#define WLAN_REASON_IE_IN_4WAY_DIFFERS 17
#define WLAN_REASON_GROUP_CIPHER_NOT_VALID 18
#define WLAN_REASON_PAIRWISE_CIPHER_NOT_VALID 19
#define WLAN_REASON_AKMP_NOT_VALID 20
#define WLAN_REASON_UNSUPPORTED_RSN_IE_VERSION 21
#define WLAN_REASON_INVALID_RSN_IE_CAPAB 22
#define WLAN_REASON_IEEE_802_1X_AUTH_FAILED 23
#define WLAN_REASON_CIPHER_SUITE_REJECTED 24

#define IEEE80211_SEQ_SEQ_MASK	0xfff0
#define IEEE80211_SEQ_SEQ_SHIFT	4

#define WBIT(n) (1 << (n))
#define WPA_KEY_INFO_TYPE_MASK (WBIT(0) | WBIT(1) | WBIT(2))
#define WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 WBIT(0)
#define WPA_KEY_INFO_TYPE_HMAC_SHA1_AES WBIT(1)
#define WPA_KEY_INFO_KEY_TYPE WBIT(3) /* 1 = Pairwise, 0 = Group key */
#define WPA_KEY_INFO_KEY_INDEX_MASK (WBIT(4) | WBIT(5))
#define WPA_KEY_INFO_KEY_INDEX_SHIFT 4
#define WPA_KEY_INFO_INSTALL WBIT(6)  /* pairwise */
#define WPA_KEY_INFO_TXRX WBIT(6) /* group */
#define WPA_KEY_INFO_ACK WBIT(7)
#define WPA_KEY_INFO_MIC WBIT(8)
#define WPA_KEY_INFO_SECURE WBIT(9)
#define WPA_KEY_INFO_ERROR WBIT(10)
#define WPA_KEY_INFO_REQUEST WBIT(11)
#define WPA_KEY_INFO_ENCR_KEY_DATA WBIT(12) /* IEEE 802.11i/RSN only */
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((packed))
{
 u64	timestamp;
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define HCXTXBEACONINTERVAL	0x0400U
#define HCXTXCAPABILITY		0x0431U
#elif __BYTE_ORDER == __BIG_ENDIAN
#define HCXTXBEACONINTERVAL	0x0004U
#define HCXTXCAPABILITY		0x3104U
#endif
 u16	beacon_interval;
 u16	capability;
 u8	ie[1];
}ieee80211_beacon_proberesponse_t;
#define	IEEE80211_BEACON_SIZE offsetof(ieee80211_beacon_proberesponse_t, ie)
#define	IEEE80211_PROBERESPONSE_SIZE offsetof(ieee80211_beacon_proberesponse_t, ie)
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((packed))
{
 u8	ie[1];
}ieee80211_proberequest_t;
#define	IEEE80211_PROBEREQUEST_SIZE offsetof(ieee80211_proberequest_t, ie)
/*===========================================================================*/
typedef struct __attribute__((__packed__))
{
 u8	category;
#define RADIO_MEASUREMENT	5
 u8	code;
#define NEIGHBOR_REPORT_REQUEST	4
 u8	dialog;
 u8	ie[1];
}ieee80211_action_t;
#define	IEEE80211_ACTION_SIZE offsetof(ieee80211_action_t, ie)
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
#define OPEN_SYSTEM		0
 u16	algorithm;
 u16	sequence;
 u16	status;
 u8	ie[1];
}ieee80211_auth_t;
#define	IEEE80211_AUTH_SIZE offsetof(ieee80211_auth_t, ie)
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u16	capability;
 u16	status;
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define HCXTXAID	0xc001U
#elif __BYTE_ORDER == __BIG_ENDIAN
#define HCXTXAID	0x01c0U
#endif
 u16	aid;
 u8	ie[1];
}ieee80211_assoc_or_reassoc_resp_t;
#define IEEE80211_ASSOCIATIONRESPONSE_SIZE offsetof(ieee80211_assoc_or_reassoc_resp_t, ie)
#define IEEE80211_REASSOCIATIONRESPONSE_SIZE offsetof(ieee80211_assoc_or_reassoc_resp_t, ie)
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u16 capability;
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define HCXTXLISTENINTERVAL	0x0014U
#elif __BYTE_ORDER == __BIG_ENDIAN
#define HCXTXLISTENINTERVAL	0x1400U
#endif
 u16 listen_interval;
 u8	ie[1];
}ieee80211_assoc_req_t;
#define IEEE80211_ASSOCIATIONREQUEST_SIZE offsetof(ieee80211_assoc_req_t, ie)
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u16 capability;
 u16 listen_interval;
 u8 current_macap[ETH_ALEN];
 u8	ie[1];
}ieee80211_reassoc_req_t;
#define IEEE80211_REASSOCIATIONREQUEST_SIZE offsetof(ieee80211_reassoc_req_t, ie)
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u8	id;
#define TAG_SSID	0x00
#define TAG_RATE	0x01
#define TAG_CHAN	0x03
#define TAG_COUNTRY	0x07
#define TAG_RSN		0x30
#define TAG_PAG		0xde
#define TAG_VENDOR	0xdd
 u8 	len;
 u8	ie[1];
}ieee80211_ietag_t;
#define	IEEE80211_IETAG_SIZE offsetof(ieee80211_ietag_t, ie)
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u8	control;
 u8	flags;
}ieee80211_qos_t;
#define	IEEE80211_QOS_SIZE (sizeof(ieee80211_qos_t))
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u8	dsap;
 u8	ssap;
 u8	control;
 u8	org[3];
 u16	type;
#define LLC_TYPE_AUTH	0x888e
#define LLC_TYPE_IPV4	0x0800
#define LLC_TYPE_IPV6	0x86dd
#define LLC_TYPE_PREAUT	0x88c7
#define LLC_TYPE_FRRR	0x890d
}ieee80211_llc_t;
#define	IEEE80211_LLC_SIZE (sizeof(ieee80211_llc_t))
#define	IEEE80211_LLC_SNAP 0xaa
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u8	version;
 u8	type;
#define EAP_PACKET 0
#define EAPOL_START 1
#define EAPOL_LOGOFF 2
#define EAPOL_KEY 3
#define EAPOL_ASF 4
#define EAPOL_MKA 5
 u16	len;
 u8	data[1];
}ieee80211_eapauth_t;
#define	IEEE80211_EAPAUTH_SIZE offsetof(ieee80211_eapauth_t, data)
/*---------------------------------------------------------------------------*/
#define M1	1
#define M2	2
#define M3	3
#define M4	4
typedef struct __attribute__((__packed__))
{
 u8	keydescriptor;
 u16	keyinfo;
 u16	keylen;
 u64	replaycount;
 u8	nonce[32];
 u8	keyiv[16];
 u64	keyrsc;
 u8	keyid[8];
 u8	keymic[16];
 u16	wpadatalen;
 u8	data[1];
}ieee80211_wpakey_t;
#define	IEEE80211_WPAKEY_SIZE offsetof(ieee80211_wpakey_t, data)
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u8	id;
 u8	len;
 u8	oui[3];
 u8	type;
#define PMKID_KDE	4
 u8	pmkid[16];
}ieee80211_pmkid_t;
#define	IEEE80211_PMKID_SIZE (sizeof(ieee80211_pmkid_t))
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u16	version;
}ieee80211_rsnie_t;
#define	IEEE80211_RSNIE_SIZE sizeof(ieee80211_rsnie_t)
#define IEEE80211_RSNIE_LEN_MIN	20
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u8	oui[3];
#define RSN_CS_WEP		1
#define RSN_CS_TKIP		2
#define RSN_CS_WRAP		3
#define RSN_CS_CCMP		4
#define RSN_CS_WEP104		5
#define RSN_AKM_PSK		2
#define RSN_AKM_PSKFT		4
#define RSN_AKM_PSK256		6
 u8	type;
}ieee80211_rnsuite_t;
#define	IEEE80211_RSNSUITE_SIZE sizeof(ieee80211_rnsuite_t)
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u16	count;
}ieee80211_rsnsuitecount_t;
#define	IEEE80211_RSNSUITECOUNT_SIZE sizeof(ieee80211_rsnsuitecount_t)
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
#define MFP_REQUIRED	0x40
 u16	capability;
}ieee80211_rsncapability_t;
#define	IEEE80211_RSNCAPABILITY_SIZE sizeof(ieee80211_rsncapability_t)
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u8	oui[3];
 u8	type;
 u16	version;
}ieee80211_wpaie_t;
#define	IEEE80211_WPAIE_SIZE sizeof(ieee80211_wpaie_t)
#define IEEE80211_WPAIE_LEN_MIN	22
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u8	oui[3];
#define WPA_CS_TKIP		2
#define WPA_CS_CCMP		4
#define WPA_AKM_PSK		2
 u8	type;
}ieee80211_wpasuite_t;
#define IEEE80211_WPASUITE_SIZE sizeof(ieee80211_wpasuite_t)
/*---------------------------------------------------------------------------*/
typedef struct __attribute__((__packed__))
{
 u16	count;
}ieee80211_wpasuitecount_t;
#define	IEEE80211_WPASUITECOUNT_SIZE sizeof(ieee80211_wpasuitecount_t)
/*===========================================================================*/
/* DS bit usage
 *
 * TA = transmitter address
 * RA = receiver address
 * DA = destination address
 * SA = source address
 *
 * ToDS    FromDS  A1(RA)  A2(TA)  A3      A4      Use
 * -----------------------------------------------------------------
 *  0       0       DA      SA      BSSID   -       IBSS/DLS
 *  0       1       DA      BSSID   SA      -       AP -> STA
 *  1       0       BSSID   SA      DA      -       AP <- STA
 *  1       1       RA      TA      DA      SA      unspecified (WDS)
 */

typedef struct __attribute__((__packed__))
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
 unsigned	version : 2;
 unsigned	type : 2;
 unsigned	subtype : 4;

 unsigned	to_ds : 1;
 unsigned	from_ds : 1;
 unsigned	more_frag : 1;
 unsigned	retry : 1;
 unsigned	power : 1;
 unsigned	more_data : 1;
 unsigned	prot : 1;
 unsigned	ordered : 1;
#define HCXTXDURATION	0x013aU
#elif __BYTE_ORDER == __BIG_ENDIAN
 unsigned	subtype : 4;
 unsigned	type : 2;
 unsigned	version : 2;

 unsigned	ordered : 1;
 unsigned	prot : 1;
 unsigned	more_data : 1;
 unsigned	power : 1;
 unsigned	retry : 1;
 unsigned	more_frag : 1;
 unsigned	from_ds : 1;
 unsigned	to_ds : 1;
#define HCXTXDURATION	0x3a01U
#endif
 u16		duration;
 u8		addr1[6];
 u8		addr2[6];
 u8		addr3[6];
 u16		sequence;
 u8		addr4[6];
 ieee80211_qos_t	qos;
}ieee80211_mac_t;
/*===========================================================================*/
static const u8 zeroed[] =
{
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

static const u8 macbc[] =
{
0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

static const u8 rsnsuiteoui[3] =
{
0x00, 0x0f, 0xac
};
static const u8 wpasuiteoui[3] =
{
0x00, 0x50, 0xf2
};

static const int vendoraprg[] =
{
0x00006C, 0x000101, 0x000578, 0x000B18, 0x000BF4, 0x000C53, 0x000D58, 0x000DA7,
0x000DC2, 0x000DF2, 0x000E17, 0x000E22, 0x000E2A, 0x000EEF, 0x000F09, 0x0016B4,
0x001761, 0x001825, 0x002067, 0x00221C, 0x0022F1, 0x00234A, 0x00238C, 0x0023F7,
0x002419, 0x0024FB, 0x00259D, 0x00269F, 0x005047, 0x005079, 0x0050C7, 0x0086A0,
0x00A054, 0x00A085, 0x00CB00, 0x0418B6, 0x0C8112, 0x100000, 0x105F02, 0x10B713,
0x1100AA, 0x111111, 0x146E0A, 0x18421D, 0x1CF4CA, 0x205B2A, 0x20D160, 0x24336C,
0x24FDFA, 0x3CB87A, 0x48062B, 0x487604, 0x48D35D, 0x48F317, 0x4CE136, 0x50E14A,
0x544E45, 0x580943, 0x586ED6, 0x6074F4, 0x609620, 0x60FCF1, 0x68E166, 0x706F81,
0x780B8C, 0x78F944, 0x7CE4AA, 0x806D97, 0x8C0734, 0x8C8401, 0x906F18, 0x90B4DD,
0x980EE4, 0x9C93E4, 0xA06260, 0xA4A6A9, 0xACDE48, 0xB025AA, 0xB0ECE1, 0xB0FEBD,
0xB4E1EB, 0xC8AACC, 0xD85DFB, 0xDC7014, 0xE4F14C, 0xE80410, 0xF03F03, 0xF49DA7 
};
#define VENDORAPRG_SIZE sizeof(vendoraprg)

static const int vendorclientrg[] =
{
0x780B8C, 0x78F944, 0x7CE4AA, 0x806D97, 0x8C0734, 0x8C8401, 0x906F18, 0x90B4DD,
0x980EE4, 0x9C93E4, 0xA06260, 0xA4A6A9, 0xACDE48, 0xB025AA, 0xB0ECE1, 0xB0FEBD,
0xB4E1EB, 0xC8AACC, 0xD85DFB, 0xDC7014, 0xE4F14C, 0xE80410, 0xF03F03, 0xF49DA7
};
#define VENDORCLIENTRG_SIZE sizeof(vendorclientrg)
/*===========================================================================*/

