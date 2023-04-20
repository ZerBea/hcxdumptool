/*===========================================================================*/
#define PCAPMAGICNUMBER		0xa1b2c3d4
#define PCAPMAGICNUMBERBE	0xd4c3b2a1

#define PCAPNGBLOCKTYPE		0x0a0d0d0a
#define PCAPNGMAGICNUMBER	0x1a2b3c4d
#define PCAPNGMAGICNUMBERBE	0x4d3c2b1a

#define PCAPNG_MAJOR_VER	1
#define PCAPNG_MINOR_VER	0
#define PCAPNG_BLOCK_SIZE	2048

#define SHB_SYSINFO_LEN		256
/*===========================================================================*/
/* Header of all pcapng options */
typedef struct __attribute__((__packed__))
{
#define SHB_EOC		0
#define SHB_COMMENT	1
#define SHB_HARDWARE	2
#define SHB_OS		3
#define SHB_USER_APPL	4
#define SHB_CUSTOM_OPT	0x0bad

#define IF_NAME		2
#define IF_DESCRIPTION	3
#define IF_MACADDR	6
#define IF_TSRESOL	9
#define IF_TZONE	10

#define TSRESOL_USEC	6
#define TSRESOL_NSEC	9

/* custom option code */
#define OPTIONCODE_MACORIG		0xf29a
#define OPTIONCODE_MACAP		0xf29b
#define OPTIONCODE_RC			0xf29c
#define OPTIONCODE_ANONCE		0xf29d
#define OPTIONCODE_MACCLIENT		0xf29e
#define OPTIONCODE_SNONCE		0xf29f
#define OPTIONCODE_WEAKCANDIDATE	0xf2a0
#define OPTIONCODE_NMEA			0xf2a1

 u16	option_code;	/* option code - depending of block (0 - end of opts, 1 - comment are in common) */
 u16	option_length;	/* option length - length of option in bytes (will be padded to 32bit) */
 char	option_data[1];
}option_header_t;
#define	OH_SIZE offsetof(option_header_t, option_data)
/*===========================================================================*/
/* Option Field */
typedef struct __attribute__((__packed__))
{
 u16	option_code;
 u16	option_length;
 u64	option_value;
}optionfield64_t;
#define	OPTIONFIELD64_SIZE (sizeof(optionfield64_t))
/*===========================================================================*/
/* total length*/
typedef struct __attribute__((__packed__))
{
 u32	total_length;
}total_length_t;
#define	TOTAL_SIZE (sizeof(total_length_t))
/*===========================================================================*/
/* Section Header Block (SHB) - ID 0x0A0D0D0A */
typedef struct __attribute__((__packed__))
{
 u32	block_type;		/* block type */
 u32	total_length;		/* block length */
 u32	byte_order_magic;	/* byte order magic - indicates swapped data */
 u16	major_version;		/* major version of pcapng (1 atm) */
 u16	minor_version;		/* minor version of pcapng (0 atm) */
 s64	section_length;		/* length of section - can be -1 (parsing necessary) */
}section_header_block_t;
#define	SHB_SIZE (sizeof(section_header_block_t))
/*---------------------------------------------------------------------------*/
/* Interface Description Block (IDB) - ID 0x00000001 */
typedef struct __attribute__((__packed__))
 {
 u32	block_type;		/* block type */
#define	IDBID	0x00000001
 u32	total_length;		/* block length */
 u16	linktype;		/* the link layer type (was -network- in classic pcap global header) */
 u16	reserved;		/* 2 bytes of reserved data */
 u32	snaplen;		/* maximum number of bytes dumped from each packet (was -snaplen- in classic pcap global header */
}interface_description_block_t;
#define	IDB_SIZE (sizeof(interface_description_block_t))
/*---------------------------------------------------------------------------*/
/* Custom Block (CB) - ID 0x00000bad */
typedef struct __attribute__((__packed__))
{
 u32	block_type;		/* block type */
#define CBID	0x00000bad
 u32	total_length;		/* block length */
 u8	pen[4];			/* Private Enterprise Number */
 u8	hcxm[32];		/* hcxdumptool magic number */
 u8	data[1];
}custom_block_t;
#define	CB_SIZE offsetof (custom_block_t, data)
/*---------------------------------------------------------------------------*/
/* Enhanced Packet Block (EPB) - ID 0x00000006 */
typedef struct  __attribute__((__packed__))
{
#define EPBID	0x00000006
 u32	block_type;		/* block type */
 u32	total_length;		/* block length */
 u32	interface_id;		/* the interface the packet was captured from - identified by interface description block in current section */
 u32	timestamp_high;		/* high bytes of timestamp */
 u32	timestamp_low;		/* low bytes of timestamp */
 u32	cap_len;		/* length of packet in the capture file (was -incl_len- in classic pcap packet header) */
 u32	org_len;		/* length of packet when transmitted (was -orig_len- in classic pcap packet header) */
}enhanced_packet_block_t;
#define	EPB_SIZE (sizeof(enhanced_packet_block_t))
/*===========================================================================*/
static const u8 hcxmagic[] =
{
0x2a, 0xce, 0x46, 0xa1, 0x79, 0xa0, 0x72, 0x33, 0x83, 0x37, 0x27, 0xab, 0x59, 0x33, 0xb3, 0x62,
0x45, 0x37, 0x11, 0x47, 0xa7, 0xcf, 0x32, 0x7f, 0x8d, 0x69, 0x80, 0xc0, 0x89, 0x5e, 0x5e, 0x98
};
#define	HCXMAGIC_SIZE (sizeof(hcxmagic))
/*===========================================================================*/
