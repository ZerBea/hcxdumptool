#ifndef __BYTE_ORDER
# error "Please fix ENDIANESS <endian.h>"
#endif
/*===========================================================================*/
#define __hcxbswab16(x) \
	((u16)((((u16)(x) & (u16) 0x00ffU) << 8u) \
	| (((u16)(x) & (u16) 0xff00U) >> 8u)))

#define __hcxbswab32(x) \
	((u32)((((u32)(x) & (u32) 0x000000ffUL) << 24u) \
	| (((u32)(x) & (u32) 0x0000ff00UL) << 8u) \
	| (((u32)(x) & (u32) 0x00ff0000UL) >> 8u) \
	| (((u32)(x) & (u32) 0xff000000UL) >> 24u)))

#define __hcxbswab64(x) \
	((u64)((u64)(((u64)(x) & (u64) 0x00000000000000ffULL) << 56u) \
	| (u64)(((u64)(x) & (u64) 0x000000000000ff00ULL) << 40u) \
	| (u64)(((u64)(x) & (u64) 0x0000000000ff0000ULL) << 24u) \
	| (u64)(((u64)(x) & (u64) 0x00000000ff000000ULL) << 8u) \
	| (u64)(((u64)(x) & (u64) 0x000000ff00000000ULL) >> 8u) \
	| (u64)(((u64)(x) & (u64) 0x0000ff0000000000ULL) >> 24u) \
	| (u64)(((u64)(x) & (u64) 0x00ff000000000000ULL) >> 40u) \
	| (u64)(((u64)(x) & (u64) 0xff00000000000000ULL) >> 56u)))
/*---------------------------------------------------------------------------*/
#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __hcx16le(x) (u16)(x)
#define __hcx32le(x) (u32)(x)
#define __hcx64le(x) (u64)(x)
#define __hcx16be(x) __hcxbswab16(x)
#define __hcx32be(x) __hcxbswab32(x)
#define __hcx64be(x) __hcxbswab64(x)
#elif __BYTE_ORDER == __BIG_ENDIAN
#define __hcx16le(x) __hcxbswab16(x)
#define __hcx32le(x) __hcxbswab32(x)
#define __hcx64le(x) __hcxbswab64(x)
#define __hcx16be(x) (u16)(x)
#define __hcx32be(x) (u32)(x)
#define __hcx64be(x) (u64)(x)
#endif
/*===========================================================================*/
