#define GPIO_LED_DELAY	100000000

#define GPIO_PERI_BASE_OLD	0x20000000
#define GPIO_PERI_BASE_NEW	0x3F000000
#define GPIO_BASE		0x200000
#define PAGE_SIZE		(4*1024)
#define BLOCK_SIZE		(4*1024)

#define INP_GPIO(g) *(gpio +((g) /10)) &= ~(7 << (((g) %10) *3))
#define OUT_GPIO(g) *(gpio +((g) /10)) |=  (1 << (((g) %10) *3))
#define GPIO_SET *(gpio +7)
#define GPIO_CLR *(gpio +10)
#define GET_GPIO(g) (*(gpio +13) & (1 << g))

static int rpirevision;
static void *gpio_map;
static volatile unsigned *gpio;
