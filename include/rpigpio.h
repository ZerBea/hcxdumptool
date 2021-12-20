#define RASPBERRY_INFO	2048
#define GPIO_LED_DELAY	100000000

#define PAGE_SIZE	(4*1024)
#define BLOCK_SIZE	(4*1024)

#define INP_GPIO(g) *(gpio +((g) /10)) &= ~(7 << (((g) %10) *3))
#define OUT_GPIO(g) *(gpio +((g) /10)) |=  (1 << (((g) %10) *3))
#define GPIO_SET *(gpio +7)
#define GPIO_CLR *(gpio +10)
#define GET_GPIO(g) (*(gpio +13) & (1 << g))

static void *gpio_map;
static volatile unsigned *gpio;
