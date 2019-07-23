#define _GNU_SOURCE
#include <getopt.h>
#include <signal.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "include/version.h"
#include "include/rpigpio.h"


#define HCX_GPIO_BUTTON		1
#define HCX_GPIO_STATUSLED	2
#define HCX_HELP		'h'
#define HCX_VERSION		'v'

/*===========================================================================*/
/* global var */

static int gpiostatusled;
static int gpiobutton;
static struct timespec sleepled;
/*===========================================================================*/
static inline size_t chop(char *buffer, size_t len)
{
static char *ptr;

ptr = buffer +len -1;
while(len)
	{
	if (*ptr != '\n')
		break;
	*ptr-- = 0;
	len--;
	}
while(len)
	{
	if (*ptr != '\r')
		break;
	*ptr-- = 0;
	len--;
	}
return len;
}
/*---------------------------------------------------------------------------*/
static inline int fgetline(FILE *inputstream, size_t size, char *buffer)
{
static size_t len;
static char *buffptr;

if(feof(inputstream))
	return -1;
buffptr = fgets (buffer, size, inputstream);
if(buffptr == NULL)
	return -1;
len = strlen(buffptr);
len = chop(buffptr, len);
return len;
}
/*===========================================================================*/
static bool initgpio(int gpioperi)
{
static int fd_mem;

fd_mem = open("/dev/mem", O_RDWR|O_SYNC);
if(fd_mem < 0)
	{
	fprintf(stderr, "failed to get device memory\n");
	return false;
	}

gpio_map = mmap(NULL, BLOCK_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd_mem, GPIO_BASE +gpioperi);
close(fd_mem);

if(gpio_map == MAP_FAILED)
	{
	fprintf(stderr, "failed to map GPIO memory\n");
	return false;
	}

gpio = (volatile unsigned *)gpio_map;

return true;
}
/*===========================================================================*/
static int getrpirev()
{
static FILE *fh_rpi;
static int len;
static int rpi = 0;
static int rev = 0;
static int gpioperibase = 0;
static char *revptr = NULL;
static char *revstr = "Revision";
static char *hwstr = "Hardware";
static char *snstr = "Serial";
static char linein[128];

fh_rpi = fopen("/proc/cpuinfo", "r");
if(fh_rpi == NULL)
	{
	perror("failed to retrieve cpuinfo");
	return gpioperibase;
	}
while(1)
	{
	if((len = fgetline(fh_rpi, 128, linein)) == -1)
		{
		break;
		}
	if(len < 15)
		{
		continue;
		}
	if(memcmp(&linein, hwstr, 8) == 0)
		{
		rpi |= 1;
		continue;
		}
	if(memcmp(&linein, revstr, 8) == 0)
		{
		rpirevision = strtol(&linein[len -6], &revptr, 16);
		if((revptr - linein) == len)
			{
			rev = (rpirevision >> 4) &0xff;
			if(rev <= 3)
				{
				gpioperibase = GPIO_PERI_BASE_OLD;
				rpi |= 2;
				continue;
				}
			if(rev == 0x09)
				{
				gpioperibase = GPIO_PERI_BASE_OLD;
				rpi |= 2;
				continue;
				}
			if(rev == 0x0c)
				{
				gpioperibase = GPIO_PERI_BASE_OLD;
				rpi |= 2;
				continue;
				}
			if((rev == 0x04) || (rev == 0x08) || (rev == 0x0d) || (rev == 0x00e) || (rev == 0x011))
				{
				gpioperibase = GPIO_PERI_BASE_NEW;
				rpi |= 2;
				continue;
				}
			continue;
			}
		rpirevision = strtol(&linein[len -4], &revptr, 16);
		if((revptr - linein) == len)
			{
			if((rpirevision < 0x02) || (rpirevision > 0x15))
				{
				continue;
				}
			if((rpirevision == 0x11) || (rpirevision == 0x14))
				{
				continue;
				}
			gpioperibase = GPIO_PERI_BASE_OLD;
			rpi |= 2;
			}
		continue;
		}
	if(memcmp(&linein, snstr, 6) == 0)
		{
		rpi |= 4;
		continue;
		}
	}
fclose(fh_rpi);

if(rpi < 0x7)
	{
	return 0;
	}
return gpioperibase;
}
/*===========================================================================*/
static bool globalinit()
{
static int gpiobasemem = 0;

sleepled.tv_sec = 0;
sleepled.tv_nsec = GPIO_LED_DELAY;

if((gpiobutton > 0) || (gpiostatusled > 0))
	{
	if(gpiobutton == gpiostatusled)
		{
		fprintf(stderr, "same value for wpi_button and wpi_statusled is not allowed\n");
		return false;
		}
	gpiobasemem = getrpirev();
	if(gpiobasemem == 0)
		{
		fprintf(stderr, "failed to locate GPIO\n");
		return false;
		}
	if(initgpio(gpiobasemem) == false)
		{
		fprintf(stderr, "failed to init GPIO\n");
		return false;
		}
	if(gpiostatusled > 0)
		{
		INP_GPIO(gpiostatusled);
		OUT_GPIO(gpiostatusled);
		}
	if(gpiobutton > 0)
		{
		INP_GPIO(gpiobutton);
		}
	}

return true;
}
/*===========================================================================*/
static void ledflash()
{
if(gpiostatusled == 0)
	{
	return;
	}

GPIO_SET = 1 << gpiostatusled;
nanosleep(&sleepled, NULL);
GPIO_CLR = 1 << gpiostatusled;
nanosleep(&sleepled, NULL);
GPIO_SET = 1 << gpiostatusled;
nanosleep(&sleepled, NULL);
GPIO_CLR = 1 << gpiostatusled;
nanosleep(&sleepled, NULL);
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void waitloop()
{
static int ret = 0;
static int count = 0;

while(1)
	{
	if(GET_GPIO(gpiobutton) > 0)
		{
		if(GET_GPIO(gpiobutton) > 0)
			{
			if(gpiostatusled > 0)
				{
				GPIO_CLR = 1 << gpiostatusled;
				nanosleep(&sleepled, NULL);
				GPIO_SET = 1 << gpiostatusled;
				nanosleep(&sleepled, NULL);
				GPIO_CLR = 1 << gpiostatusled;
				nanosleep(&sleepled, NULL);
				GPIO_SET = 1 << gpiostatusled;
				nanosleep(&sleepled, NULL);
				}
			ret = system("poweroff");
			if(ret != 0)
				{
				puts("poweroff failed!");
				exit(EXIT_FAILURE);
				}
			}
		}
	sleep(1);
	count++;
	if(count < 5)
		{
		continue;
		}
	ledflash();
	count = 0;
	}
}
/*===========================================================================*/
__attribute__ ((noreturn))
static inline void version(char *eigenname)
{
printf("%s %s (wpi version) (C) %s ZeroBeat\n", eigenname, VERSION, VERSION_JAHR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usage(char *eigenname)
{
printf("%s %s (wpi version) (C) %s ZeroBeat\n"
	"usage  : %s <options>\n"
	"         press the button to power off\n"
	"         hardware modification is necessary, read more:\n"
	"         https://github.com/ZerBea/hcxdumptool/tree/master/docs\n" 
	"\n"
	"options:\n"
	"-h       : show this help\n"
	"-v       : show version\n"
	"\n"
	"--gpio_button=<digit>    : Raspberry Pi GPIO pin number of button (2...27)\n"
	"                           default = GPIO not in use\n"
	"--gpio_statusled=<digit> : Raspberry Pi GPIO number of status LED (2...27)\n"
	"                           default = GPIO not in use\n"
	"--help                   : show this help\n"
	"--version                : show version\n"
	"\n"
	"run gpio readall to print a table of all accessable pins and their numbers\n"
	"(wiringPi, BCM_GPIO and physical pin numbers)\n"
	"\n",
	eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usageerror(char *eigenname)
{
printf("%s %s (wpi version) (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl;
static int index;

static const char *short_options = "hv";
static const struct option long_options[] =
{
	{"gpio_button",		required_argument,	NULL,	HCX_GPIO_BUTTON},
	{"gpio_statusled",	required_argument,	NULL,	HCX_GPIO_STATUSLED},
	{"version",		no_argument,		NULL,	HCX_VERSION},
	{"help",		no_argument,		NULL,	HCX_HELP},
	{NULL,			0,			NULL,	0}
};

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;
gpiostatusled = 0;
gpiobutton = 0;

while((auswahl = getopt_long(argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCX_GPIO_BUTTON:
		gpiobutton = strtoll(optarg, NULL, 10);
		if((gpiobutton < 2) || (gpiobutton > 27))
			{
			fprintf(stderr, "only 2...27 allowed\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_GPIO_STATUSLED:
		gpiostatusled = strtoll(optarg, NULL, 10);
		if((gpiostatusled < 2) || (gpiostatusled > 27))
			{
			fprintf(stderr, "only 2...27 allowed\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_HELP:
		usage(basename(argv[0]));
		break;

		case HCX_VERSION:
		version(basename(argv[0]));
		break;

		case '?':
		usageerror(basename(argv[0]));
		break;
		}
	}

if((gpiobutton == 0) && (gpiostatusled == 0))
	{
	fprintf(stderr, "no GPIO pin selected\n");
	exit(EXIT_FAILURE);
	}

if(globalinit() == false)
	{
	exit(EXIT_FAILURE);
	}

waitloop();

return EXIT_SUCCESS;
}
/*===========================================================================*/
