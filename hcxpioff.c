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
#include <sys/time.h>

#include "include/rpigpio.h"

#define HCX_GPIO_BUTTON		1
#define HCX_GPIO_STATUSLED	2
#define HCX_TOT			3
#define HCX_REBOOT		4
#define HCX_POWER_OFF		5
#define HCX_HELP		'h'
#define HCX_VERSION		'v'
/*===========================================================================*/
/* global var */

static int gpiostatusled;
static int gpiobutton;
static struct timespec sleepled;
struct timeval tv;
struct timeval tvtot;

static bool poweroffflag;
static bool rebootflag;
/*===========================================================================*/
__attribute__ ((noreturn))
static void globalclose()
{
if(gpiostatusled > 0) GPIO_SET = 1 << gpiostatusled;
if(poweroffflag == true)
	{
	if(system("poweroff") != 0)
		{
		fprintf(stderr, "can't power off\n");
		exit(EXIT_FAILURE);
		}
	}
if(rebootflag == true)
	{
	if(system("reboot") != 0)
		{
		fprintf(stderr, "can't reboot\n");
		exit(EXIT_FAILURE);
		}
	}
exit(EXIT_SUCCESS);
}
/*===========================================================================*/
static inline size_t chop(char *buffer, size_t len)
{
static char *ptr;

ptr = buffer +len -1;
while(len)
	{
	if (*ptr != '\n') break;
	*ptr-- = 0;
	len--;
	}
while(len)
	{
	if (*ptr != '\r') break;
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

if(feof(inputstream)) return -1;
buffptr = fgets (buffer, size, inputstream);
if(buffptr == NULL) return -1;
len = strlen(buffptr);
len = chop(buffptr, len);
return len;
}
/*===========================================================================*/
static bool initgpio(unsigned int gpioperi)
{
static int fd_mem;

fd_mem = open("/dev/mem", O_RDWR|O_SYNC);
if(fd_mem < 0)
	{
	fprintf(stderr, "failed to get device memory\n");
	return false;
	}
gpio_map = mmap(NULL, BLOCK_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fd_mem, gpioperi);
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
static inline unsigned int getgpiobasemem()
{
static FILE *cpuinfo;
static FILE *iomem;
static int len;
static bool rpi = false;
static unsigned int gpioperibase = 0;
static char linein[RASPBERRY_INFO];

cpuinfo = fopen("/proc/cpuinfo", "r");
if(cpuinfo == NULL)
	{
	perror("failed to retrieve cpuinfo");
	return gpioperibase;
	}
while(1)
	{
	if((len = fgetline(cpuinfo, RASPBERRY_INFO, linein)) == -1) break;
	if(strstr(linein, "Raspberry Pi")) rpi = true;
	}
fclose(cpuinfo);
if(rpi == false) return gpioperibase;
iomem = fopen("/proc/iomem", "r");
if(iomem == NULL)
	{
	perror("failed to retrieve iomem");
	return gpioperibase;
	}
while(1)
	{
	if((len = fgetline(iomem, RASPBERRY_INFO, linein)) == -1) break;
	if(strstr(linein, ".gpio") != NULL)
		{
		if(linein[8] != '-') break;
			{
			linein[8] = 0;
			gpioperibase = strtoul(linein, NULL, 16);
			break;
			}
		}
	}
fclose(iomem);
return gpioperibase;
}
/*===========================================================================*/
static bool globalinit()
{
static unsigned int gpiobasemem = 0;

sleepled.tv_sec = 0;
sleepled.tv_nsec = GPIO_LED_DELAY;
if((gpiobutton > 0) || (gpiostatusled > 0))
	{
	if(gpiobutton == gpiostatusled)
		{
		fprintf(stderr, "same value for wpi_button and wpi_statusled is not allowed\n");
		return false;
		}
	gpiobasemem = getgpiobasemem();
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
	if(gpiobutton > 0) INP_GPIO(gpiobutton);
	}
return true;
}
/*===========================================================================*/
static void ledflash()
{
if(gpiostatusled == 0) return;
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
static int count = 1;
while(1)
	{
	if(GET_GPIO(gpiobutton) > 0) globalclose();
	gettimeofday(&tv, NULL);
	if(tv.tv_sec >= tvtot.tv_sec) globalclose();
	if((count %5) == 0) ledflash();
	count++;
	sleep(1);
	}
}
/*===========================================================================*/
__attribute__ ((noreturn))
static inline void version(char *eigenname)
{
fprintf(stdout, "%s %s (wpi version) (C) %s ZeroBeat\n", eigenname, VERSION_TAG, VERSION_YEAR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usage(char *eigenname)
{
fprintf(stdout, "%s %s (wpi version) (C) %s ZeroBeat\n"
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
	"--tot=<digit>            : enable timeout timer in minutes (minimum = 2 minutes)\n"
	"                         : hcxpioff will terminate if tot reached\n"
	"--reboot                 : once hcxpioff terminated, reboot system\n"
	"                         : default: power off system\n"
	"--help                   : show this help\n"
	"--version                : show version\n"
	"\n"
	"run gpio readall to print a table of all accessible pins and their numbers\n"
	"(wiringPi, BCM_GPIO and physical pin numbers)\n"
	"\n",
	eigenname, VERSION_TAG, VERSION_YEAR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usageerror(char *eigenname)
{
fprintf(stdout, "%s %s (wpi version) (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSION_TAG, VERSION_YEAR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl;
static int index;
static long int totvalue;

static const char *short_options = "hv";
static const struct option long_options[] =
{
	{"gpio_button",		required_argument,	NULL,	HCX_GPIO_BUTTON},
	{"gpio_statusled",	required_argument,	NULL,	HCX_GPIO_STATUSLED},
	{"tot",			required_argument,	NULL,	HCX_TOT},
	{"reboot",		no_argument,		NULL,	HCX_REBOOT},
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
rebootflag = false;
poweroffflag = true;
tvtot.tv_sec = 2147483647L;
tvtot.tv_usec = 0;

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

		case HCX_TOT:
		totvalue = strtol(optarg, NULL, 10);
		if(totvalue < 2)
			{
			fprintf(stderr, "tot must be >= 2 (minutes)\n");
			exit(EXIT_FAILURE);
			}
		gettimeofday(&tvtot, NULL);
		tvtot.tv_sec += totvalue *60;
		break;

		case HCX_REBOOT:
		rebootflag = true;
		poweroffflag = false;
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

if(globalinit() == false) exit(EXIT_FAILURE);
if((gpiobutton > 0) && (gpiostatusled > 0)) waitloop();

return EXIT_SUCCESS;
}
/*===========================================================================*/
