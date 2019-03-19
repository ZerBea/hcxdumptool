#define _GNU_SOURCE
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <wiringPi.h>

#include "include/version.h"

#define HCX_WPI_BUTTON		1
#define HCX_WPI_STATUSLED	2
#define HCX_HELP		'h'
#define HCX_VERSION		'v'

#define DEFAULTWPISTATUSLED	0
#define DEFAULTWPIBUTTON	7

/*===========================================================================*/
/* global var */

static int wpistatusled;
static int wpibutton;

/*===========================================================================*/
static bool globalinit()
{
if(wiringPiSetup() == -1)
	{
	puts("wiringPi failed!");
	return false;
	}

pinMode(wpistatusled, OUTPUT);
pinMode(wpibutton, INPUT);
return true;
}
/*===========================================================================*/
static void ledflash()
{
digitalWrite(wpistatusled, HIGH);
delay (20);
digitalWrite(wpistatusled, LOW);
delay (200);
digitalWrite(wpistatusled, HIGH);
delay (20);
digitalWrite(wpistatusled, LOW);
delay (20);
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
	if(digitalRead(wpibutton) == HIGH)
		{
		digitalWrite(wpistatusled, HIGH);
		ret = system("poweroff");
		if(ret != 0)
			{
			puts("poweroff failed!");
			exit(EXIT_FAILURE);
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
	"--wpi_button=<digit>    : wiringPi number of of button (0...31)\n"
	"                          Raspberry Pi A and B (0...16)\n"
	"                          default = 7\n"
	"--wpi_statusled=<digit> : wiringPi number of status LED (0...31)\n"
	"                          Raspberry Pi A and B (0...16)\n"
	"                          default = 0\n"
	"--help                  : show this help\n"
	"--version               : show version\n"
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
	{"wpi_button",		required_argument,	NULL,	HCX_WPI_BUTTON},
	{"wpi_statusled",	required_argument,	NULL,	HCX_WPI_STATUSLED},
	{"version",		no_argument,		NULL,	HCX_VERSION},
	{"help",		no_argument,		NULL,	HCX_HELP},
	{NULL,			0,			NULL,	0}
};

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;
wpistatusled = DEFAULTWPISTATUSLED;
wpibutton = DEFAULTWPIBUTTON;

while((auswahl = getopt_long(argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCX_WPI_BUTTON:
		wpibutton = strtoll(optarg, NULL, 10);
		if((wpibutton < 0) || (wpibutton > 31))
			{
			fprintf(stderr, "only 0...31 allowed\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_WPI_STATUSLED:
		wpistatusled = strtoll(optarg, NULL, 10);
		if((wpistatusled < 0) || (wpistatusled > 31))
			{
			fprintf(stderr, "only 0...31 allowed\n");
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

if(wpibutton == wpistatusled)
	{
	fprintf(stderr, "same value for wpi_button and wpi_statusled is not allowed\n");
	exit(EXIT_FAILURE);
	}

if(globalinit() == false)
	{
	system("poweroff");
	}

waitloop();

return EXIT_SUCCESS;
}
/*===========================================================================*/
