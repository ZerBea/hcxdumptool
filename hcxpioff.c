#define _GNU_SOURCE
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wiringPi.h>


/*===========================================================================*/
static void ledflash()
{
digitalWrite(0, HIGH);
delay (20);
digitalWrite(0, LOW);
delay (200);
digitalWrite(0, HIGH);
delay (20);
digitalWrite(0, LOW);
delay (20);
return;
}
/*===========================================================================*/
int main()
{
int ret;
int count;
if(wiringPiSetup() == -1)
	{
	puts("wiringPi failed!");
	system("poweroff");
	}

pinMode(0, OUTPUT);
pinMode(7, INPUT);

count = 0;
ledflash();
while(1)
	{
	if(digitalRead(7) == 1)
		{
		digitalWrite(0, HIGH);
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
return EXIT_SUCCESS;
}
/*===========================================================================*/
