#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>

#include "pcap.h"
/*===========================================================================*/
uint16_t addoption(uint8_t *posopt, uint16_t optioncode, uint16_t optionlen, char *option)
{
uint16_t padding;
option_header_t *optionhdr;

optionhdr = (option_header_t*)posopt;
optionhdr->option_code = optioncode;
optionhdr->option_length = optionlen;
padding = (4 -(optionlen %4)) %4;
memset(optionhdr->option_data, 0, optionlen +padding); 
memcpy(optionhdr->option_data, option, optionlen);
return optionlen + padding +4;
}
/*===========================================================================*/
uint16_t addcustomoptionheader(uint8_t *pospt)
{
int colen;
option_header_t *optionhdr;

optionhdr = (option_header_t*)pospt;
optionhdr->option_code = SHB_CUSTOM_OPT;
colen = OH_SIZE;
memcpy(pospt +colen, &hcxmagic, 4);
colen += 4;
memcpy(pospt +colen, &hcxmagic, 32);
colen += 32;
return colen;
}
/*===========================================================================*/
uint16_t addcustomoption(uint8_t *pospt, uint8_t *macap, uint64_t rcrandom, uint8_t *anonce, uint8_t *macsta, uint8_t *snonce, uint8_t wclen, char *wc)
{
int colen;
option_header_t *optionhdr;
optionfield64_t *of;

optionhdr = (option_header_t*)pospt;
optionhdr->option_code = SHB_CUSTOM_OPT;
colen = OH_SIZE;
memcpy(pospt +colen, &hcxmagic, 4);
colen += 4;
memcpy(pospt +colen, &hcxmagic, 32);
colen += 32;

colen += addoption(pospt +colen, OPTIONCODE_MACAP, 6, (char*)macap);
of = (optionfield64_t*)(pospt +colen);
of->option_code = OPTIONCODE_RC;
of->option_length = 8;
of->option_value = rcrandom;
colen += 12;
colen += addoption(pospt +colen, OPTIONCODE_ANONCE, 32, (char*)anonce);
colen += addoption(pospt +colen, OPTIONCODE_MACCLIENT, 6, (char*)macsta);
colen += addoption(pospt +colen, OPTIONCODE_SNONCE, 32, (char*)snonce);
colen += addoption(pospt +colen, OPTIONCODE_WEAKCANDIDATE, wclen, wc);
colen += addoption(pospt +colen, 0, 0, NULL);
optionhdr->option_length = colen -OH_SIZE;
return colen;
}
/*===========================================================================*/
bool writecb(int fd, uint8_t *macap, uint64_t rcrandom, uint8_t *anonce, uint8_t *macsta, uint8_t *snonce, uint8_t wclen, char *wc)
{
int cblen;
int written;
custom_block_t *cbhdr;
optionfield64_t *of;
total_length_t *totallength;
uint8_t cb[2048];

memset(&cb, 0, 2048);
cbhdr = (custom_block_t*)cb;
cblen = CB_SIZE;
cbhdr->block_type = CBID;
cbhdr->total_length = CB_SIZE;
memcpy(cbhdr->pen, &hcxmagic, 4);
memcpy(cbhdr->hcxm, &hcxmagic, 32);

cblen += addoption(cb +cblen, OPTIONCODE_MACAP, 6, (char*)macap);
of = (optionfield64_t*)(cb +cblen);
of->option_code = OPTIONCODE_RC;
of->option_length = 8;
of->option_value = rcrandom;
cblen += 12;
cblen += addoption(cb +cblen, OPTIONCODE_ANONCE, 32, (char*)anonce);
cblen += addoption(cb +cblen, OPTIONCODE_MACCLIENT, 6, (char*)macsta);
cblen += addoption(cb +cblen, OPTIONCODE_SNONCE, 32, (char*)snonce);
cblen += addoption(cb +cblen, OPTIONCODE_WEAKCANDIDATE, wclen, wc);
cblen += addoption(cb +cblen, 0, 0, NULL);

totallength = (total_length_t*)(cb +cblen);
cblen += TOTAL_SIZE;
cbhdr->total_length = cblen;
totallength->total_length = cblen;
written = write(fd, &cb, cblen);
if(written != cblen)
	{
	close(fd);
	return false;
	}
return true;
}
/*===========================================================================*/
bool writeisb(int fd, uint32_t interfaceid, uint64_t starttimestamp, uint64_t incomming)
{
int written;
struct timeval tvend;
uint64_t endtimestamp;

interface_statistics_block_t *isbhdr;
uint8_t isb[1024];

memset(&isb, 0, 256);
isbhdr = (interface_statistics_block_t*)isb;
isbhdr->block_type = ISBID;
isbhdr->total_length = ISB_SIZE;
isbhdr->interface_id = interfaceid;
gettimeofday(&tvend, NULL);
endtimestamp = ((uint64_t)tvend.tv_sec * 1000000) + tvend.tv_usec;
isbhdr->timestamp_high = endtimestamp >> 32;
isbhdr->timestamp_low = (uint32_t)endtimestamp &0xffffffff;

isbhdr->code_starttime = ISB_STARTTIME;
isbhdr->starttime_len = 8;
isbhdr->starttime_timestamp_high = starttimestamp >> 32;
isbhdr->starttime_timestamp_low = (uint32_t)starttimestamp &0xffffffff;

isbhdr->code_endtime = ISB_ENDTIME;
isbhdr->endtime_len = 8;
isbhdr->endtime_timestamp_high = endtimestamp >> 32;
isbhdr->endtime_timestamp_low = (uint32_t)endtimestamp &0xffffffff;

isbhdr->code_recv = ISB_IFRECV;
isbhdr->recv_len = 8;
isbhdr->recv = incomming;

isbhdr->code_ifdrop = ISB_IFDROP;
isbhdr->ifdrop_len = 8;
isbhdr->ifdrop = 0;

isbhdr->code_filteraccept = ISB_FILTERACCEPT;
isbhdr->filteraccept_len = 8;
isbhdr->filteraccept = incomming;

isbhdr->code_osdrop = ISB_OSDROP;
isbhdr->osdrop_len = 8;
isbhdr->osdrop = 0;

isbhdr->code_usredliv = ISB_USRDELIV;
isbhdr->usredliv_len = 8;
isbhdr->usredliv = incomming;

isbhdr->code_eoo = 0;
isbhdr->eoo_len = 0;
isbhdr->total_length_dup = ISB_SIZE;

written = write(fd, &isb, ISB_SIZE);
if(written != ISB_SIZE)
	{
	close(fd);
	return false;
	}
return true;
}
/*===========================================================================*/
bool writeidb(int fd, uint8_t *macorig, char *interfacestr)
{
int idblen;
int written;
interface_description_block_t *idbhdr;
total_length_t *totallength;
char vendor[6];
uint8_t idb[1024];

memset(&idb, 0, 256);
idblen = IDB_SIZE;
idbhdr = (interface_description_block_t*)idb;
idbhdr->block_type = IDBID;
idbhdr->linktype = DLT_IEEE802_11_RADIO;
idbhdr->reserved = 0;
idbhdr->snaplen = PCAPNG_MAXSNAPLEN;
idblen += addoption(idb +idblen, IF_NAME, strlen(interfacestr), interfacestr);
memset(&vendor, 0, 6);
memcpy(&vendor, macorig, 3);
idblen += addoption(idb +idblen, IF_MACADDR, 6, vendor);
idblen += addoption(idb +idblen, SHB_EOC, 0, NULL);

totallength = (total_length_t*)(idb +idblen);
idblen += TOTAL_SIZE;
idbhdr->total_length = idblen;
totallength->total_length = idblen;

written = write(fd, &idb, idblen);
if(written != idblen)
	{
	close(fd);
	return false;
	}
return true;
}
/*===========================================================================*/
bool writeshb(int fd, uint8_t *macap, uint64_t rcrandom, uint8_t *anonce, uint8_t *macsta, uint8_t *snonce, uint8_t wclen, char *wc)
{
int shblen;
int written;
section_header_block_t *shbhdr;

total_length_t *totallength;
struct utsname unameData;
char sysinfo[256];
uint8_t shb[1024];

memset(&shb, 0, 256);
shblen = SHB_SIZE;
shbhdr = (section_header_block_t*)shb;
shbhdr->block_type = PCAPNGBLOCKTYPE;
#ifdef BIG_ENDIAN_HOST
shbhdr->byte_order_magic = PCAPNGMAGICNUMBERBE;
#else
shbhdr->byte_order_magic = PCAPNGMAGICNUMBER;
#endif
shbhdr->byte_order_magic = PCAPNGMAGICNUMBER;
shbhdr->major_version = PCAPNG_MAJOR_VER;
shbhdr->minor_version = PCAPNG_MINOR_VER;
shbhdr->section_length = -1;
if(uname(&unameData) == 0)
	{
	shblen += addoption(shb +shblen, SHB_HARDWARE, strlen(unameData.machine), unameData.machine);
	sprintf(sysinfo, "%s %s", unameData.sysname, unameData.release);
	shblen += addoption(shb +shblen, SHB_OS, strlen(sysinfo), sysinfo);
	sprintf(sysinfo, "hcxdumptool %s", VERSION);
	shblen += addoption(shb +shblen, SHB_USER_APPL, strlen(sysinfo), sysinfo);
	}

shblen += addcustomoption(shb +shblen, macap, rcrandom, anonce, macsta, snonce, wclen, wc);
shblen += addoption(shb +shblen, SHB_EOC, 0, NULL);
totallength = (total_length_t*)(shb +shblen);
shblen += TOTAL_SIZE;
shbhdr->total_length = shblen;
totallength->total_length = shblen;

written = write(fd, &shb, shblen);
if(written != shblen)
	{
	close(fd);
	return false;
	}
return true;
}
/*===========================================================================*/
int hcxcreatepcapngdump(char *pcapngdumpname, uint8_t *macorig, char *interfacestr, uint8_t *macap, uint64_t rc, uint8_t *anonce, uint8_t *macsta, uint8_t *snonce, uint8_t wclen, char *wc)
{
int c;
int fd;
struct stat statinfo;
char newpcapngoutname[PATH_MAX +2];

c = 0;
strcpy(newpcapngoutname, pcapngdumpname);
while(stat(newpcapngoutname, &statinfo) == 0)
	{
	snprintf(newpcapngoutname, PATH_MAX, "%s-%d", pcapngdumpname, c);
	c++;
	}

umask(0);
fd = open(newpcapngoutname, O_WRONLY | O_CREAT, 0644);
if(fd == -1)
	{
	return -1;
	}

if(writeshb(fd, macap, rc, anonce, macsta, snonce, wclen, wc) == false)
	{
	return -1;
	}

if(writeidb(fd, macorig, interfacestr) == false)
	{
	return -1;
	}

if(writecb(fd, macap, rc, anonce, macsta, snonce, wclen, wc) == false)
	{
	return -1;
	}
return fd;
}
/*===========================================================================*/
