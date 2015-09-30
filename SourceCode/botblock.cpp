/*
The purpose of this tool is to monitor the tcp traffic and find if you are communicating with any malicious IP address.
The tool will pope up the malicious IP address,user has choice to block or whitelist the ip address.
__author__ = "SREEJITH KOVILAKATHUVEETTIL CHANDRAN"
__copyright__ = " Copyright 2015,SREEJITH KOVILAKATHUVEETTIL CHANDRAN"
__email__ = "sreeju_kc@hotmail.com"
__license__ = "Apache License 2.0"

*/

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define  _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <regex>
#include <stdlib.h>
#include <string.h>
#include <Shlwapi.h>
#include "sqlite3.h"
#include "db.h"
#include <Windows.h>
#include "fwblock.h"
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#define MALLOC(x) HeapAlloc(GetProcessHeap(), 0, (x))
#define FREE(x) HeapFree(GetProcessHeap(), 0, (x))

using namespace std;

int c = 0;
char dip[256] = { 0 };
char rip[256] = { 0 };
regex rp("^(192\.168\.([0,1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([0,1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))$");
regex rs("^(172\.(1[6-9]|2[0-9]|3[0-1])\.([0,1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([0,1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))$");
regex rc("^(169\.254\.([0,1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.([0,1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))$");
regex rx("^(10\.(([0,1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.){2}([0,1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))$");
regex rr("^(127\.(([0,1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.){2}([0,1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))$");
regex rk("^(0\.(([0,1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5])\.){2}([0,1]?[0-9]{1,2}|2[0-4][0-9]|25[0-5]))$");
bool mathp;
bool maths;
bool mathc;
bool mathx;
bool mathr;
bool mathk;

int tcpch();
int selects(char *ip);
int inserts(char *ip);
int cselects(char *ip);

int main()
{
	FreeConsole();
	while (TRUE) {
		tcpch();
		Sleep(1000);

	}



	return 0;
}



int tcpch()
{
	PMIB_TCPTABLE2 pTcpTable;
	DWORD dwSize = 0;
	DWORD dwRetVal = 0;
	ULONG ulSize = 0;
	unsigned int pid;

	/*LPCTSTR path = "C:\\botdetect";
	int retval = PathFileExists(path);
	if (!retval) {
		CreateDirectory(path, NULL);
	}*/

	char srAddr[128];
	char drAddr[128];

	struct in_addr IpAddr;
	/* FILE *logs;

	logs = fopen("C:\\BotBlock\\botnetlogs.txt", "a"); */


	char malip[256];

	int i;

	pTcpTable = (MIB_TCPTABLE2 *)MALLOC(sizeof(MIB_TCPTABLE2));
	if (pTcpTable == NULL) {
		printf("Error allocating memory\n");
		return 1;
	}
	ulSize = sizeof(MIB_TCPTABLE);


	if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) ==
		ERROR_INSUFFICIENT_BUFFER) {
		FREE(pTcpTable);
		pTcpTable = (MIB_TCPTABLE2 *)MALLOC(ulSize);
		if (pTcpTable == NULL) {
			printf("Error allocating memory\n");
			return 1;
		}
	}
	int nument;
	if ((dwRetVal = GetTcpTable2(pTcpTable, &ulSize, TRUE)) == NO_ERROR) {

		nument = (int)pTcpTable->dwNumEntries;

		for (i = 0; i < (int)pTcpTable->dwNumEntries; i++) {

			IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwLocalAddr;
			strcpy_s(srAddr, sizeof(srAddr), inet_ntoa(IpAddr));
			IpAddr.S_un.S_addr = (u_long)pTcpTable->table[i].dwRemoteAddr;
			strcpy_s(drAddr, sizeof(drAddr), inet_ntoa(IpAddr));
			pid = (unsigned int)pTcpTable->table[i].dwOwningPid;

			cmatch narrowMatch;

			const char * ss;
			ss = (const char *)drAddr;
			const char *sss = ss + strlen(ss);


			if (!((mathx = regex_match(ss, sss, narrowMatch, rx)) || (maths = regex_match(ss, sss, narrowMatch, rs)) || (mathp = regex_match(ss, sss, narrowMatch, rp)) || (mathc = regex_match(ss, sss, narrowMatch, rc)) || (mathr = regex_match(ss, sss, narrowMatch, rr)) || (mathk = regex_match(ss, sss, narrowMatch, rk)))) {
				int selc = selects(drAddr);
				if (selc == 100) {
					int csel = cselects(drAddr);
					if (csel == 101) {
						time_t rawtime;
						struct tm * timeinfo;
						char test[3] = "\n";
						time(&rawtime);
						timeinfo = localtime(&rawtime);
						char *time = (char *)asctime(timeinfo);
						strtok(time, "\n");
						char *inf = " : You have tried to contact a malicious IP address ";
						char *info = " , please contact your local administrator immediatly ";
						FILE *lgs;
						lgs = fopen("C:\\BotBlock\\botnetlogs.txt", "a");
						if (lgs != NULL) {
							fprintf(lgs, "%s%s%s%s", time, inf, drAddr, info);
							Sleep(50);
							fprintf(lgs, "\n");
							Sleep(20);
							fprintf(lgs, "----------------------------------------------------------------------------------------------------------------------------------------------\n");
							Sleep(50);
							fprintf(lgs, "\n");
							Sleep(50);
							//fclose(lgs);
							//return 0;
						} 
						char mess[1000] = "You are trying to contact a malicious IP ";
						char mm[500] = "\nPlease check the logs in C:\\BotBlock\\botlogs.txt\nPlease click 'Yes' to block in local firewall,click 'No' to whitelist";
						strcat(mess, drAddr);
						strcat(mess, mm);
						DWORD dwProcessId = (DWORD)pid;
						message(mess,drAddr,dwProcessId);
						if (lgs) {
							fclose(lgs);
						}
						
					}
					

				}

			}

		}

	}
	else {
		printf("\tGetTcpTable failed with %d\n", dwRetVal);
		FREE(pTcpTable);
		return 1;
	}

	if (pTcpTable != NULL) {
		FREE(pTcpTable);
		pTcpTable = NULL;
		return 0;
	}
	return 0;
}
