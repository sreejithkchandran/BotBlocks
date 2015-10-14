#define  _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE
#include "sqlite3.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#pragma comment(lib, "shlwapi.lib")

void messageout(char * mess, char * title);

int inserts(char *ip)
{
	sqlite3 *dbf;
	sqlite3_stmt *res;
	int rec_count = 0;
	int rc;
	char *errMSG;
	const char *tail;

	LPCTSTR path = "C:\\BotBlock\\exclude.db";
	int retval = PathFileExists(path);
	if (!retval) {
		char mess[1000] = "I can not find 'exclude.db' file, please make sure its in the C:\BotBlock\ folder ";
		char title[500] = "Database Error";
		messageout(mess, title);
		exit(10);
		
	}

	int error = sqlite3_open("C:\\BotBlock\\exclude.db", &dbf);
	if (error)
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(dbf));
		return 10;
		exit(10);
	}

	char *zSQL = sqlite3_mprintf("INSERT INTO malicious VALUES('%s')", ip);

	sqlite3_prepare_v2(dbf, zSQL, -1, &res, 0);

	sqlite3_bind_text(res, 1, ip, strlen(ip), SQLITE_STATIC);
	rc = sqlite3_step(res);
	sqlite3_reset(res);

	if (rc == 0) {
		return 0;
	}
	sqlite3_finalize(res);
	sqlite3_close(dbf);
	return 101;

}

int selects(char *ip)
{
	sqlite3 *db;

	sqlite3_stmt *res;
	int rec_count = 0;
	int rc;
	char *errMSG;
	const char *tail;

	LPCTSTR path = "C:\\BotBlock\\maliciousIP.db";
	int retval = PathFileExists(path);
	if (!retval) {
		char mess[1000] = "I can not find 'maliciousIP.db' file, please make sure its in the C:\BotBlock\ folder ";
		char title[500] = "Database Error";
		messageout(mess, title);
		exit(10);

	}

	int error = sqlite3_open("C:\\BotBlock\\maliciousIP.db", &db);
	if (error)
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		return 10;
		exit(10);
	}

	char *sql = "SELECT * FROM malicious WHERE IP=?";

	sqlite3_prepare_v2(db, sql, -1, &res, 0);
	sqlite3_bind_text(res, 1, ip, strlen(ip), SQLITE_STATIC);
	rc = sqlite3_step(res);
	if (rc == SQLITE_ROW) {
		return 100;
	}

	sqlite3_finalize(res);
	sqlite3_close(db);
	return 101;

}

int cselects(char *ip)
{
	sqlite3 *dbs;
	sqlite3_stmt *res;
	int rec_count = 0;
	int rc;
	char *errMSG;
	const char *tail;

	LPCTSTR path = "C:\\BotBlock\\exclude.db";

	int retval = PathFileExists(path);
	if (!retval) {
		char mess[1000] = "I can not find 'exclude.db' file, please make sure its in the C:\BotBlock\ folder ";
		char title[500] = "Database Error";
		messageout(mess, title);
		exit(10);

	}

	int error = sqlite3_open("C:\\BotBlock\\exclude.db", &dbs);
	if (error)
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(dbs));
		return 10;
		exit(10);
	}

	char *sql = "SELECT * FROM malicious WHERE IP=?";

	sqlite3_prepare_v2(dbs, sql, -1, &res, 0);
	sqlite3_bind_text(res, 1, ip, strlen(ip), SQLITE_STATIC);
	rc = sqlite3_step(res);
	sqlite3_reset(res);

	if (rc == SQLITE_ROW) {
		return 100;
	}

	sqlite3_finalize(res);
	sqlite3_close(dbs);
	return 101;

}

void messageout(char * mess, char * title)
{
	int msgboxID = MessageBox(
		NULL,
		mess,
		title,
		MB_ICONERROR | MB_OK);

	switch (msgboxID)
	{
	case IDOK:
		break;
	}
}
