#include "sqlite3.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int inserts(char *ip)
{
	sqlite3 *dbf;
	sqlite3_stmt *res;
	int rec_count = 0;
	int rc;
	char *errMSG;
	const char *tail;

	int error = sqlite3_open("C:\\BotBlock\\exclude.db", &dbf);
	if (error)
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(dbf));
		return 10;
	}

	char *zSQL = sqlite3_mprintf("INSERT INTO malicious VALUES('%s')", ip);
	rc = sqlite3_exec(dbf, zSQL, 0, 0, NULL);
	sqlite3_free(zSQL);

	if (rc == 0) {
		return 0;
	}
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

	int error = sqlite3_open("C:\\BotBlock\\maliciousIP.db", &db);
	if (error)
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
		return 10;
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


}

int cselects(char *ip)
{
	sqlite3 *dbs;
	sqlite3_stmt *res;
	int rec_count = 0;
	int rc;
	char *errMSG;
	const char *tail;
	int error = sqlite3_open("C:\\BotBlock\\exclude.db", &dbs);
	if (error)
	{
		fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(dbs));
		return 10;
	}

	char *sql = "SELECT * FROM malicious WHERE IP=?";

	sqlite3_prepare_v2(dbs, sql, -1, &res, 0);
	sqlite3_bind_text(res, 1, ip, strlen(ip), SQLITE_STATIC);
	rc = sqlite3_step(res);

	if (rc == SQLITE_ROW) {
		return 100;
	}

	sqlite3_finalize(res);
	sqlite3_close(dbs);
	return 101;

}
