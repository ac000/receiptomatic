/*
 * receiptomatic-www.c
 *
 * Copyright (C) 2011		OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU General Public License (GPL) version 3.
 * See COPYING
 */

#define _XOPEN_SOURCE		/* for strptime(), crypt() */

/* FastCGI stdio wrappers */
#include <fcgi_stdio.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>

#include "common.h"
#include "get_config.h"
#include "url_handlers.h"
#include "receiptomatic-www.h"

extern char **environ;
static char **rargv;

FILE *access_log;
FILE *sql_log;
FILE *error_log;
FILE *debug_log;

/*
 * Main program loop. This sits in accept() waiting for connections.
 */
static void accept_request(void)
{
	/*
	 * We use SIGUSR1 to dump the session state which we only want
	 * handled by the parent process. Ignore it in the children.
	 */
	signal(SIGUSR1, SIG_IGN);
	/*
	 * We use SIGRTMIN to clear out old sessions. This signal is
	 * produced by a timer. We only want this signal handled in the
	 * parent so ignore it in the children.
	 */
	signal(SIGRTMIN, SIG_IGN);

	while (FCGI_Accept() >= 0) {
		handle_request();
		FCGI_Finish();
	}

	/* If we get here, something went wrong */
	_exit(EXIT_FAILURE);
}

/*
 * This function will change the process name to 'title'
 *
 * This is likely to only work on Linux and basically just makes a
 * copy of the environment and clobbers the old one with the new name.
 *
 * Based on code from; nginx
 */
static void set_proc_title(char *title)
{
	size_t size = 0;
	int i;
	char *p;
	char *argv_last;

	for (i = 0; environ[i]; i++)
		size += strlen(environ[i]) + 1;

	p = malloc(size);

	argv_last = rargv[0] + strlen(rargv[0]) + 1;

	for (i = 0; rargv[i]; i++) {
		if (argv_last == rargv[i])
			argv_last = rargv[i] + strlen(rargv[i]) + 1;
	}

	for (i = 0; environ[i]; i++) {
		if (argv_last == environ[i]) {
			size = strlen(environ[i]) + 1;
			argv_last = environ[i] + size;

			strncpy(p, environ[i], size);
			environ[i] = p;
			p += size;
		}
	}
	argv_last--;

	rargv[1] = NULL;
	p = strncpy(rargv[0], title, argv_last - rargv[0]);
}

/*
 * Create nr server processes.
 */
static void create_server(int nr)
{
	int i;

	for (i = 0; i < nr; i++) {
		pid_t pid;

		pid = fork();
		if (pid == 0) {  /* child */
			set_proc_title("receiptomatic-www: worker");
			accept_request();
		}
	}
}

/*
 * Dumps session state upon receiving a SIGUSR1
 */
static void dump_session_state(int signo)
{
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;
	TCMAP *cols;
	int i;
	int rsize;
	int nres;
	const char *rbuf;

	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOREADER);

	qry = tctdbqrynew(tdb);
	res = tctdbqrysearch(qry);
	nres = tclistnum(res);
	fprintf(debug_log, "Number of active sessions: %d\n", nres);
	for (i = 0; i < nres; i++) {
		rbuf = tclistval(res, i, &rsize);
		cols = tctdbget(tdb, rbuf, rsize);
		tcmapiterinit(cols);

		fprintf(debug_log, "\tsid          : %s\n", tcmapget2(cols,
								"sid"));
		fprintf(debug_log, "\tuid          : %s\n", tcmapget2(cols,
								"uid"));
		fprintf(debug_log, "\tcapabilities : %s\n", tcmapget2(cols,
							"capabilities"));
		fprintf(debug_log, "\tusername     : %s\n", tcmapget2(cols,
								"username"));
		fprintf(debug_log, "\tname         : %s\n", tcmapget2(cols,
								"name"));
		fprintf(debug_log, "\tlogin_at     : %s\n", tcmapget2(cols,
								"login_at"));
		fprintf(debug_log, "\tlast_seen    : %s\n", tcmapget2(cols,
								"last_seen"));
		fprintf(debug_log, "\torigin_ip    : %s\n", tcmapget2(cols,
								"origin_ip"));
		fprintf(debug_log, "\tclient_id    : %s\n", tcmapget2(cols,
								"client_id"));
		fprintf(debug_log, "\tsession_id   : %s\n", tcmapget2(cols,
								"session_id"));
		fprintf(debug_log, "\trestrict_ip  : %s\n\n", tcmapget2(cols,
							"restrict_ip"));
		tcmapdel(cols);
	}
	tclistdel(res);
	tctdbqrydel(qry);

	tctdbclose(tdb);
	tctdbdel(tdb);

	fflush(debug_log);
}

/*
 * Upon receiving the TERM signal, terminate all children and exit.
 */
static void terminate(int signo)
{
	kill(0, SIGTERM);
	exit(EXIT_SUCCESS);
}

/*
 * Clear out old sessions that haven't been accessed (last_seen) since
 * SESSION_EXPIRY ago.
 */
static void clear_old_sessions(int sig, siginfo_t *si, void *uc)
{
	TCTDB *tdb;
	TDBQRY *qry;
	TCLIST *res;
	int i;
	int nres;
	int rsize;
	char expiry[21];
	const char *rbuf;

	d_fprintf(debug_log, "Clearing old sessions\n");

	snprintf(expiry, 21, "%ld", time(NULL) - SESSION_EXPIRY);

	tdb = tctdbnew();
	tctdbopen(tdb, SESSION_DB, TDBOWRITER);

	qry = tctdbqrynew(tdb);
	tctdbqryaddcond(qry, "last_seen", TDBQCNUMLT, expiry);
	res = tctdbqrysearch(qry);
	nres = tclistnum(res);
	if (nres < 1)
		goto out;

	for (i = 0; i < nres; i++) {
		rbuf = tclistval(res, 0, &rsize);
		tctdbout(tdb, rbuf, strlen(rbuf));
	}

out:
	tclistdel(res);
	tctdbqrydel(qry);
	tctdbclose(tdb);
	tctdbdel(tdb);
}

/*
 * Sets up a timer to clear old sessions. Fires every SESSION_CHECK seconds.
 */
static void init_clear_session_timer(void)
{
	timer_t timerid;
	struct sigevent sev;
	struct itimerspec its;
	struct sigaction action;

	memset(&action, 0, sizeof(&action));
	action.sa_flags = SA_RESTART;
	action.sa_sigaction = clear_old_sessions;
	sigemptyset(&action.sa_mask);
	sigaction(SIGRTMIN, &action, NULL);

	sev.sigev_notify = SIGEV_SIGNAL;
	sev.sigev_signo = SIGRTMIN;
	sev.sigev_value.sival_ptr = &timerid;
	timer_create(CLOCK_REALTIME, &sev, &timerid);

	its.it_value.tv_sec = SESSION_CHECK;
	its.it_value.tv_nsec = 0;
	its.it_interval.tv_sec = its.it_value.tv_sec;
	its.it_interval.tv_nsec = its.it_value.tv_nsec;

	timer_settime(timerid, 0, &its, NULL);
}

int main(int argc, char **argv)
{
	struct sigaction action;
	int status;
	int ret;

	/* Used by set_proc_title() */
	rargv = argv;

	mysql_library_init(0, NULL, NULL);

	access_log = fopen("/tmp/receiptomatic-www.access.log", "w");
	error_log = fopen("/tmp/receiptomatic-www.error.log", "w");
	sql_log = fopen("/tmp/receiptomatic-www.sql.log", "w");
	debug_log = fopen("/tmp/receiptomatic-www.debug.log", "w");

	ret = get_config(argv[1]);
	if (ret == -1) {
		d_fprintf(error_log, "config: could not open %s\n", argv[1]);
		exit(EXIT_FAILURE);
	}

	/* Ignore SIGHUP for now */
	signal(SIGHUP, SIG_IGN);

	/* Setup signal handler for USR1 to dump session state */
	memset(&action, 0, sizeof(&action));
	sigemptyset(&action.sa_mask);
	action.sa_handler = dump_session_state;
	action.sa_flags = SA_RESTART;
	sigaction(SIGUSR1, &action, NULL);

	/*
	 * Setup a signal handler for SIGTERM to terminate all the
	 * child processes.
	 */
	memset(&action, 0, sizeof(&action));
	sigemptyset(&action.sa_mask);
	action.sa_handler = terminate;
	action.sa_flags = SA_RESTART;
	sigaction(SIGTERM, &action, NULL);

	init_clear_session_timer();

	/* Pre-fork NR_PROCS worker processes */
	create_server(NR_PROCS);

	/* Set the process name for the master process */
	set_proc_title("receiptomatic-www: master");

	for (;;) {
		waitpid(-1, &status, 0);
		/*
		 * If a process dies, create a new one.
		 *
		 * However, don't create new processes if we get a
		 * SIGTERM or SIGKILL signal as that will stop the
		 * thing from being shutdown.
		 */
		if (WIFSIGNALED(status) && (WTERMSIG(status) != SIGTERM &&
						WTERMSIG(status) != SIGKILL))
			create_server(1);
	}

	mysql_library_end();
	fclose(access_log);
	fclose(error_log);
	fclose(sql_log);
	fclose(debug_log);

	exit(EXIT_SUCCESS);
}
