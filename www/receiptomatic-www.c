/*
 * receiptomatic-www.c
 *
 * Copyright (C) 2011-2012	OpenTech Labs
 *				Andrew Clayton <andrew@opentechlabs.co.uk>
 * Released under the GNU Affero General Public License version 3.
 * See COPYING
 */

/* FastCGI stdio wrappers */
#include <fcgi_stdio.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>
#include <sys/sysinfo.h>

#include "common.h"
#include "get_config.h"
#include "receiptomatic_config.h"
#include "url_handlers.h"
#include "receiptomatic-www.h"

extern char **environ;
static char **rargv;

static volatile sig_atomic_t create_new_server;
static volatile sig_atomic_t dump_sessions;
static volatile sig_atomic_t clear_sessions;
static volatile sig_atomic_t rotate_log_files;

char *log_dir = "/tmp";
static char access_log_path[PATH_MAX];
static char error_log_path[PATH_MAX];
static char sql_log_path[PATH_MAX];
static char debug_log_path[PATH_MAX];

FILE *access_log;
FILE *sql_log;
FILE *error_log;
FILE *debug_log;

/*
 * Decide how many worker processes should be created.
 *
 * If we have a specified number in the config file (NR_PROCS), use
 * that.
 *
 * Else try getting the number of available processors and fork one
 * process per processor.
 *
 * Else just create a single worker.
 */
static int get_nr_procs(void)
{
	if (NR_PROCS > 0)
		return NR_PROCS;
	else if (get_nprocs() > 0)
		return get_nprocs();
	else
		return 1;
}

/*
 * This function will change the process name to 'title'
 *
 * This is likely to only work on Linux and basically just makes a
 * copy of the environment and clobbers the old one with the new name.
 *
 * Based on code from; nginx
 */
static void set_proc_title(const char *title)
{
	size_t size = 0;
	int i;
	char *p;
	char *argv_last;

	for (i = 0; environ[i]; i++)
		size += strlen(environ[i]) + 1;

	p = malloc(size);
	if (!p) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}

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
 * signal handler for SIGUSR1, sets a flag to inform that
 * dump_sessions_state() should be run.
 */
static void sh_dump_session_state(int signo)
{
	dump_sessions = 1;
}

/*
 * Dumps session state upon receiving a SIGUSR2
 */
static void dump_session_state(void)
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
		unsigned char capabilities;

		rbuf = tclistval(res, i, &rsize);
		cols = tctdbget(tdb, rbuf, rsize);
		tcmapiterinit(cols);

		fprintf(debug_log, "\tsid          : %s\n", tcmapget2(cols,
								"sid"));
		fprintf(debug_log, "\tuid          : %s\n", tcmapget2(cols,
								"uid"));
		capabilities = atoi(tcmapget2(cols, "capabilities"));
		fprintf(debug_log, "\tcapabilities : (%d) %s %s %s %s %s %s\n",
				capabilities,
				capabilities & ADMIN ? "admin," : "",
				capabilities & APPROVER ? "approver -" : "",
				capabilities & APPROVER_CARD ? "card" : "",
				capabilities & APPROVER_CASH ? "cash" : "",
				capabilities & APPROVER_CHEQUE ? "cheque" : "",
				capabilities & APPROVER_SELF ? "self" : "");
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
		fprintf(debug_log, "\tcsrf_token   : %s\n", tcmapget2(cols,
								"csrf_token"));
		fprintf(debug_log, "\trestrict_ip  : %s\n\n",
				tcmapget2(cols, "restrict_ip")[0] == '1' ?
				"true" : "false");
		tcmapdel(cols);
	}
	tclistdel(res);
	tctdbqrydel(qry);

	tctdbclose(tdb);
	tctdbdel(tdb);

	fflush(debug_log);

	dump_sessions = 0;
}

/*
 * Signal handler to handle child process terminations.
 */
static void reaper(int signo)
{
	int status;

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
		create_new_server = 1;
}

/*
 * Upon receiving the TERM signal, terminate all children and exit.
 */
static void terminate(int signo)
{
	kill(0, SIGTERM);
	_exit(EXIT_SUCCESS);
}

/*
 * signal handler for SIGRTMIN, sets a flag to inform that
 * clear_old_sessions() should be run.
 */
static void sh_clear_old_sessions(int sig, siginfo_t *si, void *uc)
{
	clear_sessions = 1;
}

/*
 * Clear out old sessions that haven't been accessed (last_seen) since
 * SESSION_EXPIRY ago.
 */
static void clear_old_sessions(void)
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

	clear_sessions = 0;
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

	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_RESTART;
	action.sa_sigaction = sh_clear_old_sessions;
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

/*
 * signal handler for SIGHUP, sets a flag to inform that
 * the log files should be closed and reopened for log file
 * rotation.
 */
static void sh_rotate_log_files(int signo)
{
	rotate_log_files = 1;
}

static void init_logs(void)
{
	if (rotate_log_files) {
		d_fprintf(debug_log,
			  "logrotation: closing and re-opening log files\n");

		fclose(access_log);
		fclose(error_log);
		fclose(sql_log);
		fclose(debug_log);

		/*
		 * The log files need to be opened for appending here or
		 * they will get truncated while other processes have them
		 * open.
		 */
		access_log = fopen(ACCESS_LOG, "a");
		error_log = fopen(ERROR_LOG, "a");
		sql_log = fopen(SQL_LOG, "a");
		debug_log = fopen(DEBUG_LOG, "a");
	} else {
		snprintf(access_log_path, PATH_MAX,
			 "%s/receiptomatic-www.access.log", LOG_DIR);
		snprintf(error_log_path, PATH_MAX,
			 "%s/receiptomatic-www.error.log", LOG_DIR);
		snprintf(sql_log_path, PATH_MAX,
			 "%s/receiptomatic-www.sql.log", LOG_DIR);
		snprintf(debug_log_path, PATH_MAX,
			 "%s/receiptomatic-www.debug.log", LOG_DIR);

		access_log = fopen(ACCESS_LOG, "w");
		error_log = fopen(ERROR_LOG, "w");
		sql_log = fopen(SQL_LOG, "w");
		debug_log = fopen(DEBUG_LOG, "w");
	}

	/* Make stderr point to the error_log */
	dup2(fileno(error_log), STDERR_FILENO);

	rotate_log_files = 0;
}

/*
 * Send a SIGHUP signal to the worker processes to notify them
 * about log file rotation.
 *
 * Close and re-open the log files.
 *
 * This function should _only_ be called from the master process.
 * The worker processes should just call init_logs() directy.
 */
static void logfile_rotation(void)
{
	sigset_t hup;

	/*
	 * We don't want the master process receiving the
	 * HUP signal itself.
	 */
	sigemptyset(&hup);
	sigaddset(&hup, SIGHUP);
	sigprocmask(SIG_BLOCK, &hup, NULL);
	kill(0, SIGHUP);
	sigprocmask(SIG_UNBLOCK, &hup, NULL);

	init_logs();
}

/*
 * Main program loop. This sits in accept() waiting for connections.
 */
static void accept_request(void)
{
	/*
	 * We use SIGUSR2 to dump the session state which we only want
	 * handled by the parent process. Ignore it in the children.
	 */
	signal(SIGUSR2, SIG_IGN);
	/*
	 * We use SIGRTMIN to clear out old sessions. This signal is
	 * produced by a timer. We only want this signal handled in the
	 * parent so ignore it in the children.
	 */
	signal(SIGRTMIN, SIG_IGN);

	while (FCGI_Accept() >= 0) {
		if (rotate_log_files)
			init_logs();
		handle_request();
		FCGI_Finish();
	}

	/* If we get here, something went wrong */
	_exit(EXIT_FAILURE);
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

	create_new_server = 0;
}

int main(int argc, char **argv)
{
	struct sigaction action;
	int ret;

	/* Used by set_proc_title() */
	rargv = argv;

	/* Set the log paths and open them */
	init_logs();

	ret = get_config(argv[1]);
	if (ret == -1) {
		d_fprintf(error_log, "config: could not open %s\n", argv[1]);
		goto close_logs;
	}

	ret = mysql_library_init(0, NULL, NULL);
	if (ret) {
		d_fprintf(error_log, "mysql: could not initialise library.\n");
		goto close_logs;
	}

	/* Ignore SIGPIPE as per the fastcgi faq */
	signal(SIGPIPE, SIG_IGN);

	/* Setup signal handler for SIGHUP for logfile rotation */
	sigemptyset(&action.sa_mask);
	action.sa_handler = sh_rotate_log_files;
	action.sa_flags = SA_RESTART;
	sigaction(SIGHUP, &action, NULL);

	/* Setup signal handler for SIGUSR2 to dump session state */
	sigemptyset(&action.sa_mask);
	action.sa_handler = sh_dump_session_state;
	action.sa_flags = SA_RESTART;
	sigaction(SIGUSR2, &action, NULL);

	/*
	 * Setup a signal handler for SIGTERM to terminate all the
	 * child processes.
	 */
	sigemptyset(&action.sa_mask);
	action.sa_handler = terminate;
	action.sa_flags = 0;
	sigaction(SIGTERM, &action, NULL);

	/*
	 * Setup a signal handler for SIGCHLD to handle child
	 * process terminations.
	 */
	sigemptyset(&action.sa_mask);
	action.sa_handler = reaper;
	action.sa_flags = 0;
	sigaction(SIGCHLD, &action, NULL);

	init_clear_session_timer();

	/* Pre-fork worker processes */
	create_server(get_nr_procs());

	/* Set the process name for the master process */
	set_proc_title("receiptomatic-www: master");

	/*
	 * To make the signal handlers as simple as possible and
	 * reentrant safe, they just set flags to say what should
	 * be done.
	 *
	 * The simplest way to check these is to wake up periodically, which
	 * is what we currently do. The more complex way is the self-pipe
	 * trick. p. 1370, The Linux Programming Interface - M. Kerrisk
	 *
	 * Changed from sleep() to pause() which matches more what we want.
	 */
	for (;;) {
		pause();
		if (create_new_server)
			create_server(1);
		if (dump_sessions)
			dump_session_state();
		if (clear_sessions)
			clear_old_sessions();
		if (rotate_log_files)
			logfile_rotation();
	}

	mysql_library_end();

close_logs:
	fclose(access_log);
	fclose(error_log);
	fclose(sql_log);
	fclose(debug_log);

	/* We shouldn't run through to here */
	exit(EXIT_FAILURE);
}
