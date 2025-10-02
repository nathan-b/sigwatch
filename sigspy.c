// sigspy.c: LD_PRELOAD to trace signal handler installs
#define _GNU_SOURCE
#include <dlfcn.h>
#include <execinfo.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static int (*real_sigaction)(int, const struct sigaction*, struct sigaction*) = NULL;
static __sighandler_t (*real_signal)(int, __sighandler_t) = NULL;

static void log_stack(const char* what, int signo, void* handler) {
  void* addrs[20]; int n = backtrace(addrs, 20);
  fprintf(stderr, "[sigspy] %s sig=%d handler=%p pid=%d\n", what, signo, handler, getpid());
  backtrace_symbols_fd(addrs, n, STDERR_FILENO);
}

int sigaction(int signo, const struct sigaction* act, struct sigaction* oldact) {
  if (!real_sigaction) {
    real_sigaction = dlsym(RTLD_NEXT, "sigaction");
  }
  if (act) {
    log_stack("sigaction", signo, (void*)(act->sa_flags & SA_SIGINFO ? act->sa_sigaction : act->sa_handler));
  }
  return real_sigaction(signo, act, oldact);
}

__sighandler_t signal(int signo, __sighandler_t handler) {
  if (!real_signal) {
    real_signal = dlsym(RTLD_NEXT, "signal");
  }
  log_stack("signal", signo, (void*)handler);
  return real_signal(signo, handler);
}

