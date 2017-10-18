#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include "include/log.h"
#include "include/list.h"
#include "include/led.h"
#include "include/signal.h"

void signal_init(void (*_crtlc_cb)(int))
{
	struct sigaction s;
	s.sa_handler = _crtlc_cb;
	s.sa_flags = 0;
	sigaction(SIGTERM, &s, NULL);
}
