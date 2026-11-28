/* Prints what the kernel says about the clock's sync, as the agent's time_sync
 * collector reads it, for capture-unix.sh. Asking changes nothing (modes is 0), so
 * it needs no root. */
#include <stdio.h>
#include <sys/timex.h>

int main(void) {
    struct timex tx = {0};
    int state = ntp_adjtime(&tx);
    if (state < 0) {
        perror("ntp_adjtime");
        return 1;
    }
    printf("state=%d\nstatus=0x%x\nmaxerror=%ld\nesterror=%ld\noffset=%ld\n", state,
           (unsigned)tx.status, (long)tx.maxerror, (long)tx.esterror, (long)tx.offset);
    return 0;
}
