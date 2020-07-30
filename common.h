#ifndef COMMON_H
#define COMMON_H

#define LOG(format__, ...) fprintf(stdout, PROGRAM_NAME ": %s " format__ "\n", now_epoch_usec_str(), __VA_ARGS__)
#define FATAL(...) (LOG(__VA_ARGS__), exit(1))
#define ASSERT(cond__) ((cond__) ? 0 : FATAL("%s", #cond__))

typedef enum {
    SENDER_TYPE_FE,
    SENDER_TYPE_BE,
} sender_type_t;

/* Don't be tempted to use gettimeofday, we need to use the time value provided by libpcap so that savefile
   times work. */
struct timeval global_now;

static uint64_t timeval_to_usec(const struct timeval *tv) {
    uint64_t result = tv->tv_sec;
    result *= 1000000;
    result += tv->tv_usec;
    return result;
}

static uint64_t now_epoch_usec() {
    return timeval_to_usec(&global_now);
}

static void set_now(const struct timeval *tv) {
    memcpy(&global_now, tv, sizeof(global_now));
}

/* sprintf is too slow and strtoll does weird stuff. */
static char *uint64_to_dec_str(char *num_str, uint64_t i) {
    char reversed[64];
    char *reversed_ptr = reversed;
    do {
      *reversed_ptr++ = '0' + i % 10;
      i = i/10;
    } while (i != 0);
    
    while (--reversed_ptr >= reversed) {
      *num_str++ = *reversed_ptr;
    }
    
    *num_str = '\0';
    return num_str;
}

static const char *now_epoch_usec_str() {
    static char s[64];
    uint64_to_dec_str(s, now_epoch_usec());
    return s;
}

#endif
