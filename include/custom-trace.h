#ifndef CUSTOM_TRACE
#define CUSTOM_TRACE

#define TRACE_LEVEL_ERROR 0
#define TRACE_LEVEL_WARNING 1
#define TRACE_LEVEL_INFORMATION 2
#define TRACE_LEVEL_VERBOSE 3
#define TRACE_LEVEL_DEBUG 4

#ifndef TRACE_LEVEL
#define TRACE_LEVEL TRACE_LEVEL_ERROR
#endif

static const char* f_err_msg[] = {
    [TRACE_LEVEL_ERROR] = "ERROR",
    [TRACE_LEVEL_WARNING] = "WARNING",
    [TRACE_LEVEL_INFORMATION] = "INFO",
    [TRACE_LEVEL_DEBUG] = "DEBUG",
};

#define TraceEvents(lvl, fmt, args...)                           \
  do {                                                           \
    if (lvl <= TRACE_LEVEL) {                              \
      fprintf(stderr, "%s: " fmt, f_err_msg[lvl], ##args);        \
    }                                                            \
  } while (0)

#if TRACE_LEVEL == TRACE_LEVEL_DEBUG
#define PDEBUG(fmt, args...) TraceEvents(TRACE_LEVEL_DEBUG, fmt, ##args)
#else
#define PDEBUG(fmt, args...)
#endif

#if TRACE_LEVEL >= TRACE_LEVEL_INFORMATION
#define PINFO(fmt, args...) TraceEvents(TRACE_LEVEL_INFORMATION, fmt, ##args)
#else
#define PINFO(fmt, args...)
#endif

#define PERROR(fmt, args...) TraceEvents(TRACE_LEVEL_ERROR, fmt, ##args)

#endif
