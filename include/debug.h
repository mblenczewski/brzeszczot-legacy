#ifndef DEBUG_H
#define DEBUG_H

#include <assert.h>
#include <stdio.h>

#define errlog(...) fprintf(stderr, __VA_ARGS__)

#ifndef NDEBUG
#define dbglog(...) errlog(__VA_ARGS__)
#endif /* NDEBUG */

#endif /* DEBUG_H */
