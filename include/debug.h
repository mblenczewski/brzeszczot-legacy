#ifndef DEBUG_H
#define DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <assert.h>
#include <stdio.h>

#define errlog(...) fprintf(stderr, __VA_ARGS__)

#ifndef NDEBUG
#define dbglog(...) errlog(__VA_ARGS__)
#else
#define dbglog(...)
#endif /* NDEBUG */

#ifdef __cplusplus
};
#endif /* __cplusplus */

#endif /* DEBUG_H */
