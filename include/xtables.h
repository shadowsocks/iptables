#ifndef _XTABLES_H
#define _XTABLES_H

extern void *fw_calloc(size_t count, size_t size);
extern void *fw_malloc(size_t size);

extern const char *modprobe;
extern int xtables_insmod(const char *modname, const char *modprobe, int quiet);

#endif /* _XTABLES_H */
