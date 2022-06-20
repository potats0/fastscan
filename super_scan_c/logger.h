#ifndef LOGGER_H
#define LOGGER_H


void LOG(int level, const char *fmt, ...);

void LOG_add_level(int level);

#endif
