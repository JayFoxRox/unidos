#ifndef UNIDOS_DOSPATH_H
#define UNIDOS_DOSPATH_H

struct dospath
{
    char drive;
    unsigned char depth;
    char** path;
};

void path_to_string(struct dospath path, char* buf);

void path_parse(char* str, struct dospath* path);

void path_combine(struct dospath first, struct dospath second, struct dospath* output);

void path_absolute(struct dospath path, struct dospath* output);

void path_copy(struct dospath src, struct dospath* dest);

#endif