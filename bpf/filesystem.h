// SPDX-License-Identifier: GPL-2.0

#ifndef PODTRACE_FILESYSTEM_H
#define PODTRACE_FILESYSTEM_H

#include "common.h"
#include "maps.h"

static inline int get_path_str_from_file(struct file *file, char *out_buf, u32 buf_size)
{
    if (file == NULL || out_buf == NULL || buf_size < 2)
        return 0;

    struct path path;
    bpf_core_read(&path, sizeof(path), &file->f_path);
    
    struct dentry *dentry;
    bpf_core_read(&dentry, sizeof(dentry), &path.dentry);
    if (dentry == NULL)
        return 0;

    out_buf[0] = '\0';
    return 0;
}

#endif

