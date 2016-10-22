/*
   Copyright 2016 Vanderbilt University
   
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

/**
 * @file command.c
 * Implements filesystem operations (mostly metadata things)
 */

#include <lio/lio.h>
#include <string.h>

#include "lstore_dsi.h"

int plugin_checksum(lstore_handle_t *h, char *path, char **response) {
    int retval = -1;

    /*
     * Adler32 checksum in human-readable form is 8 bytes long. Additionally add
     * an extra byte for the null terminator
     */
    int buf_length = 9 * sizeof(char);
    char *buf = malloc(buf_length);
    retval = lio_getattr(lio_gc,
                            lio_gc->creds,
                            path,
                            NULL,
                            "user.gridftp.adler32",
                            (void **) &buf,
                            &buf_length);

    if (retval != OP_STATE_SUCCESS) {
        const char *errstr2 = "-FAIL-";
        memcpy(buf, errstr2, strlen(errstr2) + 1);
    }
    (*response) = buf;

    return (retval == OP_STATE_SUCCESS) ? 0 : -3;
}

int plugin_mkdir(lstore_handle_t *h, char *path) {
    int retval = gop_sync_exec(lio_create_gop(lio_gc, lio_gc->creds, path,
                                                OS_OBJECT_DIR, NULL, NULL));
    return retval;
}

int plugin_rmdir(lstore_handle_t *h, char *path) {
    // FIXME Unsure if this is supposed to be recursive or not
    return 0;
}

int plugin_rm(lstore_handle_t *h, char *path) {
    struct stat file_info;
    char *readlink = NULL;
    int retval = lio_stat(lio_gc, lio_gc->creds, path, &file_info, h->prefix, &readlink);
    if (retval == -ENOENT) {
        return 0;
    }
    retval = gop_sync_exec(lio_remove_gop(lio_gc, lio_gc->creds, path,
                                                NULL, 0));
    return retval;
}

