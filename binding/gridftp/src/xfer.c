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
 * @file recv.c
 * Necessary bits to receive data from a client and write to LStore
 */

#include <globus_gridftp_server.h>

#include "lstore_dsi.h"

int plugin_xfer_init(lstore_handle_t *h,
                        globus_gfs_transfer_info_t * transfer_info,
                        xfer_direction_t direction) {
    int open_flags;
    if (direction == XFER_RECV) {
        open_flags = lio_fopen_flags("w");
    } else if (direction == XFER_SEND) {
        open_flags = lio_fopen_flags("r");
    } else {
        // Shouldn't happen.
        return -1;
    }
    
    if (transfer_info->expected_checksum) {
        char *tmp = strdup(transfer_info->expected_checksum);
        if (!tmp) {
            return -1;
        }
        h->expected_checksum = tmp;
    } else {
        h->expected_checksum = NULL;
    }

    h->path = copy_path_to_lstore(h->prefix, transfer_info->pathname);
    if (!h->path) {
        goto error_alloc;
    }
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] Before open: %p\n", h->fd);
    int retval = gop_sync_exec(lio_open_gop(lio_gc,
                                lio_gc->creds,
                                h->path,
                                open_flags,
                                NULL,
                                &(h->fd), 60));
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] After open: %p ret: %d\n", h->fd, retval);
    if (retval != OP_STATE_SUCCESS || (!h->fd)) {
        goto error_open;
    }

    if (transfer_info->alloc_size > 0) {
        gop_sync_exec(lio_truncate_gop(h->fd, -transfer_info->alloc_size));
    }
    return retval;

error_open:
    free(h->path);
    h->path = NULL;
error_alloc:
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] Open failure\n", h->fd);
    return -1;
}

