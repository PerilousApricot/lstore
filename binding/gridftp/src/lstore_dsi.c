/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file lstore_dsi.c
 * Basic GridFTP boilerplate generated from dsi_bones
 *
 * As much as possible, this handles all the conversion to/from GridFTP's API
 * and the rest of the plugin. Hopefully this separation of interests will
 * let the plugin keep clean in spite of the API quirks.
 */

#include <globus_gridftp_server.h>
#include <lio/lio.h>
#include <sys/prctl.h>
#include <time.h>
#include <zlib.h>

#include "lstore_dsi.h"
#include "version.h"

// Forward declaration
static void gfs_send_callback(globus_gfs_operation_t op,
                                globus_result_t result,
                                globus_byte_t *buffer,
                                globus_size_t nbytes,
                                void *user_arg);
/* Marked unread since only gridftp calls it */
void gfs_recv_callback(globus_gfs_operation_t op,
                                globus_result_t result,
                                globus_byte_t * buffer,
                                globus_size_t nbytes,
                                globus_off_t offset,
                                globus_bool_t eof,
                                void * user_arg);
static globus_result_t gfs_xfer_pump(lstore_handle_t *h);
static void gfs_xfer_callback(globus_gfs_operation_t op,
                                globus_result_t result,
                                globus_byte_t * buffer,
                                globus_size_t nbytes,
                                globus_off_t offset,
                                globus_bool_t eof,
                                void * user_arg);
static void globus_l_gfs_file_destroy_stat(
                                globus_gfs_stat_t *stat_array,
                                int stat_count);
static
globus_version_t local_version =
{
    LSTORE_DSI_VERSION_MAJOR, /* major version number */
    LSTORE_DSI_VERSION_MINOR, /* minor version number */
    LSTORE_DSI_TIMESTAMP,
    0 /* branch ID */
};
static void
handler(int sig, siginfo_t *si, void *unused)
{
    globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, "Got SIGSEGV at address: %p\n", si->si_addr);
    exit(EXIT_FAILURE);
}
#define MSG_SIZE 2048
static
void
gridftp_check_core()
{
    int err;
    struct rlimit rlim;
    char err_msg[MSG_SIZE];

    rlim.rlim_cur = RLIM_INFINITY;
    rlim.rlim_max = RLIM_INFINITY;
    err = setrlimit(RLIMIT_CORE, &rlim);
    if (err) {
        snprintf(err_msg, MSG_SIZE, "Cannot set rlimits due to %s.\n", strerror(err));
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, err_msg);
    }

    int isDumpable = prctl(PR_GET_DUMPABLE);

    if (!isDumpable) {
        err = prctl(PR_SET_DUMPABLE, 1);
    }
    if (err) {
        snprintf(err_msg, MSG_SIZE, "Cannot set dumpable: %s.\n", strerror(errno));
        globus_gfs_log_message(GLOBUS_GFS_LOG_ERR, err_msg);
    }

    // Reset signal handler:
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sa.sa_sigaction = handler;
    signal(SIGSEGV, SIG_DFL);
    //sigaction(SIGSEGV, &sa, NULL);
}

/*
 * Temporary read code
 */
#if 0
char err_msg[256];
static int local_io_block_size = 0;
static int local_io_count = 0;
/* send files to client */

static
void
globus_l_gfs_posix2_read_from_storage(
    lstore_handle_t *      posix_handle);

static
void
globus_l_gfs_posix2_read_from_storage_cb(
    globus_gfs_operation_t              op,
    globus_result_t                     result,
    globus_byte_t *                     buffer,
    globus_size_t                       nbytes,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_posix2_read_from_storage_cb);
    lstore_handle_t *      posix_handle;
 
    posix_handle = (lstore_handle_t *) user_arg;

    posix_handle->outstanding_count--;
    globus_free(buffer);
    globus_l_gfs_posix2_read_from_storage(posix_handle);
}


static
void
globus_l_gfs_posix2_read_from_storage(
    lstore_handle_t *      posix_handle)
{
    globus_byte_t *                     buffer;
    globus_size_t                       nbytes;
    globus_size_t                       read_length;
    globus_result_t                     rc;

    GlobusGFSName(globus_l_gfs_posix2_read_from_storage);

    globus_mutex_lock(&posix_handle->mutex);
    while (posix_handle->outstanding_count < posix_handle->optimal_count &&
           ! posix_handle->done) 
    {
        buffer = globus_malloc(posix_handle->block_size);
        if (buffer == NULL)
        {
            rc = GlobusGFSErrorGeneric("fail to allocate buffer");
            globus_gridftp_server_finished_transfer(posix_handle->op, rc);
            return;
        }
/*
        if (posix_handle->seekable)
        {
            lseek(posix_handle->fd, posix_handle->offset, SEEK_SET);
        }
 */ 
        /* block_length == -1 indicates transferring data to until eof */
        if (posix_handle->xfer_length < 0 ||   
            posix_handle->xfer_length > posix_handle->block_size)
        {
            read_length = posix_handle->block_size;
        }
        else
        {
            read_length = posix_handle->xfer_length;
        }
 
        nbytes = lio_read(posix_handle->fd,
                                (char *)buffer,
                                read_length,
                                posix_handle->offset,
                                NULL);
        //read(posix_handle->fd, buffer, read_length);
        if (nbytes == 0)    /* eof */
        {
            posix_handle->done = GLOBUS_TRUE;
            sprintf(err_msg,"send %d blocks of size %d bytes\n",
                            local_io_count,local_io_block_size);
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,err_msg);
            local_io_count = 0;
            local_io_block_size = 0;
        }
        else
        {
            if (nbytes != local_io_block_size)
            {
                 if (local_io_block_size != 0)
                 {
                      sprintf(err_msg,"send %d blocks of size %d bytes\n",
                                      local_io_count,local_io_block_size);
                      globus_gfs_log_message(GLOBUS_GFS_LOG_INFO,err_msg);
                 }
                 local_io_block_size = nbytes;
                 local_io_count=1;
            }
            else
            {
                 local_io_count++;
            }
        }
        if (! posix_handle->done) 
        {
            posix_handle->outstanding_count++;
            posix_handle->offset += nbytes;
            posix_handle->xfer_length -= nbytes;
            rc = globus_gridftp_server_register_write(posix_handle->op,
                                       buffer,
                                       nbytes,
                                       posix_handle->offset - nbytes,
                                       -1,
                                       globus_l_gfs_posix2_read_from_storage_cb,
                                       posix_handle);
            if (rc != GLOBUS_SUCCESS)
            {
                rc = GlobusGFSErrorGeneric("globus_gridftp_server_register_write() fail");
                globus_gridftp_server_finished_transfer(posix_handle->op, rc);
            }
        }
    }
    globus_mutex_unlock(&posix_handle->mutex);
    if (posix_handle->outstanding_count == 0)
    {
        gop_sync_exec(lio_close_gop(posix_handle->fd));
        globus_gridftp_server_finished_transfer(posix_handle->op, 
                                                    GLOBUS_SUCCESS);
    }
    return;
}

/*************************************************************************
 *  send
 *  ----
 *  This interface function is called when the client requests to receive
 *  a file from the server.
 *
 *  To send a file to the client the following functions will be used in roughly
 *  the presented order.  They are doced in more detail with the
 *  gridftp server documentation.
 *
 *      globus_gridftp_server_begin_transfer();
 *      globus_gridftp_server_register_write();
 *      globus_gridftp_server_finished_transfer();
 *
 ************************************************************************/
static
void
globus_l_gfs_posix2_send(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    globus_result_t                     rc;
    lstore_handle_t *       posix_handle;
    GlobusGFSName(globus_l_gfs_posix2_send);

    posix_handle = (lstore_handle_t *) user_arg;

    posix_handle->path = copy_path_to_lstore("/lio/lfs", transfer_info->pathname);
    posix_handle->op = op;
    posix_handle->outstanding_count = 0;
    posix_handle->done = GLOBUS_FALSE;
    globus_gridftp_server_get_block_size(op, &posix_handle->block_size);

    globus_gridftp_server_get_read_range(posix_handle->op,
                                         &posix_handle->offset,
                                         &posix_handle->xfer_length);

    globus_gridftp_server_begin_transfer(posix_handle->op, 0, posix_handle);
    int  open_flags = lio_fopen_flags("r");
    int retval = gop_sync_exec(lio_open_gop(lio_gc,
                                lio_gc->creds,
                                posix_handle->path,
                                open_flags,
                                NULL,
                                &(posix_handle->fd), 60));
    if (retval != OP_STATE_SUCCESS || (!posix_handle->fd)) {
        rc = GlobusGFSErrorGeneric("open() fail");
        globus_gridftp_server_finished_transfer(op, rc);
    }

/*
 * /dev/null and /dev/zero are not seekable. They are used for memory-to-memory
 * performance test.
 */
    posix_handle->seekable=1;
    if (! strcmp(posix_handle->path,"/dev/zero"))
    {
        posix_handle->seekable=0;
    }
    
    globus_gridftp_server_get_optimal_concurrency(posix_handle->op,
                                                  &posix_handle->optimal_count);

    globus_l_gfs_posix2_read_from_storage(posix_handle);
    return;
}
#endif
/*
 * start
 * -----
 * This function is called when a new session is initialized, ie a user
 * connectes to the server.  This hook gives the dsi an oppertunity to
 * set internal state that will be threaded through to all other
 * function calls associated with this session.  And an oppertunity to
 * reject the user.
 *
 * finished_info.info.session.session_arg should be set to an DSI
 * defined data structure.  This pointer will be passed as the void *
 * user_arg parameter to all other interface functions.
 *
 * NOTE: at nice wrapper function should exist that hides the details
 *       of the finished_info structure, but it currently does not.
 *       The DSI developer should jsut follow this template for now
 */
static
void
globus_l_gfs_lstore_start(
    globus_gfs_operation_t              op,
    globus_gfs_session_info_t *         session_info)
{
    GlobusGFSName(globus_l_gfs_lstore_start);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] start\n");

    globus_result_t result = GLOBUS_SUCCESS;
    lstore_handle_t *lstore_handle;

    int retval = 0;
    lstore_handle = user_connect(op, &retval);
    if (retval) {
        GlobusGFSErrorGenericStr(result, ("[lstore] Failed to start session."));
    }

    globus_gfs_finished_info_t finished_info;
    memset(&finished_info, '\0', sizeof(globus_gfs_finished_info_t));
    finished_info.type = GLOBUS_GFS_OP_SESSION_START;
    finished_info.result = result;
    finished_info.info.session.session_arg = lstore_handle;
    finished_info.info.session.username = session_info->username;
    finished_info.info.session.home_dir = "/lio/lfs/";

    // Enable core dumps
    gridftp_check_core();

    globus_gridftp_server_operation_finished(
        op, result, &finished_info);
}

/*
 * destroy
 * -------
 * This is called when a session ends, ie client quits or disconnects.
 * The dsi should clean up all memory they associated wit the session
 * here.
 */
static
void
globus_l_gfs_lstore_destroy(
    void *                              user_arg)
{
    lstore_handle_t *       lstore_handle;

    GlobusGFSName(globus_l_gfs_lstore_destroy);
    lstore_handle = (lstore_handle_t *) user_arg;

    // Set any needed options in handle here
    int retval = user_close(lstore_handle);
    if (retval) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] Failed to destroy session.");
    }
}

static
void
globus_l_gfs_lstore_trev(
    globus_gfs_event_info_t *           event_info,
    void *                              user_arg
)
{
    lstore_handle_t *       lstore_handle;
    GlobusGFSName(globus_l_gfs_lstore_trev);

    lstore_handle = (lstore_handle_t *) user_arg;
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] Recieved a transfer event.\n");

    switch (event_info->type) {
        case GLOBUS_GFS_EVENT_TRANSFER_ABORT:
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] Got an abort request to the lstore client.\n");
            user_handle_done(lstore_handle, XFER_ERROR_DEFAULT);
            break;
        default:
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] Got some other transfer event %d.\n", event_info->type);
    }
}

/*
 * stat
 * ----
 * This interface function is called whenever the server needs
 * information about a given file or resource.  It is called then an
 * LIST is sent by the client, when the server needs to verify that
 * a file exists and has the proper permissions, etc.
 */
static
void
globus_l_gfs_lstore_stat(
    globus_gfs_operation_t              op,
    globus_gfs_stat_info_t *            stat_info,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_lstore_stat);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] stat\n");

    lstore_handle_t * lstore_handle;
    lstore_handle = (lstore_handle_t *) user_arg;

    globus_result_t result = GLOBUS_SUCCESS;
    globus_gfs_stat_t *stat_array = NULL;
    int stat_count = 0;

    int retval = user_stat(lstore_handle, stat_info, &stat_array, &stat_count);
    if (retval == GLOBUS_FAILURE) {
        // Catchall for generic globus oopsies
        GlobusGFSErrorGenericStr(result, ("[lstore] Failed to perform stat."));
    } else if (retval != GLOBUS_SUCCESS) {
        // If we get something that's not GLOBUS_FAILURE or SUCCESS, treat it
        // like a real globus error string
        result = GlobusGFSErrorSystemError("stat", ENOENT);
    }
    if (retval == GLOBUS_SUCCESS) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] stat complete\n");
        globus_gridftp_server_finished_stat(
            op, result, stat_array, stat_count);
        globus_l_gfs_file_destroy_stat(stat_array, stat_count);
    } else {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] stat error\n");
        globus_gridftp_server_finished_stat(op, result, NULL, 0);
    }
}

/*
 * command
 * -------
 * This interface function is called when the client sends a 'command'.
 * commands are such things as mkdir, remdir, delete.  The complete
 * enumeration is below.
 *
 * To determine which command is being requested look at:
 *     cmd_info->command
 *
 *     GLOBUS_GFS_CMD_MKD = 1,
 *     GLOBUS_GFS_CMD_RMD,
 *     GLOBUS_GFS_CMD_DELE,
 *     GLOBUS_GFS_CMD_RNTO,
 *     GLOBUS_GFS_CMD_RNFR,
 *     GLOBUS_GFS_CMD_CKSM,
 *     GLOBUS_GFS_CMD_SITE_CHMOD,
 *     GLOBUS_GFS_CMD_SITE_DSI
 */
static
void
globus_l_gfs_lstore_command(
    globus_gfs_operation_t              op,
    globus_gfs_command_info_t *         cmd_info,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_lstore_command);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] command\n");

    lstore_handle_t * lstore_handle;
    lstore_handle = (lstore_handle_t *) user_arg;
    globus_result_t result = GLOBUS_SUCCESS;

    char *response = GLOBUS_NULL;
    int retval = user_command(lstore_handle, cmd_info, &response);
    if (retval == GLOBUS_FAILURE) {
        // Catchall for generic globus oopsies
        GlobusGFSErrorGenericStr(result, ("[lstore] Failed to execute generic command"));
    } else if (retval != GLOBUS_SUCCESS) {
        // If we get something that's not GLOBUS_FAILURE or SUCCESS, treat it
        // like a real globus error string
        result = retval;
    }

    globus_gridftp_server_finished_command(op, result, response);
}


/*
 * recv
 * ----
 * This interface function is called when the client requests that a
 * file be transfered to the server.
 *
 * To receive a file the following functions will be used in roughly
 * the presented order.  They are doced in more detail with the
 * gridftp server documentation.
 *
 *     globus_gridftp_server_begin_transfer();
 *     globus_gridftp_server_register_read();
 *     globus_gridftp_server_finished_transfer();
 *
 * Function heavily stolen from xrootd-dsi plugin
 */
static
void
globus_l_gfs_lstore_recv(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_lstore_recv);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] Begin recv\n");

    lstore_handle_t * lstore_handle;
    lstore_handle = (lstore_handle_t *) user_arg;
    lstore_handle->op = op;
    globus_result_t result = GLOBUS_SUCCESS;

    globus_gridftp_server_get_block_size(lstore_handle->op,
                                            &lstore_handle->block_size);
    globus_gridftp_server_get_read_range(lstore_handle->op,
                                            &lstore_handle->offset,
                                            &lstore_handle->xfer_length);
    globus_gridftp_server_get_optimal_concurrency(lstore_handle->op,
                                            &lstore_handle->optimal_count);
    /*
     * Once GridFTP is notified by begin_transfer, you can at any point kill
     * the xfer by issuing a globus_gridftp_server_finished_transfer(). Since
     * we're going to perform the transfers asynchronously, we don't call that
     * function unless there's an error condition we can detect very early.
     * Otherwise, we'll just let control fall off the end of this function.
     */
    globus_gridftp_server_begin_transfer(lstore_handle->op, 0, lstore_handle);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] Performing recv init. Expect %i bytes\n", lstore_handle->xfer_length);
    int retval = user_recv_init(lstore_handle, transfer_info);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] Init performed\n");
    if (!lstore_handle->fd) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] No FD in init?\n");
    }

    if (retval != 0) {
        // Catchall for generic globus oopsies
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] recv fail\n");
        GlobusGFSErrorGenericStr(result, ("[lstore] Failed to recv file."));
        globus_gridftp_server_finished_transfer(op, result);
    } else if (lstore_handle->fd == NULL) {
        GlobusGFSErrorGenericStr(result, ("[lstore] Failed to open file."));
        globus_gridftp_server_finished_transfer(op, result);
    } else {
        /*
         * Now that we've begun the transfer, we trigger the initial
         * asynchronous I/O requests. After this point, the control flow is
         * enirely through callbacks being submitted and handled
         */

        globus_mutex_lock(&lstore_handle->mutex);
        result = gfs_xfer_pump(lstore_handle);
        globus_mutex_unlock(&lstore_handle->mutex);
        if (result) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] recv pump fail\n");
            globus_gridftp_server_finished_transfer(op, result);
        }
    }

}

/*
 * send
 * ----
 * This interface function is called when the client requests to receive
 * a file from the server.
 *
 * To send a file to the client the following functions will be used in roughly
 * the presented order.  They are doced in more detail with the
 * gridftp server documentation.
 *
 *     globus_gridftp_server_begin_transfer();
 *     globus_gridftp_server_register_write();
 *     globus_gridftp_server_finished_transfer();
 *
 */
static
void
globus_l_gfs_lstore_send(
    globus_gfs_operation_t              op,
    globus_gfs_transfer_info_t *        transfer_info,
    void *                              user_arg)
{
    GlobusGFSName(globus_l_gfs_lstore_send);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] send\n");

    lstore_handle_t * lstore_handle;
    lstore_handle = (lstore_handle_t *) user_arg;
    lstore_handle->op = op;
    globus_result_t result = GLOBUS_SUCCESS;

    globus_gridftp_server_get_block_size(lstore_handle->op,
                                            &lstore_handle->block_size);
    globus_gridftp_server_get_write_range(lstore_handle->op,
                                            &lstore_handle->offset,
                                            &lstore_handle->xfer_length);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] Transmitting %ld bytes from offset %ld\n", lstore_handle->xfer_length, lstore_handle->offset);
    globus_gridftp_server_get_optimal_concurrency(lstore_handle->op,
                                                    &lstore_handle->optimal_count);
    /*
     * Once GridFTP is notified by begin_transfer, you can at any point kill
     * the xfer by issuing a globus_gridftp_server_finished_transfer(). Since
     * we're going to perform the transfers asynchronously, we don't call that
     * function unless there's an error condition we can detect very early.
     * Otherwise, we'll just let control fall off the end of this function.
     */
    globus_gridftp_server_begin_transfer(lstore_handle->op, 0, lstore_handle);
    int retval = user_send_init(lstore_handle, transfer_info);

    if (retval != 0) {
        // Catchall for generic globus oopsies
        GlobusGFSErrorGenericStr(result, ("[lstore] Failed to send file."));
        globus_gridftp_server_finished_transfer(op, result);
    } else if (lstore_handle->fd == NULL) {
        GlobusGFSErrorGenericStr(result, ("[lstore] Failed to open file."));
        globus_gridftp_server_finished_transfer(op, result);
    } else {
        /*
         * Now that we've begun the transfer, we trigger the initial
         * asynchronous I/O requests. After this point, the control flow is
         * enirely through callbacks being submitted and handled
         */
        globus_mutex_lock(&lstore_handle->mutex);
        int ret = gfs_xfer_pump(lstore_handle);
        if (ret) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] send pump fail\n");
            globus_gridftp_server_finished_transfer(op, result);
        }
        if (lstore_handle->done && (lstore_handle->outstanding_count == 0)) {
            user_xfer_close(lstore_handle);
            if (!lstore_handle->done_sent && (lstore_handle->error == XFER_ERROR_NONE)) {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] shortcut xfer success: %s\n", lstore_handle->path);
                globus_gridftp_server_finished_transfer(lstore_handle->op, GLOBUS_SUCCESS);
                lstore_handle->done_sent = 1;
            } else if (!lstore_handle->done_sent && (lstore_handle->error != XFER_ERROR_NONE)) {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] shortcut xfer failure: %d, %s. reason:\n", lstore_handle->rc, lstore_handle->path);
                if (lstore_handle->rc == GLOBUS_SUCCESS) {
                    globus_gridftp_server_finished_transfer(lstore_handle->op, GLOBUS_FAILURE);
                } else {
                    globus_gridftp_server_finished_transfer(lstore_handle->op, lstore_handle->rc);
                }
                lstore_handle->done_sent = 1;
            }
        }
        globus_mutex_unlock(&lstore_handle->mutex);
    }
}

/**
 * Enumerates this plugin's function pointers to gridftp
 */
globus_gfs_storage_iface_t globus_l_gfs_lstore_dsi_iface =
{
    .descriptor = GLOBUS_GFS_DSI_DESCRIPTOR_BLOCKING | \
                    GLOBUS_GFS_DSI_DESCRIPTOR_SENDER,
    .init_func = globus_l_gfs_lstore_start,
    .destroy_func = globus_l_gfs_lstore_destroy,
    .send_func = globus_l_gfs_lstore_send,
    .recv_func = globus_l_gfs_lstore_recv,
    .trev_func = globus_l_gfs_lstore_trev,
    .command_func = globus_l_gfs_lstore_command,
    .stat_func = globus_l_gfs_lstore_stat,
};

/**
 * Describes this plugin
 *
 * Forward declare since the struct and functions reference each other.
 */
static int globus_l_gfs_lstore_activate(void);
static int globus_l_gfs_lstore_deactivate(void);

__attribute__((visibility ("default"))) GlobusExtensionDefineModule(globus_gridftp_server_lstore) =
{
    .module_name = "globus_gridftp_server_lstore",
    .activation_func = globus_l_gfs_lstore_activate,
    .deactivation_func = globus_l_gfs_lstore_deactivate,
    .version = &local_version
};

/*
 * activate
 * --------
 * This interface function is called when the plugin is loaded (i.e. when
 * GridFTP starts)
 */

static
int
globus_l_gfs_lstore_activate(void)
{
    GlobusGFSName(globus_l_gfs_lstore_activate);
    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] activate\n");
    globus_result_t result = GLOBUS_SUCCESS;

    int retval = activate();
    if (retval) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] Failed to activate.\n");
        GlobusGFSErrorGenericStr(result, ("[lstore] Failed to activate."));
        if (!result) {
            result = GLOBUS_FAILURE;
        }
        return result;
    }

    globus_extension_registry_add(
        GLOBUS_GFS_DSI_REGISTRY,
        "lstore",
        GlobusExtensionMyModule(globus_gridftp_server_lstore),
        &globus_l_gfs_lstore_dsi_iface);

    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] activate OK: %d\n", result);
    return result;
}

/*
 * deactivate
 * ----------
 * This interface function is called when the plugin is unloaded (i.e. when
 * GridFTP shuts down)
 */
static
int
globus_l_gfs_lstore_deactivate(void)
{
    GlobusGFSName(globus_l_gfs_lstore_deactivate);
    globus_result_t result = GLOBUS_SUCCESS;

    globus_extension_registry_remove(
        GLOBUS_GFS_DSI_REGISTRY, "lstore");

    int retval = deactivate();
    if (retval) {
        GlobusGFSErrorGenericStr(result, ("[lstore] Failed to deactivate."));
    }

    return result;
}

/*
 * Stat-handling functions stolen from "file" DSI
 */
static void
globus_l_gfs_file_destroy_stat(
    globus_gfs_stat_t *                 stat_array,
    int                                 stat_count)
{
    int                                 i;
    GlobusGFSName(globus_l_gfs_file_destroy_stat);

    for(i = 0; i < stat_count; i++)
    {
        if(stat_array[i].name != NULL)
        {
            globus_free(stat_array[i].name);
        }
        if(stat_array[i].symlink_target != NULL)
        {
            globus_free(stat_array[i].symlink_target);
        }
    }
    globus_free(stat_array);
}

static int my_min(int a, int b) {
    return (a < b) ? a : b;
}
static int my_max(int a, int b) {
    return (a > b) ? a : b;
}

/*
 * These functions exist instead of just the user_ functions because they are
 * callbacks triggerd by Globus.
 */
#define MAX_CONCURRENCY_PER_LOOP ((int) 32)
static globus_result_t gfs_xfer_pump(lstore_handle_t *h) {
    GlobusGFSName(gfs_xfer_pump);

    globus_result_t rc = GLOBUS_SUCCESS;
    int old_count = h->optimal_count;
    if (!h->done) {
        globus_gridftp_server_get_optimal_concurrency(h->op, &h->optimal_count);
    }
    if (old_count != h->optimal_count) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] Optimal %d -> %d.\n", old_count, h->optimal_count);
    }
    int concurrency_needed = h->optimal_count - h->outstanding_count;
    concurrency_needed = my_min(MAX_CONCURRENCY_PER_LOOP, concurrency_needed);
    concurrency_needed = my_max(0, concurrency_needed);
    // for pump (concur && (!done, read)
    if (h->outstanding_count == 0) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] pump @ 0, will pump %d.\n", concurrency_needed);
    }
    for (int i = 0; ((i < concurrency_needed) && !h->done); ++i) {
        // alloc (USER CODE)
        globus_byte_t *buf = globus_malloc(h->block_size);
        if (h->outstanding_count == 0 || (strstr(h->path, "/cms/store/unmerged/SAM/testSRM/SAM-se1.accre.vanderbilt.edu/lcg-util/") != NULL)) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] pump @ 0, pump count %d.\n", i);
        }
        // if recv
        if (h->xfer_direction == XFER_RECV) {
            // register read
            rc = globus_gridftp_server_register_read(h->op,
                                       buf,
                                       h->block_size,
                                       gfs_recv_callback,
                                       h);
            // inc outstanding
            ++(h->outstanding_count);
            if (rc != GLOBUS_SUCCESS) {
                // failed to register
                user_handle_done(h, XFER_ERROR_DEFAULT);
                if (h->rc == GLOBUS_SUCCESS) {
                    h->rc = rc;
                }
                break;
            }
        } else {
            // if send
            // do read (USER CODE)
            globus_size_t read_length;
            if (h->xfer_length < 0 || h->xfer_length > h->block_size) {
                read_length = h->block_size;
            } else {
                read_length = h->xfer_length;
            }
            globus_off_t offset = h->offset;
            apr_time_t read_timer;
            STATSD_TIMER_RESET(read_timer);
            if (h->outstanding_count == 0) {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] pump @ 0, starting read %d@%ld.\n", read_length, offset);
            }
            int nbytes = lio_read(h->fd,
                                            (char *)buf,
                                            read_length,
                                            offset,
                                            NULL);
            if (h->outstanding_count == 0) {
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] pump @ 0, ending read %d, bytes: %d.\n", i, nbytes);
            }
            STATSD_TIMER_POST("lfs_read_time", read_timer);
            STATSD_COUNT("lfs_bytes_read", nbytes);
            //   if bytes = 0
            if (nbytes == 0) {
                // done eof
                user_handle_done(h, XFER_ERROR_NONE);
            } else if (nbytes < 0) {
                // bad read
                user_handle_done(h, XFER_ERROR_DEFAULT);
            } else {
                // more coming
                // register read
                if (h->outstanding_count == 0) {
                    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] Register write off: %ld bytes: %d, buf: %p\n", h->offset, nbytes, buf);
                }

                rc = globus_gridftp_server_register_write(h->op,
                                                            buf,
                                                            nbytes,
                                                            h->offset,
                                                            -1,
                                                            gfs_send_callback,
                                                            h);
                // int offset
                h->offset += nbytes;
                h->xfer_length -= nbytes;
                if (rc != GLOBUS_SUCCESS) {
                    // failed to add the write
                    char *res_str = globus_error_print_chain(globus_error_peek(rc));
                    globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] ERROR in register_write: %d %p %d %d: %s\n", rc, buf, nbytes, h->offset, res_str);
                    globus_free(res_str);
                    user_handle_done(h, XFER_ERROR_DEFAULT);
                    h->rc = rc;
                    break;
                } else {
                    ++(h->outstanding_count);
                }
            }
        }
    }
    return rc;
}

static void gfs_send_callback(globus_gfs_operation_t op,
                                globus_result_t result,
                                globus_byte_t *buffer,
                                globus_size_t nbytes,
                                void *user_arg) {
    //globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] CB_send1: %d %p %d.\n", result, buffer, nbytes);
    gfs_xfer_callback(op, result, buffer, nbytes, 0, 0, user_arg);
    //globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] CB_send2: %d %p %d.\n", result, buffer, nbytes);
}

void gfs_recv_callback(globus_gfs_operation_t op,
                                globus_result_t result,
                                globus_byte_t * buffer,
                                globus_size_t nbytes,
                                globus_off_t offset,
                                globus_bool_t eof,
                                void * user_arg) {
    gfs_xfer_callback(op, result, buffer, nbytes, offset, eof, user_arg);
}

static void gfs_xfer_callback(globus_gfs_operation_t op,
                                globus_result_t result,
                                globus_byte_t * buffer,
                                globus_size_t nbytes,
                                globus_off_t offset,
                                globus_bool_t eof,
                                void * user_arg) {
    GlobusGFSName(gfs_recv_callback);
    lstore_handle_t *h = (lstore_handle_t *) user_arg;
    
    globus_mutex_lock(&h->mutex);
    if (nbytes <= 0) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] CB: Xfer of zero bytes\n");
        user_handle_done(h, XFER_ERROR_NONE);
        goto cleanup;
    }

    if (result != 0) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] CB: result != 0\n");
        user_handle_done(h, XFER_ERROR_DEFAULT);
        if (h->rc == GLOBUS_SUCCESS) {
            h->rc = result;
        }
        goto cleanup;
    }

    if (result != 0) {
        char *res_str = globus_error_print_friendly(globus_error_peek(result));
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] gfs_CB result: %s\n", res_str);
        globus_free(res_str);
    }

    if (h->done) {
        if (h->rc == GLOBUS_SUCCESS) {
            h->rc = result;
        }
    }

    if (eof) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] CB: EOF\n");
        user_handle_done(h, XFER_ERROR_NONE);
    }

    if ((nbytes > 0) && (h->xfer_direction == XFER_RECV)) {
        // write (USER CODE)
        // if written != nbytes
            // done -> error
        // else
            // update_bytes_written

        // Store the adler32 for this block
        uint32_t adler32_accum = adler32(0L, Z_NULL, 0);
        adler32_accum = adler32(adler32_accum, (const Bytef *)buffer, nbytes);
        size_t adler32_idx = 0; // offset / h->block_size;
        if (adler32_idx > h->cksum_blocks) {
            adler32_idx = 0;
        }
        if (h->cksum_nbytes[adler32_idx] != 0) {
            adler32_idx = 0;
        }
        while ((h->cksum_nbytes[adler32_idx] != 0)) {
            if (adler32_idx == h->cksum_blocks - 1) {
                int new_count = h->cksum_blocks * 2;
                globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] Checksum blocks %d -> %d\n", h->cksum_blocks, new_count);

                // FIXME: error handling
                h->cksum_nbytes = globus_realloc(h->cksum_nbytes, new_count * sizeof(globus_size_t));
                h->cksum_offset = globus_realloc(h->cksum_offset, new_count * sizeof(globus_size_t));
                h->cksum_adler = globus_realloc(h->cksum_adler, new_count * sizeof(globus_size_t));
                memset(&h->cksum_nbytes[h->cksum_blocks], 0, h->cksum_blocks * sizeof(globus_size_t));
                memset(&h->cksum_offset[h->cksum_blocks], 0, h->cksum_blocks * sizeof(globus_size_t));
                memset(&h->cksum_adler[h->cksum_blocks], 0, h->cksum_blocks * sizeof(globus_size_t));
                h->cksum_blocks = new_count;
            }
            ++adler32_idx;
        }
        h->cksum_nbytes[adler32_idx] = nbytes;
        h->cksum_offset[adler32_idx] = offset;
        h->cksum_adler[adler32_idx] = adler32_accum;
        if (adler32_idx > h->cksum_end_blocks) {
            h->cksum_end_blocks = adler32_idx;
        }
        if (offset + nbytes > h->cksum_total_len) {
            h->cksum_total_len = offset + nbytes;
        }
        if (h->fd == 0) {
            if (result != 0) {
                user_handle_done(h, XFER_ERROR_DEFAULT);
                if (h->rc == GLOBUS_SUCCESS) {
                    GlobusGFSErrorGenericStr(result, ("[lstore] Write a null filehandle."));
                    h->rc = result;
                }
            }
        } else {
            apr_time_t write_timer;
            STATSD_TIMER_RESET(write_timer);
            globus_size_t written = lio_write(h->fd,
                                                (char *)buffer,
                                                nbytes,
                                                offset,
                                                NULL);
            STATSD_TIMER_POST("lfs_write_time", write_timer);
            STATSD_COUNT("lfs_bytes_written", written);
            if (written != nbytes) {
                user_handle_done(h, XFER_ERROR_DEFAULT);
                goto cleanup;
            } else {
                globus_gridftp_server_update_bytes_written(h->op, offset, nbytes);
            }
        }
    }
    /*
     * The transfer is done when h->done is set and h->outstanding_count reaches
     * zero
     *
     * Unlock within the if statements since the conditions are protected by
     * mutex
     */

cleanup:
    // free buffer (USER CORE)
    globus_free(buffer);
    // dec outstanding
    --(h->outstanding_count);


    if (h->done && (h->outstanding_count == 0)) {
        user_xfer_close(h);
        if (!h->done_sent && (h->error == XFER_ERROR_NONE)) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] xfer success: %s\n", h->path);
            globus_gridftp_server_finished_transfer(h->op, GLOBUS_SUCCESS);
            h->done_sent = 1;
        } else if (!h->done_sent && (h->error != XFER_ERROR_NONE)) {
            globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] xfer failure: %d, %s. reason:\n", h->rc, h->path);
            if (h->rc == GLOBUS_SUCCESS) {
                globus_gridftp_server_finished_transfer(h->op, GLOBUS_FAILURE);
            } else {
                globus_gridftp_server_finished_transfer(h->op, h->rc);
            }
            h->done_sent = 1;
        }
    } else if (!h->done) {
        gfs_xfer_pump(h);
    } else {
        gfs_xfer_pump(h);
    }

    if ((!h->done) && (h->outstanding_count == 0)) {
        globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] gfs_CB bad drain!.\n");
    }
    globus_mutex_unlock(&h->mutex);
    //globus_gfs_log_message(GLOBUS_GFS_LOG_INFO, "[lstore] gfs_CB return!.\n");

    return;
}
