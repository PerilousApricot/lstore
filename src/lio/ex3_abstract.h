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
#include "lio/ex3_abstract.h"
//***********************************************************************
// Exnode3 abstract class
//***********************************************************************
#include <gop/opque.h>
#include <gop/tp.h>
#include <tbx/atomic_counter.h>
#include <tbx/iniparse.h>
#include <tbx/list.h>
#include <tbx/log.h>
#include <tbx/transfer_buffer.h>

#include "data_block.h"
#include "data_service_abstract.h"
#include "ex3_header.h"
#include "ex3_types.h"
#include "object_service_abstract.h"
#include "resource_service_abstract.h"
#include "service_manager.h"

#ifndef _EX3_ABSTRACT_H_
#define _EX3_ABSTRACT_H_

#ifdef __cplusplus
extern "C" {
#endif

#define EX_TEXT             0
#define EX_PROTOCOL_BUFFERS 1

#define LO_SIZE_USED 0
#define LO_SIZE_MAX  1

#define INSPECT_FORCE_REPAIR          128   //** Make the repair even if it leads to data loss
#define INSPECT_SOFT_ERROR_FAIL       256   //** Treat soft errors as hard
#define INSPECT_FORCE_RECONSTRUCTION  512   //** Don't use depot-depot copies for data movement.  Instead use reconstruction
#define INSPECT_FAIL_ON_ERROR        1024   //** Kick out if an unrecoverable error is hit
#define INSPECT_FIX_READ_ERROR       2048   //** Treat read errors as bad blocks for repair
#define INSPECT_FIX_WRITE_ERROR      4096   //** Treat write errors as bad blocks for repair
#define INSPECT_COMMAND_BITS 15

#define INSPECT_QUICK_CHECK   1
#define INSPECT_SCAN_CHECK    2
#define INSPECT_FULL_CHECK    3
#define INSPECT_QUICK_REPAIR  4
#define INSPECT_SCAN_REPAIR   5
#define INSPECT_FULL_REPAIR   6
#define INSPECT_SOFT_ERRORS   7
#define INSPECT_HARD_ERRORS   8
#define INSPECT_MIGRATE       9
#define INSPECT_WRITE_ERRORS 10
#define CLONE_STRUCTURE       0
#define CLONE_STRUCT_AND_DATA 1

#define INSPECT_RESULT_FULL_CHECK      512    //** Full byte-level check performed
#define INSPECT_RESULT_SOFT_ERROR     1024   //** Soft errors found
#define INSPECT_RESULT_HARD_ERROR     2048   //** Hard errors found
#define INSPECT_RESULT_MIGRATE_ERROR  4096   //** Migrate errors found
#define INSPECT_RESULT_COUNT_MASK      511    //** Bit mask for LUN counts
#define SEG_SM_LOAD   "segment_load"
#define SEG_SM_CREATE "segment_create"

typedef void segment_priv_t;


struct segment_rw_hints_t {     //** Structure for contaiing hints to the various segment drivers
    int lun_max_blacklist;  //** Max number of devs to blacklist per stripe for performance
    int number_blacklisted;
};

struct rid_inspect_tweak_t {
    rid_change_entry_t *rid;
    apr_hash_t *pick_pool;
};

struct inspect_args_t {
    rs_query_t *query;   //** Generic extra query
    opque_t *qs;         //** Cleanup Que on success
    opque_t *qf;         //** Cleanup Que for failure
    apr_hash_t *rid_changes;  //** List of RID space changes
    apr_thread_mutex_t *rid_lock;     //** Lock for manipulating the rid_changes table
    int n_dev_rows;
    int dev_row_replaced[128];
};

struct segment_fn_t {
    op_generic_t *(*read)(segment_t *seg, data_attr_t *da, segment_rw_hints_t *hints, int n_iov, ex_tbx_iovec_t *iov, tbx_tbuf_t *buffer, ex_off_t boff, int timeout);
    op_generic_t *(*write)(segment_t *seg, data_attr_t *da, segment_rw_hints_t *hints, int n_iov, ex_tbx_iovec_t *iov, tbx_tbuf_t *buffer, ex_off_t boff, int timeout);
    op_generic_t *(*inspect)(segment_t *seg, data_attr_t *da, tbx_log_fd_t *fd, int mode, ex_off_t buffer_size, inspect_args_t *args, int timeout);
    op_generic_t *(*truncate)(segment_t *seg, data_attr_t *da, ex_off_t new_size, int timeout);
    op_generic_t *(*remove)(segment_t *seg, data_attr_t *da, int timeout);
    op_generic_t *(*flush)(segment_t *seg, data_attr_t *da, ex_off_t lo, ex_off_t hi, int timeout);
    op_generic_t *(*clone)(segment_t *seg, data_attr_t *da, segment_t **clone, int mode, void *attr, int timeout);
    int (*signature)(segment_t *seg, char *buffer, int *used, int bufsize);
    ex_off_t (*block_size)(segment_t *seg);
    ex_off_t (*size)(segment_t *seg);
    int (*serialize)(segment_t *seg, exnode_exchange_t *exp);
    int (*deserialize)(segment_t *seg, ex_id_t id, exnode_exchange_t *exp);
    void (*destroy)(segment_t *seg);
};

//#define inspect_printf(fd, ...) if ((fd) != NULL) fprintf(fd, __VA_ARGS__)

#define segment_id(s) (s)->header.id
#define segment_type(s) (s)->header.type
#define segment_destroy(s) (s)->fn.destroy(s)
#define segment_read(s, da, hints, n_iov, iov, tbuf, boff, to) (s)->fn.read(s, da, hints, n_iov, iov, tbuf, boff, to)
#define segment_write(s, da, hints, n_iov, iov, tbuf, boff, to) (s)->fn.write(s, da, hints, n_iov, iov, tbuf, boff, to)
#define segment_inspect(s, da, fd, mode, bsize, query, to) (s)->fn.inspect(s, da, fd, mode, bsize, query, to)
#define segment_truncate(s, da, new_size, to) (s)->fn.truncate(s, da, new_size, to)
#define segment_remove(s, da, to) (s)->fn.remove(s, da, to)
#define segment_flush(s, da, lo, hi, to) (s)->fn.flush(s, da, lo, hi, to)
#define segment_clone(s, da, clone_ex, mode, attr, to) (s)->fn.clone(s, da, clone_ex, mode, attr, to)
#define segment_size(s) (s)->fn.size(s)
#define segment_signature(s, buffer, used, bufsize) (s)->fn.signature(s, buffer, used, bufsize)
#define segment_block_size(s) (s)->fn.block_size(s)
#define segment_serialize(s, exp) (s)->fn.serialize(s, exp)
#define segment_deserialize(s, id, exp) (s)->fn.deserialize(s, id, exp)
#define segment_lock(s) apr_thread_mutex_lock((s)->lock)
#define segment_unlock(s) apr_thread_mutex_unlock((s)->lock)

struct exnode_t {
    ex_header_t header;
    segment_t *default_seg;
    tbx_list_t *block;
    tbx_list_t *view;
};

struct segment_t {
    ex_header_t header;
    tbx_atomic_unit32_t ref_count;
    segment_priv_t *priv;
    service_manager_t *ess;
    segment_fn_t fn;
    apr_thread_mutex_t *lock;
    apr_thread_cond_t *cond;
    apr_pool_t *mpool;
};


typedef data_service_fn_t *(ds_create_t)(service_manager_t *ess, tbx_inip_file_t *ifd, char *section);
typedef segment_t *(segment_load_t)(void *arg, ex_id_t id, exnode_exchange_t *ex);
typedef segment_t *(segment_create_t)(void *arg);

struct segment_errors_t {
    int soft;
    int hard;
    int write;
};

//** Exnode related functions
op_generic_t *exnode_remove(thread_pool_context_t *tpc, exnode_t *ex, data_attr_t *da, int timeout);
void exnode_exchange_append_text(exnode_exchange_t *exp, char *buffer);
void exnode_exchange_append(exnode_exchange_t *exp, exnode_exchange_t *exp_append);
ex_header_t *exnode_get_header(exnode_t *ex);
//Exnode3__Exnode *exnode_native2pb(exnode_t *exnode);
void exnode_exchange_init(exnode_exchange_t *exp, int type);
void exnode_exchange_free(exnode_exchange_t *exp);
ex_id_t exnode_exchange_get_default_view_id(exnode_exchange_t *exp);
void exnode_set_default(exnode_t *ex, segment_t *seg);

//exnode_t *exnode_pb2native(Exnode3__Exnode *pb);
int exnode_printf(exnode_t *ex, void *buffer, int *nbytes);
exnode_t *exnode_load(char *fname);
int exnode_save(char *fname, exnode_t *ex);

//** View related functions
int view_remove(exnode_t *ex, segment_t *view);
segment_t *view_search_by_name(exnode_t *ex, char *name);
segment_t *view_search_by_id(exnode_t *ex, ex_id_t id);

//** Segment related functions
#define segment_get_header(seg) &((seg)->header)
#define segment_set_header(seg, new_head) (seg)->header = *(new_head)
op_generic_t *segment_put(thread_pool_context_t *tpc, data_attr_t *da, segment_rw_hints_t *rw_hints, FILE *fd, segment_t *dest_seg, ex_off_t dest_offset, ex_off_t len, ex_off_t bufsize, char *buffer, int do_truncate, int timeout);
op_generic_t *segment_get(thread_pool_context_t *tpc, data_attr_t *da, segment_rw_hints_t *rw_hints, segment_t *src_seg, FILE *fd, ex_off_t src_offset, ex_off_t len, ex_off_t bufsize, char *buffer, int timeout);
segment_t *load_segment(service_manager_t *ess, ex_id_t id, exnode_exchange_t *ex);

void generate_ex_id(ex_id_t *id);

#ifdef __cplusplus
}
#endif

#endif


