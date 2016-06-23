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

/** \file
* Autogenerated public API
*/

#ifndef ACCRE_LIO_EX3_ABSTRACT_H_INCLUDED
#define ACCRE_LIO_EX3_ABSTRACT_H_INCLUDED

#include <gop/tp.h>
#include <lio/lio_visibility.h>
#include <lio/data_service_abstract.h>
#include <lio/service_manager.h>
#include <lio/ex3_types.h>

#ifdef __cplusplus
extern "C" {
#endif

// Typedefs
typedef struct exnode_t exnode_t;
typedef struct inspect_args_t inspect_args_t;
typedef struct rid_inspect_tweak_t rid_inspect_tweak_t;
typedef struct segment_errors_t segment_errors_t;
typedef struct segment_fn_t segment_fn_t;
typedef struct segment_rw_hints_t segment_rw_hints_t;
typedef struct segment_t segment_t;

// Functions
LIO_API op_generic_t *lio_exnode_clone(thread_pool_context_t *tpc, exnode_t *ex, data_attr_t *da, exnode_t **clone_ex, void *arg, int mode, int timeout);
LIO_API exnode_t *lio_exnode_create();
LIO_API segment_t *lio_exnode_default_get(exnode_t *ex);
LIO_API int lio_exnode_deserialize(exnode_t *ex, exnode_exchange_t *exp, service_manager_t *ess);
LIO_API void lio_exnode_destroy(exnode_t *ex);
LIO_API exnode_exchange_t *lio_exnode_exchange_create(int type);
LIO_API void lio_exnode_exchange_destroy(exnode_exchange_t *exp);
LIO_API exnode_exchange_t *lio_exnode_exchange_load_file(char *fname);
LIO_API exnode_exchange_t *lio_exnode_exchange_text_parse(char *text);
LIO_API int lio_exnode_serialize(exnode_t *ex, exnode_exchange_t *exp);
LIO_API op_generic_t *lio_segment_copy(thread_pool_context_t *tpc, data_attr_t *da, segment_rw_hints_t *rw_hints, segment_t *src_seg, segment_t *dest_seg, ex_off_t src_offset, ex_off_t dest_offset, ex_off_t len, ex_off_t bufsize, char *buffer, int do_truncate, int timoeut);
LIO_API int lio_view_insert(exnode_t *ex, segment_t *view);

#ifdef __cplusplus
}
#endif

#endif /* ^ ACCRE_LIO_EX3_ABSTRACT_H_INCLUDED ^ */ 
