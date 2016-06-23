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

#ifndef ACCRE_LIO_OBJECT_SERVICE_ABSTRACT_H_INCLUDED
#define ACCRE_LIO_OBJECT_SERVICE_ABSTRACT_H_INCLUDED

#include "lio/lio_visibility.h"

#ifdef __cplusplus
extern "C" {
#endif

// Typedefs
typedef struct object_service_fn_t object_service_fn_t;
typedef struct os_attr_tbx_list_t os_attr_tbx_list_t;
typedef struct os_authz_t os_authz_t;
typedef struct os_regex_entry_t os_regex_entry_t;
typedef struct os_regex_table_t os_regex_table_t;
typedef struct os_virtual_attr_t os_virtual_attr_t;
typedef void os_fd_t;
typedef void os_attr_iter_t;
typedef void os_object_iter_t;
typedef void os_fsck_iter_t;


// Functions
LIO_API char *lio_os_glob2regex(char *glob);
LIO_API int lio_os_local_filetype(char *path);
LIO_API os_regex_table_t *lio_os_path_glob2regex(char *path);
LIO_API void lio_os_path_split(const char *path, char **dir, char **file);
LIO_API os_regex_table_t *lio_os_regex2table(char *regex);
LIO_API int lio_os_regex_is_fixed(os_regex_table_t *regex);
LIO_API void lio_os_regex_table_destroy(os_regex_table_t *table);

#ifdef __cplusplus
}
#endif

#endif /* ^ ACCRE_LIO_OBJECT_SERVICE_ABSTRACT_H_INCLUDED ^ */ 
